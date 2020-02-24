# pylint: disable=too-many-lines
import datetime
import json
import logging
import os
import pycurl
import re
import six
import stat
import subprocess
import sys
import time
import uuid

from collections import namedtuple
from contextlib import contextmanager
from io import BytesIO
from six.moves.urllib.parse import urlparse

from .common import error, hard_error, log_command_safe, add_perms_to_file
from .state import STATE


TIMEOUT = 300


# NOTE: This in reality binds output method (rhv-upload, openstack) to the
#       host type (VDSM, EL) we run on. This is not ideal as we should be
#       able to use any (or at least some) combinations (e.g. rhv-upload
#       from EL system). But nobody asked for this feature yet.
def detect_host(data):
    if 'export_domain' in data or \
       'rhv_url' in data:
        return OvirtHost()
    elif 'osp_environment' in data:
        return OpenstackHost()
    elif os.path.exists('data/vm'):
        return KubevirtHost()
    else:
        raise ValueError("Cannot detect type of host")


class _BaseHost(object):
    def __init__(self):
        self._tag = '%s-%d' % (time.strftime('%Y%m%dT%H%M%S'), os.getpid())

    # Interface

    def get_tag(self):
        return self._tag

    def handle_cleanup(self, data):
        """ Handle cleanup after failed conversion """
        pass

    def handle_finish(self, data):
        """ Handle finish after successfull conversion """
        pass

    def check_install_drivers(self, data):
        hard_error('cannot check_install_drivers for unknown host type')

    def prepare_command(self, data, v2v_args, v2v_env, v2v_caps):
        """ Prepare virt-v2v command parts that are method dependent """
        return v2v_args, v2v_env

    def get_uid(self):
        """ Tell under which user to run virt-v2v """
        return os.geteuid()

    def get_gid(self):
        """ Tell under which group to run virt-v2v """
        return os.getegid()

    def update_progress(self):
        """ Called to do tasks on progress update """
        pass

    def validate_data(self, data):
        """ Validate input data, fill in defaults, etc """
        hard_error("Cannot validate data for unknown host type")

    def prepare_disks(self, data):
        """ Validate input data, fill in defaults, etc """
        if data['two_phase']:
            hard_error("Host implementation did not forbid two phase "
                       "conversion, but did not implement `prepare_disks`")


class KubevirtHost(_BaseHost):

    def __init__(self):
        super(KubevirtHost, self).__init__()
        self._k8s = _K8SCommunicator()
        self._tag = '123'
        # This could be stored in the host and just requested instead of the
        # class changing an external behaviour.
        STATE.internal['duplicate_logs'] = True

    def handle_finish(self, data):
        """ Handle finish after successfull conversion """
        # Store JSON into annotation
        with open('/data/vm/%s.json' % data['vm_name'], 'rb') as f:
            vm_data = f.read().decode('utf-8')
            patch = [{
                "op": "add",
                "path": "/metadata/annotations/v2vConversionMetadata",
                "value": vm_data,
            }]
            self._k8s.patch(json.dumps(patch))

    def check_install_drivers(self, data):
        # Nothing to do for Kubevirt
        pass

    def prepare_command(self, data, v2v_args, v2v_env, v2v_caps):
        """ Prepare virt-v2v command parts that are method dependent """
        v2v_args.extend([
            '-o', 'json',
            '-os', '/data/vm',
            '-oo', 'json-disks-pattern=disk%{DiskNo}/disk.img',
        ])
        return v2v_args, v2v_env

    def update_progress(self):
        """ Called to do tasks on progress update """
        # Update POD annotation with progress
        # Just an average now, maybe later we can weight it by disk size
        disks = [d.progress for d in STATE.disks]
        if len(disks) > 0:
            progress = sum(disks)/len(disks)
        else:
            progress = 0

        # First make sure /metada/annotations exists then set progress
        patch = []
        pod = json.loads(self._k8s.get())
        if 'metadata' not in pod:
            patch.append({
                "op": "add",
                "path": "/metadata",
                "value": {},
            })
            pod['metadata'] = {}
            logging.debug('Creating /metadata in POD description')
        if 'annotations' not in pod['metadata']:
            patch.append({
                "op": "add",
                "path": "/metadata/annotations",
                "value": {},
            })
            pod['metadata']['annotations'] = {}
            logging.debug('Creating /metadata/annotations in POD description')
            patch.append({
                "op": "add",
                "path": "/metadata/annotations/v2vConversionProgress",
                "value": str(progress)
            })
            logging.debug('Updating progress in POD annotation')
            self._k8s.patch(json.dumps(patch))

    def validate_data(self, data):
        """ Validate input data, fill in defaults, etc """
        if data['two_phase']:
            # If adding support for two-phase conversion, do not forget to fix
            # the update_progress() method
            hard_error('Two-phase conversion is not supported for '
                       'Kubevirt host')


class _K8SCommunicator(object):

    def __init__(self):
        self._host = os.environ['KUBERNETES_SERVICE_HOST']
        self._port = os.environ['KUBERNETES_SERVICE_PORT']
        self._pod = os.environ['HOSTNAME']

        account_dir = '/var/run/secrets/kubernetes.io/serviceaccount'
        self._cert = os.path.join(account_dir, 'ca.crt')
        with open(os.path.join(account_dir, 'namespace')) as f:
            self._ns = f.read()
        with open(os.path.join(account_dir, 'token')) as f:
            self._token = f.read()

        self._url = ('https://%s:%s/api/v1/namespaces/%s/pods/%s' %
                     (self._host, self._port, self._ns, self._pod))
        # too early for logging
        # logging.info('Accessing Kubernetes on: %s', self._url)
        self._headers = [
            'Authorization: Bearer %s' % self._token,
            'Accept: application/json',
        ]

    def get(self):
        logging.debug('Accessing Kubernetes on: %s', self._url)
        response = BytesIO()
        c = pycurl.Curl()
        # c.setopt(pycurl.VERBOSE, 1)
        c.setopt(pycurl.URL, self._url)
        c.setopt(pycurl.HTTPHEADER, self._headers)
        c.setopt(pycurl.CAINFO, self._cert)
        c.setopt(pycurl.WRITEFUNCTION, response.write)
        c.perform()
        ret = c.getinfo(pycurl.RESPONSE_CODE)
        logging.debug('HTTP response code %d', ret)
        if ret >= 300:
            logging.debug('response output: %s', response.getvalue())
            c.close()
        return response.getvalue()

    def patch(self, body):
        logging.debug('Accessing Kubernetes on: %s', self._url)
        data = BytesIO(body.encode('utf-8'))
        response = BytesIO()
        c = pycurl.Curl()
        # c.setopt(pycurl.VERBOSE, 1)
        c.setopt(pycurl.URL, self._url)
        c.setopt(pycurl.UPLOAD, 1)
        c.setopt(pycurl.CUSTOMREQUEST, 'PATCH')
        c.setopt(pycurl.HTTPHEADER, self._headers +
                 ['Content-Type: application/json-patch+json'])
        c.setopt(pycurl.CAINFO, self._cert)
        c.setopt(pycurl.READFUNCTION, data.read)
        c.setopt(pycurl.WRITEFUNCTION, response.write)
        c.perform()
        ret = c.getinfo(pycurl.RESPONSE_CODE)
        logging.debug('HTTP response code %d', ret)
        if ret >= 300:
            logging.debug('response output: %s', response.getvalue())
            c.close()


class OpenstackHost(_BaseHost):

    def handle_cleanup(self, data):
        """ Handle cleanup after failed conversion """
        volumes = STATE.internal['disk_ids'].values()
        ports = STATE.internal['ports']
        # Remove attached volumes
        for v in volumes:
            rm_args = [
                'server', 'remove', 'volume',
                data['osp_server_id'],
                v
            ]
            self._run_openstack(rm_args, data)
        # Cancel transfers
        transfers = self._run_openstack([
            'volume', 'transfer', 'request', 'list',
            '--format', 'json',
            ], data)
        if transfers is None:
            logging.error('Failed to remove transfer(s)')
        else:
            transfers = json.loads(transfers)
            # Strangely, the keys are not lowercase
            transfers = [t['ID'] for t in transfers if t['Volume'] in volumes]
            if len(transfers) > 0:
                trans_cmd = ['volume', 'transfer', 'request', 'delete']
                trans_cmd.extend(transfers)
                if self._run_openstack(trans_cmd, data) is None:
                    logging.error('Failed to remove transfer(s)')
        # Remove created ports
        if len(ports) > 0:
            logging.info('Removing ports: %r', ports)
            port_cmd = ['port', 'delete']
            port_cmd.extend(ports)
            if self._run_openstack(port_cmd, data, destination=True) is None:
                logging.error('Failed to remove port(s)')
        # Remove volumes
        if len(volumes) > 0:
            # We don't know in which project the volumes are and figuring that
            # out using openstack command can be impractical in large
            # environments. Let's just try to remove them from both.
            logging.info('Removing volume(s): %r', volumes)
            vol_cmd = ['volume', 'delete']
            vol_cmd.extend(volumes)
            if self._run_openstack(vol_cmd, data) is None:
                logging.error(
                    'Failed to remove volumes(s) from current project')
            if self._run_openstack(vol_cmd, data, destination=True) is None:
                logging.error(
                    'Failed to remove volumes(s) from destination project')

    def handle_finish(self, data):
        """
        Handle finish after successfull conversion

        For OpenStack this entails creating a VM instance.
        """
        vm_name = data['vm_name']
        if STATE.internal['display_name'] is not None:
            vm_name = STATE.internal['display_name']

        # Init keystone
        if self._run_openstack(['token', 'issue'], data) is None:
            STATE.failed = True
            error('Create VM failed')
            return
        volumes = []
        # Build volume list
        for k in sorted(STATE.internal['disk_ids'].keys()):
            volumes.append(STATE.internal['disk_ids'][k])
        if len(volumes) == 0:
            STATE.failed = True
            error('No volumes found!')
            return
        if len(volumes) != len(STATE.internal['disk_ids']):
            STATE.failed = True
            error('Detected duplicate indices of Cinder volumes')
            logging.debug('Source volume map: %r',
                          STATE.internal['disk_ids'])
            logging.debug('Assumed volume list: %r', volumes)
            return
        for vol in volumes:
            logging.info('Transferring volume: %s', vol)
            # Checking if volume is in available state
            is_available = False
            start_at = time.time()
            while start_at + TIMEOUT > time.time():
                volume_state = self._run_openstack([
                        'volume', 'show', '-f', 'value', '-c', 'status', vol,
                        ], data)
                if volume_state is None:
                    STATE.failed = True
                    error('Unable to get volume state, quitting.')
                    return
                volume_state = volume_state.rstrip()
                logging.info('Current volume state: %s.', volume_state)
                if volume_state == b'available':
                    logging.info(
                        'Volume detached in %s second(s), trasferring.',
                        int(time.time() - start_at))
                    is_available = True
                    break
                time.sleep(20)
            if not is_available:
                STATE.failed = True
                error(
                    'Volume not ready in time',
                    'Volume did not get ready (available) '
                    'for transfer within %s seconds.',
                    TIMEOUT)
                return
            # Move volumes to the destination project
            transfer = self._run_openstack([
                'volume', 'transfer', 'request', 'create',
                '--format', 'json',
                vol,
                ], data)
            if transfer is None:
                STATE.failed = True
                error('Failed to transfer volume')
                return
            transfer = json.loads(transfer)
            self._run_openstack([
                'volume', 'transfer', 'request', 'accept',
                '--auth-key', transfer['auth_key'],
                transfer['id']
                ], data, destination=True)
        # Create ports
        ports = []
        for nic in data['network_mappings']:
            port_cmd = [
                'port', 'create',
                '--format', 'json',
                '--network', nic['destination'],
                '--mac-address', nic['mac_address'],
                '--enable',
                '%s_port_%s' % (vm_name, len(ports)),
                ]
            if 'ip_address' in nic:
                ipaddr = nic['ip_address']
                subnets_cmd = [
                    'subnet', 'list',
                    '--network', nic['destination'],
                    '-f', 'json'
                ]
                subnets_json = self._run_openstack(subnets_cmd, data)
                if subnets_json is not None:
                    subnets = json.loads(subnets_json)
                    for subnet in subnets:
                        network = subnet["Subnet"]
                        if self._check_ip_in_network(ipaddr, network):
                            port_cmd.extend([
                                '--fixed-ip',
                                'ip-address=%s' % ipaddr,
                            ])
                            break
            for grp in data['osp_security_groups_ids']:
                port_cmd.extend(['--security-group', grp])
            port = self._run_openstack(port_cmd, data, destination=True)
            if port is None:
                STATE.failed = True
                error('Failed to create port')
                return
            port = json.loads(port)
            logging.info('Created port id=%s', port['id'])
            ports.append(port['id'])
        STATE.internal['ports'] = ports
        # Create instance
        os_command = [
            'server', 'create',
            '--format', 'json',
            '--flavor', data['osp_flavor_id'],
            ]
        for grp in data['osp_security_groups_ids']:
            os_command.extend(['--security-group', grp])
        os_command.extend(['--volume', volumes[0]])
        for i in range(1, len(volumes)):
            os_command.extend([
                '--block-device-mapping',
                '%s=%s' % (self._get_disk_name(i+1), volumes[i]),
                ])
        for port in ports:
            os_command.extend(['--nic', 'port-id=%s' % port])
        os_command.append(vm_name)
        # Let's get rolling...
        vm = self._run_openstack(os_command, data, destination=True)
        if vm is None:
            STATE.failed = True
            error('Create VM failed')
            return
        else:
            vm = json.loads(vm)
            STATE.vm_id = str(vm.get('id'))
            STATE.write()
            logging.info('Created Openstack instance with id=%s', STATE.vm_id)
            return

    def check_install_drivers(self, data):
        # Nothing to do for Openstack
        pass

    def prepare_command(self, data, v2v_args, v2v_env, v2v_caps):
        """ Prepare virt-v2v command parts that are method dependent """
        v2v_args.extend([
            '-o', 'openstack',
            '-oo', 'server-id=%s' % data['osp_server_id'],
            '-oo', 'guest-id=%s' % data['osp_guest_id'],
            ])
        # Convert to arguments of the form os-something
        for k, v in six.iteritems(data['osp_environment']):
            v2v_args.extend([
                '-oo',
                '%s=%s' % (k.lower().replace('_', '-'), v)])
        if 'osp_volume_type_id' in data:
            v2v_args.extend([
                '-os', data['osp_volume_type_id'],
                ])
        if data['insecure_connection']:
            v2v_args.extend([
                '-oo', 'verify-server-certificate=false'
                ])
        return v2v_args, v2v_env

    def set_user(self, data):
        """ Possibly switch to different user """
        # Check we are running as root
        uid = os.geteuid()
        if uid != 0:
            sys.stderr.write('Need to run as root!\n')
            sys.exit(1)

    def validate_data(self, data):
        """ Validate input data, fill in defaults, etc """
        # Check necessary keys
        for k in [
                'osp_destination_project_id',
                'osp_environment',
                'osp_flavor_id',
                'osp_security_groups_ids',
                'osp_server_id',
                ]:
            if k not in data:
                hard_error('Missing argument: %s' % k)
        if 'insecure_connection' not in data:
            data['insecure_connection'] = False
        if data.get('insecure_connection', False):
            logging.info(
                'SSL verification is disabled for OpenStack connections')
        openstack_arg_re = re.compile('os[-_]', re.IGNORECASE)
        for k in data['osp_environment'].keys():
            if not openstack_arg_re.match(k[:3]):
                hard_error('found invalid key in Openstack environment: %s'
                           % k)
        if 'osp_guest_id' not in data:
            data['osp_guest_id'] = uuid.uuid4()
        if not isinstance(data['osp_security_groups_ids'], list):
            hard_error('osp_security_groups_ids must be a list')
        for mapping in data['network_mappings']:
            if 'mac_address' not in mapping:
                hard_error('Missing mac address in one of network mappings')
        if data['two_phase']:
            hard_error('Two-phase conversion is not supported for '
                       'Openstack host')
        return data

    def _check_ip_in_network(self, ipaddr, network):
        [netaddr, netsize] = network.split('/')
        netsize = int(netsize)
        ip_prefix_bin = self._get_prefix_bin(ipaddr, netsize)
        net_prefix_bin = self._get_prefix_bin(netaddr, netsize)
        if ip_prefix_bin == net_prefix_bin:
            return True
        return False

    def _ip_to_binary(self, ipaddr):
        octet_list_int = ipaddr.split('.')
        octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
        return ('').join(octet_list_bin)

    def _get_prefix_bin(self, ipaddr, netsize):
        ipaddr_bin = self._ip_to_binary(ipaddr)
        return ipaddr_bin[0:32-(32-netsize)]

    def _get_disk_name(self, index):
        if index < 1:
            raise ValueError('Index less then 1', index)
        if index > 702:
            raise ValueError('Index too large', index)
        index = index - 1
        one = index // 26
        two = index % 26
        enumid = (lambda i: chr(ord('a') + i))
        return 'vd%s%s' % ('' if one == 0 else enumid(one-1), enumid(two))

    def _run_openstack(self, cmd, data, destination=False):
        """
        Run the openstack commands with necessary arguments. When @destination
        is True the command is run in destination project. Otherwise it is run
        in current project.
        """
        command = ['openstack']
        if data.get('insecure_connection', False):
            command.append('--insecure')
        # Convert to arguments of the form os-something
        for k, v in six.iteritems(data['osp_environment']):
            command.append('--%s=%s' % (k.lower().replace('_', '-'), v))
        if destination:
            # It doesn't matter if there already is --os-project-name or
            # --os-project-id. The last argument takes precedence.
            command.append('--os-project-id=%s' %
                           data['osp_destination_project_id'])
        command.extend(cmd)
        log_command_safe(command, {})
        try:
            return subprocess.check_output(command, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            # NOTE: Do NOT use logging.exception() here as it leaks passwords
            # into the log!
            logging.error(
                'Command exited with non-zero return code %d, output:\n%s\n',
                e.returncode, e.output)
            return None


OvirtDisk = namedtuple('OvirtDisk', ['id', 'index'])
OvirtDiskAttachment = namedtuple('OvirtDiskAttachment', ['disk_id',
                                                         'attachment_id'])


class OvirtHost(_BaseHost):
    """ Encapsulates data and methods specific to oVirt/RHV environment """

    # TODO: remove once virt-v2v supports global trust store
    CA_PATH = '/etc/pki/ca-trust/source/anchors'
    CA_FILE = 'v2v-conversion-host-ca-bundle.pem'

    def __init__(self):
        super(OvirtHost, self).__init__()
        import ovirtsdk4 as sdk
        self.sdk = sdk
        # For now there are limited possibilities in how we can select
        # allocation type and format. The best thing we can do now is to base
        # the allocation on type of target storage domain.
        self.PREALLOCATED_STORAGE_TYPES = (
            self.sdk.types.StorageType.CINDER,
            self.sdk.types.StorageType.FCP,
            self.sdk.types.StorageType.GLUSTERFS,
            self.sdk.types.StorageType.ISCSI,
            self.sdk.types.StorageType.POSIXFS,
            )
        self._conversion_vm = None
        self._vm_name = None
        self._created_disks = []
        self._attached_disks = []

    @contextmanager
    def sdk_connection(self, data):
        connection = None
        url = urlparse(data['rhv_url'])
        username = url.username if url.username is not None \
            else 'admin@internal'
        try:
            insecure = data['insecure_connection']
            connection = self.sdk.Connection(
                url=str(data['rhv_url']),
                username=str(username),
                password=str(data['rhv_password']),
                log=logging.getLogger(),
                debug=data.get('rhv_debug', False),
                insecure=insecure,
            )
            yield connection
        finally:
            if connection is not None:
                connection.close()

    def _get_vm(self, system_service, vm_name):
        vms = system_service.vms_service().list(search='name="%s"' % vm_name)
        if len(vms) > 1:
            raise RuntimeError('Multiple VMs found after conversion')
        if len(vms) != 1:
            return None
        return vms[0]

    def _wait_for_ovirt_disks(self, disks_service):
        endt = time.time() + TIMEOUT
        wait_for_disks = self._created_disks[:]
        while wait_for_disks:
            for disk in wait_for_disks[:]:
                st = disks_service.disk_service(disk.id).get().status
                if st == self.sdk.types.DiskStatus.OK:
                    wait_for_disks.remove(disk)
                    STATE.pre_copy.disks[disk.index].status = 'Created'
                    STATE.write()

            if wait_for_disks:
                if endt < time.time():
                    raise RuntimeError('Timed out waiting for disks '
                                       'to become unlocked')
                time.sleep(1)

    def _wait_for_local_disks(self, paths):
        logging.debug('Waiting for all disks to get plugged/noticed')
        wait_for_paths = paths[:]
        endt = time.time() + TIMEOUT
        while wait_for_paths:
            for path in wait_for_paths[:]:
                if os.path.exists(path):
                    wait_for_paths.remove(path)
            if wait_for_paths:
                if endt < time.time():
                    raise RuntimeError('Timed out waiting for disks '
                                       'to get plugged/noticed')
                time.sleep(1)

        for path in paths:
            add_perms_to_file(path,
                              stat.S_IRGRP | stat.S_IWGRP,
                              -1, self.get_gid())

    def _create_disks(self, disks_service, data):
        if not STATE.pre_copy.disks:
            RuntimeError('Looks like no disks were detected')

        if data['output_format'] == 'raw':
            disk_format = self.sdk.types.DiskFormat.RAW
        elif data['output_format'] == 'qcow2':
            disk_format = self.sdk.types.DiskFormat.COW

        for i, pc_disk in enumerate(STATE.pre_copy.disks):
            dt = datetime.datetime.now(datetime.timezone.utc).ctime()
            name = '%s_Disk%d' % (data['vm_name'], i + 1)
            logging.debug('Creating disk #%d: "%s"', i, name)
            disk = self.sdk.types.Disk(
                name=name,
                description='Converted from VMware on %s' % dt,
                format=disk_format,
                initial_size=pc_disk.size,
                provisioned_size=pc_disk.size,
                sparse=data['allocation'] == 'sparse',
                shareable=True,
                storage_domains=[
                    self.sdk.types.StorageDomain(name=data['rhv_storage'])
                ])
            pc_disk.status = 'Creating'
            STATE.write()
            disk = disks_service.add(disk)
            disk = disks_service.disk_service(disk.id)
            # Adding it here so that it gets tried to be cleaned up even if
            # the timeout is reached
            d = disk.get()
            self._created_disks.append(OvirtDisk(d.id, i))

        self._wait_for_ovirt_disks(disks_service)

    def _remove_disks(self, system_service):
        disks_service = system_service.disks_service()
        self._delete_disks(disks_service, [d.id for d in self._created_disks])

    def _attach_disks(self, system_service):
        paths = []
        arguments = dict(active=True,
                         bootable=False,
                         interface=self.sdk.types.DiskInterface.VIRTIO)
        arguments['vm'] = self._conversion_vm
        arguments['description'] = ('Temporary attachment for pre_copy '
                                    'of VM %s' % self._vm_name)

        vm_svc = system_service.vms_service().vm_service(arguments['vm'].id)
        das = vm_svc.disk_attachments_service()

        disks_service = system_service.disks_service()
        ndisks = len(self._created_disks)
        for i, v in enumerate(self._created_disks):
            logging.debug('Attaching disk %d/%d to the conversion VM',
                          i, ndisks)
            kwargs = arguments.copy()
            kwargs['disk'] = disks_service.disk_service(v.id).get()
            disk_att = das.add(self.sdk.types.DiskAttachment(**kwargs))
            self._attached_disks.append(disk_att)
            local_path = '/dev/disk/by-id/virtio-%s' % disk_att.id[:20]
            STATE.pre_copy.disks[v.index].local_path = local_path
            paths.append(local_path)

        self._wait_for_local_disks(paths)

    def _update_disks(self, conn):
        if STATE.vm_id is None:
            STATE.failed = True
            error("No vm_id parsed from virt-v2v output")
            return

        vms_service = conn.system_service().vms_service()
        vm = vms_service.vm_service(STATE.vm_id)
        das = vm.disk_attachments_service()
        for i, att in enumerate(das.list()):
            logging.debug('Updating shareable state of disk #%d', i)
            disk = conn.follow_link(att.disk)
            att.disk = disk
            att.disk.shareable = False
            das.attachment_service(att.id).update(att)

    def _detach_disks(self, system_service, vm):
        vms = system_service.vms_service().vm_service(vm.id)
        das = vms.disk_attachments_service()
        # Let's keep the list of attached disks, so that we can unplug it from
        # both VMs in case of an error
        disks = self._attached_disks[:]
        for att in disks:
            da = das.attachment_service(att.id)

            logging.debug('Deactivating disk attachment id=%s' % att.id)
            da.update(self.sdk.types.DiskAttachment(active=False))

        endt = time.time() + TIMEOUT
        while len(disks) > 0:
            for att in disks[:]:
                da = das.attachment_service(att.id).get()
                if not da.active:
                    disks.remove(att)

            if len(disks) > 0:
                if endt < time.time():
                    logging.error('Timed out waiting for deactivation of '
                                  'disk attachments: %r', disks)
                    break
                time.sleep(1)

        disks = self._attached_disks[:]
        for att in disks:
            da = das.attachment_service(att.id)

            logging.debug('Deactivating disk attachment id=%s' % att.id)
            da.remove()

        endt = time.time() + TIMEOUT
        while len(disks) > 0:
            for att in disks[:]:
                da = das.attachment_service(att.id)
                try:
                    da.get()
                except self.sdk.NotFoundError:
                    disks.remove(att)

            if len(disks) > 0:
                if endt < time.time():
                    logging.error('Timed out waiting for removal of '
                                  'disk attachments: %r', disks)
                    break
                time.sleep(1)

        if len(disks) > 0:
            STATE.failed = True
            error('Timed out waiting for attachments: %s' % disks)

    def prepare_disks(self, data):
        with self.sdk_connection(data) as conn:
            system_service = conn.system_service()
            disks_service = system_service.disks_service()
            self._create_disks(disks_service, data)
            self._attach_disks(system_service)

    def handle_cleanup(self, data):
        with self.sdk_connection(data) as conn:
            system_service = conn.system_service()
            # We could probably just clean up everything no matter whether it's
            # two phase or not.
            if data['two_phase']:
                self._handle_twophase_cleanup(system_service, data)
            else:
                self._handle_simple_cleanup(system_service, data)

    def handle_finish(self, data):
        if data['two_phase']:
            with self.sdk_connection(data) as conn:
                system_service = conn.system_service()
                self._detach_disks(system_service, self._conversion_vm)
                self._update_disks(conn)

    def _handle_twophase_cleanup(self, system_service, data):
        self._detach_disks(system_service, self._conversion_vm)
        if STATE.vm_id:
            vm = system_service.vms_service().vm_service(STATE.vm_id)
            self._detach_disks(system_service, vm.get())
            vm.remove()
        self._remove_disks(system_service)

    def _handle_simple_cleanup(self, system_service, data):
        transfers_service = system_service.image_transfers_service()
        disk_ids = list(STATE.internal['disk_ids'].values())
        # First stop all active transfers...
        try:
            transfers = transfers_service.list()
            transfers = [t for t in transfers if t.image.id in disk_ids]
            if len(transfers) == 0:
                logging.debug('No active transfers to cancel')
            for transfer in transfers:
                logging.info('Canceling transfer id=%s for disk=%s',
                             transfer.id, transfer.image.id)
                transfer_service = \
                    transfers_service.image_transfer_service(
                        transfer.id)
                transfer_service.cancel()
                # The incomplete disk will be removed automatically
                disk_ids.remove(transfer.image.id)
        except self.sdk.Error:
            logging.exception('Failed to cancel transfers')

        # ... then delete the uploaded disks
        self._delete_disks(system_service.disks_service(), disk_ids)

    def _delete_disks(self, disks_service, disk_ids):
        logging.info('Removing disks: %r', disk_ids)
        endt = time.time() + TIMEOUT
        while len(disk_ids) > 0:
            for disk_id in disk_ids[:]:
                try:
                    disk_service = disks_service.disk_service(str(disk_id))
                    disk = disk_service.get()
                    if disk.status != self.sdk.types.DiskStatus.OK:
                        continue
                    logging.info('Removing disk id=%s', disk_id)
                    disk_service.remove()
                except self.sdk.NotFoundError:
                    logging.info('Disk id=%s does not exist (already '
                                 'removed?), skipping it',
                                 disk_id)
                except self.sdk.Error:
                    logging.exception('Failed to remove disk id=%s',
                                      disk_id)
                disk_ids.remove(disk_id)
            # Avoid checking timeouts, and waiting, if there are no
            # more disks to remove
            if len(disk_ids) > 0:
                if endt < time.time():
                    logging.error('Timed out waiting for disks: %r',
                                  disk_ids)
                    break
                time.sleep(1)

    def prepare_command(self, data, v2v_args, v2v_env, v2v_caps):
        output_format = data['output_format']
        allocation = data.get('allocation')

        if STATE.pre_copy is not None:
            output_format = 'raw'
            allocation = 'sparse'

        v2v_args.extend([
            '--bridge', 'ovirtmgmt',
            '-of', output_format,
            ])
        if allocation is not None:
            v2v_args.extend([
                '-oa', allocation
                ])

        if 'rhv_url' in data:
            verifypeer = str(not data['insecure_connection']).lower()
            v2v_args.extend([
                '-o', 'rhv-upload',
                '-oc', data['rhv_url'],
                '-os', data['rhv_storage'],
                '-op', data['rhv_password_file'],
                # TODO: remove once virt-v2v supports global trust store
                '-oo', 'rhv-cafile=%s/%s' % (self.CA_PATH, self.CA_FILE),
                '-oo', 'rhv-cluster=%s' % data['rhv_cluster'],
                '-oo', 'rhv-direct',
                '-oo', 'rhv-verifypeer=%s' % verifypeer,
                ])
            if STATE.pre_copy is not None:
                for disk in self._created_disks:
                    v2v_args.extend(['-oo', 'rhv-disk-uuid=' + disk.id])

        return v2v_args, v2v_env

    def get_uid(self):
        """ Tell under which user to run virt-v2v """
        return 0

    def get_gid(self):
        """ Tell under which group to run virt-v2v """
        return 0

    def validate_data(self, data):
        """ Validate input data, fill in defaults, etc """
        # First, the connection options
        if 'insecure_connection' not in data:
            data['insecure_connection'] = False
        if data['insecure_connection']:
            logging.info(
                'SSL verification is disabled for oVirt SDK connections')

        # Output file format (raw or qcow2)
        if 'output_format' in data:
            if data['output_format'] not in ('raw', 'qcow2'):
                hard_error('Invalid output format %r, expected raw or qcow2' %
                           data['output_format'])
        else:
            data['output_format'] = 'raw'

        # Targets (only rhv_url domain for now)
        if 'rhv_url' in data:
            for k in [
                    'rhv_cluster',
                    'rhv_password',
                    'rhv_storage',
                    ]:
                if k not in data:
                    hard_error('Missing argument: %s' % k)
        else:
            hard_error('No target specified')

        if data['two_phase']:
            if 'rhv_url' not in data:
                hard_error('Two-phase conversion is '
                           'only supported with "rhv_url"')

        if 'rhv_url' in data:
            with self.sdk_connection(data) as c:
                vm_svc = c.system_service().vms_service()
                vms = vm_svc.list(search='name=' + data['vm_name'])
                if len(vms) > 0:
                    hard_error('VM with the name "%s" already exists on the '
                               'destination' % data['vm_name'])

                if 'allocation' not in data:
                    # Check storage domain type and decide on suitable
                    # allocation type Note: This is only temporary. We should
                    # get the info from the caller in the future.
                    domain_type = None
                    service = c.system_service().storage_domains_service()
                    domains = service.list(search='name="%s"' %
                                           str(data['rhv_storage']))
                    if len(domains) != 1:
                        hard_error('Found %d domains matching "%s"!' %
                                   (len(domains), data['rhv_storage']))
                    domain_type = domains[0].storage.type
                    logging.info('Storage domain "%s" is of type %r',
                                 data['rhv_storage'], domain_type)
                    data['allocation'] = 'sparse'
                    if domain_type in self.PREALLOCATED_STORAGE_TYPES:
                        data['allocation'] = 'preallocated'
                    logging.info('... selected allocation type is %s',
                                 data['allocation'])

                # We cannot reliably check that we are running on a VM with the
                # specified UUID in `conversion_host_uuid` (otherwise we would
                # not need the ID in the input in the first place), but we can
                # at least fail early if the machine does not exist or if it is
                # not up.
                if data['two_phase']:
                    try:
                        vm_uuid = str(data['conversion_host_uuid'])
                        vm = vm_svc.vm_service(vm_uuid)
                        vm = vm.get()
                        if vm.status != self.sdk.types.VmStatus.UP:
                            hard_error('VM %s is not running,\n'
                                       'how can this script be running on '
                                       'a machine that is not up?' %
                                       data['conversion_host_uuid'])
                    except self.sdk.NotFoundError:
                        hard_error('VM %s not found,\n'
                                   'how can this script be running on a '
                                   'machine that does not exist?' %
                                   data['conversion_host_uuid'])
                    self._conversion_vm = vm

        self._vm_name = data['vm_name']
