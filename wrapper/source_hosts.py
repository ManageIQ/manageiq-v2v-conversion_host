""" Source hosts

Some migration sources require significant setup before they can export block
devices with nbdkit. This module holds the code used to set up nbdkit exports
on such sources.

For example, the current OpenStack export strategy is to shut down the source
VM, attach its volumes to a source conversion host, and export the volumes from
inside the conversion host via nbdkit. The OpenStackSourceHost class will take
care of the process up to this point, and some other class in the regular hosts
module will take care of copying the data from those exports to their final
migration destination. There is an exception for KVM-to-KVM migrations though,
because those aren't supposed to use virt-v2v - in this case, this module will
transfer the data itself instead of calling the main wrapper function.
"""

import errno
import fcntl
import json
import logging
import os
import subprocess
import time
from collections import namedtuple

from .common import VDDK_LIBDIR
from .hosts import OpenstackHost
from .state import STATE, Disk
from .pre_copy import PreCopy


NBD_READY_SENTINEL = 'nbdready'  # Created when nbdkit exports are ready
DEFAULT_TIMEOUT = 600            # Maximum wait for openstacksdk operations

# Lock to serialize volume attachments. This helps prevent device path
# mismatches between the OpenStack SDK and /dev in the VM.
ATTACH_LOCK_FILE_SOURCE = '/var/lock/v2v-source-volume-lock'
ATTACH_LOCK_FILE_DESTINATION = '/var/lock/v2v-destination-volume-lock'

# Local directory to copy logs from source conversion host
SOURCE_LOGS_DIR = '/data/source_logs'


def detect_source_host(data, agent_sock):
    """ Create the right source host object based on the input data. """
    if 'osp_source_environment' in data:
        return OpenStackSourceHost(data, agent_sock)
    return None


def avoid_wrapper(source_host, host):
    """
    Check if this combination of source and destination host should avoid
    running virt-v2v.
    """
    return source_host and source_host.avoid_wrapper(host)


def migrate_instance(source_host, host):
    """ Run all the pieces of a source_host migration. """
    if source_host:
        try:
            source_host.prepare_exports()
            source_host.transfer_exports(host)
            source_host.close_exports()
        except RuntimeError:
            logging.error('Got error migrating instance, attempting cleanup.')
            source_host.close_exports()
            raise
    else:
        logging.info('Ignoring migration request for empty source_host.')


def _use_lock(lock_file):
    """ Boilerplate for functions that need to take a lock. """
    def _decorate_lock(function):
        def wait_for_lock(self):
            with open(lock_file, 'wb+') as lock:
                for second in range(DEFAULT_TIMEOUT):
                    try:
                        logging.info('Waiting for lock %s...', lock_file)
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError:
                        logging.info('Another conversion has the lock.')
                        time.sleep(1)
                else:
                    raise RuntimeError(
                        'Unable to acquire lock {}!'.format(lock_file))
                try:
                    function(self)
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
        return wait_for_lock
    return _decorate_lock


class _BaseSourceHost(object):
    """ Interface for source hosts. """

    def prepare_exports(self):
        """ Creates the nbdkit exports from the migration source. """
        logging.info('No preparation needed for this migration source.')

    def close_exports(self):
        """ Stops the nbdkit exports on the migration source. """
        logging.info('No cleanup needed for this migration source.')

    def transfer_exports(self, host):
        """ Performs a data copy to a destination host. """
        logging.info('No transfer ability for this migration source.')

    def avoid_wrapper(self, host):
        """ Decide whether or not to avoid running virt-v2v. """
        logging.info('No reason to avoid virt-v2v from this migration source.')
        return True


VolumeMapping = namedtuple('VolumeMapping', [
    'source_dev',  # Device path (like /dev/vdb) on source conversion host
    'source_id',   # Volume ID on source conversion host
    'dest_dev',    # Device path on destination conversion host
    'dest_id',     # Volume ID on destination conversion host
    'snap_id',     # Root volumes need snapshot+new volume
    'image_id',    # Direct-from-image VMs create temporary snapshot image
    'name',        # Save volume name to set on destination
    'size',        # Volume size reported by OpenStack, in GB
    'url',         # Final NBD export address from source conversion host
    'state'        # STATE.Disk object for tracking progress
])


class OpenStackSourceHost(_BaseSourceHost):
    """ Export volumes from an OpenStack instance. """

    def __init__(self, data, agent_sock):
        try:
            import openstack
        except ImportError:
            raise RuntimeError('OpenStack SDK is not installed on this '
                               'conversion host!')
        osp_arg_list = ['os-auth_url', 'os-username', 'os-password',
                        'os-project_name', 'os-project_domain_name',
                        'os-user_domain_name']

        # Create a connection to the source cloud
        osp_env = data['osp_source_environment']
        osp_args = {arg[3:].lower(): osp_env[arg] for arg in osp_arg_list}
        osp_args['verify'] = not data.get('insecure_connection', False)
        self.source_converter = data['osp_source_conversion_vm_id']
        self.source_instance = data['osp_source_vm_id']
        self.conn = openstack.connect(**osp_args)

        # Create a connection to the destination cloud
        osp_env = data['osp_environment']
        osp_args = {arg[3:].lower(): osp_env[arg] for arg in osp_arg_list}
        osp_args['verify'] = not data.get('insecure_connection', False)
        self.dest_converter = data['osp_server_id']
        self.dest_conn = openstack.connect(**osp_args)

        self.agent_sock = agent_sock
        openstack.enable_logging(debug=False, http_debug=False, stream=None)

        if self._converter() is None:
            raise RuntimeError('Cannot find source instance {}'.format(
                               self.source_converter))
        if self._destination() is None:
            raise RuntimeError('Cannot find destination instance {}'.format(
                               self.dest_converter))

        # Build up a list of VolumeMappings keyed by the original device path
        self.volume_map = {}

        # Temporary directory for logs on source conversion host
        self.tmpdir = None

        # SSH tunnel process
        self.forwarding_process = None

        # If there is a specific list of disks to transfer, remember them so
        # only those disks get transferred.
        self.source_disks = None
        if 'source_disks' in data:
            self.source_disks = data['source_disks']

        # Allow UCI container ID (or name) to be passed in input JSON
        self.uci_container = data.get('uci_container', 'v2v-conversion-host')

    def prepare_exports(self):
        """ Attach the source VM's volumes to the source conversion host. """
        self._test_ssh_connection()
        self._test_source_vm_shutdown()
        self._get_root_and_data_volumes()
        self._detach_data_volumes_from_source()
        self._attach_volumes_to_converter()
        self._export_volumes_from_converter()

    def close_exports(self):
        """ Put the source VM's volumes back where they were. """
        self._converter_close_exports()
        self._detach_volumes_from_converter()
        self._attach_data_volumes_to_source()

    def transfer_exports(self, host):
        self._create_destination_volumes()
        self._attach_destination_volumes()
        self._convert_destination_volumes()
        self._detach_destination_volumes()

    def avoid_wrapper(self, host):
        """ Assume OpenStack to OpenStack migrations are always KVM to KVM. """
        if isinstance(host, OpenstackHost):
            logging.info('OpenStack->OpenStack migration, skipping virt-v2v.')
            return True
        return False

    def _source_vm(self):
        """
        Changes to the VM returned by get_server_by_id are not necessarily
        reflected in existing objects, so just get a new one every time.
        """
        return self.conn.get_server_by_id(self.source_instance)

    def _converter(self):
        """ Same idea as _source_vm, for source conversion host. """
        return self.conn.get_server_by_id(self.source_converter)

    def _destination(self):
        """ Same idea as _source_vm, for destination conversion host. """
        return self.dest_conn.get_server_by_id(self.dest_converter)

    def _ssh_args(self):
        """ Provide default set of SSH options. """
        return [
            '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'ConnectTimeout=10',
        ]

    def _ssh_cmd(self, address, args):
        """ Build an SSH command and environment using the running agent. """
        environment = os.environ.copy()
        environment['SSH_AUTH_SOCK'] = self.agent_sock
        command = ['ssh']
        command.extend(self._ssh_args())
        command.extend(['cloud-user@'+address])
        command.extend(args)
        return command, environment

    def _destination_out(self, args):
        """ Run a command on the dest conversion host and get the output. """
        address = self._destination().accessIPv4
        command, environment = self._ssh_cmd(address, args)
        output = subprocess.check_output(command, env=environment)
        return output.decode('utf-8').strip()

    def _converter_out(self, args):
        """ Run a command on the source conversion host and get the output. """
        address = self._converter().accessIPv4
        command, environment = self._ssh_cmd(address, args)
        output = subprocess.check_output(command, env=environment)
        return output.decode('utf-8').strip()

    def _converter_val(self, args):
        """ Run a command on the source conversion host and get return code """
        address = self._converter().accessIPv4
        command, environment = self._ssh_cmd(address, args)
        return subprocess.call(command, env=environment)

    def _converter_sub(self, args):
        """ Run a long-running command on the source conversion host. """
        address = self._converter().accessIPv4
        command, environment = self._ssh_cmd(address, args)
        return subprocess.Popen(command, env=environment)

    def _converter_scp(self, source, dest):
        """ Copy a file to the source conversion host. """
        environment = os.environ.copy()
        environment['SSH_AUTH_SOCK'] = self.agent_sock
        address = self._converter().accessIPv4
        command = ['scp']
        command.extend(self._ssh_args())
        command.extend([source, 'cloud-user@'+address+':'+dest])
        return subprocess.call(command, env=environment)

    def _converter_scp_from(self, source, dest, recursive=False):
        """ Copy a file from the source conversion host. """
        environment = os.environ.copy()
        environment['SSH_AUTH_SOCK'] = self.agent_sock
        address = self._converter().accessIPv4
        command = ['scp']
        command.extend(self._ssh_args())
        if recursive:
            command.extend(['-r'])
        command.extend(['cloud-user@'+address+':'+source, dest])
        return subprocess.call(command, env=environment)

    def _test_ssh_connection(self):
        """ Quick SSH connectivity check for source conversion host. """
        out = self._converter_out(['echo connected'])
        if out != 'connected':
            raise RuntimeError('Unable to SSH to source conversion host!')

    def _test_source_vm_shutdown(self):
        """ Make sure the source VM is shutdown, and fail if it isn't. """
        server = self.conn.compute.get_server(self._source_vm().id)
        if server.status != 'SHUTOFF':
            raise RuntimeError('Source VM is not shut down!')

    def _get_attachment(self, volume, vm):
        """
        Get the attachment object from the volume with the matching server ID.
        Convenience method for use only when the attachment is already certain.
        """
        for attachment in volume.attachments:
            if attachment.server_id == vm.id:
                return attachment
        raise RuntimeError('Volume is not attached to the specified instance!')

    def _get_root_and_data_volumes(self):
        """
        Volume mapping step one: get the IDs and sizes of all volumes on the
        source VM. Key off the original device path to eventually preserve this
        order on the destination.
        """
        sourcevm = self._source_vm()
        for server_volume in sourcevm.volumes:
            volume = self.conn.get_volume_by_id(server_volume['id'])
            logging.info('Inspecting volume: %s', volume.id)
            if self.source_disks and volume.id not in self.source_disks:
                logging.info('Volume is not in specified disk list, ignoring.')
                continue
            dev_path = self._get_attachment(volume, sourcevm).device
            disk = Disk(dev_path, 0)
            self.volume_map[dev_path] = VolumeMapping(
                source_dev=None, source_id=volume.id, dest_dev=None,
                dest_id=None, snap_id=None, image_id=None, name=volume.name,
                size=volume.size, url=None, state=disk)
            STATE.disks.append(disk)
            logging.debug('STATE.disks is now %s', STATE.disks)
            STATE.write()

    def _detach_data_volumes_from_source(self):
        """
        Detach data volumes from source VM, and pretend to "detach" the boot
        volume by creating a new volume from a snapshot of the VM. If the VM is
        booted directly from an image, take a VM snapshot and create the new
        volume from that snapshot.
        Volume map step two: replace boot disk ID with this new volume's ID,
        and record snapshot/image ID for later deletion.
        """
        sourcevm = self._source_vm()
        if '/dev/vda' in self.volume_map:
            mapping = self.volume_map['/dev/vda']
            volume_id = mapping.source_id

            # Create a snapshot of the root volume
            logging.info('Creating root device snapshot')
            root_snapshot = self.conn.create_volume_snapshot(
                force=True, wait=True, volume_id=volume_id,
                name='rhosp-migration-{}'.format(volume_id),
                timeout=DEFAULT_TIMEOUT)

            # Create a new volume from the snapshot
            logging.info('Creating new volume from root snapshot')
            root_volume_copy = self.conn.create_volume(
                wait=True, name='rhosp-migration-{}'.format(volume_id),
                snapshot_id=root_snapshot.id, size=root_snapshot.size,
                timeout=DEFAULT_TIMEOUT)

            # Update the volume map with the new volume ID
            self.volume_map['/dev/vda'] = mapping._replace(
                source_id=root_volume_copy.id,
                snap_id=root_snapshot.id)
        elif sourcevm.image:
            logging.info('Image-based instance, creating snapshot...')
            image = self.conn.compute.create_server_image(
                name='rhosp-migration-root-{}'.format(sourcevm.name),
                server=sourcevm.id)
            for second in range(DEFAULT_TIMEOUT):
                refreshed_image = self.conn.get_image_by_id(image.id)
                if refreshed_image.status == 'active':
                    break
                time.sleep(1)
            else:
                raise RuntimeError(
                    'Could not create new image of image-based instance!')
            volume = self.conn.create_volume(
                image=image.id, bootable=True, wait=True, name=image.name,
                timeout=DEFAULT_TIMEOUT, size=image.min_disk)
            disk = Disk('/dev/vda', 0)
            self.volume_map['/dev/vda'] = VolumeMapping(
                source_dev=None, source_id=volume.id, dest_dev=None,
                dest_id=None, snap_id=None, image_id=image.id,
                name=volume.name, size=volume.size, url=None, state=disk)
            STATE.disks.append(disk)
            logging.debug('STATE.disks is now %s', STATE.disks)
            STATE.write()
        else:
            raise RuntimeError('No known boot device found for this instance!')

        for path, mapping in self.volume_map.items():
            if path != '/dev/vda':  # Detach non-root volumes
                volume_id = mapping.source_id
                volume = self.conn.get_volume_by_id(volume_id)
                logging.info('Detaching %s from %s', volume.id, sourcevm.id)
                self.conn.detach_volume(server=sourcevm, volume=volume,
                                        wait=True, timeout=DEFAULT_TIMEOUT)

    def _wait_for_volume_dev_path(self, conn, volume, vm, timeout):
        volume_id = volume.id
        for second in range(timeout):
            volume = conn.get_volume_by_id(volume_id)
            if volume.attachments:
                attachment = self._get_attachment(volume, vm)
                if attachment.device.startswith('/dev/'):
                    return
            time.sleep(1)
        raise RuntimeError('Timed out waiting for volume device path!')

    def _attach_volumes(self, conn, name, funcs):
        """
        Attach all volumes in the volume map to the specified conversion host.
        Check the list of disks before and after attaching to be absolutely
        sure the right source data gets copied to the right destination disk.
        This is here because _attach_destination_volumes and
        _attach_volumes_to_converter looked almost identical.
        """
        logging.info('Attaching volumes to %s wrapper', name)
        host_func, ssh_func, update_func, volume_id_func = funcs
        for path, mapping in sorted(self.volume_map.items()):
            volume_id = volume_id_func(mapping)
            volume = conn.get_volume_by_id(volume_id)
            logging.info('Attaching %s to %s conversion host', volume_id, name)

            disks_before = ssh_func(['lsblk', '--noheadings', '--list',
                                     '--paths', '--nodeps', '--output NAME'])
            disks_before = set(disks_before.split())
            logging.debug('Initial disk list: %s', disks_before)

            conn.attach_volume(volume=volume, wait=True, server=host_func(),
                               timeout=DEFAULT_TIMEOUT)
            logging.info('Waiting for volume to appear in %s wrapper', name)
            self._wait_for_volume_dev_path(conn, volume, host_func(),
                                           DEFAULT_TIMEOUT)

            disks_after = ssh_func(['lsblk', '--noheadings', '--list',
                                    '--paths', '--nodeps', '--output NAME'])
            disks_after = set(disks_after.split())
            logging.debug('Updated disk list: %s', disks_after)

            new_disks = disks_after-disks_before
            volume = conn.get_volume_by_id(volume_id)
            attachment = self._get_attachment(volume, host_func())
            dev_path = attachment.device
            if len(new_disks) == 1:
                if dev_path in new_disks:
                    logging.debug('Successfully attached new disk %s, and %s '
                                  'conversion host path matches OpenStack.',
                                  dev_path, name)
                else:
                    dev_path = new_disks.pop()
                    logging.debug('Successfully attached new disk %s, but %s '
                                  'conversion host path does not match the  '
                                  'result from OpenStack. Using internal '
                                  'device path %s.', attachment.device,
                                  name, dev_path)
            else:
                raise RuntimeError('Got unexpected disk list after attaching '
                                   'volume to {} conversion host instance. '
                                   'Failing migration procedure to avoid '
                                   'assigning volumes incorrectly. New '
                                   'disks(s) inside VM: {}, disk provided by '
                                   'OpenStack: {}'.format(name, new_disks,
                                                          dev_path))
            self.volume_map[path] = update_func(mapping, dev_path)

    # Lock this part to have a better chance of the OpenStack device path
    # matching the device path seen inside the conversion host.
    @_use_lock(ATTACH_LOCK_FILE_SOURCE)
    def _attach_volumes_to_converter(self):
        """
        Attach all the source volumes to the conversion host. Volume mapping
        step 3: fill in the volume's device path on the source conversion host.
        """
        def update_source(volume_mapping, dev_path):
            return volume_mapping._replace(source_dev=dev_path)

        def volume_id(volume_mapping):
            return volume_mapping.source_id

        self._attach_volumes(self.conn, 'source', (self._converter,
                                                   self._converter_out,
                                                   update_source, volume_id))

    def _export_volumes_from_converter(self):
        """
        SSH to source conversion host and start an NBD export. Start the UCI
        with /dev/vdb, /dev/vdc, etc. attached, then pass JSON input to request
        nbdkit exports from the V2V wrapper. Volume mapping step 4: fill in the
        URL to the volume's matching NBD export.
        """
        logging.info('Exporting volumes from source conversion host...')

        # Create a temporary directory on source conversion host
        self.tmpdir = self._converter_out(['mktemp', '-d', '-t', 'v2v-XXXXXX'])
        logging.info('Source conversion host temp dir: %s', self.tmpdir)

        # Choose NBD ports for inside the container
        port = 10809
        port_map = {}          # Map device path to port number, for export_nbd
        reverse_port_map = {}  # Map port number to device path, for forwarding
        nbd_ports = []         # podman arguments for NBD ports
        device_list = []       # podman arguments for block devices
        for path, mapping in self.volume_map.items():
            volume_id = mapping.source_id
            dev_path = mapping.source_dev
            uci_dev_path = mapping.source_dev+'-v2v'
            logging.info('Exporting %s from volume %s', dev_path, volume_id)
            nbd_ports.extend(['-p', '127.0.0.1::{0}'.format(port)])
            device_list.extend(['--device', dev_path+':'+uci_dev_path])
            reverse_port_map[port] = path
            port_map[uci_dev_path] = port
            port += 1

        # Copy the port map as input to the source conversion host wrapper
        self._converter_val(['mkdir', '-p', self.tmpdir+'/lib'])
        self._converter_val(['mkdir', '-p', self.tmpdir+'/log'])
        self._converter_val(['mkdir', '-p', self.tmpdir+'/input'])
        ports = json.dumps({'nbd_export_only': port_map})
        export_input = '/tmp/nbd_conversion.json'
        with open(export_input, 'w+') as conversion:
            conversion.write(ports)
        self._converter_scp(export_input, self.tmpdir+'/input/conversion.json')

        # Run UCI on source conversion host. Create a temporary directory to
        # use as the UCI's /data directory so more than one can run at a time.
        ssh_args = ['sudo', 'podman', 'run', '--detach']
        ssh_args.extend(['--volume', '/var/tmp:/var/tmp:z'])
        ssh_args.extend(['--volume', '/var/lock:/var/lock:z'])
        ssh_args.extend(['--volume', self.tmpdir+':/data:z'])
        ssh_args.extend(['--volume', self.tmpdir+'/lib:/var/lib/uci:z'])
        ssh_args.extend(['--volume', self.tmpdir+'/log:/var/log/uci:z'])
        ssh_args.extend(['--volume', '{0}:{0}'.format(VDDK_LIBDIR)])
        ssh_args.extend(nbd_ports)
        ssh_args.extend(device_list)
        ssh_args.extend([self.uci_container])
        self.uci_id = self._converter_out(ssh_args)
        logging.debug('Source UCI container ID: %s', self.uci_id)

        # Find the ports chosen by podman and forward them
        ssh_args = ['sudo', 'podman', 'port', self.uci_id]
        out = self._converter_out(ssh_args)
        forward_ports = ['-N', '-T']
        for line in out.split('\n'):  # Format: 10809/tcp -> 0.0.0.0:33437
            logging.debug('Forwarding port from podman: %s', line)
            internal_port, _, _ = line.partition('/')
            _, _, external_port = line.rpartition(':')
            try:
                port = int(internal_port)
            except ValueError:
                raise RuntimeError('Could not get port number from podman on '
                                   'source conversion host! Line was '+line)
            path = reverse_port_map[port]
            # The internal_port in the source conversion container is forwarded
            # to external_port on the source conversion host, and then we need
            # any local port on the destination conversion container to forward
            # over SSH to that external_port. For simplicity, just choose the
            # same as internal_port, so both source and destination containers
            # use the same ports for the same NBD volumes. This is worth
            # explaining in detail because otherwise the following arguments
            # may look backwards at first glance.
            forward_ports.extend(['-L',
                                  '{}:localhost:{}'.format(internal_port,
                                                           external_port)])
            mapping = self.volume_map[path]
            url = 'nbd://localhost:'+internal_port
            self.volume_map[path] = mapping._replace(url=url)
            logging.info('Volume map so far: %s', self.volume_map)

        # Get SSH to forward the NBD ports to localhost
        self.forwarding_process = self._converter_sub(forward_ports)

        # Make sure export worked by checking the exports. The conversion
        # host on the source should create an 'nbdready' file after it has
        # started all the nbdkit processes, and after that qemu-img info
        # should be able to read them.
        logging.info('Waiting for NBD exports from source container...')
        sentinel = os.path.join(self.tmpdir, NBD_READY_SENTINEL)
        for second in range(DEFAULT_TIMEOUT):
            if self._converter_val(['test', '-f', sentinel]) == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Timed out waiting for NBD export!')
        for path, mapping in self.volume_map.items():
            cmd = ['qemu-img', 'info', mapping.url]
            image_info = subprocess.check_output(cmd)
            logging.info('qemu-img info for %s: %s', path, image_info)

    def _converter_close_exports(self):
        """
        SSH to source conversion host and close the NBD export. Currently this
        pretty much amounts to just stopping the container.
        """
        logging.info('Stopping export from source conversion host...')
        try:
            out = self._converter_out(['sudo', 'podman', 'stop', self.uci_id])
            logging.info('Closed NBD export with result: %s', out)
        except subprocess.CalledProcessError as err:
            logging.debug('Error stopping UCI container on source: %s', err)

        try:
            # Copy logs from temporary directory locally, and clean up source
            if self.tmpdir:
                os.makedirs(SOURCE_LOGS_DIR, exist_ok=True)
                self._converter_scp_from(self.tmpdir+'/*', SOURCE_LOGS_DIR,
                                         recursive=True)
                self._converter_out(['sudo', 'rm', '-rf', self.tmpdir])
        except subprocess.CalledProcessError as err:
            logging.debug('Error copying logs from source: %s', err)

        if self.forwarding_process:
            self.forwarding_process.terminate()

    def _volume_still_attached(self, volume, vm):
        """ Check if a volume is still attached to a VM. """
        for attachment in volume.attachments:
            if attachment.server_id == vm.id:
                return True
        return False

    @_use_lock(ATTACH_LOCK_FILE_SOURCE)
    def _detach_volumes_from_converter(self):
        """ Detach volumes from conversion host. """
        converter = self._converter()
        for path, mapping in self.volume_map.items():
            volume = self.conn.get_volume_by_id(mapping.source_id)
            logging.info('Inspecting volume %s', volume.id)
            if mapping.source_dev is None:
                logging.info('Volume is not attached to conversion host, '
                             'skipping detach.')
                continue
            self.conn.detach_volume(server=converter, volume=volume,
                                    timeout=DEFAULT_TIMEOUT, wait=True)
            for second in range(DEFAULT_TIMEOUT):
                converter = self._converter()
                volume = self.conn.get_volume_by_id(mapping.source_id)
                if not self._volume_still_attached(volume, converter):
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Timed out waiting to detach volumes from '
                                   'source conversion host!')

    def _attach_data_volumes_to_source(self):
        """ Clean up the copy of the root volume and reattach data volumes. """
        logging.info('Re-attaching volumes to source VM...')
        for path, mapping in sorted(self.volume_map.items()):
            if path == '/dev/vda':
                # Delete the temporary copy of the source root disk
                logging.info('Removing copy of root volume')
                self.conn.delete_volume(name_or_id=mapping.source_id,
                                        wait=True, timeout=DEFAULT_TIMEOUT)

                # Remove the root volume snapshot
                if mapping.snap_id:
                    logging.info('Deleting temporary root device snapshot')
                    self.conn.delete_volume_snapshot(
                        timeout=DEFAULT_TIMEOUT, wait=True,
                        name_or_id=mapping.snap_id)

                # Remove root image copy, for image-launched instances
                if mapping.image_id:
                    logging.info('Deleting temporary root device image')
                    self.conn.delete_image(
                        timeout=DEFAULT_TIMEOUT, wait=True,
                        name_or_id=mapping.image_id)
            else:
                # Attach data volumes back to source VM
                volume = self.conn.get_volume_by_id(mapping.source_id)
                sourcevm = self._source_vm()
                try:
                    self._get_attachment(volume, sourcevm)
                except RuntimeError:
                    logging.info('Attaching %s back to source VM', volume.id)
                    self.conn.attach_volume(volume=volume, server=sourcevm,
                                            wait=True, timeout=DEFAULT_TIMEOUT)
                else:
                    logging.info('Volume %s is already attached to source VM',
                                 volume.id)
                    continue

    def _create_destination_volumes(self):
        """
        Volume mapping step 5: create new volumes on the destination OpenStack,
        and fill in dest_id with the new volumes.
        """
        logging.info('Creating volumes on destination cloud')
        for path, mapping in self.volume_map.items():
            volume_id = mapping.source_id
            volume = self.conn.get_volume_by_id(volume_id)
            new_volume = self.dest_conn.create_volume(
                name=mapping.name, bootable=volume.bootable,
                description=volume.description, size=volume.size, wait=True,
                timeout=DEFAULT_TIMEOUT)
            self.volume_map[path] = mapping._replace(dest_id=new_volume.id)
            STATE.internal['disk_ids'][path] = new_volume.id
        STATE.write()

    @_use_lock(ATTACH_LOCK_FILE_DESTINATION)
    def _attach_destination_volumes(self):
        """
        Volume mapping step 6: attach the new destination volumes to the
        destination conversion host. Fill in the destination device name.
        """
        def update_dest(volume_mapping, dev_path):
            return volume_mapping._replace(dest_dev=dev_path)

        def volume_id(volume_mapping):
            return volume_mapping.dest_id

        self._attach_volumes(self.dest_conn, 'destination',
                             (self._destination, self._destination_out,
                              update_dest, volume_id))

    def _convert_destination_volumes(self):
        """
        Finally run the commands to copy the exported source volumes to the
        local destination volumes. Attempt to sparsify the volumes to minimize
        the amount of data sent over the network.
        """
        logging.info('Converting volumes...')
        for path, mapping in self.volume_map.items():
            logging.info('Converting source VM\'s %s: %s', path, str(mapping))
            overlay = '/tmp/'+os.path.basename(mapping.dest_dev)+'.qcow2'

            def _log_convert(source_disk, source_format, mapping):
                """ Write qemu-img convert progress to the wrapper log. """
                logging.info('Copying volume data...')
                cmd = ['qemu-img', 'convert', '-p', '-f', source_format, '-O',
                       'host_device', source_disk, mapping.dest_dev]
                # Non-blocking output processing stolen from pre_copy.py
                img_sub = subprocess.Popen(cmd,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL,
                                           universal_newlines=True, bufsize=1)
                flags = fcntl.fcntl(img_sub.stdout, fcntl.F_GETFL)
                flags |= os.O_NONBLOCK
                fcntl.fcntl(img_sub.stdout, fcntl.F_SETFL, flags)
                while img_sub.poll() is None:
                    try:
                        line = img_sub.stdout.readline()
                    except OSError as err:
                        if err.errno != errno.EAGAIN:
                            raise
                    if line:
                        matches = PreCopy.qemu_progress_re.search(line)
                        if matches is not None:
                            mapping.state.progress = float(matches.group(1))
                            STATE.write()
                    else:
                        time.sleep(1)
                logging.info('Conversion return code: %d', img_sub.returncode)
                if img_sub.returncode != 0:
                    raise RuntimeError('Failed to convert volume!')
                # Just in case qemu-img returned before readline got to 100%
                mapping.state.progress = 100.0
                STATE.write()

            try:
                logging.info('Attempting initial sparsify...')
                environment = os.environ.copy()
                environment['LIBGUESTFS_BACKEND'] = 'direct'

                cmd = ['qemu-img', 'create', '-f', 'qcow2',
                       '-b', mapping.url, overlay]
                out = subprocess.check_output(cmd)
                logging.info('Overlay output: %s', out)
                logging.info('Overlay size: %s', str(os.path.getsize(overlay)))

                cmd = ['virt-sparsify', '--in-place', overlay]
                with open(STATE.wrapper_log, 'a') as log_fd:
                    img_sub = subprocess.Popen(cmd,
                                               stdout=log_fd,
                                               stderr=subprocess.STDOUT,
                                               stdin=subprocess.DEVNULL,
                                               env=environment)
                    returncode = img_sub.wait()
                    logging.info('Sparsify return code: %d', returncode)
                    if returncode != 0:
                        raise RuntimeError('Failed to convert volume!')

                _log_convert(overlay, 'qcow2', mapping)
            except (OSError, subprocess.CalledProcessError):
                logging.info('Sparsify failed, converting whole device...')
                if os.path.isfile(overlay):
                    os.remove(overlay)
                _log_convert(mapping.url, 'raw', mapping)

    @_use_lock(ATTACH_LOCK_FILE_DESTINATION)
    def _detach_destination_volumes(self):
        """ Disconnect new volumes from destination conversion host. """
        logging.info('Detaching volumes from destination wrapper.')
        for path, mapping in self.volume_map.items():
            volume_id = mapping.dest_id
            volume = self.dest_conn.get_volume_by_id(volume_id)
            self.dest_conn.detach_volume(server=self._destination(),
                                         timeout=DEFAULT_TIMEOUT,
                                         volume=volume,
                                         wait=True)
