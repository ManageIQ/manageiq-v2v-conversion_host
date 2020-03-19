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

import fcntl
import json
import logging
import openstack
import os
import subprocess
import time
from collections import namedtuple


NBD_READY_SENTINEL = 'nbdready' # Created when nbdkit exports are ready
DEFAULT_TIMEOUT = 600           # Maximum wait for openstacksdk operations

# Lock to serialize volume attachments. This helps prevent device path
# mismatches between the OpenStack SDK and /dev in the VM.
ATTACH_LOCK_FILE_SOURCE = '/var/lock/v2v-source-volume-lock'

# Local directory to copy logs from source conversion host
SOURCE_LOGS_DIR = '/data/source_logs'


def detect_source_host(data, agent_sock):
    """ Create the right source host object based on the input data. """
    if 'osp_source_environment' in data:
        return OpenStackSourceHost(data, agent_sock)
    return None

class _BaseSourceHost(object):
    """ Interface for source hosts. """

    def prepare_exports(self):
        """ Creates the nbdkit exports from the migration source. """
        logging.info('No preparation needed for this migration source.')

    def close_exports(self):
        """ Stops the nbdkit exports on the migration source. """
        logging.info('No cleanup needed for this migration source.')


VolumeMapping = namedtuple('VolumeMapping',
    ['source_dev', # Device path (like /dev/vdb) on source conversion host
     'source_id', # Volume ID on source conversion host
     'snap_id', # Root volumes need snapshot+new volume, so record snapshot ID
     'image_id', # Direct-from-image VMs create this temporary snapshot image
     'size', # Volume size reported by OpenStack, in GB
     'url' # Final NBD export address from source conversion host
    ])
class OpenStackSourceHost(_BaseSourceHost):
    """ Export volumes from an OpenStack instance. """

    def __init__(self, data, agent_sock):
        # Create a connection to the source cloud
        osp_arg_list = ['auth_url', 'username', 'password',
                        'project_name', 'project_domain_name',
                        'user_domain_name', 'verify']
        osp_env = data['osp_source_environment']
        osp_args = {arg: osp_env[arg] for arg in osp_arg_list}
        self.source_converter = osp_env['conversion_vm_id']
        self.source_instance = osp_env['vm_id']
        self.conn = openstack.connect(**osp_args)

        self.agent_sock = agent_sock
        openstack.enable_logging() # Lots of openstacksdk messages without this

        # Build up a list of VolumeMappings keyed by the original device path
        self.volume_map = {}

        # Temporary directory for logs on source conversion host
        self.tmpdir = None

        # If there is a specific list of disks to transfer, remember them so
        # only those disks get transferred.
        self.source_disks = None
        if 'source_disks' in data:
            self.source_disks = data['source_disks']

    def prepare_exports(self):
        """ Attach the source VM's volumes to the source conversion host. """
        self._test_ssh_connection()
        self._shutdown_source_vm()
        self._get_root_and_data_volumes()
        self._detach_data_volumes_from_source()
        self._attach_volumes_to_converter()
        self._export_volumes_from_converter()

    def close_exports(self):
        """ Put the source VM's volumes back where they were. """
        self._test_ssh_connection()
        self._converter_close_exports()
        self._detach_volumes_from_converter()
        self._attach_data_volumes_to_source()

    def _source_vm(self):
        """
        Changes to the VM returned by get_server_by_id are not necessarily
        reflected in existing objects, so just get a new one every time.
        """
        return self.conn.get_server_by_id(self.source_instance)

    def _converter(self):
        """ Same idea as _source_vm, for source conversion host. """
        return self.conn.get_server_by_id(self.source_converter)

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
        return subprocess.check_output(command, env=environment)

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
        return subprocess.check_output(command, env=environment)

    def _test_ssh_connection(self):
        """ Quick SSH connectivity check for source conversion host. """
        out = self._converter_out(['echo connected'])
        if out != 'connected':
            raise RuntimeError('Unable to SSH to source conversion host!')

    def _shutdown_source_vm(self):
        """ Shut down the migration source VM before moving its volumes. """
        server = self.conn.compute.get_server(self._source_vm().id)
        if server.status != 'SHUTOFF':
            self.conn.compute.stop_server(server=server)
            logging.info('Waiting for source VM to stop...')
            self.conn.compute.wait_for_server(server, 'SHUTOFF',
                wait=DEFAULT_TIMEOUT)

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
            self.volume_map[dev_path] = VolumeMapping(source_dev=None,
                source_id=volume.id, snap_id=None,
                image_id=None, name=volume.name, size=volume.size, url=None)

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
            root_snapshot = self.conn.create_volume_snapshot(force=True,
                wait=True, name='rhosp-migration-{}'.format(volume_id),
                volume_id=volume_id, timeout=DEFAULT_TIMEOUT)

            # Create a new volume from the snapshot
            logging.info('Creating new volume from root snapshot')
            root_volume_copy = self.conn.create_volume(wait=True,
                    name='rhosp-migration-{}'.format(volume_id),
                    snapshot_id=root_snapshot.id,
                    size=root_snapshot.size,
                    timeout=DEFAULT_TIMEOUT)

            # Update the volume map with the new volume ID
            self.volume_map['/dev/vda'] = mapping._replace(
                source_id=root_volume_copy.id,
                snap_id=root_snapshot.id)
        elif sourcevm.image:
            logging.info('Image-based instance, creating snapshot...')
            image = self.conn.compute.create_server_image(server=sourcevm.id,
                name='rhosp-migration-root-{}'.format(sourcevm.name))
            for second in range(DEFAULT_TIMEOUT):
                refreshed_image = self.conn.get_image_by_id(image.id)
                if refreshed_image.status == 'active':
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Could not create new image of image-based '
                    'instance!')
            volume = self.conn.create_volume(image=image.id, bootable=True,
                wait=True, timeout=DEFAULT_TIMEOUT, size=image.min_disk,
                name=image.name)
            self.volume_map['/dev/vda'] = VolumeMapping(source_dev=None,
                source_id=volume.id, snap_id=None,
                image_id=image.id, name=volume.name, size=volume.size,
                url=None)
        else:
            raise RuntimeError('No known boot device found for this instance!')

        for path, mapping in self.volume_map.items():
            if path == '/dev/vda':
                continue
            else: # Detach non-root volumes
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

    def _attach_volumes(self, conn, host_func, name, ssh_func, update_func,
            volume_id_func):
        """
        Attach all volumes in the volume map to the specified conversion host.
        Check the list of disks before and after attaching to be absolutely
        sure the right source data gets copied to the right destination disk.
        This is here because _attach_destination_volumes and
        _attach_volumes_to_converter looked almost identical.
        """
        logging.info('Attaching volumes to %s wrapper', name)
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
                        'conversion host path agrees with OpenStack.',
                        dev_path, name)
                else:
                    dev_path = new_disks.pop()
                    logging.debug('Successfully attached new disk %s, but %s '
                        'conversion host path does not match the result from '
                        'OpenStack. Using internal device path %s.',
                        attachment.device, name, dev_path)
            else:
                raise RuntimeError('Got unexpected disk list after attaching '
                    'volume to %s conversion host instance. Failing migration '
                    'procedure to avoid assigning volumes incorrectly. New '
                    'disks(s) inside VM: {}, disk provided by OpenStack: '
                    '{}'.format(name, new_disks, dev_path))
            self.volume_map[path] = update_func(mapping, dev_path)

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
                        except OSError as error:
                            logging.info('Another conversion has the lock.')
                            time.sleep(1)
                    else:
                        raise RuntimeError('Unable to acquire lock %s!',
                            lock_file)
                    try:
                        function(self)
                    finally:
                        fcntl.flock(lock, fcntl.LOCK_UN)
            return wait_for_lock
        return _decorate_lock

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
        self._attach_volumes(self.conn, self._converter, 'source',
            self._converter_out, update_source, volume_id)

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
        port_map = {} # Map device path to port number, for export_nbd
        reverse_port_map = {} # Map port number to device path, for forwarding
        nbd_ports = [] # podman arguments for NBD ports
        device_list = [] # podman arguments for block devices
        for path, mapping in self.volume_map.items():
            volume_id = mapping.source_id
            dev_path = mapping.source_dev
            uci_dev_path = mapping.source_dev+'-v2v'
            logging.info('Exporting %s from volume %s', dev_path, volume_id)
            nbd_ports.extend(['-p', '{0}'.format(port)])
            device_list.extend(['--device', dev_path+':'+uci_dev_path])
            reverse_port_map[port] = path
            port_map[uci_dev_path] = port
            port += 1

        # Copy the port map as input to the source conversion host wrapper
        self._converter_val(['mkdir', '-p', self.tmpdir+'/lib'])
        self._converter_val(['mkdir', '-p', self.tmpdir+'/log'])
        self._converter_val(['mkdir', '-p', self.tmpdir+'/input'])
        ports = json.dumps({'nbd_export_only': port_map})
        nbd_conversion = '/tmp/nbd_conversion.json'
        with open(nbd_conversion, 'w+') as conversion:
            conversion.write(ports)
        self._converter_scp(nbd_conversion,
            self.tmpdir+'/input/conversion.json')

        # Run UCI on source conversion host. Create a temporary directory to
        # use as the UCI's /data directory so more than one can run at a time.
        ssh_args = ['sudo', 'podman', 'run', '--detach']
        ssh_args.extend(['--volume', '/var/tmp:/var/tmp:z'])
        ssh_args.extend(['--volume', '/var/lock:/var/lock:z'])
        ssh_args.extend(['--volume', self.tmpdir+':/data:z'])
        ssh_args.extend(['--volume', self.tmpdir+'/lib:/var/lib/uci:z'])
        ssh_args.extend(['--volume', self.tmpdir+'/log:/var/log/uci:z'])
        ssh_args.extend(['--volume',
            '/opt/vmware-vix-disklib-distrib:/opt/vmware-vix-disklib-distrib'])
        ssh_args.extend(nbd_ports)
        ssh_args.extend(device_list)
        ssh_args.extend(['v2v-conversion-host'])
        self.uci_id = self._converter_out(ssh_args)
        logging.debug('Source UCI container ID: %s', self.uci_id)

        # Find the ports chosen by podman and forward them
        ssh_args = ['sudo', 'podman', 'port', self.uci_id]
        out = self._converter_out(ssh_args)
        forward_ports = ['-N', '-T']
        for line in out.split('\n'): # Format: 10809/tcp -> 0.0.0.0:33437
            logging.debug('Forwarding port from podman: %s', line)
            internal_port, _, _ = line.partition('/')
            _, _, external_port = line.rpartition(':')
            port = int(internal_port)
            path = reverse_port_map[port]
            # The internal_port in the source conversion container is forwarded
            # to external_port on the source conversion host, and then we need
            # any local port on the destination conversion container to forward
            # over SSH to that external_port. For simplicity, just choose the
            # same as internal_port, so both source and destination containers
            # use the same ports for the same NBD volumes. This is worth
            # explaining in detail because otherwise the following arguments
            # may look backwards at first glance.
            forward_ports.extend(['-L', '{}:localhost:{}'.format(internal_port,
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

            # Copy logs from temporary directory locally, and clean up source
            if self.tmpdir:
                os.mkdir(SOURCE_LOGS_DIR)
                self._converter_scp_from(self.tmpdir+'/*', SOURCE_LOGS_DIR,
                    recursive=True)
                self._converter_out(['rm', '-rf', self.tmpdir])

            self.forwarding_process.terminate()
        except Exception as error:
            pass


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
            self.conn.detach_volume(server=converter, wait=True,
                timeout=DEFAULT_TIMEOUT, volume=volume)
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
                    self.conn.delete_volume_snapshot(timeout=DEFAULT_TIMEOUT,
                        wait=True, name_or_id=mapping.snap_id)

                # Remove root image copy, for image-launched instances
                if mapping.image_id:
                    logging.info('Deleting temporary root device image')
                    self.conn.delete_image(timeout=DEFAULT_TIMEOUT,
                        wait=True, name_or_id=mapping.image_id)
            else:
                # Attach data volumes back to source VM
                volume = self.conn.get_volume_by_id(mapping.source_id)
                sourcevm = self._source_vm()
                try:
                    attachment = self._get_attachment(volume, sourcevm)
                except RuntimeError:
                    logging.info('Attaching %s back to source VM', volume.id)
                    self.conn.attach_volume(volume=volume, wait=True,
                        server=sourcevm, timeout=DEFAULT_TIMEOUT)
                else:
                    logging.info('Volume %s is already attached to source VM',
                        volume.id)
                    continue
