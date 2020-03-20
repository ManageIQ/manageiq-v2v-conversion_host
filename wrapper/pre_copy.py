"All helpers needed to handle copying data from VMWare"

import os
import errno
import fcntl
import libvirt
import logging
import re
import six
import stat
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ETree

from collections import namedtuple
from packaging import version
from six.moves.urllib.parse import urlparse, unquote, parse_qs

from .state import STATE, StateObject
from .common import RUN_DIR, VDDK_LIBDIR, VDDK_LIBRARY_PATH
from .common import add_perms_to_file, error, nbd_uri_from_unix_socket


_TIMEOUT = 10

NBD_MIN_VERSION = version.parse('1.0.0')
NBD_AIO_MAX_IN_FLIGHT = 4

MAX_BLOCK_STATUS_LEN = 2 << 30  # 2GB (4GB requests fail over the 32b protocol)
MAX_PREAD_LEN = 23 << 20        # 23MB (24M requests fail in vddk)


BlockStatusData = namedtuple('BlockStatusData', ['offset', 'length', 'flags'])


def get_block_status(nbd_handle, extents):
    blocks = []

    def update_blocks(metacontext, offset, extents, err):
        if metacontext != 'base:allocation':
            return
        for length, flags in zip(extents[::2], extents[1::2]):
            if blocks:
                last_block = blocks[-1]
                last_flags = last_block.flags
                last_offset = last_block.offset + last_block.length
                if last_flags == flags and last_offset == offset:
                    # The new block is just an extension to the previous one
                    blocks[-1] = BlockStatusData(last_block.offset,
                                                 last_block.length + length,
                                                 last_flags)
                else:
                    blocks.append(BlockStatusData(offset, length, flags))
            else:
                blocks.append(BlockStatusData(offset, length, flags))
            offset += length

    for extent in extents:
        if extent.length < 1 << 20:
            # Copying 1MB extent is usually faster than requesting block
            # status on it.  We might make this configurable.
            blocks.append(BlockStatusData(extent.start, extent.length, 0))
            continue

        last_offset = extent.start
        end_offset = extent.start + extent.length
        while last_offset < end_offset:
            missing_length = end_offset - last_offset
            length = min(missing_length, MAX_BLOCK_STATUS_LEN)

            logging.debug('Calling block_status with length=%d offset=%d',
                          length, last_offset)

            nbd_handle.block_status(length, last_offset, update_blocks)

            new_offset = blocks[-1].offset + blocks[-1].length

            if last_offset == new_offset:
                raise ValueError('No new block status data from NBD')

            last_offset = new_offset

    return blocks


class _VMWare(object):
    __slots__ = [
        'server',
        'user',
        '_password',
        'password_file',
        'port',
        'pyvmomi',
        '_conn',
        'insecure',
        'thumbprint',
        '_uri',
        '_vm',
        '_vm_name',
        '_snapshots',
    ]

    def __init__(self, data):
        self._conn = None
        self._vm = None
        self._vm_name = data['vm_name']
        self.insecure = False

        self._snapshots = []

        self._uri = data['vmware_uri']
        uri = urlparse(self._uri)

        self.server = uri.hostname
        self.port = uri.port
        self.user = 'administrator@vsphere.local'
        self._password = data['vmware_password']
        self.thumbprint = data['vmware_fingerprint']
        if uri.username:
            self.user = unquote(uri.username)

        no_verify = parse_qs(uri.query).get('no_verify', [])
        if no_verify:
            if len(no_verify) > 1:
                raise ValueError('Multiple values for "no_verify"')

            try:
                val = int(no_verify[0])
            except ValueError:
                error('Invalid value for "no_verify"')
                raise

            if val == 1:
                self.insecure = True
            elif val == 0:
                self.insecure = False
            else:
                raise ValueError('Invalid value for "no_verify"')

        from . import pyvmomi_wrapper
        self.pyvmomi = pyvmomi_wrapper

    def _connect(self):
        "Connect to the remote VMWare server"

        if self._conn:
            return

        connect_args = {
            'host': self.server,
            'user': self.user,
            'pwd': self._password,
            'thumbprint': self.thumbprint,
        }
        if self.port is not None:
            connect_args['port'] = self.port

        if self.insecure:
            self._conn = self.pyvmomi.SmartConnectNoSSL(**connect_args)
        else:
            self._conn = self.pyvmomi.SmartConnect(**connect_args)

    def _disconnect(self):
        if self._conn is None:
            return
        self.pyvmomi.Disconnect(self._conn)
        self._conn = None

    def keepalive(self):
        self._conn.CurrentTime()

    def get_vm(self):
        self._connect()
        if self._vm:
            self._vm.Reload()
            return self._vm

        view_mgr = self._conn.content.viewManager
        view = view_mgr.CreateContainerView(self._conn.content.rootFolder,
                                            [self.pyvmomi.vim.VirtualMachine],
                                            recursive=True)
        vms = [vm for vm in view.view if vm.name == self._vm_name]
        if len(vms) > 1:
            raise ValueError('VM name "%s" is not unique' % self._vm_name)
        if len(vms) != 1:
            raise ValueError('No VM with name "%s"' % self._vm_name)

        self._vm = vms[0]
        return self._vm

    def get_domxml(self):
        def auth_cb(cred, _):
            for c in cred:
                if c[0] == libvirt.VIR_CRED_AUTHNAME:
                    c[4] = self.user
                elif c[0] == libvirt.VIR_CRED_PASSPHRASE:
                    c[4] = self._password
                else:
                    return -1
            return 0

        cred_info = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_PASSPHRASE],
                     auth_cb, None]
        conn = libvirt.openAuth(self._uri, cred_info)
        domxml = conn.lookupByName(self._vm_name).XMLDesc()
        logging.debug('Fetched domxml: \n%s', domxml)

        return domxml

    def get_disks_from_config(self, config):
        return [x for x in config.hardware.device
                if isinstance(x, self.pyvmomi.vim.vm.device.VirtualDisk)]

    def get_disk_by_key(self, config, key):
        disks = [x for x in self.get_disks_from_config(config)
                 if x.key == key]
        if len(disks) != 1:
            raise RuntimeError('Integrity error: '
                               'Number of disks with key %s: %d' %
                               (key, len(disks)))
        return disks[0]

    def create_snapshot(self):
        vm = self.get_vm()
        logging.debug('Creating snapshot to get a new change_id')
        task = vm.CreateSnapshot(name='v2v_cbt',
                                 description='Snapshot to start CBT',
                                 memory=False,
                                 # The `quiesce` parameter can be False to
                                 # make it slightly faster, but it should
                                 # be first tested independently.
                                 quiesce=True)
        self.pyvmomi.WaitForTask(task)
        # Update the VM data
        vm = self.get_vm()
        logging.debug('Snapshot created: %s', vm.snapshot.currentSnapshot)
        self._snapshots.append(vm.snapshot.currentSnapshot)

    def clean_snapshot(self, final):
        # Here final means clean all (for the sake of clean-up simplicity)
        if final:
            snaps = [s for s in self._snapshots if s is not None]
            if not snaps:
                return
            snapshot = snaps[0]
            # All snapshots should be removed, there should be none remaining
            self._snapshots = []
        else:
            if len(self._snapshots) < 2:
                return
            snapshot = self._snapshots[-2]
            self._snapshots[-2] = None

        logging.debug('Removing snapshot %s%s',
                      snapshot, ' with children' if final else '')
        self.pyvmomi.WaitForTask(snapshot.RemoveSnapshot_Task(final))
        logging.debug('Snapshot removed')

    def __del__(self):
        self._disconnect()


class CopyIterationData(StateObject):
    __slots__ = [
        'change_id',
        'path',
        'snapshot',

        'copied',
        'to_copy',

        'start_time',
        'end_time',

        'status',
        'error',
    ]

    _hidden = [
        'snapshot',
    ]

    def __init__(self, change_id=None, path=None):
        self.change_id = change_id
        self.path = path
        self.snapshot = None

        self.copied = None
        self.to_copy = None

        self.start_time = None
        self.end_time = None
        self.status = 'Prepared'
        self.error = None


class _PreCopyDisk(StateObject):
    __slots__ = [
        'commit_progress',
        'copies',  # Information for copy iterations (mostly progress)
        'extents',  # List of allocated extents of the disk
        'key',  # Key on the VMWare server
        'label',  # Label for nicer user reporting
        'local_path',  # Path on local filesystem
        'overlay',  # Path to the local overlay
        'path',  # The VMWare-reported path (on the host)
        'pidfile',  # nbdkit's pidfile path
        'proc_nbdkit',  # nbdkit process
        'proc_qemu',  # nbdkit process
        'size',  # in Bytes
        'sock',  # nbdkit's unix socket path
        'status',  # Any string for user-reporting
    ]

    _hidden = [
        'extents',
        'key',
        'local_path',
        'overlay',
        'path',
        'pidfile',
        'proc_nbdkit',
        'proc_qemu',
        'sock',
    ]

    def __init__(self, nbd, disk, tmp_dir):
        self.nbd = nbd
        self.label = disk.deviceInfo.label
        self.local_path = None
        self.size = int(disk.capacityInBytes)
        self.status = 'Prepared'
        self.key = disk.key
        self.logname = '%s(key=%s)' % (self.label, self.key)

        self.sock = os.path.join(tmp_dir, 'nbdkit-%s.sock' % self.key)
        self.pidfile = os.path.join(tmp_dir, 'nbdkit-%s.pid' % self.key)
        self.proc_nbdkit = None
        self.proc_qemu = None
        self.overlay = None

        self.commit_progress = None

        self.copies = [CopyIterationData('*', disk.backing.fileName)]

    def copy_ref(self, final):
        return self.copies[-1 if final else -2]

    def get_extents(self, vm, final):
        self.extents = []
        offset = 0
        copy = self.copy_ref(final)

        logging.debug('Requesting changed disk areas for '
                      'snapshot "%s" with change id "%s"',
                      copy.snapshot, copy.change_id)

        while offset < self.size:
            tmp = vm.QueryChangedDiskAreas(copy.snapshot,
                                           int(self.key),
                                           offset,
                                           copy.change_id)
            self.extents += tmp.changedArea
            offset += tmp.startOffset + tmp.length

    def copy(self, vm, final, keepalive=None):
        copy = self.copy_ref(final)
        copy.start_time = time.time()
        copy.status = 'Connected'
        STATE.write()

        self.get_extents(vm, final)
        if len(self.extents) == 0:
            copy.to_copy = 0
            copy.copied = 0
            copy.end_time = time.time()
            if not final and len(self.copies) > 2:
                self.copies[-2].path = None
                self.copies[-2].change_id = None
                self.copies[-3].snapshot = None
            return

        nbd_handle = self.nbd.NBD()
        nbd_handle.add_meta_context('base:allocation')
        nbd_handle.connect_uri(nbd_uri_from_unix_socket(self.sock))
        fd = os.open(self.local_path, os.O_WRONLY)

        try:
            copy.status = 'Copying'
            STATE.write()
            self._copy_all(nbd_handle, fd, final, keepalive)
            copy.status = 'Copied'
            copy.end_time = time.time()
            if not final and len(self.copies) > 2:
                self.copies[-2].path = None
                self.copies[-2].change_id = None
                self.copies[-3].snapshot = None
            STATE.write()
        except Exception:
            self.status = 'Unrecoverable error during copy'
            copy.error = True
            STATE.write()

            # TODO: asdf: figure out when do we try to recover

            raise
        finally:
            # No matter whether it failed or not, we do not need to keep the
            # snapshot, just the change_id
            os.close(fd)
            nbd_handle.shutdown()

    def _copy_all(self, nbd_handle, fd, final, keepalive):
        copy = self.copy_ref(final)

        # This is called back when nbd_aio_pread completes.
        def _read_completed(fd, buf, offset, err):
            logging.debug('Writing %d B to offset %d B', buf.size(), offset)
            os.pwrite(fd, buf.to_bytearray(), offset)
            copy.copied += buf.size()
            STATE.write()
            # Everything is running in the same thread, so we can safely call
            # keepalive here as that makes it more spread out (lower chance of
            # not being called for a long time)
            if keepalive is not None:
                keepalive()
            # By returning 1 here we auto-retire the aio_pread command.
            return 1

        # Process any AIO requests without blocking.
        def _process_aio_requests(nbd_handle, keepalive):
            while nbd_handle.poll(0) == 1:
                # One more keepalive call just in case no write was completed
                # for a long time.
                # TODO: Ideally all keepalive calls would be wrapped in another
                # condition so that they are not called too often.
                if keepalive is not None:
                    keepalive()

        # Wait until there's less AIO commands on the handle.
        def _process_some_requests(nbd_handle):
            while nbd_handle.aio_in_flight() > NBD_AIO_MAX_IN_FLIGHT:
                nbd_handle.poll(1)

        # Block until all AIO commands on the handle have finished.
        def _wait_for_aio_commands_to_finish(nbd_handle):
            while nbd_handle.aio_in_flight() > 0:
                nbd_handle.poll(-1)

        logging.debug('Getting block info for disk: %s', self.logname)
        self.status = 'Copying (getting block stats)'
        STATE.write()

        blocks = get_block_status(nbd_handle, self.extents)
        data_blocks = [x for x in blocks if not x.flags & self.nbd.STATE_HOLE]

        logging.debug('Block status filtered down to %d data blocks',
                      len(data_blocks))
        copy.copied = 0
        copy.to_copy = sum([block.length for block in data_blocks])

        if len(data_blocks) == 0:
            logging.debug('No extents have allocated data for disk: %s',
                          self.logname)
            return

        copy.status = 'Copying'
        STATE.write()

        logging.debug('Copying %d B of data', copy.to_copy)

        for block in data_blocks:
            if block.flags & self.nbd.STATE_ZERO:
                # Optimize for memory usage, maybe?
                os.pwrite(fd, [0] * block.length, block.offset)
                copy.copied += block.length
                STATE.write()
            else:
                count = 0
                while count < block.length:
                    _process_some_requests(nbd_handle)

                    length = min(block.length - count, MAX_PREAD_LEN)
                    offset = block.offset + count

                    buf = self.nbd.Buffer(length)
                    nbd_handle.aio_pread(buf, offset,
                                         lambda e, f=fd, b=buf, o=offset:
                                         _read_completed(f, b, o, e))
                    count += length

                    _process_aio_requests(nbd_handle, keepalive)

        _wait_for_aio_commands_to_finish(nbd_handle)

        logging.debug('Copied %d B for disk: %s',
                      copy.copied, self.logname)

    def update_change_ids(self, orig_disk, device, snapshot):
        self.copies[-1].snapshot = snapshot
        change_id = device.backing.changeId
        new_filename = orig_disk.backing.fileName

        # This might happen for some special disks and we might need to handle
        # it, although it is out of the question for now
        if change_id is None:
            raise RuntimeError('Missing changeId for a disk')

        logging.debug('Disk "%s" has new changeId=%s', self.logname, change_id)
        self.copies.append(CopyIterationData(change_id, new_filename))
        STATE.write()


class PreCopy(StateObject):
    __slots__ = [
        '_tmp_dir',
        'vmware',
        '_vmware_password_file',
        'warm',
        '_cutover_path',
        '_iteration_seconds',
        '_copy_trigger_path',

        'disks',
    ]

    _hidden = [
        '_tmp_dir',
        'vmware',
        '_vmware_password_file',
        'warm',
        '_cutover_path',
        '_iteration_seconds',
        '_copy_trigger_path',
    ]

    qemu_progress_re = re.compile(r'\((\d+\.\d+)/100%\)')

    @staticmethod
    def __new__(cls, data):
        if not data.get('two_phase', False):
            return None
        try:
            import nbd
        except ImportError:
            raise RuntimeError('libnbd is not available, it is required for '
                               'two-phase conversion')

        nbd_version = version.parse(nbd.NBD().get_version())
        if nbd_version < NBD_MIN_VERSION:
            raise RuntimeError('libnbd is too old (%s), '
                               'minimum version required is %s' %
                               (nbd_version, NBD_MIN_VERSION))

        try:
            from . import pyvmomi_wrapper
            dir(pyvmomi_wrapper)
        except ImportError:
            raise RuntimeError('pyvmomi is not available, it is required for '
                               'two-phase conversion')

        return super(PreCopy, cls).__new__(cls)

    def __init__(self, data):
        import nbd
        self.nbd = nbd

        self._tmp_dir = tempfile.TemporaryDirectory(prefix='v2v-')

        self.disks = None

        self.vmware = _VMWare(data)
        self.warm = data['warm']
        self._cutover_path = os.path.join(RUN_DIR, 'cutover')
        self._copy_trigger_path = os.path.join(RUN_DIR, 'copy_trigger')
        self._iteration_seconds = int(data.get('iteration_seconds', 3600))
        if self._iteration_seconds < 0:
            raise RuntimeError('Invalid value for `iteration_seconds`')

        # Let others browse it
        add_perms_to_file(self._tmp_dir.name, stat.S_IXOTH, -1, -1)

    def __del__(self):
        # This is mostly for tests, but neither the object nor the
        # TemporaryDirectory object should be used multiple times anyway.
        if hasattr(self, '_tmp_dir') and self._tmp_dir is not None:
            self._tmp_dir.cleanup()

    def init_disk_data(self):
        "Updates data about disks in the remote VM"

        STATE.status = 'Preparing'
        STATE.write()

        vm = self.vmware.get_vm()
        if vm.snapshot:
            logging.warning('VM should not have any previous snapshots')

        logging.info('Enabling CBT for the VM')
        cs = self.vmware.pyvmomi.vim.vm.ConfigSpec(changeTrackingEnabled=True)
        self.vmware.pyvmomi.WaitForTask(vm.Reconfigure(cs))
        logging.debug('CBT for the VM enabled')

        disks = self.vmware.get_disks_from_config(vm.config)

        self.disks = [_PreCopyDisk(self.nbd, d, self._tmp_dir.name)
                      for d in disks]
        STATE.disks = self.disks
        STATE.write()

    def _fix_disks(self, domxml):
        class DiskToFix(object):
            __slots__ = ['path', 'fixed']

            def __init__(self, path):
                self.path = path
                self.fixed = False

            def __repr__(self):
                return 'DiskToFix(path=%s, fixed=%s)' % (self.path, self.fixed)

        # We're taking the name of the original disk because at this point all
        # intermediate (CBT-related) snapshots were cleared and there should be
        # no new name for the disks
        disk_map = {disk.copies[0].path: DiskToFix(disk.local_path)
                    for disk in self.disks}
        logging.debug('Fixing disks with disk map: %s', disk_map)
        tree = ETree.fromstring(domxml)
        for disk in tree.find('devices').findall('disk'):
            src = disk.find('source')
            if src is None:
                continue
            path = src.get('file')
            if path is None:
                continue
            disk_data = disk_map.get(path)
            if disk_data is None:
                continue
            driver = ETree.Element('driver')
            driver.set('type', 'raw')
            src.set('file', disk_data.path)
            disk.append(driver)
            disk_data.fixed = True

        # Check that all paths were changed
        for k, v in six.iteritems(disk_map):
            if not v.fixed:
                raise RuntimeError('Disk path "%s" was '
                                   'not fixed in the domxml' % k)

        return ETree.tostring(tree)

    def get_xml(self):
        xmlfile = os.path.join(self._tmp_dir.name, 'vm.xml')
        with open(xmlfile, 'wb') as f:
            f.write(self._fix_disks(self.vmware.get_domxml()))
        return xmlfile

    def _get_nbdkit_cmd(self, disk, filters, final):
        env = 'LD_LIBRARY_PATH=%s' % VDDK_LIBRARY_PATH
        if 'LD_LIBRARY_PATH' in os.environ:
            env += ':' + os.environ['LD_LIBRARY_PATH']

        nbdkit_cmd = [
            'env',
            env,
            'nbdkit',
            '-v',
            '-U', disk.sock,
            '-P', disk.pidfile,
            '--exit-with-parent',
            '--readonly',
            '--foreground',
            '--exportname=/',
        ] + [
            '--filter=' + f for f in filters
        ] + [
            '--filter=log',
            'vddk',
            # pylint: disable=protected-access
            'vm=moref=%s' % self.vmware.get_vm()._moId,
            'server=%s' % self.vmware.server,
            'password=+%s' % self._vmware_password_file,
            'thumbprint=%s' % self.vmware.thumbprint,
            'libdir=%s' % VDDK_LIBDIR,
            'file=%s' % disk.copy_ref(final).path,
        ]
        if self.vmware.user:
            nbdkit_cmd.append('user=%s' % self.vmware.user)
        nbdkit_cmd.extend([
            'logfile=%s' % STATE.wrapper_log,
            'logappend=true',
        ])

        return nbdkit_cmd

    def _start_nbdkits(self, final):
        paths = []
        filters = ['cacheextents', 'retry']

        for filt in filters[:]:
            try:
                subprocess.check_call(['nbdkit',
                                       '--dump-plugin',
                                       '--filter=' + filt,
                                       'null'],
                                      timeout=5)
                continue
            except subprocess.TimeoutExpired:
                filters.remove(filt)
            except subprocess.CalledProcessError:
                filters.remove(filt)

        for disk in self.disks:
            cmd = self._get_nbdkit_cmd(disk, filters, final)
            logging.debug('Starting nbdkit: %s', cmd)
            log_fd = open(STATE.wrapper_log, 'a')
            disk.proc_nbdkit = subprocess.Popen(cmd,
                                                stdout=log_fd,
                                                stderr=subprocess.STDOUT,
                                                stdin=subprocess.DEVNULL)
            paths.append((disk.pidfile, disk.sock))

        logging.debug('Waiting for all nbdkit processes to initialize')
        endt = time.time() + _TIMEOUT
        while paths:
            for path in paths[:]:
                if os.path.exists(path[0]) and os.path.exists(path[1]):
                    paths.remove(path)
            if endt < time.time() or not paths:
                break
            time.sleep(.1)

        if paths:
            raise RuntimeError('Timed out waiting for nbdkits to initialize')

    def _stop_nbdkits(self):
        for disk in self.disks:
            if disk.proc_nbdkit is None:
                continue
            logging.debug('Stopping nbdkit with pid=%d', disk.proc_nbdkit.pid)
            disk.proc_nbdkit.terminate()
            try:
                disk.proc_nbdkit.wait(timeout=_TIMEOUT)
            except subprocess.TimeoutExpired:
                disk.proc_nbdkit.kill()
                disk.proc_nbdkit.wait()
            disk.proc_nbdkit = None
            try:
                os.remove(disk.sock)
            except FileNotFoundError:
                pass

    # Returns True/False whether the process is still running
    def _update_qemu_proc(self, disk, cb_progress):
        if disk.proc_qemu.poll() is not None:
            return False

        try:
            line = disk.proc_qemu.stdout.readline()
        except OSError as err:
            if err.errno != errno.EAGAIN:
                raise

        # Short-circuit the regexp code, line is b'' most of the time
        if not line:
            return True

        matches = self.qemu_progress_re.search(line)
        if matches is not None and cb_progress is not None:
            cb_progress(disk, float(matches.group(1)))

        return True

    def _wait_for_qemus(self, cb_progress=None, cb_done=None):
        while any([d.proc_qemu is not None for d in self.disks]):
            for disk in self.disks:
                if disk.proc_qemu is None:
                    continue
                if self._update_qemu_proc(disk, cb_progress):
                    continue
                retcode = disk.proc_qemu.returncode
                disk.proc_qemu = None
                if retcode != 0:
                    error('qemu-img failed with returncode %d' % retcode)
                    STATE.failed = True
                if cb_done is not None:
                    cb_done(disk, retcode == 0)

    def _update_disk_data(self):
        vm = self.vmware.get_vm()
        snapshot = vm.snapshot.currentSnapshot
        devices = self.vmware.get_disks_from_config(snapshot.config)
        for device in devices:
            disk = [x for x in self.disks if x.key == device.key]
            config = self.vmware.get_vm().config
            orig_disk = self.vmware.get_disk_by_key(config, device.key)
            if not disk:
                # Start tracking the disk now
                self.disks.append(_PreCopyDisk(self.nbd, orig_disk,
                                               self._tmp_dir.name))
            elif len(disk) == 1:
                disk[0].update_change_ids(orig_disk, device, snapshot)
            else:
                raise RuntimeError('Integrity error: Multiple disks have '
                                   'the same key, which should be unique!')

    def _wait_for_triggers(self):
        STATE.status = 'Waiting'
        STATE.write()

        endt = time.time() + self._iteration_seconds
        while endt > time.time():
            self.vmware.keepalive()

            if os.path.exists(self._cutover_path):
                logging.debug('Found file notifying end of the '
                              'warm part of first conversion phase')
                self.warm = False
                return
            if os.path.exists(self._copy_trigger_path):
                os.remove(self._copy_trigger_path)
                return
            time.sleep(5)

    def copy_disks(self, vmware_password_file):
        "Copy all disk data from the VMWare server to locally mounted disks."

        self._vmware_password_file = vmware_password_file

        iteration = 0
        while self.warm:
            STATE.status = 'Pre-copy #%d' % iteration
            STATE.write()
            iteration += 1
            self.vmware.create_snapshot()
            self._update_disk_data()
            self._copy_iteration(final=False)
            self._wait_for_triggers()

        STATE.status = 'Pre-copy #%d (last)' % iteration
        STATE.write()

        if self.vmware.get_vm().runtime.powerState != 'poweredOff':
            raise RuntimeError('Cannot perform final copy for running VM')

        self._copy_iteration(final=True)

    def _copy_iteration(self, final):

        self._start_nbdkits(final)

        ndisks = len(self.disks)
        for i, disk in enumerate(self.disks, start=1):
            logging.debug('Copying disk %d/%d', i, ndisks)
            disk.copy(self.vmware.get_vm(), final, self.vmware.keepalive)

        self._stop_nbdkits()
        self.vmware.clean_snapshot(final)

        for disk in self.disks:
            if disk.status == 'Copied':
                disk.status = 'Done'

    def commit_overlays(self):
        "Commit all overlays to local disks."

        for disk in self.disks:
            if disk.overlay is None:
                raise RuntimeError('Did not get any overlay data from v2v')

        ndisks = len(self.disks)
        cmd_templ = ['qemu-img', 'commit', '-p']
        for i, disk in enumerate(self.disks, start=1):
            logging.debug('Committing disk %d/%d', i, ndisks)
            cmd = cmd_templ + [disk.overlay]
            try:
                disk.proc_qemu = subprocess.Popen(cmd,
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT,
                                                  stdin=subprocess.DEVNULL,
                                                  universal_newlines=True,
                                                  bufsize=1)
            except subprocess.CalledProcessError as e:
                error('qemu-img failed with: %s' % e.output, exception=True)
                raise

            # We need to set the output to non-blocking so that we can process
            # the output without blocking
            fl = fcntl.fcntl(disk.proc_qemu.stdout, fcntl.F_GETFL)
            fl |= os.O_NONBLOCK
            fcntl.fcntl(disk.proc_qemu.stdout, fcntl.F_SETFL, fl)

            disk.status = 'Committing'
            STATE.write()

        def cb_progress(disk, progress):
            disk.commit_progress = progress
            STATE.write()

        def cb_done(disk, success):
            disk.status = 'Committed' if success else 'Failed during commit'
            disk.commit_progress = 100
            STATE.write()
            try:
                os.remove(disk.overlay)
            except FileNotFoundError:
                pass
            disk.overlay = None

        self._wait_for_qemus(cb_progress, cb_done)

    def cleanup(self):
        "Clean up everything upon any error"

        # Stopping nbdkits first because it might help us stop the qemu
        # processes
        self._stop_nbdkits()

        for disk in self.disks:
            if disk.proc_qemu is None:
                continue
            logging.debug('Stopping qemu-img with pid=%d', disk.proc_qemu.pid)
            disk.proc_qemu.terminate()
            try:
                disk.proc_qemu.wait(timeout=_TIMEOUT)
            except subprocess.TimeoutExpired:
                disk.proc_qemu.kill()
                disk.proc_qemu.wait()
            disk.proc_qemu = None
            if disk.overlay is not None:
                try:
                    os.remove(disk.overlay)
                except FileNotFoundError:
                    pass
                except Exception:
                    error('Cannot remove temporary file "%s", subsequent '
                          'conversions of the same hose might fail if this '
                          'file is not removed' % disk.overlay, exception=True)
            disk.overlay = None

        try:
            self.vmware.clean_snapshot(True)
        except Exception:
            error('Error cleaning up snapshots after another error',
                  exception=True)

    def finish(self):
        "Finish anything that is needed after successful conversion"

        self.commit_overlays()
