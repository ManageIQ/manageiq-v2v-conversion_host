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
from pyVim.connect import SmartConnect, SmartConnectNoSSL, Disconnect
from pyVmomi import vim  # pylint: disable=no-name-in-module; dynamic module

from .state import STATE, StateObject
from .common import VDDK_LIBDIR, VDDK_LIBRARY_PATH
from .common import add_perms_to_file, error, nbd_uri_from_unix_socket


_TIMEOUT = 10

NBD_MIN_VERSION = version.parse("1.0.0")
NBD_AIO_MAX_IN_FLIGHT = 4

MAX_BLOCK_STATUS_LEN = 2 << 30  # 2GB (4GB requests fail over the 32b protocol)
MAX_PREAD_LEN = 23 << 20        # 23MB (24M requests fail in vddk)


BlockStatusData = namedtuple('BlockStatusData', ['offset', 'length', 'flags'])


def get_block_status(nbd_handle, size):
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
            offset += length

    last_offset = 0
    while last_offset < size:
        missing_length = size - last_offset
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
        '_conn',
        'insecure',
        'thumbprint',
        '_uri',
        '_vm',
        '_vm_name',
    ]

    def __init__(self, data):
        self._conn = None
        self._vm = None
        self._vm_name = data['vm_name']
        self.insecure = False

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
            self._conn = SmartConnectNoSSL(**connect_args)
        else:
            self._conn = SmartConnect(**connect_args)

    def _disconnect(self):
        if self._conn is None:
            return
        Disconnect(self._conn)
        self._conn = None

    def get_vm(self):
        self._connect()
        if self._vm:
            return self._vm

        view_mgr = self._conn.content.viewManager
        view = view_mgr.CreateContainerView(self._conn.content.rootFolder,
                                            [vim.VirtualMachine],
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
                if isinstance(x, vim.vm.device.VirtualDisk)]

    def __del__(self):
        self._disconnect()


class CopyIterationData(StateObject):
    __slots__ = [
        'change_id',
        'copied',
        'to_copy',
    ]

    def __init__(self):
        self.change_id = None
        self.copied = None
        self.to_copy = None


class _PreCopyDisk(StateObject):
    __slots__ = [
        'commit_progress',
        'copies',  # Information for copy iterations (mostly progress)
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
        'vmware_object',  # Disk object returned by pyvmomi
    ]

    _hidden = [
        'change_ids',
        'key',
        'local_path',
        'overlay',
        'path',
        'pidfile',
        'proc_nbdkit',
        'proc_qemu',
        'sock',
        'vmware_object',
    ]

    def __init__(self, nbd, disk, tmp_dir):
        self.nbd = nbd
        self.change_ids = []
        self.label = disk.deviceInfo.label
        self.local_path = None
        self.path = disk.backing.fileName
        self.size = int(disk.capacityInBytes)
        self.status = 'Prepared'
        self.key = disk.key
        self.vmware_object = disk
        self.logname = '%s(key=%s)' % (self.label, self.key)

        self.sock = os.path.join(tmp_dir, 'nbdkit-%s.sock' % self.key)
        self.pidfile = os.path.join(tmp_dir, 'nbdkit-%s.pid' % self.key)
        self.proc_nbdkit = None
        self.proc_qemu = None
        self.overlay = None

        self.copies = None

    def copy(self):
        self.status = 'Copying (connecting)'
        STATE.write()

        nbd_handle = self.nbd.NBD()
        nbd_handle.add_meta_context("base:allocation")
        nbd_handle.connect_uri(nbd_uri_from_unix_socket(self.sock))
        fd = os.open(self.local_path, os.O_WRONLY)

        if self.copies is None:
            self.copies = []
        self.copies.append(CopyIterationData())

        try:
            self._copy_all(nbd_handle, fd)
        except Exception:
            self.status = 'Failed during copy'
            STATE.write()
            os.close(fd)
            nbd_handle.shutdown()
            raise

        self.status = 'Copied'
        STATE.write()

    def _copy_all(self, nbd_handle, fd):
        # This is called back when nbd_aio_pread completes.
        def _read_completed(fd, buf, offset, err):
            logging.debug('Writing %d B to offset %d B', buf.size(), offset)
            os.pwrite(fd, buf.to_bytearray(), offset)
            self.copies[-1].copied += buf.size()
            STATE.write()
            # By returning 1 here we auto-retire the aio_pread command.
            return 1

        # Process any AIO requests without blocking.
        def _process_aio_requests(nbd_handle):
            while nbd_handle.poll(0) == 1:
                pass

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

        # TODO: We'll use extents later
        blocks = get_block_status(nbd_handle, self.size)
        data_blocks = [x for x in blocks if not x.flags & self.nbd.STATE_HOLE]

        logging.debug('Block status filtered down to %d data blocks',
                      len(data_blocks))
        self.copies[-1].copied = 0
        self.copies[-1].to_copy = sum([block.length for block in data_blocks])

        if len(data_blocks) == 0:
            logging.debug('No extents have allocated data for disk: %s',
                          self.logname)
            return

        self.status = 'Copying'
        STATE.write()

        logging.debug('Copying %d B of data', self.copies[-1].to_copy)

        for block in data_blocks:
            if block.flags & self.nbd.STATE_ZERO:
                # Optimize for memory usage, maybe?
                os.pwrite(fd, [0] * block.length, block.offset)
                self.copies[-1].copied += block.length
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

                    _process_aio_requests(nbd_handle)

        _wait_for_aio_commands_to_finish(nbd_handle)

        if self.copies[-1].copied == 0:
            logging.debug('Nothing to copy for disk: %s', self.logname)
        else:
            logging.debug('Copied %d B for disk: %s',
                          self.copies[-1].copied, self.logname)


class PreCopy(StateObject):
    __slots__ = [
        'data',
        '_tmp_dir',
        '_tmp_dir_path',
        'vmware',

        'disks',
    ]

    _hidden = [
        'data',
        '_tmp_dir',
        '_tmp_dir_path',
        'vmware',
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
        return super(PreCopy, cls).__new__(cls)

    def __init__(self, data):
        import nbd
        self.nbd = nbd

        self.output_format = data['output_format']
        self._tmp_dir = tempfile.TemporaryDirectory(prefix='v2v-')
        self._tmp_dir_path = self._tmp_dir.name

        self.disks = None

        self.vmware = _VMWare(data)

        # Let others browse it
        add_perms_to_file(self._tmp_dir_path, stat.S_IXOTH, -1, -1)

    def __del__(self):
        # This is mostly for tests, but neither the object nor the
        # TemporaryDirectory object should be used multiple times anyway.
        if self._tmp_dir is not None:
            self._tmp_dir.cleanup()

    def init_disk_data(self):
        "Updates data about disks in the remote VM"

        vm = self.vmware.get_vm()
        if vm.snapshot:
            logging.warning("VM should not have any previous snapshots")
        disks = self.vmware.get_disks_from_config(vm.config)

        self.disks = [_PreCopyDisk(self.nbd, d, self._tmp_dir_path)
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

        disk_map = {disk.path: DiskToFix(disk.local_path)
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
        xmlfile = os.path.join(self._tmp_dir_path, 'vm.xml')
        with open(xmlfile, 'wb') as f:
            f.write(self._fix_disks(self.vmware.get_domxml()))
        return xmlfile

    def _get_nbdkit_cmd(self, disk, vmware_password_file, filters):
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
            'password=+%s' % vmware_password_file,
            'thumbprint=%s' % self.vmware.thumbprint,
            'libdir=%s' % VDDK_LIBDIR,
            'file=%s' % disk.path,
        ]
        if self.vmware.user:
            nbdkit_cmd.append('user=%s' % self.vmware.user)
        nbdkit_cmd.extend([
            'logfile=%s' % STATE.wrapper_log,
            'logappend=true',
        ])

        return nbdkit_cmd

    def _start_nbdkits(self, vmware_password_file):
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
            cmd = self._get_nbdkit_cmd(disk, vmware_password_file, filters)
            logging.debug('Starting nbdkit: %s', cmd)
            # logging.debug('Logging nbdkit output into: %s', log_path)
            disk.proc_nbdkit = subprocess.Popen(cmd,
                                                stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL,
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

    def copy_disks(self, vmware_password_file):
        "Copy all disk data from the VMWare server to locally mounted disks."

        self._start_nbdkits(vmware_password_file)

        ndisks = len(self.disks)
        for i, disk in enumerate(self.disks):
            logging.debug('Copying disk %d/%d', i, ndisks)
            disk.copy()

        self._stop_nbdkits()

    def commit_overlays(self):
        "Commit all overlays to local disks."

        for disk in self.disks:
            if disk.overlay is None:
                raise RuntimeError('Did not get any overlay data from v2v')

        ndisks = len(self.disks)
        cmd_templ = ['qemu-img', 'commit', '-p']
        for i, disk in enumerate(self.disks):
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

    def finish(self):
        "Finish anything that is needed after successful conversion"

        self.commit_overlays()
