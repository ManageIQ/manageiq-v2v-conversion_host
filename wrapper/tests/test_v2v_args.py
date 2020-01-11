import unittest
from wrapper import virt_v2v_wrapper as wrapper
from wrapper.state import STATE


class TestV2vArgs(unittest.TestCase):
    """ Bunch of trivial in-out tests """

    def assert_has_args(self, arg_list, expected, msg=None):
        if len(expected) == 0:
            return
        items = len(expected)
        first = -1
        while True:
            previous = first
            first = None
            try:
                first = arg_list.index(expected[0], previous+1)
            except ValueError:
                pass
            self.assertIsNotNone(first, msg=msg)
            self.assertGreaterEqual(len(arg_list), first+len(expected),
                                    msg=msg)
            matched = 0
            for i in range(1, items):
                if arg_list[first+i] != expected[i]:
                    break
                matched = matched + 1
            if matched == items-1:
                return
        self.fail('How did we get here?')

    VDDK_RHV = {
        'vm_name': 'My Virtual',
        'transport_method': 'vddk',

        'rhv_url': 'https://example.my-ovirt.org/ovirt-engine/api',
        'rhv_password_file': '/rhv/password',
        'rhv_cluster': 'Default',
        'rhv_storage': 'data',
        'rhv_cafile': '/rhv/ca.pem',

        'vmware_fingerprint': '01:23:45:67:89:AB:CD:EA:DB:EE:F0:12:34:56:78:9A:BC:DE:F0:12',  # NOQA E501
        'vmware_uri': 'esx://root@1.2.3.4?',
        'vmware_password_file': '/vmware/password',

        'install_drivers': False,
        'output_format': 'raw',
        'insecure_connection': False,
    }

    def test_vddk_basic(self):
        STATE.machine_readable_log = '/some/path'
        data = self.VDDK_RHV.copy()
        expected = [
            '-v', '-x', 'My Virtual',
            '--root', 'first',
            '--machine-readable=file:/some/path',
            '-i', 'libvirt',
            '-ic', 'esx://root@1.2.3.4?',
            '-it', 'vddk',
            '-io', 'vddk-libdir=/opt/vmware-vix-disklib-distrib',
            '-io', 'vddk-thumbprint=01:23:45:67:89:AB:CD:EA:DB:EE:F0:12:34:56:78:9A:BC:DE:F0:12',  # NOQA E501
            '--password-file', '/vmware/password',
        ]
        v2v_args, v2v_env = wrapper.prepare_command(data, [])
        self.assertEqual(v2v_args, expected)

    def test_luks(self):
        STATE.machine_readable_log = '/some/path'
        data = self.VDDK_RHV.copy()
        data['luks_keys_files'] = [
            {
                'device': '/dev/sda1',
                'filename': '/tmp/luks/sda1',
            },
            {
                'device': '/dev/sda2',
                'filename': '/tmp/luks/sda2',
            },
        ]
        v2v_args, v2v_env = wrapper.prepare_command(data, [])
        self.assert_has_args(
            v2v_args,
            ['--key', '/dev/sda1:file:/tmp/luks/sda1'],
            'Looking for LUKS key of device sda1 %r' % v2v_args)
        self.assert_has_args(
            v2v_args,
            ['--key', '/dev/sda2:file:/tmp/luks/sda2'],
            'Looking for LUKS key of device sda2 %r' % v2v_args)

    def test_network_mappings(self):
        data = self.VDDK_RHV.copy()
        data['network_mappings'] = [
            {
                'source': 'src_net_1',
                'destination': 'dst_net_1'
            },
            {
                'source': 'src net 2',
                'destination': 'dst net 2'
            },
            {
                'source': 'src net 3',
                'destination': 'dst net 3',
                'mac_address': '01:23:45:67:89:AB',
            },
        ]
        v2v_args, v2v_env = wrapper.prepare_command(data, ["mac-option"])
        self.assert_has_args(
            v2v_args,
            ['--bridge', 'src_net_1:dst_net_1'],
            'Looking for network 1 in %r' % v2v_args)
        self.assert_has_args(
            v2v_args,
            ['--bridge', 'src net 2:dst net 2'],
            'Looking for network 2 in %r' % v2v_args)
        self.assert_has_args(
            v2v_args,
            ['--mac', '01:23:45:67:89:AB:bridge:dst net 3'],
            'Looking for network 3 in %r' % v2v_args)
