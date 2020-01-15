import unittest
from wrapper import hosts


class TestOvirt(unittest.TestCase):
    """ Test specific to oVirt """

    VDDK_OVIRT = {
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

    # TODO: remove once virt-v2v supports global trust store
    CA_PATH = '/etc/pki/ca-trust/source/anchors'
    CA_FILE = 'v2v-conversion-host-ca-bundle.pem'

    def test_vddk_ovirt_basic(self):
        data = self.VDDK_OVIRT.copy()
        expected = [
            '--bridge', 'ovirtmgmt',
            '-of', 'raw',
            '-o', 'rhv-upload',
            '-oc', 'https://example.my-ovirt.org/ovirt-engine/api',
            '-os', 'data',
            '-op', '/rhv/password',
            # TODO: remove once virt-v2v supports global trust store
            '-oo', 'rhv-cafile=%s/%s' % (self.CA_PATH, self.CA_FILE),
            '-oo', 'rhv-cluster=Default',
            '-oo', 'rhv-direct',
            '-oo', 'rhv-verifypeer=true',
        ]
        host = hosts.BaseHost.factory(hosts.BaseHost.TYPE_OVIRT)
        v2v_args, v2v_env = host.prepare_command(
                data, [], {}, [])
        self.assertEqual(v2v_args, expected)

    def test_vddk_ovirt_insecure(self):
        data = self.VDDK_OVIRT.copy()
        data['insecure_connection'] = True
        expected = [
            '--bridge', 'ovirtmgmt',
            '-of', 'raw',
            '-o', 'rhv-upload',
            '-oc', 'https://example.my-ovirt.org/ovirt-engine/api',
            '-os', 'data',
            '-op', '/rhv/password',
            # TODO: remove once virt-v2v supports global trust store
            '-oo', 'rhv-cafile=%s/%s' % (self.CA_PATH, self.CA_FILE),
            '-oo', 'rhv-cluster=Default',
            '-oo', 'rhv-direct',
            '-oo', 'rhv-verifypeer=false',
        ]
        host = hosts.BaseHost.factory(hosts.BaseHost.TYPE_OVIRT)
        v2v_args, v2v_env = host.prepare_command(
                data, [], {}, [])
        self.assertEqual(v2v_args, expected)
