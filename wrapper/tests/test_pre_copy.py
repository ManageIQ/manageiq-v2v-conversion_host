import unittest
from wrapper.pre_copy import _VMWare, PreCopy


class TestPreCopy(unittest.TestCase):
    """ Tests various pre-copy functionality (mostly URI parsing) """

    basic_data = {
        'output_format': 'raw',
        'vmware_uri': 'esx://esx1.example.com',
        'vmware_fingerprint': '',
        'vmware_password': '',
        'vm_name': 'some-name',
        'two_phase': True,
        'transport_method': 'vddk',
        'insecure_connection': True,
    }

    def get_vmware(self, uri, two_phase=True):
        data = self.basic_data.copy()
        data['vmware_uri'] = uri
        return _VMWare(data)

    def test_uri_parsing_one_phase_vpx(self):
        """ Nothing should happen unless two phase conversion is requested. """

        data = self.basic_data.copy()
        data['vmware_uri'] = 'vpx://vcenter.example.com'
        data['two_phase'] = False
        vmw = PreCopy(data)

        self.assertIsNone(vmw)

    def test_uri_parsing_one_phase_esx(self):
        """ Nothing should happen unless two phase conversion is requested. """

        data = self.basic_data.copy()
        data['vmware_uri'] = 'esx://esx1.example.com'
        data['two_phase'] = False
        vmw = PreCopy(data)

        self.assertIsNone(vmw)

    def test_uri_parsing_one_phase_ssh(self):
        """ Nothing should happen unless two phase conversion is requested. """

        data = self.basic_data.copy()
        data['vmware_uri'] = 'ssh://esx.local/vmfs/volumes/datastore/vm/vm.vmx'
        data['two_phase'] = False
        vmw = PreCopy(data)

        self.assertIsNone(vmw)

    def test_uri_parsing_minimal_vpx(self):
        """ Make sure the VMWare URI is parsed correctly with vpx:// scheme """

        vmw = self.get_vmware('vpx://vcenter.example.com')

        self.assertIsNotNone(vmw)
        self.assertEqual(vmw.user, 'administrator@vsphere.local')
        self.assertEqual(vmw.server, 'vcenter.example.com')
        self.assertEqual(vmw.port, None)
        self.assertEqual(vmw.insecure, False)

    def test_uri_parsing_minimal_esx(self):
        """ Make sure the VMWare URI is parsed correctly with esx:// scheme """

        vmw = self.get_vmware('esx://esx1.example.com/?no_verify=1')

        self.assertIsNotNone(vmw)
        self.assertEqual(vmw.user, 'root')
        self.assertEqual(vmw.server, 'esx1.example.com')
        self.assertEqual(vmw.port, None)
        self.assertEqual(vmw.insecure, True)

    def test_uri_parsing_minimal_ssh(self):
        """ Make sure the VMWare URI is parsed correctly with ssh:// scheme """

        uri = 'ssh://esx1.example.com/vmfs/volumes/datastore/vm/vm.vmx'
        vmw = self.get_vmware(uri)

        self.assertIsNotNone(vmw)
        self.assertEqual(vmw.user, 'root')
        self.assertEqual(vmw.server, 'esx1.example.com')
        self.assertEqual(vmw.port, None)
        self.assertEqual(vmw.insecure, True)

    def test_uri_parsing(self):
        """ Make sure the VMWare URI is parsed correctly. """

        vmw = self.get_vmware('esx://some.server:12345')

        self.assertIsNotNone(vmw)
        self.assertEqual(vmw.user, 'root')
        self.assertEqual(vmw.server, 'some.server')
        self.assertEqual(vmw.port, 12345)

    def test_uri_parsing_full(self):
        """ Make sure the VMWare URI is parsed correctly. """

        vmw = self.get_vmware('esx://user%40domain@some.remote.server:443')

        self.assertIsNotNone(vmw)
        self.assertEqual(vmw.user, 'user@domain')
        self.assertEqual(vmw.server, 'some.remote.server')
        self.assertEqual(vmw.port, 443)
