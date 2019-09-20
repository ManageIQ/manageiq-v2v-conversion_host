import unittest
from wrapper.pre_copy import _VMWare, PreCopy


class TestPreCopy(unittest.TestCase):
    """ Tests various pre-copy functionality (mostly URI parsing) """

    basic_data = {
        'output_format': 'raw',
        'vmware_uri': 'vpx://example.com',
        'vmware_fingerprint': '',
        'vmware_password': '',
        'vm_name': 'some-name',
        'two_phase': True,
    }

    def get_vmware(self, uri, two_phase=True):
        data = self.basic_data.copy()
        data['vmware_uri'] = uri
        return _VMWare(data)

    def test_uri_parsing_one_phase(self):
        """ Nothing should happen unless two phase conversion is requested. """

        data = self.basic_data.copy()
        data['vmware_uri'] = 'esx://example.com'
        data['two_phase'] = False
        vmw = PreCopy(data)

        self.assertIsNone(vmw)

    def test_uri_parsing_minimal(self):
        """ Make sure the VMWare URI is parsed correctly. """

        vmw = self.get_vmware('vpx://example.com')

        self.assertIsNotNone(vmw)
        self.assertEqual(vmw.user,
                         'administrator@vsphere.local')
        self.assertEqual(vmw.server, 'example.com')
        self.assertEqual(vmw.port, None)

    def test_uri_parsing(self):
        """ Make sure the VMWare URI is parsed correctly. """

        vmw = self.get_vmware('vpx://some.server:12345')

        self.assertIsNotNone(vmw)
        self.assertEqual(vmw.user,
                         'administrator@vsphere.local')
        self.assertEqual(vmw.server, 'some.server')
        self.assertEqual(vmw.port, 12345)

    def test_uri_parsing_full(self):
        """ Make sure the VMWare URI is parsed correctly. """

        vmw = self.get_vmware('esx://user%40domain@some.remote.server:443')

        self.assertIsNotNone(vmw)
        self.assertEqual(vmw.user, 'user@domain')
        self.assertEqual(vmw.server, 'some.remote.server')
        self.assertEqual(vmw.port, 443)
