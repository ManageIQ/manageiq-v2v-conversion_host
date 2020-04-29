import unittest
from wrapper.pre_copy import _VMWare, PreCopy
from wrapper.pre_copy import _get_overlay_path, _get_index_string


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

    def test_get_index_string_basic(self):
        """ Test mapping disk indices to string. """
        self.assertEqual(_get_index_string(0), 'a')
        self.assertEqual(_get_index_string(1), 'b')
        self.assertEqual(_get_index_string(5), 'f')
        self.assertEqual(_get_index_string(25), 'z')

        # Last positions in multi-digit numbers is treated differently, because
        # that's how the naming works out.

        #                                  a        a
        self.assertEqual(_get_index_string(1 * 26 + 0), 'aa')
        #                                  a        b
        self.assertEqual(_get_index_string(1 * 26 + 1), 'ab')
        #                                  a        z
        self.assertEqual(_get_index_string(1 * 26 + 25), 'az')
        #                                  b        a
        self.assertEqual(_get_index_string(2 * 26 + 0), 'ba')
        #                                  x         y
        self.assertEqual(_get_index_string(24 * 26 + 24), 'xy')
        #                                  a             a        a
        self.assertEqual(_get_index_string(1 * 26 * 26 + 1 * 26 + 0), 'aaa')
        #                                  a             e        a
        self.assertEqual(_get_index_string(1 * 26 * 26 + 5 * 26 + 0), 'aea')

        self.assertEqual(_get_index_string(1 * (26 ** 3) +  # a
                                           1 * (26 ** 2) +  # a
                                           1 * (26 ** 1) +  # a
                                           0 * (26 ** 0)),  # a
                         'aaaa')

        self.assertEqual(_get_index_string(1 * (26 ** 3) +  # a
                                           2 * (26 ** 2) +  # b
                                           3 * (26 ** 1) +  # c
                                           3 * (26 ** 0)),  # d
                         'abcd')

        self.assertEqual(_get_index_string(1 * (26 ** 4) +  # you
                                           1 * (26 ** 3) +  # get
                                           1 * (26 ** 2) +  # the
                                           1 * (26 ** 1) +  # point,
                                           0 * (26 ** 0)),  # right?
                         'aaaaa')

        self.assertEqual(_get_index_string(26 * (26 ** 4) +
                                           25 * (26 ** 3) +
                                           24 * (26 ** 2) +
                                           23 * (26 ** 1) +
                                           21 * (26 ** 0)),
                         'zyxwv')

    def test_get_index_string_transitions(self):
        """ Test mapping disk indices to string. """

        def str_idx(s):
            ret = ord(s[-1]) - ord('a')
            for i, c in enumerate(s[-2::-1], start=1):
                ret += (ord(c) - ord('a') + 1) * (26 ** i)
            return ret

        def str_idx_eq(idx):
            self.assertEqual(str_idx(_get_index_string(idx)), idx)

        # Test first 1024 disk names.
        #
        # This is here so that it can be easily changed to test more of them in
        # case of a failure later on, but I tested it for up to 26**5 with this
        # function and against linux kernel code up to 'jjjj'.
        for i in range(1024):
            str_idx_eq(i)

    def test_get_disk_path(self):
        """ Check that overlay paths are constructed properly. """

        self.assertEqual(_get_overlay_path('/some/temp/path', 'MyVM', 0),
                         '/some/temp/path/MyVM-sda.qcow2')
        self.assertEqual(_get_overlay_path('/other/path', 'vmName', 27),
                         '/other/path/vmName-sdab.qcow2')
        self.assertEqual(_get_overlay_path('/other/path', 'vmName', 51),
                         '/other/path/vmName-sdaz.qcow2')
        self.assertEqual(_get_overlay_path('/an/other/one', 'test', 18277),
                         '/an/other/one/test-sdzzz.qcow2')
