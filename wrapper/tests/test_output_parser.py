import unittest
from wrapper import virt_v2v_wrapper as wrapper
from wrapper.state import STATE, Disk


class TestOutputParser(unittest.TestCase):

    def setUp(self):
        # Destroy any previous state
        STATE.reset()

    def test_disk_number(self):
        STATE.v2v_log = '/dev/null'
        STATE.machine_readable_log = '/dev/null'
        with wrapper.log_parser() as parser:
            parser._current_disk = 0
            parser._current_path = '/path1'
            STATE.disks = [
                Disk('[store1] path1.vmdk'),
                Disk('[store1] path2.vmdk'),
                Disk('[store1] path3.vmdk'),
                ]
            parser.parse_line(b'Copying disk 2/3 to /some/path')
            self.assertEqual(parser._current_disk, 1)
            self.assertIsNone(parser._current_path)
            self.assertEqual(STATE['disk_count'], 3)

    def test_locate_disk(self):
        STATE.v2v_log = '/dev/null'
        STATE.machine_readable_log = '/dev/null'
        with wrapper.log_parser() as parser:
            parser._current_disk = 0
            parser._current_path = '[store1] path1.vmdk'
            STATE.disks = [
                Disk('[store1] path2.vmdk'),
                Disk('[store1] path1.vmdk'),
                Disk('[store1] path3.vmdk'),
                ]
            parser._locate_disk()
            self.assertEqual(STATE.disks[0].path, '[store1] path1.vmdk')
            self.assertEqual(STATE.disks[1].path, '[store1] path2.vmdk')
            self.assertEqual(STATE.disks[2].path, '[store1] path3.vmdk')

    def test_progress(self):
        STATE.v2v_log = '/dev/null'
        STATE.machine_readable_log = '/dev/null'
        with wrapper.log_parser() as parser:
            parser._current_disk = 0
            parser._current_path = '/path1'
            STATE.disks = [Disk('/path1', 0.0)]
            parser.parse_line(b'  (10.42/100%)')
            self.assertEqual(STATE.disks[0].progress, 10.42)

    # TODO
    # def test_rhv_disk_path_ssh(self):
    #     with wrapper.log_parser('/dev/null') as parser:
    #         state = {}
    #         state = parser.parse_line(
    #             b'  overlay source qemu URI: nbd:unix:/var/tmp/vddk.Iwg7XW/nbdkit1.sock:exportname=/')  # NOQA
    #         self.assertEqual(parser._current_path, '[store1] /path1.vmdk')

    def test_rhv_disk_path_vddk(self):
        STATE.v2v_log = '/dev/null'
        STATE.machine_readable_log = '/dev/null'
        with wrapper.log_parser() as parser:
            parser.parse_line(
                b'nbdkit: debug: Opening file [store1] /path1.vmdk (ha-nfcssl://[store1] path1.vmdk@1.2.3.4:902)')  # NOQA
            self.assertEqual(parser._current_path, '[store1] /path1.vmdk')

    def test_rhv_disk_uuid(self):
        STATE.v2v_log = '/dev/null'
        STATE.machine_readable_log = '/dev/null'
        with wrapper.log_parser() as parser:
            parser._current_disk = 0
            path = '/path1'
            STATE.disks = [Disk(path)]
            parser.parse_line(
                b'disk.id = \'11111111-1111-1111-1111-111111111111\'')
            self.assertIn(path, STATE['internal']['disk_ids'])
            self.assertEqual(
                STATE['internal']['disk_ids'][path],
                b'11111111-1111-1111-1111-111111111111')

    def test_osp_volume_uuid(self):
        STATE.v2v_log = '/dev/null'
        STATE.machine_readable_log = '/dev/null'
        with wrapper.log_parser() as parser:
            lines = [
                    br"openstack '--os-username=admin' '--os-identity-api-version=3' '--os-user-domain-name=Default' '--os-auth-url=http://10.19.2.25:5000//v3' '--os-volume-api-version=3' '--os-project-domain-name=Default' '--os-project-name=admin' '--os-password=100Root-' 'volume' 'show' '-f' 'json' '77c51545-f2a4-4bbf-8f04-169a15c23354'",  # NOQA
                    br"openstack '--os-username=admin' '--os-identity-api-version=3' '--os-user-domain-name=Default' '--os-auth-url=http://10.19.2.25:5000//v3' '--os-volume-api-version=3' '--os-project-domain-name=Default' '--os-project-name=admin' '--os-password=100Root-' 'volume' 'show' '-f' 'json' 'd85b7a6f-bffa-4b77-93df-912afd6e7014'",  # NOQA
                    ]
            for l in lines:
                parser.parse_line(l)
            self.assertIn(1, STATE['internal']['disk_ids'])
            self.assertIn(2, STATE['internal']['disk_ids'])
            self.assertEqual(
                STATE['internal']['disk_ids'][1],
                '77c51545-f2a4-4bbf-8f04-169a15c23354')
            self.assertEqual(
                STATE['internal']['disk_ids'][2],
                'd85b7a6f-bffa-4b77-93df-912afd6e7014')
