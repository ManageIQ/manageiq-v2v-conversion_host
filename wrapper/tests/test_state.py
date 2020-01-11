import json
import tempfile
import unittest
from wrapper import virt_v2v_wrapper as wrapper


class TestState(unittest.TestCase):
    """ Tests state object, make sure it it singleton """

    def setUp(self):
        # Destroy any previous state
        wrapper.STATE.reset()

    def test_dict(self):
        """ Make sure the access to internal dictionary works """
        state = wrapper.STATE
        self.assertEqual(state['disks'], [])
        self.assertEqual(state['internal']['disk_ids'], {})
        # check -- change -- check
        self.assertEqual(state['failed'], False)
        state['failed'] = True
        self.assertEqual(state['failed'], True)

    def test_singleton(self):
        state1 = wrapper.STATE
        state2 = wrapper.STATE
        # Internal dictionary
        key = 'abcdef'
        value = '123456'
        with self.assertRaises(KeyError):
            state1[key]
        with self.assertRaises(KeyError):
            state2[key]
        state1[key] = value
        self.assertEqual(state1[key], value)
        self.assertEqual(state2[key], value)
        # Property
        state1.state_file = None
        state2.state_file = None
        self.assertEqual(state1.state_file, None)
        self.assertEqual(state2.state_file, None)
        value = '/some/path'
        state1.state_file = value
        self.assertEqual(state2.state_file, value)

    def test_write(self):
        state = wrapper.STATE
        self.assertEqual(state.state_file, None)
        state.state_file = tempfile.mkstemp(prefix='vchtest')[1]
        state.write()
        with open(state.state_file, 'rb') as f:
            json.loads(f.read())

    def test_write_full(self):
        state = wrapper.STATE
        self.assertEqual(state.state_file, None)
        state.state_file = tempfile.mkstemp(prefix='vchtest')[1]
        state['disks'] = [
            {'path': '/some/path', 'progress': 12.34},
            {'path': '/some/other/path', 'progress': 0}
        ]
        # TODO: This can happen and it fails, so it needs to be fixed
        # state['last_message'] = b'Byte data being saved'
        state.write()
        with open(state.state_file, 'rb') as f:
            json.loads(f.read())
