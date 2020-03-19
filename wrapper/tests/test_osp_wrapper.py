import os
import json
import subprocess
import tempfile
import unittest

from wrapper.osp_wrapper import osp_wrapper_create


class TestOSPWrapper(unittest.TestCase):
    """ Tests for openstack wrapper functionality """

    SOME_IDS = [
        'fdsa-1',
        'fdsa-2',
        'fdsa-3',
        'asdf-3',
        ]

    def _run_wrapper(self, args, key=None):
        env = os.environ.copy()
        env['PATH'] = self._tmp_dir.name + os.pathsep + env['PATH']
        output = subprocess.check_output(['openstack'] + args,
                                         env=env,
                                         universal_newlines=True)
        if key is None:
            return output
        return json.loads(output)[key]

    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory(dir=os.getcwd())
        osp_wrapper_create(self._tmp_dir.name, 'echo', self.SOME_IDS, -1, -1)

    def tearDown(self):
        self._tmp_dir.cleanup()
        del self._tmp_dir

    def test_basic_create(self):
        volumes = []
        args = ['volume', 'create', '']
        for _ in range(len(self.SOME_IDS)):
            volumes.append(self._run_wrapper(args, 'id'))
        self.assertEqual(volumes, self.SOME_IDS)

    def test_create_overflow(self):
        # Deplete the IDs
        for _ in range(len(self.SOME_IDS)):
            self._run_wrapper(['volume', 'create', ''], 'id')
        with self.assertRaises(subprocess.CalledProcessError):
            self._run_wrapper(['volume', 'create', ''])

    def test_params_skip(self):
        volumes = []
        args = ['--insecure',
                '-f', 'json',
                '--osp-auth-url=test',
                'volume', 'create', '']
        for _ in range(len(self.SOME_IDS)):
            volumes.append(self._run_wrapper(args, 'id'))
        self.assertEqual(volumes, self.SOME_IDS)

    def test_volume_show(self):
        status = self._run_wrapper(['volume', 'show', ''], 'status')
        self.assertEqual(status, 'available')

    def test_volume_delete(self):
        output = self._run_wrapper(['volume', 'delete', ''])
        self.assertEqual(output, '')

    def test_attach(self):
        output = self._run_wrapper(['server', 'add', 'volume'])
        self.assertEqual(output, '')

    def test_detach(self):
        output = self._run_wrapper(['server', 'remove', 'volume'])
        self.assertEqual(output, '')

    def test_passthrough(self):
        args = ['--insecure',
                'volume', 'set',
                '--parameter\tvalue',
                '--param', 'value']
        output = self._run_wrapper(args)
        self.assertEqual(output, ' '.join(args) + '\n')
