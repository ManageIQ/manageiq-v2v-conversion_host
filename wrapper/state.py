import tempfile
import os
import json
import stat

from .utils import add_perms_to_file


class StateObject(object):
    def as_dict(self):
        hidden = ['internal'] + getattr(self, '_hidden', [])
        slots = [key for key in getattr(self, '__slots__', self.__dict__)
                 if key not in hidden and not key.startswith('_')]
        return {key: getattr(self, key) for key in slots
                if getattr(self, key, None) is not None}


class _StateEncoder(json.JSONEncoder):
    def default(self, obj):  # pylint: disable=method-hidden
        if isinstance(obj, bytes):
            return obj.decode()
        if isinstance(obj, StateObject):
            return obj.as_dict()
        return json.JSONEncoder.default(self, obj)


class Disk(StateObject):
    """
    Represents one disk instance (to be) copied.
    """

    __slots__ = [
        'path',
        'progress',
    ]

    def __init__(self, path, progress=0.0):
        self.path = path
        self.progress = progress

    def __repr__(self):
        return "Disk(path=%s, progress=%.2f)" % (self.path, self.progress)


class _State(StateObject):
    """
    State object using a dict for data storage.

    This is not just the contain of state file, but it contains all the
    internal configuration.

    Gradual conversion from the dict to properties is to be expected.
    """

    __slots__ = [
        'state_file',
        'v2v_log',
        'machine_readable_log',
        'wrapper_log',
        '_tmp_dir',

        # These fields are written to the state file
        'disk_count',
        'disks',
        'failed',
        'finished',
        'internal',
        'last_message',
        'pid',
        'pre_copy',
        'return_code',
        'started',
        'status',
        'vm_id',
    ]

    _hidden = [
        'state_file',
        'v2v_log',
        'machine_readable_log',
        'wrapper_log',
        'pre_copy',
    ]

    def __init__(self):
        self.reset()

    def reset(self):
        """
        This function exists only so that the state can be re-used in tests
        """

        self._tmp_dir = None
        self.state_file = None
        self.v2v_log = None
        self.machine_readable_log = None

        self.disk_count = None
        self.disks = []
        self.failed = None
        self.finished = None
        self.internal = {
            'disk_ids': {},
            'display_name': None,
            'ports': [],
            'duplicate_logs': False,
            'password_files': []
        }
        self.last_message = None
        self.pid = None
        self.pre_copy = None
        self.started = None
        self.return_code = None
        self.vm_id = None
        self.wrapper_log = None
        self.status = None

    def write(self):
        tmp_state = tempfile.mkstemp(suffix='.v2v.state',
                                     dir=os.path.dirname(self.state_file))
        os.fchmod(tmp_state[0],
                  stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        with os.fdopen(tmp_state[0], 'w') as f:
            json.dump(self, f, cls=_StateEncoder)
            os.rename(tmp_state[1], self.state_file)

    def tmp_dir(self):
        if self._tmp_dir is None:
            d = os.getenv('V2V_WRAPPER_TMPDIR')
            if d is None:
                d = os.getenv('TMPDIR', '/var/tmp')
            self._tmp_dir = tempfile.TemporaryDirectory(prefix='v2v-', dir=d)

            # Let others browse it
            add_perms_to_file(self._tmp_dir.name, stat.S_IXOTH, -1, -1)

        return self._tmp_dir.name

    def finish(self):
        self._tmp_dir.cleanup()
        self._tmp_dir = None

        if self.failed is None:
            self.failed = False
        self.finished = True
        self.write()


STATE = _State()
