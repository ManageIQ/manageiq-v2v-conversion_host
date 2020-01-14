import subprocess

VIRT_V2V = '/usr/bin/virt-v2v'


class BaseRunner(object):

    def __init__(self, host, arguments, environment, log):
        self._arguments = arguments
        self._environment = environment
        self._host = host
        self._log = log
        self._pid = None
        self._return_code = None

    def is_running(self):
        """ Returns True if process is still running """
        raise NotImplementedError()

    def kill(self):
        """ Stop the process """
        raise NotImplementedError()

    @property
    def pid(self):
        """ Get PID of the process """
        return self._pid

    @property
    def return_code(self):
        """ Get return code of the process or None if it is still running """
        return self._return_code

    def run(self):
        """ Start the process """
        raise NotImplementedError()


class SubprocessRunner(BaseRunner):

    def is_running(self):
        return self._proc.poll() is None

    def kill(self):
        self._proc.kill()

    @property
    def pid(self):
        return self._proc.pid

    @property
    def return_code(self):
        self._proc.poll()
        return self._proc.returncode

    def run(self):
        with open(self._log, 'w') as log:
            self._proc = subprocess.Popen(
                    [VIRT_V2V] + self._arguments,
                    stdin=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    stdout=log,
                    env=self._environment,
                    )
