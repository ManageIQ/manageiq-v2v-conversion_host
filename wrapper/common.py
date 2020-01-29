import atexit
import copy
import logging
import os
import re
import stat
import subprocess
import sys
import tempfile

from .state import STATE


RUN_DIR = '/var/lib/uci'
LOG_DIR = '/var/log/uci'

VDDK_LIBDIR = '/opt/vmware-vix-disklib-distrib'
VDDK_LIBRARY_PATH = '/opt/vmware-vix-disklib-distrib/lib64'


def atexit_command(cmd):
    """
    Run command ignoring any errors. This is supposed to be used with atexit.
    """
    def remove(cmd):
        try:
            logging.info('Running command at exit: %r', cmd)
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            logging.warning(
                'Ignoring failed command at exit,'
                'returncode=%d, output=\n%s\n',
                e.returncode, e.output)
    atexit.register(lambda: remove(cmd))


def error(short_message, *args, **kwargs):
    """
    Used for error reporting, e.g.:

        error('Failed create port')
        error('Error starting ssh-agent',
              'Incomplete match: sock=%r; pid=%r', sock, pid)
        error(e.args[0],
              'An error occured, finishing state file...',
              exception=True)

    Note that this function is not mean to be used for all errors, only those
    that should be visible to the user. Essentially we want to report only the
    first error we encounter and do that in the form that is easy to understand
    to the user. For example, this function should not be used in
    handle_cleanup() methods. It is not used in _run_openstack() either because
    the error is not fit for user and caller should take care of proper error
    report.
    """
    if 'exception' in kwargs:
        is_exception = bool(kwargs['exception'])
        del kwargs['exception']
    else:
        is_exception = False
    if len(args) == 0:
        args = (short_message,)  # NOTE: tuple!!!
    if is_exception:
        logging.info('have exception: %r %r', args, kwargs)
        logging.exception(*args, **kwargs)
    else:
        logging.info('have error: %r %r', args, kwargs)
        logging.error(*args, **kwargs)
    STATE.last_message = {
        'message': short_message,
        'type': 'error'
        }
    STATE.write()


def hard_error(msg):
    """
    Function to produce an error and terminate the wrapper.

    WARNING: This can be used only at the early initialization stage! Do NOT
    use this once the password files are written or there are any other
    temporary data that should be removed at exit. This function uses
    sys.exit() which overcomes the code responsible for removing the files.
    """
    logging.error(msg)
    sys.stderr.write(msg)
    sys.stderr.write('\n')
    sys.exit(1)


def log_command_safe(args, env, log=None):
    args = copy.deepcopy(args)
    env = copy.deepcopy(env)
    # Filter command
    arg_re = re.compile('([^=]*password[^=]*)=(.*)', re.IGNORECASE)
    for i in range(1, len(args)):
        m = arg_re.match(args[i])
        if m:
            args[i] = '%s=*****' % m.group(1)
    # Filter environment
    env_re = re.compile('password', re.IGNORECASE)
    for k in env.keys():
        if env_re.search(k):
            env[k] = '*****'
    # Log the result
    if log is None:
        log = logging
    log.info('Executing command: %r, environment: %r', args, env)


def write_password(password, host):
    pfile = tempfile.mkstemp(suffix='.v2v')
    STATE.internal['password_files'].append(pfile[1])
    os.fchown(pfile[0], host.get_uid(), host.get_gid())
    os.write(pfile[0], bytes(password.encode('utf-8')))
    os.close(pfile[0])
    return pfile[1]


def add_perms_to_file(path, modes, uid=-1, gid=-1):
    cur_mode = stat.S_IMODE(os.stat(path).st_mode)
    new_mode = cur_mode | modes

    if uid != -1 or gid != -1:
        logging.debug('Changing uid:gid of "%s" to %s:%s',
                      path, uid, gid)
        os.chown(path, uid, gid)

    logging.debug('Changing permissions on "%s" from 0%o to 0%o',
                  path, cur_mode, new_mode)
    os.chmod(path, new_mode)


def nbd_uri_from_unix_socket(sock_path):
    return 'nbd+unix:///?socket=%s' % sock_path
