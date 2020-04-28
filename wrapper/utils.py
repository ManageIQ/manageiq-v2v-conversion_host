"""
Common self-contained utilities

This file does not depend on any other file, not even state.py and cannot
therefore introduce circular dependencies
"""

import os
import stat
import logging


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
