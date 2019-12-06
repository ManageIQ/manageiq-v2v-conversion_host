#!/usr/bin/env python
#
# vim: foldmethod=marker foldlevel=99
#
# Copyright (c) 2018 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import json
import logging
import os
import re
import signal
import subprocess
import stat
import sys
import tempfile
import time

from .state import STATE, Disk
from .common import error, hard_error, log_command_safe
from .hosts import detect_host, KubevirtHost
from .log_parser import log_parser
from .checks import CHECKS

# Wrapper version
VERSION = "23"

RUN_DIR = '/var/lib/uci'
LOG_DIR = '/var/log/uci'
LOG_LEVEL = logging.DEBUG


############################################################################
#
#  Routines {{{
#

def prepare_command(data, v2v_caps, agent_sock=None):
    v2v_args = [
        '-v', '-x',
        data['vm_name'],
        '--root', 'first',
        '--machine-readable=file:{}'.format(STATE.machine_readable_log),
    ]

    if data['transport_method'] == 'vddk':
        v2v_args.extend([
            '-i', 'libvirt',
            '-ic', data['vmware_uri'],
            '-it', 'vddk',
            '-io', 'vddk-libdir=%s' % '/opt/vmware-vix-disklib-distrib',
            '-io', 'vddk-thumbprint=%s' % data['vmware_fingerprint'],
            '--password-file', data['vmware_password_file'],
            ])
    elif data['transport_method'] == 'ssh':
        v2v_args.extend([
            '-i', 'vmx',
            '-it', 'ssh',
            ])

    if 'network_mappings' in data:
        for mapping in data['network_mappings']:
            if 'mac_address' in mapping and 'mac-option' in v2v_caps:
                v2v_args.extend(['--mac', '%s:bridge:%s' %
                                (mapping['mac_address'],
                                    mapping['destination'])])
            else:
                v2v_args.extend(['--bridge', '%s:%s' %
                                (mapping['source'], mapping['destination'])])

    if 'luks_keys_files' in data:
        for luks_key in data['luks_keys_files']:
            v2v_args.extend([
                '--key',
                '%s:file:%s' % (
                    luks_key['device'],
                    luks_key['filename']
                )
            ])

    # Prepare environment
    v2v_env = os.environ.copy()
    v2v_env['LANG'] = 'C'
    logging.debug('Using direct backend. Hack, hack...')
    v2v_env['LIBGUESTFS_BACKEND'] = 'direct'
    if agent_sock is not None:
        v2v_env['SSH_AUTH_SOCK'] = agent_sock

    return (v2v_args, v2v_env)


def wrapper(host, data, v2v_caps, agent_sock=None):

    v2v_args, v2v_env = prepare_command(data, v2v_caps, agent_sock)
    v2v_args, v2v_env = host.prepare_command(
        data, v2v_args, v2v_env, v2v_caps)

    logging.info('Starting virt-v2v:')
    log_command_safe(v2v_args, v2v_env)

    runner = host.create_runner(v2v_args, v2v_env, STATE.v2v_log)
    try:
        runner.run()
    except RuntimeError:
        error('Failed to start virt-v2v', exception=True)
        STATE.failed = True
        STATE.write()
        return
    STATE.pid = runner.pid

    try:
        STATE.started = True
        STATE.write()
        with log_parser(isinstance(host, KubevirtHost)) as parser:
            while runner.is_running():
                parser.parse()
                STATE.write()
                host.update_progress()
                time.sleep(5)
            logging.info(
                'virt-v2v terminated with return code %d',
                runner.return_code)
            parser.parse()
    except Exception:
        STATE.failed = True
        error('Error while monitoring virt-v2v', exception=True)
        logging.info('Killing virt-v2v process')
        runner.kill()

    STATE.return_code = runner.return_code
    STATE.write()

    if STATE.return_code != 0:
        STATE.failed = True
    STATE.write()


def write_password(password, password_files, uid, gid):
    pfile = tempfile.mkstemp(suffix='.v2v')
    password_files.append(pfile[1])
    os.fchown(pfile[0], uid, gid)
    os.write(pfile[0], bytes(password.encode('utf-8')))
    os.close(pfile[0])
    return pfile[1]


def spawn_ssh_agent(data, uid, gid):
    cmd = [
        'setpriv', '--reuid=%d' % uid, '--regid=%d' % gid, '--clear-groups',
        'ssh-agent']
    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        error('Failed to start ssh-agent', exception=True)
        logging.error('Command failed with: %s', e.output)
        return None, None
    logging.debug('ssh-agent: %s' % out)
    sock = re.search(br'^SSH_AUTH_SOCK=([^;]+);', out, re.MULTILINE)
    pid = re.search(br'^echo Agent pid ([0-9]+);', out, re.MULTILINE)
    if not sock or not pid:
        error(
            'Error starting ssh-agent',
            'Incomplete match of ssh-agent output; sock=%r; pid=%r',
            sock, pid)
        return None, None
    try:
        agent_sock = sock.group(1)
        agent_pid = int(pid.group(1))
    except ValueError:
        error('Failed to parse ssh-agent output', exception=True)
        return None, None
    logging.info('SSH Agent started with PID %d', agent_pid)
    env = os.environ.copy()
    env['SSH_AUTH_SOCK'] = agent_sock
    cmd = [
        'setpriv', '--reuid=%d' % uid, '--regid=%d' % gid, '--clear-groups',
        'ssh-add']
    if 'ssh_key_file' in data:
        logging.info('Using custom SSH key')
        cmd.append(data['ssh_key_file'])
    else:
        logging.info('Using SSH key(s) from ~/.ssh')
    try:
        out = subprocess.check_output(
            cmd,
            env=env,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        error('Failed to add SSH keys to the agent', exception=True)
        logging.error("ssh-add output: %s", e.output)
        os.kill(agent_pid, signal.SIGTERM)
        return None, None
    return agent_pid, agent_sock


def virt_v2v_capabilities():
    try:
        out = subprocess.check_output(['virt-v2v', u'--machine-readable'])
        return out.decode('utf-8').split('\n')
    except subprocess.CalledProcessError:
        logging.exception('Failed to start virt-v2v')
        return None


#  }}}
#
############################################################################
#
#  Main {{{
#


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '--checks':
            for check in CHECKS.keys():
                print("%s" % check)
            sys.exit(0)
        if sys.argv[1][:8] == '--check-':
            check = CHECKS.get(sys.argv[1][8:])
            if check is not None and check():
                sys.exit(0)
            else:
                sys.exit(1)
        if sys.argv[1] == '--version':
            print('virt-v2v-wrapper %s' % VERSION)
            sys.exit(0)

    # Read and parse input -- hopefully this should be safe to do as root
    data = json.load(sys.stdin)
    host = detect_host(data)

    # The logging is delayed until we now which user runs the wrapper.
    # Otherwise we would have two logs.
    STATE.v2v_log = os.path.join(LOG_DIR, 'virt-v2v.log')
    STATE.machine_readable_log = os.path.join(LOG_DIR, 'virt-v2v-mr.log')
    wrapper_log = os.path.join(LOG_DIR, 'virt-v2v-wrapper.log')
    STATE.state_file = os.path.join(RUN_DIR, 'state.json')

    log_format = '%(asctime)s:%(levelname)s:' \
        + ' %(message)s (%(module)s:%(lineno)d)'
    logging.basicConfig(
        level=LOG_LEVEL,
        filename=wrapper_log,
        format=log_format)

    logging.info('Wrapper version %s, uid=%d', VERSION, os.getuid())

    logging.info('Will store virt-v2v log in: %s', STATE.v2v_log)
    logging.info('Will store state file in: %s', STATE.state_file)

    password_files = []

    # Collect virt-v2v capabilities
    virt_v2v_caps = virt_v2v_capabilities()
    if virt_v2v_caps is None:
        hard_error('Could not get virt-v2v capabilities.')
    logging.debug("virt-v2v capabilities: %r" % virt_v2v_caps)

    try:

        # Make sure all the needed keys are in data. This is rather poor
        # validation, but...
        if 'vm_name' not in data:
            hard_error('Missing vm_name')

        # Transports (only VDDK for now)
        if 'transport_method' not in data:
            hard_error('No transport method specified')
        if data['transport_method'] not in ('ssh', 'vddk'):
            hard_error('Unknown transport method: %s' %
                       data['transport_method'])

        if data['transport_method'] == 'vddk':
            for k in [
                    'vmware_fingerprint',
                    'vmware_uri',
                    'vmware_password',
                    ]:
                if k not in data:
                    hard_error('Missing argument: %s' % k)

        # Network mappings
        if 'network_mappings' in data:
            if isinstance(data['network_mappings'], list):
                for mapping in data['network_mappings']:
                    if not all(
                            k in mapping for k in ("source", "destination")):
                        hard_error('Both "source" and "destination"'
                                   ' must be provided in network mapping')
            else:
                hard_error('"network_mappings" must be an array')
        else:
            data['network_mappings'] = []

        # Method dependent validation
        data = host.validate_data(data)

        #
        # NOTE: don't use hard_error() beyond this point!
        #

        # Store password(s)
        logging.info('Writing password file(s)')
        if 'vmware_password' in data:
            data['vmware_password_file'] = write_password(
                    data['vmware_password'], password_files,
                    host.get_uid(), host.get_gid())
        if 'rhv_password' in data:
            data['rhv_password_file'] = write_password(data['rhv_password'],
                                                       password_files,
                                                       host.get_uid(),
                                                       host.get_gid())
        if 'ssh_key' in data:
            data['ssh_key_file'] = write_password(data['ssh_key'],
                                                  password_files,
                                                  host.get_uid(),
                                                  host.get_gid())

        if 'luks_keys_vault' not in data:
            data['luks_keys_vault'] = os.path.join(
                os.environ['HOME'],
                '.v2v_luks_keys_vault.json'
            )
        if os.path.exists(data['luks_keys_vault']):
            file_stat = os.stat(data['luks_keys_vault'])
            if file_stat.st_uid != host.get_uid():
                hard_error('LUKS keys vault does\'nt belong to'
                           'user running virt-v2v-wrapper')
            if file_stat.st_mode & stat.S_IRWXO > 0:
                hard_error('LUKS keys vault is accessible to others')
            if file_stat.st_mode & stat.S_IRWXG > 0:
                hard_error('LUKS keys vault is accessible to group')
            with open(data['luks_keys_vault']) as fp:
                luks_keys_vault = json.load(fp)
            if data['vm_name'] in luks_keys_vault:
                data['luks_keys_files'] = []
                for luks_key in luks_keys_vault[data['vm_name']]:
                    data['luks_keys_files'].append({
                        'device': luks_key['device'],
                        'filename': write_password(luks_key['key'],
                                                   password_files,
                                                   host.get_uid(),
                                                   host.get_gid())
                    })

        try:
            if 'source_disks' in data:
                logging.debug('Initializing disk list from %r',
                              data['source_disks'])
                for d in data['source_disks']:
                    STATE.disks.append(Disk(d, 0))
                logging.debug('Internal disk list: %r', STATE.disks)
                STATE.disk_count = len(data['source_disks'])
            # Create state file before dumping the JSON
            STATE.write()

            # Send some useful info on stdout in JSON
            print(json.dumps({
                'v2v_log': STATE.v2v_log,
                'wrapper_log': wrapper_log,
                'state_file': STATE.state_file,
            }))

            # Let's get to work
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.DEBUG)
            # TODO: drop junk from virt-v2v log
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logging.getLogger().addHandler(handler)
            agent_pid = None
            agent_sock = None
            if data['transport_method'] == 'ssh':
                agent_pid, agent_sock = spawn_ssh_agent(
                    data, host.get_uid(), host.get_gid())
                if agent_pid is None:
                    raise RuntimeError('Failed to start ssh-agent')
            wrapper(host, data, virt_v2v_caps, agent_sock)
            if agent_pid is not None:
                os.kill(agent_pid, signal.SIGTERM)
            if not STATE.failed:
                STATE.failed = not host.handle_finish(data)
        except Exception as e:
            # No need to log the exception, it will get logged below
            error(e.args[0],
                  'An error occured, finishing state file...',
                  exception=True)
            STATE.failed = True
            STATE.write()
            raise
        finally:
            if STATE.failed:
                # Perform cleanup after failed conversion
                logging.debug('Cleanup phase')
                try:
                    host.handle_cleanup(data)
                finally:
                    STATE.finished = True
                    STATE.write()

        # Remove password files
        logging.info('Removing password files')
        for f in password_files:
            try:
                os.remove(f)
            except OSError:
                error('Error removing password file(s)',
                      'Error removing password file: %s' % f,
                      exception=True)

        STATE.finished = True
        STATE.write()

    except Exception:
        logging.exception('Wrapper failure')
        # Remove password files
        logging.info('Removing password files')
        for f in password_files:
            try:
                os.remove(f)
            except OSError:
                error('Error removing password file(s)',
                      'Error removing password file: %s' % f,
                      exception=True)
        # Re-raise original error
        raise

    logging.info('Finished')
    if STATE.failed:
        sys.exit(2)


# }}}
if __name__ == '__main__':
    main()
