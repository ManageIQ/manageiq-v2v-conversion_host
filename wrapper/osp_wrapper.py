import os
import shutil
import stat

from wrapper.utils import add_perms_to_file

_SCRIPT = r'''#!/bin/bash

set -e

main() {
    local my_path="$(dirname "$0")"
    local orig_cmd="$(head -1 "${my_path}/osp_cmd" | tr -d '\n')"
    local data_path="${my_path}/osp_data"
    local orig_args=( "$@" )

    # Skip parameters
    while [[ "$1" =~ ^- ]];
    do
        case "$1" in
            *=*) ;;
            --insecure) ;;
            *)
                # Double skip for things like:
                #   '--osp-auth-url' 'some://uri'
                # or
                #   '-f' 'json'
                # Even those should not show up in this place / manner
                shift
                ;;
        esac
        shift
    done

    if (( $# < 3 ))
    then
        echo '{"errno":"ENOPE","otha":'
        "$orig_cmd" "${orig_args[@]}"
        echo '}'
    fi

    if [[ "$1 $2" == "volume create" ]]
    then
        if [[ "$(wc -l "$data_path" | cut -d' ' -f1)" == 0 ]]
        then
            echo "Unexpected number of volumes" >&2
            return 1
        fi

        tail -n +2 "$data_path" >"${data_path}.new"
        # JSON output on one line
        echo '{"id":"'"$(head -1 "$data_path")"'"}'
        mv "$data_path"{.new,}
        return 0
    fi

    if [[ "$1 $2" == "volume show" ]]
    then
        echo '{"status":"available"}'
        return 0
    fi

    if [[ "$1 $2" == "volume delete" ]]
    then
        # virt-v2v-wrapper will take care of cleaning up the volumes
        return 0
    fi

    if [[ "$1 $3" == "server volume" ]]
    then
        if [[ "$2" == "add" || "$2" == "remove" ]]
        then
            return 0
        fi
    fi

    "$orig_cmd" "${orig_args[@]}"
}

main "$@"
'''


def osp_wrapper_create(path, command, volumes, uid, gid):
    script_path = os.path.join(path, 'openstack')
    with open(script_path, 'w') as f:
        f.write(_SCRIPT)
    add_perms_to_file(script_path, stat.S_IXUSR | stat.S_IXGRP, uid, gid)
    with open(os.path.join(path, 'osp_cmd'), 'w') as f:
        f.write(shutil.which(command))
    with open(os.path.join(path, 'osp_data'), 'w') as f:
        f.write('\n'.join(volumes) + '\n')
