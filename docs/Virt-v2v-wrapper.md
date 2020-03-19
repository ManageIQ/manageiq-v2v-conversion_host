# Virt-v2v Wrapper

The script shields the caller from complexities involved in starting virt-v2v
on oVirt/RHV host. It monitors the progress of the conversion, providing the
status information in a state file. This allows for asynchronous conversion
workflow.

The expected usage is as follows:

1)  *wrapper start*: client runs the wrapper; at the moment there are no
    command line arguments and everything is configured by JSON data presented
    on stdin

2)  *initialization*: wrapper read JSON data from stdin, parses and validates
    the content; based on the situation it may also change the effective user
    to a non-root account; wrapper writes to stdout simple JSON containing
    paths to wrapper log file (`wrapper_log`), virt-v2v log file (`v2v_log`),
    state file (`state_file`) that can be used to monitor the progress

3)  Optionally, if `two_phase` conversion is selected (not supported for all
    input and output modes), it will copy the disks to their destinations and
    generate a libvirt XML to be used as an input to the virt-v2v process

4)  *conversion*: finally, virt-v2v process is executed; wrapper monitors its
    output and updates the state file on a regular basis

5)  *finalization*: when virt-v2v terminates wrapper updates the state file
    one last time and exits


## Input Data

This section describes various keys understood by the wrapper in JSON on
input. Keys are mandatory unless explicitly stated otherwise.

General information:

* `vm_name`: name of the VM to import. In case of `ssh` transport method this
  is an URI containing the host and path to the VM files, e.g.
  `ssh://root@1.2.3.4/vmfs/volumes/datastore/tg-mini/tg-mini.vmx`.

* `output_format`: one of `raw`, or `qcow2`; default is `raw` if not specified

* `transport_method`: type of transport to use; supported methods are `ssh` and
  `vddk`.

For `vddk` the following keys need to be specified:

* `vmware_uri`: libvirt URI of the source hypervisor

* `vmware_password`: password used when connecting to the source hypervisor

* `vmware_fingerprint`: fingerprint of SSL certificate on the source
  hypervisor (also called thumbprint)

For `ssh` method there are no other information necessary. Optionaly the
following can be specified:

* `ssh_key`: optional, private part of SSH key to use. If this is not provided
  then keys in ~/.ssh directory are used.

Two-phase conversion can be requested by setting `two_phase` to `True` at which
point the following key is mandatory:

* `conversion_host_uuid`: the UUID of a VM in which the actual conversion is
  being performed.

Output configuration: reffer to the section [Output
configuration](#output-configuration) below.

Miscellaneous:

* `source_disks`: optional key containing list of disks in the VM; if specified
  it is used to initialize progress information in the state file

* `network_mappings`: optional key containing list of network mappings; if
   specified, it is used to connect the VM's NICs to the destination networks
   during the conversion using virt-v2v `--bridge` option.

* `install_drivers`: optional key whether to install Windows drivers during
  conversion, default is `false`.

* `allocation`: optional key specifying the allocation type to use; possible
  values are `preallocated` and `sparse`.

* `luks_keys_vault`: optional key to specify a JSON file containing the LUKS
  keys for encrypted devices (see below).

Debugging:

All keys in this section are subject to change without notice and should not be relied upon.  They exist *only* for debugging.

* `rhv_debug`: optional key to enable debugging of `ovirtsdk4` API calls.

## Output configuration

There is no configuration key specifying the type of output. Rather the output
method is chosen depending on the keys present. The only supported output mode
is oVirt API upload.

### oVirt API upload

To select oVirt API upload method add `rhv_url` to the configuraton. Together
with `rhv_url` some other keys need to be also specified.

* `rhv_url`: URL to the oVirt API endpoint.

* `rhv_password`: password used to authorize to API

* `rhv_cluster`: name of the target cluster

* `rhv_storage`: name of the target storage domain

* `insecure_connection`: optional, whether to verify peer certificates. Default
  is `false`. The default path for the CA certificates file is
  `/etc/pki/ca-trust/source/anchors/v2v-conversion-host-ca-bundle.pem`.

Example:

    {
        "vm_name": "My_Machine",

        "transport_method": "vddk",
        "vmware_fingerprint": "1A:3F:26:C6:DC:2C:44:88:AA:33:81:3C:18:6E:5D:9F:C0:EE:DF:5C",
        "vmware_uri": "esx://root@10.2.0.20?no_verify=1",
        "vmware_password": "secret-password",

        "rhv_url": "https://ovirt.example.com/ovirt-engine/api",
        "rhv_password": "secret-password",
        "rhv_cluster": "Default",
        "rhv_storage": "data",
        "insecure_connection": true

        "source_disks": [
            "[dataStore_1] My_Machine/My_Machine_1.vmdk",
            "[dataStore_1] My_Machine/My_Machine_2.vmdk"
        ],
        "network_mappings": [
            {
                "source": "networkA1",
                "destination": "networkA2"
            },
            {
                "source": "networkX1",
                "destination": "networkX2"
            }
        ],
        "luks_keys_vault": "/path_to/luks_key_vault.json"
    }

## State File Format

State file is a JSON file. Its content changes as the conversion goes through
various stages. With it also the keys present in the file.

the output differs based on the type of conversion that is running:

<a id="anchor_onephase"></a>
### One-Phase Conversion

Once virt-v2v is executed the state file is created with the following keys:

* `started`: with value `true`

* `pid`: the process ID of virt-v2v. This can be used to kill the process and
  terminate the conversion. In this case, once virt-v2v terminates (with
  non-zero return code) the wrapper immediately terminates too.

* `disks`: array of progress per each disk. The value is either empty list or
  a list of objects initialized from `source_disks` passed to the wrapper. If
  no `source_disks` is specified, the `disks` list is constructed incrementally
  during the conversion process.

* `disk_count`: the number of disks that will be copied. Initially zero or
  number of disks in `source_disks`. When virt-v2v starts copying disks, the
  value is updated to match the count of disks virt-v2v will actually copy.
  Note that the values does not have to represent the length of `disks` array!
  If `source_disks` is not specified or contains invalid values length of
  `disks` can be smaller or larger than `disk_count`.

When virt-v2v gets past the initialization phase and starts copying disks the
wrapper updates the progress for each disk in the `disks` list. Each item in
the list contains the following keys:

* `path`: the path description of the disk as the backend sees it

* `progress`: the percentage of the disk copied, in the range from 0 to 100 (as
  numeric)

When virt-v2v finishes the state is updated with the following keys:

* `return_code`: return code of virt-v2v process. As usual 0 means the process
  terminated successfully and any non-zero value means an error. Note however,
  that the value should not be used to check if conversion succeeded or failed.
  (See below.)

* `vm_id`: unique ID of the newly created VM. Available in OSP and RHV.

Right before the wrapper terminates it updates the state with:

* `finished`: with value `true`

* `failed`: with value `true` if the conversion process failed.

### Two-Phase Conversion

* `disks`: This key includes a list of disks and for each one there is
  information about the progress of copying disks before running virt-v2v.  The
  data are pulled from the source server and they are being updated depending on
  the progress.
  
Once virt-v2v is started all keys from the [One-Phase Conversion](#anchor_onephase)
except `disks` and `disk_count` are updated in a similar fashion.

## LUKS encrypted devices

virt-v2v-wrapper always looks for a default path:
`${HOME}/.v2v_luks_keys_vault.json`. The file MUST NOT be readable by group
or other.

In the file, the devices names are not the actual names of the devices inside
the virtual machine. They mainly represent the order: /dev/sda means that it
is the first disk, /dev/sda1 means that it is the first encrypted partition
on the first disk.

Example LUKS keys file:

```
{
    "my_vm_1": [
        {
            "device": "/dev/sda1",
            "key": "secret11"
        },
        {
            "device": "/dev/sda2",
            "key": "secret12"
        }
    ],
    "my_vm_2": [
        {
            "device": "/dev/sda1",
            "key": "secret11"
        }
    ]
}
```
