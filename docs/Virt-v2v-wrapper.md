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

* `vm_name`: name of the VM to import.

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

* `vmware_uri`: an URI containing the host and path to the VM files, e.g.
  `ssh://root@1.2.3.4/vmfs/volumes/datastore/tg-mini/tg-mini.vmx`.

* `vmware_password`: password used when connecting to the source hypervisor

* `vmware_fingerprint`: fingerprint of SSL certificate on the source
  hypervisor (also called thumbprint)

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

OpenStack instance migration is supported, but only to another OpenStack cloud.
OpenStack VMs cannot currently be migrated to RHV, for example. To set up a
migration from OpenStack to OpenStack, the source and destination clouds must
be configured with conversion host instances as shown in the sub-topics below.
The migration works by attaching volumes to the source and destination
conversion hosts and transferring data from inside the conversion hosts over
SSH.

### Source OpenStack cloud

* A conversion host instance must be launched from the UCI, in the same project
as the VM that is going to be moved. Keeping the conversion host in the same
project means that administrator credentials are not required for migration,
assuming everything else is already configured.
* The conversion host instance must have an IPv4 address that is accessible
from the destination OpenStack cloud.
* The conversion host instance must have SSH enabled in the security rules.
* The conversion host instance must be configured for key-based SSH access from
the destination conversion host instance (see input arguments below).
* The source VM must be shut down. If it is not already shut down, the wrapper
will shut it down forcibly before proceeding with the transfer.
* If the source VM is launched from a volume, there must be space in the
project's quota for one snapshot of that volume, and for one new volume to be
created from that snapshot.
* If the source VM is launched from an image, there must be space in the
project's quota for one new image snapshotted from that base image, and one new
volume that is the same size as that snapshot (this size may be checked in the
VM's flavor specification).


### Destination OpenStack cloud

* A conversion host instance must be launched from the UCI, in the same way
virt-v2v requires.
* The destination conversion host must be configured to be able to log in to
the source conversion host instance with an SSH key. The key can be specified
in the `ssh_key` input argument, or stored in /home/cloud-user/.ssh.

### OpenStack-specific inputs

To initiate an OpenStack migration, the input file must have the following keys
set:

* `vm_name`: The name of the migrated VM on the destination side
* `transport_method`: Must be set to "ssh" for OpenStack-to-OpenStack migration
* `osp_environment`: Contains the usual OpenStack destination arguments, passed
to the openstack command through virt-v2v. Each subkey must be prefixed with
'os-'.
* `osp_destination_project_id`: The ID of the receiving project on the
destination OpenStack side.
* `osp_flavor_id`: The flavor to use to create the new VM on the destination
OpenStack side, after all volumes are transferred.
* `osp_security_group_ids`: A list of IDs of the security groups that should be
applied to the new VM on the destination.
* `osp_server_id`: The ID of the destination conversion host.
* `insecure_connection`: Set to true or false to decide whether or not the
certificate of the destination OpenStack API should be verified.
* `source_disks`: Optional list of volume IDs to include in the transfer.
Without this, the wrapper will transfer all volumes connected to the source VM.
If this is set, the wrapper will only transfer the connected volumes that are
included in this list. Volumes that are included in this list but not connected
to the target VM will not be included in the transfer.
* `ssh_key`: An OpenSSH private key that is authorized on the source and
destination conversion host instances. Optional, but if this is missing then
care must be taken to authorize the destination conversion host's private key
on the source conversion host. The destination conversion host will expect to
have password-less SSH to the source conversion host!
* `osp_source_environment`: A set of sub-items to organize arguments for the
source OpenStack cloud.
  * `vm_id`: The ID of the target VM to migrate from the OpenStack source
  * `conversion_vm_id`: The ID of the source conversion host instance
  * `auth_url`: Public keystone URL for access to the OpenStack API
  * `username`: Source OpenStack username. Currently only username/password
  logins are supported for the source side.
  * `password`: Source OpenStack password
  * `user_domain_name`: Source OpenStack user domain
  * `project_name`: Name of project containing source conversion host instance
  * `project_domain_name`: Domain name of source project
  * `verify`: Verify source OpenStack API certificate (true or false)

Example:

	{
		"vm_name": "migration-vm",
		"transport_method": "ssh",
		"osp_environment": {
			"os-auth_url": "http://192.168.55.9:5000/v3",
			"os-username": "migration-user",
			"os-password": "migrate",
			"os-project_name": "migration-destination",
			"os-project_domain_name": "Default",
			"os-user_domain_name": "Default"
		},
		"osp_destination_project_id": "46deadaba9234ed4bef28caa459bdd16",
		"osp_flavor_id": "a96b2815-3525-4eea-9ab4-14ba58e17835",
		"osp_security_groups_ids": ["d5366f19-c34f-493c-a816-b305085c8fae"],
		"osp_server_id": "b9ca0b1b-0eba-45c4-8c0b-4f27457b72be",
		"insecure_connection": true,
		"osp_source_environment": {
			"auth_url": "http://192.168.75.19:5000/v3",
			"username": "new-migration-user",
			"password": "migrate",
			"project_name": "migration-source",
			"project_domain_name": "Default",
			"user_domain_name": "Default",
			"verify": false,
			"vm_id": "c28d5a15-0372-4222-95d3-13055f3c6a9b",
			"conversion_vm_id": "5143dba7-c8ac-4230-ac9a-dbd21788f209"
		},
		"ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n...\n-----END OPENSSH PRIVATE KEY-----\n"
	}

OpenStack migrations assume the wrapper is running in a UCI container on both
source and destination clouds. The wrapper serializes volume attachments by
writing lock files to /var/lock, so this directory must be exposed to all
destination instances if there are multiple migrations running concurrently. An
example invocation from the destination conversion host looks like this:

	sudo podman run --privileged --volume /dev:/dev --volume /etc/pki/ca-trust:/etc/pki/ca-trust --volume /var/tmp:/var/tmp --volume /v2v:/data --volume /v2v/lib:/var/lib/uci --volume /v2v/log:/var/log/uci --volume /opt/vmware-vix-disklib-distrib:/opt/vmware-vix-disklib-distrib --volume /var/lock:/var/lock v2v-conversion-host

This assumes a working directory named /v2v. The conversion JSON should be
placed in /v2v/input/conversion.json, and logs from the source conversion host
should be copied to `/v2v/source_logs` at the end of the migration. In the
event of a failure, there may be volumes or snapshots prefixed with
`rhosp-migration`. These may be detached and deleted.

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

### Openstack output

To select the Openstack method add `osp_environment` to the configuration. Together
with `osp_environment` some other keys need to be also specified.

* `osp_environment`: all environment variables (with values) needed to connect
  and authenticate to openstack (usually found in keystonerc file) with the
  project in which the conversion host is running, which will be passed directly
  to virt-v2v

* `osp_destination_project_id`: ID of a project in which the VM should end up
  after the conversion

* `osp_flavor_id`: ID of the flavor of created VM

* `osp_security_groups_ids`: array of IDs of all security groups to assign to the VM

* `osp_server_id`: ID of the conversion VM

* `insecure_connection`: optional, whether to verify certificates, default is
  `false`

Also the `network_mappings` array has to have a `mac_address` for each mapping.

Example:

    {
        "vm_name": "My_Machine",

        "osp_destination_project_id": "d159eb2e318f40d8a7b1ddd3edd5eb72",
        "osp_flavor_id": "m1.small",
        "osp_security_groups_ids": [],
        "osp_server_id": "9d8da538-1bf6-429d-84de-5b0f9d0c5ed0",

        "osp_environment": {
            "OS_AUTH_URL": "https://auth.url:13000/v3",
            "OS_PROJECT_ID": "c159eb2e318f40d8a7b1ddd3edd5eb73",
            "OS_PROJECT_NAME": "prow_jekt",
            "OS_USER_DOMAIN_NAME": "The_fault",
            "OS_PROJECT_DOMAIN_ID": "D-folt",
            "OS_USERNAME": "AzureDiamond",
            "OS_PASSWORD": "hunter2",
            "OS_REGION_NAME": "ree_johnUno",
            "OS_INTERFACE": "pubLick",
            "OS_IDENTITY_API_VERSION": 3
        },

        "insecure_connection": true,

        "transport_method": "vddk",
        "vmware_fingerprint": "1A:3F:26:C6:DC:2C:44:88:AA:33:81:3C:18:6E:5D:9F:C0:EE:DF:5C",
        "vmware_uri": "esx://root@10.2.0.20?no_verify=1",
        "vmware_password": "secret-password",
        "network_mappings": [
            {
                "mac_address": "00:50:56:a6:ee:58",
                "source": "VM Network",
                "destination": "prow_jekt-network"
            }
        ],
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
