# Description

This is a python project to manage Synology NAS devices.

## Requirements

* Use https://github.com/N4S4/synology-api.git
* Data should be in dataclasses, including configs, post data, return data. If object already exists in N4S4/synology-api, use that object.
* CLI exit code should be 0 on success, non-zero on failure. Different failures should have different exit codes.
* Create different classes for each functionality: class SynShareClient
*

## SynShareClient

* function to list shares

## Cli

global parameters are --username, --password, --host, --port (default: 5001), --insecure (default: false)
If user does not provide these parameters, look for environment variables: SYN_USERNAME, SYN_PASSWORD, SYN_HOST - if these are not set, error out.

### ./syn-cli list-shares

Lists all shares on the Synology NAS

./syn-cli list-shares -o (json,yaml,table - default table)

### ./syn-cli create-share

Creates a new share on the Synology NAS

./syn-cli create-share <name> -p <path>

## ./syn-cli apply-config

Create a source of truth for the Synology NAS configuration

./syn-cli apply-config <path>

The config would look something like this:

- host: 10.192.10.10
  volume1:
    - share_name: test1
      description: "test1"
      quota: 200
      acl:
        entries:
          - principal: "konri@jumpcloud.com"
            principal_type: user
            permissions: read_write
      nfs:
        rules:
          - client_cidr: "10.192.10.0/24"
            access: read_write
            root_squash: guest
            security_flavors:
              - sys
            async: false
            insecure: false
            crossmnt: false

The live NAS must match this config exactly. Obviously, don't remove the default local_group:administrators:read-write.
If ACL have other entries, they will be removed.
If NFS have other clients, they will be removed.
If share does not have NFS, then all NFS rules will be removed.
If share have nfs.rules, but rules is empty, then all NFS rules will be removed.
Only shares on this config will be managed.

If I want to delete the shares, I would put in state: absent (default is always present)

The script should basically get a list of all the shares on the NAS, create a dataclass object of it, then create a dataclass object of the shares in the config, then compare the two and make any necessary changes.

This package would also need a sample config that has all the possible options for shares.

## Testing and verification on live host

If you need to test out the code on a live synology device, the credentials are in credentials.json. It contains host address, username, and password.
