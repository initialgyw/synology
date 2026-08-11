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

## Testing and verification on live host

If you need to test out the code on a live synology device, the credentials are in credentials.json. It contains host address, username, and password.
