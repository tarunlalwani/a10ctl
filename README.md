# A10 Load Balanacer CLI (a10ctl)

`a10ctl` is a A10 Load balancer CLI tool. It currently has below mentioned functionality:

- List information about a server
- Enable a server
- Disable a server
- Enable certain ports for a server
- Disable certain ports for a server
- List or watch connections for a server
- Wait for Zero connections to a specific server or port
- List all servers configured in LB
- List all Service groups configure in LB

## Installing a10ctl

You need to have Python installed. For windows make sure to add python to PATH and Scripts directory inside python also to path. Also install using GIT Bash or GIT CMD

Installation is simple. Can be done in two way

### Install using pip

 ```sh
 pip install a10ctl
 ```

### Install using setup.py

 ```sh
 git clone https://github.com/tarunlalwani/a10ctl
 cd a10ctl
 python setup.py install
 ```

## A10 Config

There are 3 ways to configure or provide a10 configuration. These configuration parameters are
- host
- username
- password
- partition

#### Config file

Easiest way to create a config file is to use the `a10ctl config` command

```sh
$ a10ctl config
Where to create the config file?

        0 - ./.a10.conf
        1 - ~/.a10.conf
        2 - /etc/.a10.conf

[0]: 0
Enter profile name [root]: root
Enter host name []: lb
Enter username []: tarun
Enter password (Leave blank to save existing) [****]:
Enter partition [shared]: DMZ_WEB
Configuration saved!
```

This will create a `.a10.conf` file with below contents

```conf
[root]
host = lb
username = tarun
password = ..................
partition = DMZ_WEB
```

A user can create multiple profiles. The default profile is the `root` profile. If you choose to create the config file in current directory then `a10ctl` should always be used in the same directory for it to pick the config file

By default `a10ctl` looks for `.a10.conf` in below directories in order (stopping at the first one found):
- ./.a10.conf
- ~/.a10.conf
- /etc/.a10.conf

A custom config file path can be specified to `a10ctl` using the `-c` or `--config` flag. The profile can be specified using `-L` or `--profile` flag

```sh
$ a10ctl --config ~/mya10.conf --profile root
```

#### Environment variables

`a10ctl` supports below mentioned environment variables to configure the command line options

- A10_HOST
- A10_USERNAME
- A10_PASSWORD
- A10_PARTITION
- A10_CONFIG
- A10_PROFILE

```sh
$ export A10_HOST=lb
$ export A10_USERNAME=tarun
$ export A10_PASSWORD='xyz....'
$ export A10_PARTITION=DMZ_WEB
$ a10ctl servers
```

#### Command line parameters

All parameters support command line options as well

- -H or --host
- -u or --username
- -p or --password
- -k or --ask-password (will ask for username/password if not provided)
- -L or --profile (To provide profile name. root by default)
- -P or --partition (The partition name)

## Commands

All these commands assume that you have provided all the command line details about username, password, host, partition through environment variables or config file.

#### Get list of all Server

```sh
$ a10ctl servers
```

#### Get information about a server

```sh
$ a10ctl status 192.168.1.101
```

To get additional details on the server there are few flags that can be used
- `--groups` - List all the Virtual groups this service is part of
- `--services` - List all the Virtual Service this server is part of
- `--vservers` - List all the Virtual servers this server is part of
- `--all` - Get all the details without specifying above flags

```sh
$ a10ctl status --all 192.168.1.101
```

### Get list of all Virtual Groups

```sh
$ a10ctl groups
```

If you need to see members of each group use the `--members` flag

```sh
$ a10ctl groups --members
```

#### Disable a server in LB

Using IP

```sh
$ a10ctl disable 192.168.1.101
```

Using Name

```sh
$ a10ctl disable Name_192.168.1.101
```

If you need to wait for zero connections on the server you can pass a additional flag `--wait`. By default wait would timeout after `120` secs. You can change the timeout using `--timeout` flag if you want

```sh
$ a10ctl disable --wait --timeout 360 192.168.1.101
```

#### Enable a server in LB

```sh
$ a10ctl enable 192.168.1.101
```

#### Disable certain ports of a server in LB

```sh
$ a10ctl disableports 192.168.1.101 80
```

Disable multiple ports at the same time

```sh
$ a10ctl disableports 192.168.1.101 80 443
```

Like the disable command, this command also supports `--wait` and `--timeout` flag

```sh
$ a10ctl disableports --wait --timeout 360 192.168.1.101 80 443
```

#### Enable certain ports in LB

```sh
$ a10ctl enableports 192.168.1.101 80 443
```

#### Watch connections for a server

```sh
$ a10ctl connections 192.168.1.101
```

If you are interested only in certain ports, you can use `--port` or `-p` flag

```sh
$ a10ctl connections 192.168.1.101 --port 80 --port 443
```

The connection command displays current status and exits. To continuously watch for connection use `--watch` or `-w` flag. The interval to sleep between polling can be controlled using `--interval` or `-i` flag. Default interval is 5 secs.

```sh
$ a10ctl connections 192.168.1.101 --port 80 --port 443 --watch --interval 10
```

#### Wait for zero connections on a server or certain ports of server

Wait for zero connections on a server

```sh
$ a10ctl zeroconnections 192.168.1.101
```

Wait for zero connections os ports of server

```sh
$ a10ctl zeroconnections 192.168.1.101 --port 80 --port 443
```

Default timeout is `120` secs. The timeout can be changed using `--timeout` flag


# References

This code is fork of https://github.com/fim/a10ctl
