# zabbix-api-caller
zabbix api with golang

# Installation

## Linux

```
$ curl -sLO https://github.com/tkuchiki/zabbix-api-caller/releases/download/v0.0.1/zabbix-api-caller-linux-amd64.zip
$ unzip zabbix-api-caller-linux-amd64.zip
$ mv zabbix-api-caller-linux-amd64 zabbix-api-caller
```

# Build

```
go get
go build -o zabbix-api-caller main.go
```

# Usage

```
$ ./zabbix-api-caller --help
usage: zabbix-api-caller --file=FILE [<flags>] <command> [<args> ...]

Flags:
  --help           Show help (also see --help-long and --help-man).
  -f, --file=FILE  Config file
  -h, --hostname=HOSTNAME
                   Hostname
  --ipaddr=IPADDR  IP Address
  --version        Show application version.

Commands:
  help [<command>...]
    Show help.

  host status enable
    Enable host status

  host status disable
    Disable Host status

  host register
    Regist host

  host delete
    Delete host

  host list
    List host

```