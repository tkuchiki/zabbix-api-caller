package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
	"net"
)

func GetIP(ipaddr string) (string, error) {
	var err error

	if ipaddr != "" {
		return ipaddr, err
	}

	var ifaces []net.Addr
	ifaces, err = net.InterfaceAddrs()
	for _, i := range ifaces {
		if ipnet, ok := i.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ipaddr = ipnet.IP.String()
			}
		}
	}
	return ipaddr, err
}

var (
	file         = kingpin.Flag("file", "Config file").Short('f').Required().String()
	hostname     = kingpin.Flag("hostname", "Hostname").Short('h').String()
	ipaddr       = kingpin.Flag("ipaddr", "IP Address").String()
	ignoreErrors = kingpin.Flag("ignore-errors", "Ignore errors").Bool()
	host         = kingpin.Command("host", "Operate host")
	// host status
	hostStatus = host.Command("status", "Operate host status")
	// host status enable
	hostStatusEnable = hostStatus.Command("enable", "Enable host status")
	// host status disable
	hostStatusDisable = hostStatus.Command("disable", "Disable Host status")
	// host register
	hostRegister = host.Command("register", "Regist host")
	// host delete
	hostDelete = host.Command("delete", "Delete host")
	// host list
	hostList = host.Command("list", "Host list")
)

func main() {
	var err error
	kingpin.Version("0.1.1")
	subcommand := kingpin.Parse()

	log := logrus.New()

	var config Config
	config, err = LoadYAML(*file, *hostname)
	if err != nil {
		log.Fatal(err)
	}

	var consul Consul
	consul, err = NewConsul()
	if err != nil {
		log.Fatal(err)
	}

	var storage Storage
	storage, err = NewStorage(config.DBPath, config.DBPerm)
	if err != nil {
		log.Fatal(err)
	}
	defer storage.Close()

	zabbix := NewZabbix(config, consul, storage)

	err = zabbix.APILogin()
	if err != nil {
		log.Fatal(err)
	}

	switch subcommand {
	case "host status enable":
		host, err := zabbix.HostGetByHost()
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}
		err = zabbix.HostEnable(host.HostId)
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}
	case "host status disable":
		host, err := zabbix.HostGetByHost()
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}
		err = zabbix.HostDisable(host.HostId)
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}
	case "host register":
		ipaddr, err := GetIP(*ipaddr)
		if err != nil {
			log.Fatal(err)
		}

		interfaces := zabbix.HostInterface("", ipaddr, 1, 1, 1)

		groups, err := zabbix.HostGroupIds(config.HostGroups)
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}

		templates, err := zabbix.Templates(config.Templates)
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}

		err = zabbix.HostCreate(config.Hostname, groups, interfaces, templates)
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}
	case "host delete":
		host, err := zabbix.HostGetByHost()
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}
		err = zabbix.HostDelete(host.HostId)
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}
	case "host list":
		zabbixHosts, err := zabbix.EnableHosts()
		if err != nil && !*ignoreErrors {
			log.Fatal(err)
		}

		for _, zHost := range zabbixHosts {
			fmt.Println(zHost.Hostname, zHost.IPAddr)
		}
	case "host proxy":
	}
}
