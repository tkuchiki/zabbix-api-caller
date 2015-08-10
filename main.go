package main

import (
	"fmt"
	"github.com/AlekSi/zabbix"
	"github.com/hashicorp/consul/api"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type HostTemplateId struct {
	TemplateId string `json:"templateid"`
}
type TemplateIds []HostTemplateId

type Templates []string
type GroupNames []string
type ZabbixHost struct {
	Hostname string
	IPAddr   string
}

type Config struct {
	ZabbixServer    string   `yaml:"zabbix_server"`
	ConsulKVKey     string   `yaml:"consul_kv_key"`
	Username        string   `yaml:"username"`
	Password        string   `yaml:"password"`
	HostGroups      []string `yaml:"host_groups"`
	Templates       []string `yaml:"templates"`
	Hostname        string   `yaml:"hostname"`
	IpAddr          string   `yaml:"ipaddr"`
	ZabbixAgentPort string   `yaml:"zabbix_agent_port"`
}

func AbsPath(fname string) (f string, err error) {
	var fpath string
	matched, _ := regexp.Match("^~/", []byte(fname))
	if matched {
		usr, _ := user.Current()
		fpath = strings.Replace(fname, "~", usr.HomeDir, 1)
	} else {
		fpath, err = filepath.Abs(fname)
	}

	return fpath, err
}

func LoadYAML(filename string) (config Config, err error) {
	fpath, err := AbsPath(filename)
	if err != nil {
		return config, err
	}
	buf, err := ioutil.ReadFile(fpath)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(buf, &config)

	return config, err
}

func Hostname(name string) (hostname string, err error) {
	if name != "" {
		return name, err
	} else if config.Hostname != "" {
		return config.Hostname, err
	} else {
		hostname, err = os.Hostname()
		return hostname, err
	}
}

func ZabbixAgentPort() (port string) {
	if config.ZabbixAgentPort == "" {
		return zabbixAgentPort
	}

	return config.ZabbixAgentPort
}

func APINewClient(config *api.Config) (client *api.Client, err error) {
	client, err = api.NewClient(config)
	return client, err
}

func GetPair(key string) (pair *api.KVPair, err error) {
	pair, _, err = kv.Get(key, nil)

	return pair, err
}

func PutKV(key, value string) (err error) {
	p := &api.KVPair{Key: key, Value: []byte(value)}
	_, err = kv.Put(p, nil)

	return err
}

func GetIP() (ipaddr string, err error) {
	var ifaces []net.Addr
	if config.IpAddr != "" {
		return config.IpAddr, err
	}
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

func ZabbixAPI() *zabbix.API {
	return zabbix.NewAPI(config.ZabbixServer + "/api_jsonrpc.php")
}

func ZabbixAPILogin(username, password string) (err error) {
	var res zabbix.Response
	var pair *api.KVPair
	var token string

	pair, err = GetPair(config.ConsulKVKey)
	if err != nil {
		return err
	}
	if pair != nil {
		token = string(pair.Value)
	}
	zabbixapi.Auth = token
	res, err = zabbixapi.Call("user.get", zabbix.Params{"output": "extend"})
	if err != nil || res.Error != nil {
		token, err = zabbixapi.Login(username, password)
		if err == nil {
			err = PutKV(config.ConsulKVKey, token)
		}
	}

	return err
}

func ZabbixHostInterface(dns, ip, port string, main, useip int, _type zabbix.InterfaceType) zabbix.HostInterface {
	return zabbix.HostInterface{
		DNS:   dns,
		IP:    ip,
		Port:  port,
		Main:  main,
		UseIP: useip,
		Type:  _type,
	}
}

func ZabbixHostCreate(host string, groupIds zabbix.HostGroupIds, interfaces zabbix.HostInterfaces, templates TemplateIds) (err error) {
	i := 0
	for {
		res, err := zabbixapi.Call("host.create", zabbix.Params{"host": host,
			"groups":     groupIds,
			"interfaces": interfaces,
			"templates":  templates,
		})
		fmt.Println(res)
		if (err == nil && res.Error == nil) || i == retry {
			break
		}
		i++
		time.Sleep(sleepTime)
	}
	return err
}

func ZabbixHostGetByHost(hostname string) (host *zabbix.Host, err error) {
	i := 0
	for {
		host, err = zabbixapi.HostGetByHost(hostname)
		if err == nil || i == retry {
			break
		}
		i++
		time.Sleep(sleepTime)
	}

	return host, err
}

func ZabbixHostDelete(hostid string) (err error) {
	h := zabbix.Host{HostId: hostid}
	hosts := zabbix.Hosts{h}

	i := 0
	for {
		err = zabbixapi.HostsDelete(hosts)
		if err == nil || i == retry {
			break
		}
		i++
		time.Sleep(sleepTime)
	}

	return err
}

func ZabbixTemplates(templates Templates) (templateIds TemplateIds, err error) {
	var res zabbix.Response
	hostTemplates := map[string]Templates{"host": templates}
	i := 0
	for {
		res, err = zabbixapi.Call("template.get", zabbix.Params{"output": "shorten", "filter": hostTemplates})

		if res.Error == nil {
			for _, template := range res.Result.([]interface{}) {
				t := template.(map[string]interface{})
				templateIds = append(templateIds, HostTemplateId{TemplateId: t["templateid"].(string)})
			}
		}

		if (err == nil && res.Error == nil) || i == retry {
			break
		}
		i++
		time.Sleep(sleepTime)
	}

	return templateIds, err
}

func ZabbixGroupIds(groupNames GroupNames) (groupIds zabbix.HostGroupIds, err error) {
	var res zabbix.Response
	names := map[string]GroupNames{"name": groupNames}
	i := 0
	for {
		res, err = zabbixapi.Call("hostgroup.get", zabbix.Params{"output": "shorten", "filter": names})

		if res.Error == nil {
			for _, group := range res.Result.([]interface{}) {
				g := group.(map[string]interface{})
				groupIds = append(groupIds, zabbix.HostGroupId{GroupId: g["groupid"].(string)})
			}
		}

		if (err == nil && res.Error == nil) || i == retry {
			break
		}
		i++
		time.Sleep(sleepTime)
	}

	return groupIds, err
}

func ZabbixHostUpdateStatus(hostid string, status int) (err error) {
	i := 0
	for {
		res, err := zabbixapi.Call("host.update", zabbix.Params{"hostid": hostid, "status": status})
		if (err == nil && res.Error == nil) || i == retry {
			break
		}
		i++
		time.Sleep(sleepTime)
	}

	return err
}

func ZabbixHosts(available, status string) (map[string]ZabbixHost, error) {
	var res zabbix.Response
	var err error
	filters := map[string][]string{"hostids": config.HostGroups, "available": []string{available}, "status": []string{status}}
	var zabbixHosts map[string]ZabbixHost = make(map[string]ZabbixHost)
	var hostIds []string
	i := 0
	for {
		res, err = zabbixapi.Call("host.get", zabbix.Params{"output": "extend", "filter": filters})

		if res.Error == nil {
			for _, h := range res.Result.([]interface{}) {
				hostObject := h.(map[string]interface{})
				zHostName := hostObject["name"].(string)
				hostid := hostObject["hostid"].(string)
				hostIds = append(hostIds, hostid)
				zabbixHosts[hostid] = ZabbixHost{Hostname: zHostName, IPAddr: ""}
			}
		}

		if (err == nil && res.Error == nil) || i == retry {
			break
		}
		i++
		time.Sleep(sleepTime)
	}

	zabbixHosts, err = ZabbixHostIPs(zabbixHosts, hostIds)

	return zabbixHosts, err
}

func ZabbixHostIPs(zabbixHosts map[string]ZabbixHost, hostIds []string) (map[string]ZabbixHost, error) {
	var res zabbix.Response
	var err error
	i := 0
	for {
		res, err = zabbixapi.Call("hostinterface.get", zabbix.Params{"output": "extend", "hostids": hostIds})

		if res.Error == nil {
			for _, h := range res.Result.([]interface{}) {
				hostInterface := h.(map[string]interface{})
				ipaddr := hostInterface["ip"].(string)
				hostid := hostInterface["hostid"].(string)
				tmp := zabbixHosts[hostid]
				tmp.IPAddr = ipaddr
				zabbixHosts[hostid] = tmp
			}
		}

		if (err == nil && res.Error == nil) || i == retry {
			break
		}
		i++
		time.Sleep(sleepTime)
	}

	return zabbixHosts, err
}

func ZabbixEnableHosts() (map[string]ZabbixHost, error) {
	var err error
	var zabbixHosts map[string]ZabbixHost = make(map[string]ZabbixHost)
	zabbixHosts, err = ZabbixHosts("1", "0")
	return zabbixHosts, err
}

func ZabbixDisableHosts() (map[string]ZabbixHost, error) {
	var err error
	var zabbixHosts map[string]ZabbixHost = make(map[string]ZabbixHost)
	zabbixHosts, err = ZabbixHosts("1", "1")
	return zabbixHosts, err
}

func ZabbixHostEnable(hostid string) (err error) {
	return ZabbixHostUpdateStatus(hostid, 0)
}

func ZabbixHostDisable(hostid string) (err error) {
	return ZabbixHostUpdateStatus(hostid, 1)
}

var (
	zabbixapi       *zabbix.API
	username        string
	password        string
	config          Config
	kv              *api.KV
	retry           int           = 3
	sleepTime       time.Duration = 500 * time.Millisecond
	zabbixAgentPort string        = "10050"
	version         string        = "0.0.1"
)

var (
	//app      = kingpin.Command("zabbix-api", "Call zabbix api.")
	file     = kingpin.Flag("file", "Config file").Short('f').Required().String()
	hostname = kingpin.Flag("hostname", "Hostname").Short('h').String()
	ipaddr   = kingpin.Flag("ipaddr", "IP Address").String()
	host     = kingpin.Command("host", "Operate host")
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
	kingpin.Version(version)
	subcommand := kingpin.Parse()

	config, err = LoadYAML(*file)
	if err != nil {
		log.Fatal(err)
	}

	client, err := APINewClient(api.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}

	kv = client.KV()
	zabbixapi = ZabbixAPI()

	zabbixHost, err := Hostname(*hostname)
	if err != nil {
		log.Fatal(err)
	}

	err = ZabbixAPILogin(config.Username, config.Password)
	if err != nil {
		log.Fatal(err)
	}

	switch subcommand {
	case "host status enable":
		host, err := ZabbixHostGetByHost(zabbixHost)
		if err != nil {
			log.Fatal(err)
		}
		ZabbixHostEnable(host.HostId)
	case "host status disable":
		host, err := ZabbixHostGetByHost(zabbixHost)
		if err != nil {
			log.Fatal(err)
		}
		ZabbixHostDisable(host.HostId)
	case "host register":
		ipaddr, err := GetIP()
		if err != nil {
			log.Fatal(err)
		}

		i := ZabbixHostInterface("", ipaddr, ZabbixAgentPort(), 1, 1, 1)
		interfaces := zabbix.HostInterfaces{i}

		groups, err := ZabbixGroupIds(config.HostGroups)
		if err != nil {
			log.Fatal(err)
		}

		templates, err := ZabbixTemplates(config.Templates)
		if err != nil {
			log.Fatal(err)
		}

		err = ZabbixHostCreate(zabbixHost, groups, interfaces, templates)
		if err != nil {
			log.Fatal(err)
		}
	case "host delete":
		host, err := ZabbixHostGetByHost(zabbixHost)
		if err != nil {
			log.Fatal(err)
		}
		ZabbixHostDelete(host.HostId)
	case "host list":
		zabbixHosts, err := ZabbixEnableHosts()
		if err != nil {
			log.Fatal(err)
		}

		for _, zHost := range zabbixHosts {
			fmt.Println(zHost.Hostname, zHost.IPAddr)
		}
	}
}
