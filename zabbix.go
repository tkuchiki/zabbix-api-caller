package main

import (
	"github.com/AlekSi/zabbix"
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

type Zabbix struct {
	api     *zabbix.API
	config  Config
	consul  Consul
	storage Storage
	token   string
}

func newZabbixAPI(server string) *zabbix.API {
	return zabbix.NewAPI(server + "/api_jsonrpc.php")
}

func NewZabbix(config Config, consul Consul, storage Storage) Zabbix {
	return Zabbix{
		api:     newZabbixAPI(config.ZabbixServer),
		config:  config,
		consul:  consul,
		storage: storage,
	}
}

func (z *Zabbix) newZabbixAPI() {
	z.api = newZabbixAPI(z.config.ZabbixServer)
}

func (z *Zabbix) getConsulKV() string {
	var token string
	pair, _ := z.consul.GetPair(z.config.ConsulKVKey)
	if pair != nil {
		token = string(pair.Value)
	}

	return token
}

func (z *Zabbix) userGet(token string) (zabbix.Response, error) {
	z.api.Auth = token
	return z.api.Call("user.get", zabbix.Params{"output": "extend"})
}

func (z *Zabbix) login() (string, error) {
	return z.api.Login(z.config.Username, z.config.Password)
}

func (z *Zabbix) loginAndVerifyToken(token string) (string, error) {
	res, err := z.userGet(token)
	if err != nil || res.Error != nil {
		z.newZabbixAPI()
		token, err = z.login()
	} else {
		err = nil
	}

	return token, err
}

func (z *Zabbix) getDBToken(bucket, key string) (string, error) {
	return z.storage.Read(bucket, key)
}

func (z *Zabbix) loginAndGetToken(bucket, key string) (string, string, error) {
	token, _ := z.getDBToken(bucket, key)
	newToken, err := z.loginAndVerifyToken(token)

	return token, newToken, err
}

func (z *Zabbix) APILogin() error {
	var err error
	var token string
	var newToken string

	bucket := "token"
	key := "token"

	switch z.config.Storage {
	case "consul":
		token = z.getConsulKV()

		newToken, err = z.loginAndVerifyToken(token)
		if err == nil {
			err = z.consul.PutKV(z.config.ConsulKVKey, newToken)
		}

		if err != nil {
			token, newToken, err = z.loginAndGetToken(bucket, key)
		}
	case "db":
		token, newToken, err = z.loginAndGetToken(bucket, key)
	}

	if token != newToken && newToken != "" {
		err = z.storage.Write(bucket, key, newToken)
	}

	return err
}

func (z *Zabbix) HostInterface(dns, ip string, main, useip int, _type zabbix.InterfaceType) []zabbix.HostInterface {
	return zabbix.HostInterfaces{
		zabbix.HostInterface{
			DNS:   dns,
			IP:    ip,
			Port:  z.config.ZabbixAgentPort,
			Main:  main,
			UseIP: useip,
			Type:  _type,
		},
	}
}

func (z *Zabbix) HostCreate(host string, groupIds zabbix.HostGroupIds, interfaces zabbix.HostInterfaces, templates TemplateIds) (err error) {
	i := 0
	zParams := zabbix.Params{"host": host,
		"groups":     groupIds,
		"interfaces": interfaces,
		"templates":  templates,
	}

	if z.config.ProxyName != "" {
		var proxyId string
		proxyId, err = z.proxyGet()
		zParams["proxy_hostid"] = proxyId
	}

	for {
		res, err := z.api.Call("host.create", zParams)
		if (err == nil && res.Error == nil) || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}
	return err
}

func (z *Zabbix) proxyGet() (proxyId string, err error) {
	var res zabbix.Response
	i := 0
	for {
		res, err = z.api.Call("proxy.get", zabbix.Params{"output": []string{"host", "proxyid"}, "filter": map[string]string{"host": z.config.ProxyName}})

		if res.Error == nil {
			for _, proxy := range res.Result.([]interface{}) {
				p := proxy.(map[string]interface{})
				proxyId = p["proxyid"].(string)
			}
		}

		if (err == nil && res.Error == nil) || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}
	return proxyId, err
}

func (z *Zabbix) HostGetByHost() (host *zabbix.Host, err error) {
	i := 0
	for {
		host, err = z.api.HostGetByHost(z.config.Hostname)
		if err == nil || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}

	return host, err
}

func (z *Zabbix) HostDelete(hostid string) (err error) {
	h := zabbix.Host{HostId: hostid}
	hosts := zabbix.Hosts{h}

	i := 0
	for {
		err = z.api.HostsDelete(hosts)
		if err == nil || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}

	return err
}

func (z *Zabbix) Templates(templates Templates) (templateIds TemplateIds, err error) {
	var res zabbix.Response
	hostTemplates := map[string]Templates{"host": templates}
	i := 0
	for {
		res, err = z.api.Call("template.get", zabbix.Params{"output": "shorten", "filter": hostTemplates})

		if res.Error == nil {
			for _, template := range res.Result.([]interface{}) {
				t := template.(map[string]interface{})
				templateIds = append(templateIds, HostTemplateId{TemplateId: t["templateid"].(string)})
			}
		}

		if (err == nil && res.Error == nil) || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}

	return templateIds, err
}

func (z *Zabbix) HostGroupIds(groupNames GroupNames) (groupIds zabbix.HostGroupIds, err error) {
	var res zabbix.Response
	names := map[string]GroupNames{"name": groupNames}
	i := 0
	for {
		res, err = z.api.Call("hostgroup.get", zabbix.Params{"output": "shorten", "filter": names})

		if res.Error == nil {
			for _, group := range res.Result.([]interface{}) {
				g := group.(map[string]interface{})
				groupIds = append(groupIds, zabbix.HostGroupId{GroupId: g["groupid"].(string)})
			}
		}

		if (err == nil && res.Error == nil) || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}

	return groupIds, err
}

func (z *Zabbix) hostUpdateStatus(hostid string, status int) (err error) {
	i := 0
	for {
		res, err := z.api.Call("host.update", zabbix.Params{"hostid": hostid, "status": status})
		if (err == nil && res.Error == nil) || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}

	return err
}

func (z *Zabbix) Hosts(available, status string) (map[string]ZabbixHost, error) {
	var res zabbix.Response
	var err error
	filters := map[string][]string{"hostids": z.config.HostGroups, "available": []string{available}, "status": []string{status}}
	var zabbixHosts map[string]ZabbixHost = make(map[string]ZabbixHost)
	var hostIds []string
	i := 0
	for {
		res, err = z.api.Call("host.get", zabbix.Params{"output": "extend", "filter": filters})

		if res.Error == nil {
			for _, h := range res.Result.([]interface{}) {
				hostObject := h.(map[string]interface{})
				zHostName := hostObject["name"].(string)
				hostid := hostObject["hostid"].(string)
				hostIds = append(hostIds, hostid)
				zabbixHosts[hostid] = ZabbixHost{Hostname: zHostName, IPAddr: ""}
			}
		}

		if (err == nil && res.Error == nil) || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}

	zabbixHosts, err = z.hostIPs(zabbixHosts, hostIds)

	return zabbixHosts, err
}

func (z *Zabbix) hostIPs(zabbixHosts map[string]ZabbixHost, hostIds []string) (map[string]ZabbixHost, error) {
	var res zabbix.Response
	var err error
	i := 0
	for {
		res, err = z.api.Call("hostinterface.get", zabbix.Params{"output": "extend", "hostids": hostIds})

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

		if (err == nil && res.Error == nil) || i == z.config.Retry {
			break
		}
		i++
		time.Sleep(z.config.retrySleepDuration)
	}

	return zabbixHosts, err
}

func (z *Zabbix) EnableHosts() (map[string]ZabbixHost, error) {
	var err error
	var zabbixHosts map[string]ZabbixHost = make(map[string]ZabbixHost)
	zabbixHosts, err = z.Hosts("1", "0")
	return zabbixHosts, err
}

func (z *Zabbix) DisableHosts() (map[string]ZabbixHost, error) {
	var err error
	var zabbixHosts map[string]ZabbixHost = make(map[string]ZabbixHost)
	zabbixHosts, err = z.Hosts("1", "1")
	return zabbixHosts, err
}

func (z *Zabbix) HostEnable(hostid string) (err error) {
	return z.hostUpdateStatus(hostid, 0)
}

func (z *Zabbix) HostDisable(hostid string) (err error) {
	return z.hostUpdateStatus(hostid, 1)
}
