package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	ZabbixServer       string   `yaml:"zabbix_server"`
	ConsulKVKey        string   `yaml:"consul_kv_key"`
	Username           string   `yaml:"username"`
	Password           string   `yaml:"password"`
	HostGroups         []string `yaml:"host_groups"`
	Templates          []string `yaml:"templates"`
	Hostname           string   `yaml:"hostname"`
	IpAddr             string   `yaml:"ipaddr"`
	ZabbixAgentPort    string   `yaml:"zabbix_agent_port"`
	ProxyName          string   `yaml:"proxy_name"`
	Storage            string   `yaml:"storage"`
	Retry              int      `yaml:"retry"`
	RetrySleep         int64    `yaml:"retry_sleep"`
	retrySleepDuration time.Duration
	DBPath             string      `yaml:"db_path"`
	DBPerm             os.FileMode `yaml:"db_perm"`
}

func LoadYAML(filename, hostname string) (config Config, err error) {
	if err != nil {
		return config, err
	}
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(buf, &config)

	if config.DBPath == "" {
		config.DBPath = filepath.Join(os.TempDir(), "zabbix.db")
	}

	if config.Storage == "" {
		config.Storage = "db"
	}

	if hostname != "" {
		config.Hostname = hostname
	} else if config.Hostname == "" {
		config.Hostname, err = os.Hostname()

		if err != nil {
			return config, err
		}
	}

	if config.ZabbixAgentPort == "" {
		config.ZabbixAgentPort = "10050"
	}

	if config.Retry == 0 {
		config.Retry = 3
	}

	if config.RetrySleep == 0 {
		config.retrySleepDuration = 500 * time.Millisecond
	} else {
		config.retrySleepDuration = time.Duration(config.RetrySleep) * time.Millisecond
	}

	if config.DBPerm == 0 {
		config.DBPerm = 0600
	}

	return config, err
}
