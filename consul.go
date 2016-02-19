package main

import (
	"github.com/hashicorp/consul/api"
)

type Consul struct {
	client *api.Client
	kv     *api.KV
}

func NewConsul() (Consul, error) {
	client, err := api.NewClient(api.DefaultConfig())

	return Consul{
		client: client,
		kv:     client.KV(),
	}, err
}

func (c *Consul) GetPair(key string) (*api.KVPair, error) {
	pair, _, err := c.kv.Get(key, nil)

	return pair, err
}

func (c *Consul) PutKV(key, value string) error {
	p := &api.KVPair{Key: key, Value: []byte(value)}
	_, err := c.kv.Put(p, nil)

	return err
}
