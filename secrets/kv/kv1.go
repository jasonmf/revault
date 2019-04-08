package kv

import (
	"fmt"
	"path"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"

	"github.com/AgentZombie/revault"
)

const (
	KeyTTL = "ttl"
)

type KV1 struct {
	BasePath string
	C        *revault.Client
}

func (kv KV1) Get(relPath string) (Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return Secret{}, errors.Wrap(err, "preparing request")
	}
	sec, err := l.Read(path.Join(kv.BasePath, relPath))
	if err != nil {
		return Secret{}, errors.Wrap(err, "retrieving secret")
	}
	return SecretFromAPISecret(sec), nil
}

func (kv KV1) List(relPath string) (Listing, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return Listing{}, errors.Wrap(err, "preparing request")
	}
	sec, err := l.List(path.Join(kv.BasePath, relPath))
	if err != nil {
		return Listing{}, errors.Wrap(err, "retrieving listing")
	}
	return ListingFromAPISecret(sec), nil
}

func (kv KV1) Delete(relPath string) (*api.Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return nil, errors.Wrap(err, "preparing request")
	}
	return l.Delete(path.Join(kv.BasePath, relPath))
}

func (kv KV1) Set(relPath string, sec Secret) (*api.Secret, error) {
	data := make(map[string]interface{}, len(sec.Values))
	for k, v := range sec.Values {
		data[k] = v
	}
	if sec.Duration != nil {
		data[KeyTTL] = fmt.Sprintf("%ds", *sec.Duration/time.Second)
	}
	return kv.SetRaw(relPath, data)
}

func (kv KV1) SetRaw(relPath string, data map[string]interface{}) (*api.Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return nil, errors.Wrap(err, "preparing request")
	}
	secOut, err := l.Write(path.Join(kv.BasePath, relPath), data)
	if err != nil {
		return nil, errors.Wrap(err, "writing data")
	}
	return secOut, nil
}
