package kv2

import (
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/AgentZombie/revault"
)

const (
	KeyTTL = "ttl"
)

type KV2 struct {
	BasePath string
	C        *revault.Client
}

func (kv KV2) Get(relPath string, version int) (Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return Secret{}, fmt.Errorf("preparing request: %w", err)
	}
	dir, base := path.Dir(relPath), path.Base(relPath)
	secPath := path.Join(kv.BasePath, dir, "data", base)
	d := map[string][]string{}
	if version != 0 {
		d["version"] = []string{strconv.Itoa(version)}
	}
	sec, err := l.ReadWithData(secPath, d)
	if err != nil {
		return Secret{}, fmt.Errorf("retrieving secret: %w", err)
	}
	if sec == nil {
		return Secret{}, revault.ErrNotFound
	}
	return SecretFromAPISecret(sec), nil
}

func (kv KV2) List(relPath string) (Listing, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return Listing{}, fmt.Errorf("preparing request: %w", err)
	}
	sec, err := l.List(path.Join(kv.BasePath, relPath))
	if err != nil {
		return Listing{}, fmt.Errorf("retrieving listing: %w", err)
	}
	return ListingFromAPISecret(sec), nil
}

func (kv KV2) Delete(relPath string) (*api.Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return nil, fmt.Errorf("preparing request: %w", err)
	}
	return l.Delete(path.Join(kv.BasePath, relPath))
}

func (kv KV2) Set(relPath string, sec Secret) (*api.Secret, error) {
	data := make(map[string]interface{}, len(sec.Values))
	for k, v := range sec.Values {
		data[k] = v
	}
	if sec.Duration != nil {
		data[KeyTTL] = fmt.Sprintf("%ds", *sec.Duration/time.Second)
	}
	return kv.SetRaw(relPath, data)
}

func (kv KV2) SetRaw(relPath string, data map[string]interface{}) (*api.Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return nil, fmt.Errorf("preparing request: %w", err)
	}
	secOut, err := l.Write(path.Join(kv.BasePath, relPath), data)
	if err != nil {
		return nil, fmt.Errorf("writing data: %w", err)
	}
	return secOut, nil
}
