package kv

import (
	"fmt"
	"path"
	"time"

	"github.com/hashicorp/vault/api"

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
		return Secret{}, fmt.Errorf("preparing request: %w", err)
	}
	sec, err := l.Read(path.Join(kv.BasePath, relPath))
	if err != nil {
		return Secret{}, fmt.Errorf("retrieving secret: %w", err)
	}
	return SecretFromAPISecret(sec), nil
}

func (kv KV1) List(relPath string) (Listing, error) {
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

func (kv KV1) Delete(relPath string) (*api.Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return nil, fmt.Errorf("preparing request: %w", err)
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
		return nil, fmt.Errorf("preparing request: %w", err)
	}
	secOut, err := l.Write(path.Join(kv.BasePath, relPath), data)
	if err != nil {
		return nil, fmt.Errorf("writing data: %w", err)
	}
	return secOut, nil
}
