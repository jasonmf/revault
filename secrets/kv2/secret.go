package kv2

import (
	"encoding/json"
	"log"
	"time"

	"github.com/hashicorp/vault/api"
)

type Secret struct {
	Secret   *api.Secret       // The underlying Secret structure from the vault API.
	Duration *time.Duration    // The desired lease duration when setting a secret. If nil, no expiraiton.
	Expires  *time.Time        // When the secret expires, for retrieved secrets. If nil, no expiration.
	Values   map[string]string // The K/V values.
	Metadata Metadata
}

type Metadata struct {
	CreatedTime  *time.Time
	DeletionTime *time.Time
	Destroyed    bool
	Version      int
}

func SecretFromAPISecret(src *api.Secret) Secret {
	s := Secret{
		Secret: src,
		Values: map[string]string{},
	}
	if src.LeaseDuration > 0 {
		expires := time.Now().Add(time.Second * time.Duration(src.LeaseDuration))
		s.Expires = &expires
	}
	if m, ok := src.Data["metadata"].(map[string]interface{}); ok {
		setMetadata(&s.Metadata, m)
	}
	log.Printf("Secret: %#v", src)
	d := src.Data["data"].(map[string]interface{})
	for k, iv := range d {
		if k == KeyTTL {
			continue
		}
		if str, ok := iv.(string); ok {
			s.Values[k] = str
		}
	}
	return s
}

func setMetadata(md *Metadata, m map[string]interface{}) {
	if v, ok := m["created_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			md.CreatedTime = &t
		}
	}
	if v, ok := m["deletion_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			md.DeletionTime = &t
		}
	}
	if v, ok := m["destroyed"].(bool); ok {
		md.Destroyed = v
	}
	if v, ok := m["version"].(json.Number); ok {
		if i64, err := v.Int64(); err == nil {
			md.Version = int(i64)
		}
	}
}
