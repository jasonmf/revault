package kv

import (
	"time"

	"github.com/hashicorp/vault/api"
)

type Secret struct {
	Secret   *api.Secret       // The underlying Secret structure from the vault API.
	Duration *time.Duration    // The desired lease duration when setting a secret. If nil, no expiraiton.
	Expires  *time.Time        // When the secret expires, for retrieved secrets. If nil, no expiration.
	Values   map[string]string // The K/V values.
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
	for k, iv := range src.Data {
		if k == KeyTTL {
			continue
		}
		if str, ok := iv.(string); ok {
			s.Values[k] = str
		}
	}
	return s
}
