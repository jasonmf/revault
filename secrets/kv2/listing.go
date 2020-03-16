package kv2

import (
	"github.com/hashicorp/vault/api"
)

type Listing struct {
	Paths  []string
	Secret *api.Secret
}

func ListingFromAPISecret(src *api.Secret) Listing {
	l := Listing{Secret: src}
	if src == nil || len(src.Data) == 0 {
		return l
	}
	keysM, ok := src.Data["keys"]
	if !ok {
		return l
	}
	keysL := keysM.([]interface{})
	if len(keysL) == 0 {
		return l
	}
	keys := make([]string, len(keysL))
	for i, v := range keysL {
		keys[i] = v.(string)
	}
	l.Paths = keys
	return l
}
