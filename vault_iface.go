package revault

import "github.com/hashicorp/vault/api"

type VaultWriter interface {
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}

type VaultLogicalWriter interface {
	Logical() VaultWriter
}
