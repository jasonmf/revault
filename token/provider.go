package token

import (
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// A provider provides an authentication token.
type Provider interface {
	Token() (token *api.SecretAuth, expiration time.Time, err error)
	Close() error
}

type concurrencySafeProvider struct {
	lock *sync.Mutex
	Provider
}

func (p concurrencySafeProvider) Token() (*api.SecretAuth, time.Time, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.Provider.Token()
}

// MakeConcurrencySafe wraps calls to Token in a Mutex. This should probably be the outermost wrapping layer.
func Synchronize(p Provider) Provider {
	return &concurrencySafeProvider{
		lock:     &sync.Mutex{},
		Provider: p,
	}
}

type cachedProvider struct {
	token   *api.SecretAuth
	expires time.Time
	Provider
}

func (p cachedProvider) Token() (*api.SecretAuth, time.Time, error) {
	if p.expires.After(time.Now()) {
		return p.token, p.expires, nil
	}
	token, expires, err := p.Provider.Token()
	if err != nil {
		return nil, time.Time{}, err
	}
	p.token = token
	p.expires = expires
	return token, expires, nil
}

// Cache wraps a provider, caching the token returned by the wrapped provider until *after* its expiration.
func Cache(p Provider) Provider {
	return &cachedProvider{
		Provider: p,
	}
}

// Static tokens can be manually set and are assumed not to expire.
type Static api.SecretAuth

func (s Static) Token() (*api.SecretAuth, time.Time, error) {
	return (*api.SecretAuth)(&s), time.Time{}, nil
}

func (s Static) Close() error {
	return nil
}
