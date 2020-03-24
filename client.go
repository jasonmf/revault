package revault

import (
	"errors"

	"github.com/hashicorp/vault/api"

	"github.com/AgentZombie/revault/token"
)

var (
	ErrNotFound = errors.New("not found")
)

type Client struct {
	V  *api.Client
	tp token.Provider
}

func New(v *api.Client, tp token.Provider) *Client {
	return &Client{
		V:  v,
		tp: tp,
	}
}

func (c Client) Logical() (*api.Logical, error) {
	sa, _, err := c.tp.Token()
	if err != nil {
		return nil, err
	}
	c.V.SetToken(sa.ClientToken)
	return c.V.Logical(), err
}

func (c Client) Sys() (*api.Sys, error) {
	sa, _, err := c.tp.Token()
	if err != nil {
		return nil, err
	}
	c.V.SetToken(sa.ClientToken)
	return c.V.Sys(), err
}
