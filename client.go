package revault

import (
	"github.com/hashicorp/vault/api"

	"github.com/AgentZombie/revault/token"
)

type Client struct {
	v  *api.Client
	tp token.Provider
}

func New(v *api.Client, tp token.Provider) *Client {
	return &Client{
		v:  v,
		tp: tp,
	}
}

func (c Client) Logical() (*api.Logical, error) {
	sa, _, err := c.tp.Token()
	if err != nil {
		return nil, err
	}
	c.v.SetToken(sa.ClientToken)
	return c.v.Logical(), err
}

func (c Client) Sys() (*api.Sys, error) {
	sa, _, err := c.tp.Token()
	if err != nil {
		return nil, err
	}
	c.v.SetToken(sa.ClientToken)
	return c.v.Sys(), err
}
