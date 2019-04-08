package main

import (
	"flag"
	"log"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/AgentZombie/revault"
	"github.com/AgentZombie/revault/secrets/kv"
	"github.com/AgentZombie/revault/token"
)

var (
	fToken = flag.String("token", "FOO", "token to use")
)

func fatalIfError(err error, msg string) {
	if err != nil {
		log.Fatal("error ", msg, ": ", err)
	}
}

func main() {
	flag.Parse()
	token := token.Static(
		api.SecretAuth{
			ClientToken: *fToken,
		},
	)
	v, err := api.NewClient(api.DefaultConfig())
	fatalIfError(err, "creating vault client")
	client := revault.New(v, token)

	kv1 := kv.KV1{
		BasePath: "",
		C:        client,
	}

	dur := time.Hour
	sec := kv.Secret{
		Values: map[string]string{
			"foo": "bar",
			"1":   "a",
		},
		Duration: &dur,
	}

	_, err = kv1.Set("secv1/foo", sec)
	fatalIfError(err, "setting secret")

	listing, err := kv1.List("secv1")
	fatalIfError(err, "listing")

	for _, p := range listing.Paths {
		log.Print("Path: ", p)
	}

	sec, err = kv1.Get("secv1/foo")
	fatalIfError(err, "getting foo")

	for k, v := range sec.Values {
		log.Printf("%s: %q", k, v)
	}

	_, err = kv1.Delete("secv1/foo")
	fatalIfError(err, "deleting")
}
