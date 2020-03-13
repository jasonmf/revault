package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/AgentZombie/revault"
	kv "github.com/AgentZombie/revault/secrets/kv2"
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

	kv2 := kv.KV2{
		BasePath: "",
		C:        client,
	}

	sec2, err := kv2.Get("devsecrets/foo", 0)
	fatalIfError(err, "getting secret")
	b, err := json.Marshal(sec2.Values)
	fatalIfError(err, "sec -> json")
	fmt.Println(string(b))
	return

	dur := time.Hour
	sec := kv.Secret{
		Values: map[string]string{
			"foo": "bar",
			"1":   "a",
		},
		Duration: &dur,
	}

	_, err = kv2.Set("secv1/foo", sec)
	fatalIfError(err, "setting secret")

	listing, err := kv2.List("secv1")
	fatalIfError(err, "listing")

	for _, p := range listing.Paths {
		log.Print("Path: ", p)
	}

	sec, err = kv2.Get("secv1/foo", 0)
	fatalIfError(err, "getting foo")

	for k, v := range sec.Values {
		log.Printf("%s: %q", k, v)
	}

	_, err = kv2.Delete("secv1/foo")
	fatalIfError(err, "deleting")
}
