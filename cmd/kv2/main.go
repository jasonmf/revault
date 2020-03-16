package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/hashicorp/vault/api"

	"github.com/AgentZombie/revault"
	"github.com/AgentZombie/revault/secrets/kv2"
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

	kv2 := kv2.KV2{
		BasePath: "",
		C:        client,
	}

	sec2, err := kv2.Get("devsecrets/foo", 0)
	fatalIfError(err, "getting secret")
	b, err := json.Marshal(sec2.Values)
	fatalIfError(err, "sec -> json")
	fmt.Println(string(b))
}
