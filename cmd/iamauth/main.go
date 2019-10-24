package main

import (
	"flag"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/hashicorp/vault/api"

	"github.com/AgentZombie/revault"
	"github.com/AgentZombie/revault/login/awsiam"
	"github.com/AgentZombie/revault/secrets/kv"
	"github.com/AgentZombie/revault/token"
)

var (
	fAuthPath = flag.String("auth", "", "auth path")
	fAuthRole = flag.String("role", "", "auth role")
	fSecret   = flag.String("secret", "", "secret to read")
)

func fatalIfError(err error, msg string) {
	if err != nil {
		log.Fatal("error ", msg, ": ", err)
	}
}

func main() {
	flag.Parse()
	if *fAuthPath == "" || *fAuthRole == "" || *fSecret == "" {
		flag.PrintDefaults()
		os.Exit(-1)
	}

	sess, err := awsiam.EnvironmentSession()
	fatalIfError(err, "getting AWS session from environment")
	sess.Config.Region = aws.String("us-west-2")

	apiClient, err := api.NewClient(api.DefaultConfig())
	fatalIfError(err, "creating vault client")
	p := token.Synchronize(token.Cache(awsiam.New(sess, apiClient, *fAuthRole, *fAuthPath)))
	defer func() {
		if err := p.Close(); err != nil {
			log.Print("error closing auth provider: ", err)
		}
	}()

	client := revault.New(apiClient, p)
	kv1 := kv.KV1{
		BasePath: "",
		C:        client,
	}

	sec, err := kv1.Get(*fSecret)
	fatalIfError(err, "getting secret")

	for k, v := range sec.Values {
		log.Printf("%s: %q", k, v)
	}
}
