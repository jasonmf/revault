package awsiam

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/api"
)

type provider struct {
	session  *session.Session
	role     string
	authPath string
	client   *api.Client
}

func New(session *session.Session, client *api.Client, role, authPath string) *provider {
	p := &provider{
		session:  session,
		role:     role,
		authPath: authPath,
		client:   client,
	}
	return p
}

func (p provider) Token() (*api.SecretAuth, time.Time, error) {
	stsReq, _ := sts.New(p.session).GetCallerIdentityRequest(nil)
	if err := stsReq.Sign(); err != nil {
		return nil, time.Time{}, fmt.Errorf("signing request: %w", err)
	}
	headersJson, err := json.Marshal(stsReq.HTTPRequest.Header)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("marshalling STS request header: %w", err)
	}
	reqBody, err := ioutil.ReadAll(stsReq.HTTPRequest.Body)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("reading sts request body: %w", err)
	}
	loginData := map[string]interface{}{
		"iam_http_request_method": stsReq.HTTPRequest.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(stsReq.HTTPRequest.URL.String())),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headersJson),
		"iam_request_body":        base64.StdEncoding.EncodeToString(reqBody),
		"role":                    p.role,
	}

	sec, err := p.client.Logical().Write(path.Join("auth", p.authPath, "login"), loginData)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("logging in: %w", err)
	}
	if sec == nil {
		return nil, time.Time{}, errors.New("empty response logging in")
	}
	tokenExpires := time.Now().Add(time.Second * time.Duration(sec.Auth.LeaseDuration))
	return sec.Auth, tokenExpires, nil
}

func (p provider) Close() error {
	return p.client.Auth().Token().RevokeSelf("")
}

func EnvironmentSession() (*session.Session, error) {
	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.EnvProvider{},
			&ec2rolecreds.EC2RoleProvider{
				Client: ec2metadata.New(session.Must(session.NewSession())),
			},
		},
	)
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Credentials: creds},
	})
	if err != nil {
		return nil, fmt.Errorf("creating STS session: %w", err)
	}
	return sess, nil
}
