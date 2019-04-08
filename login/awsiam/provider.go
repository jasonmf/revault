package awsiam

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"path"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"

	"github.com/AgentZombie/revault"
)

type provider struct {
	session  *aws.Session
	role     string
	authPath string
	client   revault.VaultLogicalWriter
}

func New(session *aws.Session, client revault.VaultLogicalWriter, role, authPath string) *provider {
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
	stsReq.Sign()
	headersJson, err := json.Marshal(stsReq.HTTPRequest.Header)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(err, "marshalling STS request header")
	}
	reqBody, err := ioutil.ReadAll(stsReq.HTTPRequest.Body)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(err, "reading sts request body")
	}
	loginData := map[string]interface{}{
		"iam_http_request_method": stsReq.HTTPRequest.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(stsReq.HTTPRequest.URL.String())),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headersJson),
		"iam_request_body":        base64.StdEncoding.EncodeToString(reqBody),
		"role":                    p.Role,
	}

	sec, err := p.client.Logical().Write(path.Join("auth", p.authPath, "login"), loginData)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(err, "logging in")
	}
	if sec == nil {
		return nil, time.Time{}, errors.New("empty response logging in")
	}
	tokenExpires = time.Now().Add(time.Second * time.Duration(sec.Auth.LeaseDuration))
	return sec.Auth, tokenExpires, nil
}

func EnvironmentSession() (*aws.Session, error) {
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
		return nil, errors.Wrap(err, "creating STS session")
	}
	return sess, nil
}
