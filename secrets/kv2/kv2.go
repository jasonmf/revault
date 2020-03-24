package kv2

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/AgentZombie/revault"
)

const (
	KeyTTL = "ttl"
)

type KV2 struct {
	BasePath string
	C        *revault.Client
}

func (kv KV2) Get(relPath string, version int) (Secret, error) {
	secPath := path.Join(kv.BasePath, relPath)
	l, err := kv.C.Logical()
	if err != nil {
		return Secret{}, fmt.Errorf("preparing request: %w", err)
	}
	mountPath, v2, err := isKVv2(secPath, kv.C.V)
	if err != nil {
		return Secret{}, fmt.Errorf("checking mount version: %w", err)
	}
	if !v2 {
		return Secret{}, fmt.Errorf("not a v2 mount: %s", mountPath)
	}

	secPath = addPrefixToVKVPath(secPath, mountPath, "data")

	d := map[string][]string{}
	if version != 0 {
		d["version"] = []string{strconv.Itoa(version)}
	}
	sec, err := l.ReadWithData(secPath, d)
	if err != nil {
		return Secret{}, fmt.Errorf("retrieving secret: %w", err)
	}
	if sec == nil {
		return Secret{}, revault.ErrNotFound
	}
	return SecretFromAPISecret(sec), nil
}

func (kv KV2) List(relPath string) (Listing, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return Listing{}, fmt.Errorf("preparing request: %w", err)
	}
	sec, err := l.List(path.Join(kv.BasePath, relPath))
	if err != nil {
		return Listing{}, fmt.Errorf("retrieving listing: %w", err)
	}
	return ListingFromAPISecret(sec), nil
}

func (kv KV2) Delete(relPath string) (*api.Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return nil, fmt.Errorf("preparing request: %w", err)
	}
	return l.Delete(path.Join(kv.BasePath, relPath))
}

func (kv KV2) Set(relPath string, sec Secret) (*api.Secret, error) {
	data := make(map[string]interface{}, len(sec.Values))
	for k, v := range sec.Values {
		data[k] = v
	}
	if sec.Duration != nil {
		data[KeyTTL] = fmt.Sprintf("%ds", *sec.Duration/time.Second)
	}
	return kv.SetRaw(relPath, data)
}

func (kv KV2) SetRaw(relPath string, data map[string]interface{}) (*api.Secret, error) {
	l, err := kv.C.Logical()
	if err != nil {
		return nil, fmt.Errorf("preparing request: %w", err)
	}
	secOut, err := l.Write(path.Join(kv.BasePath, relPath), data)
	if err != nil {
		return nil, fmt.Errorf("writing data: %w", err)
	}
	return secOut, nil
}

func isKVv2(path string, client *api.Client) (string, bool, error) {
	mountPath, version, err := kvPreflightVersionRequest(client, path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

func kvPreflightVersionRequest(client *api.Client, path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := client.CurrentWrappingLookupFunc()
	client.SetWrappingLookupFunc(nil)
	defer client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := client.OutputCurlString()
	client.SetOutputCurlString(false)
	defer client.SetOutputCurlString(currentOutputCurlString)

	r := client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil && resp.StatusCode == 404 {
			return "", 1, nil
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if secret == nil {
		return "", 0, errors.New("nil response from pre-flight request")
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}

func addPrefixToVKVPath(p, mountPath, apiPrefix string) string {
	switch {
	case p == mountPath, p == strings.TrimSuffix(mountPath, "/"):
		return path.Join(mountPath, apiPrefix)
	default:
		p = strings.TrimPrefix(p, mountPath)
		return path.Join(mountPath, apiPrefix, p)
	}
}
