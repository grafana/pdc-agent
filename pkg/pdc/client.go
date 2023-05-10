package pdc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/grafana/pdc-agent/pkg/httpclient"
	"golang.org/x/crypto/ssh"
)

var (
	// ErrInternal indicates the item could not be processed.
	ErrInternal = errors.New("internal error")
	// ErrInvalidCredentials indicates the auth token is incorrect
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type Config struct {
	Host            string
	Domain          string
	Token           string
	HostedGrafanaId string
	API             *url.URL
	Gateway         *url.URL
}

func DefaultConfig() *Config {
	return &Config{
		Domain: "grafana.net",
	}
}

func (cfg *Config) RegisterFlags(fs *flag.FlagSet) {
	def := DefaultConfig()
	fs.StringVar(&cfg.Token, "token", "", "The token to use to authenticate with Grafana Cloud. It must have the pdc-signing:write scope")
	fs.StringVar(&cfg.Host, "host", "", "The host for PDC endpoints")
	fs.StringVar(&cfg.Domain, "domain", def.Domain, "The domain for PDC endpoints")
	fs.StringVar(&cfg.HostedGrafanaId, "gcloud-hosted-grafana-id", "", "The ID of the Hosted Grafana instance to connect to")
}

func (cfg *Config) APIURL() (*url.URL, error) {
	if cfg.API != nil {
		return cfg.API, nil
	}

	prefix := "private-datasource-connect"
	cluster, found := strings.CutPrefix(cfg.Host, prefix)
	if !found {
		// some custom host. Try to parse it and assume we dont need to edit it
		return url.Parse(cfg.Host + "." + cfg.Domain)
	}
	// add "-api" into hostname between private-datasource-connect and cluster
	url, err := url.Parse("https://" + prefix + "-api" + cluster + "." + cfg.Domain)
	if err != nil {
		return nil, err
	}
	cfg.API = url
	return cfg.API, nil
}

func (cfg *Config) GatewayURL() (*url.URL, error) {
	url, err := url.Parse(cfg.Host + "." + cfg.Domain)
	if err != nil {
		return nil, err
	}
	cfg.Gateway = url
	return cfg.Gateway, nil
}

type Client interface {
	SignSSHKey(ctx context.Context, key []byte) (*SigningResponse, error)
}

type SigningResponse struct {
	Certificate ssh.Certificate // use anon struct for unmarshalling, not this one.
	KnownHosts  []byte
}

func (sr *SigningResponse) UnmarshalJSON(data []byte) error {
	target := struct {
		Certificate string `json:"certificate"`
		KnownHosts  string `json:"known_hosts"`
	}{}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err := dec.Decode(&target)
	if err != nil {
		return err
	}

	block, rest := pem.Decode([]byte(target.Certificate))
	if block == nil {
		return fmt.Errorf("failed to pem-decode certificate: %w", err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("only expected one PEM")
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return errors.New("public key is not an SSH certificate")
	}

	sr.KnownHosts = []byte(target.KnownHosts)
	sr.Certificate = *cert
	return nil
}

func NewClient(cfg *Config) (Client, error) {
	url, err := cfg.APIURL()
	if err != nil {
		return nil, err
	}

	log.Printf("client URL is %s", url)

	return &pdcClient{
		cfg:        cfg,
		httpClient: &http.Client{Transport: httpclient.UserAgentTransport(nil)},
		url:        url,
	}, nil
}

type pdcClient struct {
	cfg        *Config
	httpClient *http.Client
	url        *url.URL
}

func (c *pdcClient) SignSSHKey(ctx context.Context, key []byte) (*SigningResponse, error) {
	resp, err := c.call(ctx, http.MethodPost, "/pdc/api/v1/sign-public-key", nil, map[string]string{
		"publicKey": string(key),
	})
	if err != nil {
		return nil, err
	}

	sr := &SigningResponse{}
	err = sr.UnmarshalJSON(resp)
	if err != nil {
		return nil, err
	}

	return sr, nil
}

func (c *pdcClient) call(ctx context.Context, method, rpath string, params map[string]string, body map[string]string) ([]byte, error) {

	url := *c.url
	url.Path = path.Join(url.Path, rpath)

	q := url.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	url.RawQuery = q.Encode()

	jsonB, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, method, url.String(), bytes.NewBuffer(jsonB))
	if err != nil {
		log.Println("error creating request")
		return nil, ErrInternal
	}

	// base64 id:token for auth
	b := []byte{}
	buf := bytes.NewBuffer(b)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	encoder.Write([]byte(c.cfg.HostedGrafanaId + ":" + c.cfg.Token))
	err = encoder.Close()
	if err != nil {
		log.Printf("Failed to encode values for Authorization header: %s\n", err)
		return nil, err
	}

	req.Header.Add("Authorization", "Basic "+buf.String())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("request failed: %s", err)
		return nil, ErrInternal
	}
	defer resp.Body.Close()
	respB, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response: %s", err)
		return nil, ErrInternal
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return respB, nil
	case http.StatusUnauthorized:
		return respB, ErrInvalidCredentials
	default:
		log.Println("unknown response from pdc: " + fmt.Sprintf("%d", resp.StatusCode))
		return respB, ErrInternal
	}
}
