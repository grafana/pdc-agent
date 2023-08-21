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
	"net/http"
	"net/url"
	"path"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/pdc-agent/pkg/httpclient"
	"github.com/hashicorp/go-retryablehttp"

	"golang.org/x/crypto/ssh"
)

var (
	// ErrInternal indicates the item could not be processed.
	ErrInternal = errors.New("internal error")
	// ErrInvalidCredentials indicates the auth token is incorrect
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// Config describes all properties that can be configured for the PDC package
type Config struct {
	Token           string
	HostedGrafanaID string
	URL             *url.URL
	RetryMax        int
}

func (cfg *Config) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&cfg.Token, "token", "", "The token to use to authenticate with Grafana Cloud. It must have the pdc-signing:write scope")
	fs.StringVar(&cfg.HostedGrafanaID, "gcloud-hosted-grafana-id", "", "The ID of the Hosted Grafana instance to connect to")
}

// Client is a PDC API client
type Client interface {
	SignSSHKey(ctx context.Context, key []byte) (*SigningResponse, error)
}

// SigningResponse is the response received from a SSH key signing request
type SigningResponse struct {
	Certificate ssh.Certificate
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

// NewClient returns a new Client
func NewClient(cfg *Config, logger log.Logger) (Client, error) {
	if cfg.URL == nil {
		return nil, errors.New("-api-url cannot be nil")
	}

	rc := retryablehttp.NewClient()
	if cfg.RetryMax != 0 {
		rc.RetryMax = cfg.RetryMax
	}
	rc.Logger = &logAdapter{logger}
	rc.CheckRetry = retryablehttp.ErrorPropagatedRetryPolicy
	hc := rc.StandardClient()

	hc.Transport = httpclient.UserAgentTransport(hc.Transport)

	return &pdcClient{
		cfg:        cfg,
		httpClient: hc,
		logger:     logger,
	}, nil
}

type pdcClient struct {
	cfg        *Config
	httpClient *http.Client
	logger     log.Logger
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

	url := *c.cfg.URL
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

	req, err := http.NewRequestWithContext(ctx, method, url.String(), bytes.NewBuffer(jsonB))
	if err != nil {
		level.Error(c.logger).Log("msg", "error creating PDC API request", "err", err)
		return nil, ErrInternal
	}

	// base64 id:token for auth
	b := []byte{}
	buf := bytes.NewBuffer(b)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	_, werr := encoder.Write([]byte(c.cfg.HostedGrafanaID + ":" + c.cfg.Token))
	err = encoder.Close()
	if werr != nil || err != nil {
		level.Error(c.logger).Log("msg", "error encoding Authorization header", "err", err)
		return nil, ErrInternal
	}

	req.Header.Add("Authorization", "Basic "+buf.String())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		level.Error(c.logger).Log("msg", "error making request to PDC API", "err", err)
		return nil, ErrInternal
	}
	defer resp.Body.Close()
	respB, err := io.ReadAll(resp.Body)
	if err != nil {
		level.Error(c.logger).Log("msg", "error reading response from PDC API", "err", err)
		return nil, ErrInternal
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return respB, nil
	case http.StatusUnauthorized:
		return respB, ErrInvalidCredentials
	default:
		level.Error(c.logger).Log("msg", "unknown response from PDC API", "code", resp.StatusCode)
		return respB, ErrInternal
	}
}

type logAdapter struct {
	l log.Logger
}

var _ retryablehttp.LeveledLogger = (*logAdapter)(nil)

func (l *logAdapter) Debug(msg string, kv ...interface{}) {
	keyvals := []interface{}{"msg", msg}
	keyvals = append(keyvals, kv...)
	level.Debug(l.l).Log(keyvals...)
}

func (l *logAdapter) Info(msg string, kv ...interface{}) {
	keyvals := []interface{}{"msg", msg}
	keyvals = append(keyvals, kv...)
	level.Info(l.l).Log(keyvals...)
}
func (l *logAdapter) Warn(msg string, kv ...interface{}) {
	keyvals := []interface{}{"msg", msg}
	keyvals = append(keyvals, kv...)
	level.Warn(l.l).Log(keyvals...)
}
func (l *logAdapter) Error(msg string, kv ...interface{}) {
	keyvals := []interface{}{"msg", msg}
	keyvals = append(keyvals, kv...)
	level.Error(l.l).Log(keyvals...)
}
