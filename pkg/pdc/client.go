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
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/pdc-agent/pkg/httpclient"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_golang/prometheus"
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

	// The version of pdc-agent thats running, defined by goreleaser during the build process.
	Version string

	// The PDC api endpoint used to sign public keys.
	// It is not a constant only to make it easier to override the endpoint in local development.
	SignPublicKeyEndpoint string

	// Used for local development.
	// Contains headers that are included in each http request send to the pdc api.
	DevHeaders map[string]string

	// Used for local development.
	// DevNetwork is the network that the agent will connect to.
	DevNetwork string

	// Used for local development.
	// DevPort is the port number for the PDC API
	DevPort string
}

func (cfg *Config) RegisterFlags(fs *flag.FlagSet) {
	var deprecated string
	fs.StringVar(&cfg.Token, "token", "", "The token to use to authenticate with Grafana Cloud. It must have the pdc-signing:write scope")
	fs.StringVar(&cfg.HostedGrafanaID, "gcloud-hosted-grafana-id", "", "The ID of the Hosted Grafana instance to connect to")
	fs.StringVar(&deprecated, "network", "", "DEPRECATED: The name of the PDC network to connect to")
	fs.IntVar(&cfg.RetryMax, "retrymax", 4, "The max num of retries for http requests")

	fs.StringVar(&cfg.DevNetwork, "dev-network", "", "[DEVELOPMENT ONLY] the network the agent will connect to")
	fs.StringVar(&cfg.DevPort, "dev-api-port", "9181", "[DEVELOPMENT ONLY] The port to use for agent connections to the PDC API")
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

	// If the value has not been set for testing.
	if cfg.SignPublicKeyEndpoint == "" {
		cfg.SignPublicKeyEndpoint = "/pdc/api/v1/sign-public-key"
	}

	rc := retryablehttp.NewClient()
	if cfg.RetryMax != 0 {
		rc.RetryMax = cfg.RetryMax
	}
	rc.Logger = &logAdapter{logger}
	rc.CheckRetry = retryablehttp.ErrorPropagatedRetryPolicy
	hc := rc.StandardClient()

	hc.Transport = httpclient.UserAgentTransport(hc.Transport, cfg.Version)

	return &pdcClient{
		cfg:        cfg,
		httpClient: hc,
		logger:     logger,
		metrics:    newPromMetrics(),
	}, nil
}

type pdcClient struct {
	cfg        *Config
	httpClient *http.Client
	logger     log.Logger
	metrics    *promMetrics
}

func (c *pdcClient) SignSSHKey(ctx context.Context, key []byte) (*SigningResponse, error) {
	start := time.Now()

	resp, err := c.call(ctx, http.MethodPost, c.cfg.SignPublicKeyEndpoint, nil, map[string]string{
		"publicKey": string(key),
	})
	if err != nil {
		c.metrics.signingRequests.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return nil, err
	}

	c.metrics.signingRequests.WithLabelValues("success").Observe(time.Since(start).Seconds())

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

	for header, value := range c.cfg.DevHeaders {
		req.Header.Add(header, value)
	}

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

func (c *pdcClient) Collect(ch chan<- prometheus.Metric) {
	c.metrics.signingRequests.Collect(ch)
}

func (c *pdcClient) Describe(ch chan<- *prometheus.Desc) {
	c.metrics.signingRequests.Describe(ch)
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
