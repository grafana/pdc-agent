package pdc

import (
	"context"
	"flag"
	"net/http"

	"github.com/grafana/pdc-agent/pkg/httpclient"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Host   string // Also required in SSH Client
	Domain string // Also required in SSH client
	Token  string
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
}

type Client interface {
	SignSSHKey(ctx context.Context, key []byte) (*SigningResponse, error)
}

type SigningResponse struct {
	Certificate ssh.Certificate // use anon struct for unmarshalling, not this one.
	KnownHosts  []byte
}

func NewClient(cfg *Config) Client {
	return &pdcClient{
		cfg:        cfg,
		httpClient: &http.Client{Transport: httpclient.UserAgentTransport(nil)},
	}
}

type pdcClient struct {
	cfg        *Config
	httpClient *http.Client
}

func (c *pdcClient) SignSSHKey(ctx context.Context, key []byte) (*SigningResponse, error) {
	return nil, nil
}
