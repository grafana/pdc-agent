package pdc

import (
	"context"
	"flag"
	"net/http"
	"net/url"
	"strings"

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

func (cfg *Config) APIURL() (*url.URL, error) {
	prefix := "private-datasource-connect"
	cluster, found := strings.CutPrefix(cfg.Host, prefix)
	if !found {
		// some custom host. Try to parse it and assume we dont need to edit it
		return url.Parse(cfg.Host + "." + cfg.Domain)
	}
	// add "-api" into hostname between private-datasource-connect and cluster
	return url.Parse(prefix + "-api" + cluster + "." + cfg.Domain)
}

func (cfg *Config) GatewayURL() (*url.URL, error) {
	return url.Parse(cfg.Host + "." + cfg.Domain)
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
