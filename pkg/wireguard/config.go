package wireguard

import (
	"flag"
	"fmt"
	"net"
	"time"
)

type Config struct {
	ListenPort       int
	SOCKSAddr        string
	MetricsAddr      string
	TunnelID         string
	PDCEndpoint      string
	PDCPort          int
	PDCPublicKey     string
	KeepAlive        time.Duration
	HandshakeTimeout time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		ListenPort:       51820,
		SOCKSAddr:        "127.0.0.1:1080",
		MetricsAddr:      "127.0.0.1:9090",
		PDCPort:          51820,
		KeepAlive:        25 * time.Second,
		HandshakeTimeout: 30 * time.Second,
	}
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.IntVar(&cfg.ListenPort, "wireguard.listen-port", cfg.ListenPort, "Wireguard listen port")
	f.StringVar(&cfg.SOCKSAddr, "wireguard.socks-addr", cfg.SOCKSAddr, "SOCKS5 server listen address")
	f.StringVar(&cfg.MetricsAddr, "wireguard.metrics-addr", cfg.MetricsAddr, "Metrics server listen address")
	f.StringVar(&cfg.TunnelID, "wireguard.tunnel-id", cfg.TunnelID, "Tunnel ID for this agent instance")
	f.StringVar(&cfg.PDCEndpoint, "wireguard.pdc-endpoint", cfg.PDCEndpoint, "PDC server endpoint hostname")
	f.IntVar(&cfg.PDCPort, "wireguard.pdc-port", cfg.PDCPort, "PDC server Wireguard port")
	f.StringVar(&cfg.PDCPublicKey, "wireguard.pdc-public-key", cfg.PDCPublicKey, "PDC server Wireguard public key (optional, will be obtained from registration response)")
	f.DurationVar(&cfg.KeepAlive, "wireguard.keepalive", cfg.KeepAlive, "Wireguard keep-alive interval")
	f.DurationVar(&cfg.HandshakeTimeout, "wireguard.handshake-timeout", cfg.HandshakeTimeout, "Wireguard handshake timeout")
}

func (cfg *Config) Validate() error {
	if cfg.TunnelID == "" {
		return fmt.Errorf("tunnel-id is required for Wireguard mode")
	}

	if cfg.PDCEndpoint == "" {
		return fmt.Errorf("pdc-endpoint is required for Wireguard mode")
	}

	if _, _, err := net.SplitHostPort(cfg.SOCKSAddr); err != nil {
		return fmt.Errorf("invalid socks-addr: %w", err)
	}

	return nil
}
