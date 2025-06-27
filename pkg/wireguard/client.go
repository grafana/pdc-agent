package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Client struct {
	config      Config
	logger      log.Logger
	device      *device.Device
	tnet        *netstack.Net
	tunnelID    string
	pdcClient   pdc.Client
	keyMgr      *KeyManager
	socksServer *SOCKSServer

	mu      sync.RWMutex
	running bool
}

func NewClient(config Config, logger log.Logger, pdcClient pdc.Client) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	keyMgr := NewKeyManager(config, logger, pdcClient)

	return &Client{
		config:    config,
		logger:    logger,
		tunnelID:  config.TunnelID,
		pdcClient: pdcClient,
		keyMgr:    keyMgr,
	}, nil
}

func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("client already running")
	}

	level.Info(c.logger).Log("msg", "starting Wireguard client", "tunnel_id", c.tunnelID)

	if err := c.ensureKeys(ctx); err != nil {
		return fmt.Errorf("failed to ensure keys: %w", err)
	}

	// Register with PDC first to get the server public key
	if err := c.registerWithPDC(ctx); err != nil {
		return fmt.Errorf("failed to register with PDC: %w", err)
	}

	// Setup Wireguard device after registration (now we have the PDC public key)
	if err := c.setupWireguardDevice(); err != nil {
		return fmt.Errorf("failed to setup Wireguard device: %w", err)
	}

	if err := c.startSOCKSServer(); err != nil {
		return fmt.Errorf("failed to start SOCKS server: %w", err)
	}

	c.running = true
	level.Info(c.logger).Log("msg", "Wireguard client started successfully")

	return nil
}

func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	level.Info(c.logger).Log("msg", "stopping Wireguard client")

	if c.socksServer != nil {
		c.socksServer.Stop()
	}

	if c.device != nil {
		c.device.Close()
	}

	c.running = false
	level.Info(c.logger).Log("msg", "Wireguard client stopped")

	return nil
}

func (c *Client) ensureKeys(ctx context.Context) error {
	return c.keyMgr.EnsureKeys(ctx)
}

func (c *Client) setupWireguardDevice() error {
	// Get assigned IP from KeyManager
	assignedIP := c.keyMgr.GetAssignedIP()
	var tunIPs []netip.Addr

	if assignedIP != "" {
		ip, err := netip.ParseAddr(assignedIP)
		if err != nil {
			return fmt.Errorf("failed to parse assigned IP %s: %w", assignedIP, err)
		}
		tunIPs = []netip.Addr{ip}
		level.Info(c.logger).Log("msg", "using assigned IP for TUN interface", "ip", assignedIP)
	} else {
		level.Debug(c.logger).Log("msg", "no assigned IP available, using empty IP list")
	}

	tun, tnet, err := netstack.CreateNetTUN(
		tunIPs,         // Use assigned IP
		[]netip.Addr{}, // No DNS needed
		1420,           // MTU
	)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}
	c.tnet = tnet

	c.device = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))

	privateKey, err := c.keyMgr.GetPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to get private key: %w", err)
	}

	peerConfig, err := c.generatePeerConfig(privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate peer config: %w", err)
	}

	err = c.device.IpcSet(peerConfig)
	if err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}

	return c.device.Up()
}

func (c *Client) generatePeerConfig(privateKey wgtypes.Key) (string, error) {
	// Get PDC endpoint from KeyManager (from registration response) or fall back to config
	pdcEndpoint := c.keyMgr.GetPDCEndpoint()
	if pdcEndpoint == "" {
		pdcEndpoint = fmt.Sprintf("%s:%d", c.config.PDCEndpoint, c.config.PDCPort)
	}

	// Get PDC public key from KeyManager (from registration response)
	pdcPublicKeyB64 := c.keyMgr.GetPDCPublicKey()
	if pdcPublicKeyB64 == "" {
		return "", fmt.Errorf("PDC public key not available from registration response")
	}

	// Convert base64-encoded PDC public key to hex
	pdcPublicKeyBytes, err := base64.StdEncoding.DecodeString(pdcPublicKeyB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode PDC public key: %w", err)
	}
	pdcPublicKeyHex := hex.EncodeToString(pdcPublicKeyBytes)

	// For SOCKS proxy functionality, route all traffic through the tunnel
	allowedIPs := "allowed_ip=0.0.0.0/0\nallowed_ip=::/0"
	level.Debug(c.logger).Log("msg", "using 0.0.0.0/0 for allowed IPs to enable SOCKS proxy routing")

	config := fmt.Sprintf(`private_key=%s
listen_port=%d
public_key=%s
endpoint=%s
%s
persistent_keepalive_interval=%d
`,
		hex.EncodeToString(privateKey[:]),
		c.config.ListenPort,
		pdcPublicKeyHex,
		pdcEndpoint,
		allowedIPs,
		int(c.config.KeepAlive.Seconds()),
	)

	return config, nil
}

func (c *Client) registerWithPDC(ctx context.Context) error {
	// Registration is handled by KeyManager in ensureKeys()
	// This method is kept for backward compatibility but does nothing if already registered
	if c.keyMgr.GetPDCPublicKey() != "" {
		level.Debug(c.logger).Log("msg", "already registered with PDC, skipping")
		return nil
	}

	publicKey, err := c.keyMgr.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	resp, err := c.pdcClient.RegisterWireguardKey(ctx, publicKey.String(), c.tunnelID)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("registration failed: %s", resp.Message)
	}

	level.Info(c.logger).Log("msg", "registered with PDC", "endpoint", resp.ServerEndpoint)
	return nil
}

func (c *Client) startSOCKSServer() error {
	c.socksServer = NewSOCKSServer(c.config, c.logger, c.tnet)
	return c.socksServer.Start()
}
