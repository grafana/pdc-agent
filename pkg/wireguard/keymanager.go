package wireguard

import (
	"context"
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type KeyManager struct {
	config    Config
	logger    log.Logger
	pdcClient pdc.Client

	privateKey   *wgtypes.Key
	publicKey    *wgtypes.Key
	pdcPublicKey string
	pdcEndpoint  string
	assignedIP   string
	networkCIDR  string
}

func NewKeyManager(config Config, logger log.Logger, pdcClient pdc.Client) *KeyManager {
	return &KeyManager{
		config:    config,
		logger:    logger,
		pdcClient: pdcClient,
	}
}

func (km *KeyManager) EnsureKeys(ctx context.Context) error {
	// Always generate fresh keys to avoid any caching/state issues
	level.Info(km.logger).Log("msg", "generating fresh Wireguard key pair")

	privateKey, publicKey, err := km.generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	if err := km.registerPublicKey(ctx, publicKey); err != nil {
		return fmt.Errorf("failed to register public key with PDC: %w", err)
	}

	km.privateKey = &privateKey
	km.publicKey = &publicKey

	level.Info(km.logger).Log("msg", "fresh Wireguard keys generated and registered successfully")

	return nil
}

func (km *KeyManager) GetPrivateKey() (wgtypes.Key, error) {
	if km.privateKey == nil {
		return wgtypes.Key{}, fmt.Errorf("private key not initialized")
	}
	return *km.privateKey, nil
}

func (km *KeyManager) GetPublicKey() (wgtypes.Key, error) {
	if km.publicKey == nil {
		return wgtypes.Key{}, fmt.Errorf("public key not initialized")
	}
	return *km.publicKey, nil
}

func (km *KeyManager) generateKeyPair() (wgtypes.Key, wgtypes.Key, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}

	publicKey := privateKey.PublicKey()
	return privateKey, publicKey, nil
}

func (km *KeyManager) registerPublicKey(ctx context.Context, publicKey wgtypes.Key) error {
	resp, err := km.pdcClient.RegisterWireguardKey(ctx, publicKey.String(), km.config.TunnelID)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("registration failed: %s", resp.Message)
	}

	// Store the PDC public key, endpoint, and IP assignment from the response
	km.pdcPublicKey = resp.ServerPublicKey
	km.pdcEndpoint = resp.ServerEndpoint
	km.assignedIP = resp.AssignedIP
	km.networkCIDR = resp.NetworkCIDR

	level.Info(km.logger).Log("msg", "received PDC server info", "endpoint", km.pdcEndpoint, "assignedIP", km.assignedIP, "networkCIDR", km.networkCIDR)

	return nil
}

func (km *KeyManager) GetPDCPublicKey() string {
	return km.pdcPublicKey
}

func (km *KeyManager) GetPDCEndpoint() string {
	return km.pdcEndpoint
}

func (km *KeyManager) GetAssignedIP() string {
	return km.assignedIP
}

func (km *KeyManager) GetNetworkCIDR() string {
	return km.networkCIDR
}
