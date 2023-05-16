package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
)

const (
	// SSHKeySize is the size of the SSH key.
	SSHKeySize     = 4096
	KnownHostsFile = "grafana_pdc_known_hosts"
)

// TODO
// KeyManager implements KeyManager. If needed, it gets new certificates signed
// by the PDC API.
//
// If the service starts successfully, then the key and cert files will exist.
// It will attempt to reuse existing keys and certs if they exist.
type KeyManager struct {
	cfg    *Config
	client pdc.Client
	logger log.Logger
}

// NewKeyManager returns a new KeyManager in an idle state
func NewKeyManager(cfg *Config, logger log.Logger, client pdc.Client) *KeyManager {
	km := KeyManager{
		cfg:    cfg,
		client: client,
		logger: logger,
	}

	return &km
}

func (km *KeyManager) CreateKeys(ctx context.Context) error {
	level.Info(km.logger).Log("msg", "starting key manager")

	newCertRequired, err := km.ensureKeysExist()
	if err != nil {
		return err
	}

	return km.ensureCertExists(ctx, newCertRequired)
}

// EnsureCertExists checks for the existence of a valid SSH certificate and
// regenerates one if it cannot find one, or if forceCreate is true.
func (km KeyManager) ensureCertExists(ctx context.Context, forceCreate bool) error {
	newCertRequired := forceCreate

	if newCertRequired {
		err := km.generateCert(ctx)
		if err != nil {
			return fmt.Errorf("failed to generate new certificate: %w", err)
		}
		return nil
	}

	newCertRequired = km.newCertRequired()

	if !newCertRequired {
		return nil
	}

	err := km.generateCert(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate new certificate: %w", err)
	}
	return nil
}

// ensureKeysExist checks for the existence of valid SSH keys. If they exist,
// it does nothing. If they don't, it creates them. It returns a boolean
// indicating whether new keys were created, and an error.
func (km KeyManager) ensureKeysExist() (bool, error) {

	// check if files already exist
	r := km.newKeysRequired()

	if !r {
		return false, nil
	}

	// ensure the key file dir exists before we try and write there
	err := os.MkdirAll(km.cfg.KeyFileDir(), 0774)
	if err != nil && !os.IsExist(err) {
		return false, err
	}

	return true, km.generateKeyPair()
}

func (km KeyManager) newKeysRequired() bool {
	kb, err := km.readKeyFile()
	if err != nil {
		level.Info(km.logger).Log("msg", "new keys required: could not read private key file")
		return true
	}

	block, _ := pem.Decode(kb)
	if block == nil {
		level.Info(km.logger).Log("msg", "new keys required: could not parse private key PEM file")
		return true
	}

	pbk, err := km.readPubKeyFile()
	if err != nil {
		level.Info(km.logger).Log("msg", "new keys required: could not read public key file")
		return true
	}

	_, _, _, _, err = ssh.ParseAuthorizedKey(pbk)
	if err != nil {
		level.Info(km.logger).Log("msg", "new keys required: could not parse public key")
		return true
	}

	return false
}

func (km KeyManager) newCertRequired() bool {
	cb, err := km.readCertFile()
	if err != nil {
		level.Info(km.logger).Log("msg", "new certificate required: could not read certificate file")
		return true
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(cb)
	if err != nil {
		level.Info(km.logger).Log("msg", "new certificate required: could not parse certificate")
		return true
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		level.Info(km.logger).Log("msg", "new certificate required: certificate is incorrect format")
		return true
	}
	now := uint64(time.Now().Unix())

	if now > cert.ValidBefore {
		level.Info(km.logger).Log("msg", "new certificate required: certificate validity has expired")
		return true
	}

	if now < cert.ValidAfter {
		level.Info(km.logger).Log("msg", "new certificate required: certificate is not yet valid")
		return true
	}

	level.Info(km.logger).Log("msg", "found existing valid certificate")

	kh, err := os.ReadFile(path.Join(km.cfg.KeyFileDir(), KnownHostsFile))
	if err != nil {
		level.Info(km.logger).Log("msg", "fetching new certificate: cannot not read known hosts file")
		return true
	}
	_, _, _, _, _, err = ssh.ParseKnownHosts(kh)
	if err != nil {
		level.Info(km.logger).Log("msg", fmt.Sprintf("fetching new certificate: cannot parse %s", KnownHostsFile))
		return true
	}

	level.Info(km.logger).Log("msg", fmt.Sprintf("found valid %s", KnownHostsFile))
	return false
}

func (km KeyManager) generateKeyPair() error {

	// Generate a new private/public keypair for OpenSSH
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	sshPubKey, _ := ssh.NewPublicKey(pubKey)

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey),
	}
	pemPrivKey := pem.EncodeToMemory(pemKey)

	err := km.writeKeyFile(pemPrivKey)
	if err != nil {
		return err
	}

	// public key should be in authorized_keys file format
	return km.writePubKeyFile(ssh.MarshalAuthorizedKey(sshPubKey))
}

func (km KeyManager) generateCert(ctx context.Context) error {
	level.Info(km.logger).Log("msg", "generating new certificate")

	pbk, err := km.readPubKeyFile()
	if err != nil {
		return fmt.Errorf("could not read public ssh key file: %w", err)
	}

	resp, err := km.client.SignSSHKey(ctx, pbk)
	if err != nil {
		return fmt.Errorf("key signing request failed: %w", err)
	}

	if resp == nil {
		return errors.New("received empty response from PDC API")
	}

	// write response to file
	err = km.writeKnownHostsFile(resp.KnownHosts)
	if err != nil {
		return fmt.Errorf("failed to write known hosts file: %w", err)
	}
	err = km.writeCertFile(ssh.MarshalAuthorizedKey(&resp.Certificate))
	if err != nil {
		return err
	}

	return nil
}

func (km KeyManager) readKeyFile() ([]byte, error) {
	return os.ReadFile(km.cfg.KeyFile)
}

func (km KeyManager) readPubKeyFile() ([]byte, error) {
	path := km.cfg.KeyFile + ".pub"
	return os.ReadFile(path)
}

func (km KeyManager) readCertFile() ([]byte, error) {
	path := km.cfg.KeyFile + "-cert.pub"
	return os.ReadFile(path)
}

func (km KeyManager) writeKeyFile(data []byte) error {
	return os.WriteFile(km.cfg.KeyFile, data, 0600)
}

func (km KeyManager) writePubKeyFile(data []byte) error {
	path := km.cfg.KeyFile + ".pub"
	return os.WriteFile(path, data, 0600)
}

func (km KeyManager) writeKnownHostsFile(data []byte) error {
	path := path.Join(km.cfg.KeyFileDir(), KnownHostsFile)
	return os.WriteFile(path, data, 0600)
}

func (km KeyManager) writeCertFile(data []byte) error {
	path := path.Join(km.cfg.KeyFile + "-cert.pub")
	return os.WriteFile(path, data, 0600)
}
