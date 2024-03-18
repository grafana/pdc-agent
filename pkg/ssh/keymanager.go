package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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

// Start ensures valid keys and certs exist, and optionally starts a background
// certificate refresh goroutine.
func (km *KeyManager) Start(ctx context.Context) error {
	level.Debug(km.logger).Log("msg", "starting key manager")
	err := km.CreateKeys(ctx, km.cfg.ForceKeyFileOverwrite)
	if err != nil {
		return err
	}

	go km.backgroundCertRefresh(ctx)
	return nil
}

func (km *KeyManager) backgroundCertRefresh(ctx context.Context) {
	if km.cfg.CertCheckCertExpiryPeriod == 0 {
		level.Debug(km.logger).Log("msg", "CertCheckCertExpiryPeriod is 0, will not refresh certificate in the background")
		return
	}

	ticker := time.NewTicker(km.cfg.CertCheckCertExpiryPeriod)
	for {
		select {
		case <-ticker.C:
			level.Debug(km.logger).Log("msg", "check certificate expiration time, renew if needed")

			if err := km.ensureCertExists(ctx, false); err != nil {
				level.Error(km.logger).Log("msg", "could not check or generate certificate", "error", err)
			}
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}

// CreateKeys checks that the SSH public key, private key, certificate and known_hosts
// files for existence and validity, and generates new ones if required.
func (km *KeyManager) CreateKeys(ctx context.Context, forceNewKeys bool) error {
	newCertRequired, err := km.ensureKeysExist(forceNewKeys)
	if err != nil {
		return err
	}

	argumentHash := km.argumentsHash()
	if km.argumentsHashIsDifferent(argumentHash) {
		level.Info(km.logger).Log("msg", "new certificate required: agent arguments changed", "hash", argumentHash)
		newCertRequired = true
	}

	if err := km.ensureCertExists(ctx, newCertRequired); err != nil {
		return fmt.Errorf("ensuring certificate exists: %w", err)
	}

	if err := km.writeHashFile([]byte(argumentHash)); err != nil {
		return fmt.Errorf("writing to hash file: %w", err)
	}

	return nil
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
func (km KeyManager) ensureKeysExist(forceCreate bool) (bool, error) {

	// check if files already exist
	r := forceCreate || km.newKeysRequired()

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

	if now > (cert.ValidBefore - uint64(km.cfg.CertExpiryWindow.Seconds())) {
		level.Info(km.logger).Log("msg", "new certificate required: certificate is about to expire")
		return true
	}

	if now < cert.ValidAfter {
		level.Info(km.logger).Log("msg", "new certificate required: certificate is not yet valid")
		return true
	}

	level.Debug(km.logger).Log("msg", "found existing valid certificate")

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

	level.Debug(km.logger).Log("msg", fmt.Sprintf("found valid %s", KnownHostsFile))
	return false
}

// argumentsHashIsDifferent returns true when specific arguments
// passed to the pdc agent are different from the previous arguments.
func (km KeyManager) argumentsHashIsDifferent(hash string) bool {
	bytes, err := km.readHashFile()
	if errors.Is(err, os.ErrNotExist) {
		// No hash stored yet, let's get a new certificate and store the hash.
		return true
	}

	contents := string(bytes)

	return contents != hash
}

// argumentsHash returns a hash of the values that end up in the principals field of the certificate.
func (km KeyManager) argumentsHash() string {
	value := km.cfg.PDC.HostedGrafanaID

	if km.cfg.PDC.DevNetwork != "" {
		value = fmt.Sprintf("%s/%s", value, km.cfg.PDC.DevNetwork)
	}

	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
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

func (km KeyManager) readHashFile() ([]byte, error) {
	path := km.cfg.KeyFile + "_hash"
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

func (km KeyManager) writeHashFile(data []byte) error {
	path := path.Join(km.cfg.KeyFile + "_hash")
	return os.WriteFile(path, data, 0600)
}
