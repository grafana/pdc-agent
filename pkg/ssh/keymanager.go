package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"time"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"golang.org/x/crypto/ssh"
)

const (
	// SSHKeySize is the size of the SSH key.
	SSHKeySize = 4096
)

// KeyManager manages SSH keys and certificates. It ensures that the SSH keys,
// certificates and known_hosts files exist in their configured locations.
type KeyManager struct {
	*services.BasicService
	cfg    *Config
	frw    FileReadWriter
	client pdc.Client
}

func NewKeyManager(cfg *Config, client pdc.Client) *KeyManager {
	km := KeyManager{
		cfg:    cfg,
		frw:    &OSFileReadWriter{},
		client: client,
	}

	km.BasicService = services.NewIdleService(km.starting, km.stopping)
	return &km
}

func (km *KeyManager) starting(ctx context.Context) error {
	log.Println("starting key manager")
	// if new flags are not set, do nothing.
	if km.cfg.PDC == nil || km.cfg.PDC.Host == "" || km.cfg.PDC.HostedGrafanaId == "" {
		return nil
	}

	newCertRequired, err := km.ensureKeysExist()
	if err != nil {
		return err
	}

	return km.ensureCertExists(newCertRequired)
}

func (km *KeyManager) stopping(_ error) error {
	log.Println("stopping key manager")

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

	return true, km.generateKeyPair()
}

// ensureCertExists checks for the existence of a valid SSH certificate and
// regenerates one if it cannot find one, or if forceCreate is true.
func (km KeyManager) ensureCertExists(forceCreate bool) error {
	newCertRequired := forceCreate

	if newCertRequired {
		return km.generateCert()
	}

	newCertRequired = km.newCertRequired()

	if !newCertRequired {
		return nil
	}

	return km.generateCert()
}

func (km KeyManager) newKeysRequired() bool {
	kb, err := km.readKeyFile()
	if err != nil {
		log.Println("could not read private key file")
		return true
	}

	_, err = x509.ParsePKCS1PrivateKey(kb)
	if err != nil {
		log.Println("could not parse private key file")
	}

	pbk, err := km.readPubKeyFile()
	if err != nil {
		log.Println("could not read public key file")
		return true
	}

	_, _, _, _, err = ssh.ParseAuthorizedKey(pbk)
	if err != nil {
		log.Println("could not parse public key")
		return true
	}

	return false
}

func (km KeyManager) newCertRequired() bool {
	cb, err := km.readCertFile()
	if err != nil {
		log.Println("could not read certificate file")
		return true
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(cb)
	if err != nil {
		log.Println("could not parse certificate")
		return true
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		log.Println("certificate is incorrect format")
		return true
	}

	if cert.ValidBefore >= uint64(time.Now().Unix()) {
		log.Println("certificate validity has expired")
		return true
	}

	if cert.ValidAfter < uint64(time.Now().Unix()) {
		log.Println("certificate is not yet valid")
		return true
	}

	return false
}

func (km KeyManager) generateKeyPair() error {
	privKey, err := rsa.GenerateKey(rand.Reader, SSHKeySize)
	if err != nil {
		return err
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return err
	}
	pubKey := signer.PublicKey()

	var b bytes.Buffer
	err = pem.Encode(&b, &pem.Block{
		Type:  "SSH PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	if err != nil {
		return err
	}
	err = km.writeKeyFile(b.Bytes())
	if err != nil {
		return err
	}

	// public key should not be in PEM format
	return km.writePubKeyFile(ssh.MarshalAuthorizedKey(pubKey))
}

func (km KeyManager) generateCert() error {

	pbk, err := km.readPubKeyFile()
	if err != nil {
		return fmt.Errorf("could not read public ssh key file: %w", err)
	}

	resp, err := km.client.SignSSHKey(km.ServiceContext(), pbk)
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
	return km.frw.ReadFile(km.cfg.KeyFile)
}

func (km KeyManager) readPubKeyFile() ([]byte, error) {
	path := km.cfg.KeyFile + ".pub"
	return km.frw.ReadFile(path)
}

func (km KeyManager) readCertFile() ([]byte, error) {
	path := km.cfg.KeyFile + "-cert.pub"
	return km.frw.ReadFile(path)
}

func (km KeyManager) writeKeyFile(data []byte) error {
	return km.frw.WriteFile(km.cfg.KeyFile, data, 0600)
}

func (km KeyManager) writePubKeyFile(data []byte) error {
	path := km.cfg.KeyFile + ".pub"
	return km.frw.WriteFile(path, data, 0600)
}

func (km KeyManager) writeKnownHostsFile(data []byte) error {
	path := path.Join(km.cfg.KeyFileDir(), "known_hosts")
	return km.frw.WriteFile(path, data, 0600)
}

func (km KeyManager) writeCertFile(data []byte) error {
	path := path.Join(km.cfg.KeyFile + "-cert.pub")
	return km.frw.WriteFile(path, data, 0600)
}

type FileReadWriter interface {
	WriteFile(path string, data []byte, perm fs.FileMode) error
	ReadFile(path string) ([]byte, error)
}

type OSFileReadWriter struct {
}

func (f OSFileReadWriter) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (f *OSFileReadWriter) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(path, data, perm)
}
