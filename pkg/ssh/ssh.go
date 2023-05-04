package ssh

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Args []string // deprecated

	KeyFile               string   // path to private key file
	SSHFlags              []string // Additional flags to be passed to ssh(1). e.g. --ssh-flag="-vvv" --ssh-flag="-L 80:localhost:80"
	ForceKeyFileOverwrite bool
	Port                  int
	Identity              string // Once we have multiple private networks, this will be the network name
	HostedGrafanaId       string
	PDC                   *pdc.Config
}

const forceKeyFileOverwriteUsage = `If enabled, the pdc-agent will regenerate an SSH key pair and request a new
certificate to use whem establishing an SSH tunnel.

If disabled, pdc-agent will use existing SSH keys and only request a new SSH
certificate when the existing one is expired. If no SHH keys exist, it will
generate a pair and request a certificate.`

// DefaultConfig returns a Config with some sensible defaults set
func DefaultConfig() *Config {

	return &Config{
		Port:    22,
		PDC:     pdc.DefaultConfig(),
		KeyFile: "~/.ssh/gcloud_pdc",
	}
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	def := DefaultConfig()

	cfg.SSHFlags = []string{}
	f.Func("ssh-flag", "Additional flags to be passed to ssh. Can be set more than once.", cfg.addSSHFlag)
	f.StringVar(&cfg.KeyFile, "ssh-key-file", def.KeyFile, "The path to the SSH key file.")
	// Once we're on multiple networks, this can be returned by the PDC API signing request call, because it will be the network ID
	f.StringVar(&cfg.Identity, "ssh-identity", "", "The identity used for the ssh connection. This should be your stack name")
	f.StringVar(&cfg.HostedGrafanaId, "gcloud-hosted-grafana-id", "", "The ID of the Hosted Grafana instance to connect to")
	f.BoolVar(&cfg.ForceKeyFileOverwrite, "force-key-file-overwrite", false, forceKeyFileOverwriteUsage)

}

func (cfg *Config) addSSHFlag(flag string) error {
	return nil
}

type SSHClient struct {
	*services.BasicService
	cfg    *Config
	SSHCmd string // SSH command to run, defaults to "ssh". Require for testing.
}

// NewClient returns a new SSH client
func NewClient(cfg *Config) *SSHClient {
	client := &SSHClient{
		cfg:    cfg,
		SSHCmd: "ssh",
	}

	// Set the Identity to the HG ID for now. When we have multiple private
	// networks, the Identity will be the network ID.
	if cfg.Identity == "" {
		cfg.Identity = cfg.HostedGrafanaId
	}

	client.BasicService = services.NewIdleService(client.starting, client.stopping)
	return client
}

func (s *SSHClient) starting(ctx context.Context) error {
	log.Println("starting ssh client")
	go func() {
		for {

			flags, err := s.SSHFlagsFromConfig()
			if err != nil {
				log.Printf("could not parse flags: %s\n", err)
				return
			}

			log.Println("parsed flags;")
			log.Println(s.SSHFlagsFromConfig())
			cmd := exec.CommandContext(ctx, s.SSHCmd, flags...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			if ctx.Err() != nil {
				break // context was canceled
			}
			log.Println("ssh client exited, restarting")
			// backoff
			// TODO: Implement exponential backoff
			time.Sleep(1 * time.Second)
		}
	}()
	return nil
}

func (s *SSHClient) stopping(err error) error {
	log.Println("stopping ssh client")
	return err
}

func (s *SSHClient) legacyMode() bool {
	return s.cfg.PDC.Host == "" || s.cfg.HostedGrafanaId == "" || s.cfg.Identity == ""
}

// SSHFlagsFromConfig generates the flags we pass to ssh.
// I don't think we need to enforce some flags from being overidden: The agent
// is just a convenience, users could override anything using ssh if they wanted.
// All of our control lives within the SSH certificate.
func (s *SSHClient) SSHFlagsFromConfig() ([]string, error) {

	if s.legacyMode() {
		log.Println("running in legacy mode")
		log.Printf("%+v \n %+v", s.cfg, *s.cfg.PDC)
		return s.cfg.Args, nil
	}

	keyFileArr := strings.Split(s.cfg.KeyFile, "/")
	keyFileDir := strings.Join(keyFileArr[:len(keyFileArr)-1], "/")

	gwURL, _ := s.cfg.PDC.GatewayURL()
	result := []string{
		"-i",
		s.cfg.KeyFile,
		fmt.Sprintf("%s@%s", s.cfg.Identity, gwURL.String()),
		"-p",
		fmt.Sprintf("%d", s.cfg.Port),
		"-R", "0",
		"-vv",
		"-o", fmt.Sprintf("UserKnownHostsFile=%s/known_hosts", keyFileDir),
		"-o", fmt.Sprintf("CertificateFile=%s-cert.pub", s.cfg.KeyFile),
	}

	return result, nil
}

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
	if km.cfg.PDC.Host == "" || km.cfg.HostedGrafanaId == "" {
		return nil
	}

	// TODO otherwise, ensure ssh keys and certificate
	return km.EnsureKeysExist()
}

func (km *KeyManager) stopping(_ error) error {
	log.Println("stopping key manager")

	return nil
}

func (km KeyManager) EnsureKeysExist() error {

	// check if files already exist

	newKeysReqiured := km.newKeysRequired()
	newCertRequired := false
	if newKeysReqiured {
		newCertRequired = true

		// TODO gen keys
	}

	if !newCertRequired {
		newCertRequired = km.newCertRequired()
	}

	if !newCertRequired {
		return nil
	}

	// TODO generate cert
	return nil
}

// TODO refactor this to return the keys if valid
func (km KeyManager) newKeysRequired() bool {
	_, err := os.Open(km.cfg.KeyFile)
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("private key file not found: %s\n", km.cfg.KeyFile)
		return true
	}

	// TODO also check private key file has reasonable contents, if possible

	pubKeyPath := km.cfg.KeyFile + ".pub"
	pubKeyFile, err := os.Open(pubKeyPath)
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("public key file not found: %s\n", pubKeyPath)
		return true
	}
	pubKeyBytes := []byte{}
	_, err = pubKeyFile.Read(pubKeyBytes)
	if err != nil {
		log.Println("failed to read public key file")
		return true
	}

	_, _, _, _, err = ssh.ParseAuthorizedKey(pubKeyBytes)
	if err != nil {
		log.Println("failed to parse public key")
		return true
	}

	return false
}

func (km KeyManager) newCertRequired() bool {
	certKeyPath := km.cfg.KeyFile + "-cert.pem"
	file, err := os.Open(certKeyPath)
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("certificate file not found: %s\n", certKeyPath)
		return true
	}

	b := []byte{}
	_, err = file.Read(b)
	if err != nil {
		log.Println("could not read certificate file")
		return true
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		log.Println("file is not a public key")
		return true
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		log.Println("file is not an SSH certificate")
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

type FileReadWriter interface {
	WriteFile(name string, data []byte, perm fs.FileMode) error
	ReadFile(name string) ([]byte, error)
}

type OSFileReadWriter struct {
}

func (f OSFileReadWriter) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (f *OSFileReadWriter) WriteFile(name string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(name, data, perm)
}
