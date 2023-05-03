package ssh

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/grafana/dskit/services"
)

type Config struct {
	Args []string // deprecated

	KeyFile               string   // path to private key file
	SSHFlags              []string // Additional flags to be passed to ssh(1). e.g. --ssh-flag="-vvv" --ssh-flag="-L 80:localhost:80"
	ForceKeyFileOverwrite bool
	Port                  int
	Identity              string // Once we have multiple private networks, this will be the network name
	Domain                string
	HostedGrafanaId       string
	PDCSigningToken       string
	Host                  string // TODO consider having separate config items for gateway and api endpoints
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
		Domain:  "grafana.net",
		KeyFile: "~/.ssh/gcloud_pdc",
	}
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	def := DefaultConfig()

	f.StringVar(&cfg.Host, "host", "", "The host for PDC endpoints")
	f.StringVar(&cfg.Domain, "domain", def.Domain, "The domain for PDC endpoints")

	cfg.SSHFlags = []string{}
	f.Func("ssh-flag", "Additional flags to be passed to ssh. Can be set more than once.", cfg.addSSHFlag)
	f.StringVar(&cfg.KeyFile, "ssh-key-file", def.KeyFile, "The path to the SSH key file.")
	// Once we're on multiple networks, this can be returned by the PDC API signing request call, because it will be the network ID
	f.StringVar(&cfg.Identity, "ssh-identity", "", "The identity used for the ssh connection. This should be your stack name")
	f.StringVar(&cfg.HostedGrafanaId, "gcloud-hosted-grafana-id", "", "The ID of the Hosted Grafana instance to connect to")
	f.StringVar(&cfg.PDCSigningToken, "token", "", "The token to use to authenticate with Grafana Cloud. It must have the pdc-signing:write scope")
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

			fmt.Println(s.SSHFlagsFromConfig())
			cmd := exec.CommandContext(ctx, s.SSHCmd, s.SSHFlagsFromConfig()...)
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
	return s.cfg.Host == "" || s.cfg.HostedGrafanaId == "" || s.cfg.PDCSigningToken == "" || s.cfg.Identity == ""
}

// SSHFlagsFromConfig generates the flags we pass to ssh.
// I don't think we need to enforce some flags from being overidden: The agent
// is just a convenience, users could override anything using ssh if they wanted.
// All of our control lives within the SSH certificate.
func (s *SSHClient) SSHFlagsFromConfig() []string {

	if s.legacyMode() {
		return s.cfg.Args
	}

	keyFileArr := strings.Split(s.cfg.KeyFile, "/")
	keyFileDir := strings.Join(keyFileArr[:len(keyFileArr)-1], "/")

	defaults := []string{
		"-i",
		s.cfg.KeyFile,
		fmt.Sprintf("%s@%s.%s", s.cfg.Identity, s.cfg.Host, s.cfg.Domain),
		"-p",
		fmt.Sprintf("%d", s.cfg.Port),
		"-R", "0",
		"-vv",
		"-o", fmt.Sprintf("UserKnownHostsFile=%s/known_hosts", keyFileDir),
		"-o", fmt.Sprintf("CertificateFile=%s-cert.pub", s.cfg.KeyFile),
	}

	return defaults
}

// KeyManager manages SSH keys and certificates. It ensures that the SSH keys,
// certificates and known_hosts files exist in their configured locations.
type KeyManager struct {
	*services.BasicService
	cfg        *Config
	filesystem FileReadWriter
}

func NewKeyManager(cfg *Config) *KeyManager {
	km := KeyManager{
		cfg:        cfg,
		filesystem: &OSFileReadWriter{},
	}

	km.BasicService = services.NewIdleService(km.starting, km.stopping)
	return &km
}

func (km *KeyManager) starting(ctx context.Context) error {
	log.Println("starting key manager")
	// if new flags are not set, do nothing.
	if km.cfg.Host == "" || km.cfg.HostedGrafanaId == "" || km.cfg.PDCSigningToken == "" {
		return nil
	}

	// TODO otherwise, ensure ssh keys and certificate
	return k.EnsureKeysExist()
}

func (km *KeyManager) stopping(_ error) error {
	log.Println("stopping key manager")

	return nil
}

func (km KeyManager) EnsureKeysExist() error {

	os.WriteFile("", []byte{}, 0666)

	return nil
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
