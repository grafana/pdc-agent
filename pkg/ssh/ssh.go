package ssh

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
)

type Config struct {
	Args []string // deprecated

	KeyFile               string   // path to private key file
	SSHFlags              []string // Additional flags to be passed to ssh(1). e.g. --ssh-flag="-vvv" --ssh-flag="-L 80:localhost:80"
	ForceKeyFileOverwrite bool
	Port                  int
	PDC                   pdc.Config
	LegacyMode            bool
	URL                   *url.URL
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
		PDC:     pdc.Config{},
		KeyFile: "~/.ssh/gcloud_pdc",
	}
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	def := DefaultConfig()

	cfg.SSHFlags = []string{}
	f.Func("ssh-flag", "Additional flags to be passed to ssh. Can be set more than once.", cfg.addSSHFlag)
	f.StringVar(&cfg.KeyFile, "ssh-key-file", def.KeyFile, "The path to the SSH key file.")
	f.BoolVar(&cfg.ForceKeyFileOverwrite, "force-key-file-overwrite", false, forceKeyFileOverwriteUsage)
	f.Func("ssh-url", "url of the PDC SSH gateway", cfg.parseGatewayURL)

}

func (cfg *Config) parseGatewayURL(s string) error {
	url, err := url.Parse(s)
	if err != nil {
		return err
	}

	cfg.URL = url
	return nil
}

func (cfg Config) KeyFileDir() string {
	dir, _ := path.Split(cfg.KeyFile)
	return dir
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
func NewClient(cfg *Config) (*SSHClient, error) {
	if cfg.URL == nil {
		return nil, errors.New("ssh-url cannot be nil")
	}
	client := &SSHClient{
		cfg:    cfg,
		SSHCmd: "ssh",
	}

	client.BasicService = services.NewIdleService(client.starting, client.stopping)
	return client, nil
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

// SSHFlagsFromConfig generates the flags we pass to ssh.
// I don't think we need to enforce some flags from being overidden: The agent
// is just a convenience, users could override anything using ssh if they wanted.
// All of our control lives within the SSH certificate.
func (s *SSHClient) SSHFlagsFromConfig() ([]string, error) {

	if s.cfg.LegacyMode {
		log.Println("running in legacy mode")
		return s.cfg.Args, nil
	}

	keyFileArr := strings.Split(s.cfg.KeyFile, "/")
	keyFileDir := strings.Join(keyFileArr[:len(keyFileArr)-1], "/")

	gwURL := s.cfg.URL
	result := []string{
		"-i",
		s.cfg.KeyFile,
		fmt.Sprintf("%s@%s", s.cfg.PDC.HostedGrafanaId, gwURL.String()),
		"-p",
		fmt.Sprintf("%d", s.cfg.Port),
		"-R", "0",
		"-vv",
		"-o", fmt.Sprintf("UserKnownHostsFile=%s/known_hosts", keyFileDir),
		"-o", fmt.Sprintf("CertificateFile=%s-cert.pub", s.cfg.KeyFile),
	}

	return result, nil
}
