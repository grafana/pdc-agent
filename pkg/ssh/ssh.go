package ssh

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"golang.org/x/sync/errgroup"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
)

// Config represents all configurable properties of the ssh package.
type Config struct {
	Args []string // deprecated

	KeyFile     string
	SSHFlags    []string // Additional flags to be passed to ssh(1). e.g. --ssh-flag="-vvv" --ssh-flag="-L 80:localhost:80"
	Port        int
	PDC         pdc.Config
	LegacyMode  bool
	URL         *url.URL
	ExitOnError bool
}

// DefaultConfig returns a Config with some sensible defaults set
func DefaultConfig() *Config {
	root, err := os.UserHomeDir()
	if err != nil {
		// Use relative path (should not happen)
		root = ""
	}
	return &Config{
		Port:    22,
		PDC:     pdc.Config{},
		KeyFile: path.Join(root, ".ssh/grafana_pdc"),
	}
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	def := DefaultConfig()

	cfg.SSHFlags = []string{}
	f.StringVar(&cfg.KeyFile, "ssh-key-file", def.KeyFile, "The path to the SSH key file.")
	f.BoolVar(&cfg.ExitOnError, "exit-on-error", false, "Exit if the agent encounters an error whilst, instead of retrying")
	f.Func("ssh-flag", "Additional flags to be passed to ssh. Can be set more than once.", cfg.addSSHFlag)
}

func (cfg Config) KeyFileDir() string {
	dir, _ := path.Split(cfg.KeyFile)
	return dir
}

func (cfg *Config) addSSHFlag(s string) error {
	cfg.SSHFlags = append(cfg.SSHFlags, s)
	return nil
}

// Client is a client for ssh. It configures and runs ssh commands
type Client struct {
	*services.BasicService
	cfg    *Config
	SSHCmd string // SSH command to run, defaults to "ssh". Require for testing.
	logger log.Logger
	km     *KeyManager
}

// NewClient returns a new SSH client in an idle state
func NewClient(cfg *Config, logger log.Logger, km *KeyManager) *Client {
	client := &Client{
		cfg:    cfg,
		SSHCmd: "ssh",
		logger: logger,
		km:     km,
	}

	client.BasicService = services.NewIdleService(client.starting, client.stopping)
	return client
}

func (s *Client) starting(ctx context.Context) error {
	level.Info(s.logger).Log("msg", "starting ssh client")
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			// check keys and cert validity before (re)start, create new cert if required
			// This will exit if it fails, rather than endlessly retrying to sign keys.
			if s.km != nil {
				err := s.km.CreateKeys(ctx)
				if err != nil {
					level.Error(s.logger).Log("msg", "could not check or generate certificate", "error", err)
					return err
				}
			}

			flags, err := s.SSHFlagsFromConfig()
			if err != nil {
				level.Error(s.logger).Log("msg", fmt.Sprintf("could not parse flags: %s", err))
				return err
			}

			level.Debug(s.logger).Log("msg", fmt.Sprintf("parsed flags: %s", flags))
			cmd := exec.CommandContext(ctx, s.SSHCmd, flags...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
			if ctx.Err() != nil {
				break // context was canceled
			}

			level.Error(s.logger).Log("msg", "ssh client exited. restarting")
			// backoff
			// TODO: Implement exponential backoff
			time.Sleep(1 * time.Second)

		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}
	return nil
}

func (s *Client) stopping(err error) error {
	level.Info(s.logger).Log("msg", "stopping ssh client")
	return err
}

// SSHFlagsFromConfig generates the array of flags to pass to the ssh command.
// It does not stop default flags from being overidden, but only the first instance
// of `-o` flags are used.
func (s *Client) SSHFlagsFromConfig() ([]string, error) {

	if s.cfg.LegacyMode {
		level.Warn(s.logger).Log("msg", "running in legacy mode")
		return s.cfg.Args, nil
	}

	keyFileArr := strings.Split(s.cfg.KeyFile, "/")
	keyFileDir := strings.Join(keyFileArr[:len(keyFileArr)-1], "/")

	gwURL := s.cfg.URL
	result := []string{
		"-i",
		s.cfg.KeyFile,
		fmt.Sprintf("%s@%s", s.cfg.PDC.HostedGrafanaID, gwURL.String()),
		"-p",
		fmt.Sprintf("%d", s.cfg.Port),
		"-R", "0",
		"-vv",
		"-o", fmt.Sprintf("UserKnownHostsFile=%s/%s", keyFileDir, KnownHostsFile),
		"-o", fmt.Sprintf("CertificateFile=%s-cert.pub", s.cfg.KeyFile),
		"-o", "ServerAliveInterval=15",
	}

	for _, f := range s.cfg.SSHFlags {
		// flags are in the format '-vv' or '-o Option=Value'. Split to flatten strings
		// in the second format
		result = append(result, strings.Split(f, " ")...)
	}

	return result, nil
}
