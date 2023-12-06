package ssh

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/retry"
)

const (
	// The exit code sent by the pdc server when the connection limit is reached.
	ConnectionLimitReachedCode = 254
)

// Config represents all configurable properties of the ssh package.
type Config struct {
	Args []string // deprecated

	KeyFile  string
	SSHFlags []string // Additional flags to be passed to ssh(1). e.g. --ssh-flag="-vvv" --ssh-flag="-L 80:localhost:80"
	Port     int
	LogLevel int
	// Value passed as the -R option to the ssh command.
	ListenPort int
	PDC        pdc.Config
	LegacyMode bool
	// ForceKeyFileOverwrite forces a new ssh key pair to be generated.
	ForceKeyFileOverwrite bool
	URL                   *url.URL
}

// DefaultConfig returns a Config with some sensible defaults set
func DefaultConfig() *Config {
	root, err := os.UserHomeDir()
	if err != nil {
		// Use relative path (should not happen)
		root = ""
	}
	return &Config{
		Port:     22,
		LogLevel: 2,
		PDC:      pdc.Config{},
		KeyFile:  path.Join(root, ".ssh/grafana_pdc"),
	}
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	def := DefaultConfig()

	cfg.SSHFlags = []string{}
	f.StringVar(&cfg.KeyFile, "ssh-key-file", def.KeyFile, "The path to the SSH key file.")
	f.IntVar(&cfg.LogLevel, "log-level", def.LogLevel, "The level of log verbosity. The maximum is 3.")
	// use default log level if invalid
	if cfg.LogLevel > 3 {
		cfg.LogLevel = def.LogLevel
	}
	f.Func("ssh-flag", "Additional flags to be passed to ssh. Can be set more than once.", cfg.addSSHFlag)
	f.BoolVar(&cfg.ForceKeyFileOverwrite, "force-key-file-overwrite", false, "Force a new ssh key pair to be generated.")
	f.IntVar(&cfg.ListenPort, "listen-port", 0, "The port the agent will listen on.")
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

	// check keys and cert validity before start, create new cert if required
	// This will exit if it fails, rather than endlessly retrying to sign keys.
	if s.km != nil {
		err := s.km.CreateKeys(ctx)
		if err != nil {
			level.Error(s.logger).Log("msg", "could not check or generate certificate", "error", err)
			return err
		}
	}

	// Attempt to parse SSH flags before triggering the goroutine, so we can exit
	// if the parsing fails
	flags, err := s.SSHFlagsFromConfig()
	if err != nil {
		level.Error(s.logger).Log("msg", fmt.Sprintf("could not parse flags: %s", err))
		return err
	}
	level.Debug(s.logger).Log("msg", fmt.Sprintf("parsed flags: %s", flags))

	retryOpts := retry.Opts{MaxBackoff: 16 * time.Second, InitialBackoff: 1 * time.Second}
	go retry.Forever(retryOpts, func() error {
		cmd := exec.CommandContext(ctx, s.SSHCmd, flags...)

		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		if ctx.Err() != nil {
			return nil // context was canceled
		}

		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == ConnectionLimitReachedCode {
			level.Info(s.logger).Log("msg", "limit of connections for stack and network reached. exiting")
			os.Exit(1)
		}

		level.Error(s.logger).Log("msg", "ssh client exited. restarting")

		// Check keys and cert validity before restart, create new cert if required.
		// This covers the case where a certificate has become invalid since the last start.
		// Do not return here: we want to keep trying to connect in case the PDC API
		// is temporarily unavailable.
		if s.km != nil {
			err := s.km.CreateKeys(ctx)
			if err != nil {
				level.Error(s.logger).Log("msg", "could not check or generate certificate", "error", err)
			}
		}

		return fmt.Errorf("ssh client exited")
	})

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

	logLevelFlag := ""
	if s.cfg.LogLevel > 0 {
		logLevelFlag = "-" + strings.Repeat("v", s.cfg.LogLevel)
	}

	gwURL := s.cfg.URL
	user := fmt.Sprintf("%s@%s", s.cfg.PDC.HostedGrafanaID, gwURL.String())

	// keep ssh_config parameters in a map so they can be oveeridden by the user
	sshOptions := map[string]string{
		"UserKnownHostsFile":  fmt.Sprintf("%s/%s", keyFileDir, KnownHostsFile),
		"CertificateFile":     fmt.Sprintf("%s-cert.pub", s.cfg.KeyFile),
		"ServerAliveInterval": "15",
		"ConnectTimeout":      "1",
	}

	nonOptionFlags := []string{} // for backwards compatibility, on -v particularly
	for _, f := range s.cfg.SSHFlags {
		name, value, err := extractOptionFromFlag(f)
		if err != nil {
			return nil, err
		}
		if name == "" {
			nonOptionFlags = append(nonOptionFlags, f)
			continue
		}
		sshOptions[name] = value
	}

	// make options ordering deterministic
	optionsList := []string{}
	for o := range sshOptions {
		optionsList = append(optionsList, o)
	}
	sort.Strings(optionsList)

	result := []string{
		"-i",
		s.cfg.KeyFile,
		user,
		"-p",
		fmt.Sprintf("%d", s.cfg.Port),
		"-R", fmt.Sprintf("%d", s.cfg.ListenPort),
	}

	for _, o := range optionsList {
		result = append(result, "-o", fmt.Sprintf("%s=%s", o, sshOptions[o]))
	}

	if logLevelFlag != "" {
		result = append(result, logLevelFlag)
	}

	result = append(result, nonOptionFlags...)

	return result, nil
}

func extractOptionFromFlag(flag string) (string, string, error) {
	parts := strings.SplitN(flag, " ", 2)
	if parts[0] != "-o" {
		return "", "", nil
	}

	oParts := strings.Split(parts[1], "=")
	if len(oParts) != 2 {
		return "", "", errors.New("invalid ssh option format, expecting '-o Name=string'")
	}
	return oParts[0], oParts[1], nil
}
