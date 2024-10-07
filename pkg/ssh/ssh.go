package ssh

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/retry"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// The exit code sent by the pdc server when the connection limit is reached.
	ConnectionLimitReachedCode  = 254
	ConnectionAlreadyExistsCode = 253
)

// Config represents all configurable properties of the ssh package.
type Config struct {
	Args []string // deprecated

	KeyFile           string
	SSHFlags          []string // Additional flags to be passed to ssh(1). e.g. --ssh-flag="-vvv" --ssh-flag="-L 80:localhost:80"
	Port              int
	LogLevel          string
	PDC               pdc.Config
	LegacyMode        bool
	SkipSSHValidation bool
	// ForceKeyFileOverwrite forces a new ssh key pair to be generated.
	ForceKeyFileOverwrite bool
	// CertExpiryWindow is the time before the certificate expires to renew it.
	CertExpiryWindow time.Duration
	// CertCheckCertExpiryPeriod is how often to check that the current certificate
	// is valid and regenerate it if necessary.
	CertCheckCertExpiryPeriod time.Duration
	URL                       *url.URL
	// MetricsAddr is the port to expose metrics on
	MetricsAddr string

	// Used for local development.
	// DevPort is the port number for the PDC gateway
	DevPort int
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
		PDC:      pdc.Config{},
		LogLevel: "info",
		KeyFile:  path.Join(root, ".ssh/grafana_pdc"),
	}
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	def := DefaultConfig()

	cfg.SSHFlags = []string{}
	f.StringVar(&cfg.KeyFile, "ssh-key-file", def.KeyFile, "The path to the SSH key file.")
	f.BoolVar(&cfg.SkipSSHValidation, "skip-ssh-validation", false, "Ignore openssh minimum version constraints.")
	f.Func("ssh-flag", "Additional flags to be passed to ssh. Can be set more than once.", cfg.addSSHFlag)
	f.BoolVar(&cfg.ForceKeyFileOverwrite, "force-key-file-overwrite", false, "Force a new ssh key pair to be generated")
	f.DurationVar(&cfg.CertExpiryWindow, "cert-expiry-window", 5*time.Minute, "The time before the certificate expires to renew it.")
	f.DurationVar(&cfg.CertCheckCertExpiryPeriod, "cert-check-expiry-period", 1*time.Minute, "How often to check certificate validity. 0 means it is only checked at start")
	f.StringVar(&cfg.MetricsAddr, "metrics-addr", ":8090", "HTTP server address to expose metrics on")

	f.IntVar(&cfg.DevPort, "dev-ssh-port", 2244, "[DEVELOPMENT ONLY] The port to use for agent connections to the PDC SSH gateway")

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
	cfg     *Config
	SSHCmd  string // SSH command to run, defaults to "ssh". Require for testing.
	logger  log.Logger
	km      *KeyManager
	metrics *promMetrics
}

// NewClient returns a new SSH client in an idle state
func NewClient(cfg *Config, logger log.Logger, km *KeyManager) *Client {
	client := &Client{
		cfg:     cfg,
		SSHCmd:  "ssh",
		logger:  logger,
		km:      km,
		metrics: newPromMetrics(),
	}

	client.BasicService = services.NewIdleService(client.starting, client.stopping)
	return client
}

func (s *Client) Collect(ch chan<- prometheus.Metric) {
	s.metrics.sshRestartsCount.Collect(ch)
}

func (s *Client) Describe(ch chan<- *prometheus.Desc) {
	s.metrics.sshRestartsCount.Describe(ch)
}

func (s *Client) starting(ctx context.Context) error {
	level.Info(s.logger).Log("msg", "starting ssh client")

	if !s.cfg.SkipSSHValidation {
		if err := validateSSHVersion(ctx, s.logger, s.SSHCmd); err != nil {
			return fmt.Errorf("invalid SSH version: %w", err)
		}
	}

	// check keys and cert validity before start, create new cert if required
	// This will exit if it fails, rather than endlessly retrying to sign keys.
	if s.km != nil {
		err := s.km.Start(ctx)
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
		loggerWriter := newLoggerWriterAdapter(s.logger, s.cfg.LogLevel)
		cmd.Stdout = loggerWriter
		cmd.Stderr = loggerWriter
		_ = cmd.Run()
		if ctx.Err() != nil {
			return nil // context was canceled
		}

		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == ConnectionAlreadyExistsCode {
			level.Debug(s.logger).Log("msg", "server already had a connection for this tunnelID. trying a different server")
			return retry.ResetBackoffError{}
		}

		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == ConnectionLimitReachedCode {
			level.Info(s.logger).Log("msg", "limit of connections for stack and network reached. exiting")
			os.Exit(1)
		}

		exitCode := cmd.ProcessState.ExitCode()
		level.Info(s.logger).Log("msg", "ssh client exited. restarting", "exitCode", exitCode)
		s.metrics.sshRestartsCount.WithLabelValues(fmt.Sprintf("%d", exitCode)).Inc()

		// Check keys and cert validity before restart, create new cert if required.
		// This covers the case where a certificate has become invalid since the last start.
		// Do not return here: we want to keep trying to connect in case the PDC API
		// is temporarily unavailable.
		//
		// They keymanager has logic to perform a background key refresh, but this
		// logic should stay in place in case that is disabled.
		if s.km != nil {
			err := s.km.CreateKeys(ctx, false)
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

	gwURL := s.cfg.URL
	user := fmt.Sprintf("%s@%s", s.cfg.PDC.HostedGrafanaID, gwURL.String())

	// keep ssh_config parameters in a map so they can be overidden by the user
	sshOptions := map[string]string{
		"UserKnownHostsFile":  fmt.Sprintf("%s/%s", keyFileDir, KnownHostsFile),
		"CertificateFile":     fmt.Sprintf("%s-cert.pub", s.cfg.KeyFile),
		"ServerAliveInterval": "15",
		"ConnectTimeout":      "1",
		"TCPKeepAlive":        "no",
	}

	nonOptionFlags := []string{} // for backwards compatibility
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
		"-R", "0",
	}

	for _, o := range optionsList {
		result = append(result, "-o", fmt.Sprintf("%s=%s", o, sshOptions[o]))
	}

	result = append(result, nonOptionFlags...)

	// Always pass -vvv to ssh to get verbose output, which is needed to create metrics from logs.
	result = append(result, "-vvv")

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

// Wraps a logger, implements io.Writer and writes to the logger.
type loggerWriterAdapter struct {
	logger log.Logger
	level  string
}

func newLoggerWriterAdapter(logger log.Logger, level string) loggerWriterAdapter {
	return loggerWriterAdapter{
		logger: logger,
		level:  level,
	}
}

// Implements io.Writer.
func (adapter loggerWriterAdapter) Write(p []byte) (n int, err error) {
	// The ssh command output is separated by \r\n and the logger escapes strings.
	// By default, the logger output would look like this: msg="debug: some message\r\ndebug2: some message\r\n".
	// We split the messages on \r\n and log each of them at a time to make the output look like this:
	// msg="debug: some message"
	// msg="debug2: some message"
	for _, msg := range bytes.Split(p, []byte{'\r', '\n'}) {
		if len(msg) == 0 {
			continue
		}

		// Do not log debug messages if the log level is not debug.
		if adapter.level != "debug" && strings.HasPrefix(string(msg), "debug") {
			continue
		}

		if err := level.Info(adapter.logger).Log("msg", msg); err != nil {
			return 0, fmt.Errorf("writing log statement")
		}
	}

	return len(p), nil
}

// openssh must be running 9.2 or above
// checks version in format OpenSSH_{MAJOR}.{MINOR}
func validateSSHVersion(ctx context.Context, logger log.Logger, sshCmd string) error {
	out, err := exec.CommandContext(ctx, sshCmd, "-V").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run ssh -V command: %w", err)
	}

	version := string(out)
	major, minor, err := ParseSSHVersion(version)
	if err != nil {
		level.Warn(logger).Log("msg", "unable to retrieve SSH version for validation", "err", err)
		return nil
	}

	return RequireSSHVersionAbove9_2(major, minor)
}

var sshVersionRegexp = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

func ParseSSHVersion(version string) (int, int, error) {
	matches := sshVersionRegexp.FindStringSubmatch(version)
	if len(matches) < 3 {
		return 0, 0, fmt.Errorf("failed to parse OpenSSH version")
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse OpenSSH major version")
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse OpenSSH minor version")
	}

	return major, minor, nil
}

func RequireSSHVersionAbove9_2(major, minor int) error {
	if major > 9 || (major == 9 && minor >= 2) {
		return nil
	}
	return fmt.Errorf("OpenSSH version must be greater or equal to 9.2, current version: %d.%d", major, minor)
}
