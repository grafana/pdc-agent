package ssh

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"net"
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
	socks5 "github.com/things-go/go-socks5"
	"golang.org/x/crypto/ssh"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/retry"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// The exit code sent by the pdc server when the connection limit is reached.
	ConnectionLimitReachedCode  = 254
	ConnectionAlreadyExistsCode = 253

	// String returned from PDC when the PDC agent successfully connects
	SuccessfulConnectionResponse = "This is Grafana Private Datasource Connect!"
)

// RemoteForwardRequest is the payload for tcpip-forward requests
type RemoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

// RemoteForwardSuccess is the response from a successful tcpip-forward request
type RemoteForwardSuccess struct {
	BindPort uint32
}

// RemoteForwardChannelData is the extra data sent with forwarded-tcpip channel requests
type RemoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

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
	MetricsAddr  string
	ParseMetrics bool

	// Connections is the number of connections to open
	Connections int

	// Used for local development.
	// DevPort is the port number for the PDC gateway
	DevPort int

	// When enabled, use a go implementation of the SSH client, instead of OpenSSH.
	UseGoSSHClient bool
}

// DefaultConfig returns a Config with some sensible defaults set
func DefaultConfig() *Config {
	root, err := os.UserHomeDir()
	if err != nil {
		// Use relative path (should not happen)
		root = ""
	}
	return &Config{
		Port:         22,
		PDC:          pdc.Config{},
		LogLevel:     "info",
		KeyFile:      path.Join(root, ".ssh/grafana_pdc"),
		ParseMetrics: true,
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
	f.BoolVar(&cfg.ParseMetrics, "parse-metrics", true, "Enabled or disable parsing of metrics from the ssh logs")
	f.IntVar(&cfg.Connections, "connections", 1, "The number of parallel ssh connections to open. Adding more connections will increase total bandwidth to your network. The limit is 50 connections across all your agents")
	f.BoolVar(&cfg.UseGoSSHClient, "use-go-client", false, "Use the Go SSH client instead of the OpenSSH client")

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
	s.metrics.openChannelsCount.Collect(ch)
	s.metrics.tcpConnectionsCount.Collect(ch)
	s.metrics.timeToConnect.Collect(ch)
	s.metrics.sshConnectionsCount.Collect(ch)
}

func (s *Client) Describe(ch chan<- *prometheus.Desc) {
	s.metrics.sshRestartsCount.Describe(ch)
	s.metrics.openChannelsCount.Describe(ch)
	s.metrics.tcpConnectionsCount.Describe(ch)
	s.metrics.timeToConnect.Describe(ch)
	s.metrics.sshConnectionsCount.Describe(ch)
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

	if s.cfg.UseGoSSHClient {
		s.runGoSSHClient(ctx)
	} else {
		s.runOpenSSHClient(ctx, flags)
	}

	return nil
}

func (s *Client) runGoSSHClient(ctx context.Context) {
	retryOpts := retry.Opts{MaxBackoff: 16 * time.Second, InitialBackoff: 1 * time.Second}

	for c := 0; c < s.cfg.Connections; c++ {
		go retry.Forever(retryOpts, func() (err error) {
			startTime := time.Now()
			connectionID := c + 1
			connectionLogger := log.With(s.logger, "connection", connectionID)

			defer func() {
				level.Info(connectionLogger).Log("msg", "connection finished, will try to reconnect", "error", err)
			}()

			// Create SSH client configuration
			config, err := s.createSSHClientConfig()
			if err != nil {
				level.Error(connectionLogger).Log("msg", "failed to create SSH client config", "error", err)
				return err
			}

			// Build connection address
			// If URL has no scheme, URL.Host is empty and the hostname is in URL.Path
			hostname := s.cfg.URL.Host
			if hostname == "" {
				hostname = s.cfg.URL.String()
			}
			addr := hostname + ":" + strconv.Itoa(s.cfg.Port)
			level.Debug(connectionLogger).Log("msg", "dialing SSH server", "addr", addr)
			conn, err := ssh.Dial("tcp", addr, config)
			if err != nil {
				level.Error(connectionLogger).Log("msg", "failed to dial SSH server", "error", err)
				return err
			}
			defer conn.Close()

			s.metrics.sshConnectionsCount.Inc()
			defer s.metrics.sshConnectionsCount.Dec()

			level.Info(connectionLogger).Log("msg", "SSH connection established")

			// Send tcpip-forward request (equivalent to -R 0)
			// This tells the server we want to accept forwarded-tcpip channels
			ok, response, err := conn.SendRequest("tcpip-forward", true, ssh.Marshal(&RemoteForwardRequest{
				BindAddr: "",
				BindPort: 0,
			}))
			if err != nil || !ok {
				level.Error(connectionLogger).Log("msg", "failed to setup reverse port forwarding", "error", err, "ok", ok)
				return fmt.Errorf("tcpip-forward request failed: %w", err)
			}

			var fwdSuccess RemoteForwardSuccess
			if err := ssh.Unmarshal(response, &fwdSuccess); err != nil {
				level.Error(connectionLogger).Log("msg", "failed to parse tcpip-forward response", "error", err)
				return err
			}

			level.Info(connectionLogger).Log("msg", "reverse port forwarding established", "port", fwdSuccess.BindPort)
			s.metrics.timeToConnect.WithLabelValues(fmt.Sprintf("%d", connectionID)).Observe(time.Since(startTime).Seconds())

			// Handle incoming forwarded-tcpip channel requests from the server
			channels := conn.HandleChannelOpen("forwarded-tcpip")
			if channels == nil {
				level.Error(connectionLogger).Log("msg", "failed to get channel handler")
				return fmt.Errorf("HandleChannelOpen returned nil")
			}

			for {
				select {
				case <-ctx.Done():
					return nil
				case newChannel, ok := <-channels:
					if !ok {
						level.Info(connectionLogger).Log("msg", "channel closed")
						return nil
					}

					go s.handleChannelOpen(newChannel, connectionLogger)
				}
			}
		})
	}
}

func (s *Client) createSSHClientConfig() (*ssh.ClientConfig, error) {
	// Read private key
	privateKeyBytes, err := os.ReadFile(s.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Read certificate
	certPath := s.cfg.KeyFile + "-cert.pub"
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("parsed key is not a certificate")
	}

	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate signer: %w", err)
	}

	// Read and parse known hosts for certificate authority verification
	knownHostsPath := path.Join(s.cfg.KeyFileDir(), KnownHostsFile)
	knownHostsBytes, err := os.ReadFile(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read known hosts file: %w", err)
	}

	// Parse the CA public keys from known_hosts
	// The known_hosts file contains @cert-authority entries for PDC
	var authorizedKeys []ssh.PublicKey
	for len(knownHostsBytes) > 0 {
		_, _, pubKey, _, rest, err := ssh.ParseKnownHosts(knownHostsBytes)
		if err != nil {
			break
		}
		authorizedKeys = append(authorizedKeys, pubKey)
		knownHostsBytes = rest
	}

	if len(authorizedKeys) == 0 {
		return nil, fmt.Errorf("no certificate authorities found in known hosts file")
	}

	// Create a CertChecker that verifies the server's host certificate is signed by one of our CAs
	certChecker := &ssh.CertChecker{
		IsHostAuthority: func(remote ssh.PublicKey, addr string) bool {
			for _, ca := range authorizedKeys {
				if bytes.Equal(ca.Marshal(), remote.Marshal()) {
					return true
				}
			}
			return false
		},
	}

	hostKeyCallback := certChecker.CheckHostKey

	user := fmt.Sprintf("%s", s.cfg.PDC.HostedGrafanaID)

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         1 * time.Second, // ConnectTimeout from SSH flags
	}

	return config, nil
}

func (s *Client) handleChannelOpen(newChannel ssh.NewChannel, logger log.Logger) {
	// Parse the channel extra data to get destination info
	var channelData RemoteForwardChannelData
	if err := ssh.Unmarshal(newChannel.ExtraData(), &channelData); err != nil {
		level.Error(logger).Log("msg", "failed to parse channel extra data", "error", err)
		_ = newChannel.Reject(ssh.UnknownChannelType, "failed to parse channel data")
		return
	}

	level.Debug(logger).Log(
		"msg", "accepting forwarded-tcpip channel",
		"dest", fmt.Sprintf("%s:%d", channelData.DestAddr, channelData.DestPort),
		"origin", fmt.Sprintf("%s:%d", channelData.OriginAddr, channelData.OriginPort),
	)

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		level.Error(logger).Log("msg", "failed to accept channel", "error", err)
		return
	}
	defer channel.Close()

	// Discard out-of-band requests
	go ssh.DiscardRequests(requests)

	// Handle the connection
	s.handleForwardedConnection(channel, logger)
}

func (s *Client) handleForwardedConnection(channel ssh.Channel, logger log.Logger) {
	defer channel.Close()

	level.Debug(logger).Log("msg", "handling forwarded connection")

	// The channel carries SOCKS5 protocol data from the gateway.
	// We need to act as a SOCKS5 server: read the request, dial the target, and proxy data.

	// Wrap our channel as a net.Conn
	channelConn := &channelNetConn{Channel: channel}

	// Create a SOCKS5 server to handle this single connection
	// The server will read the SOCKS5 request, dial the destination, and proxy data
	//
	// TODO I think we can write an adapter here instead of using std logger
	stdLogger := stdlog.New(log.NewStdlibAdapter(logger), "", 0)
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(stdLogger)),
		// TODO only allow CONNECT actions here
		// TODO add middleware or handler to add some telemetry
		// TODO (stretch) extract trace info from metadata fields?
	)

	// ServeConn handles a single SOCKS5 connection
	if err := server.ServeConn(channelConn); err != nil {
		level.Debug(logger).Log("msg", "SOCKS5 connection ended", "error", err)
	}
}

// channelNetConn wraps an ssh.Channel to implement net.Conn interface
type channelNetConn struct {
	ssh.Channel
}

func (c *channelNetConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *channelNetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *channelNetConn) SetDeadline(t time.Time) error {
	// SSH channels don't support deadlines
	return nil
}

func (c *channelNetConn) SetReadDeadline(t time.Time) error {
	// SSH channels don't support deadlines
	return nil
}

func (c *channelNetConn) SetWriteDeadline(t time.Time) error {
	// SSH channels don't support deadlines
	return nil
}

func (s *Client) runOpenSSHClient(ctx context.Context, flags []string) {
	retryOpts := retry.Opts{MaxBackoff: 16 * time.Second, InitialBackoff: 1 * time.Second}
	for c := 0; c < s.cfg.Connections; c++ {
		go retry.Forever(retryOpts, func() (err error) {
			startTime := time.Now()
			connectionID := c + 1
			connectionLogger := log.With(s.logger, "connection", connectionID)

			defer func() {
				level.Info(connectionLogger).Log("msg", "connection finished, will try to reconnect", "error", err)
			}()

			cmd := exec.CommandContext(ctx, s.SSHCmd, flags...)

			var mParser *logMetricsParser
			level.Debug(connectionLogger).Log("msg", "parsing metrics from logs", "enabled", s.cfg.ParseMetrics)
			if s.cfg.ParseMetrics {
				mParser = &logMetricsParser{
					m:          s.metrics,
					connStart:  startTime,
					connection: fmt.Sprintf("%d", connectionID),
				}
			}

			// define a default error to return if the command fails. We may replace it
			// with a resetBackoffError if we do not want the retry mechanism to pause
			// before retrying.
			err = errors.New("")

			cb := func() {
				err = retry.ResetBackoffError{}
			}

			loggerWriter := NewLoggerWriterAdapter(connectionLogger, s.cfg.LogLevel, mParser, cb)
			cmd.Stdout = loggerWriter
			cmd.Stderr = loggerWriter
			s.metrics.sshConnectionsCount.Inc()
			err = cmd.Run()
			s.metrics.sshConnectionsCount.Dec()
			if ctx.Err() != nil {
				return nil // context was canceled
			}

			if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == ConnectionAlreadyExistsCode {
				level.Debug(connectionLogger).Log("msg", "server already had a connection for this tunnelID. trying a different server")
				return retry.ResetBackoffError{}
			}

			if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == ConnectionLimitReachedCode {
				level.Info(connectionLogger).Log("msg", "limit of connections for stack and network reached, reach out to grafana support to increase connection limits. exiting")
				os.Exit(1)
			}

			exitCode := cmd.ProcessState.ExitCode()
			level.Info(connectionLogger).Log("msg", "ssh client exited. restarting", "exitCode", exitCode, "resetBackoff", errors.Is(err, retry.ResetBackoffError{}))
			s.metrics.sshRestartsCount.WithLabelValues(fmt.Sprintf("%d", connectionID), fmt.Sprintf("%d", exitCode)).Inc()

			// Check keys and cert validity before restart, create new cert if required.
			// This covers the case where a certificate has become invalid since the last start.
			// Do not return here: we want to keep trying to connect in case the PDC API
			// is temporarily unavailable.
			//
			// They keymanager has logic to perform a background key refresh, but this
			// logic should stay in place in case that is disabled.
			if s.km != nil {
				kerr := s.km.CreateKeys(ctx, false)
				if kerr != nil {
					level.Error(connectionLogger).Log("msg", "could not check or generate certificate", "error", kerr)
				}
			}

			return err
		})
	}
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
// If successfulConnectionCallback is not nil, it will be called when the adapter
// sees the SuccessfulConnectionResponse from the server.
type LoggerWriterAdapter struct {
	logger                       log.Logger
	level                        string
	parser                       *logMetricsParser
	successfulConnectionCallback func()
	connected                    bool
}

func NewLoggerWriterAdapter(logger log.Logger, level string, parser *logMetricsParser, connCB func()) LoggerWriterAdapter {

	return LoggerWriterAdapter{
		logger:                       logger,
		level:                        level,
		parser:                       parser,
		successfulConnectionCallback: connCB,
	}
}

// Implements io.Writer.
func (adapter LoggerWriterAdapter) Write(p []byte) (n int, err error) {
	// The ssh command output is separated by \r\n and the logger escapes strings.
	// By default, the logger output would look like this: msg="debug: some message\r\ndebug2: some message\r\n".
	// We split the messages on \r\n and log each of them at a time to make the output look like this:
	// msg="debug: some message"
	// msg="debug2: some message"
	for _, msg := range bytes.Split(p, []byte{'\r', '\n'}) {
		if len(msg) == 0 {
			continue
		}

		// if parsing is enabled, create metrics by parsing the log messages
		if adapter.parser != nil {
			adapter.parser.parseLogMetrics(msg)
		}

		msgStr := string(msg)

		// If configured with a callback, call it at most once upon a successful connection.
		// The bool check is first because it is the cheapest
		if !adapter.connected && adapter.successfulConnectionCallback != nil && strings.Contains(msgStr, SuccessfulConnectionResponse) {
			adapter.connected = true
			adapter.successfulConnectionCallback()
		}

		// Do not log debug messages if the log level is not debug.
		if adapter.level != "debug" && strings.HasPrefix(msgStr, "debug") {
			continue
		}

		if err := level.Info(adapter.logger).Log("msg", msgStr); err != nil {
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
