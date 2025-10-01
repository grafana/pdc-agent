package ssh

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
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
	"github.com/things-go/go-socks5/statute"
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

// RemoteForwardChannelData is the extra data sent with forwarded-tcpip channel requests.
// This struct can be extended to include custom metadata when both client and server
// are under our control (e.g., trace context, agent identity, etc.)
type RemoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
	// Future fields for custom protocol extensions:
	// TraceParent string // W3C traceparent for distributed tracing
	// AgentID     string // Unique agent identity
	// Priority    uint8  // Request priority for QoS
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

	// WriteKeysForDebug optionally writes in-memory keys to disk for debugging.
	// Only used when UseGoSSHClient is true.
	WriteKeysForDebug bool
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
	f.BoolVar(&cfg.WriteKeysForDebug, "write-keys-for-debug", false, "Write in-memory keys to disk for debugging (only used with --use-go-client)")

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
	cfg          *Config
	SSHCmd       string // SSH command to run, defaults to "ssh". Require for testing.
	logger       log.Logger
	km           *KeyManager
	metrics      *promMetrics
	socks5Server *socks5.Server // Reused SOCKS5 server for all connections
}

// NewClient returns a new SSH client in an idle state
func NewClient(cfg *Config, logger log.Logger, km *KeyManager) *Client {
	var socks5Server *socks5.Server

	// Only create SOCKS5 server if using Go SSH client
	if cfg.UseGoSSHClient {
		socks5Server = socks5.NewServer(
			socks5.WithLogger(&socks5LoggerAdapter{logger: logger}),
			socks5.WithRule(&connectOnlyRule{}),
		)
	}

	client := &Client{
		cfg:          cfg,
		SSHCmd:       "ssh",
		logger:       logger,
		km:           km,
		metrics:      newPromMetrics(),
		socks5Server: socks5Server,
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
	s.metrics.socks5ConnectionsActive.Collect(ch)
	s.metrics.socks5ConnectionsTotal.Collect(ch)
	s.metrics.socks5ConnectionDuration.Collect(ch)
	s.metrics.socks5ConnectionsByStatus.Collect(ch)
}

func (s *Client) Describe(ch chan<- *prometheus.Desc) {
	s.metrics.sshRestartsCount.Describe(ch)
	s.metrics.openChannelsCount.Describe(ch)
	s.metrics.tcpConnectionsCount.Describe(ch)
	s.metrics.timeToConnect.Describe(ch)
	s.metrics.sshConnectionsCount.Describe(ch)
	s.metrics.socks5ConnectionsActive.Describe(ch)
	s.metrics.socks5ConnectionsTotal.Describe(ch)
	s.metrics.socks5ConnectionDuration.Describe(ch)
	s.metrics.socks5ConnectionsByStatus.Describe(ch)
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
		connectionID := c + 1
		go func(connID int) {
			// Cache key material outside the retry loop to reuse across retries
			var keyMaterial *InMemoryKeyMaterial

			retry.Forever(retryOpts, func() error {
				return s.runSingleConnection(ctx, connID, &keyMaterial)
			})
		}(connectionID)
	}
}

// runSingleConnection handles a single SSH connection attempt
func (s *Client) runSingleConnection(ctx context.Context, connID int, keyMaterial **InMemoryKeyMaterial) error {
	startTime := time.Now()
	connectionLogger := log.With(s.logger, "connection", connID)

	// Define a default error to return if the connection fails. We may replace it
	// with a resetBackoffError if the connection succeeds before failing.
	err := errors.New("")

	defer func() {
		level.Info(connectionLogger).Log("msg", "connection finished, will try to reconnect", "error", err)
	}()

	// Get or refresh key material
	*keyMaterial, err = s.getOrRefreshKeyMaterial(ctx, *keyMaterial, connectionLogger)
	if err != nil {
		level.Error(connectionLogger).Log("msg", "failed to get key material", "error", err)
		return err
	}

	// Establish SSH connection with reverse port forwarding
	conn, port, err := s.establishSSHConnection(ctx, *keyMaterial, connectionLogger)
	if err != nil {
		level.Error(connectionLogger).Log("msg", "failed to establish connection", "error", err)
		return err
	}
	defer conn.Close()

	s.metrics.sshConnectionsCount.Inc()
	defer s.metrics.sshConnectionsCount.Dec()

	s.metrics.timeToConnect.WithLabelValues(fmt.Sprintf("%d", connID)).Observe(time.Since(startTime).Seconds())

	// Connection established successfully - reset backoff on next retry
	err = retry.ResetBackoffError{}

	// Start SSH keepalive goroutine (equivalent to ServerAliveInterval=15)
	keepaliveCtx, keepaliveCancel := context.WithCancel(ctx)
	defer keepaliveCancel()
	go s.runKeepalive(keepaliveCtx, conn, connectionLogger)

	// Handle incoming forwarded-tcpip channel requests from the server
	channels := conn.HandleChannelOpen("forwarded-tcpip")
	if channels == nil {
		level.Error(connectionLogger).Log("msg", "failed to get channel handler")
		return fmt.Errorf("HandleChannelOpen returned nil")
	}

	level.Debug(connectionLogger).Log("msg", "port forwarding established", "port", port)

	// Handle channel loop - this blocks until connection closes
	return s.handleChannelLoop(ctx, conn, channels, err, connectionLogger)
}

// getOrRefreshKeyMaterial returns existing key material or generates new keys if needed
func (s *Client) getOrRefreshKeyMaterial(ctx context.Context, current *InMemoryKeyMaterial, logger log.Logger) (*InMemoryKeyMaterial, error) {
	// Generate new keys on first attempt or if certificate is about to expire
	if current == nil || IsCertExpiringSoon(current.Certificate, s.cfg.CertExpiryWindow) {
		level.Info(logger).Log("msg", "generating or refreshing in-memory keys and certificate")
		keyMaterial, err := s.km.CreateInMemoryKeys(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create in-memory keys: %w", err)
		}
		return keyMaterial, nil
	}
	level.Debug(logger).Log("msg", "reusing existing in-memory keys and certificate")
	return current, nil
}

// establishSSHConnection creates and establishes an SSH connection with reverse port forwarding
func (s *Client) establishSSHConnection(ctx context.Context, keyMaterial *InMemoryKeyMaterial, logger log.Logger) (*ssh.Client, uint32, error) {
	// Create SSH client configuration from in-memory keys
	config, err := s.createSSHClientConfig(keyMaterial)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create SSH client config: %w", err)
	}

	// Build connection address
	// If URL has no scheme, URL.Host is empty and the hostname is in URL.Path
	hostname := s.cfg.URL.Host
	if hostname == "" {
		hostname = s.cfg.URL.String()
	}
	addr := hostname + ":" + strconv.Itoa(s.cfg.Port)
	level.Debug(logger).Log("msg", "dialing SSH server", "addr", addr)

	// Use net.DialContext for context-aware cancellation
	netConn, err := (&net.Dialer{
		Timeout:   config.Timeout,
		KeepAlive: -1, // Disable TCP keepalive (equivalent to TCPKeepAlive=no)
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to dial SSH server: %w", err)
	}
	defer func() {
		if err != nil {
			netConn.Close()
		}
	}()

	// Establish SSH connection over the net.Conn
	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, config)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to establish SSH connection: %w", err)
	}
	conn := ssh.NewClient(sshConn, chans, reqs)

	level.Info(logger).Log("msg", "SSH connection established")

	// Send tcpip-forward request (equivalent to -R 0)
	ok, response, err := conn.SendRequest("tcpip-forward", true, ssh.Marshal(&RemoteForwardRequest{
		BindAddr: "",
		BindPort: 0,
	}))
	if err != nil || !ok {
		conn.Close()
		return nil, 0, fmt.Errorf("tcpip-forward request failed: %w", err)
	}

	var fwdSuccess RemoteForwardSuccess
	if err := ssh.Unmarshal(response, &fwdSuccess); err != nil {
		conn.Close()
		return nil, 0, fmt.Errorf("failed to parse tcpip-forward response: %w", err)
	}

	level.Info(logger).Log("msg", "reverse port forwarding established", "port", fwdSuccess.BindPort)
	return conn, fwdSuccess.BindPort, nil
}

// runKeepalive starts a goroutine that sends SSH keepalive requests periodically
func (s *Client) runKeepalive(ctx context.Context, conn *ssh.Client, logger log.Logger) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send keepalive request with want_reply=true
			_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				level.Debug(logger).Log("msg", "keepalive failed", "error", err)
				// Connection is likely dead, close it to trigger reconnect
				conn.Close()
				return
			}
			level.Debug(logger).Log("msg", "keepalive sent successfully")
		}
	}
}

// handleChannelLoop processes incoming forwarded-tcpip channels until the connection closes
func (s *Client) handleChannelLoop(ctx context.Context, conn *ssh.Client, channels <-chan ssh.NewChannel, successErr error, logger log.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case newChannel, ok := <-channels:
			if !ok {
				level.Info(logger).Log("msg", "channel closed")
				// Check if connection was closed due to limit reached or duplicate connection
				waitErr := conn.Wait()
				if IsConnectionLimitError(waitErr) {
					level.Info(logger).Log("msg", "limit of connections for stack and network reached, reach out to grafana support to increase connection limits. exiting")
					os.Exit(1)
				}
				if IsConnectionAlreadyExistsError(waitErr) {
					level.Debug(logger).Log("msg", "server already had a connection for this tunnelID. trying a different server")
					return retry.ResetBackoffError{}
				}
				// Return the error set earlier (ResetBackoffError if connection was successful)
				return successErr
			}

			go s.handleChannelOpen(newChannel, logger)
		}
	}
}

func (s *Client) createSSHClientConfig(keyMaterial *InMemoryKeyMaterial) (*ssh.ClientConfig, error) {
	// Create signer from in-memory private key
	signer, err := ssh.NewSignerFromKey(keyMaterial.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer from private key: %w", err)
	}

	// Create certificate signer
	certSigner, err := ssh.NewCertSigner(keyMaterial.Certificate, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate signer: %w", err)
	}

	// Parse the CA public keys from known_hosts
	// The known_hosts data contains @cert-authority entries for PDC
	var authorizedKeys []ssh.PublicKey
	knownHostsBytes := keyMaterial.KnownHosts
	for len(knownHostsBytes) > 0 {
		_, _, pubKey, _, rest, err := ssh.ParseKnownHosts(knownHostsBytes)
		if err != nil {
			break
		}
		authorizedKeys = append(authorizedKeys, pubKey)
		knownHostsBytes = rest
	}

	if len(authorizedKeys) == 0 {
		return nil, fmt.Errorf("no certificate authorities found in known hosts data")
	}

	// Create a CertChecker that verifies the server's host certificate is signed by one of our CAs
	certChecker := &ssh.CertChecker{
		IsHostAuthority: func(remote ssh.PublicKey, _ string) bool {
			for _, ca := range authorizedKeys {
				if bytes.Equal(ca.Marshal(), remote.Marshal()) {
					return true
				}
			}
			return false
		},
	}

	hostKeyCallback := certChecker.CheckHostKey

	config := &ssh.ClientConfig{
		User:            s.cfg.PDC.HostedGrafanaID,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         1 * time.Second, // ConnectTimeout from SSH flags
	}

	return config, nil
}

func (s *Client) handleChannelOpen(newChannel ssh.NewChannel, logger log.Logger) {
	// Try to parse channel extra data for logging/tracing metadata
	// If parsing fails, we still accept the channel (lenient parsing)
	var channelData RemoteForwardChannelData
	enrichedLogger := logger

	if err := ssh.Unmarshal(newChannel.ExtraData(), &channelData); err != nil {
		level.Debug(logger).Log("msg", "could not parse channel extra data, accepting anyway", "error", err)
	} else {
		// Successfully parsed - log the destination info
		level.Debug(logger).Log(
			"msg", "accepting forwarded-tcpip channel",
			"dest", fmt.Sprintf("%s:%d", channelData.DestAddr, channelData.DestPort),
			"origin", fmt.Sprintf("%s:%d", channelData.OriginAddr, channelData.OriginPort),
		)

		// TODO: When PDC gateway sends trace context in channelData.TraceParent:
		// if channelData.TraceParent != "" {
		//     traceID, spanID := parseTraceContext(channelData.TraceParent)
		//     if traceID != "" {
		//         enrichedLogger = log.With(logger, "traceID", traceID, "spanID", spanID)
		//     }
		// }
		// TODO: When PDC gateway sends agent identity in channelData.AgentID:
		// if channelData.AgentID != "" {
		//     enrichedLogger = log.With(enrichedLogger, "agentID", channelData.AgentID)
		// }
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		level.Error(enrichedLogger).Log("msg", "failed to accept channel", "error", err)
		return
	}
	defer channel.Close()

	// Discard out-of-band requests
	go ssh.DiscardRequests(requests)

	// Handle the connection with enriched logger
	s.handleForwardedConnection(channel, enrichedLogger)
}

func (s *Client) handleForwardedConnection(channel ssh.Channel, logger log.Logger) {
	defer channel.Close()

	level.Debug(logger).Log("msg", "handling forwarded connection")

	// Track SOCKS5 connection metrics
	start := time.Now()
	s.metrics.socks5ConnectionsActive.Inc()
	s.metrics.socks5ConnectionsTotal.Inc()
	defer func() {
		s.metrics.socks5ConnectionsActive.Dec()
		s.metrics.socks5ConnectionDuration.Observe(time.Since(start).Seconds())
	}()

	// Wrap our channel as a net.Conn
	conn := &channelNetConn{Channel: channel}

	// Reuse the SOCKS5 server instance created in NewClient
	// ServeConn handles a single SOCKS5 connection
	if err := s.socks5Server.ServeConn(conn); err != nil {
		level.Debug(logger).Log("msg", "SOCKS5 connection ended", "error", err)
		s.metrics.socks5ConnectionsByStatus.WithLabelValues("error").Inc()
	} else {
		s.metrics.socks5ConnectionsByStatus.WithLabelValues("success").Inc()
	}
}

// socks5LoggerAdapter adapts go-kit logger to socks5.Logger interface
type socks5LoggerAdapter struct {
	logger log.Logger
}

func (a *socks5LoggerAdapter) Errorf(format string, args ...interface{}) {
	level.Error(a.logger).Log("msg", fmt.Sprintf(format, args...))
}

// connectOnlyRule is a RuleSet that only allows CONNECT commands.
// BIND and ASSOCIATE commands are rejected.
type connectOnlyRule struct{}

func (r *connectOnlyRule) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	return ctx, req.Command == statute.CommandConnect
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

func (c *channelNetConn) SetDeadline(_ time.Time) error {
	// SSH channels don't support deadlines
	return nil
}

func (c *channelNetConn) SetReadDeadline(_ time.Time) error {
	// SSH channels don't support deadlines
	return nil
}

func (c *channelNetConn) SetWriteDeadline(_ time.Time) error {
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

// IsCertExpiringSoon checks if an SSH certificate is expired or about to expire
func IsCertExpiringSoon(cert *ssh.Certificate, expiryWindow time.Duration) bool {
	if cert == nil {
		return true
	}
	now := uint64(time.Now().Unix())
	// Check if expired
	if now > cert.ValidBefore {
		return true
	}
	// Check if within expiry window
	if now > (cert.ValidBefore - uint64(expiryWindow.Seconds())) {
		return true
	}
	// Check if not yet valid
	if now < cert.ValidAfter {
		return true
	}
	return false
}

// IsConnectionLimitError checks if an error indicates the PDC connection limit was reached
func IsConnectionLimitError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Check for connection limit related messages from PDC server
	return strings.Contains(errStr, "connection limit") ||
		strings.Contains(errStr, "limit reached") ||
		strings.Contains(errStr, "too many connections")
}

// IsConnectionAlreadyExistsError checks if an error indicates a duplicate connection
func IsConnectionAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Check for duplicate connection messages from PDC server
	return strings.Contains(errStr, "connection already exists") ||
		strings.Contains(errStr, "duplicate connection") ||
		strings.Contains(errStr, "already connected")
}
