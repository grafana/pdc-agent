package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/pdc-agent/pkg/retry"
	socks5 "github.com/things-go/go-socks5"
	gossh "golang.org/x/crypto/ssh"
)

const (
	goKeepAliveInterval = 15 * time.Second
	goConnectTimeout    = 1 * time.Second
	goRestartExitCode   = "255"
)

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type goSSHConn interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
	Close() error
}

type goConnection struct {
	id       int
	conn     goSSHConn
	listener io.Closer
}

type goRuntimeState struct {
	mu          sync.Mutex
	inflight    int
	draining    bool
	connections map[int]goConnection
}

func newGoRuntimeState() *goRuntimeState {
	return &goRuntimeState{
		connections: make(map[int]goConnection),
	}
}

func (s *goRuntimeState) incInflight() {
	s.mu.Lock()
	s.inflight++
	s.mu.Unlock()
}

func (s *goRuntimeState) decInflight() {
	s.mu.Lock()
	if s.inflight > 0 {
		s.inflight--
	}
	s.mu.Unlock()
}

func (s *goRuntimeState) waitForZero(ctx context.Context) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		s.mu.Lock()
		inflight := s.inflight
		s.mu.Unlock()

		if inflight == 0 {
			return true
		}

		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func (s *goRuntimeState) setConnection(id int, conn goConnection) {
	s.mu.Lock()
	s.connections[id] = conn
	s.mu.Unlock()
}

func (s *goRuntimeState) deleteConnection(id int) {
	s.mu.Lock()
	delete(s.connections, id)
	s.mu.Unlock()
}

func (s *goRuntimeState) setDraining(draining bool) {
	s.mu.Lock()
	s.draining = draining
	s.mu.Unlock()
}

func (s *goRuntimeState) isDraining() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.draining
}

func (s *goRuntimeState) snapshotConnections() []goConnection {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]goConnection, 0, len(s.connections))
	for _, conn := range s.connections {
		out = append(out, conn)
	}
	return out
}

func (s *Client) runGoSSHClient(ctx context.Context) {
	retryOpts := retry.Opts{MaxBackoff: 16 * time.Second, InitialBackoff: 1 * time.Second}
	for c := 0; c < s.cfg.Connections; c++ {
		connectionID := c + 1
		go retry.Forever(retryOpts, func() error {
			return s.runSingleGoConnection(ctx, connectionID)
		})
	}
}

func (s *Client) runSingleGoConnection(ctx context.Context, connectionID int) (err error) {
	startTime := time.Now()
	connectionLogger := log.With(s.logger, "connection", connectionID)

	defer func() {
		level.Info(connectionLogger).Log("msg", "connection finished, will try to reconnect", "error", err)
	}()

	sshClient, listener, err := s.establishGoSSHConnection(ctx, connectionID, startTime, connectionLogger)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		s.metrics.sshRestartsCount.WithLabelValues(strconv.Itoa(connectionID), goRestartExitCode).Inc()
		return err
	}
	defer sshClient.Close()
	defer listener.Close()

	s.metrics.sshConnectionsCount.Inc()
	defer s.metrics.sshConnectionsCount.Dec()

	s.goState.setConnection(connectionID, goConnection{
		id:       connectionID,
		conn:     sshClient,
		listener: listener,
	})
	defer s.goState.deleteConnection(connectionID)

	srv := socks5.NewServer(
		socks5.WithLogger(&socks5LoggerAdapter{logger: connectionLogger}),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
		socks5.WithDialAndRequest(s.goSocksDialerProvider(connectionID)),
	)

	err = srv.Serve(listener)
	if ctx.Err() != nil || s.goState.isDraining() || errors.Is(err, net.ErrClosed) || isUseOfClosedConnErr(err) {
		return nil
	}
	level.Info(connectionLogger).Log("msg", "go ssh client exited. restarting", "error", err)
	s.metrics.sshRestartsCount.WithLabelValues(strconv.Itoa(connectionID), goRestartExitCode).Inc()
	return err
}

func (s *Client) establishGoSSHConnection(ctx context.Context, connectionID int, startTime time.Time, logger log.Logger) (*gossh.Client, *channelListener, error) {
	config, err := s.createGoSSHClientConfig()
	if err != nil {
		return nil, nil, err
	}

	addr := gatewayDialAddress(s.cfg.URL, s.cfg.Port)
	netConn, err := (&net.Dialer{
		Timeout:   goConnectTimeout,
		KeepAlive: -1, // disable TCP keepalive to match OpenSSH default in this agent
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dialing gateway: %w", err)
	}

	sshConn, chans, reqs, err := gossh.NewClientConn(netConn, addr, config)
	if err != nil {
		_ = netConn.Close()
		return nil, nil, fmt.Errorf("establishing ssh client conn: %w", err)
	}

	client := gossh.NewClient(sshConn, chans, reqs)

	ok, response, err := client.SendRequest("tcpip-forward", true, gossh.Marshal(&remoteForwardRequest{
		BindAddr: "",
		BindPort: 0,
	}))
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("requesting tcpip-forward: %w", err)
	}
	if !ok {
		_ = client.Close()
		return nil, nil, errors.New("tcpip-forward request rejected")
	}

	port := uint32(0)
	if len(response) > 0 {
		var forwardResp remoteForwardSuccess
		if err := gossh.Unmarshal(response, &forwardResp); err != nil {
			_ = client.Close()
			return nil, nil, fmt.Errorf("parsing tcpip-forward response: %w", err)
		}
		port = forwardResp.BindPort
	}

	connectionLabel := strconv.Itoa(connectionID)
	s.metrics.timeToConnect.WithLabelValues(connectionLabel).Observe(time.Since(startTime).Seconds())
	level.Debug(logger).Log("msg", "go ssh port forwarding established", "port", port)

	go s.runGoKeepalive(ctx, client, logger)

	listener := NewChannelListener(
		client,
		client.HandleChannelOpen("forwarded-tcpip"),
		func() {
			s.goState.incInflight()
			s.metrics.openChannelsCount.WithLabelValues(connectionLabel).Inc()
		},
		func() {
			s.goState.decInflight()
			s.metrics.openChannelsCount.WithLabelValues(connectionLabel).Dec()
		},
	)

	return client, listener, nil
}

func (s *Client) runGoKeepalive(ctx context.Context, conn *gossh.Client, logger log.Logger) {
	ticker := time.NewTicker(goKeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				level.Debug(logger).Log("msg", "keepalive request failed", "error", err)
				_ = conn.Close()
				return
			}
		}
	}
}

func (s *Client) stopGoSSHClient() {
	s.goState.setDraining(true)

	connections := s.goState.snapshotConnections()
	for _, conn := range connections {
		sendCancelTCPIPForward(conn.conn)
		if conn.listener != nil {
			_ = conn.listener.Close()
		}
	}

	shutdownTimeout := s.cfg.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = 15 * time.Second
	}
	drainCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if !s.goState.waitForZero(drainCtx) {
		level.Warn(s.logger).Log("msg", "go ssh client shutdown timeout reached before all in-flight requests drained", "timeout", shutdownTimeout)
	}

	for _, conn := range connections {
		_ = conn.conn.Close()
	}
}

func (s *Client) goSocksDialerProvider(connectionID int) func(ctx context.Context, network string, addr string, _ *socks5.Request) (net.Conn, error) {
	return func(ctx context.Context, network string, addr string, _ *socks5.Request) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)

		status := "success"
		if err != nil {
			status = "failure"
		}
		s.metrics.tcpConnectionsCount.WithLabelValues(strconv.Itoa(connectionID), addr, status).Add(1)

		return conn, err
	}
}

func (s *Client) createGoSSHClientConfig() (*gossh.ClientConfig, error) {
	privateKey, err := os.ReadFile(s.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	signer, err := gossh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	certBytes, err := os.ReadFile(s.cfg.KeyFile + "-cert.pub")
	if err != nil {
		return nil, fmt.Errorf("reading cert file: %w", err)
	}
	pk, _, _, _, err := gossh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing cert file: %w", err)
	}
	cert, ok := pk.(*gossh.Certificate)
	if !ok {
		return nil, errors.New("parsed cert file is not an SSH certificate")
	}

	certSigner, err := gossh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("building cert signer: %w", err)
	}

	knownHostsBytes, err := os.ReadFile(path.Join(s.cfg.KeyFileDir(), KnownHostsFile))
	if err != nil {
		return nil, fmt.Errorf("reading known_hosts: %w", err)
	}
	authorities, err := parseKnownHostsAuthorities(knownHostsBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing known_hosts authorities: %w", err)
	}
	if len(authorities) == 0 {
		return nil, errors.New("no authorities found in known_hosts")
	}

	certChecker := &gossh.CertChecker{
		IsHostAuthority: func(remote gossh.PublicKey, _ string) bool {
			for _, authority := range authorities {
				if bytes.Equal(authority.Marshal(), remote.Marshal()) {
					return true
				}
			}
			return false
		},
	}

	return &gossh.ClientConfig{
		User:            s.cfg.PDC.HostedGrafanaID,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(certSigner)},
		HostKeyCallback: certChecker.CheckHostKey,
		Timeout:         goConnectTimeout,
	}, nil
}

func parseKnownHostsAuthorities(contents []byte) ([]gossh.PublicKey, error) {
	rest := bytes.TrimSpace(contents)
	keys := make([]gossh.PublicKey, 0, 2)

	for len(rest) > 0 {
		_, _, key, _, next, err := gossh.ParseKnownHosts(rest)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
		rest = bytes.TrimSpace(next)
	}

	return keys, nil
}

func sendCancelTCPIPForward(conn goSSHConn) {
	if conn == nil {
		return
	}
	_, _, _ = conn.SendRequest("cancel-tcpip-forward", false, gossh.Marshal(&remoteForwardRequest{
		BindAddr: "",
		BindPort: 0,
	}))
}

func gatewayDialAddress(u *url.URL, port int) string {
	host := ""
	if u != nil {
		host = u.Host
		if host == "" {
			host = u.String()
		}
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func isUseOfClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

type socks5LoggerAdapter struct {
	logger log.Logger
}

func (a *socks5LoggerAdapter) Errorf(format string, args ...any) {
	level.Error(a.logger).Log("msg", fmt.Sprintf(format, args...))
}
