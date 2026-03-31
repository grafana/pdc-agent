package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/dskit/backoff"
	"github.com/things-go/go-socks5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardResponse struct {
	BindPort uint32
}

func (s *Client) validateGoSSH() error {
	if s.cfg.Connections > 1 {
		level.Warn(s.logger).Log("msg", "-use-gossh doesn't respect the -connections flag currently")
	}

	if len(s.cfg.SSHFlags) > 0 {
		level.Warn(s.logger).Log("msg", "The -use-gossh flag ignores most -ssh-flag values.")
		domains, err := MapSSHPermitToSocks(s.cfg.SSHFlags)
		if err != nil {
			return err
		}
		if len(domains) > 0 {
			level.Warn(s.logger).Log("msg", "Please migrate PermitRemoteOpen domains to -permit-domains flag for the -use-gossh flag.")
			s.cfg.PermitDomains = domains
		}
	}
	if _, err := deriveCertSigner(s.cfg.KeyFile, s.logger); err != nil {
		return err
	}

	hostsfile := path.Join(s.cfg.KeyFileDir(), KnownHostsFile)
	if _, err := knownhosts.New(hostsfile); err != nil {
		return err
	}

	return nil
}

func (s *Client) runGoSSH(ctx context.Context) error {
	backoffCtrl := backoff.New(ctx, backoff.Config{
		MinBackoff: 1 * time.Second,
		MaxBackoff: 16 * time.Second,
		MaxRetries: 0, //persist until ctx is cancelled
	})

	for backoffCtrl.Ongoing() {
		certSigner, err := deriveCertSigner(s.cfg.KeyFile, s.logger)

		if err != nil {
			level.Error(s.logger).Log("error making cert signer", err)
			return err
		}

		keyFileArr := strings.Split(s.cfg.KeyFile, "/")
		keyFileDir := strings.Join(keyFileArr[:len(keyFileArr)-1], "/")

		hostsfile := path.Join(keyFileDir, KnownHostsFile)
		hostCB, err := knownhosts.New(hostsfile)
		if err != nil {
			level.Error(s.logger).Log("error making knownhost", err)
			return err
		}

		config := &ssh.ClientConfig{
			User: s.cfg.PDC.HostedGrafanaID,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(certSigner),
			},
			HostKeyCallback: hostCB,
		}

		host := net.JoinHostPort(s.cfg.URL.String(), strconv.Itoa(s.cfg.Port))
		timerStart := time.Now()
		var response remoteForwardResponse

		conn, err := s.dialWithTimeout(ctx, host, config, timerStart)

		if err != nil {
			level.Error(s.logger).Log("error during dialWithTimeout", err)
			if conn != nil {
				_ = conn.Close()
			}
			backoffCtrl.Wait()
			continue
		}

		go doKeepAlives(ctx, s.sshClient.Conn, s.logger)

		chans := s.sshClient.HandleChannelOpen("forwarded-tcpip")
		s.metrics.timeToConnect.WithLabelValues("gossh").Observe(time.Since(timerStart).Seconds())

		ln := NewListenerFromChannel(s.sshClient, chans, s.metrics)

		server := socks5.NewServer(
			socks5.WithDialAndRequest(s.socksDialerRequest),
			socks5.WithRule(&PermitRemoteOpen{
				Domains: s.cfg.PermitDomains,
			}),
		)

		req := remoteForwardRequest{
			BindAddr: "",
			BindPort: 0,
		}

		ok, b, err := s.sshClient.SendRequest("tcpip-forward", true, ssh.Marshal(req))

		if err != nil {
			level.Error(s.logger).Log("error sending tcpip-forward", err)
			s.waitAndClose(backoffCtrl)
			continue
		}

		if !ok {
			level.Error(s.logger).Log("tcpip-forward request rejected.", ok)
			s.waitAndClose(backoffCtrl)
			continue
		}

		err = ssh.Unmarshal(b, &response)

		if err != nil {
			level.Error(s.logger).Log("error decoding response", err)
			s.waitAndClose(backoffCtrl)
			continue
		}

		backoffCtrl.Reset()

		s.forwardPort = &response.BindPort //save for cancel later

		err = server.Serve(ln)

		//exit early if ctx is done
		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			level.Error(s.logger).Log("error serving SOCKS", err)
			s.waitAndClose(backoffCtrl)
			continue
		}

		s.sshClient.Close()
	}

	return nil
}

func deriveCertSigner(keyFile string, logger log.Logger) (ssh.Signer, error) {
	keyfile, err := os.ReadFile(keyFile)
	if err != nil {
		level.Error(logger).Log("error reading keyfile", err)
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(keyfile)
	if err != nil {
		level.Error(logger).Log("error parsing keyfile", err)
		return nil, err
	}

	certFile, err := os.ReadFile(fmt.Sprintf("%s-cert.pub", keyFile))
	if err != nil {
		level.Error(logger).Log("error reading cert", err)
		return nil, err
	}

	authKey, _, _, _, err := ssh.ParseAuthorizedKey(certFile)
	if err != nil {
		level.Error(logger).Log("error parsing authKey", err)
		return nil, err
	}

	cert, ok := authKey.(*ssh.Certificate)

	if !ok {
		return nil, fmt.Errorf("parsed authorized key is %T, want *ssh.Certificate", authKey)
	}

	return ssh.NewCertSigner(cert, signer)
}

// dialWithTimeout does what ssh.Dial does but wires in ConnectionTimeout since ssh.ClientConfig doesn't cover the ssh handshake.
// dialWithTimeout is meant to mimic ConnectTimeout from ssh_config.
func (s *Client) dialWithTimeout(ctx context.Context, host string, config *ssh.ClientConfig, timerStart time.Time) (net.Conn, error) {
	d := net.Dialer{Timeout: s.cfg.ConnectionTimeout, KeepAlive: -1}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("error dialing context: %w", err)
	}

	err = conn.SetDeadline(timerStart.Add(s.cfg.ConnectionTimeout))

	if err != nil {
		return conn, fmt.Errorf("error setting deadline: %w", err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		return conn, fmt.Errorf("error getting client conn: %w", err)
	}

	err = conn.SetDeadline(time.Time{})
	if err != nil {
		return conn, fmt.Errorf("error clearing deadline: %w", err)
	}

	s.sshClient = ssh.NewClient(c, chans, reqs)

	return conn, nil
}

func (s *Client) waitAndClose(backoffCtrl *backoff.Backoff) {
	err := "gossh error"

	if backoffCtrl.ErrCause() != nil {
		err = backoffCtrl.ErrCause().Error()
	}

	s.metrics.sshRestartsCount.WithLabelValues("gossh", err).Inc()
	backoffCtrl.Wait()
	s.sshClient.Close()
}

// socksDialerRequest is needed to fill the tcp_connections_total target label like OpenSSH does.
func (s *Client) socksDialerRequest(ctx context.Context, network string, addr string, req *socks5.Request) (net.Conn, error) {
	var d net.Dialer
	port := "0"
	domainAndPort := ""

	if req.RawDestAddr.Port >= 0 {
		port = strconv.Itoa(req.RawDestAddr.Port)
	}

	if req.RawDestAddr.FQDN != "" {
		domainAndPort = net.JoinHostPort(req.RawDestAddr.FQDN, port)
	} else {
		domainAndPort = net.JoinHostPort(req.RawDestAddr.IP.String(), port)
	}

	conn, err := d.DialContext(ctx, network, addr)

	if err != nil {
		s.metrics.tcpConnectionsCount.WithLabelValues("1", domainAndPort, "failure").Add(1)
		return nil, err
	}
	s.metrics.tcpConnectionsCount.WithLabelValues("1", domainAndPort, "success").Add(1)

	return conn, nil
}
