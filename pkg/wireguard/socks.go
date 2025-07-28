package wireguard

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type SOCKSServer struct {
	config   Config
	logger   log.Logger
	tnet     *netstack.Net
	listener net.Listener
	server   *socks5.Server
	
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewSOCKSServer(config Config, logger log.Logger, tnet *netstack.Net) *SOCKSServer {
	ctx, cancel := context.WithCancel(context.Background())
	
	socksServer := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{&socks5.NoAuthAuthenticator{}}),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			level.Debug(logger).Log("msg", "dialing target", "network", network, "addr", addr)
			return net.Dial(network, addr)
		}),
	)
	
	return &SOCKSServer{
		config: config,
		logger: logger,
		tnet:   tnet,
		server: socksServer,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *SOCKSServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.running {
		return fmt.Errorf("SOCKS server already running")
	}
	
	listener, err := s.tnet.ListenTCP(&net.TCPAddr{Port: 1080})
	if err != nil {
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}
	
	s.listener = listener
	s.running = true
	
	level.Info(s.logger).Log("msg", "SOCKS5 server started", "addr", s.config.SOCKSAddr)
	
	go s.serveLoop()
	
	return nil
}

func (s *SOCKSServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.running {
		return
	}
	
	s.cancel()
	
	if s.listener != nil {
		s.listener.Close()
	}
	
	s.running = false
	level.Info(s.logger).Log("msg", "SOCKS5 server stopped")
}

func (s *SOCKSServer) serveLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		
		conn, err := s.listener.Accept()
		if err != nil {
			if s.isRunning() {
				level.Error(s.logger).Log("msg", "failed to accept connection", "err", err)
			}
			continue
		}
		
		go s.handleConnection(conn)
	}
}

func (s *SOCKSServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	logger := log.With(s.logger, "client", conn.RemoteAddr())
	level.Debug(logger).Log("msg", "handling SOCKS5 connection")
	
	if err := s.server.ServeConn(conn); err != nil {
		level.Error(logger).Log("msg", "SOCKS5 connection failed", "err", err)
	}
}

func (s *SOCKSServer) isRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}