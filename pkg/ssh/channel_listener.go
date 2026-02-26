package ssh

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// NewChannelListener creates a net.Listener backed by forwarded-tcpip SSH channels.
func NewChannelListener(parent gossh.Conn, nc <-chan gossh.NewChannel, onAccept, onClose func()) *channelListener {
	return &channelListener{
		parent:   parent,
		nc:       nc,
		done:     make(chan struct{}),
		onAccept: onAccept,
		onClose:  onClose,
	}
}

type channelListener struct {
	parent gossh.Conn
	nc     <-chan gossh.NewChannel

	done chan struct{}
	once sync.Once

	mu         sync.RWMutex
	chanClosed bool

	onAccept func()
	onClose  func()
}

func (l *channelListener) ok() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return !l.chanClosed && l.parent != nil
}

func (l *channelListener) Accept() (net.Conn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}

	var newChannel gossh.NewChannel
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case ch, ok := <-l.nc:
		if !ok || ch == nil {
			l.mu.Lock()
			l.chanClosed = true
			l.mu.Unlock()
			return nil, errors.New("ssh.NewChannel channel closed")
		}
		newChannel = ch
	}

	channel, _, err := newChannel.Accept()
	if err != nil {
		return nil, err
	}

	if l.onAccept != nil {
		l.onAccept()
	}

	return &trackedConn{
		Conn:    ToNetConn(l.parent, channel, false),
		onClose: l.onClose,
	}, nil
}

func (l *channelListener) Addr() net.Addr {
	return l.parent.LocalAddr()
}

func (l *channelListener) Close() error {
	l.once.Do(func() {
		close(l.done)
	})
	return nil
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

// ToNetConn converts an SSH connection and associated channel to a net.Conn.
func ToNetConn(parent gossh.Conn, ch gossh.Channel, forceClose bool) net.Conn {
	return &channel{
		Channel:    ch,
		parentConn: parent,
		forceClose: forceClose,
	}
}

type channel struct {
	gossh.Channel
	parentConn       gossh.Conn
	deadline         *time.Timer
	deadlineCanceled chan struct{}
	mu               sync.Mutex
	forceClose       bool
}

func (c *channel) LocalAddr() net.Addr {
	return c.parentConn.LocalAddr()
}

func (c *channel) RemoteAddr() net.Addr {
	return c.parentConn.RemoteAddr()
}

func (c *channel) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.deadline != nil {
		c.deadline.Stop()
		close(c.deadlineCanceled)
		c.deadline = nil
	}

	if t.IsZero() {
		return nil
	}

	c.deadline = time.NewTimer(time.Until(t))
	c.deadlineCanceled = make(chan struct{})
	go func(deadline *time.Timer, deadlineCanceled <-chan struct{}) {
		select {
		case <-deadline.C:
			if c.forceClose {
				_ = c.Channel.CloseWrite()
			} else {
				_ = c.Channel.Close()
			}
		case <-deadlineCanceled:
			return
		}
	}(c.deadline, c.deadlineCanceled)

	return nil
}

func (c *channel) SetReadDeadline(_ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (c *channel) SetWriteDeadline(_ time.Time) error {
	return fmt.Errorf("not implemented")
}
