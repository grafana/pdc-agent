package ssh

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// NewListenerFromChannel creates a net.Listener that listens for new
// requests on an ssh channel and converts the request to a net.Conn. The connection
// that received the channel is required for implementing the net.Conn interface.
func NewListenerFromChannel(parent ssh.Conn, nc <-chan ssh.NewChannel, promMetrics *promMetrics) net.Listener {
	return &listener{
		parent:  parent,
		nc:      nc,
		metrics: *promMetrics,
	}
}

// listener implements net.Listener
type listener struct {
	nc     <-chan ssh.NewChannel
	parent ssh.Conn

	mu         sync.RWMutex
	chanclosed bool
	metrics    promMetrics
}

func (l *listener) ok() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return !l.chanclosed && l.parent != nil
}

func (l *listener) Accept() (net.Conn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}

	nc := <-l.nc

	// channel close event. Error here as we don't want to try and do something
	// with the event
	if nc == nil {
		l.mu.Lock()
		l.chanclosed = true
		l.mu.Unlock()
		return nil, errors.New("ssh.NewChannel channel closed")
	}

	ch, reqs, err := (nc).Accept()
	if err != nil {
		return nil, err
	}
	l.metrics.goOpenChannelsCount.Inc()

	go ssh.DiscardRequests(reqs)

	return ToNetConn(l.parent, ch, l), nil
}

func (l *listener) Addr() net.Addr {
	return l.parent.LocalAddr()
}

func (l *listener) Close() error {
	return nil
}

// ToNetConn converts an ssh connection and associated channel to a net.Conn
func ToNetConn(parent ssh.Conn, ch ssh.Channel, l *listener) net.Conn {
	return &channel{
		Channel:    ch,
		parentConn: parent,
		metrics:    l.metrics,
	}
}

// channel implements net.Conn
type channel struct {
	ssh.Channel
	parentConn       ssh.Conn
	deadline         *time.Timer
	deadlineCanceled chan struct{}
	mu               sync.Mutex
	metrics          promMetrics
	// we only want to do teardown one time
	closeOnce sync.Once
}

func (c *channel) Close() (err error) {
	c.closeOnce.Do(func() {
		c.metrics.goOpenChannelsCount.Dec()

		err = c.Channel.Close()
	})

	return err
}

// LocalAddr returns the local network address.
func (c *channel) LocalAddr() net.Addr {
	return c.parentConn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *channel) RemoteAddr() net.Addr {
	return c.parentConn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *channel) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Stop the time if it's already running
	if c.deadline != nil {
		c.deadline.Stop()
		close(c.deadlineCanceled)
		c.deadline = nil
	}
	// If t is zero, we don't want to set a deadline
	if t.IsZero() {
		return nil
	}
	// Set the deadline
	c.deadline = time.NewTimer(time.Until(t))
	c.deadlineCanceled = make(chan struct{})
	go func(deadline *time.Timer, deadlineCanceled <-chan struct{}) {
		select {
		case <-deadline.C:
			_ = c.Close()
		case <-deadlineCanceled:
			return
		}
	}(c.deadline, c.deadlineCanceled)
	return nil
}

// A zero value for t means I/O operations will not time out.
func (c *channel) SetReadDeadline(_ time.Time) error {
	return fmt.Errorf("not implemented")
}

// A zero value for t means I/O operations will not time out.
func (c *channel) SetWriteDeadline(_ time.Time) error {
	return fmt.Errorf("not implemented")
}
