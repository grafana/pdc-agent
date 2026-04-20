package ssh

import (
	"context"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"golang.org/x/crypto/ssh"
)

// doKeepAlives performs a continuous keepAlive to the server. We use this
// instead of Server.sshServer's IdleTimeout because the IdleTimeout is reset
// whenever something is written to the Connection (even if it fails): If we
// keep writing to an invalid connection, it will not time out.
//
// doKeepAlives uses a similar approach to OpenSSH. It sends a global request
// every interval and expects a reply within timeout time. If we hit the max
// failure count, it closes the connection. The only difference to OpenSSH is
// that these keepalives keep sending when other requests are being sent - this
// is just to make the code simpler.
func doKeepAlives(ctx context.Context, conn ssh.Conn, logger log.Logger) {
	interval := 15 * time.Second
	timeout := 5 * time.Second
	maxFailures := 3

	failures := 0

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		<-t.C

		if ctx.Err() != nil {
			return
		}

		rctx, cancel := context.WithTimeout(ctx, timeout)
		err := sendKeepAliveRequest(rctx, conn, logger)
		cancel()

		if err == nil {
			failures = 0
			continue
		}

		failures++
		if failures >= maxFailures {
			level.Debug(logger).Log("msg", "client keepalive failures reached, closing connection", "remote", conn.RemoteAddr())
			conn.Close()
			return
		}
	}
}

// sendKeepAliveRequest sends a global request to the client, and awaits *any*
// response. If the context cancels before we get a response, it returns the
// context error. If the request fails to send, it will eventually return the
// context error.
//
// These requests will show up on the client as packet type 80, and the client
// will response with packet type 82. This is the same behaviour as openSSH
// performs with ServerAliveInterval
func sendKeepAliveRequest(ctx context.Context, conn ssh.Conn, logger log.Logger) error {
	successCh := make(chan struct{}, 1)

	go func(c ssh.Conn, ch chan struct{}) {
		level.Debug(logger).Log("msg", "sending keepalive")
		_, _, err := c.SendRequest("keepalive", true, []byte{})

		// if the request failed to send, dont count it as a response
		if err != nil {
			return
		}
		ch <- struct{}{}
		close(ch)
	}(conn, successCh)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-successCh:
		return nil
	}
}
