package ssh

import (
	"context"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/grafana/dskit/services"
)

type Config struct {
	Args []string
}

type SSHClient struct {
	*services.BasicService
	cfg    *Config
	SSHCmd string // SSH command to run, defaults to "ssh". Require for testing.
}

// NewClient returns a new SSH client
func NewClient(cfg *Config) *SSHClient {
	client := &SSHClient{
		cfg:    cfg,
		SSHCmd: "ssh",
	}
	client.BasicService = services.NewIdleService(client.starting, client.stopping)
	return client
}

func (s *SSHClient) starting(ctx context.Context) error {
	log.Println("starting ssh client")
	go func() {
		for {
			cmd := exec.CommandContext(ctx, s.SSHCmd, s.cfg.Args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			if ctx.Err() != nil {
				break // context was canceled
			}
			log.Println("ssh client exited, restarting")
			// backoff
			// TODO: Implement exponential backoff
			time.Sleep(1 * time.Second)
		}
	}()
	return nil
}

func (s *SSHClient) stopping(err error) error {
	log.Println("stopping ssh client")
	return err
}
