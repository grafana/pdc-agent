package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/ssh"
)

func main() {
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	// Create the SSH Service
	sshClient := ssh.NewClient(&ssh.Config{Args: os.Args[1:]})
	// Start the ssh client
	services.StartAndAwaitRunning(ctx, sshClient)
	// Wait for the ssh client to exit
	sshClient.AwaitTerminated(context.Background())
}
