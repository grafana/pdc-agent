package ssh_test

import (
	"context"
	"os"
	"testing"

	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/stretchr/testify/assert"
)

func TestStartingAndStopping(t *testing.T) {
	// Given an SSH client
	client := newTestClient(&ssh.Config{Args: []string{"-V"}})

	ctx := context.Background()

	// When starting the client
	err := client.StartAsync(ctx)
	// Then the client should be in the starting state
	assert.NoError(t, err)
	assert.Equal(t, "Starting", client.State().String())

	// And eventually move to the running state
	err = client.AwaitRunning(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "Running", client.State().String())

	// When stopping the service
	client.StopAsync()
	assert.NoError(t, err)

	// Then is should eventually move to the terminated state
	client.AwaitTerminated(ctx)
	assert.Equal(t, "Terminated", client.State().String())

}

// testClient returns a new SSH client with a mocked command
// see https://npf.io/2015/06/testing-exec-command/
func newTestClient(cfg *ssh.Config) *ssh.SSHClient {
	cfg.Args = append([]string{"-test.run=TestFakeSSHCmd", "--"}, cfg.Args...)
	client := ssh.NewClient(cfg)
	client.SSHCmd = os.Args[0]
	return client
}

// TestFakeSSHCmd is a test helper function that is executed by the SSH client
func TestFakeSSHCmd(t *testing.T) {
	assert.True(t, true)
}
