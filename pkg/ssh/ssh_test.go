package ssh_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParseURL(s string) *url.URL {
	url, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return url
}

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
	cfg.URL = mustParseURL("localhost")
	client, _ := ssh.NewClient(cfg)
	client.SSHCmd = os.Args[0]
	return client
}

// TestFakeSSHCmd is a test helper function that is executed by the SSH client
func TestFakeSSHCmd(t *testing.T) {
	assert.True(t, true)
}

// Building this out to verify behaviour, not exactly sure that the function is
// hanging off the right struct or organised appropriately.
func TestClient_SSHArgs(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := ssh.DefaultConfig()

		cfg.URL = mustParseURL("host.grafana.net")

		cfg.PDC = pdc.Config{
			HostedGrafanaId: "123",
		}

		sshClient, err := ssh.NewClient(cfg)
		require.NoError(t, err)
		result, err := sshClient.SSHFlagsFromConfig()

		assert.Nil(t, err)
		assert.Equal(t, strings.Split("-i ~/.ssh/gcloud_pdc 123@host.grafana.net -p 22 -R 0 -vv -o UserKnownHostsFile=~/.ssh/known_hosts -o CertificateFile=~/.ssh/gcloud_pdc-cert.pub", " "), result)
	})

	t.Run("legacy args (deprecated)", func(t *testing.T) {
		expectedArgs := []string{"test", "ok"}
		cfg := ssh.DefaultConfig()
		cfg.LegacyMode = true
		cfg.URL = mustParseURL("localhost")
		cfg.Args = expectedArgs

		sshClient, err := ssh.NewClient(cfg)
		require.NoError(t, err)
		result, err := sshClient.SSHFlagsFromConfig()

		assert.Nil(t, err)
		assert.Equal(t, expectedArgs, result)
	})
}
