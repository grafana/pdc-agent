package ssh_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/go-kit/log"
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
	client := newTestClient(t, &ssh.Config{Args: []string{"-V"}})

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
	_ = client.AwaitTerminated(ctx)
	assert.Equal(t, "Terminated", client.State().String())

}

// testClient returns a new SSH client with a mocked command
// see https://npf.io/2015/06/testing-exec-command/
func newTestClient(t *testing.T, cfg *ssh.Config) *ssh.Client {
	t.Helper()
	logger := log.NewNopLogger()
	if len(cfg.Args) == 0 {
		cfg.Args = append([]string{"-test.run=TestFakeSSHCmd", "--"}, cfg.Args...)
	}
	if cfg.URL == nil {
		cfg.URL = mustParseURL("localhost")
	}
	pdcCfg := pdc.Config{
		URL: mustParseURL("test.api"),
	}
	pdcClient, err := pdc.NewClient(&pdcCfg, logger)
	require.Nil(t, err)
	km := ssh.NewKeyManager(cfg, logger, pdcClient)

	client := ssh.NewClient(cfg, logger, km)
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
			HostedGrafanaID: "123",
		}

		sshClient := newTestClient(t, cfg)

		result, err := sshClient.SSHFlagsFromConfig()

		assert.Nil(t, err)
		assert.Equal(t, strings.Split(fmt.Sprintf("-i %s 123@host.grafana.net -p 22 -R 0 -vv -o UserKnownHostsFile=%s -o CertificateFile=%s -o ServerAliveInterval=15", cfg.KeyFile, path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), cfg.KeyFile+"-cert.pub"), " "), result)
	})

	t.Run("legacy args (deprecated)", func(t *testing.T) {
		expectedArgs := []string{"test", "ok"}
		cfg := ssh.DefaultConfig()
		cfg.LegacyMode = true
		cfg.URL = mustParseURL("localhost")
		cfg.Args = expectedArgs

		sshClient := newTestClient(t, cfg)
		result, err := sshClient.SSHFlagsFromConfig()

		assert.Nil(t, err)
		assert.Equal(t, expectedArgs, result)
	})

	t.Run("ssh-flags get appended to command", func(t *testing.T) {
		cfg := ssh.DefaultConfig()

		cfg.URL = mustParseURL("host.grafana.net")

		cfg.PDC = pdc.Config{
			HostedGrafanaID: "123",
		}

		cfg.SSHFlags = []string{
			"-vvv",
			"-o testoption=2",
			"-o PermitRemoteOpen=host:123 host:456",
		}

		sshClient := newTestClient(t, cfg)
		result, err := sshClient.SSHFlagsFromConfig()

		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("-i %s 123@host.grafana.net -p 22 -R 0 -vv -o UserKnownHostsFile=%s -o CertificateFile=%s -o ServerAliveInterval=15 -vvv -o testoption=2 -o PermitRemoteOpen=host:123 host:456", cfg.KeyFile, path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), cfg.KeyFile+"-cert.pub"), strings.Join(result, " "))

	})
}
