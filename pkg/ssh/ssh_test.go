package ssh_test

import (
	"context"
	"io/fs"
	"os"
	"strings"
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

// Building this out to verify behaviour, not exactly sure that the function is
// hanging off the right struct or organised appropriately.
func TestClient_SSHArgs(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		defaultCfg := ssh.DefaultConfig()

		// populate required config items with no defaults
		defaultCfg.Identity = "test"
		defaultCfg.Host = "host"
		defaultCfg.HostedGrafanaId = "123"
		defaultCfg.PDCSigningToken = "token"

		result := ssh.NewClient(defaultCfg).SSHFlagsFromConfig()

		assert.Equal(t, strings.Split("-i ~/.ssh/gcloud_pdc test@host.grafana.net -p 22 -R 0 -vv -o UserKnownHostsFile=~/.ssh/known_hosts -o CertificateFile=~/.ssh/gcloud_pdc-cert.pub", " "), result)
	})

	t.Run("legacy args (deprecated)", func(t *testing.T) {
		expectedArgs := []string{"test", "ok"}
		cfg := ssh.DefaultConfig()
		cfg.Args = expectedArgs
		result := ssh.NewClient(cfg).SSHFlagsFromConfig()

		assert.Equal(t, expectedArgs, result)
	})
}

// mockFileReadWriter implements ssh.FileReadWriter
type mockFileReadWriter struct {
	data map[string][]byte
}

func (m mockFileReadWriter) ReadFile(name string) ([]byte, error) {
	return m.data[name], nil
}

func (m *mockFileReadWriter) WriteFile(name string, data []byte, perm fs.FileMode) error {
	m.data[name] = data
	return nil
}
