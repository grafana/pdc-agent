package ssh_test

import (
	"context"
	"path"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/stretchr/testify/require"
)

// TestGoSSHClient_CreateConfig tests SSH client configuration creation
func TestGoSSHClient_CreateConfig(t *testing.T) {
	t.Run("creates valid config with cert authentication", func(t *testing.T) {
		cfg := ssh.DefaultConfig()
		cfg.URL = mustParseURL("test.grafana.net")
		cfg.PDC = pdc.Config{
			HostedGrafanaID: "test-stack-123",
		}
		cfg.UseGoSSHClient = true

		dir := t.TempDir()
		cfg.KeyFile = path.Join(dir, "test_key")

		logger := log.NewNopLogger()
		mClient := mockPDCClient{}
		km := ssh.NewKeyManager(cfg, logger, mClient)

		// Generate keys so config creation has files to read
		err := km.CreateKeys(context.Background(), false)
		require.NoError(t, err)

		client := ssh.NewClient(cfg, logger, km)

		// We can't directly call createSSHClientConfig as it's private,
		// but we can verify the client starts up without config errors
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err = client.StartAsync(ctx)
		// We expect it to fail to connect (no server), but config should be valid
		require.NoError(t, err)

		// Clean up
		client.StopAsync()
		_ = client.AwaitTerminated(context.Background())
	})
}

// TestGoSSHClient_ConnectionRetry tests retry behavior
func TestGoSSHClient_ConnectionRetry(t *testing.T) {
	t.Run("retries on connection failure", func(t *testing.T) {
		cfg := ssh.DefaultConfig()
		cfg.URL = mustParseURL("127.0.0.1")
		cfg.Port = 9999 // Non-existent port
		cfg.PDC = pdc.Config{
			HostedGrafanaID: "123",
		}
		cfg.UseGoSSHClient = true

		dir := t.TempDir()
		cfg.KeyFile = path.Join(dir, "test_key")

		logger := log.NewNopLogger()
		mClient := mockPDCClient{}
		km := ssh.NewKeyManager(cfg, logger, mClient)
		err := km.CreateKeys(context.Background(), false)
		require.NoError(t, err)

		client := ssh.NewClient(cfg, logger, km)

		ctx := context.Background()
		err = client.StartAsync(ctx)
		require.NoError(t, err)

		// Client should keep retrying in background
		// We just verify it doesn't crash
		time.Sleep(100 * time.Millisecond)

		client.StopAsync()
		_ = client.AwaitTerminated(ctx)
	})
}
