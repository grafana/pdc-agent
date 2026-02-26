package ssh_test

import (
	"context"
	"testing"

	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/stretchr/testify/require"
)

func TestGoClientModeSkipsOpenSSHValidation(t *testing.T) {
	cfg := ssh.DefaultConfig()
	cfg.UseGoClient = true
	cfg.SkipSSHValidation = false
	cfg.URL = mustParseURL("127.0.0.1")
	cfg.Port = 65535
	cfg.PDC = pdc.Config{
		HostedGrafanaID: "123",
	}

	client := newTestClient(t, cfg, false)
	client.SSHCmd = "/path/that/does/not/exist/ssh"

	ctx := context.Background()
	err := client.StartAsync(ctx)
	require.NoError(t, err)

	client.StopAsync()
	_ = client.AwaitTerminated(ctx)
}
