package ssh_test

import (
	"context"
	"io/fs"
	"testing"

	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyManager_StartingAndStopping(t *testing.T) {
	//
	cfg := &ssh.Config{}
	client, _ := pdc.NewClient(&pdc.Config{})

	// given a Key manager
	km := ssh.NewKeyManager(cfg, client)
	require.NotNil(t, km)

	ctx := context.Background()

	// When starting the km
	err := km.StartAsync(ctx)
	// Then the km should be in the starting state
	assert.NoError(t, err)
	assert.Equal(t, "Starting", km.State().String())

	// And eventually move to the running state
	err = km.AwaitRunning(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "Running", km.State().String())

	// When stopping the service
	km.StopAsync()
	assert.NoError(t, err)

	// Then is should eventually move to the terminated state
	km.AwaitTerminated(ctx)
	assert.Equal(t, "Terminated", km.State().String())
}

func TestKeyManager_EnsureKeys(t *testing.T) {
	// test cases:
	/*
	   - no files exist
	   - only key exists
	   - key exists but not a private key
	   - key valid, pubkey exists nut not a public key (format)
	   - key and pubkey exist, but pub key is invalid for:
	   	- validBefore
	   	- validAfter
	   	- ??
	   - key and pubkey exist, and are valid.

	   - The above when cert exists, and doesnt/invalid

	   - signing request fails

	*/
}

// mockFileReadWriter implements ssh.FileReadWriter
type mockFileReadWriter struct {
	data map[string][]byte
}

func (m mockFileReadWriter) ReadFile(path string) ([]byte, error) {
	return m.data[path], nil
}

func (m *mockFileReadWriter) WriteFile(path string, data []byte, perm fs.FileMode) error {
	m.data[path] = data
	return nil
}
