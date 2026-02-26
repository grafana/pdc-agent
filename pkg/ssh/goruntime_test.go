package ssh

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGoRuntimeStateWaitForDrain(t *testing.T) {
	state := newGoRuntimeState()
	state.incInflight()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan bool, 1)
	go func() {
		done <- state.waitForZero(ctx)
	}()

	time.Sleep(10 * time.Millisecond)
	state.decInflight()

	require.True(t, <-done)
}

func TestGoRuntimeStateWaitForDrainTimeout(t *testing.T) {
	state := newGoRuntimeState()
	state.incInflight()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	require.False(t, state.waitForZero(ctx))
}
