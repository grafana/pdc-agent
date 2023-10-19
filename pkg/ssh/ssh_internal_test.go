package ssh

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// Generates a random string that may contain the "Exit status <code>" string as a substring.
func generateExitStatusString(t *rapid.T) (bool, string) {
	prefix := rapid.String().Draw(t, "prefix")

	exitStatus := ""
	includeExitStatus := rapid.Bool().Draw(t, "includeExitStatus")
	if includeExitStatus {
		exitStatus = fmt.Sprintf("Exit status %s", ConnectionLimitReachedCode)
	}

	suffix := rapid.String().Draw(t, "suffix")

	return includeExitStatus, fmt.Sprintf("%s%s%s", prefix, exitStatus, suffix)
}

func TestExitStatusWatcher(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		exitStatusIncluded, s := generateExitStatusString(t)

		watcher := newExitStatusWatcher(bytes.NewBuffer([]byte{}))

		_, err := watcher.Write([]byte(s))
		assert.NoError(t, err)

		if exitStatusIncluded {
			assert.Equal(t, watcher.exitStatus, ConnectionLimitReachedCode)
		} else {
			assert.Equal(t, watcher.exitStatus, "")
		}
	})
}
