package retry

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestForever(t *testing.T) {
	t.Parallel()

	t.Run("should retry until the function succeeds", func(t *testing.T) {
		t.Parallel()

		attempts := 0

		retryOpts := Opts{MaxBackoff: 100 * time.Second, InitialBackoff: 0 * time.Second}
		Forever(retryOpts, func() error {
			attempts++

			if attempts < 1000 {
				return fmt.Errorf("try again")
			}

			return nil
		})

		assert.Equal(t, 1000, attempts)
	})
}
