package random

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestRange(t *testing.T) {
	t.Parallel()

	t.Run("sanity checks", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 0, Range(0, 0))
		assert.Equal(t, 1, Range(1, 1))

		require.Eventually(t, func() bool {
			return Range(0, 1) == 0
		}, 500*time.Millisecond, 50*time.Microsecond)

		require.Eventually(t, func() bool {
			return Range(0, 1) == 1
		}, 500*time.Millisecond, 50*time.Microsecond)
	})

	t.Run("only generates numbers between the min and max", rapid.MakeCheck(func(t *rapid.T) {
		a := rapid.IntRange(0, math.MaxInt-1).Draw(t, "minVal")
		b := rapid.IntRange(0, math.MaxInt-1).Draw(t, "maxVal")

		minVal := min(a, b)
		maxVal := max(a, b)

		n := Range(minVal, maxVal)

		assert.True(t, n >= minVal)
		assert.True(t, n <= maxVal)
	}))
}
