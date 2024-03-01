package random

import (
	"fmt"
	"math/rand"
)

// Generates a number between min and max inclusive.
func Range(min, max int) int {
	if min > max {
		panic(fmt.Sprintf("min cannot be greater than max: min=%d max=%d", min, max))
	}

	if min == max {
		return min
	}

	n := min + rand.Intn(max-min+1)
	return n
}
