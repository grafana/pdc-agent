package random

import (
	"fmt"
	"math/rand"
)

// Generates a number between min and max inclusive.
func Range(minVal, maxVal int) int {
	if minVal > maxVal {
		panic(fmt.Sprintf("min cannot be greater than max: min=%d max=%d", minVal, maxVal))
	}

	if minVal == maxVal {
		return minVal
	}

	n := minVal + rand.Intn(maxVal-minVal+1)
	return n
}
