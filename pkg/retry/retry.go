package retry

import (
	"math"
	"time"

	"github.com/grafana/pdc-agent/pkg/random"
)

type Opts struct {
	MaxBackoff     time.Duration
	InitialBackoff time.Duration
}

// Calls a function until it succeeds, waiting an exponentially increasing amount of time between calls.
// An initial backoff of 0 means the waiting time does not increase exponentially (useful for testing).
func Forever(opts Opts, f func() error) {
	attempt := 1

	for {
		err := f()
		if err == nil {
			return
		}

		maxBackoff := opts.MaxBackoff.Seconds()
		initialBackoff := opts.InitialBackoff.Seconds()

		max := int(min(maxBackoff, initialBackoff*math.Pow(2, float64(attempt))))

		duration := random.Range(0, max)

		time.Sleep(time.Duration(duration) * time.Second)

		attempt++
	}
}
