package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func NativeHistogramOpts(opts prometheus.HistogramOpts) prometheus.HistogramOpts {
	if opts.NativeHistogramBucketFactor == 0 {
		// Enable native histograms, with the factor suggested in the docs
		opts.NativeHistogramBucketFactor = 1.1
	}
	if opts.NativeHistogramMaxBucketNumber == 0 {
		// OTel default
		opts.NativeHistogramMaxBucketNumber = 160
	}
	if opts.NativeHistogramMinResetDuration == 0 {
		// Reset buckets every hour by default - override this if you want to
		// keep buckets around for longer
		opts.NativeHistogramMinResetDuration = 1 * time.Hour
	}

	return opts
}
