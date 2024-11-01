package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func nativeHistogramOpts(opts prometheus.HistogramOpts) prometheus.HistogramOpts {
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

func NewNativeHistogramVec(opts prometheus.HistogramOpts, labelNames []string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(nativeHistogramOpts(opts), labelNames)
}

func NewNativeHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	return prometheus.NewHistogram(nativeHistogramOpts(opts))
}
