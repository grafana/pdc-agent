package pdc

import (
	"github.com/grafana/pdc-agent/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type promMetrics struct {
	signingRequests *prometheus.HistogramVec
}

func newPromMetrics() *promMetrics {
	m := &promMetrics{
		signingRequests: metrics.NewNativeHistogramVec(
			prometheus.HistogramOpts{
				Name: "signing_requests_duration_seconds",
				Help: "Duration of signing requests in seconds",
			},
			[]string{"status"},
		),
	}

	return m
}
