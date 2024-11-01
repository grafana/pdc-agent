package pdc

import (
	"github.com/grafana/pdc-agent/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type promMetrics struct {
	signingRequests *prometheus.HistogramVec
}

func newPromMetrics() *promMetrics {
	return &promMetrics{
		signingRequests: metrics.NewNativeHistogramVec(
			prometheus.HistogramOpts{
				Name:      "signing_requests_duration_seconds",
				Help:      "Duration of signing requests in seconds",
				Namespace: "pdc_agent",
			},
			[]string{"status"},
		),
	}
}
