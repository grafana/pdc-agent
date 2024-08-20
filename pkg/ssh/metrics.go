package ssh

import "github.com/prometheus/client_golang/prometheus"

type promMetrics struct {
	sshRestartsCount *prometheus.CounterVec
}

func newPromMetrics() *promMetrics {
	m := &promMetrics{
		sshRestartsCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ssh_restarts_total",
				Help: "Total number of SSH restarts",
			},
			[]string{"exit_code"},
		),
	}

	return m
}
