package ssh

import (
	"bytes"
	"regexp"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

type promMetrics struct {
	sshRestartsCount    *prometheus.CounterVec
	tcpConnectionsCount *prometheus.GaugeVec
	channelsCount       prometheus.Gauge
}

func newPromMetrics() *promMetrics {
	return &promMetrics{
		sshRestartsCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "ssh_restarts_total",
				Help:      "Total number of SSH restarts",
				Namespace: "pdc_agent",
			},
			[]string{"exit_code"},
		),
		channelsCount: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name:      "ssh_channels",
				Help:      "Number of active SSH channels",
				Namespace: "pdc_agent",
			},
		),
		tcpConnectionsCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "tcp_connections",
				Help:      "Number of open TCP connections",
				Namespace: "pdc_agent",
			},
			[]string{"target", "status"},
		),
	}
}

type logMetricsParser struct {
	m *promMetrics
}

func (p logMetricsParser) parseLogMetrics(msg []byte) {
	if bytes.Contains(msg, []byte("nchannels")) {
		p.channelsCount(msg)
		return
	}

	if bytes.Contains(msg, []byte("connected to")) {
		pattern := `connected to (.+?) port (\d+)`
		p.tcpConnCount(msg, pattern, "success")
		return
	}

	if bytes.Contains(msg, []byte("connect_to")) {
		pattern := `connect_to (.+?) port (\d+): failed.`
		p.tcpConnCount(msg, pattern, "failure")
		return
	}
}

func (p logMetricsParser) channelsCount(msg []byte) {
	re := regexp.MustCompile(`nchannels (\d+)`)
	matches := re.FindSubmatch(msg)
	if len(matches) > 1 {
		if value, err := strconv.Atoi(string(matches[1])); err == nil {
			p.m.channelsCount.Set(float64(value))
		}
	}
}

func (p logMetricsParser) tcpConnCount(msg []byte, pattern string, status string) {
	re := regexp.MustCompile(pattern)
	matches := re.FindSubmatch(msg)
	if len(matches) > 1 {
		// target host name, and port if specified
		target := string(matches[1])
		if len(matches) > 2 && len(matches[2]) > 0 {
			target += ":" + string(matches[2])
		}
		p.m.tcpConnectionsCount.WithLabelValues(target, status).Add(1)
	}
}
