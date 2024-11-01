package ssh

import (
	"bytes"
	"regexp"
	"strconv"
	"time"

	"github.com/grafana/pdc-agent/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	reConnSuccess   = regexp.MustCompile(`connected to (.+?) port (\d+)`)
	reConnFailure   = regexp.MustCompile(`connect_to (.+?) port (\d+): failed.`)
	reChannelsCount = regexp.MustCompile(`nchannels (\d+)`)
)

type promMetrics struct {
	sshRestartsCount    *prometheus.CounterVec
	tcpConnectionsCount *prometheus.CounterVec
	timeToConnect       prometheus.Histogram
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
		tcpConnectionsCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "tcp_connections_total",
				Help:      "Number of open TCP connections",
				Namespace: "pdc_agent",
			},
			[]string{"target", "status"},
		),
		timeToConnect: metrics.NewNativeHistogram(
			prometheus.HistogramOpts{
				Name:      "ssh_time_to_connect_seconds",
				Help:      "Time spent to establish SSH connection",
				Namespace: "pdc_agent",
			}),
	}
}

type logMetricsParser struct {
	m         *promMetrics
	connStart time.Time
}

func (p logMetricsParser) parseLogMetrics(msg []byte) {
	switch {
	case bytes.Contains(msg, []byte("nchannels")):
		p.channelsCount(msg)
	case bytes.Contains(msg, []byte("connected to")):
		p.tcpConnCount(msg, reConnSuccess, "success")
	case bytes.Contains(msg, []byte("connect_to")):
		p.tcpConnCount(msg, reConnFailure, "failure")
	case bytes.Contains(msg, []byte("This is Grafana Private Datasource Connect!")):
		p.m.timeToConnect.Observe(time.Since(p.connStart).Seconds())
	}
}

func (p logMetricsParser) channelsCount(msg []byte) {
	matches := reChannelsCount.FindSubmatch(msg)
	if len(matches) > 1 {
		if value, err := strconv.Atoi(string(matches[1])); err == nil {
			p.m.channelsCount.Set(float64(value))
		}
	}
}

func (p logMetricsParser) tcpConnCount(msg []byte, re *regexp.Regexp, status string) {
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
