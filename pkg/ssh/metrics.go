package ssh

import (
	"bytes"
	"regexp"
	"strconv"
	"time"

	"github.com/grafana/pdc-agent/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type promMetrics struct {
	sshRestartsCount    *prometheus.CounterVec
	tcpConnectionsCount *prometheus.GaugeVec
	timeToConnect       *prometheus.HistogramVec
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
		timeToConnect: metrics.NewNativeHistogramVec(
			prometheus.HistogramOpts{
				Name:      "ssh_time_to_connect_seconds",
				Help:      "Time spent to establish SSH connection",
				Namespace: "pdc_agent",
			},
			[]string{"event"},
		),
	}
}

type logMetricsParser struct {
	m           *promMetrics
	connStart   time.Time
	connRestart time.Time
	isStart     bool // to differentiate between "start" and "restart" connection
}

func (p logMetricsParser) parseLogMetrics(msg []byte) {
	switch {
	case bytes.Contains(msg, []byte("nchannels")):
		p.channelsCount(msg)
	case bytes.Contains(msg, []byte("connected to")):
		pattern := `connected to (.+?) port (\d+)`
		p.tcpConnCount(msg, pattern, "success")
	case bytes.Contains(msg, []byte("connect_to")):
		pattern := `connect_to (.+?) port (\d+): failed.`
		p.tcpConnCount(msg, pattern, "failure")
	case bytes.Contains(msg, []byte("This is Grafana Private Datasource Connect!")):
		if p.isStart {
			p.m.timeToConnect.
				WithLabelValues("start").
				Observe(time.Since(p.connStart).Seconds())
		} else {
			p.m.timeToConnect.
				WithLabelValues("restart").
				Observe(time.Since(p.connRestart).Seconds())
		}
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
