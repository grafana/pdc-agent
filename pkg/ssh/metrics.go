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
	reConnFailure   = regexp.MustCompile(`connect_to (.+?)(?: port (\d+))?:`)
	reChannelsCount = regexp.MustCompile(`nchannels (\d+)`)
)

type promMetrics struct {
	sshConnectionsCount prometheus.Gauge // open ssh connections ready to be used/being used
	sshRestartsCount    *prometheus.CounterVec
	tcpConnectionsCount *prometheus.CounterVec // connections to the target host
	timeToConnect       *prometheus.HistogramVec
	openChannelsCount   *prometheus.GaugeVec

	// SOCKS5 metrics (for Go SSH client only)
	socks5ConnectionsActive   prometheus.Gauge       // current active SOCKS5 connections
	socks5ConnectionsTotal    prometheus.Counter     // total SOCKS5 connections handled
	socks5ConnectionDuration  prometheus.Histogram   // SOCKS5 connection duration
	socks5ConnectionsByStatus *prometheus.CounterVec // SOCKS5 connections by status (success/error)
}

func newPromMetrics() *promMetrics {
	return &promMetrics{
		sshConnectionsCount: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name:      "ssh_connections",
				Help:      "Number of open SSH connections",
				Namespace: "pdc_agent",
			},
		),
		sshRestartsCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "ssh_restarts_total",
				Help:      "Total number of SSH restarts",
				Namespace: "pdc_agent",
			},
			[]string{"connection", "exit_code"},
		),
		openChannelsCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "ssh_open_channels",
				Help:      "Number of open SSH channels",
				Namespace: "pdc_agent",
			},
			[]string{"connection"},
		),
		tcpConnectionsCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "tcp_connections_total",
				Help:      "Number of open TCP connections",
				Namespace: "pdc_agent",
			},
			[]string{"connection", "target", "status"},
		),
		timeToConnect: metrics.NewNativeHistogramVec(
			prometheus.HistogramOpts{
				Name:      "ssh_time_to_connect_seconds",
				Help:      "Time spent to establish SSH connection",
				Namespace: "pdc_agent",
			},
			[]string{"connection"},
		),
		socks5ConnectionsActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name:      "socks5_connections_active",
				Help:      "Number of currently active SOCKS5 connections",
				Namespace: "pdc_agent",
			},
		),
		socks5ConnectionsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name:      "socks5_connections_total",
				Help:      "Total number of SOCKS5 connections handled",
				Namespace: "pdc_agent",
			},
		),
		socks5ConnectionDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:      "socks5_connection_duration_seconds",
				Help:      "Duration of SOCKS5 connections",
				Namespace: "pdc_agent",
				Buckets:   prometheus.DefBuckets,
			},
		),
		socks5ConnectionsByStatus: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "socks5_connections_by_status_total",
				Help:      "Total SOCKS5 connections by status",
				Namespace: "pdc_agent",
			},
			[]string{"status"},
		),
	}
}

type logMetricsParser struct {
	m          *promMetrics
	connStart  time.Time
	connection string
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
		p.m.timeToConnect.WithLabelValues(p.connection).Observe(time.Since(p.connStart).Seconds())
	}
}

func (p logMetricsParser) channelsCount(msg []byte) {
	matches := reChannelsCount.FindSubmatch(msg)
	if len(matches) > 1 {
		if value, err := strconv.Atoi(string(matches[1])); err == nil {
			p.m.openChannelsCount.WithLabelValues(p.connection).Set(float64(value))
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
		p.m.tcpConnectionsCount.WithLabelValues(p.connection, target, status).Add(1)
	}
}
