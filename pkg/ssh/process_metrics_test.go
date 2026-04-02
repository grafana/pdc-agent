package ssh

import (
	"errors"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

var errProcessUnavailable = errors.New("process unavailable")

type stubProcessCPUReader struct {
	cpuSeconds map[int]float64
	err        error
}

func (r stubProcessCPUReader) CPUSeconds(pid int) (float64, error) {
	if r.err != nil {
		return 0, r.err
	}

	value, ok := r.cpuSeconds[pid]
	if !ok {
		return 0, errProcessUnavailable
	}

	return value, nil
}

func TestSSHProcessCPUMetricsCollectsTrackedProcesses(t *testing.T) {
	metrics := newSSHProcessCPUMetricsWithReader(stubProcessCPUReader{
		cpuSeconds: map[int]float64{
			42: 1.25,
		},
	})
	metrics.track("1", 42)

	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics)

	family := gatherMetricFamily(t, registry, "pdc_agent_ssh_process_cpu_seconds_total")
	require.Equal(t, dto.MetricType_COUNTER, family.GetType())
	require.Equal(t, "Total CPU time consumed by running OpenSSH child processes in seconds.", family.GetHelp())
	require.Len(t, family.GetMetric(), 1)

	metric := family.GetMetric()[0]
	require.Equal(t, map[string]string{
		"connection": "1",
		"pid":        "42",
	}, labelMap(metric))
	require.InDelta(t, 1.25, metric.GetCounter().GetValue(), 0.000001)
}

func TestSSHProcessCPUMetricsStopsCollectingUntrackedProcesses(t *testing.T) {
	metrics := newSSHProcessCPUMetricsWithReader(stubProcessCPUReader{
		cpuSeconds: map[int]float64{
			42: 1.25,
		},
	})
	metrics.track("1", 42)
	metrics.untrack("1", 42)

	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics)

	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		require.NotEqual(t, "pdc_agent_ssh_process_cpu_seconds_total", family.GetName())
	}
}

func TestClientCollectsTrackedSSHProcessCPUMetrics(t *testing.T) {
	client := NewClient(DefaultConfig(), log.NewNopLogger(), nil)
	client.metrics.sshProcessCPU = newSSHProcessCPUMetricsWithReader(stubProcessCPUReader{
		cpuSeconds: map[int]float64{
			42: 1.25,
		},
	})
	client.metrics.sshProcessCPU.track("1", 42)

	registry := prometheus.NewRegistry()
	registry.MustRegister(client)

	family := gatherMetricFamily(t, registry, "pdc_agent_ssh_process_cpu_seconds_total")
	require.Len(t, family.GetMetric(), 1)

	metric := family.GetMetric()[0]
	require.Equal(t, map[string]string{
		"connection": "1",
		"pid":        "42",
	}, labelMap(metric))
	require.InDelta(t, 1.25, metric.GetCounter().GetValue(), 0.000001)
}

func gatherMetricFamily(t *testing.T, registry *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()

	families, err := registry.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}

	t.Fatalf("metric family %q not found", name)
	return nil
}

func labelMap(metric *dto.Metric) map[string]string {
	labels := make(map[string]string, len(metric.GetLabel()))
	for _, pair := range metric.GetLabel() {
		labels[pair.GetName()] = pair.GetValue()
	}

	return labels
}
