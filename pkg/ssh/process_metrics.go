package ssh

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

const procTicksPerSecond = 100

type processCPUReader interface {
	CPUSeconds(pid int) (float64, error)
}

type procfsProcessCPUReader struct {
	fs procfs.FS
}

func newProcfsProcessCPUReader() (processCPUReader, error) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return nil, err
	}

	return procfsProcessCPUReader{fs: fs}, nil
}

func (r procfsProcessCPUReader) CPUSeconds(pid int) (float64, error) {
	proc, err := r.fs.Proc(pid)
	if err != nil {
		return 0, err
	}

	stat, err := proc.Stat()
	if err != nil {
		return 0, err
	}

	return float64(stat.UTime+stat.STime) / procTicksPerSecond, nil
}

type sshProcessCPUMetrics struct {
	desc      *prometheus.Desc
	reader    processCPUReader
	processes map[string]int
	mu        sync.RWMutex
}

func newSSHProcessCPUMetrics() *sshProcessCPUMetrics {
	reader, err := newProcfsProcessCPUReader()
	if err != nil {
		reader = nil
	}

	return newSSHProcessCPUMetricsWithReader(reader)
}

func newSSHProcessCPUMetricsWithReader(reader processCPUReader) *sshProcessCPUMetrics {
	return &sshProcessCPUMetrics{
		desc: prometheus.NewDesc(
			"pdc_agent_ssh_process_cpu_seconds_total",
			"Total CPU time consumed by running OpenSSH child processes in seconds.",
			[]string{"connection", "pid"},
			nil,
		),
		reader:    reader,
		processes: map[string]int{},
	}
}

func (m *sshProcessCPUMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.desc
}

func (m *sshProcessCPUMetrics) Collect(ch chan<- prometheus.Metric) {
	if m.reader == nil {
		return
	}

	for connection, pid := range m.snapshot() {
		cpuSeconds, err := m.reader.CPUSeconds(pid)
		if err != nil {
			continue
		}

		ch <- prometheus.MustNewConstMetric(
			m.desc,
			prometheus.CounterValue,
			cpuSeconds,
			connection,
			strconv.Itoa(pid),
		)
	}
}

func (m *sshProcessCPUMetrics) track(connection string, pid int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.processes[connection] = pid
}

func (m *sshProcessCPUMetrics) untrack(connection string, pid int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	currentPID, ok := m.processes[connection]
	if !ok || currentPID != pid {
		return
	}

	delete(m.processes, connection)
}

func (m *sshProcessCPUMetrics) snapshot() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	processes := make(map[string]int, len(m.processes))
	for connection, pid := range m.processes {
		processes[connection] = pid
	}

	return processes
}
