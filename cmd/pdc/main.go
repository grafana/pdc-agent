package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/metrics"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/prometheus/client_golang/prometheus"
)

// Values set by goreleaser during the build process using ldflags.
// https://goreleaser.com/cookbooks/using-main.version/
var (
	// Current Git tag (the v prefix is stripped) or the name of the snapshot, if you're using the --snapshot flag
	version string
	// Current git commit SHA
	commit string
	// Date in the RFC3339 format
	date string
)

const logLevelinfo = "info"

type mainFlags struct {
	PrintHelp bool
	LogLevel  string
	Cluster   string
	Domain    string

	APIFQDN     string
	GatewayFQDN string

	// The fields below were added to make local development easier.
	//
	// DevMode is true when the agent is being run locally while someone is working on it.
	DevMode bool
}

func (mf *mainFlags) RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&mf.PrintHelp, "h", false, "Print help")
	fs.StringVar(&mf.LogLevel, "log.level", logLevelinfo, `"debug", "info", "warn" or "error"`)
	fs.StringVar(&mf.Cluster, "cluster", "", "the PDC cluster to connect to use")
	fs.StringVar(&mf.Domain, "domain", "grafana.net", "the domain of the PDC cluster")

	fs.StringVar(&mf.APIFQDN, "api-fqdn", "", "FQDN for the PDC API. If set, this will take precedence over the cluster and domain flags")
	fs.StringVar(&mf.GatewayFQDN, "gateway-fqdn", "", "FQDN for the PDC Gateway. If set, this will take precedence over the cluster and domain flags")

	fs.BoolVar(&mf.DevMode, "dev-mode", false, "[DEVELOPMENT ONLY] run the agent in development mode")
}

// Tries to get the openssh version. Returns "UNKNOWN" on error.
func tryGetOpenSSHVersion() string {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	buffer := bytes.NewBuffer([]byte{})

	cmd := exec.CommandContext(timeoutCtx, "ssh", "-V")
	// ssh -V outputs to stderr.
	cmd.Stderr = buffer

	if err := cmd.Run(); err != nil {
		return "UNKNOWN"
	}

	// ssh -V adds \n to the end of the output.
	return strings.Replace(buffer.String(), "\n", "", 1)
}

func main() {
	sshConfig := ssh.DefaultConfig()
	mf := &mainFlags{}
	pdcClientCfg := &pdc.Config{}

	usageFn, err := parseFlags(mf.RegisterFlags, sshConfig.RegisterFlags, pdcClientCfg.RegisterFlags)
	if err != nil {
		fmt.Println("cannot parse flags")
		os.Exit(1)
	}

	sshConfig.Args = os.Args[1:]
	logger := setupLogger(mf.LogLevel)

	level.Info(logger).Log("msg", "PDC agent info",
		"version", fmt.Sprintf("v%s", version),
		"commit", commit,
		"date", date,
		"ssh version", tryGetOpenSSHVersion(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
	)

	if mf.PrintHelp {
		usageFn()
		return
	}

	if inLegacyMode() {
		sshConfig.LegacyMode = true
		err = runLegacyMode(sshConfig)
		if err != nil {
			fmt.Printf("error: %s", err)
			os.Exit(1)
		}
		return
	}

	apiURL, gatewayURL, err := createURLs(mf)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	pdcClientCfg.Version = version
	pdcClientCfg.URL = apiURL
	sshConfig.PDC = *pdcClientCfg
	sshConfig.URL = gatewayURL
	sshConfig.LogLevel = mf.LogLevel

	if mf.DevMode {
		setDevelopmentConfig(mf.Domain, sshConfig, pdcClientCfg)
	}

	err = run(logger, sshConfig, pdcClientCfg)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}

}

// Configures the agent for local development
func setDevelopmentConfig(domain string, sshCfg *ssh.Config, pdcClientCfg *pdc.Config) {
	pdcClientCfg.URL, _ = url.Parse("http://" + net.JoinHostPort(domain, pdcClientCfg.DevPort))

	pdcClientCfg.DevHeaders = map[string]string{
		"X-Scope-OrgID":      pdcClientCfg.HostedGrafanaID,
		"X-Access-Policy-ID": pdcClientCfg.DevNetwork,
	}
	pdcClientCfg.SignPublicKeyEndpoint = "/api/v1/sign-public-key"

	sshCfg.Port = sshCfg.DevPort
	sshCfg.URL, _ = url.Parse(domain)
	sshCfg.PDC = *pdcClientCfg
}

func run(logger log.Logger, sshConfig *ssh.Config, pdcConfig *pdc.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pdcClient, err := pdc.NewClient(pdcConfig, logger)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("cannot initialise PDC client: %s", err))
		return err
	}

	km := ssh.NewKeyManager(sshConfig, logger, pdcClient)

	// Create the SSH Service. KeyManager must be in running state when passed to ssh.NewClient
	sshClient := ssh.NewClient(sshConfig, logger, km)

	// Register prometheus metrics
	m := newPromMetrics()
	prometheus.MustRegister(m.agentInfo)
	prometheus.MustRegister(sshClient)
	if p, ok := pdcClient.(prometheus.Collector); ok {
		prometheus.MustRegister(p)
	}

	m.agentInfo.WithLabelValues(version, tryGetOpenSSHVersion(), pdcConfig.HostedGrafanaID).Set(1)

	// Start the ssh client
	err = services.StartAndAwaitRunning(ctx, sshClient)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("cannot start ssh client: %s", err))
		return err
	}

	// If ssh client start successfully, start the metrics server
	ms := metrics.NewMetricsServer(logger, sshConfig.MetricsAddr)
	go ms.Run()

	// Wait for the ssh client to exit
	_ = sshClient.AwaitTerminated(context.Background())

	return nil
}

func createURLs(cfg *mainFlags) (api *url.URL, gateway *url.URL, err error) {
	apiURL := fmt.Sprintf("https://private-datasource-connect-api-%s.%s", cfg.Cluster, cfg.Domain)
	gatewayURL := fmt.Sprintf("private-datasource-connect-%s.%s", cfg.Cluster, cfg.Domain)

	if cfg.APIFQDN != "" {
		apiURL = "https://" + cfg.APIFQDN
	}

	if cfg.GatewayFQDN != "" {
		gatewayURL = cfg.GatewayFQDN
	}

	api, err = url.Parse(apiURL)
	if err != nil {
		return
	}

	gateway, err = url.Parse(gatewayURL)
	return
}

// parseFlags creates a flagset, registers all given flags, and parses. It
// returns the flagset's usage function and the parsing error.
func parseFlags(registerers ...func(fs *flag.FlagSet)) (func(), error) {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	fs.Usage = func() {
		prog := os.Args[0]
		fmt.Fprintf(fs.Output(), `Usage of %s:
`, prog)
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), `

If pdc-agent is run with SSH flags, it will pass all arguments directly through to the "ssh" binary. This is deprecated behaviour.

Run %s <command> -h for more information
`, prog)
	}

	for _, r := range registerers {
		r(fs)
	}

	return fs.Usage, fs.Parse(os.Args[1:])
}

func inLegacyMode() bool {
	args := os.Args[1:]

	for _, a := range args {
		if a == "-p" || a == "-i" || a == "-R" || a == "-o" {
			return true
		}
	}

	return false
}

func runLegacyMode(sshConfig *ssh.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.NewLogfmtLogger(os.Stdout)
	sshClient := ssh.NewClient(sshConfig, logger, nil)
	// Start the ssh client
	err := services.StartAndAwaitRunning(ctx, sshClient)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("cannot start ssh client: %s", err))
		return err
	}
	// Wait for the ssh client to exit
	_ = sshClient.AwaitTerminated(context.Background())
	return nil
}

// setupLogger with level filter.
func setupLogger(lvl string) log.Logger {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = level.NewFilter(logger, level.Allow(level.ParseDefault(lvl, level.DebugValue())))
	logger = log.With(logger, "caller", log.DefaultCaller)
	logger = log.With(logger, "ts", log.DefaultTimestamp)

	return logger
}

type promMetrics struct {
	agentInfo *prometheus.GaugeVec
}

func newPromMetrics() *promMetrics {
	return &promMetrics{
		agentInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "agent_info",
				Help:      "Information about the agent version, SSH version and stack ID",
				Namespace: "pdc_agent",
			},
			[]string{"version", "ssh_version", "stack_id"},
		),
	}
}
