package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
)

type mainFlags struct {
	PrintHelp bool
	LogLevel  string
	Cluster   string
	Domain    string

	// The fields below were added to make local development easier.
	//
	// DevMode is true when the agent is being run locally while someone is working on it.
	DevMode bool
}

func (mf *mainFlags) RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&mf.PrintHelp, "h", false, "Print help")
	fs.StringVar(&mf.LogLevel, "log.level", "info", `"debug", "info", "warn" or "error"`)
	fs.StringVar(&mf.Cluster, "cluster", "", "the PDC cluster to connect to use")
	fs.StringVar(&mf.Domain, "domain", "grafana.net", "the domain of the PDC cluster")
	fs.BoolVar(&mf.DevMode, "dev-mode", false, "[DEVELOPMENT ONLY] run the agent in development mode")
}

func main() {
	sshConfig := ssh.DefaultConfig()
	mf := &mainFlags{}
	pdcClientCfg := &pdc.Config{}

	sshConfig.Args = os.Args[1:]

	if inLegacyMode() {
		sshConfig.LegacyMode = true
		err := runLegacyMode(sshConfig)
		if err != nil {
			fmt.Printf("error: %s", err)
			os.Exit(1)
		}
		return
	}

	usageFn, err := parseFlags(mf.RegisterFlags, sshConfig.RegisterFlags, pdcClientCfg.RegisterFlags)
	if err != nil {
		fmt.Println("cannot parse flags")
		os.Exit(1)
	}

	logger := setupLogger(mf.LogLevel)

	if mf.PrintHelp {
		usageFn()
		return
	}

	apiURL, gatewayURL, err := createURLsFromCluster(mf.Cluster, mf.Domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	pdcClientCfg.URL = apiURL
	sshConfig.PDC = *pdcClientCfg
	sshConfig.URL = gatewayURL

	if mf.DevMode {
		setDevelopmentConfig(sshConfig, pdcClientCfg)
	}

	err = run(logger, sshConfig, pdcClientCfg)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}

}

// Configures the agent for local development
func setDevelopmentConfig(sshCfg *ssh.Config, pdcClientCfg *pdc.Config) {
	pdcClientCfg.URL, _ = url.Parse("http://localhost:9181")

	pdcClientCfg.DevHeaders = map[string]string{
		"X-Scope-OrgID":      pdcClientCfg.HostedGrafanaID,
		"X-Access-Policy-ID": pdcClientCfg.DevNetwork,
	}
	pdcClientCfg.SignPublicKeyEndpoint = "/api/v1/sign-public-key"

	sshCfg.Port = 2244
	sshCfg.URL, _ = url.Parse("localhost")
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
	// Start the ssh client
	err = services.StartAndAwaitRunning(ctx, sshClient)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("cannot start ssh client: %s", err))
		return err
	}

	// Wait for the ssh client to exit
	_ = sshClient.AwaitTerminated(context.Background())

	return nil
}

func createURLsFromCluster(cluster string, domain string) (api *url.URL, gateway *url.URL, err error) {
	apiURL := fmt.Sprintf("https://private-datasource-connect-api-%s.%s", cluster, domain)
	gatewayURL := fmt.Sprintf("private-datasource-connect-%s.%s", cluster, domain)

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
