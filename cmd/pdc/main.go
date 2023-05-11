package main

import (
	"context"
	"flag"
	"fmt"
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
}

func (mf *mainFlags) RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&mf.PrintHelp, "h", false, "Print help")
	fs.StringVar(&mf.LogLevel, "log.level", "info", `"debug", "info", "warn" or "error"`)
}

func main() {

	sshConfig := ssh.DefaultConfig()
	mf := &mainFlags{}
	pdcClientCfg := &pdc.Config{}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sshConfig.Args = os.Args[1:]

	legacyMode := inLegacyMode()

	if legacyMode {
		sshConfig.LegacyMode = true
		runLegacyMode(ctx, sshConfig)
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

	sshConfig.PDC = *pdcClientCfg

	pdcClient, err := pdc.NewClient(pdcClientCfg, logger)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("cannot initialise PDC client: %s", err))
		os.Exit(1)
	}

	// Whilst KeyManager is not passed to SSHClient, we need KM to have run before SSHClient is running.
	km := ssh.NewKeyManager(sshConfig, logger, pdcClient, &ssh.OSFileReadWriter{})
	err = services.StartAndAwaitRunning(ctx, km)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("cannot start key manager: %s", err))
		os.Exit(1)
	}

	// Create the SSH Service
	sshClient := ssh.NewClient(sshConfig, logger)
	// Start the ssh client
	err = services.StartAndAwaitRunning(ctx, sshClient)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("cannot start ssh client: %s", err))
		os.Exit(1)
	}

	// Wait for the ssh client to exit
	_ = sshClient.AwaitTerminated(context.Background())
	_ = km.AwaitTerminated(context.Background())

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

func runLegacyMode(ctx context.Context, sshConfig *ssh.Config) {
	logger := log.NewLogfmtLogger(os.Stdout)
	sshClient := ssh.NewClient(sshConfig, logger)
	// Start the ssh client
	err := services.StartAndAwaitRunning(ctx, sshClient)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("cannot start ssh client: %s", err))
		os.Exit(1)
	}
	// Wait for the ssh client to exit
	_ = sshClient.AwaitTerminated(context.Background())
}

// setupLogger with level filter.
func setupLogger(lvl string) log.Logger {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = level.NewFilter(logger, level.Allow(level.ParseDefault(lvl, level.DebugValue())))
	logger = log.With(logger, "caller", log.DefaultCaller)

	return logger
}
