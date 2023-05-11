package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
)

type mainFlags struct {
	PrintHelp bool
}

func (mf *mainFlags) RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&mf.PrintHelp, "h", false, "Print help")
}

func main() {

	sshConfig := ssh.DefaultConfig()
	mf := &mainFlags{}
	pdcClientCfg := &pdc.Config{}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sshConfig.Args = os.Args[1:]

	if inLegacyMode() {
		sshConfig.LegacyMode = true
		runLegacyMode(ctx, sshConfig)
		return
	}

	usageFn, err := parseFlags(mf.RegisterFlags, sshConfig.RegisterFlags, pdcClientCfg.RegisterFlags)
	if err != nil {
		log.Fatal("cannot parse flags")
	}

	if mf.PrintHelp {
		usageFn()
		return
	}

	sshConfig.PDC = pdcClientCfg

	pdcClient, err := pdc.NewClient(pdcClientCfg)
	if err != nil {
		log.Fatalf("cannot initialise PDC client: %s", err)
	}

	// Whilst KeyManager is not passed to SSHClient, we need KM to have run before SSHClient is running.
	km := ssh.NewKeyManager(sshConfig, pdcClient, &ssh.OSFileReadWriter{})
	err = services.StartAndAwaitRunning(ctx, km)
	if err != nil {
		log.Fatalf("cannot start key manager: %s", err.Error())
	}

	// Create the SSH Service
	sshClient, err := ssh.NewClient(sshConfig)
	if err != nil {
		log.Fatalf("cannot declare ssh client: %s", err.Error())
	}
	// Start the ssh client
	services.StartAndAwaitRunning(ctx, sshClient)

	// Wait for the ssh client to exit
	sshClient.AwaitTerminated(context.Background())
	km.AwaitTerminated(context.Background())

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
		log.Println(a)
		if a == "-p" || a == "-i" || a == "-R" || a == "-o" {
			return true
		}
	}

	return false
}

func runLegacyMode(ctx context.Context, sshConfig *ssh.Config) {
	sshClient, err := ssh.NewClient(sshConfig)
	if err != nil {
		log.Fatalf("cannot declare ssh client: %s", err.Error())
	}
	// Start the ssh client
	services.StartAndAwaitRunning(ctx, sshClient)

	// Wait for the ssh client to exit
	sshClient.AwaitTerminated(context.Background())
}
