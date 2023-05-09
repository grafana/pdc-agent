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

	usageFn, err := parseFlags(mf.RegisterFlags, sshConfig.RegisterFlags, pdcClientCfg.RegisterFlags)
	if err != nil {
		// TODO we can do better here: detect legacy mode before trying to parse flags
		fmt.Println("pdc-agent running in legacy mode. All arguments will be passed directly to the ssh binary.")
	}

	if mf.PrintHelp {
		usageFn()
		return
	}

	sshConfig.Args = os.Args[1:]
	sshConfig.PDC = pdcClientCfg

	pdcClient, err := pdc.NewClient(pdcClientCfg)
	if err != nil {
		log.Fatalf("cannot initialise PDC client: %s", err)
	}

	km := ssh.NewKeyManager(sshConfig, pdcClient, &ssh.OSFileReadWriter{})
	err = services.StartAndAwaitRunning(ctx, km)
	if err != nil {
		log.Fatalf("cannot start key manager: %s", err.Error())
	}

	// Whilst KeyManager is not passed to SSHClient, we need KM to have run before SSHClient is running.
	// TODO add dskit module manager to we can have a more formal dependency map

	// Create the SSH Service
	sshClient := ssh.NewClient(sshConfig)
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

If pdc-agent encounters a flag parsing error, it will run in legacy mode, where the arguments are passed directly to ssh.

Run %s <command> -h for more information
`, prog)
	}

	for _, r := range registerers {
		r(fs)
	}

	return fs.Usage, fs.Parse(os.Args[1:])
}
