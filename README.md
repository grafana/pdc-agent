# pdc-agent

The Grafana Private Datasource Connect Agent allows connecting private datasources with your grafana cloud instance.

## Installation

Follow installation and running instructions in the [Grafana Labs Documentation](https://grafana.com/docs/grafana-cloud/data-configuration/configure-private-datasource-connect/)

## Setting the ssh log level

Use the `-log.level` flag. Run the agent with the `-help` flag to see the possible values.

| go log level | ssh log level    |
| ------------ | ---------------- |
| `error`      | 0 (`-v` not set) |
| `warn`       | 0 (`-v` not set) |
| `info`       | 0 (`-v` not set) |
| `debug`      | 3 (`-vvv`)       |


## Available flags

You can print the flags for the PDC agent with `-h`:

```
./pdc -h         

Usage of ./pdc:
  -api-fqdn string
    	FQDN for the PDC API. If set, this will take precedence over the cluster and domain flags
  -cert-check-expiry-period duration
    	How often to check certificate validity. 0 means it is only checked at start (default 1m0s)
  -cert-expiry-window duration
    	The time before the certificate expires to renew it. (default 5m0s)
  -cluster string
    	the PDC cluster to connect to use
  -dev-api-port string
    	[DEVELOPMENT ONLY] The port to use for agent connections to the PDC API (default "9181")
  -dev-mode
    	[DEVELOPMENT ONLY] run the agent in development mode
  -dev-network string
    	[DEVELOPMENT ONLY] the network the agent will connect to
  -dev-ssh-port int
    	[DEVELOPMENT ONLY] The port to use for agent connections to the PDC SSH gateway (default 2244)
  -domain string
    	the domain of the PDC cluster (default "grafana.net")
  -force-key-file-overwrite
    	Force a new ssh key pair to be generated
  -gateway-fqdn string
    	FQDN for the PDC Gateway. If set, this will take precedence over the cluster and domain flags
  -gcloud-hosted-grafana-id string
    	The ID of the Hosted Grafana instance to connect to
  -h	Print help
  -log.level string
    	"debug", "info", "warn" or "error" (default "info")
  -metrics-addr string
    	HTTP server address to expose metrics on (default ":8090")
  -network string
    	DEPRECATED: The name of the PDC network to connect to
  -parse-metrics
    	Enabled or disable parsing of metrics from the ssh logs (default true)
  -retrymax int
    	The max num of retries for http requests (default 4)
  -skip-ssh-validation
    	Ignore openssh minimum version constraints.
  -ssh-flag value
    	Additional flags to be passed to ssh. Can be set more than once.
  -ssh-key-file string
    	The path to the SSH key file. (default "/Users/daf/.ssh/grafana_pdc")
  -token string
    	The token to use to authenticate with Grafana Cloud. It must have the pdc-signing:write scope


If pdc is run with SSH flags, it will pass all arguments directly through to the "ssh" binary. This is deprecated behaviour.

Run ./pdc <command> -h for more information

```

## DEV flags

Flags prefixed with `-dev` are used for local development and can be removed at any time.

# Developer guide

## Dependencies

You will need the following dependencies to test and build the pdc-agent:

- git
- go (see [`go.mod`](./go.mod) for minimum required version)
- [golangci-lint](https://golangci-lint.run/)
- [gh](https://cli.github.com/), the GitHub cli (for releasing only)


## Build and test

Run unit tests, lint and build with:

```
make
```


## Releasing

Create public releases with `gh release create vX.X.X --generate-notes`

Releases are managed using [goreleaser](https://goreleaser.com/). Use the following command to build binaries on your local machine.

```
goreleaser build --snapshot --clean
```

If you want the docker image locally, you can run

```
goreleaser release --snapshot --clean
```
