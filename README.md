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
