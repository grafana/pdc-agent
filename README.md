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

## Environment Variables and Flags

If using commandline flags is difficult to use in your environment, you can define environment variables to be consumed by the PDC Agent instead. *Commandline flags always take precedence.*

The following mappings are currently provided:

| Flag                        | Environment Variable                  |
| --------------------------- | ------------------------------------- |
| `-token`                    | `GCLOUD_PDC_SIGNING_TOKEN`            |
| `-cluster`                  | `GCLOUD_PDC_CLUSTER`                  |
| `-gcloud-hosted-grafana-id` | `GCLOUD_PDC_GCLOUD_HOSTED_GRAFANA_ID` |

## DEV flags

Flags prefixed with `-dev` are used for local development and can be removed at any time.

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

## Building

`CGO_ENABLED=0 go build ./cmd/pdc`
