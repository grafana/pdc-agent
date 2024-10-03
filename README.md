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

| Flag                        | Environment Variable                      |
|-----------------------------|-------------------------------------------|
| `-token`                    | `GCLOUD_PDC_SIGNING_TOKEN`                |
| `-cluster`                  | `GCLOUD_PDC_CLUSTER`                      |
| `-gcloud-hosted-grafana-id` | `GCLOUD_PDC_GCLOUD_HOSTED_GRAFANA_ID`     |
| `-ssh-key-file`             | `GCLOUD_PDC_SSH_KEY_FILE`                 |
| `-log-level`                | `GCLOUD_PDC_SSH_LOG_LEVEL`                |
| `-skip-ssh-validation`      | `GCLOUD_PDC_SSH_SKIP_SSH_VALIDATION`      |
| `-ssh-flag`                 | `GCLOUD_PDC_SSH_ADDITIONAL_SSH_FLAGS`†    |
| `-force-key-file-overwrite` | `GCLOUD_PDC_SSH_FORCE_KEY_FILE_OVERWRITE` |
| `-cert-expiry-window`       | `GCLOUD_PDC_SSH_CERT_EXPIRY_WINDOW`       |
| `-cert-check-expiry-period` | `GCLOUD_PDC_SSH_CERT_CHECK_EXPIRY_PERIOD` |
| `-metrics-addr`             | `GCLOUD_PDC_SSH_METRICS_ADDR`             |

† - This flag, unlike the others, is _additive_ with arguments provided via `-ssh-flag`, not overridden by them

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
