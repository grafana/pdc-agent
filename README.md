# pdc-agent

The Grafana Private Datasource Connect Agent allows connecting private datasources with your grafana cloud instance.


### Releasing
Create public releases with `gh release create vX.X.X --generate-notes

Releases are managed using [goreleaser](https://goreleaser.com/). Use the following command to build binaries on your local machine.

```
goreleaser build --snapshot --rm-dist
```

If you want the docker image locally, you can run

```
goreleaser release --snapshot --rm-dist
```
