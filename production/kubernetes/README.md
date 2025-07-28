# Kubernetes config

There is a helm chart for the pdc-agent in the [grafana/helm-charts](https://github.com/grafana/helm-charts/tree/main/charts/pdc-agent) repository.

The helm chart assumes there is an existing Kubernetes secret containing an Access Policy Token for your PDC agent to use. For guidance on how to generate this token, see the [Grafana PDC docs pages](https://grafana.com/docs/grafana-cloud/connect-externally-hosted/private-data-source-connect/configure-pdc/).
