# Kubernetes config

This directory contains a Kubernetes manifest for rolling out the PDC Agent.

`pdc-agent-deployment.yaml` describes the agent Deployment. It reads its connection settings from a Secret named `grafana-pdc-agent`, which you create in step 1.

## Installing 

### 1. Installing the Secret

To install the Secret, you will need to get the required environment variables and a Grafana API token, which you can get from the **Private data source connections** page in your Grafana Cloud instance.

Create a secret with the kubectl helper:

```
kubectl create secret generic -n ${NAMESPACE} grafana-pdc-agent \
  --from-literal="token=${GCLOUD_PDC_SIGNING_TOKEN}" \
  --from-literal="hosted-grafana-id=${GCLOUD_HOSTED_GRAFANA_ID}" \
  --from-literal="cluster=${GCLOUD_PDC_CLUSTER}"
```

### 2. Installing the agent

Create a pdc-agent deployment with:

```
kubectl apply -n ${NAMESPACE} -f https://raw.githubusercontent.com/grafana/pdc-agent/main/production/kubernetes/pdc-agent-deployment.yaml
```

### Clusters that use the region URL format

By default the agent connects to `private-datasource-connect-api-<cluster>.grafana.net`. Some clusters
use the region URL format instead, `private-datasource-connect-api.<cluster>.grafana.net`. With the
wrong format the agent fails to sign its key, logs `key signing request failed`, and restarts.

To check which format your cluster uses, compare the HTTP status of both API hosts. The one that
exists answers `401` without credentials:

```
curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://private-datasource-connect-api-${GCLOUD_PDC_CLUSTER}.grafana.net/pdc/api/v1/sign-public-key"
curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://private-datasource-connect-api.${GCLOUD_PDC_CLUSTER}.grafana.net/pdc/api/v1/sign-public-key"
```

If only the second one answers `401`, download the manifest, uncomment the `-region-format` argument,
and apply your local copy instead of the URL above.
