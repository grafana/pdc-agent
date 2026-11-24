# Kubernetes config

This directory contains Kubernetes manifest templates for rolling out the PDC Agent.

Choose the Deployment template that matches the instructions shown in your Grafana Cloud instance:

- `pdc-agent-deployment.yaml` uses a cluster name.
- `pdc-agent-deployment-fqdn.yaml` uses explicit API and gateway fully qualified domain names (FQDNs).

Both templates read connection settings from a Secret named `grafana-pdc-agent` in the same namespace.

## Installing

### 1. Installing the Secret

Get the connection settings and PDC signing token from the **Private data source connections** page in your Grafana Cloud instance.

For cluster-based instructions, create the Secret with:

```
kubectl create secret generic -n ${NAMESPACE} grafana-pdc-agent \
  --from-literal="token=${GCLOUD_PDC_SIGNING_TOKEN}" \
  --from-literal="hosted-grafana-id=${GCLOUD_HOSTED_GRAFANA_ID}" \
  --from-literal="cluster=${GCLOUD_PDC_CLUSTER}"
```

For FQDN-based instructions, create the Secret with:

```sh
kubectl create secret generic -n ${NAMESPACE} grafana-pdc-agent \
  --from-literal="token=${GCLOUD_PDC_SIGNING_TOKEN}" \
  --from-literal="hosted-grafana-id=${GCLOUD_HOSTED_GRAFANA_ID}" \
  --from-literal="api-fqdn=${GCLOUD_PDC_API_FQDN}" \
  --from-literal="gateway-fqdn=${GCLOUD_PDC_GATEWAY_FQDN}"
```

Use hostnames without a URL scheme or path for the FQDN values.

### 2. Installing the agent

For cluster-based instructions, apply:

```
kubectl apply -n ${NAMESPACE} -f https://raw.githubusercontent.com/grafana/pdc-agent/main/production/kubernetes/pdc-agent-deployment.yaml
```

For FQDN-based instructions, apply:

```sh
kubectl apply -n ${NAMESPACE} -f https://raw.githubusercontent.com/grafana/pdc-agent/main/production/kubernetes/pdc-agent-deployment-fqdn.yaml
```
