# Kubernetes config

This directory contains Kubernetes manifest templates for rolling out the PDC Agent.

It contains two manifests: `agent-bare.yaml`, which describes te agent Deployment, and `agent-secret-bare.yaml`, which describes the Secret which the Agent will need to connect to the PDC gateway. Both of these manifests are templates - they contain variables, so they cannot be used as-is.

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
