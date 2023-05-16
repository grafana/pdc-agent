# Kubernetes config

This directory contains Kubernetes manifest templates for rolling out the PDC Agent.

It contains two manifests: `agent-bare.yaml`, which describes te agent Deployment, and `agent-secret-bare.yaml`, which describes the Secret which the Agent will need to connect to the PDC gateway. Both of these manifests are templates - they contain variables, so they cannot be used as-is.

## Installing 

### 1. Installing the Secret

To install the Secret, you will need to have a **Grafana API token**, which you can generate from the **Private data source connections** page in your Grafana Cloud instance.

**Option 1:** use the script

```
[NAMESPACE=namespace] install-agent-secret.sh
``` 

from within this directory. This will create a manifest file. Then you will need to create the secret using the manifest: 

```
kubectl create -f secret.yaml
```

**Option 2:** create with the kubectl helper:

```
kubectl create secret generic -n ${NAMESPACE} grafana-pdc-agent \
  --from-literal="token=${GCLOUD_PDC_SIGNING_TOKEN}"
```

### 2. Installing the agent

Run the `install-agent.sh` script, with some required environment variables. Get the correct env var values from the **Private data source connections** page in your Grafana Cloud instance:

```
GCLOUD_HOSTED_GRAFANA_ID=<id> GCLOUD_PDC_CLUSTER=<cluster> ./install-agent.sh
```

This will create a manifest. Apply the manifest with

```
kubectl create -f deployment.yaml
```
