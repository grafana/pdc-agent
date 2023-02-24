# Kubernetes config

This directory contains Kubernetes manifest templates for rolling out the PDC Agent.

It contains two manifests: `agent-bare.yaml`, which describes te agent Deployment, and `agent-secret-bare.yaml`, which describes the Secret which the Agent will need to connect to the PDC gateway. Both of these manifests are templates - they contain variables, so they cannot be used as-is.

## Installing 

### 1. Installing the Secret

To install the Secret, you will need to have received a signed **SSH Certificate** and a **known_hosts** file from Grafana.

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
  --from-file=key=./key \
  --from-file=known_hosts=./known_hosts \
  --from-file=cert.pub=./cert.pub
```

### 2. Installing the agent

Run the `install-agent.sh` script, with some required environment variables. Get the correct PDC_GATEWAY value from the Grafana team:

```
SLUG=slug PDC_GATEWAY=private-datasource-connect-prod-us-central-0.grafana.net ./install-agent.sh
```

This will create a manifest. Apply the manifest with

```
kubectl create -f deployment.yaml
```