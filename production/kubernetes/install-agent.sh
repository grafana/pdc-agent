#!/usr/bin/env bash
# shellcheck shell=bash


check_installed() {
  if ! type "$1" >/dev/null 2>&1; then
    echo "error: $1 not installed" >&2
    exit 1
  fi
}

check_installed curl
check_installed envsubst

if [[ -z "$GCLOUD_HOSTED_GRAFANA_ID" ]] ; then
  echo "error: GCLOUD_HOSTED_GRAFANA_ID is not defined" >&2
  exit 1
fi

if [[ -z "$GCLOUD_PDC_CLUSTER" ]] ; then
  echo "error: GCLOUD_PDC_CLUSTER is not defined" >&2
  exit 1
fi

MANIFEST_BRANCH=${MANIFEST_BRANCH:-main}
MANIFEST_URL=${MANIFEST_URL:-https://raw.githubusercontent.com/grafana/pdc-agent/${MANIFEST_BRANCH}/production/kubernetes/agent-bare.yaml}
NAMESPACE=${NAMESPACE:-default}
OUTFILE=${OUTFILE:-deployment.yaml}


export NAMESPACE
export GCLOUD_HOSTED_GRAFANA_ID
export GCLOUD_PDC_CLUSTER

curl -fsSL "$MANIFEST_URL" | envsubst > "$OUTFILE"
