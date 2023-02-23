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

if [[ -z "$SLUG" ]] ; then
  echo "error: SLUG is not defined" >&2
  exit 1
fi

if [[ -z "$PDC_GATEWAY" ]] ; then
  echo "error: PDC_GATEWAY is not defined" >&2
  exit 1
fi

MANIFEST_BRANCH=${MANIFEST_BRANCH:-main}
MANIFEST_URL=${MANIFEST_URL:-https://raw.githubusercontent.com/grafana/pdc-agent/${MANIFEST_BRANCH}/production/kubernetes/agent.yaml}
NAMESPACE=${NAMESPACE:-default}

export NAMESPACE
export SLUG
export PDC_GATEWAY

curl -fsSL "$MANIFEST_URL" | envsubst | kubectl apply -f -
