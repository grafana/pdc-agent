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

MANIFEST_BRANCH=main
MANIFEST_URL=${MANIFEST_URL:-https://raw.githubusercontent.com/grafana/agent/${MANIFEST_BRANCH}/production/kubernetes/agent.yaml}
NAMESPACE=${NAMESPACE:-default}

export NAMESPACE

curl -fsSL "$MANIFEST_URL" | envsubst
