#!/usr/bin/env bash
# shellcheck shell=bash

check_installed() {
  if ! type "$1" >/dev/null 2>&1; then
    echo "error: $1 not installed" >&2
    exit 1
  fi
}

check_file_exists() {
  if ! [[ -f "$1" ]] ; then
    echo "error: $1 does not exist" >&2
    exit 1
  fi
}

check_installed curl
check_installed envsubst

check_file_exists token

TOKEN=$(base64 < token)

MANIFEST_BRANCH=${MANIFEST_BRANCH:-main}
MANIFEST_URL=${MANIFEST_URL:-https://raw.githubusercontent.com/grafana/pdc-agent/${MANIFEST_BRANCH}/production/kubernetes/agent-secret-bare.yaml}
NAMESPACE=${NAMESPACE:-default}
OUTFILE=${OUTFILE:-secret.yaml}

export NAMESPACE
export TOKEN

curl -fsSLv "$MANIFEST_URL" | envsubst > "$OUTFILE"
