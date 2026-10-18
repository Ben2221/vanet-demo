#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_IMAGE="${GO_IMAGE:-golang:1.20}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to build vanetauth." >&2
  exit 1
fi

MSYS_NO_PATHCONV=1 docker run --rm \
  -e GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" \
  -v "$SCRIPT_DIR:/workspace" \
  -w /workspace \
  "$GO_IMAGE" \
  sh -c 'go mod tidy && go mod vendor && go test ./... && go build -o /tmp/vanetauth-build-check ./...'
