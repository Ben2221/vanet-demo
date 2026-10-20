#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_IMAGE="${GO_IMAGE:-golang:1.20}"

# LOCAL_GO=/path/to/go runs the same steps with an installed Go toolchain instead of the
# golang image (e.g. when Docker Hub rate-limits the pull)
if [[ -n "${LOCAL_GO:-}" ]]; then
  cd "$SCRIPT_DIR"
  "$LOCAL_GO" mod tidy && "$LOCAL_GO" mod vendor && "$LOCAL_GO" test ./... && "$LOCAL_GO" build -o /tmp/vanetauth-build-check ./...
  exit
fi

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
