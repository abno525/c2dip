#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o c2dip ./cmd/c2dip
printf 'Static Linux executable: %s/c2dip\n' "$root"
