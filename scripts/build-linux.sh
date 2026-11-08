#!/usr/bin/env bash
# Requires Docker with BuildKit; builds a static binary for the Docker host's architecture.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
docker build --file "$root/Dockerfile" --output "type=local,dest=$root/dist" "$root"
printf 'Static Linux executable: %s/dist/c2dip\n' "$root"
