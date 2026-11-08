#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Usage: DEEPSEEK_API_KEY=... %s PROJECT [or RECEIVER_BUNDLE]\n' "$0" >&2
  exit 2
fi
if [[ -z ${DEEPSEEK_API_KEY:-} ]]; then
  printf 'DEEPSEEK_API_KEY is required at build time\n' >&2
  exit 2
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -f "$1" ]]; then
  bundle=$(realpath -- "$1")
else
  bundle="$root/keys/$1/receiver.json"
fi
if [[ ! -f "$bundle" ]]; then
  printf 'receiver bundle not found: %s\n' "$bundle" >&2
  exit 2
fi
if ! grep -q '"role": *"receiver"' "$bundle"; then
  printf 'not a receiver bundle: %s\n' "$bundle" >&2
  exit 2
fi
generated="$root/internal/embedded/generated.go"
cleanup() { rm -f -- "$generated"; }
trap cleanup EXIT INT TERM

umask 077
api_encoded=$(printf %s "$DEEPSEEK_API_KEY" | base64 | tr -d '\n')
bundle_encoded=$(base64 < "$bundle" | tr -d '\n')
unset DEEPSEEK_API_KEY
cat > "$generated" <<EOF
package embedded

func init() {
	apiKeyEncoded = "$api_encoded"
	receiverBundleEncoded = "$bundle_encoded"
}
EOF

cd "$root"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o c2dip-receiver ./cmd/c2dip-receiver
./c2dip-receiver --version >/dev/null
printf 'Dedicated receiver executable: %s/c2dip-receiver\n' "$root"
