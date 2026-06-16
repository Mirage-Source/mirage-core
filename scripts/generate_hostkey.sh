#!/usr/bin/env bash
# Generate the SSH host key the honeypot core presents to attackers.
# The core fatals if core/config/hostkey is missing. Run once before `up`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY="$HERE/core/config/hostkey"

mkdir -p "$(dirname "$KEY")"
if [[ -f "$KEY" ]]; then
  echo "host key already exists at $KEY -- leaving it untouched."
  exit 0
fi

# Ed25519 is small and modern; OpenSSH PEM format is what golang.org/x/crypto/ssh
# ParsePrivateKey expects.
ssh-keygen -t ed25519 -f "$KEY" -N "" -C "mirage-honeypot" -q
echo "wrote $KEY (and ${KEY}.pub)"
