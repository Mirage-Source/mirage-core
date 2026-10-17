#!/usr/bin/env bash
# Generate the SSH host keys the honeypot core presents to attackers.
# The core fatals if config/hostkey (ed25519) is missing; the RSA and ECDSA
# keys are optional but a stock Ubuntu sshd offers all three, so a sensor
# without them is distinguishable. Safe to re-run: existing keys are kept.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="$HERE/config/hostkey"
mkdir -p "$(dirname "$BASE")"

# OpenSSH format is what golang.org/x/crypto/ssh ParsePrivateKey expects.
# Sizes match ssh-keygen -A on Ubuntu 22.04 (RSA 3072, ECDSA P-256).
gen() {
  local path="$1"; shift
  if [[ -f "$path" ]]; then
    echo "host key already exists at $path -- leaving it untouched."
    return
  fi
  if [[ -d "$path" ]]; then
    # Left behind by a compose bind mount of a file that did not exist yet.
    rmdir "$path"
  fi
  ssh-keygen "$@" -f "$path" -N "" -C "" -q
  # The container runs as a non-root user; see DEPLOYMENT.md section 2.
  chmod 644 "$path"
  echo "wrote $path (and ${path}.pub)"
}

gen "$BASE" -t ed25519
gen "${BASE}_rsa" -t rsa -b 3072
gen "${BASE}_ecdsa" -t ecdsa -b 256
