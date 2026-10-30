#!/usr/bin/env bash
# Refuses a deploy while a freeze is active.
#
#   check_freeze.sh deploy/FREEZE_UNTIL
#
# The file holds one UTC timestamp (first non-comment line). Before that instant the script exits 1. A missing or
# empty file means no freeze. An unparseable timestamp fails closed. OVERRIDE_FREEZE=true bypasses the check
# (nothing else does). NOW_EPOCH replaces the clock, for tests.
set -u
file="${1:-}"

if [ "${OVERRIDE_FREEZE:-}" = "true" ]; then
  echo "freeze check overridden"
  exit 0
fi
[ -f "$file" ] || { echo "no freeze file: not frozen"; exit 0; }

line="$(grep -v -E '^[[:space:]]*(#|$)' "$file" | head -n1 || true)"
[ -n "$line" ] || { echo "empty freeze file: not frozen"; exit 0; }

until_epoch="$(date -u -d "$line" +%s 2>/dev/null)" || { echo "cannot parse freeze time '$line': refusing" >&2; exit 1; }
now="${NOW_EPOCH:-$(date -u +%s)}"
if [ "$now" -lt "$until_epoch" ]; then
  echo "refusing: deploys are frozen until $line (set override_freeze to bypass)" >&2
  exit 1
fi
echo "freeze ended at $line"
