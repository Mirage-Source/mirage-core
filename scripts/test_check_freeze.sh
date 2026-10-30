#!/usr/bin/env bash
# Checks for scripts/check_freeze.sh. Run: sh scripts/test_check_freeze.sh
set -u
here="$(cd "$(dirname "$0")" && pwd)"
fail=0
t() { # name expected_exit file_content override now
  local name="$1" want="$2" content="$3" override="$4" now="$5" f got
  f="$(mktemp)"; [ "$content" = "<none>" ] && rm -f "$f" || printf '%b' "$content" > "$f"
  NOW_EPOCH="$now" OVERRIDE_FREEZE="$override" bash "$here/check_freeze.sh" "$f" >/dev/null 2>&1; got=$?
  rm -f "$f"
  if [ "$got" = "$want" ]; then echo "  PASS  $name"; else echo "  FAIL  $name (exit $got, wanted $want)"; fail=1; fi
}
BEFORE=$(date -u -d '2026-11-10T22:00:00Z' +%s); AFTER=$(date -u -d '2026-11-10T22:30:00Z' +%s)
t "blocks a deploy before the freeze ends"        1 "2026-11-10T22:23:00Z\n" false "$BEFORE"
t "allows a deploy after the freeze ends"         0 "2026-11-10T22:23:00Z\n" false "$AFTER"
t "allows a deploy exactly at the end time"       0 "2026-11-10T22:23:00Z\n" false "$(date -u -d '2026-11-10T22:23:00Z' +%s)"
t "override lets a deploy through during freeze"  0 "2026-11-10T22:23:00Z\n" true  "$BEFORE"
t "no freeze file means no freeze"                0 "<none>"                  false "$BEFORE"
t "an empty file means no freeze"                 0 ""                        false "$BEFORE"
t "comment lines are skipped"                     1 "# why: self-test window\n2026-11-10T22:23:00Z\n" false "$BEFORE"
t "an unparseable date fails closed"              1 "tomorrow-ish\n"          false "$AFTER"
t "override only counts when exactly 'true'"      1 "2026-11-10T22:23:00Z\n" yes   "$BEFORE"
[ "$fail" = 0 ] && echo "all freeze checks passed"
exit "$fail"
