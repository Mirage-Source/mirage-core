#!/usr/bin/env python3
"""The analysis pre-registered in selftest_intervention.md. Run once, after the window closes.

  python3 experiments/selftest_intervention_analysis.py --db nur --host <socket or host> --user mirage \
      --deploy-ts 2026-11-05T12:00:00Z --new-build <build_sha>

--deploy-ts is the UTC time of the first session that carries the new build_sha (the deploy log
records it). Sessions before it are the baseline; sessions from it on are the treatment window.
--dry-run labels the output and skips the build-stamp filter, for running this on a snapshot that
predates the stamp (the Nuremberg snapshot of 2026-10-27 has no build_sha column).

Nothing here is tuned to a result: every threshold is a constant below and in the document.
"""
import argparse
import hashlib
import statistics
import sys
from datetime import datetime, timedelta, timezone

import psycopg2

# the three variants of the fingerprinting command, by SHA-256 of the raw bytes
VARIANTS = {
    "9dc0f0fe6a402818d0335f679d265004acff9194dd2b7e846fa757fbc4b48ddc": "p1 (3273 B)",
    "7002e7827601cc7ba13bf63b9afd02c347af3ac752e74f3509166c89084925dd": "p2 (11956 B)",
    "ec1c737137828e2e91709f272988c67c01159511d40141531748663fbe16ec8a": "p3 (10972 B)",
}
# SHA-256 of the sorted, newline-joined list of the 18 addresses that sent the command before 2026-10-27
REGISTERED_ADDRESS_SHA = "0a7c2808b0c8f3e4109b577f42dd24ae831e90e6b5e1b6595d64e501f29fabce"
MIN_SESSIONS, MIN_ADDRESSES = 300, 8   # activation: enough exposure for the test to mean anything
REJECT_AT_K = 3                        # reject the null if this many baseline addresses qualify
MIN_DELIVERED = 0.90                   # share of post sessions whose probe was answered in full
WINDOW_DAYS, MAX_WINDOW_DAYS = 14, 28

SQL = """
SELECT s.session_id, s.client_ip::text, s.start_ms, s.duration_ms, {build},
       c.sequence_number, encode(sha256(decode(c.raw_input_b64,'base64')),'hex'),
       (position('UNAME:' in coalesce(c.response_text,'')) > 0
        AND position('FILTER:' in coalesce(c.response_text,'')) > 0),
       coalesce(c.deception_action,'')
FROM sessions s JOIN commands c USING (session_id)
WHERE s.session_id IN (SELECT session_id FROM commands
                       WHERE position('===SHELL_BEHAVIOR===' in convert_from(decode(raw_input_b64,'base64'),'UTF8')) > 0)
ORDER BY s.session_id, c.sequence_number
"""


def median(xs):
    return statistics.median(xs) if xs else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--user", default="mirage")
    ap.add_argument("--deploy-ts", required=True)
    ap.add_argument("--new-build", default="")
    ap.add_argument("--window-days", type=int, default=WINDOW_DAYS)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    deploy = datetime.fromisoformat(a.deploy_ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    dms = int(deploy.timestamp() * 1000)
    end_ms = int((deploy + timedelta(days=min(a.window_days, MAX_WINDOW_DAYS))).timestamp() * 1000)
    cur = psycopg2.connect(host=a.host, user=a.user, dbname=a.db).cursor()
    cur.execute("SELECT 1 FROM information_schema.columns WHERE table_name='sessions' AND column_name='build_sha'")
    has_build = cur.fetchone() is not None
    if not has_build and not a.dry_run:
        sys.exit("sessions has no build_sha column: this is not data from the new build (use --dry-run to test)")
    cur.execute(SQL.format(build="s.build_sha" if has_build else "''"))

    sess = {}
    for sid, ip, start, dur, build, seq, sha, done, action in cur.fetchall():
        s = sess.setdefault(sid, dict(ip=ip, start=start, dur=dur, build=build, cmds=[], actions=set()))
        s["cmds"].append((seq, sha, done))
        s["actions"].add(action)

    label = "DRY RUN (no build filter)" if a.dry_run else f"build {a.new_build}"
    print(f"== self-test intervention analysis: {label}; deploy {deploy:%Y-%m-%d %H:%M}Z; window {a.window_days} d ==")

    base = {k: v for k, v in sess.items() if v["start"] < dms}
    post = {k: v for k, v in sess.items() if dms <= v["start"] < end_ms and (a.dry_run or v["build"].startswith(a.new_build))}
    base_ips = sorted({v["ip"] for v in base.values()})
    sha = hashlib.sha256("\n".join(base_ips).encode()).hexdigest()
    print(f"baseline: {len(base)} probe sessions from {len(base_ips)} addresses; "
          f"address-list sha256 {'matches' if sha == REGISTERED_ADDRESS_SHA else 'DIFFERS from'} the registered one")

    # activation
    p_ips = {v["ip"] for v in post.values()}
    exposed = p_ips & set(base_ips)
    print(f"\n[activation] post probe sessions {len(post)} (need {MIN_SESSIONS}), baseline addresses seen {len(exposed)} (need {MIN_ADDRESSES})")
    active = len(post) >= MIN_SESSIONS and len(exposed) >= MIN_ADDRESSES

    # treatment delivered: both variants answered in full, in the session
    def delivered(v):
        probes = [d for (_, h, d) in v["cmds"] if h in VARIANTS]
        return bool(probes) and all(probes)
    dshare = sum(delivered(v) for v in post.values()) / len(post) if post else float("nan")
    print(f"[delivery] probe answered in full in {dshare:.1%} of post sessions (need {MIN_DELIVERED:.0%})")

    # primary: a probe session that also runs a command which is not a probe variant
    def qualifies(v):
        return any(h not in VARIANTS for (_, h, _) in v["cmds"])
    q_base = {v["ip"] for v in base.values() if qualifies(v)}
    q_post_sessions = [v for v in post.values() if qualifies(v)]
    k = len({v["ip"] for v in q_post_sessions} & set(base_ips))
    print(f"\n[primary] baseline: {sum(qualifies(v) for v in base.values())} qualifying sessions, {len(q_base)} addresses")
    print(f"[primary] post: {len(q_post_sessions)} qualifying sessions; K = {k} baseline addresses with one (reject at K >= {REJECT_AT_K})")
    if not active:
        verdict = "NOT TESTABLE: not enough probe traffic after the deploy (this is not a null)"
    elif dshare < MIN_DELIVERED:
        verdict = "NOT TESTABLE: the probe was not answered in full often enough (treatment not delivered)"
    elif k >= REJECT_AT_K:
        verdict = f"REJECT the null: {k} addresses proceeded"
    else:
        verdict = f"DO NOT REJECT: {k} of {len(exposed)} exposed addresses proceeded; the design detects ~1 in 4 at 80% power"
    print(f"[verdict] {verdict}")

    # secondary: how often a variant is run per session (the bots retry on failure), and how long they stay
    def runs(group):
        return [sum(1 for (_, h, _) in v["cmds"] if h == sha_) for v in group.values()
                for sha_ in {h for (_, h, _) in v["cmds"] if h in VARIANTS}]
    print(f"\n[secondary] runs of one variant per session: baseline median {median(runs(base))}, post median {median(runs(post))}")
    print(f"[secondary] session duration ms: baseline median {median([v['dur'] for v in base.values() if v['dur'] is not None])}, "
          f"post median {median([v['dur'] for v in post.values() if v['dur'] is not None])}")

    # covariates and sensitivity
    acts = sorted({x for v in post.values() for x in v["actions"]})
    print(f"[covariate] deception_action values in post sessions: {acts}")
    new_ips = p_ips - set(base_ips)
    print(f"[sensitivity] addresses not in the baseline list that sent the probe after the deploy: {len(new_ips)}")


if __name__ == "__main__":
    main()
