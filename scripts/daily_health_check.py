#!/usr/bin/env python3
"""Daily check that the sensor pipeline is capturing sane data.

Catches the silent failures documented in the preprint, where every component
kept running and nothing alerted:
  - an authentication callback that accepted every credential (acceptance
    ~100% for 25 days),
  - one that rejected every credential (acceptance ~0%),
  - days with no sessions at all (downtime that looked like quiet traffic).

For each UTC day it checks session volume against the trailing median and the
password-acceptance rate against fixed bounds. Three further checks do not depend
on a rate threshold:
  - accepted pairs: every distinct user:pass accepted on a day must be on the
    sensor's accept list. This catches accept-everything at any traffic level and
    works for Telnet, whose ~68% acceptance is policy, not health;
  - heartbeats: any silent gap longer than --max-gap-min on any sensor, and a
    latest heartbeat older than --max-age-min. Daily counts miss a 2 h 34 min
    outage inside a busy day;
  - hour coverage: runs of hours with no sessions that are unprecedented for the sensor (in
    the last week even the quietest 5% of hours had >= --hour-floor sessions). A capture failure leaves the sensor up and beating (60
    heartbeats in an hour with no sessions occurred in the Nuremberg data), and a
    sensor without a heartbeat table (Frankfurt) has no other outage detector;
  - build stamp (--check-builds): sessions written with build_sha 'unknown' (an
    unstamped build) or '' (an old binary).
A missing accept list is itself a finding: skipping the check silently is the
failure this tool exists to prevent. Exit status is 1 if anything is flagged, so
it can run from cron or CI and page on failure.

    DATABASE_URL=postgres://... scripts/daily_health_check.py [--check-builds]
    scripts/daily_health_check.py --csv days.csv      # offline: date,sessions,attempts,accepted
    # offline extras: --accepted-csv date,username,credential  --heartbeats-csv sensor_id,ts
    #                 --builds-csv date,build_sha,sessions  --accept-list FILE  --now ISO

Defaults come from measurement, and each has the figure it rests on:
  heartbeat gap/age 5 min   123,650 heartbeat intervals: median 60.0 s, largest normal 64.6 s;
                            the only two over 90 s were real outages (16 min, 2 h 34 min)
  acceptance 1% - 25%       normal SSH days 2.3% (Frankfurt, post-fix) to 11.4% (Nuremberg);
                            reject-everything is 0%, accept-everything 61.6% - 100%
  empty hour, floor 5       Telnet is bursty (17% of hours under 10 sessions, 5th percentile 4), so a
                            median is not enough; SSH's quietest 5% of hours stay far above 5
They rest on two sensors, so review them for a third; every one has a flag.
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path


@dataclass
class Thresholds:
    min_sessions: int = 1          # fewer sessions than this counts as no data
    min_attempts_for_rate: int = 100
    min_accept: float = 0.01       # below: looks like reject-everything (lowest normal day: 2.3%)
    max_accept: float = 0.25       # above: looks like accept-everything (highest normal day: 11.4%)
    drop_frac: float = 0.25        # volume below this fraction of the median ...
    hard_drop_frac: float = 0.05   # ... counts only if an hour was empty, or it is below this
    hour_floor: int = 5            # an empty hour is judged only if the quietest 5% of last week's hours had this many
    hour_history: int = 168        # hours of history behind "typical"
    min_hour_history: int = 12     # populated hours needed before judging
    history_days: int = 14
    min_history: int = 7           # prior days needed before the volume check applies
    max_heartbeat_gap_min: int = 5    # heartbeats are 60 s apart (largest normal: 64.6 s); outages were 16+ min
    max_heartbeat_age_min: int = 5    # latest heartbeat older than this: the sensor is down now


def evaluate(rows, t: Thresholds | None = None):
    """Return a list of {date, kind, detail} findings for the given daily rows.

    rows: dicts with date (ISO string), sessions, attempts, accepted. Calendar
    days between the first and last row that are missing are treated as zero.
    """
    t = t or Thresholds()
    if not rows:
        return []
    by_day = {date.fromisoformat(r["date"]): r for r in rows}
    first, last = min(by_day), max(by_day)
    findings, history = [], []
    d = first
    while d <= last:
        r = by_day.get(d, {"sessions": 0, "attempts": 0, "accepted": 0})
        iso = d.isoformat()
        if r["sessions"] < t.min_sessions:
            findings.append({"date": iso, "kind": "no_sessions",
                             "detail": f"{r['sessions']} sessions"})
        else:
            prior = history[-t.history_days:]
            if len(prior) >= t.min_history:
                med = statistics.median(prior)
                # A lower total with sessions in every hour means the sensor was receiving all day:
                # traffic changed, capture did not fail (Nuremberg 2026-09-21: 15% of median, 24/24 hours).
                full_day = r.get("active_hours") == 24
                if r["sessions"] < t.drop_frac * med and (not full_day or r["sessions"] < t.hard_drop_frac * med):
                    findings.append({"date": iso, "kind": "volume_drop",
                                     "detail": f"{r['sessions']} sessions vs trailing median {med:.0f}"})
            if r["attempts"] >= t.min_attempts_for_rate:
                rate = r["accepted"] / r["attempts"]
                if rate > t.max_accept:
                    findings.append({"date": iso, "kind": "acceptance_too_high",
                                     "detail": f"{rate:.1%} of {r['attempts']} attempts accepted"})
                elif rate < t.min_accept:
                    findings.append({"date": iso, "kind": "acceptance_too_low",
                                     "detail": f"{rate:.2%} of {r['attempts']} attempts accepted"})
            history.append(r["sessions"])
        d += timedelta(days=1)
    return findings


def parse_ts(text: str) -> datetime:
    """ISO-ish timestamp (psql prints '2026-10-18 08:53:52.657699+00') as an aware UTC datetime."""
    t = text.strip().replace("Z", "+00:00").replace(" ", "T", 1)
    t = re.sub(r"([+-]\d\d)$", r"\1:00", t)
    dt = datetime.fromisoformat(t)
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def parse_accept_list(text: str) -> set:
    """Same rule as the server (loadWeakCredentials): one trimmed 'user:pass' per line, # comments."""
    return {l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")}


def check_accepted_pairs(accepted_by_day: dict, allowed: set):
    findings = []
    for day_, pairs in sorted(accepted_by_day.items()):
        bad = sorted(set(pairs) - allowed)
        if bad:
            sample = ", ".join(repr(b[:24]) for b in bad[:3])
            findings.append({"date": day_, "kind": "accepted_pair_not_listed",
                             "detail": f"{len(bad)} accepted pair(s) not on the accept list, e.g. {sample}"})
    return findings


def _span(seconds: float) -> str:
    m = int(seconds / 60 + 0.5)
    return f"{m // 60} h {m % 60} min" if m >= 60 else f"{m} min"


def check_heartbeats(beats, now: datetime | None = None, t: Thresholds | None = None):
    """beats: iterable of (sensor_id, aware datetime). Each sensor is checked on its own,
    because a healthy stream must not hide a silent one."""
    t = t or Thresholds()
    per = {}
    for sensor, ts in beats:
        per.setdefault(sensor, []).append(ts)
    findings = []
    for sensor, stamps in per.items():
        stamps.sort()
        for a, b in zip(stamps, stamps[1:]):
            if (b - a).total_seconds() > t.max_heartbeat_gap_min * 60:
                findings.append({"date": a.date().isoformat(), "kind": "heartbeat_gap", "_at": a,
                                 "detail": f"{sensor}: no heartbeat for {_span((b - a).total_seconds())} "
                                           f"({a:%Y-%m-%d %H:%M} to {b:%H:%M} UTC)"})
        if now is not None and (now - stamps[-1]).total_seconds() > t.max_heartbeat_age_min * 60:
            findings.append({"date": now.date().isoformat(), "kind": "heartbeat_stale", "_at": now,
                             "detail": f"{sensor}: last heartbeat {_span((now - stamps[-1]).total_seconds())} ago"})
    findings.sort(key=lambda f: f["_at"])
    for f in findings:
        del f["_at"]
    return findings


def _hour(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def check_hour_coverage(hours, now: datetime | None = None, t: Thresholds | None = None):
    """hours: (aware datetime, sessions) for hours that had any. Reports each run of empty hours
    between the first populated hour and the last (or the last complete hour before `now`, which
    is what exposes an outage still in progress), if it is unprecedented: in the preceding week
    even the quietest 5% of populated hours had at least hour_floor sessions. A rate threshold
    alone fails on bursty traffic (17% of Nuremberg's Telnet hours had under 10 sessions)."""
    t = t or Thresholds()
    counts = {_hour(h): n for h, n in hours}
    if not counts:
        return []
    first, last = min(counts), max(counts)
    if now is not None:
        last = max(last, _hour(now) - timedelta(hours=1))
    series = [first + timedelta(hours=i) for i in range(int((last - first).total_seconds() // 3600) + 1)]
    findings, i = [], 0
    while i < len(series):
        if counts.get(series[i], 0) > 0:
            i += 1
            continue
        j = i
        while j + 1 < len(series) and counts.get(series[j + 1], 0) == 0:
            j += 1
        past = sorted(counts[h] for h in series[max(0, i - t.hour_history):i] if counts.get(h, 0) > 0)
        if len(past) >= t.min_hour_history and past[int(0.05 * len(past))] >= t.hour_floor:
            n, a, b = j - i + 1, series[i], series[j]
            findings.append({"date": a.date().isoformat(), "kind": "empty_hours",
                             "detail": f"{n} empty hour(s), {a:%Y-%m-%d %H:%M} to {b:%H:59} UTC "
                                       f"(typical hour has {statistics.median(past):.0f}, quietest 5% at least {past[int(0.05 * len(past))]})"})
        i = j + 1
    return findings


def check_builds(rows):
    """rows: (date, build_sha, sessions). 'unknown' is an unstamped build, '' an old binary."""
    findings = []
    for day_, sha, n in sorted(rows):
        if sha == "unknown":
            findings.append({"date": day_, "kind": "build_unknown",
                             "detail": f"{n} sessions from an unstamped build (deploy with BUILD_SHA set)"})
        elif sha == "":
            findings.append({"date": day_, "kind": "build_blank",
                             "detail": f"{n} sessions with no build_sha (a binary older than schema 1.2)"})
    return findings


SQL = """
WITH s AS (
  SELECT (to_timestamp(start_ms/1000.0) AT TIME ZONE 'UTC')::date d, count(*) sessions,
         count(DISTINCT date_trunc('hour', to_timestamp(start_ms/1000.0) AT TIME ZONE 'UTC')) active_hours
  FROM sessions WHERE {proto_s} start_ms >= extract(epoch FROM now() - interval '{days} days')*1000 GROUP BY 1),
a AS (
  SELECT (to_timestamp(a.timestamp_ms/1000.0) AT TIME ZONE 'UTC')::date d,
         count(*) attempts, count(*) FILTER (WHERE a.success) accepted
  FROM auth_attempts a JOIN sessions USING (session_id)
  WHERE a.method = 'password' {proto_a}
    AND a.timestamp_ms >= extract(epoch FROM now() - interval '{days} days')*1000 GROUP BY 1)
SELECT d, coalesce(sessions,0), coalesce(attempts,0), coalesce(accepted,0), coalesce(active_hours,0)
FROM s FULL JOIN a USING (d) ORDER BY d
"""


def load_db(dsn: str, days: int, protocol: str = "ssh"):
    # Acceptance differs by protocol (Nuremberg: SSH ~5%, Telnet ~68%), so a
    # mixed rate would false-alarm. Check each protocol separately.
    proto_s = "" if protocol == "any" else f"protocol = '{protocol}' AND"
    proto_a = "" if protocol == "any" else f"AND sessions.protocol = '{protocol}'"
    out = subprocess.run(["psql", dsn, "-At", "-F", ",", "-c",
                          SQL.format(days=days, proto_s=proto_s, proto_a=proto_a)],
                         capture_output=True, text=True, check=True).stdout
    return [dict(zip(("date", "sessions", "attempts", "accepted", "active_hours"), line.split(",")))
            for line in out.splitlines() if line]


def load_csv(path: str):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _psql_csv(dsn: str, sql: str):
    # --csv quotes properly; credentials may contain commas and quotes.
    out = subprocess.run(["psql", dsn, "--csv", "-c", sql], capture_output=True, text=True, check=True).stdout
    return list(csv.DictReader(io.StringIO(out)))


def _proto(protocol: str, alias: str = "") -> str:
    return "" if protocol == "any" else f"AND {alias}protocol = '{protocol}'"


def load_accepted_db(dsn: str, days: int, protocol: str):
    return _psql_csv(dsn, f"""SELECT DISTINCT (to_timestamp(a.timestamp_ms/1000.0) AT TIME ZONE 'UTC')::date AS date,
        a.username, a.credential FROM auth_attempts a JOIN sessions s USING (session_id)
        WHERE a.method = 'password' AND a.success {_proto(protocol, 's.')}
          AND a.timestamp_ms >= extract(epoch FROM now() - interval '{days} days')*1000""")


def load_hours_db(dsn: str, days: int, protocol: str):
    return _psql_csv(dsn, f"""SELECT to_char(date_trunc('hour', to_timestamp(start_ms/1000.0) AT TIME ZONE 'UTC'),
        'YYYY-MM-DD HH24:00:00') AS hour, count(*) AS sessions FROM sessions WHERE true {_proto(protocol)}
        AND start_ms >= extract(epoch FROM now() - interval '{days} days')*1000 GROUP BY 1""")


def load_heartbeats_db(dsn: str, days: int):
    return _psql_csv(dsn, f"SELECT sensor_id, ts FROM sensor_heartbeats "
                          f"WHERE ts::timestamptz >= now() - interval '{days} days' ORDER BY 1, 2")  # cast: no-op on the real column


def load_builds_db(dsn: str, days: int, protocol: str):
    return _psql_csv(dsn, f"""SELECT (to_timestamp(start_ms/1000.0) AT TIME ZONE 'UTC')::date AS date, build_sha,
        count(*) AS sessions FROM sessions WHERE true {_proto(protocol)}
        AND start_ms >= extract(epoch FROM now() - interval '{days} days')*1000 GROUP BY 1, 2""")


def default_accept_list(protocol: str) -> Path:
    cfg = Path(__file__).resolve().parent.parent / "config"
    if protocol == "telnet":
        return Path(os.environ.get("TELNET_WEAK_CREDENTIALS_FILE") or cfg / "telnet_weak_credentials.txt")
    return Path(os.environ.get("WEAK_CREDENTIALS_FILE") or cfg / "weak_credentials.txt")


def _guarded(name, load, always):
    """Run one optional loader. A failure (say a missing table) becomes a finding, so one broken
    check neither crashes the run nor hides what the other checks found."""
    try:
        return load()
    except subprocess.CalledProcessError as e:
        first = (e.stderr or "").strip().splitlines()[:1]
        always.append({"date": date.today().isoformat(), "kind": "check_failed",
                       "detail": f"{name} could not run: {first[0] if first else e}"})
        return None


def _accept_list(path_arg, protocol):
    """The accept list for the protocol(s) being checked, or None if it cannot be read."""
    paths = ([Path(path_arg)] if path_arg else
             [default_accept_list("ssh"), default_accept_list("telnet")] if protocol == "any" else
             [default_accept_list(protocol)])
    try:
        return set().union(*(parse_accept_list(p.read_text()) for p in paths))
    except OSError:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dsn", default=os.environ.get("DATABASE_URL"))
    ap.add_argument("--csv", help="read date,sessions,attempts,accepted rows instead of the database")
    ap.add_argument("--protocol", default="ssh", choices=["ssh", "telnet", "any"],
                    help="which protocol's sessions and attempts to check (default ssh)")
    ap.add_argument("--lookback", type=int, default=30, help="days of history to read")
    ap.add_argument("--report-days", type=int, default=2, help="only report findings this recent")
    ap.add_argument("--all", action="store_true", help="report findings for the whole lookback")
    ap.add_argument("--min-accept", type=float, default=Thresholds.min_accept)
    ap.add_argument("--max-accept", type=float, default=Thresholds.max_accept)
    ap.add_argument("--max-gap-min", type=int, default=Thresholds.max_heartbeat_gap_min,
                    help="longest tolerated silence between heartbeats of one sensor")
    ap.add_argument("--hour-floor", type=int, default=Thresholds.hour_floor,
                    help="judge empty hours only if the quietest 5%% of last week's hours had at least this many sessions")
    ap.add_argument("--hours-csv", help="offline: hour,sessions for every hour that had sessions")
    ap.add_argument("--max-age-min", type=int, default=Thresholds.max_heartbeat_age_min,
                    help="longest tolerated age of the latest heartbeat (needs the database or --now)")
    ap.add_argument("--accept-list", help="accept list file (default: the sensor's config, via its env var)")
    ap.add_argument("--accepted-csv", help="offline: date,username,credential of accepted password attempts")
    ap.add_argument("--heartbeats-csv", help="offline: sensor_id,ts")
    ap.add_argument("--builds-csv", help="offline: date,build_sha,sessions")
    ap.add_argument("--check-builds", action="store_true",
                    help="flag build_sha 'unknown' or '' (off by default: old binaries write '')")
    ap.add_argument("--now", help="ISO time to judge heartbeat staleness against (default: now, database mode)")
    a = ap.parse_args(argv)

    if a.csv:
        raw = load_csv(a.csv)
    elif a.dsn:
        raw = load_db(a.dsn, a.lookback, a.protocol)
    else:
        ap.error("set DATABASE_URL, pass --dsn, or use --csv")
    rows = [{"date": r["date"], "sessions": int(r["sessions"]), "attempts": int(r["attempts"]),
             "accepted": int(r["accepted"]),
             "active_hours": int(r["active_hours"]) if r.get("active_hours") not in (None, "") else None}
            for r in raw]
    if not a.csv:
        rows = [r for r in rows if date.fromisoformat(r["date"]) < date.today()]  # today is partial
    # Telnet accepts a decoded Mirai table (~68% of attempts) by design, so a high rate is not a
    # failure there; the accepted-pairs check covers accept-everything instead. Rejecting
    # everything still shows as a rate near 0.
    max_accept = 1.0 if a.protocol == "telnet" else a.max_accept
    t = Thresholds(min_accept=a.min_accept, max_accept=max_accept,
                   max_heartbeat_gap_min=a.max_gap_min, max_heartbeat_age_min=a.max_age_min,
                   hour_floor=a.hour_floor)
    findings = evaluate(rows, t)
    now = parse_ts(a.now) if a.now else (None if a.csv else datetime.now(timezone.utc))
    always = []  # reported regardless of the report window

    # accepted-pairs invariant
    accepted = (load_csv(a.accepted_csv) if a.accepted_csv else
                _guarded("accepted-pairs check", lambda: load_accepted_db(a.dsn, a.lookback, a.protocol), always)
                if a.dsn and not a.csv else None)
    if accepted is not None:
        allowed = _accept_list(a.accept_list, a.protocol)
        if allowed is None:
            always.append({"date": date.today().isoformat(), "kind": "accept_list_missing",
                           "detail": "cannot read the accept list, so accepted pairs were NOT checked"})
        else:
            by_day = {}
            for r in accepted:
                by_day.setdefault(r["date"], set()).add(f"{r['username']}:{r['credential']}")
            findings += check_accepted_pairs(by_day, allowed)

    # heartbeats
    hb = (load_csv(a.heartbeats_csv) if a.heartbeats_csv else
          _guarded("heartbeat check", lambda: load_heartbeats_db(a.dsn, a.lookback), always)
          if a.dsn and not a.csv else None)
    if hb is not None:
        hb_findings = check_heartbeats([(r["sensor_id"], parse_ts(r["ts"])) for r in hb], now, t)
        findings += [f for f in hb_findings if f["kind"] != "heartbeat_stale"]
        always += [f for f in hb_findings if f["kind"] == "heartbeat_stale"]

    # hour coverage
    hours = (load_csv(a.hours_csv) if a.hours_csv else
             _guarded("hour-coverage check", lambda: load_hours_db(a.dsn, a.lookback, a.protocol), always)
             if a.dsn and not a.csv else None)
    if hours is not None:
        findings += check_hour_coverage([(parse_ts(r["hour"]), int(r["sessions"])) for r in hours], now, t)

    # build stamp
    if a.check_builds:
        br = (load_csv(a.builds_csv) if a.builds_csv else
              _guarded("build check", lambda: load_builds_db(a.dsn, a.lookback, a.protocol), always)
              if a.dsn and not a.csv else [])
        findings += check_builds([(r["date"], r["build_sha"], int(r["sessions"])) for r in br or []])

    if not a.all and rows:
        cutoff = date.fromisoformat(max(r["date"] for r in rows)) - timedelta(days=a.report_days - 1)
        findings = [f for f in findings if date.fromisoformat(f["date"]) >= cutoff]
    findings = sorted(findings + always, key=lambda f: f["date"])
    for f in findings:
        print(f"{f['date']}  {f['kind']:24s}  {f['detail']}")
    if not findings:
        print("ok: no findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
