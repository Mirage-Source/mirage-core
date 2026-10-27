"""
Plain-assert tests for daily_health_check.evaluate(): the two silent failures
the preprint documents (an authentication callback that accepted everything,
then one that rejected everything) plus the zero-session downtime days, each
expressed as daily rows.

No pytest dependency, consistent with scripts/ CI (see
.github/workflows/publish-dataset.yml).

Usage:
    python3 scripts/tests/test_daily_health_check.py
"""

import contextlib
import csv
import io
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import daily_health_check  # noqa: E402
from daily_health_check import (  # noqa: E402
    Thresholds, check_accepted_pairs, check_builds, check_heartbeats, evaluate, main,
    parse_accept_list, parse_ts,
)


def day(date, sessions, attempts=None, accepted=0):
    return {
        "date": date,
        "sessions": sessions,
        "attempts": sessions if attempts is None else attempts,
        "accepted": accepted,
    }


def normal_week():
    # ~5% of password attempts accepted, steady volume
    return [day(f"2026-10-0{d}", 2000, accepted=100) for d in range(1, 8)]


def kinds(findings):
    return sorted(f["kind"] for f in findings)


def test_healthy_history_has_no_findings():
    assert evaluate(normal_week() + [day("2026-10-08", 1900, accepted=95)]) == []


def test_zero_session_day_is_flagged():
    f = evaluate(normal_week() + [day("2026-10-08", 0)])
    assert kinds(f) == ["no_sessions"], f
    assert f[0]["date"] == "2026-10-08"


def test_missing_calendar_day_is_flagged():
    # the Frankfurt gap: 07-19 and 07-20 are absent rather than zero
    rows = normal_week()
    rows.append(day("2026-10-10", 2000, accepted=100))  # 10-08 and 10-09 never appear
    f = evaluate(rows)
    assert [x["date"] for x in f if x["kind"] == "no_sessions"] == ["2026-10-08", "2026-10-09"], f


def test_accept_everything_is_flagged():
    f = evaluate(normal_week() + [day("2026-10-08", 2000, accepted=2000)])
    assert kinds(f) == ["acceptance_too_high"], f


def test_reject_everything_is_flagged():
    f = evaluate(normal_week() + [day("2026-10-08", 2000, accepted=0)])
    assert kinds(f) == ["acceptance_too_low"], f


def test_sharp_volume_drop_is_flagged_against_the_trailing_median():
    f = evaluate(normal_week() + [day("2026-10-08", 300, accepted=15)])
    assert kinds(f) == ["volume_drop"], f


def test_small_samples_do_not_trigger_acceptance_checks():
    # 20 attempts at 0% acceptance is noise, not a failed pipeline
    rows = normal_week() + [day("2026-10-08", 20, accepted=0)]
    t = Thresholds(min_sessions=10, min_attempts_for_rate=100)
    assert "acceptance_too_low" not in kinds(evaluate(rows, t))


def test_short_history_skips_the_relative_volume_check():
    # with 2 prior days there is no trustworthy median; only absolute checks apply
    rows = [day("2026-10-01", 2000, accepted=100), day("2026-10-02", 2000, accepted=100),
            day("2026-10-03", 300, accepted=15)]
    assert "volume_drop" not in kinds(evaluate(rows))


# --- accepted-pairs invariant -------------------------------------------------
# After the fix, a password is accepted only if "user:pass" is on a fixed list, so the
# distinct pairs accepted on any day must be a subset of that list. Unlike a rate
# threshold this catches accept-everything at any traffic level, and it works for
# Telnet, whose accept rate (~68%) is policy and cannot be thresholded.

ALLOWED = {"root:123456", "admin:admin", "ubnt:ubnt"}


def test_accept_list_parsing_matches_the_server():
    text = "# comment\n\nroot:123456\n  admin:admin  \nroot:pa:ss\n"
    assert parse_accept_list(text) == {"root:123456", "admin:admin", "root:pa:ss"}


def test_listed_pairs_only_is_clean():
    assert check_accepted_pairs({"2026-10-08": {"root:123456", "ubnt:ubnt"}}, ALLOWED) == []


def test_a_single_unlisted_accepted_pair_is_flagged_even_at_a_tiny_rate():
    f = check_accepted_pairs({"2026-10-08": {"root:123456", "root:hunter2"}}, ALLOWED)
    assert [(x["date"], x["kind"]) for x in f] == [("2026-10-08", "accepted_pair_not_listed")], f


def test_unlisted_finding_reports_a_count_and_a_few_samples_not_every_pair():
    pairs = {f"root:pw{i}" for i in range(500)}
    (f,) = check_accepted_pairs({"2026-10-08": pairs}, ALLOWED)
    assert "500" in f["detail"] and len(f["detail"]) < 200, f


# --- heartbeats ----------------------------------------------------------------

def beats(sensor, start, end, every_s=60):
    out, t = [], start
    while t <= end:
        out.append((sensor, t))
        t += timedelta(seconds=every_s)
    return out


T0 = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)


def test_steady_heartbeats_are_clean():
    assert check_heartbeats(beats("default", T0, T0 + timedelta(hours=2))) == []


def test_a_three_hour_gap_is_flagged():
    hb = beats("default", T0, T0 + timedelta(hours=1)) + beats("default", T0 + timedelta(hours=4), T0 + timedelta(hours=5))
    (f,) = check_heartbeats(hb)
    assert f["kind"] == "heartbeat_gap" and "3 h" in f["detail"] and f["date"] == "2026-10-08", f


def test_the_two_real_nuremberg_outages_are_found():
    # exact heartbeat timestamps either side of the two outages in the 2026-10-27 snapshot
    d = lambda *a: datetime(*a, tzinfo=timezone.utc)
    out1 = (d(2026, 10, 18, 8, 53, 52, 657699), d(2026, 10, 18, 9, 9, 43, 487491))
    out2 = (d(2026, 10, 19, 21, 32, 44, 250017), d(2026, 10, 20, 0, 6, 43, 239151))
    hb = [(s, t) for s, t in beats("default", d(2026, 10, 18, 8, 0), d(2026, 10, 20, 1, 0))
          if not (out1[0] < t < out1[1] or out2[0] < t < out2[1])]
    hb += [("default", t) for t in out1 + out2]
    f = check_heartbeats(hb)
    assert [x["date"] for x in f] == ["2026-10-18", "2026-10-19"], f
    assert "16 min" in f[0]["detail"] and "2 h 34 min" in f[1]["detail"], f


def test_each_sensor_is_checked_on_its_own():
    # a healthy sensor must not hide a silent one (merging the streams would)
    hb = (beats("default", T0, T0 + timedelta(hours=2))
          + beats("telnet", T0, T0 + timedelta(minutes=30)) + beats("telnet", T0 + timedelta(hours=1, minutes=30), T0 + timedelta(hours=2)))
    (f,) = check_heartbeats(hb)
    assert f["kind"] == "heartbeat_gap" and "telnet" in f["detail"], f


def test_a_stale_latest_heartbeat_is_flagged_only_when_now_is_given():
    hb = beats("default", T0, T0 + timedelta(hours=1))
    assert check_heartbeats(hb) == []
    (f,) = check_heartbeats(hb, now=T0 + timedelta(hours=1, minutes=20))
    assert f["kind"] == "heartbeat_stale", f


def test_postgres_style_timestamps_parse():
    assert parse_ts("2026-10-18 08:53:52.657699+00") == datetime(2026, 10, 18, 8, 53, 52, 657699, tzinfo=timezone.utc)
    assert parse_ts("2026-10-18T08:53:52+05:30") == datetime(2026, 10, 18, 3, 23, 52, tzinfo=timezone.utc)


# --- build stamp ---------------------------------------------------------------

def test_unstamped_and_blank_builds_are_flagged_on_recent_days():
    f = check_builds([("2026-10-08", "abc1234", 900), ("2026-10-08", "unknown", 3), ("2026-10-08", "", 7)])
    assert sorted(x["kind"] for x in f) == ["build_blank", "build_unknown"], f


def test_stamped_builds_are_clean_even_when_two_builds_overlap_on_a_deploy_day():
    assert check_builds([("2026-10-08", "abc1234", 900), ("2026-10-08", "def5678-dirty", 400)]) == []


# --- exit status: the two silent failures must fail the run --------------------

def _write(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _healthy_days(path):
    _write(path, ["date", "sessions", "attempts", "accepted"],
           [(f"2026-10-0{d}", 2000, 2000, 100) for d in range(1, 9)])


def _run(tmp, *extra):
    days = Path(tmp) / "days.csv"
    _healthy_days(days)
    lst = Path(tmp) / "accept.txt"
    lst.write_text("root:123456\nadmin:admin\n")
    return main(["--csv", str(days), "--accept-list", str(lst), *extra])


def test_exit_is_zero_when_everything_is_healthy():
    with tempfile.TemporaryDirectory() as tmp:
        acc = Path(tmp) / "acc.csv"
        _write(acc, ["date", "username", "credential"], [("2026-10-08", "root", "123456")])
        hb = Path(tmp) / "hb.csv"
        _write(hb, ["sensor_id", "ts"], [(s, t.isoformat()) for s, t in beats("default", T0, T0 + timedelta(hours=2))])
        assert _run(tmp, "--accepted-csv", str(acc), "--heartbeats-csv", str(hb)) == 0


def test_simulated_accept_everything_day_makes_the_run_fail():
    with tempfile.TemporaryDirectory() as tmp:
        acc = Path(tmp) / "acc.csv"
        _write(acc, ["date", "username", "credential"],
               [("2026-10-08", "root", "123456"), ("2026-10-08", "root", "letmein"), ("2026-10-08", "bob", "hunter2")])
        assert _run(tmp, "--accepted-csv", str(acc)) == 1


def test_simulated_three_hour_heartbeat_gap_makes_the_run_fail():
    with tempfile.TemporaryDirectory() as tmp:
        hb = Path(tmp) / "hb.csv"
        rows = beats("default", T0, T0 + timedelta(hours=1)) + beats("default", T0 + timedelta(hours=4), T0 + timedelta(hours=5))
        _write(hb, ["sensor_id", "ts"], [(s, t.isoformat()) for s, t in rows])
        assert _run(tmp, "--heartbeats-csv", str(hb)) == 1


def test_builds_are_only_checked_when_asked():
    with tempfile.TemporaryDirectory() as tmp:
        b = Path(tmp) / "builds.csv"
        _write(b, ["date", "build_sha", "sessions"], [("2026-10-08", "unknown", 50)])
        assert _run(tmp, "--builds-csv", str(b)) == 0           # off by default: old binaries write ''
        assert _run(tmp, "--builds-csv", str(b), "--check-builds") == 1


def test_a_missing_accept_list_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        days, acc = Path(tmp) / "days.csv", Path(tmp) / "acc.csv"
        _healthy_days(days)
        _write(acc, ["date", "username", "credential"], [("2026-10-08", "root", "123456")])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--csv", str(days), "--accepted-csv", str(acc), "--accept-list", str(Path(tmp) / "nope.txt")])
        assert code == 1 and "accept_list_missing" in out.getvalue(), out.getvalue()


def test_a_failing_loader_becomes_a_finding_and_does_not_hide_the_other_checks():
    # e.g. the Frankfurt dump has no sensor_heartbeats table
    with tempfile.TemporaryDirectory() as tmp:
        lst = Path(tmp) / "accept.txt"
        lst.write_text("root:123456\n")
        saved = (daily_health_check.load_db, daily_health_check.load_accepted_db, daily_health_check.load_heartbeats_db)
        def boom(*a, **k):
            raise subprocess.CalledProcessError(1, "psql", stderr='ERROR:  relation "sensor_heartbeats" does not exist\nLINE 1')
        daily_health_check.load_db = lambda *a, **k: [
            {"date": f"2026-10-0{d}", "sessions": "2000", "attempts": "2000", "accepted": "100"} for d in range(1, 9)]
        daily_health_check.load_accepted_db = lambda *a, **k: [{"date": "2026-10-08", "username": "bob", "credential": "hunter2"}]
        daily_health_check.load_heartbeats_db = boom
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                code = main(["--dsn", "x", "--accept-list", str(lst), "--all"])
        finally:
            daily_health_check.load_db, daily_health_check.load_accepted_db, daily_health_check.load_heartbeats_db = saved
        text = out.getvalue()
        assert code == 1
        assert "check_failed" in text and "sensor_heartbeats" in text, text
        assert "accepted_pair_not_listed" in text, text  # the other check still ran


def test_telnet_acceptance_of_two_thirds_is_policy_not_a_failure():
    # Telnet accepts a decoded Mirai table, ~68% of attempts by design (Nuremberg)
    with tempfile.TemporaryDirectory() as tmp:
        days, acc = Path(tmp) / "days.csv", Path(tmp) / "acc.csv"
        _write(days, ["date", "sessions", "attempts", "accepted"],
               [(f"2026-10-0{d}", 5000, 5000, 3400) for d in range(1, 9)])
        _write(acc, ["date", "username", "credential"], [("2026-10-08", "root", "xc3511")])
        lst = Path(tmp) / "telnet.txt"
        lst.write_text("root:xc3511\n")
        base = ["--csv", str(days), "--accepted-csv", str(acc), "--accept-list", str(lst)]
        assert main(base + ["--protocol", "telnet"]) == 0
        assert main(base + ["--protocol", "ssh"]) == 1  # the same 68% on SSH is the accept-everything signature


def test_telnet_rejecting_everything_is_still_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        days = Path(tmp) / "days.csv"
        _write(days, ["date", "sessions", "attempts", "accepted"],
               [(f"2026-10-0{d}", 5000, 5000, 0) for d in range(1, 9)])
        assert main(["--csv", str(days), "--protocol", "telnet"]) == 1


def test_database_mode_against_the_real_schema():
    """psql loaders against tables built from the real migrations (timestamptz heartbeats, build_sha)."""
    if os.environ.get("MIRAGE_E2E_TEST") != "1":
        print("  (skipped: set MIRAGE_E2E_TEST=1 and DB_* for a throwaway Postgres)")
        return
    dsn = (f"postgresql://{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}@{os.environ['DB_HOST']}:"
           f"{os.environ['DB_PORT']}/{os.environ['DB_NAME']}")
    def sql(q):
        subprocess.run(["psql", dsn, "-q", "-v", "ON_ERROR_STOP=1", "-c", q], check=True, capture_output=True)
    sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    for f in sorted((Path(__file__).resolve().parent.parent.parent / "internal/store/migrations").glob("*.sql")):
        subprocess.run(["psql", dsn, "-q", "-v", "ON_ERROR_STOP=1", "-f", str(f)], check=True, capture_output=True)
    # nine full days ending yesterday, 1000 sessions a day, 5% of password attempts accepted (all listed pairs)
    sql("""INSERT INTO sessions (session_id, schema_version, node_id, protocol, client_ip, client_port, server_port,
             ssh_client_banner, start_ms, outcome, build_sha, session_document)
           SELECT 's' || d || '-' || i, '1.2', 'Ubuntu', 'ssh', '198.51.100.1', 1, 2222, 'SSH-2.0-Go',
                  (extract(epoch FROM date_trunc('day', now()) - (d || ' days')::interval) * 1000)::bigint + i * 1000,
                  'auth_failed', CASE WHEN d = 1 AND i < 4 THEN 'unknown' ELSE 'abc1234' END, '{}'::jsonb
           FROM generate_series(1, 9) d, generate_series(1, 1000) i""")
    sql("""INSERT INTO auth_attempts (session_id, timestamp_ms, method, username, credential, success)
           SELECT session_id, start_ms, 'password',
                  CASE WHEN session_id = 's1-500' THEN 'bob' ELSE 'root' END,
                  CASE WHEN session_id = 's1-500' THEN 'hunter2' ELSE '123456' END,
                  (right(session_id, 2) = '50') OR session_id = 's1-500'
           FROM sessions""")
    # heartbeats every minute for the last 6 hours, with a 3 hour hole starting 5 hours ago... plus a live tail
    sql("""INSERT INTO sensor_heartbeats (sensor_id, ts)
           SELECT 'default', g FROM generate_series(now() - interval '8 hours', now() - interval '5 hours', interval '1 minute') g
           UNION ALL
           SELECT 'default', g FROM generate_series(now() - interval '2 hours', now(), interval '1 minute') g""")
    lst = Path(tempfile.mkdtemp()) / "accept.txt"
    lst.write_text("root:123456\n")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--dsn", dsn, "--accept-list", str(lst), "--check-builds", "--lookback", "10", "--all"])
    text = out.getvalue()
    assert code == 1
    for kind in ("accepted_pair_not_listed", "heartbeat_gap", "build_unknown"):
        assert kind in text, (kind, text)
    assert "heartbeat_stale" not in text and "check_failed" not in text, text  # live tail, every table present
    assert "acceptance_too" not in text and "no_sessions" not in text, text    # the healthy parts stay quiet


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    for t in TESTS:
        t()
        print("ok", t.__name__)
    print(f"{len(TESTS)} tests passed")
