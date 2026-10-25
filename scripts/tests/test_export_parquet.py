"""
Tests for export_parquet.py, the weekly incremental Parquet export.

Unit tests need only pyarrow. The end-to-end test needs a migrated-from-scratch
Postgres and runs only with MIRAGE_E2E_TEST=1 plus DB_HOST/DB_PORT/DB_USER/
DB_PASSWORD/DB_NAME; it applies internal/store/migrations itself, so point it
at a throwaway database.

Usage:
    python3 scripts/tests/test_export_parquet.py
"""

import base64
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from export_parquet import (  # noqa: E402
    COMMANDS_PLANNER,
    COMMANDS_SQL,
    DAY_MS,
    LocalStore,
    Manifest,
    Week,
    command_record,
    complete_weeks,
    data_path,
    is_ready,
    publish_week,
    run,
    session_record,
    week_of,
)

REPO = Path(__file__).resolve().parents[2]


def ms(y, mo, d, h=0, mi=0):
    return int(datetime(y, mo, d, h, mi, tzinfo=timezone.utc).timestamp() * 1000)


# --- weeks -------------------------------------------------------------------

def test_week_of_is_iso_week_in_utc():
    # 2026-10-19 is a Monday; ISO week 43.
    w = week_of(ms(2026, 10, 21, 15))
    assert w == Week("2026-W43", ms(2026, 10, 19), ms(2026, 10, 26))
    # Sunday 23:59 UTC still belongs to the week that started Monday.
    assert week_of(ms(2026, 10, 25, 23, 59)).label == "2026-W43"
    assert week_of(ms(2026, 10, 26)).label == "2026-W44"


def test_week_of_uses_iso_year_at_year_boundary():
    # 2027-01-01 is a Friday, so it is in ISO week 2026-W53.
    assert week_of(ms(2027, 1, 1)).label == "2026-W53"


def test_complete_weeks_stops_before_lag_has_passed():
    first = ms(2026, 10, 7)   # in W41
    lag = DAY_MS
    # W43 ends Mon 26 Oct 00:00; with a 1-day lag it is complete from Tue 00:00.
    labels = [w.label for w in complete_weeks(first, ms(2026, 10, 26, 23), lag)]
    assert labels == ["2026-W41", "2026-W42"]
    labels = [w.label for w in complete_weeks(first, ms(2026, 10, 27), lag)]
    assert labels == ["2026-W41", "2026-W42", "2026-W43"]


def test_complete_weeks_empty_before_first_week_ends():
    assert complete_weeks(ms(2026, 10, 20), ms(2026, 10, 22), DAY_MS) == []


def test_is_ready_waits_for_enrichment_then_gives_up():
    w = week_of(ms(2026, 10, 21))
    max_wait = 7 * DAY_MS
    assert is_ready(w, w.end_ms + DAY_MS, pending_enrichment=0, max_wait_ms=max_wait)
    assert not is_ready(w, w.end_ms + DAY_MS, pending_enrichment=3, max_wait_ms=max_wait)
    assert is_ready(w, w.end_ms + max_wait, pending_enrichment=3, max_wait_ms=max_wait)


# --- manifest ----------------------------------------------------------------

def test_manifest_covers_a_week_only_when_both_tables_are_present():
    m = Manifest.empty()
    w = week_of(ms(2026, 10, 21))
    m.add({"table": "sessions", "protocol": "ssh", "week": w.label, "path": data_path("sessions", "ssh", w)})
    assert not m.covers("ssh", w)
    m.add({"table": "commands", "protocol": "ssh", "week": w.label, "path": data_path("commands", "ssh", w)})
    assert m.covers("ssh", w)
    assert not m.covers("telnet", w)
    # Re-adding a file replaces its entry rather than duplicating it.
    m.add({"table": "commands", "protocol": "ssh", "week": w.label, "path": data_path("commands", "ssh", w), "rows": 9})
    assert len(m.files) == 2
    assert Manifest.from_json(m.to_json()).covers("ssh", w)


def test_data_path_is_hive_partitioned():
    w = week_of(ms(2026, 10, 21))
    assert data_path("commands", "telnet", w) == "commands/protocol=telnet/week=2026-W43.parquet"


# --- row transforms ----------------------------------------------------------

def _geo(ip):
    return {"198.51.100.7": ("AS64500", "Example Net", "DE")}.get(ip, (None, None, None))


def test_session_record_adds_geo_and_keeps_real_ip_by_default():
    row = {
        "session_id": "s1", "protocol": "ssh", "node_id": "Ubuntu", "client_ip": "198.51.100.7",
        "ssh_client_banner": "SSH-2.0-Go", "start_ms": 1, "end_ms": 2, "duration_ms": 1,
        "outcome": "auth_failed", "command_count": 0, "bait_hit_count": 0,
        "attacker_class": "automated_scanner", "classifier_confidence": 0.8, "cluster_id": None,
        "mitre_techniques": ["T1110"], "auth_attempt_count": 3, "unique_usernames_tried": 2,
        "top_username": "root",
    }
    out = session_record(row, _geo, ip_salt=None)
    assert out["client_ip"] == "198.51.100.7"
    assert (out["asn"], out["asn_name"], out["country"]) == ("AS64500", "Example Net", "DE")
    assert out["mitre_techniques"] == ["T1110"]
    hashed = session_record(row, _geo, ip_salt="salt")
    assert hashed["client_ip"].startswith("anon_")
    # Geo is resolved from the real IP before it is hashed.
    assert hashed["country"] == "DE"


def test_command_record_decodes_scrubs_and_hashes_ip():
    raw = "echo AKIAABCDEFGHIJKLMNOP\n\xff".encode("latin-1")
    row = {
        "event_id": "e1", "session_id": "s1", "protocol": "telnet", "sequence_number": 0,
        "timestamp_ms": 5, "inter_command_delay_ms": None,
        "raw_input_b64": base64.b64encode(raw).decode(), "parsed_command": "echo",
        "parsed_args": ["AKIAABCDEFGHIJKLMNOP"], "command_chain": None, "working_directory": "/",
        "response_text": "contact root@example.com", "exit_code": 0, "response_source": "hardcoded",
        "deception_action": None, "bait_id": None, "bait_type": None,
        "client_ip": "198.51.100.7", "ssh_client_banner": "", "attacker_class": None,
        "mitre_techniques": None,
    }
    out = command_record(row, ip_salt="salt")
    assert "AKIA" not in out["raw_command"] and "[REDACTED_AWS_ACCESS_KEY]" in out["raw_command"]
    # The old export scrubbed only raw_command and response; parsed_args repeats the same text.
    assert out["parsed_args"] == ["[REDACTED_AWS_ACCESS_KEY]"]
    assert out["raw_command"].endswith("�")  # invalid UTF-8 replaced, as the Go API does
    assert out["response"] == "contact [REDACTED_EMAIL]"
    assert out["client_ip"].startswith("anon_")
    assert out["bait_hit"] is False and out["command_chain"] == [] and out["mitre_techniques"] == []
    assert "raw_input_b64" not in out and "response_text" not in out


# --- publishing order --------------------------------------------------------

class RecordingStore(LocalStore):
    def __init__(self, root):
        super().__init__(root)
        self.order = []

    def put(self, path, local_file, immutable):
        self.order.append(path)
        super().put(path, local_file, immutable)


def test_publish_week_uploads_data_before_manifest():
    w = week_of(ms(2026, 10, 21))
    with tempfile.TemporaryDirectory() as d:
        store = RecordingStore(Path(d) / "bucket")
        manifest = Manifest.empty()
        files = {}
        for table in ("sessions", "commands"):
            f = Path(d) / f"{table}.parquet"
            f.write_bytes(b"PAR1")
            files[table] = (f, 1)
        publish_week(store, manifest, "ssh", w, files, pending_enrichment=0)
        assert store.order == [data_path("sessions", "ssh", w), data_path("commands", "ssh", w), "manifest.json"]
        saved = Manifest.from_json(store.get("manifest.json"))
        assert saved.covers("ssh", w)
        entry = next(f for f in saved.files if f["table"] == "sessions")
        assert entry["rows"] == 1 and entry["bytes"] == 4 and len(entry["sha256"]) == 64


# --- end to end against Postgres --------------------------------------------

def _connect():
    import psycopg

    return psycopg.connect(
        host=os.environ["DB_HOST"], port=os.environ["DB_PORT"], user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"], dbname=os.environ["DB_NAME"], autocommit=True,
    )


def _fresh_schema(conn):
    conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    for f in sorted((REPO / "internal/store/migrations").glob("*.sql")):
        conn.execute(f.read_text())


def _seed_session(conn, sid, protocol, start, ip, attacker_class="automated_scanner", outcome="auth_failed"):
    conn.execute(
        "INSERT INTO sessions (session_id, schema_version, node_id, protocol, client_ip, client_port,"
        " server_port, ssh_client_banner, start_ms, end_ms, duration_ms, outcome, attacker_class,"
        " mitre_techniques, session_document) VALUES (%s,'1.1','Ubuntu',%s,%s,40000,22,'',%s,%s,1000,%s,%s,"
        " '[\"T1110\"]'::jsonb, '{}'::jsonb)",
        (sid, protocol, ip, start, start + 1000, outcome, attacker_class),
    )


def _seed_command(conn, sid, eid, ts, text):
    conn.execute(
        "INSERT INTO commands (event_id, session_id, sequence_number, timestamp_ms, raw_input_b64,"
        " parsed_command, parsed_args, working_directory, response_source)"
        " VALUES (%s,%s,0,%s,%s,%s,'[]'::jsonb,'/root','hardcoded')",
        (eid, sid, ts, base64.b64encode(text.encode()).decode(), text.split()[0]),
    )


def test_end_to_end_incremental_export():
    if os.environ.get("MIRAGE_E2E_TEST") != "1":
        print("  (skipped: set MIRAGE_E2E_TEST=1 and DB_* for a throwaway Postgres)")
        return
    conn = _connect()
    _fresh_schema(conn)
    w42, w43 = ms(2026, 10, 14, 10), ms(2026, 10, 21, 10)
    _seed_session(conn, "ssh-42", "ssh", w42, "198.51.100.7")
    _seed_command(conn, "ssh-42", "e-42", w42 + 10, "uname -a")
    conn.execute("INSERT INTO auth_attempts (session_id, timestamp_ms, method, username, credential, success)"
                 " VALUES ('ssh-42', %s, 'password', 'root', 'x', false)", (w42,))
    _seed_session(conn, "tel-42", "telnet", w42 + 5, "198.51.100.8", attacker_class=None)
    _seed_command(conn, "tel-42", "e-t42", w42 + 20, "enable")
    # W43: one SSH session not yet classified by the bridge.
    _seed_session(conn, "ssh-43", "ssh", w43, "198.51.100.9", attacker_class=None)
    # Last-week boundary: a session at Sunday 23:59:59.999 belongs to W43, not W44.
    _seed_session(conn, "tel-43-edge", "telnet", ms(2026, 10, 26) - 1, "198.51.100.8", attacker_class=None)

    with tempfile.TemporaryDirectory() as d:
        store = LocalStore(Path(d) / "bucket")
        kwargs = dict(protocols=["ssh", "telnet"], lag_ms=DAY_MS, max_wait_ms=7 * DAY_MS,
                      geo=_geo, session_ip_salt=None, command_ip_salt="salt", chunk_ms=6 * 3600 * 1000)
        db = _connect()

        # Tue 27 Oct: W42 and W43 are complete, but SSH W43 still awaits enrichment.
        summary = run(db, store, now_ms=ms(2026, 10, 27, 1), **kwargs)
        assert summary["published"] == [("ssh", "2026-W42"), ("telnet", "2026-W42"), ("telnet", "2026-W43")]
        assert summary["waiting"] == [("ssh", "2026-W43", 1)]

        sessions = pq.read_table(Path(d) / "bucket" / "sessions/protocol=ssh/week=2026-W42.parquet").to_pylist()
        assert [s["session_id"] for s in sessions] == ["ssh-42"]
        assert sessions[0]["country"] == "DE" and sessions[0]["auth_attempt_count"] == 1
        assert sessions[0]["mitre_techniques"] == ["T1110"]
        cmds = pq.read_table(Path(d) / "bucket" / "commands/protocol=ssh/week=2026-W42.parquet").to_pylist()
        assert [c["raw_command"] for c in cmds] == ["uname -a"] and cmds[0]["client_ip"].startswith("anon_")
        edge = pq.read_table(Path(d) / "bucket" / "sessions/protocol=telnet/week=2026-W43.parquet").to_pylist()
        assert [s["session_id"] for s in edge] == ["tel-43-edge"]

        # Same day again: nothing new, nothing re-exported.
        again = run(db, store, now_ms=ms(2026, 10, 27, 2), **kwargs)
        assert again["published"] == [] and again["waiting"] == [("ssh", "2026-W43", 1)]

        # The bridge classifies it; the next run publishes SSH W43.
        conn.execute("UPDATE sessions SET attacker_class='automated_scanner' WHERE session_id='ssh-43'")
        later = run(db, store, now_ms=ms(2026, 10, 28), **kwargs)
        assert later["published"] == [("ssh", "2026-W43")]

        manifest = json.loads((Path(d) / "bucket" / "manifest.json").read_text())
        assert len(manifest["files"]) == 8  # 2 protocols x 2 weeks x 2 tables
        # The export session must not be able to write.
        try:
            with db.transaction():
                db.execute("CREATE TEMP TABLE should_fail (x int)")
        except Exception as e:  # psycopg.errors.ReadOnlySqlTransaction
            assert "read-only" in str(e), e
        else:
            raise AssertionError("export connection allowed a write")

        db.close()
    conn.close()


def _commands_scan(db, planner):
    lo = 1_780_000_000_000
    with db.transaction():
        for setting in planner:
            db.execute(setting)
        plan = db.execute("EXPLAIN (FORMAT JSON) " + COMMANDS_SQL,
                          {"lo": lo, "hi": lo + 100 * 60_000, "protocol": "telnet"}).fetchone()[0]
    scans = []

    def walk(node):
        if node.get("Relation Name") == "commands":
            scans.append(node["Node Type"])
        for child in node.get("Plans", []):
            walk(child)

    walk(plan[0]["Plan"])
    return scans


def test_commands_query_reads_only_its_sessions_commands():
    if os.environ.get("MIRAGE_E2E_TEST") != "1":
        print("  (skipped: set MIRAGE_E2E_TEST=1 and DB_* for a throwaway Postgres)")
        return
    conn = _connect()
    _fresh_schema(conn)
    # Shaped like prod: a chunk holds ~5% of all commands, which is where the
    # default planner switches to scanning the whole commands table.
    conn.execute("""
        INSERT INTO sessions (session_id, schema_version, node_id, protocol, client_ip, client_port,
                              server_port, ssh_client_banner, start_ms, outcome, session_document)
        SELECT 'bulk-' || i, '1.1', 'x', 'telnet', '198.51.100.1', 1, 23, '',
               1780000000000 + i * 60000, 'clean_disconnect', '{}'::jsonb
        FROM generate_series(1, 2000) i""")
    conn.execute("""
        INSERT INTO commands (event_id, session_id, sequence_number, timestamp_ms, raw_input_b64,
                              parsed_command, parsed_args, working_directory, response_source, response_text)
        SELECT 'bulk-' || i || '-' || j, 'bulk-' || i, j, 1780000000000 + i * 60000 + j, 'ZWNobw==',
               'echo', '[]'::jsonb, '/', 'hardcoded', repeat('x', 300)
        FROM generate_series(1, 2000) i, generate_series(1, 25) j""")
    conn.execute("ANALYZE sessions; ANALYZE commands; ANALYZE bait_interactions")
    # The fixture must reproduce the problem, or the next assert proves nothing.
    assert "Seq Scan" in _commands_scan(conn, ()), "fixture no longer makes the planner seq-scan commands"
    scans = _commands_scan(conn, COMMANDS_PLANNER)
    assert scans and "Seq Scan" not in scans, scans
    conn.close()


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\n{len(tests)} tests passed")
