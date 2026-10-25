"""
export_parquet.py

Weekly, incremental Parquet export of the session and command data, read
straight from Postgres on the sensor and uploaded to object storage (R2).

Each run publishes every complete ISO week (Monday 00:00 UTC to Monday 00:00
UTC) that is not yet in the bucket's manifest.json, one file per table, per
protocol, per week:

    sessions/protocol=ssh/week=2026-W43.parquet
    commands/protocol=telnet/week=2026-W43.parquet
    manifest.json

so each run reads only new weeks, never the whole history. Published files are
never rewritten.

Two things decide when a week is ready:
  - A session row is inserted when it ends. Sessions idle out after 120s
    (internal/server), so waiting --lag-hours (default 24) past the week's
    end is enough for every session that started in it to be inserted.
  - The ML bridge fills in attacker_class/cluster_id/mitre_techniques on SSH
    sessions after insert (bridge/db.py). An SSH week waits until none of its
    finished sessions is still unclassified, or until --max-wait-days after
    the week ends, when it is published anyway with the count recorded.
    Telnet sessions are never enriched, so telnet weeks never wait.

A command belongs to the week its session started in, so a session and its
commands are always in the same week's files.

The database connection is read-only and the reads are split into
--chunk-hours windows, each in its own short transaction, so the export never
holds a long-running snapshot or locks that a migration would queue behind.

Usage on the sensor (see deploy/dataset-export/):
    python3 export_parquet.py --geo-asn-csv data/geo/dbip-asn-lite.csv \\
        --geo-country-csv data/geo/dbip-country-lite.csv
Local, without R2:
    python3 export_parquet.py ... --out-dir /tmp/dataset
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from anonymize import anonymize_ip, scrub_secrets

HOUR_MS = 3600 * 1000
DAY_MS = 24 * HOUR_MS
WEEK_MS = 7 * DAY_MS
MANIFEST = "manifest.json"
MANIFEST_FORMAT = 1
TABLES = ("sessions", "commands")
ROW_GROUP_ROWS = 100_000

# --- weeks -------------------------------------------------------------------


@dataclass(frozen=True)
class Week:
    label: str  # ISO week, e.g. "2026-W43"
    start_ms: int  # Monday 00:00 UTC, inclusive
    end_ms: int  # next Monday 00:00 UTC, exclusive


def week_of(ts_ms: int) -> Week:
    day = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).date()
    monday = day - timedelta(days=day.weekday())
    start = int(datetime(monday.year, monday.month, monday.day, tzinfo=timezone.utc).timestamp() * 1000)
    iso_year, iso_week, _ = monday.isocalendar()
    return Week(f"{iso_year}-W{iso_week:02d}", start, start + WEEK_MS)


def complete_weeks(first_ms: int, now_ms: int, lag_ms: int) -> list[Week]:
    """Weeks from the one containing first_ms whose end is at least lag_ms ago."""
    weeks = []
    w = week_of(first_ms)
    while w.end_ms + lag_ms <= now_ms:
        weeks.append(w)
        w = week_of(w.end_ms)
    return weeks


def is_ready(week: Week, now_ms: int, pending_enrichment: int, max_wait_ms: int) -> bool:
    return pending_enrichment == 0 or now_ms >= week.end_ms + max_wait_ms


def data_path(table: str, protocol: str, week: Week) -> str:
    return f"{table}/protocol={protocol}/week={week.label}.parquet"


# --- manifest ----------------------------------------------------------------


class Manifest:
    """The bucket's index of published files, and the export's only state."""

    def __init__(self, files: list[dict]):
        self.files = files

    @classmethod
    def empty(cls) -> "Manifest":
        return cls([])

    @classmethod
    def from_json(cls, raw: bytes | str) -> "Manifest":
        doc = json.loads(raw)
        if doc.get("format") != MANIFEST_FORMAT:
            raise ValueError(f"unsupported manifest format {doc.get('format')!r}")
        return cls(doc["files"])

    def to_json(self) -> str:
        files = sorted(self.files, key=lambda f: (f["table"], f["protocol"], f["week"]))
        return json.dumps(
            {
                "format": MANIFEST_FORMAT,
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "files": files,
            },
            indent=2,
        )

    def add(self, entry: dict) -> None:
        self.files = [f for f in self.files if f["path"] != entry["path"]] + [entry]

    def covers(self, protocol: str, week: Week) -> bool:
        present = {f["table"] for f in self.files if f["protocol"] == protocol and f["week"] == week.label}
        return present.issuperset(TABLES)


# --- stores ------------------------------------------------------------------


class LocalStore:
    """A directory laid out like the bucket. For --out-dir runs and tests."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def get(self, path: str) -> bytes | None:
        p = self.root / path
        return p.read_bytes() if p.exists() else None

    def put(self, path: str, local_file: Path, immutable: bool) -> None:
        dest = self.root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local_file, dest)


class R2Store:
    """Cloudflare R2 through its S3-compatible API."""

    def __init__(self, account_id: str, access_key_id: str, secret_access_key: str, bucket: str):
        import boto3

        self.bucket = bucket
        self.s3 = boto3.client(
            "s3",
            endpoint_url=f"https://{account_id}.r2.cloudflarestorage.com",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="auto",
        )

    def get(self, path: str) -> bytes | None:
        try:
            return self.s3.get_object(Bucket=self.bucket, Key=path)["Body"].read()
        except self.s3.exceptions.NoSuchKey:
            return None

    def put(self, path: str, local_file: Path, immutable: bool) -> None:
        content_type = "application/json" if path.endswith(".json") else "application/vnd.apache.parquet"
        # A week's file never changes once published; the manifest changes
        # every run, so caches must recheck it.
        cache = "public, max-age=31536000, immutable" if immutable else "public, max-age=300"
        self.s3.upload_file(
            str(local_file), self.bucket, path,
            ExtraArgs={"ContentType": content_type, "CacheControl": cache},
        )


def publish_week(store, manifest: Manifest, protocol: str, week: Week, files: dict, pending_enrichment: int) -> None:
    """Upload a week's data files, then the manifest that lists them.

    Data first, so a reader following the manifest never finds a listed file
    missing; if the run dies between the two, the next run redoes the week.
    """
    exported_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for table in TABLES:
        local, rows = files[table]
        path = data_path(table, protocol, week)
        store.put(path, local, immutable=True)
        manifest.add({
            "table": table,
            "protocol": protocol,
            "week": week.label,
            "start_ms": week.start_ms,
            "end_ms": week.end_ms,
            "path": path,
            "rows": rows,
            "bytes": Path(local).stat().st_size,
            "sha256": hashlib.sha256(Path(local).read_bytes()).hexdigest(),
            "exported_at": exported_at,
            "unenriched_sessions": pending_enrichment,
        })
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(manifest.to_json())
    try:
        store.put(MANIFEST, Path(f.name), immutable=False)
    finally:
        os.unlink(f.name)


# --- rows --------------------------------------------------------------------

SESSION_SCHEMA = pa.schema([
    ("session_id", pa.string()),
    ("protocol", pa.string()),
    ("node_id", pa.string()),
    ("client_ip", pa.string()),
    ("asn", pa.string()),
    ("asn_name", pa.string()),
    ("country", pa.string()),
    ("ssh_client_banner", pa.string()),
    ("start_ms", pa.int64()),
    ("end_ms", pa.int64()),
    ("duration_ms", pa.int64()),
    ("outcome", pa.string()),
    ("command_count", pa.int32()),
    ("bait_hit_count", pa.int32()),
    ("attacker_class", pa.string()),
    ("classifier_confidence", pa.float64()),
    ("cluster_id", pa.string()),
    ("mitre_techniques", pa.list_(pa.string())),
    ("auth_attempt_count", pa.int64()),
    ("unique_usernames_tried", pa.int64()),
    ("top_username", pa.string()),
])

COMMAND_SCHEMA = pa.schema([
    ("event_id", pa.string()),
    ("session_id", pa.string()),
    ("protocol", pa.string()),
    ("sequence_number", pa.int32()),
    ("timestamp_ms", pa.int64()),
    ("inter_command_delay_ms", pa.int64()),
    ("raw_command", pa.string()),
    ("parsed_command", pa.string()),
    ("parsed_args", pa.list_(pa.string())),
    ("command_chain", pa.list_(pa.string())),
    ("working_directory", pa.string()),
    ("response", pa.string()),
    ("exit_code", pa.int32()),
    ("response_source", pa.string()),
    ("deception_action", pa.string()),
    ("bait_hit", pa.bool_()),
    ("bait_type", pa.string()),
    ("client_ip", pa.string()),
    ("ssh_client_banner", pa.string()),
    ("attacker_class", pa.string()),
    ("mitre_techniques", pa.list_(pa.string())),
])


def session_record(row: dict, geo, ip_salt: str | None) -> dict:
    """geo(ip) -> (asn, asn_name, country), resolved from the real IP."""
    out = {name: row.get(name) for name in SESSION_SCHEMA.names}
    out["asn"], out["asn_name"], out["country"] = geo(row["client_ip"])
    out["mitre_techniques"] = row.get("mitre_techniques") or []
    if ip_salt is not None:
        out["client_ip"] = anonymize_ip(row["client_ip"], ip_salt)
    return out


def command_record(row: dict, ip_salt: str | None) -> dict:
    out = {name: row.get(name) for name in COMMAND_SCHEMA.names}
    # Same as the Go API: raw bytes as text, invalid UTF-8 replaced.
    raw = base64.b64decode(row["raw_input_b64"]).decode("utf-8", errors="replace")
    out["raw_command"] = scrub_secrets(raw)
    out["response"] = scrub_secrets(row.get("response_text"))
    out["parsed_args"] = [scrub_secrets(a) for a in row.get("parsed_args") or []]
    out["command_chain"] = row.get("command_chain") or []
    out["mitre_techniques"] = row.get("mitre_techniques") or []
    out["bait_hit"] = row.get("bait_id") is not None
    if ip_salt is not None:
        out["client_ip"] = anonymize_ip(row["client_ip"], ip_salt)
    return out


# --- queries -----------------------------------------------------------------

# Range on start_ms first so both protocols seek the index: the partial
# (protocol, start_ms) index for telnet, idx_sessions_start_ms for SSH.
SESSIONS_SQL = """
    SELECT
        s.session_id, s.protocol, s.node_id, s.client_ip, s.ssh_client_banner,
        s.start_ms, s.end_ms, s.duration_ms, s.outcome,
        s.command_count, s.bait_hit_count,
        s.attacker_class, s.classifier_confidence, s.cluster_id, s.mitre_techniques,
        COALESCE(a.attempt_count, 0) AS auth_attempt_count,
        COALESCE(a.unique_usernames, 0) AS unique_usernames_tried,
        a.top_username
    FROM sessions s
    LEFT JOIN LATERAL (
        SELECT
            COUNT(*) AS attempt_count,
            COUNT(DISTINCT username) AS unique_usernames,
            (
                SELECT username FROM auth_attempts aa2
                WHERE aa2.session_id = s.session_id
                GROUP BY username ORDER BY COUNT(*) DESC LIMIT 1
            ) AS top_username
        FROM auth_attempts aa
        WHERE aa.session_id = s.session_id
    ) a ON true
    WHERE s.start_ms >= %(lo)s AND s.start_ms < %(hi)s AND s.protocol = %(protocol)s
    ORDER BY s.start_ms, s.session_id
"""

# Commands are selected through their sessions' start_ms (indexed) and
# idx_commands_session_id, so no index on commands.timestamp_ms is needed.
COMMANDS_SQL = """
    SELECT
        c.event_id, c.session_id, s.protocol, c.sequence_number,
        c.timestamp_ms, c.inter_command_delay_ms,
        c.raw_input_b64, c.parsed_command, c.parsed_args, c.command_chain,
        c.working_directory, c.response_text, c.exit_code,
        c.response_source, c.deception_action,
        b.bait_id, b.bait_type,
        s.client_ip, s.ssh_client_banner, s.attacker_class, s.mitre_techniques
    FROM sessions s
    JOIN commands c ON c.session_id = s.session_id
    LEFT JOIN bait_interactions b ON b.triggered_by_command_event_id = c.event_id
    WHERE s.start_ms >= %(lo)s AND s.start_ms < %(hi)s AND s.protocol = %(protocol)s
    ORDER BY s.start_ms, c.session_id, c.sequence_number
"""

# Without this, the planner estimates a chunk's commands as a few percent of
# the table and seq-scans all of it (7.7M rows, 4.3 GB, October 2026) for every
# chunk, so each run would read the whole table ~28 times per week exported.
# Forced onto idx_commands_session_id, a chunk reads only its own sessions'
# commands: the same 4s per 6h telnet chunk today, but flat as the table grows.
COMMANDS_PLANNER = ("SET LOCAL enable_seqscan = off",)

PENDING_ENRICHMENT_SQL = """
    SELECT count(*) FROM sessions
    WHERE start_ms >= %(lo)s AND start_ms < %(hi)s AND protocol = 'ssh'
      AND attacker_class IS NULL AND outcome <> 'active'
"""

FIRST_SESSION_SQL = "SELECT min(start_ms) FROM sessions WHERE protocol = %(protocol)s"


def _scalar(conn, sql: str, params: dict):
    with conn.transaction():
        return conn.execute(sql, params).fetchone()[0]


def write_table(conn, sql: str, schema: pa.Schema, to_record, protocol: str, week: Week,
                chunk_ms: int, out_path: Path, planner: tuple[str, ...] = ()) -> int:
    """Stream one week of rows into a Parquet file, chunk by chunk."""
    from psycopg.rows import dict_row

    rows_written = 0
    buffer: list[dict] = []
    with pq.ParquetWriter(out_path, schema, compression="zstd") as writer:
        for lo in range(week.start_ms, week.end_ms, chunk_ms):
            params = {"lo": lo, "hi": min(lo + chunk_ms, week.end_ms), "protocol": protocol}
            # One short transaction per chunk: nothing holds a snapshot or a
            # lock for the length of the whole week.
            with conn.transaction():
                for setting in planner:
                    conn.execute(setting)
                with conn.cursor(name="dataset_export", row_factory=dict_row) as cur:
                    cur.itersize = 5000
                    cur.execute(sql, params)
                    for row in cur:
                        buffer.append(to_record(row))
                        if len(buffer) >= ROW_GROUP_ROWS:
                            writer.write_table(pa.Table.from_pylist(buffer, schema=schema))
                            rows_written += len(buffer)
                            buffer.clear()
        if buffer:
            writer.write_table(pa.Table.from_pylist(buffer, schema=schema))
            rows_written += len(buffer)
    return rows_written


def run(conn, store, protocols: list[str], now_ms: int, lag_ms: int, max_wait_ms: int, geo,
        session_ip_salt: str | None, command_ip_salt: str | None, chunk_ms: int) -> dict:
    """Publish every ready, unpublished week. Returns what it did, for logging and tests."""
    # Enforced here rather than trusted to the caller's connection string.
    conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
    conn.execute("SET statement_timeout = '10min'")
    conn.execute("SET application_name = 'mirage-dataset-export'")

    raw = store.get(MANIFEST)
    manifest = Manifest.from_json(raw) if raw else Manifest.empty()
    summary = {"published": [], "waiting": []}

    for protocol in protocols:
        first_ms = _scalar(conn, FIRST_SESSION_SQL, {"protocol": protocol})
        if first_ms is None:
            continue
        for week in complete_weeks(first_ms, now_ms, lag_ms):
            if manifest.covers(protocol, week):
                continue
            pending = 0
            if protocol == "ssh":
                pending = _scalar(conn, PENDING_ENRICHMENT_SQL, {"lo": week.start_ms, "hi": week.end_ms})
            if not is_ready(week, now_ms, pending, max_wait_ms):
                summary["waiting"].append((protocol, week.label, pending))
                log(f"{protocol} {week.label}: waiting on {pending} unclassified sessions")
                continue

            started = time.monotonic()
            with tempfile.TemporaryDirectory() as tmp:
                files = {}
                for table, sql, schema, to_record, planner in (
                    ("sessions", SESSIONS_SQL, SESSION_SCHEMA, lambda r: session_record(r, geo, session_ip_salt), ()),
                    ("commands", COMMANDS_SQL, COMMAND_SCHEMA, lambda r: command_record(r, command_ip_salt),
                     COMMANDS_PLANNER),
                ):
                    out = Path(tmp) / f"{table}.parquet"
                    rows = write_table(conn, sql, schema, to_record, protocol, week, chunk_ms, out, planner)
                    files[table] = (out, rows)
                publish_week(store, manifest, protocol, week, files, pending)
            summary["published"].append((protocol, week.label))
            log(
                f"{protocol} {week.label}: {files['sessions'][1]} sessions, {files['commands'][1]} commands"
                f" in {time.monotonic() - started:.0f}s" + (f" ({pending} unclassified)" if pending else "")
            )
    return summary


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {msg}", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--geo-asn-csv", required=True)
    parser.add_argument("--geo-country-csv", required=True)
    parser.add_argument("--protocols", default="ssh,telnet")
    parser.add_argument("--out-dir", help="write to this directory instead of R2")
    parser.add_argument("--lag-hours", type=float, default=24)
    parser.add_argument("--max-wait-days", type=float, default=7)
    parser.add_argument("--chunk-hours", type=float, default=6)
    parser.add_argument(
        "--anonymize-session-ips", action="store_true",
        help="hash client_ip in sessions files too (off: sessions carry the real IP, as the published dataset always has)",
    )
    parser.add_argument(
        "--no-anonymize-command-ips", action="store_true",
        help="ship real client_ip in commands files (off by default, as in export_commands_dataset.py)",
    )
    args = parser.parse_args()

    ip_salt = os.environ.get("IP_SALT")
    if (args.anonymize_session_ips or not args.no_anonymize_command_ips) and not ip_salt:
        parser.error("IP_SALT must be set to anonymize IPs")

    if args.out_dir:
        store = LocalStore(Path(args.out_dir))
    else:
        missing = [k for k in ("R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET") if not os.environ.get(k)]
        if missing:
            parser.error(f"set {', '.join(missing)} or pass --out-dir")
        store = R2Store(os.environ["R2_ACCOUNT_ID"], os.environ["R2_ACCESS_KEY_ID"],
                        os.environ["R2_SECRET_ACCESS_KEY"], os.environ["R2_BUCKET"])

    from geo_lookup import GeoLookup

    lookup = GeoLookup(args.geo_asn_csv, args.geo_country_csv)

    @lru_cache(maxsize=1_000_000)
    def geo(ip: str):
        r = lookup.lookup(ip)
        return r.asn, r.asn_name, r.country

    import psycopg

    conn = psycopg.connect(
        host=os.environ["DB_HOST"], port=os.environ.get("DB_PORT", "5432"), user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"], dbname=os.environ["DB_NAME"], autocommit=True,
    )
    with conn:
        summary = run(
            conn, store,
            protocols=[p.strip() for p in args.protocols.split(",") if p.strip()],
            now_ms=int(time.time() * 1000),
            lag_ms=int(args.lag_hours * HOUR_MS),
            max_wait_ms=int(args.max_wait_days * DAY_MS),
            geo=geo,
            session_ip_salt=ip_salt if args.anonymize_session_ips else None,
            command_ip_salt=None if args.no_anonymize_command_ips else ip_salt,
            chunk_ms=int(args.chunk_hours * HOUR_MS),
        )
    log(f"done: published {len(summary['published'])} week files, {len(summary['waiting'])} waiting")


if __name__ == "__main__":
    main()
