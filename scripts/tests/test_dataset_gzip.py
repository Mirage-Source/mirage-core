"""
Plain-assert tests for the gzip-compressed dataset files. GitHub rejects any
pushed file over 100 MB, and sessions.json reached 189 MB uncompressed; gzip
brings it to ~14 MB. Confirms:
  - every published data file is named *.gz and really is gzip on disk
  - each writer's output reads back to the same rows
  - generate_report reads the compressed CSV, and still reads the plain
    sessions.csv in versions published before compression

Usage:
    python3 scripts/tests/test_dataset_gzip.py
"""

import csv
import gzip
import io
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dataset_io import COMMANDS_JSONL, SESSIONS_CSV, SESSIONS_JSON  # noqa: E402
from export_commands_dataset import write_jsonl  # noqa: E402
from export_dataset import FIELDNAMES, write_csv, write_json  # noqa: E402
from generate_report import load_sessions  # noqa: E402

GZIP_MAGIC = b"\x1f\x8b"


def _row(i: int) -> dict:
    row = {name: "" for name in FIELDNAMES}
    row.update(session_id=f"s{i}", client_ip=f"198.51.100.{i}", command_count=i)
    return row


def _is_gzip(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(2) == GZIP_MAGIC


def test_published_names_are_gz():
    for name in (SESSIONS_CSV, SESSIONS_JSON, COMMANDS_JSONL):
        assert name.endswith(".gz"), name


def test_write_csv_gz_round_trips():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / SESSIONS_CSV
        write_csv([_row(1), _row(2)], path)
        assert _is_gzip(path)
        with gzip.open(path, "rt", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert [r["session_id"] for r in rows] == ["s1", "s2"]
        assert rows[1]["command_count"] == "2"


def test_csv_carries_build_sha_and_tolerates_an_older_api():
    stamped = _row(1)
    stamped["build_sha"] = "abc1234-dirty"
    old_api = {k: v for k, v in _row(2).items() if k != "build_sha"}  # API from before schema 1.2
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / SESSIONS_CSV
        write_csv([stamped, old_api], path)
        with gzip.open(path, "rt", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    assert rows[0]["build_sha"] == "abc1234-dirty"
    assert rows[1]["build_sha"] == ""
    assert FIELDNAMES.index("build_sha") == FIELDNAMES.index("node_id") + 1


def test_write_json_gz_round_trips():
    raw = [{"session_id": "s1", "client_ip": "real", "mitre_techniques": ["T1059"]}]
    enriched = [{"client_ip": "anon", "asn": 64500, "asn_name": "TEST", "country": "DE"}]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / SESSIONS_JSON
        write_json(raw, enriched, path)
        assert _is_gzip(path)
        with gzip.open(path, "rt", encoding="utf-8") as f:
            out = json.load(f)
        assert out == [{
            "session_id": "s1", "client_ip": "anon", "mitre_techniques": ["T1059"],
            "asn": 64500, "asn_name": "TEST", "country": "DE",
        }]


def test_write_jsonl_gz_round_trips():
    rows = [{"event_id": "e1", "raw_command": "uname -a"}, {"event_id": "e2", "raw_command": "id"}]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / COMMANDS_JSONL
        write_jsonl(rows, path)
        assert _is_gzip(path)
        with gzip.open(path, "rt", encoding="utf-8") as f:
            assert [json.loads(line) for line in f] == rows


def test_load_sessions_reads_gz():
    with tempfile.TemporaryDirectory() as d:
        write_csv([_row(1)], Path(d) / SESSIONS_CSV)
        assert [r["session_id"] for r in load_sessions(Path(d))] == ["s1"]


def test_load_sessions_falls_back_to_plain_csv():
    with tempfile.TemporaryDirectory() as d:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerow(_row(7))
        (Path(d) / "sessions.csv").write_text(buf.getvalue(), encoding="utf-8")
        assert [r["session_id"] for r in load_sessions(Path(d))] == ["s7"]


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\n{len(tests)} tests passed")
