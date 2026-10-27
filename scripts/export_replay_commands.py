#!/usr/bin/env python3
"""Export the most common real commands from a sessions database as a replay corpus (JSONL).

    DATABASE_URL=postgresql://... python3 scripts/export_replay_commands.py --protocol ssh > replay/ssh.jsonl
    make replay REPLAY_FILE=replay/ssh.jsonl

One line per distinct command: {"sessions": N, "cmd": "..."} where N is the number of distinct sessions
that ran it (a bot retrying eight times in one session counts once). Ties at the cut are broken by the
command text, so the same database always gives the same corpus. Commands of --max-bytes or more are left
out; the default 4000 excludes only the two long variants of the botnet self-test payload (10,972 and
11,956 bytes) and keeps the 3,273-byte one. How much that leaves out is printed to stderr.

The corpus holds attacker-supplied text (addresses, URLs, sometimes keys). Keep it out of version control;
replay/ is ignored. Running it executes nothing: the shell package has no os/exec, network or real
filesystem access.
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import subprocess
import sys

PROTOCOLS = ("ssh", "telnet", "any")


def build_sql(protocol: str, top: int, max_bytes: int) -> str:
    if protocol not in PROTOCOLS:
        raise ValueError(f"protocol must be one of {PROTOCOLS}")
    top, max_bytes = int(top), int(max_bytes)   # raises on anything that is not an integer
    where = "true" if protocol == "any" else f"s.protocol = '{protocol}'"
    return f"""
WITH c AS (SELECT s.session_id, convert_from(decode(c.raw_input_b64, 'base64'), 'UTF8') AS cmd
           FROM commands c JOIN sessions s USING (session_id) WHERE {where})
SELECT count(DISTINCT session_id) AS sessions,
       replace(encode(convert_to(cmd, 'UTF8'), 'base64'), E'\\n', '') AS cmd_b64
FROM c WHERE octet_length(cmd) < {max_bytes}
GROUP BY cmd ORDER BY 1 DESC, cmd LIMIT {top}"""


def parse_rows(csv_text: str):
    return [(int(r["sessions"]), base64.b64decode(r["cmd_b64"]).decode("utf-8"))
            for r in csv.DictReader(io.StringIO(csv_text))]


def to_jsonl(rows) -> str:
    return "".join(json.dumps({"sessions": n, "cmd": c}, ensure_ascii=False) + "\n" for n, c in rows)


def _psql(dsn: str, sql: str) -> str:
    return subprocess.run(["psql", dsn, "--csv", "-c", sql], capture_output=True, text=True, check=True).stdout


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dsn", default=os.environ.get("DATABASE_URL"))
    ap.add_argument("--protocol", default="ssh", choices=PROTOCOLS)
    ap.add_argument("--top", type=int, default=500)
    ap.add_argument("--max-bytes", type=int, default=4000)
    ap.add_argument("--out", help="write here instead of stdout")
    a = ap.parse_args(argv)
    if not a.dsn:
        ap.error("set DATABASE_URL or pass --dsn")
    rows = parse_rows(_psql(a.dsn, build_sql(a.protocol, a.top, a.max_bytes)))
    text = to_jsonl(rows)
    if a.out:
        open(a.out, "w").write(text)
    else:
        sys.stdout.write(text)
    # what the corpus leaves out: sessions with a command, and sessions only reached by too-long commands
    where = "true" if a.protocol == "any" else f"s.protocol = '{a.protocol}'"
    stats = list(csv.DictReader(io.StringIO(_psql(a.dsn, f"""
        SELECT count(DISTINCT session_id) AS all_sessions,
               count(DISTINCT session_id) FILTER (WHERE octet_length(convert_from(decode(raw_input_b64,'base64'),'UTF8')) >= {int(a.max_bytes)}) AS long_sessions
        FROM commands c JOIN sessions s USING (session_id) WHERE {where}"""))))[0]
    covered = sum(n for n, _ in rows)
    print(f"{len(rows)} commands, {covered} session-weights; {stats['all_sessions']} sessions ran a command, "
          f"{stats['long_sessions']} of them a command of {a.max_bytes}+ bytes (left out)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
