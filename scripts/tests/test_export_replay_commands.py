"""scripts/export_replay_commands.py turns a sessions database into the corpus the shell replay runs.

A command is weighted by the number of distinct sessions that ran it, not by how many times it appears:
a bot that retries eight times is still one session. Pure functions only; no database needed.
"""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from export_replay_commands import build_sql, parse_rows, to_jsonl  # noqa: E402


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def test_rows_are_decoded_from_base64_so_newlines_and_quotes_survive_csv():
    csv_text = f"sessions,cmd_b64\n5241,{_b64('uname -s')}\n3,{_b64(chr(10).join(['a', 'b']))}\n"
    assert parse_rows(csv_text) == [(5241, "uname -s"), (3, "a\nb")]


def test_jsonl_round_trips_multiline_unicode_and_tabs():
    rows = [(2, "echo 'é'\n\techo \"x\""), (1, "")]
    lines = to_jsonl(rows).splitlines()
    assert [json.loads(l) for l in lines] == [{"sessions": 2, "cmd": "echo 'é'\n\techo \"x\""}, {"sessions": 1, "cmd": ""}]


def test_sql_counts_distinct_sessions_and_breaks_ties_deterministically():
    sql = build_sql("ssh", top=500, max_bytes=4000)
    assert "count(DISTINCT" in sql and "session_id" in sql
    assert "octet_length(cmd) < 4000" in sql
    assert "ORDER BY 1 DESC, cmd" in sql      # ties at the cut must not depend on plan or luck
    assert "LIMIT 500" in sql and "protocol = 'ssh'" in sql


def test_any_protocol_has_no_protocol_filter():
    assert "protocol =" not in build_sql("any", top=10, max_bytes=100)


def test_protocol_and_limits_are_validated_not_interpolated_blindly():
    for bad in ("ssh' OR '1'='1", "tel;net", ""):
        try:
            build_sql(bad, top=10, max_bytes=100)
        except ValueError:
            continue
        raise AssertionError(f"accepted protocol {bad!r}")
    try:
        build_sql("ssh", top="10; DROP TABLE sessions", max_bytes=100)
    except (ValueError, TypeError):
        pass
    else:
        raise AssertionError("accepted a non-integer limit")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok", t.__name__)
    print(f"\n{len(tests)} tests passed")
