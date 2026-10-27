"""scripts/ubuntu_diff.py keeps internal/shell/testdata/ubuntu2204.json honest.

Expected values come from a real ubuntu:22.04 container, never from hand edits: `regen` rewrites every
expectation from the container, `check` compares without writing. The container is replaced by a fake
runner here, so these tests need no Docker.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ubuntu_diff import check, regen  # noqa: E402


class FakeContainer:
    """Answers like a tiny 'ubuntu': echo-ish commands succeed, anything else is command-not-found."""
    image_id = "sha256:aaaa"
    bash_version = "GNU bash, version 5.1.16(1)-release"

    def run(self, cmd):
        if cmd.startswith("echo "):
            return (cmd[5:] + "\n", "", 0)
        return ("", f"bash: line 1: {cmd.split()[0]}: command not found\n", 127)


def _write(tmp, doc):
    p = Path(tmp) / "u.json"
    p.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
    return p


def _doc(cases, gaps=()):
    return {"image": "ubuntu:22.04", "image_id": "sha256:aaaa", "bash": FakeContainer.bash_version,
            "cases": cases, "known_gaps": list(gaps)}


def _case(cmd, out, err="", code=0):
    return {"cmd": cmd, "stdout": out, "stderr": err, "code": code}


def test_check_passes_when_every_case_matches():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, _doc([_case("echo hi", "hi\n"), _case("nope", "", "bash: line 1: nope: command not found\n", 127)]))
        bad, warn = check(p, FakeContainer())
        assert bad == [] and warn == [], (bad, warn)


def test_check_reports_each_mismatch_with_got_and_want():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, _doc([_case("echo hi", "WRONG\n"), _case("echo ok", "ok\n")]))
        bad, _ = check(p, FakeContainer())
        assert len(bad) == 1 and bad[0]["cmd"] == "echo hi", bad
        assert bad[0]["got"]["stdout"] == "hi\n" and bad[0]["want"]["stdout"] == "WRONG\n", bad


def test_check_also_covers_the_known_gaps():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, _doc([], gaps=[_case("echo gap", "stale\n")]))
        bad, _ = check(p, FakeContainer())
        assert [b["cmd"] for b in bad] == ["echo gap"], bad


def test_a_changed_image_is_a_warning_not_a_silent_pass():
    class Other(FakeContainer):
        image_id = "sha256:bbbb"
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, _doc([_case("echo hi", "hi\n")]))
        bad, warn = check(p, Other())
        assert bad == [] and any("image" in w for w in warn), warn


def test_regen_fills_expectations_from_the_container_and_keeps_order():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, _doc([_case("echo b", ""), _case("echo a", "stale"), _case("zzz", "")]))
        regen(p, FakeContainer())
        doc = json.loads(p.read_text())
        assert [c["cmd"] for c in doc["cases"]] == ["echo b", "echo a", "zzz"]
        assert doc["cases"][0]["stdout"] == "b\n" and doc["cases"][1]["stdout"] == "a\n"
        assert doc["cases"][2]["code"] == 127 and "command not found" in doc["cases"][2]["stderr"]


def test_regen_records_provenance_and_is_idempotent():
    class New(FakeContainer):
        image_id = "sha256:cccc"
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, _doc([_case("echo hi", "")]))
        regen(p, New())
        first = p.read_text()
        assert json.loads(first)["image_id"] == "sha256:cccc"
        regen(p, New())
        assert p.read_text() == first, "regen must not churn the file"
        bad, warn = check(p, New())
        assert bad == [] and warn == []


def test_a_new_case_needs_only_its_command():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, _doc([{"cmd": "echo new"}]))
        regen(p, FakeContainer())
        assert json.loads(p.read_text())["cases"][0] == _case("echo new", "new\n")


def test_duplicate_commands_are_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, _doc([_case("echo hi", "hi\n"), _case("echo hi", "hi\n")]))
        try:
            check(p, FakeContainer())
        except ValueError as e:
            assert "duplicate" in str(e)
        else:
            raise AssertionError("duplicate commands must be an error")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok", t.__name__)
    print(f"\n{len(tests)} tests passed")
