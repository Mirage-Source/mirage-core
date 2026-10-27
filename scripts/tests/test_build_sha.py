"""scripts/build_sha.sh prints the stamp for the binary a `docker compose build` is about to make.

Docker copies the whole working tree, including untracked files, so "dirty" has to
mean any difference from HEAD, not just modified tracked files (which is all
`git describe --dirty` looks at).
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "build_sha.sh"
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]


def _run(cwd):
    r = subprocess.run(["sh", str(SCRIPT)], cwd=cwd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _repo(d):
    subprocess.run(GIT + ["init", "-q"], cwd=d, check=True)
    (Path(d) / "a.go").write_text("package a\n")
    subprocess.run(GIT + ["add", "."], cwd=d, check=True)
    subprocess.run(GIT + ["commit", "-q", "-m", "x"], cwd=d, check=True)
    return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=d, capture_output=True, text=True).stdout.strip()


def test_clean_tree_is_the_short_sha():
    with tempfile.TemporaryDirectory() as d:
        sha = _repo(d)
        assert _run(d) == sha


def test_modified_tracked_file_is_dirty():
    with tempfile.TemporaryDirectory() as d:
        sha = _repo(d)
        (Path(d) / "a.go").write_text("package a // changed\n")
        assert _run(d) == sha + "-dirty"


def test_untracked_file_is_dirty_because_docker_copies_it():
    with tempfile.TemporaryDirectory() as d:
        sha = _repo(d)
        (Path(d) / "new.go").write_text("package a\n")
        assert _run(d) == sha + "-dirty"


def test_outside_a_repository_is_unknown_not_an_error():
    with tempfile.TemporaryDirectory() as d:
        assert _run(d) == "unknown"


def test_runs_from_a_subdirectory():
    with tempfile.TemporaryDirectory() as d:
        sha = _repo(d)
        (Path(d) / "sub").mkdir()
        assert _run(Path(d) / "sub") == sha


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\n{len(tests)} tests passed")
