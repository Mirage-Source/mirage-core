#!/usr/bin/env python3
"""Check or regenerate the Ubuntu 22.04 ground truth behind the shell's differential test.

internal/shell/testdata/ubuntu2204.json holds shell commands with the stdout, stderr and exit status a
real ubuntu:22.04 container produced for each (`bash -c <cmd>`, root, cwd /root, no network, no stdin).
The Go test (TestMatchesUbuntu2204) requires the simulated shell to reproduce every byte.

  python3 scripts/ubuntu_diff.py check    # compare the file with the container; changes nothing
  python3 scripts/ubuntu_diff.py regen    # rewrite every expectation from the container

To add a case, append {"cmd": "..."} to "cases" and run `regen`. Never edit an expected value to make a
test pass: the value is whatever Ubuntu printed, and the shell is what gets fixed. `regen` records the image
id and bash version, and `check` warns if the image on this machine is not the one the file was made with.
Needs Docker. The commands are short probes written for this test, not attacker input.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

IMAGE = "ubuntu:22.04"
DEFAULT = Path(__file__).resolve().parent.parent / "internal/shell/testdata/ubuntu2204.json"


class Container:
    """A fresh container per command, so no case can see another's files."""

    def __init__(self, image: str = IMAGE):
        self.image = image
        self._id = self._bash = None

    def _docker(self, *args):
        return subprocess.run(["docker", *args], capture_output=True, stdin=subprocess.DEVNULL, check=True)

    @property
    def image_id(self) -> str:
        if self._id is None:
            self._id = self._docker("image", "inspect", "--format", "{{.Id}}", self.image).stdout.decode().strip()
        return self._id

    @property
    def bash_version(self) -> str:
        if self._bash is None:
            out = self._docker("run", "--rm", "--network", "none", self.image, "bash", "--version").stdout.decode()
            self._bash = out.splitlines()[0]
        return self._bash

    def run(self, cmd: str):
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "-w", "/root", self.image, "bash", "-c", cmd],
                           capture_output=True, stdin=subprocess.DEVNULL)
        return r.stdout.decode("utf-8"), r.stderr.decode("utf-8"), r.returncode  # strict: invalid UTF-8 is an error


def _load(path: Path) -> dict:
    doc = json.loads(Path(path).read_text())
    seen = set()
    for c in doc["cases"] + doc.get("known_gaps", []):
        if c["cmd"] in seen:
            raise ValueError(f"duplicate command: {c['cmd']!r}")
        seen.add(c["cmd"])
    return doc


def _dump(doc: dict) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n"


def check(path, container):
    """Return (mismatches, warnings). Each mismatch has cmd, got and want."""
    doc = _load(path)
    warnings = []
    if doc.get("image_id") != container.image_id:
        warnings.append(f"image changed: file made with {doc.get('image_id')}, this machine has {container.image_id}")
    bad = []
    for c in doc["cases"] + doc.get("known_gaps", []):
        out, err, code = container.run(c["cmd"])
        got = {"stdout": out, "stderr": err, "code": code}
        want = {"stdout": c.get("stdout"), "stderr": c.get("stderr"), "code": c.get("code")}
        if got != want:
            bad.append({"cmd": c["cmd"], "got": got, "want": want})
    return bad, warnings


def regen(path, container):
    doc = _load(path)
    for c in doc["cases"] + doc.get("known_gaps", []):
        c["stdout"], c["stderr"], c["code"] = container.run(c["cmd"])
    doc.update(image=getattr(container, "image", IMAGE), image_id=container.image_id, bash=container.bash_version)
    Path(path).write_text(_dump(doc))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("action", choices=["check", "regen"])
    ap.add_argument("file", nargs="?", default=str(DEFAULT))
    a = ap.parse_args(argv)
    c = Container()
    if a.action == "regen":
        regen(a.file, c)
        print(f"regenerated {a.file} from {c.image_id[:19]} ({c.bash_version})")
        return 0
    bad, warnings = check(a.file, c)
    for w in warnings:
        print("warning:", w)
    for b in bad:
        print(f"DIFFERS {b['cmd']!r}\n  got  {b['got']}\n  want {b['want']}")
    n = len(_load(a.file)["cases"]) + len(_load(a.file).get("known_gaps", []))
    print(f"{n} cases, {len(bad)} differ from the container")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
