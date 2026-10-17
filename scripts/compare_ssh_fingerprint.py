#!/usr/bin/env python3
"""Diff what an SSH server advertises against a reference server.

Runs ssh-audit (pip install ssh-audit) against both and compares the banner,
the KEXINIT algorithm lists (order included) and the auth methods offered
after a failed "none" attempt -- everything a scanner sees before login.

    scripts/compare_ssh_fingerprint.py 127.0.0.1:22022 127.0.0.1:2222

A reference matching the sensor's claimed version:

    docker run -d --rm -p 127.0.0.1:22022:22 ubuntu:22.04 bash -c \\
      "apt-get update -qq && apt-get install -y -qq openssh-server && \\
       mkdir -p /run/sshd && /usr/sbin/sshd -D"

Exit status is 1 if anything differs, so it can gate a release.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys


def audit(target: str) -> dict:
    host, port = target.rsplit(":", 1)
    out = subprocess.run(
        ["ssh-audit", "-j", "-p", port, host],
        capture_output=True, text=True, timeout=60,
    ).stdout
    return json.loads(out)


def auth_methods(target: str) -> str:
    if not shutil.which("ssh"):
        return "?"
    host, port = target.rsplit(":", 1)
    err = subprocess.run(
        ["ssh", "-v", "-p", port, "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "PreferredAuthentications=none", f"probe@{host}", "true"],
        capture_output=True, text=True, timeout=30,
    ).stderr
    m = re.search(r"Authentications that can continue: (\S+)", err)
    return m.group(1) if m else "?"


def lists(j: dict) -> dict[str, list[str]]:
    return {k: [a["algorithm"] for a in j.get(k, [])] for k in ("kex", "key", "enc", "mac")}


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    ref_t, sut_t = sys.argv[1], sys.argv[2]
    ref, sut = audit(ref_t), audit(sut_t)
    differs = False

    rb, sb = ref["banner"]["raw"], sut["banner"]["raw"]
    print(f"banner  ref: {rb}\n        sut: {sb}")

    for k, (rl, sl) in zip(("kex", "key", "enc", "mac"), zip(lists(ref).values(), lists(sut).values())):
        missing = [a for a in rl if a not in sl]
        extra = [a for a in sl if a not in rl]
        common_ref = [a for a in rl if a in sl]
        common_sut = [a for a in sl if a in rl]
        order = "same" if common_ref == common_sut else "DIFFERENT"
        ok = not missing and not extra and order == "same"
        differs |= not ok
        print(f"{k:4} {'ok  ' if ok else 'DIFF'} order of shared: {order}")
        if missing:
            print(f"       only in ref: {', '.join(missing)}")
        if extra:
            print(f"       only in sut: {', '.join(extra)}")

    ra, sa = auth_methods(ref_t), auth_methods(sut_t)
    ok = ra == sa
    differs |= not ok
    print(f"auth {'ok  ' if ok else 'DIFF'} ref: {ra}  sut: {sa}")
    return 1 if differs else 0


if __name__ == "__main__":
    sys.exit(main())
