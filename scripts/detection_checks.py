#!/usr/bin/env python3
"""Run published honeypot-detection checks against SSH/Telnet targets.

Each check is taken from a public source (cited in its `source`) or from
known Cowrie/Kippo defaults, and is run against every target, including a
real reference host:

  - Protocol probes (Bitter Harvest, Vetterl & Clayton, WOOT '18; Srinivasa
    et al., "Gotta catch 'em all", DTRAP 2023): PASS when the target's
    observable reply equals the reference's.
  - Credential and shell probes (SANS ISC diaries 31064 and 32878, the
    static-response table of Srinivasa et al., cross-command consistency):
    PASS when the target behaves as a real host must. The reference is
    graded too; a check the reference fails is a broken check, not a tell.

    pip install paramiko
    scripts/detection_checks.py \\
        --ssh real=127.0.0.1:22022 --ssh mirage=127.0.0.1:2222 \\
        --ssh cowrie=127.0.0.1:22023 --reference real \\
        --telnet real=127.0.0.1:22323 --telnet mirage=127.0.0.1:2323 \\
        --telnet cowrie=172.17.0.3:2223 \\
        --user root --password password

Prints a markdown table (check x target). Exit status is 1 if any
non-reference target fails a check the reference passes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import sys
import time

try:
    import paramiko
except ImportError:  # protocol probes still run
    paramiko = None

TIMEOUT = 4.0


# ---------------------------------------------------------------- raw SSH

def _recv_until_quiet(s: socket.socket, wait: float = TIMEOUT) -> tuple[bytes, bool]:
    """Read until the peer closes or stays quiet for `wait` seconds.
    Returns (data, closed)."""
    s.settimeout(wait)
    buf = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            return buf, False
        except ConnectionResetError:
            return buf, True
        if not chunk:
            return buf, True
        buf += chunk


def _connect(addr: tuple[str, int]) -> tuple[socket.socket, bytes]:
    s = socket.create_connection(addr, timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    banner = b""
    while not banner.endswith(b"\n"):
        c = s.recv(1)
        if not c:
            break
        banner += c
    return s, banner


def _read_packet(s: socket.socket) -> tuple[int, bytes, bytes] | None:
    """One unencrypted binary packet: (padding_len, payload, padding)."""
    s.settimeout(TIMEOUT)
    try:
        head = _exact(s, 5)
        length, padlen = struct.unpack(">IB", head)
        if length > 35000:
            return None
        rest = _exact(s, length - 1)
    except (OSError, ValueError):
        return None
    return padlen, rest[: length - 1 - padlen], rest[length - 1 - padlen :]


def _exact(s: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        c = s.recv(n - len(out))
        if not c:
            raise ValueError("closed")
        out += c
    return out


def _describe(data: bytes, closed: bool) -> str:
    """Normalise what a server sent after a probe into a comparable label:
    packet types and disconnect texts, not random bytes."""
    labels = []
    rest = data
    while len(rest) >= 6:
        length, padlen = struct.unpack(">IB", rest[:5])
        if length < 5 or length > 35000 or len(rest) < 4 + length:
            break
        payload = rest[5 : 4 + length - padlen]
        rest = rest[4 + length :]
        if payload[:1] == b"\x01" and len(payload) >= 9:  # DISCONNECT
            reason = struct.unpack(">I", payload[1:5])[0]
            n = struct.unpack(">I", payload[5:9])[0]
            labels.append(f"DISCONNECT({reason}) {payload[9:9 + n]!r}")
        elif payload[:1] == b"\x14":
            labels.append("KEXINIT")
        else:
            labels.append(f"msg{payload[:1].hex()}")
    if rest:
        labels.append(f"text {rest[:80]!r}")
    labels.append("closed" if closed else "stays open")
    return ", ".join(labels)


def _kexinit_payload(kex=b"ecdh-sha2-nistp521", hostkey=b"ssh-dss", cipher=b"blowfish-cbc",
                     mac=b"hmac-sha1", comp=b"zlib@openssh.com") -> bytes:
    def nl(x: bytes) -> bytes:
        return struct.pack(">I", len(x)) + x
    return (b"\x14" + os.urandom(16) + nl(kex) + nl(hostkey) + nl(cipher) + nl(cipher)
            + nl(mac) + nl(mac) + nl(comp) + nl(comp) + nl(b"") + nl(b"") + b"\x00" + b"\x00" * 4)


def _packet(payload: bytes, block: int = 8) -> bytes:
    padlen = block - ((5 + len(payload)) % block)
    if padlen < 4:
        padlen += block
    return struct.pack(">IB", 1 + len(payload) + padlen, padlen) + payload + os.urandom(padlen)


def _after_version(addr, client_version: bytes, then: bytes | None = None, skip_kexinit=True) -> str:
    s, _ = _connect(addr)
    try:
        s.sendall(client_version)
        if then is not None:
            if skip_kexinit and _read_packet(s) is None:
                return "no KEXINIT before probe"
            s.sendall(then)
        return _describe(*_recv_until_quiet(s))
    finally:
        s.close()


def probe_version_22(addr):
    return _after_version(addr, b"SSH-2.2-OpenSSH \r\n")


def probe_version_15(addr):
    return _after_version(addr, b"SSH-1.5-OpenSSH_9.0\r\n")


def probe_kippo_newlines(addr):
    return _after_version(addr, b"SSH-2.0-OpenSSH\n\n\n\n\n\n\n\n\n\n")


def probe_http(addr):
    return _after_version(addr, b"GET / HTTP/1.0\r\n\r\n")


def probe_kexinit_no_length(addr):
    return _after_version(addr, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18\r\n",
                          then=_kexinit_payload() + os.urandom(8))


def probe_kexinit_bad_padding(addr):
    return _after_version(addr, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18\r\n",
                          then=_packet(_kexinit_payload(), block=13))


def probe_kexinit_padding(addr):
    s, _ = _connect(addr)
    try:
        s.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18\r\n")
        p = _read_packet(s)
        if p is None:
            return "no KEXINIT"
        padlen, _, pad = p
        return "NUL padding" if pad == b"\x00" * padlen else "random padding"
    finally:
        s.close()


# ------------------------------------------------------------- SSH login

class Shell:
    """One SSH connection; run() opens a fresh exec channel per command,
    the way most bots drive a box."""

    def __init__(self, host, port, user, password):
        self.c = paramiko.SSHClient()
        self.c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.c.connect(host, port, user, password, timeout=10, banner_timeout=10,
                       auth_timeout=15, look_for_keys=False, allow_agent=False)

    def run(self, cmd: str) -> tuple[bytes, bytes, int]:
        ch = self.c.get_transport().open_session(timeout=10)
        ch.settimeout(15)
        # exec with want_reply=false, as OpenSSH's client effectively
        # tolerates: Cowrie closes the channel before acknowledging the
        # request, which paramiko's exec_command reports as a failure.
        m = paramiko.Message()
        m.add_byte(paramiko.common.cMSG_CHANNEL_REQUEST)
        m.add_int(ch.remote_chanid)
        m.add_string("exec")
        m.add_boolean(False)
        m.add_string(cmd)
        ch.transport._send_user_message(m)
        out, err = b"", b""
        while True:
            if ch.recv_ready():
                out += ch.recv(65536)
            elif ch.recv_stderr_ready():
                err += ch.recv_stderr(65536)
            elif ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():
                break
            else:
                time.sleep(0.02)
        code = ch.recv_exit_status()
        ch.close()
        return out, err, code

    def close(self):
        self.c.close()


def accepts(host, port, user, password) -> bool:
    t = paramiko.Transport((host, port))
    t.banner_timeout = 10
    try:
        t.connect()
        t.auth_password(user, password)
        return t.is_authenticated()
    except paramiko.AuthenticationException:
        return False
    finally:
        t.close()


def _text(b: bytes) -> str:
    return b.decode("utf-8", "replace")


# Each shell check: (name, source, function(shell) -> (passed, observation)).

def sh_dd_self_exe(sh):
    cmd = ("busybox dd if=$SHELL bs=22 count=1||dd if=/proc/self/exe bs=22 count=1||"
           "while read i;do busybox echo -n $i;done</proc/self/exe||cat /proc/self/exe")
    out, _, _ = sh.run(cmd)
    ok = out.startswith(b"\x7fELF") and len(out) == 22
    return ok, f"{len(out)} bytes, starts {out[:4]!r}"


def sh_dir_marker(sh):
    out, _, _ = sh.run(r'(/bin/busybox echo -e "\x44\x49\x52"||echo -e "\x44\x49\x52")')
    return out.strip() == b"DIR", repr(out[:40])


def sh_busybox_marker(sh):
    has, _, _ = sh.run("test -e /bin/busybox && echo yes || echo no")
    out, err, _ = sh.run("cd /dev/shm; cat .s || cp /bin/echo .s; /bin/busybox ZRKTA")
    both = _text(out + err)
    if has.strip() == b"yes":
        ok = "ZRKTA: applet not found" in both
    else:
        ok = "/bin/busybox: No such file or directory" in both
    return ok, f"busybox={_text(has).strip()}: {both.strip()[-70:]!r}"


def sh_fake_install(sh):
    out, err, code = sh.run("apt-get install -y qzxvbnmlkjh")
    both = _text(out + err)
    ok = "Unable to locate package qzxvbnmlkjh" in both and code != 0
    return ok, f"exit {code}: {both.strip()[-70:]!r}"


def sh_static_arp(sh):
    out, err, _ = sh.run("arp -a; arp")
    both = _text(out + err)
    ok = "52:5e:0a:40:43:c8" not in both and "192.168.1.27" not in both
    return ok, repr(both.strip()[:70])


def sh_static_vi(sh):
    out, err, _ = sh.run("vi --version | head -1; nano --version | head -1")
    both = _text(out + err)
    return "E558: Terminal entry not found" not in both, repr(both.strip()[:70])


def sh_cowrie_defaults(sh):
    host, _, _ = sh.run("hostname")
    uname, _, _ = sh.run("uname -a")
    passwd, _, _ = sh.run("cat /etc/passwd")
    hits = [s for s in ("svr04", "phil:", "3.2.0-4-amd64", "Debian 3.2.68")
            if s.encode() in host + uname + passwd]
    return not hits, ", ".join(hits) or "none of svr04/phil/3.2.0-4"


def sh_hostname_consistent(sh):
    a, _, _ = sh.run("hostname")
    b, _, _ = sh.run("cat /etc/hostname")
    return a.strip() == b.strip() and a.strip() != b"", f"{_text(a).strip()!r} vs {_text(b).strip()!r}"


def sh_uname_proc_version(sh):
    r, _, _ = sh.run("uname -r")
    v, _, _ = sh.run("cat /proc/version")
    return r.strip() != b"" and r.strip() in v, f"uname -r {_text(r).strip()!r}"


def sh_nproc_cpuinfo(sh):
    n, _, _ = sh.run("nproc")
    c, _, _ = sh.run("grep -c ^processor /proc/cpuinfo")
    return n.strip() == c.strip() and n.strip().isdigit(), f"nproc {_text(n).strip()!r}, cpuinfo {_text(c).strip()!r}"


def sh_meminfo_free(sh):
    f, _, _ = sh.run("free -k | awk '/^Mem:/{print $2}'")
    m, _, _ = sh.run("awk '/^MemTotal:/{print $2}' /proc/meminfo")
    return f.strip() == m.strip() and f.strip().isdigit(), f"free {_text(f).strip()!r}, meminfo {_text(m).strip()!r}"


def sh_size_matches_content(sh):
    ls, _, _ = sh.run("ls -l /etc/passwd")
    wc, _, _ = sh.run("wc -c < /etc/passwd")
    fields = _text(ls).split()
    size = fields[4] if len(fields) > 4 else "?"
    return size == _text(wc).strip(), f"ls {size}, wc {_text(wc).strip()!r}"


def sh_exec_newlines(sh):
    out, _, _ = sh.run("echo hi")
    return out == b"hi\n", repr(out)


def sh_stderr_channel(sh):
    out, err, code = sh.run("ls /nonexistent_dir")
    ok = out == b"" and b"No such file or directory" in err and code == 2
    return ok, f"stdout {out[:40]!r}, stderr {err[:40]!r}, exit {code}"


def sh_not_found(sh):
    # bash 5.1 (Ubuntu 22.04) running a command line under -c, as sshd does.
    out, err, code = sh.run("qzxv_nope")
    ok = err == b"bash: line 1: qzxv_nope: command not found\n" and code == 127
    return ok, f"stderr {err.strip()[:50]!r}, exit {code}"


def sh_persist_across_channels(sh):
    sh.run("echo mirage_probe_7 > /tmp/.dc_probe")
    out, _, _ = sh.run("cat /tmp/.dc_probe")
    sh.run("rm -f /tmp/.dc_probe")
    return out.strip() == b"mirage_probe_7", repr(out[:40])


def sh_shell_vars(sh):
    out, _, _ = sh.run("echo $0 $SHELL")
    return out == b"bash /bin/bash\n", repr(out)


def sh_many_execs(sh):
    # Bots often run each step as its own exec on one connection. OpenSSH
    # limits concurrent sessions (MaxSessions 10), not how many in total.
    for i in range(20):
        out, _, _ = sh.run(f"echo {i}")
        if out.strip() != str(i).encode():
            return False, f"exec #{i + 1} gave {out[:30]!r}"
    return True, "20 of 20 answered"


def sh_case_in_substitution(sh):
    # The botnet self-test seen on both Mirage sensors wraps a case statement in $( ). bash accepts it;
    # a parser that miscounts the ")" ending a case pattern fails with a syntax error. None of the
    # published checks above exercises it, so they score the regressed and the fixed shell alike.
    out, err, code = sh.run('x=$(case a in a) echo sub;; esac); echo "[$x]"')
    ok = out == b"[sub]\n" and err == b"" and code == 0
    return ok, f"stdout {out[:40]!r}, stderr {err[:50]!r}, exit {code}"


def sh_write_chmod_run(sh):
    # The self-test also writes a small script, marks it executable and runs it.
    out, err, code = sh.run("printf '#!/bin/bash\\necho hi\\n' > /tmp/.dc_script && chmod +x /tmp/.dc_script "
                            "&& /tmp/.dc_script; rm -f /tmp/.dc_script")
    ok = out == b"hi\n" and err == b"" and code == 0
    return ok, f"stdout {out[:40]!r}, stderr {err[:50]!r}, exit {code}"


def sh_own_sshd(sh):
    out, _, _ = sh.run("ps aux")
    return b"sshd" in out, f"{out.count(b'sshd')} sshd lines"


SHELL_CHECKS = [
    ("dd 22 bytes of $SHELL / /proc/self/exe", "SANS ISC 31064", sh_dd_self_exe),
    ("echo -e hex marker prints DIR", "SANS ISC 31064", sh_dir_marker),
    ("/bin/busybox ZRKTA marker", "SANS ISC 31064", sh_busybox_marker),
    ("apt-get install of a nonexistent package fails", "SANS ISC 32878", sh_fake_install),
    ("arp: no Cowrie static table", "Srinivasa et al. Table 14", sh_static_arp),
    ("vi/nano: no Kippo E558", "Srinivasa et al. Table 14", sh_static_vi),
    ("no Cowrie default host/users/kernel", "Cowrie defaults", sh_cowrie_defaults),
    ("hostname == /etc/hostname", "consistency", sh_hostname_consistent),
    ("uname -r appears in /proc/version", "consistency", sh_uname_proc_version),
    ("nproc == processors in /proc/cpuinfo", "consistency", sh_nproc_cpuinfo),
    ("free total == /proc/meminfo MemTotal", "consistency", sh_meminfo_free),
    ("ls -l size == wc -c (/etc/passwd)", "consistency", sh_size_matches_content),
    ("exec output uses \\n, not \\r\\n (no pty)", "consistency", sh_exec_newlines),
    ("errors on stderr, exit 2", "consistency", sh_stderr_channel),
    ("unknown command: not found on stderr, exit 127", "consistency", sh_not_found),
    ("file written in one exec is there in the next", "consistency", sh_persist_across_channels),
    ("ps shows sshd", "consistency", sh_own_sshd),
    ("case statement inside $( )", "botnet self-test (Mirage logs)", sh_case_in_substitution),
    ("write, chmod +x and run a script", "botnet self-test (Mirage logs)", sh_write_chmod_run),
    ("echo $0 $SHELL under exec", "consistency", sh_shell_vars),
    ("20 sequential execs on one connection", "consistency", sh_many_execs),
]

PROTOCOL_CHECKS = [
    ("version SSH-2.2 (best BH probe)", "Bitter Harvest 4.4.2", probe_version_22),
    ("version SSH-1.5", "Bitter Harvest 3.2", probe_version_15),
    ("version + 9 newlines (detect_kippo)", "Srinivasa et al. Table 1", probe_kippo_newlines),
    ("HTTP request on SSH port", "Srinivasa et al. 2.2.1", probe_http),
    ("KEXINIT without length fields", "Bitter Harvest 4.4.2", probe_kexinit_no_length),
    ("KEXINIT padded mod 13", "Bitter Harvest 4.4.2", probe_kexinit_bad_padding),
    ("server KEXINIT padding bytes", "Bitter Harvest 4.4.1", probe_kexinit_padding),
]


# ------------------------------------------------------------------ Telnet

def telnet_greeting(addr):
    s = socket.create_connection(addr, timeout=TIMEOUT)
    try:
        data, closed = _recv_until_quiet(s, 2.0)
        # The hostname in the prompt differs per host; compare the rest.
        data = re.sub(rb"[^\r\n\xff]+ login: $", b"<host> login: ", data)
        return f"{data[:60]!r}"
    finally:
        s.close()


def telnet_bh_probe(addr):
    s = socket.create_connection(addr, timeout=TIMEOUT)
    try:
        _recv_until_quiet(s, 2.0)
        s.sendall(b"\xff\xfb\x00\xff\xfb\x12")  # IAC WILL BINARY IAC WILL LOGOUT
        data, closed = _recv_until_quiet(s, 2.0)
        return f"{data[:60]!r}{' closed' if closed else ''}"
    finally:
        s.close()


TELNET_CHECKS = [
    ("greeting bytes (negotiation + prompt)", "Srinivasa et al. Table 10", telnet_greeting),
    ("reply to IAC WILL BINARY IAC WILL LOGOUT", "Bitter Harvest 3.2", telnet_bh_probe),
]


# -------------------------------------------------------------------- main

def parse_targets(items):
    out = {}
    for it in items or []:
        name, hostport = it.split("=", 1)
        host, port = hostport.rsplit(":", 1)
        out[name] = (host, int(port))
    return out


def run_check(fn, *args):
    try:
        return fn(*args)
    except Exception as e:  # a probe that crashes is an observation too
        return f"error: {type(e).__name__}: {e}"[:90]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ssh", action="append", help="name=host:port")
    ap.add_argument("--telnet", action="append", help="name=host:port")
    ap.add_argument("--reference", default="real")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="password")
    ap.add_argument("--json", help="also write raw observations here")
    args = ap.parse_args()

    ssh, telnet = parse_targets(args.ssh), parse_targets(args.telnet)
    names = list(dict.fromkeys(list(ssh) + list(telnet)))
    ref = args.reference
    rows, raw, tells = [], {}, 0

    def cell(name, passed, obs):
        return f"{'pass' if passed else 'FAIL'}: {obs}"

    for title, source, fn in PROTOCOL_CHECKS:
        obs = {n: run_check(fn, a) for n, a in ssh.items()}
        raw[title] = obs
        row = [title, source]
        for n in names:
            if n not in obs:
                row.append("-")
            elif n == ref:
                row.append(f"ref: {obs[n]}")
            else:
                same = obs[n] == obs.get(ref)
                tells += not same
                row.append(cell(n, same, obs[n]))
        rows.append(row)

    if paramiko:
        for title, source in [("improbable login honeypot/indexer", "SANS ISC 32878"),
                              ("root with a random 24-char password", "SANS ISC 32878")]:
            row, raw[title] = [title, source], {}
            for n in names:
                if n not in ssh:
                    row.append("-")
                    continue
                pw = "indexer" if "honeypot" in title else os.urandom(12).hex()
                user = "honeypot" if "honeypot" in title else "root"
                ok = run_check(accepts, *ssh[n], user, pw)
                raw[title][n] = ok
                passed = ok is False
                tells += (n != ref and not passed)
                row.append(cell(n, passed, "rejected" if ok is False else f"accepted ({ok})"))
            rows.append(row)

        for title, source, fn in SHELL_CHECKS:
            row, raw[title] = [title, source], {}
            results = {}
            for n in names:
                if n not in ssh:
                    continue
                # A fresh connection per check, so one check's channel use
                # or state cannot affect the next.
                try:
                    sh = Shell(*ssh[n], args.user, args.password)
                except Exception as e:
                    results[n] = (False, f"login failed: {e}")
                    continue
                r = run_check(fn, sh)
                sh.close()
                results[n] = r if isinstance(r, tuple) else (False, r)
            ref_passed = results.get(ref, (None,))[0]
            for n in names:
                if n not in results:
                    row.append("-")
                    continue
                passed, obs = results[n]
                raw[title][n] = [passed, obs]
                if n != ref and ref_passed and not passed:
                    tells += 1
                label = cell(n, passed, obs)
                if n == ref and not passed:
                    label = f"REF FAILS (check needs work): {obs}"
                row.append(label)
            rows.append(row)

    for title, source, fn in TELNET_CHECKS:
        obs = {n: run_check(fn, a) for n, a in telnet.items()}
        raw[title] = obs
        row = [title, source]
        for n in names:
            if n not in obs:
                row.append("-")
            elif n == ref:
                row.append(f"ref: {obs[n]}")
            else:
                same = obs[n] == obs.get(ref)
                tells += not same
                row.append(cell(n, same, obs[n]))
        rows.append(row)

    md = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    print("| Check | Source | " + " | ".join(names) + " |")
    print("|---|---|" + "---|" * len(names))
    for r in rows:
        print("| " + " | ".join(md(c) for c in r) + " |")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(raw, f, indent=1, default=str)
    sys.exit(1 if tells else 0)


if __name__ == "__main__":
    main()
