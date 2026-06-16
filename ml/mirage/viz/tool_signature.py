"""Weak tool-signature inference for coloring and evaluation.

Public Cowrie corpora carry no ground-truth "which tool / botnet" label, so -- as
with the Phase-1 bait inference -- we derive a **weak label** from command
content. The signature is a coarse family of automated SSH-attack behavior,
matched by regex over the session's command skeleton:

* ``dropper``        -- fetch + execute a payload (wget/curl/tftp -> chmod -> run).
* ``miner``          -- cryptominer install (xmrig, minerd, stratum pools).
* ``ddos_botnet``    -- Mirai/Gafgyt-style busybox + multi-arch binary pulls.
* ``recon``          -- enumeration only (uname, whoami, cat /proc, ls, w).
* ``persistence``    -- authorized_keys / cron / user manipulation.
* ``defense_evasion``-- history wipe, log/iptables tampering.
* ``other``          -- anything unmatched.

These labels are deliberately *not* used during training (training is
self-supervised). They are used only to **color** the embedding map and to score
clustering quality -- i.e. to test whether the unsupervised embedding recovers
tool families it was never told about. Treat them as noisy ground truth, the same
caveat that applies to ``mirage.data.bait``.

Stdlib-only (regex over strings); no torch / sklearn dependency.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

__all__ = ["TOOL_SIGNATURES", "infer_tool_signature"]

#: Ordered (label, compiled-pattern) rules. Order encodes priority: the first
#: family whose evidence threshold is met wins. More specific / higher-intent
#: families are listed before generic ones.
_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("miner", re.compile(r"xmrig|minerd|cpuminer|stratum\+tcp|--donate-level|nicehash", re.I)),
    ("ddos_botnet", re.compile(r"busybox|mirai|gafgyt|\.(?:mips|arm|x86|sh4|ppc)\b|tftp\s+-[gr]", re.I)),
    ("dropper", re.compile(r"\b(?:wget|curl|tftp|ftpget)\b.*?(?:http|ftp|\d+\.\d+\.\d+\.\d+)", re.I)),
    ("persistence", re.compile(r"authorized_keys|crontab|/etc/cron|useradd|adduser|/etc/passwd\s*>>", re.I)),
    ("defense_evasion", re.compile(r"history\s+-c|>\s*/var/log|iptables\s+-F|chattr|unset\s+HISTFILE", re.I)),
    ("recon", re.compile(r"\b(?:uname|whoami|id|w|lscpu|nproc|free|cat\s+/proc|ls\s|lspci)\b", re.I)),
]


#: Public, importable view of the supported labels (in priority order).
TOOL_SIGNATURES: tuple[str, ...] = tuple(label for label, _ in _RULES) + ("other",)


def infer_tool_signature(commands: Iterable[str]) -> str:
    """Infer a weak tool-family label from a session's raw command lines.

    Args:
        commands: The session's raw command strings (e.g.
            ``session.raw_commands()``).

    Returns:
        One of :data:`TOOL_SIGNATURES`. A session matching several families is
        assigned the highest-priority match (rule order); ``"other"`` if nothing
        matches.
    """
    blob = "\n".join(commands)
    if not blob.strip():
        return "other"
    hits: Counter[str] = Counter()
    for label, pattern in _RULES:
        if pattern.search(blob):
            hits[label] += 1
    if not hits:
        return "other"
    # Rules are pre-ordered by priority; return the earliest matched rule.
    for label, _ in _RULES:
        if hits[label]:
            return label
    return "other"
