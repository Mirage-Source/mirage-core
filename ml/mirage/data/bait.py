"""Heuristic bait-interaction inference for public corpora.

.. note::
   **Reconstructed module.** The original ``bait.py`` was not present in the
   working tree when the integration work was assembled, so this file was rebuilt
   to the behavior documented in ``loader.py`` and the README ("``bait_interactions``
   are back-filled for public corpora ... by ``BaitDetector`` regex rules ... These
   are **weak labels**"). The public surface (:class:`BaitDetector` with
   :meth:`~BaitDetector.detect`) is what the loader depends on. Diff against the
   canonical Phase-1 version if you have it.

MIRAGE's real bait subsystem emits :class:`~mirage.data.schema.BaitInteraction`
events directly. Public Cowrie logs have no such subsystem, so we infer when a
session *touched* a planted-credential class of file from the command content --
a regex over the raw command line. The inferred ``bait_type`` is drawn from the
ML schema's taxonomy (``ssh_key``/``env_file``/``shadow``/``s3``).

These are deliberately weak labels: a session that ``cat``s ``/etc/shadow`` is
flagged as a ``shadow`` bait touch even though the public honeypot had no real
decoy there. Treat the rates as a behavioral signal, not ground truth.
"""

from __future__ import annotations

import re
from datetime import datetime

from .schema import BaitInteraction, BaitType, Command

__all__ = ["BaitDetector", "BAIT_PATTERNS"]

#: Ordered ``(bait_type, pattern)`` rules. The first matching rule per command
#: assigns that command's bait type; a session emits at most one interaction per
#: bait type (its earliest touch), keeping the weak labels sparse and stable.
BAIT_PATTERNS: list[tuple[BaitType, re.Pattern[str]]] = [
    (
        "ssh_key",
        re.compile(
            r"id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|\.ssh/|"
            r"ssh-rsa|BEGIN[ _]?(?:RSA |OPENSSH )?PRIVATE KEY",
            re.IGNORECASE,
        ),
    ),
    (
        "s3",
        re.compile(
            r"s3://|\.aws/credentials|aws_access_key|aws_secret|"
            r"\baws\s+s3\b|s3api",
            re.IGNORECASE,
        ),
    ),
    (
        "shadow",
        re.compile(r"/etc/shadow|\bshadow\b(?:\s+file)?", re.IGNORECASE),
    ),
    (
        "env_file",
        re.compile(r"(?:^|[\s/])\.env\b|\benvironment\s+file\b|/\.env", re.IGNORECASE),
    ),
]


class BaitDetector:
    """Infer bait interactions from a session's commands via regex rules.

    Args:
        patterns: Optional override of the ``(bait_type, pattern)`` rule list;
            defaults to :data:`BAIT_PATTERNS`.
        first_touch_only: If ``True`` (default), emit at most one interaction per
            bait type per session, at the earliest matching command. If ``False``,
            emit one interaction per matching command.
    """

    def __init__(
        self,
        patterns: list[tuple[BaitType, re.Pattern[str]]] | None = None,
        first_touch_only: bool = True,
    ) -> None:
        self.patterns = patterns if patterns is not None else BAIT_PATTERNS
        self.first_touch_only = first_touch_only

    def detect(self, commands: list[Command]) -> list[BaitInteraction]:
        """Scan commands in order and return inferred bait interactions.

        Args:
            commands: The session's time-ordered commands.

        Returns:
            A list of :class:`BaitInteraction`, ordered by time.
        """
        interactions: list[BaitInteraction] = []
        seen: set[BaitType] = set()
        for command in commands:
            raw = command.raw or ""
            for bait_type, pattern in self.patterns:
                if self.first_touch_only and bait_type in seen:
                    continue
                if pattern.search(raw):
                    interactions.append(
                        BaitInteraction(
                            bait_type=bait_type,
                            timestamp=_command_time(command),
                        )
                    )
                    seen.add(bait_type)
        return interactions


def _command_time(command: Command) -> datetime:
    """Best-effort timestamp for a command's bait interaction."""
    return command.timestamp
