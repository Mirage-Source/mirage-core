"""Ingest the live core's ``session_document`` JSON into ML-ready objects.

The Go core (``mirage-core``) serialises each captured session as a rich JSON
document (the ``session.Session`` struct) and stores it in the ``sessions``
table's ``session_document`` column, also exposed via the API at
``/api/sessions/{id}``. That document carries far more than the Phase-1 Cowrie
schema: per-command sequence numbers, working directory and *response source*;
structured **bait interactions** with an access type (read → copy → exfil); auth
attempts with credentials; and the SSH client banner.

This module parses that document into

* a Phase-1 :class:`~mirage.data.schema.Session` (command + timing channels) that
  the existing tokenizer / embedder / trajectory stack consumes unchanged, and
* a :class:`ProductionSession` wrapper carrying the *extra* production signals
  (bait, auth, banner, working dirs, response sources) that Phase-4 intelligence
  needs but the Phase-1 schema does not model.

Keeping the two separate means none of the Phase-1/2/3 code has to change: the
embedder still sees a plain ``Session``, while the intelligence layer reads the
richer fields off the wrapper.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from ..data.schema import Command, Session

__all__ = [
    "AuthAttempt",
    "BaitEvent",
    "ProductionSession",
    "decode_command_text",
    "parse_session_document",
]

#: Bait access types in escalating order of intent (the core's taxonomy).
ACCESS_ESCALATION: dict[str, int] = {"read": 1, "copy": 2, "exfil_attempt": 3}


@dataclass(slots=True)
class AuthAttempt:
    """One credential attempt against the honeypot."""

    timestamp_ms: int
    method: str
    username: str
    credential: str
    success: bool


@dataclass(slots=True)
class BaitEvent:
    """An attacker touching a planted decoy (the core's bait subsystem).

    Attributes:
        timestamp_ms: When the bait was touched.
        bait_id: Identifier of the specific planted decoy.
        bait_type: One of credential / private_key / config / env_file / shadow.
        access_type: read / copy / exfil_attempt -- the escalation signal.
        triggered_by_command_event_id: The command event that triggered it.
    """

    timestamp_ms: int
    bait_id: str
    bait_type: str
    access_type: str
    triggered_by_command_event_id: str

    @property
    def escalation(self) -> int:
        """Numeric intent level (1 read, 2 copy, 3 exfil; 0 unknown)."""
        return ACCESS_ESCALATION.get(self.access_type, 0)


@dataclass
class ProductionSession:
    """A parsed live-core session: the Phase-1 ``Session`` plus production extras.

    Attributes:
        session: The Phase-1 :class:`Session` (command + timing channels).
        client_ip: Source IP of the attacker.
        ssh_banner: The client's SSH version banner (a coarse client fingerprint).
        outcome: Session outcome (clean_disconnect / timeout / ...).
        node_id: Which honeypot node captured this.
        duration_ms: Session duration if known.
        auth_attempts: Credential attempts.
        bait_events: Structured bait interactions.
        working_directories: Per-command working directory (cwd exploration).
        response_sources: Per-command response source (hardcoded / llm / ...).
    """

    session: Session
    client_ip: str
    ssh_banner: str = ""
    outcome: str = ""
    node_id: str = ""
    duration_ms: int | None = None
    auth_attempts: list[AuthAttempt] = field(default_factory=list)
    bait_events: list[BaitEvent] = field(default_factory=list)
    working_directories: list[str] = field(default_factory=list)
    response_sources: list[str] = field(default_factory=list)

    @property
    def max_bait_escalation(self) -> int:
        """Highest bait-access intent reached (0 none .. 3 exfil_attempt)."""
        return max((b.escalation for b in self.bait_events), default=0)


def decode_command_text(command: dict[str, Any]) -> str:
    """Recover the typed command line from a core ``Command`` JSON object.

    Prefers the base64 raw input (exactly what the attacker typed); falls back to
    reconstructing ``parsed_command`` + ``parsed_args`` if the base64 is absent or
    malformed.
    """
    raw_b64 = command.get("raw_input_b64")
    if raw_b64:
        try:
            decoded = base64.b64decode(raw_b64, validate=True)
            text = decoded.decode("utf-8", errors="replace").strip()
            if text:
                return text
        except (binascii.Error, ValueError):
            pass
    parsed = command.get("parsed_command", "")
    args = command.get("parsed_args") or []
    return " ".join([parsed, *(str(a) for a in args)]).strip()


def _epoch_ms_to_dt(ms: int) -> datetime:
    """Convert an epoch-millisecond timestamp to a UTC ``datetime``."""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)


def parse_session_document(doc: dict[str, Any]) -> ProductionSession:
    """Parse a core ``session_document`` dict into a :class:`ProductionSession`.

    Robust to missing optional fields and to both the nested
    (``network.client_ip``, ``timing.start_ms``) and any flattened variants.

    Args:
        doc: The decoded ``session_document`` JSON (e.g. from
            ``/api/sessions/{id}`` or the ``session_document`` column).

    Returns:
        A :class:`ProductionSession`.
    """
    network = doc.get("network") or {}
    timing = doc.get("timing") or {}
    client_ip = network.get("client_ip") or doc.get("client_ip") or "0.0.0.0"
    start_ms = int(timing.get("start_ms") or doc.get("start_ms") or 0)
    start_time = _epoch_ms_to_dt(start_ms)

    commands: list[Command] = []
    working_dirs: list[str] = []
    response_sources: list[str] = []
    for raw_cmd in doc.get("commands", []):
        ts_ms = int(raw_cmd.get("timestamp_ms", start_ms))
        ms_offset = max(0, ts_ms - start_ms)
        commands.append(
            Command(
                timestamp=start_time + timedelta(milliseconds=ms_offset),
                raw=decode_command_text(raw_cmd),
                ms_offset=ms_offset,
            )
        )
        working_dirs.append(raw_cmd.get("working_directory", ""))
        response_sources.append(raw_cmd.get("response_source", ""))

    # Sort commands chronologically (defensive; the core emits them in order).
    order = sorted(range(len(commands)), key=lambda i: commands[i].ms_offset)
    commands = [commands[i] for i in order]
    working_dirs = [working_dirs[i] for i in order]
    response_sources = [response_sources[i] for i in order]

    duration_ms = timing.get("duration_ms") or doc.get("duration_ms")
    session = Session(
        session_id=str(doc.get("session_id", "")),
        ip=str(client_ip),
        start_time=start_time,
        commands=commands,
        duration_ms=int(duration_ms) if duration_ms is not None else None,
    )

    auth_attempts = [
        AuthAttempt(
            timestamp_ms=int(a.get("timestamp_ms", 0)),
            method=a.get("method", ""),
            username=a.get("username", ""),
            credential=a.get("credential", ""),
            success=bool(a.get("success", False)),
        )
        for a in doc.get("auth_attempts", [])
    ]

    # The core serialises bait events under the JSON key "bait_interactions".
    bait_events = [
        BaitEvent(
            timestamp_ms=int(b.get("timestamp_ms", 0)),
            bait_id=b.get("bait_id", ""),
            bait_type=b.get("bait_type", ""),
            access_type=b.get("access_type", ""),
            triggered_by_command_event_id=b.get("triggered_by_command_event_id", ""),
        )
        for b in doc.get("bait_interactions", [])
    ]

    return ProductionSession(
        session=session,
        client_ip=str(client_ip),
        ssh_banner=network.get("ssh_client_banner", ""),
        outcome=doc.get("outcome", ""),
        node_id=doc.get("node_id", ""),
        duration_ms=int(duration_ms) if duration_ms is not None else None,
        auth_attempts=auth_attempts,
        bait_events=bait_events,
        working_directories=working_dirs,
        response_sources=response_sources,
    )
