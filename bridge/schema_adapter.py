"""Adapt the Go core's session schema to the ML ``Session`` schema.

The honeypot core and the ML layer evolved separate-but-parallel schemas. This
module is the single, well-tested translation point between them. It consumes the
``session_document`` JSONB the core writes (a marshaled Go ``session.Session``)
and produces a :class:`mirage.data.schema.Session` the ML stack understands.

Field mapping (core -> ML):

    session_id                       -> session_id
    network.client_ip                -> ip
    timing.start_ms (epoch ms)       -> start_time (UTC datetime)
    timing.duration_ms               -> duration_ms
    commands[].timestamp_ms          -> commands[].timestamp (UTC datetime)
    timestamp_ms - start_ms          -> commands[].ms_offset   (clamped >= 0)
    base64decode(raw_input_b64)      -> commands[].raw
        (fallback: parsed_command + " " + parsed_args)
    bait_interactions[].bait_type    -> bait_interactions[].bait_type (mapped)
    bait_interactions[].timestamp_ms -> bait_interactions[].timestamp

``classifier_output`` is left ``None`` -- that is precisely what this pipeline is
about to compute.

The core's bait taxonomy is richer than the ML schema's, so bait types are mapped
to the nearest ML category (see :data:`CORE_TO_ML_BAIT`); unmappable types are
dropped rather than guessed, since bait is a weak auxiliary signal only.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from typing import Any

from mirage.data.schema import BaitInteraction, Command, Session

__all__ = ["CORE_TO_ML_BAIT", "core_session_to_ml", "SchemaAdaptationError"]


class SchemaAdaptationError(ValueError):
    """Raised when a core session document cannot be adapted (missing keys)."""


#: Map the Go core's ``BaitType`` values to the ML schema's ``BaitType``.
#: The core defines: credential, private_key, config, env_file, shadow.
#: The ML schema defines: ssh_key, env_file, shadow, s3.
CORE_TO_ML_BAIT: dict[str, str] = {
    "private_key": "ssh_key",
    "credential": "ssh_key",   # planted credential ~ key material, behaviorally
    "env_file": "env_file",
    "config": "env_file",      # config secrets behave like env-file secrets
    "shadow": "shadow",
    # No clean ML analogue for cloud bait yet; "s3" is reserved for when the core
    # grows a cloud-credential bait type.
}


def _ms_to_dt(ms: int) -> datetime:
    """Convert epoch milliseconds (the core's time unit) to a UTC datetime."""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)


def _decode_raw(command: dict[str, Any]) -> str:
    """Recover the raw command line the attacker typed.

    Prefers the base64-encoded raw input (exactly what was typed before the
    newline); falls back to reconstructing from the parsed verb + args when the
    blob is absent or undecodable.
    """
    b64 = command.get("raw_input_b64")
    if b64:
        try:
            return base64.b64decode(b64, validate=False).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            pass
    parsed = command.get("parsed_command", "") or ""
    args = command.get("parsed_args") or []
    if parsed and args:
        return parsed + " " + " ".join(str(a) for a in args)
    return parsed


def _adapt_commands(
    commands: list[dict[str, Any]], start_ms: int
) -> list[Command]:
    """Adapt the core's command events, sorted by sequence then time."""
    ordered = sorted(
        commands,
        key=lambda c: (c.get("sequence_number", 0), c.get("timestamp_ms", 0)),
    )
    out: list[Command] = []
    for c in ordered:
        ts_ms = c.get("timestamp_ms")
        if ts_ms is None:
            continue
        raw = _decode_raw(c)
        if not raw.strip():
            continue  # skip empty lines (bare Enter presses captured by the core)
        offset = int(ts_ms) - int(start_ms)
        if offset < 0:
            offset = 0  # clamp clock-skew / pre-start jitter, like the ML loader
        out.append(
            Command(timestamp=_ms_to_dt(int(ts_ms)), raw=raw, ms_offset=offset)
        )
    return out


def _adapt_bait(
    events: list[dict[str, Any]]
) -> list[BaitInteraction]:
    """Adapt the core's bait events to ML bait interactions (mapping types)."""
    out: list[BaitInteraction] = []
    for e in events:
        core_type = e.get("bait_type")
        ts_ms = e.get("timestamp_ms")
        ml_type = CORE_TO_ML_BAIT.get(str(core_type)) if core_type else None
        if ml_type is None or ts_ms is None:
            continue
        out.append(
            BaitInteraction(bait_type=ml_type, timestamp=_ms_to_dt(int(ts_ms)))  # type: ignore[arg-type]
        )
    return out


def core_session_to_ml(doc: dict[str, Any]) -> Session:
    """Convert one core ``session_document`` dict into an ML :class:`Session`.

    Args:
        doc: The parsed ``session_document`` JSON (a marshaled Go session).

    Returns:
        An ML :class:`~mirage.data.schema.Session`, ready for the tokenizer and
        the embedder. ``classifier_output`` is ``None`` (to be computed).

    Raises:
        SchemaAdaptationError: If required fields (session_id, timing.start_ms)
            are missing.
    """
    session_id = doc.get("session_id")
    if not session_id:
        raise SchemaAdaptationError("session_document missing 'session_id'")

    timing = doc.get("timing") or {}
    start_ms = timing.get("start_ms")
    if start_ms is None:
        raise SchemaAdaptationError(f"session {session_id} missing timing.start_ms")
    start_ms = int(start_ms)

    network = doc.get("network") or {}
    ip = network.get("client_ip") or "0.0.0.0"

    duration_ms = timing.get("duration_ms")
    commands = _adapt_commands(doc.get("commands") or [], start_ms)
    bait = _adapt_bait(doc.get("bait_interactions") or [])

    return Session(
        session_id=str(session_id),
        ip=str(ip),
        start_time=_ms_to_dt(start_ms),
        commands=commands,
        bait_interactions=bait,
        classifier_output=None,
        duration_ms=int(duration_ms) if duration_ms is not None else None,
    )
