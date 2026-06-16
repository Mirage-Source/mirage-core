"""Core data structures for MIRAGE sessions.

A MIRAGE session is the unit of analysis throughout the ML stack. Conceptually
it is a **marked temporal point process**: a sequence of events (shell commands)
occurring at irregular times, where each event carries a *mark* (the command
itself). This is the same mathematical object used to describe a neural spike
train, where each spike has a time and a mark (the neuron of origin). That
correspondence is not cosmetic -- it is why inter-spike-interval (ISI) tooling
from neuroscience transfers directly to inter-command-interval (ICI) analysis
here (see ``mirage.analysis.timing``).

The dataclasses below serialize to / deserialize from the canonical MIRAGE JSON
schema:

    {
      "session_id": "uuid",
      "ip": "string",
      "start_time": "iso8601",
      "commands": [{"timestamp": "iso8601", "raw": "string", "ms_offset": 0}],
      "bait_interactions": [{"bait_type": "...", "timestamp": "iso8601"}],
      "classifier_output": {"class": "string", "confidence": 0.0}
    }

Note the JSON key ``class`` is a Python reserved word, so it is stored on the
``ClassifierOutput`` dataclass as ``cls`` and (de)serialized explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, get_args

__all__ = [
    "BaitType",
    "BAIT_TYPES",
    "Command",
    "BaitInteraction",
    "ClassifierOutput",
    "Session",
    "parse_iso8601",
    "to_iso8601",
]

#: Bait taxonomy used by the MIRAGE bait subsystem. For public cowrie corpora
#: (which have no native bait system) these are inferred heuristically from
#: command content -- see ``mirage.data.bait``.
BaitType = Literal["ssh_key", "env_file", "shadow", "s3"]
BAIT_TYPES: tuple[BaitType, ...] = get_args(BaitType)


def parse_iso8601(value: str | datetime) -> datetime:
    """Parse an ISO-8601 timestamp into a timezone-aware UTC ``datetime``.

    Cowrie emits UTC timestamps with a trailing ``Z`` (e.g.
    ``2018-09-05T13:56:32.039222Z``). ``datetime.fromisoformat`` only learned to
    accept ``Z`` directly in Python 3.11, so we normalize it for portability.
    Naive datetimes are assumed to be UTC.

    Args:
        value: An ISO-8601 string or an existing ``datetime``.

    Returns:
        A timezone-aware ``datetime`` in UTC.
    """
    if isinstance(value, datetime):
        dt = value
    else:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso8601(dt: datetime) -> str:
    """Serialize a ``datetime`` to a cowrie-style ISO-8601 UTC string."""
    dt = dt.astimezone(timezone.utc)
    # Render with microseconds and a trailing 'Z', matching cowrie's convention.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


@dataclass(slots=True)
class Command:
    """A single shell command issued within a session.

    Attributes:
        timestamp: Absolute time the command was entered (UTC).
        raw: The raw command line exactly as the attacker typed it.
        ms_offset: Milliseconds elapsed since ``Session.start_time``. This is
            the event time in the point-process view of the session.
    """

    timestamp: datetime
    raw: str
    ms_offset: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": to_iso8601(self.timestamp),
            "raw": self.raw,
            "ms_offset": int(self.ms_offset),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Command":
        return cls(
            timestamp=parse_iso8601(d["timestamp"]),
            raw=d["raw"],
            ms_offset=int(d["ms_offset"]),
        )


@dataclass(slots=True)
class BaitInteraction:
    """An attacker touching a planted decoy credential / secret.

    Attributes:
        bait_type: Which class of bait was accessed.
        timestamp: When the interaction occurred (UTC).
    """

    bait_type: BaitType
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        return {"bait_type": self.bait_type, "timestamp": to_iso8601(self.timestamp)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BaitInteraction":
        return cls(bait_type=d["bait_type"], timestamp=parse_iso8601(d["timestamp"]))


@dataclass(slots=True)
class ClassifierOutput:
    """Output of the real-time session classifier (populated in later phases).

    Attributes:
        cls: Predicted class label (serialized to JSON key ``class``).
        confidence: Model confidence in ``[0, 1]``.
    """

    cls: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {"class": self.cls, "confidence": float(self.confidence)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ClassifierOutput":
        return cls(cls=d["class"], confidence=float(d["confidence"]))


@dataclass(slots=True)
class Session:
    """A complete attacker session: the atomic unit for all MIRAGE ML models.

    Attributes:
        session_id: Unique session identifier (cowrie ``session`` field).
        ip: Source IP address of the attacker.
        start_time: Session start (UTC); the origin for all ``ms_offset`` values.
        commands: Ordered list of ``Command`` events (sorted by time).
        bait_interactions: Decoy access events (inferred for public corpora).
        classifier_output: Populated by the classifier in later phases; ``None``
            during data exploration.
        duration_ms: Optional explicit session duration in milliseconds (from
            cowrie ``session.closed``). Falls back to the last command offset.
    """

    session_id: str
    ip: str
    start_time: datetime
    commands: list[Command] = field(default_factory=list)
    bait_interactions: list[BaitInteraction] = field(default_factory=list)
    classifier_output: ClassifierOutput | None = None
    duration_ms: int | None = None

    # -- Derived, point-process style accessors -----------------------------

    @property
    def n_commands(self) -> int:
        """Number of command events in the session."""
        return len(self.commands)

    @property
    def effective_duration_ms(self) -> int:
        """Best available session duration in milliseconds.

        Prefers the explicit ``duration_ms`` (from cowrie ``session.closed``);
        otherwise falls back to the offset of the final command.
        """
        if self.duration_ms is not None:
            return self.duration_ms
        if self.commands:
            return self.commands[-1].ms_offset
        return 0

    def inter_command_deltas_ms(self) -> list[int]:
        """Inter-command intervals (ICIs) in milliseconds.

        These are the analogue of inter-spike intervals (ISIs) in a spike train.
        Returns ``len(commands) - 1`` deltas; empty if fewer than two commands.
        Commands are assumed time-sorted (guaranteed by the loader).
        """
        offsets = [c.ms_offset for c in self.commands]
        return [b - a for a, b in zip(offsets, offsets[1:])]

    def raw_commands(self) -> list[str]:
        """Convenience accessor for the ordered raw command strings."""
        return [c.raw for c in self.commands]

    # -- Serialization ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the canonical MIRAGE JSON schema."""
        out: dict[str, Any] = {
            "session_id": self.session_id,
            "ip": self.ip,
            "start_time": to_iso8601(self.start_time),
            "commands": [c.to_dict() for c in self.commands],
            "bait_interactions": [b.to_dict() for b in self.bait_interactions],
            "classifier_output": (
                self.classifier_output.to_dict()
                if self.classifier_output is not None
                else None
            ),
        }
        if self.duration_ms is not None:
            out["duration_ms"] = int(self.duration_ms)
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Session":
        """Deserialize from the canonical MIRAGE JSON schema."""
        classifier = d.get("classifier_output")
        return cls(
            session_id=d["session_id"],
            ip=d["ip"],
            start_time=parse_iso8601(d["start_time"]),
            commands=[Command.from_dict(c) for c in d.get("commands", [])],
            bait_interactions=[
                BaitInteraction.from_dict(b) for b in d.get("bait_interactions", [])
            ],
            classifier_output=(
                ClassifierOutput.from_dict(classifier) if classifier else None
            ),
            duration_ms=d.get("duration_ms"),
        )
