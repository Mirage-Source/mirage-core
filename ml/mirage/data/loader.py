"""Ingestion of public SSH-honeypot corpora into MIRAGE ``Session`` objects.

Supports the cowrie JSON event log format (used by the Honeynet Project and by
SANS ISC / DShield sensors, which run a cowrie fork and emit the same
``eventid`` schema). Input may be:

* newline-delimited JSON (``.json`` / ``.jsonl``), optionally gzip-compressed;
* Parquet (``.parquet``), one event per row, columns named like the JSON keys.

The loader is **event-stream oriented**: cowrie logs interleave events from many
concurrent sessions, so we accumulate per-session state across a full pass and
emit a :class:`~mirage.data.schema.Session` once the file is exhausted.

Relevant cowrie eventids (see https://docs.cowrie.org/en/latest/OUTPUT.html):

* ``cowrie.session.connect``  -> session start, ``src_ip``/``src_port``
* ``cowrie.command.input``    -> a command line, field ``input``
* ``cowrie.command.failed``   -> a command that errored, field ``input``
* ``cowrie.session.closed``   -> field ``duration`` (seconds)

Neuroscience note: producing ``ms_offset`` for each command is exactly the
"align events to a common t=0" step done when extracting spike times relative to
trial onset. ``ms_offset`` is the event time of the marked point process.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from .bait import BaitDetector
from .schema import Command, Session, parse_iso8601

__all__ = ["DataLoader", "COMMAND_EVENTS"]

#: Cowrie eventids that we treat as "a command was issued".
COMMAND_EVENTS: frozenset[str] = frozenset(
    {"cowrie.command.input", "cowrie.command.failed"}
)
_CONNECT_EVENT = "cowrie.session.connect"
_CLOSE_EVENTS: frozenset[str] = frozenset(
    {"cowrie.session.closed", "cowrie.log.closed"}
)

# Field-name fallbacks, since forks (DShield, older cowrie, custom pipelines)
# vary slightly. We try each in order.
_IP_FIELDS = ("src_ip", "peerIP", "peer_ip", "source_ip", "ip")
_SESSION_FIELDS = ("session", "session_id", "sessionid")
_INPUT_FIELDS = ("input", "command", "cmd")


def _first(d: dict[str, Any], keys: tuple[str, ...]) -> Any | None:
    """Return the first present, non-empty value among ``keys``."""
    for key in keys:
        value = d.get(key)
        if value is not None and value != "":
            return value
    return None


class _SessionAccumulator:
    """Mutable per-session state built up while scanning the event stream."""

    __slots__ = ("session_id", "ip", "start_time", "events", "duration_ms")

    def __init__(self, session_id: str) -> None:
        self.session_id: str = session_id
        self.ip: str | None = None
        self.start_time: datetime | None = None
        # (timestamp, raw_command) pairs for command events.
        self.events: list[tuple[datetime, str]] = []
        self.duration_ms: int | None = None

    def observe_start(self, ts: datetime) -> None:
        """Track the earliest timestamp seen as a fallback session start."""
        if self.start_time is None or ts < self.start_time:
            self.start_time = ts


class DataLoader:
    """Load honeypot event logs into normalized MIRAGE sessions.

    Args:
        min_commands: Drop sessions with fewer than this many commands. The
            default of ``1`` discards pure brute-force / connect-only sessions
            that contain no shell interaction.
        infer_bait: If ``True``, run :class:`~mirage.data.bait.BaitDetector` to
            populate ``bait_interactions`` from command content.
        bait_detector: Optional custom detector; a default is created if omitted.
        drop_unstarted: If ``True``, drop sessions that have commands but no
            resolvable start time (should be rare; only when timestamps are
            entirely missing).
    """

    def __init__(
        self,
        min_commands: int = 1,
        infer_bait: bool = True,
        bait_detector: BaitDetector | None = None,
        drop_unstarted: bool = True,
    ) -> None:
        self.min_commands = min_commands
        self.infer_bait = infer_bait
        self.bait_detector = bait_detector or BaitDetector()
        self.drop_unstarted = drop_unstarted

    # -- Public API ---------------------------------------------------------

    def load_file(self, path: str | Path) -> list[Session]:
        """Load all sessions from a single log file (eager)."""
        return list(self.iter_file(path))

    def load_dir(
        self, path: str | Path, pattern: str = "*.json*"
    ) -> list[Session]:
        """Load all sessions from every matching file under ``path`` (eager).

        Args:
            path: Directory to scan.
            pattern: Glob for log files. The default matches ``.json``,
                ``.jsonl`` and their ``.gz`` variants. Use ``"*.parquet"`` for
                Parquet dumps.
        """
        return list(self.iter_dir(path, pattern=pattern))

    def iter_dir(
        self, path: str | Path, pattern: str = "*.json*"
    ) -> Iterator[Session]:
        """Lazily yield sessions across all matching files in a directory."""
        root = Path(path)
        for file_path in sorted(root.glob(pattern)):
            if file_path.is_file():
                yield from self.iter_file(file_path)

    def iter_file(self, path: str | Path) -> Iterator[Session]:
        """Lazily yield sessions from one file, dispatching on extension."""
        file_path = Path(path)
        suffixes = {s.lower() for s in file_path.suffixes}
        if ".parquet" in suffixes:
            events = self._read_parquet(file_path)
        else:
            events = self._read_jsonl(file_path)
        yield from self._sessions_from_events(events)

    # -- Raw event readers --------------------------------------------------

    @staticmethod
    def _read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
        """Yield event dicts from a (optionally gzipped) JSON-lines file."""
        opener = gzip.open if path.suffix.lower() == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    # Corrupt / truncated line: skip rather than abort the file.
                    continue

    @staticmethod
    def _read_parquet(path: Path) -> Iterator[dict[str, Any]]:
        """Yield event dicts from a Parquet file (one event per row)."""
        try:
            import pandas as pd
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError(
                "Reading Parquet requires pandas + pyarrow. "
                "Install with: pip install pandas pyarrow"
            ) from exc
        frame = pd.read_parquet(path)
        for record in frame.to_dict(orient="records"):
            # Drop NaN-valued keys so downstream `.get` fallbacks behave.
            yield {k: v for k, v in record.items() if pd.notna(v)}

    # -- Core grouping logic ------------------------------------------------

    def _sessions_from_events(
        self, events: Iterable[dict[str, Any]]
    ) -> Iterator[Session]:
        """Group a flat event stream into sessions and finalize each one."""
        accumulators: dict[str, _SessionAccumulator] = {}

        for event in events:
            session_id = _first(event, _SESSION_FIELDS)
            if session_id is None:
                continue
            session_id = str(session_id)
            acc = accumulators.get(session_id)
            if acc is None:
                acc = _SessionAccumulator(session_id)
                accumulators[session_id] = acc

            eventid = event.get("eventid", "")
            raw_ts = event.get("timestamp")
            ts = parse_iso8601(raw_ts) if raw_ts else None

            ip = _first(event, _IP_FIELDS)
            if ip is not None and acc.ip is None:
                acc.ip = str(ip)

            if ts is not None:
                acc.observe_start(ts)

            if eventid == _CONNECT_EVENT and ts is not None:
                # Connect time is authoritative for session start.
                acc.start_time = ts
            elif eventid in COMMAND_EVENTS:
                raw_cmd = _first(event, _INPUT_FIELDS)
                if raw_cmd is not None and ts is not None:
                    acc.events.append((ts, str(raw_cmd)))
            elif eventid in _CLOSE_EVENTS:
                duration = event.get("duration")
                if duration is not None:
                    try:
                        acc.duration_ms = int(round(float(duration) * 1000.0))
                    except (TypeError, ValueError):
                        pass

        for acc in accumulators.values():
            session = self._finalize(acc)
            if session is not None:
                yield session

    def _finalize(self, acc: _SessionAccumulator) -> Session | None:
        """Turn an accumulator into a validated, normalized ``Session``."""
        if len(acc.events) < self.min_commands:
            return None

        start_time = acc.start_time
        if start_time is None:
            if self.drop_unstarted:
                return None
            start_time = min(ts for ts, _ in acc.events)

        # Sort command events chronologically (logs can be slightly out of order).
        ordered = sorted(acc.events, key=lambda e: e[0])

        commands: list[Command] = []
        for ts, raw in ordered:
            ms_offset = int((ts - start_time).total_seconds() * 1000.0)
            # Clamp tiny negative offsets from clock jitter / out-of-order connect.
            if ms_offset < 0:
                ms_offset = 0
            commands.append(Command(timestamp=ts, raw=raw, ms_offset=ms_offset))

        session = Session(
            session_id=acc.session_id,
            ip=acc.ip or "0.0.0.0",
            start_time=start_time,
            commands=commands,
            duration_ms=acc.duration_ms,
        )

        if self.infer_bait:
            session.bait_interactions = self.bait_detector.detect(commands)

        return session
