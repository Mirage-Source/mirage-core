"""Phase-1 data layer: schema, ingestion, bait inference.

Importing this subpackage pulls in only the lightweight schema (stdlib). The
loader (which depends on the bait detector) is imported lazily by callers that
need it, so ``import mirage.data`` stays cheap.
"""

from __future__ import annotations

from .schema import (
    BaitInteraction,
    BaitType,
    ClassifierOutput,
    Command,
    Session,
    parse_iso8601,
    to_iso8601,
)

__all__ = [
    "BaitInteraction",
    "BaitType",
    "ClassifierOutput",
    "Command",
    "Session",
    "parse_iso8601",
    "to_iso8601",
]
