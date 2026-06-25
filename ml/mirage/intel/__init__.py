"""Phase 4 -- the real-time intelligence layer.

Turns the live core's captured sessions into the structured threat intelligence
the honeypot is meant to produce: a calibrated **attacker classification**, a
**MITRE ATT&CK** technique mapping, a natural-language **threat-intel summary**,
and a **STIX 2.1** export -- filling the ``sessions`` intelligence columns the Go
core leaves empty. It consumes the core's rich new signals (per-command timing,
working directory, the real bait subsystem, credentials, SSH banners) and builds
directly on Phases 1-3 (timing analysis, tool signatures, behavioral embeddings).

Everything degrades gracefully: it runs with no trained classifier (interpretable
weak labels), no LLM (deterministic template summary), and no embedding
(features-only), and only improves as those are switched on.

Pipeline
--------
* :mod:`~mirage.intel.ingest` -- parse the core ``session_document`` JSON.
* :mod:`~mirage.intel.features` -- behavioral feature extraction.
* :mod:`~mirage.intel.taxonomy` -- attacker classes + programmatic weak labels.
* :mod:`~mirage.intel.classifier` -- calibrated MLP attacker classifier.
* :mod:`~mirage.intel.mitre` -- ATT&CK technique mapping.
* :mod:`~mirage.intel.summarize` -- template / Claude threat-intel summary.
* :mod:`~mirage.intel.stix` -- STIX 2.1 bundle export.
* :mod:`~mirage.intel.pipeline` -- the orchestrator (session document -> intelligence).
"""

from __future__ import annotations

from .ingest import (
    AuthAttempt,
    BaitEvent,
    ProductionSession,
    parse_session_document,
)
from .pipeline import IntelligenceResult, IntelPipeline, enrich_session_document
from .taxonomy import ATTACKER_CLASSES, AttackerClass, WeakLabel, weak_label

__all__ = [
    "AuthAttempt",
    "BaitEvent",
    "ProductionSession",
    "parse_session_document",
    "AttackerClass",
    "ATTACKER_CLASSES",
    "WeakLabel",
    "weak_label",
    "IntelPipeline",
    "IntelligenceResult",
    "enrich_session_document",
]
