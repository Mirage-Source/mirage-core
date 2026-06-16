"""MIRAGE bridge: wire the Go honeypot core to the Python ML intelligence layer.

The two halves of MIRAGE were built separately:

* **core** (Go) -- the SSH honeypot. Captures attacker sessions and writes them
  to PostgreSQL. Every ``sessions`` row already has empty *intelligence* columns
  (``attacker_class``, ``classifier_confidence``, ``cluster_id``,
  ``mitre_techniques``, ``session_summary``) waiting to be filled.
* **ml** (Python) -- the intelligence layer. Phase-1 timing heuristics, the
  Phase-2 ``SessionEmbedder`` + ``TemporalTrajectoryAnalyzer``, and weak
  tool-signature inference.

This package is the glue between them, designed for **zero changes to the Go
core**. The integration is a decoupled, poll-based enrichment worker:

    honeypot (Go) --writes--> PostgreSQL <--polls/updates-- enrichment worker (this)

so the honeypot never blocks on ML inference, and the worker can be restarted,
scaled, or upgraded independently.

Modules:
    config          Environment-driven configuration (shares the core's DB vars).
    schema_adapter  Map the core's session JSON to the ML ``Session`` schema.
    enrich          Run the ML stack on one session -> an ``EnrichmentResult``.
    db              Fetch un-enriched sessions and write results back to Postgres.
    worker          The long-running polling service.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
