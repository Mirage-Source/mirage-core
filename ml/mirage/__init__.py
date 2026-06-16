"""MIRAGE -- the machine-learning intelligence layer of an AI SSH honeypot.

This top-level package is intentionally side-effect free: importing ``mirage``
pulls in **no** heavy dependencies (torch, sklearn, umap). Submodules declare
their own requirements, so the lightweight Phase-1 data tooling and the
torch-based Phase-2 models can be imported independently.

Subpackages:
    data       Phase 1 -- schema, loader, bait inference, synthetic corpora.
    tokenizer  Phase 1 -- dual-channel (command + log-ICI) tokenizer.
    analysis   Phase 1 -- inter-command timing heuristics, corpus stats.
    models     Phase 2 -- SessionEmbedder + TemporalTrajectoryAnalyzer (torch).
    training   Phase 2 -- contrastive training pipeline (CEBRA-style).
    viz        Phase 2 -- UMAP / trajectory / clustering-quality visualization.
"""

from __future__ import annotations

__version__ = "0.2.0"  # Phase 2: session embeddings + trajectory analysis.
