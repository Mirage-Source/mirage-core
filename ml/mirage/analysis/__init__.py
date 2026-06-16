"""Phase-1 analysis: inter-command timing heuristics and corpus statistics.

Only the timing module is re-exported here; ``session_stats`` is a CLI module
(it depends on the synthetic-corpus generator) and is imported directly when run.
"""

from __future__ import annotations

from .timing import (
    TimingFeatures,
    TimingHeuristicConfig,
    TimingLabel,
    classify_session,
    compute_timing_features,
)

__all__ = [
    "TimingFeatures",
    "TimingHeuristicConfig",
    "TimingLabel",
    "classify_session",
    "compute_timing_features",
]
