"""Inter-command timing analysis -- MIRAGE's first-class behavioral feature.

This module operationalizes the central Phase-1 claim: **the inter-command
interval (ICI) distribution distinguishes human attackers from automated tools,
and it is underexploited in the honeypot literature.**

The framing is borrowed directly from spike-train analysis. A session's command
times are event times of a marked point process; the gaps between them are
inter-command intervals, the exact analogue of inter-spike intervals (ISIs). The
single most informative summary of an ISI sequence is its **coefficient of
variation** ``CV = std / mean``:

    * ``CV -> 0``  : perfectly regular / metronomic firing (a pacemaker neuron;
                     here, a script looping at a fixed cadence).
    * ``CV ~ 1``  : Poisson-like memoryless firing.
    * ``CV >> 1`` : bursty, irregular firing (cortical neurons; here, a human who
                     thinks, types, pauses, reacts).

Combined with the median ICI (humans are simply *slower* between commands than a
tight wget|chmod|exec loop), CV gives a robust, interpretable heuristic. We use
it here as a weak prior / sanity baseline; later phases replace it with a learned
classifier that consumes the full timing channel.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Literal

from ..data.schema import Session

__all__ = ["TimingFeatures", "TimingHeuristicConfig", "compute_timing_features",
           "classify_session", "TimingLabel"]

TimingLabel = Literal["automated", "human", "unknown"]


@dataclass(slots=True)
class TimingFeatures:
    """Summary statistics of a session's inter-command interval distribution.

    Attributes:
        n_deltas: Number of inter-command intervals (``n_commands - 1``).
        median_ms: Median ICI in milliseconds.
        mean_ms: Mean ICI in milliseconds.
        cv: Coefficient of variation of the ICIs (``std / mean``); ``nan`` if
            undefined. The regularity metric.
        frac_superhuman: Fraction of ICIs below ``superhuman_ms`` (intervals too
            short to plausibly reflect human reaction / typing).
        mean_log_ici: Mean of ``log(1 + ICI_ms)``; the location of the
            distribution in the analysis-friendly log domain.
    """

    n_deltas: int
    median_ms: float
    mean_ms: float
    cv: float
    frac_superhuman: float
    mean_log_ici: float


@dataclass(slots=True)
class TimingHeuristicConfig:
    """Thresholds for the human-vs-automated timing heuristic.

    All thresholds are explicit and swept-able for the paper's ablations. They
    encode priors, not learned parameters.

    Attributes:
        min_deltas: Minimum ICIs required to make any call; below this the
            session is ``"unknown"`` (insufficient timing evidence).
        automated_median_ms: Upper bound on median ICI for "fast" sessions.
        automated_cv: Upper bound on CV for "regular" sessions.
        superhuman_ms: ICIs shorter than this are implausibly fast for a human.
        superhuman_frac: If at least this fraction of ICIs are superhuman, the
            session is automated regardless of CV.
        human_median_ms: Median ICI above this strongly suggests a human.
        human_cv: CV above this (bursty) strongly suggests a human.
    """

    min_deltas: int = 3
    automated_median_ms: float = 250.0
    automated_cv: float = 0.5
    superhuman_ms: float = 50.0
    superhuman_frac: float = 0.8
    human_median_ms: float = 800.0
    human_cv: float = 1.0


def compute_timing_features(session: Session) -> TimingFeatures:
    """Compute ICI summary statistics for a session.

    Args:
        session: The session to analyze.

    Returns:
        A :class:`TimingFeatures` (fields are ``nan`` / zero when there are too
        few intervals to define them).
    """
    deltas = [float(d) for d in session.inter_command_deltas_ms()]
    n = len(deltas)
    if n == 0:
        return TimingFeatures(0, math.nan, math.nan, math.nan, 0.0, math.nan)

    median_ms = statistics.median(deltas)
    mean_ms = statistics.fmean(deltas)
    if n >= 2 and mean_ms > 0:
        std_ms = statistics.stdev(deltas)
        cv = std_ms / mean_ms
    else:
        cv = math.nan
    frac_superhuman = sum(1 for d in deltas if d < 50.0) / n
    mean_log_ici = statistics.fmean(math.log1p(d) for d in deltas)

    return TimingFeatures(
        n_deltas=n,
        median_ms=median_ms,
        mean_ms=mean_ms,
        cv=cv,
        frac_superhuman=frac_superhuman,
        mean_log_ici=mean_log_ici,
    )


def classify_session(
    session: Session,
    config: TimingHeuristicConfig | None = None,
    features: TimingFeatures | None = None,
) -> TimingLabel:
    """Classify a session as ``automated`` / ``human`` / ``unknown`` by timing.

    Decision logic (heuristic prior):
        1. Too few intervals -> ``unknown``.
        2. Overwhelmingly superhuman cadence -> ``automated``.
        3. Fast *and* regular (low median ICI, low CV) -> ``automated``.
        4. Slow *or* bursty (high median ICI or high CV) -> ``human``.
        5. Otherwise -> ``unknown`` (ambiguous middle ground).

    Args:
        session: Session to classify.
        config: Heuristic thresholds; defaults to :class:`TimingHeuristicConfig`.
        features: Optionally pass precomputed features to avoid recomputation.

    Returns:
        A timing label.
    """
    cfg = config or TimingHeuristicConfig()
    feats = features or compute_timing_features(session)

    if feats.n_deltas < cfg.min_deltas:
        return "unknown"

    if feats.frac_superhuman >= cfg.superhuman_frac:
        return "automated"

    cv = feats.cv
    cv_is_low = not math.isnan(cv) and cv < cfg.automated_cv
    cv_is_high = not math.isnan(cv) and cv > cfg.human_cv

    if feats.median_ms < cfg.automated_median_ms and cv_is_low:
        return "automated"

    if feats.median_ms > cfg.human_median_ms or cv_is_high:
        return "human"

    return "unknown"
