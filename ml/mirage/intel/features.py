"""Behavioural feature extraction for real-time attacker classification.

Turns a :class:`~mirage.intel.ingest.ProductionSession` into a fixed-length,
named numeric feature vector that the :class:`~mirage.intel.classifier.SessionClassifier`
consumes (optionally concatenated with the 128-d behavioural embedding). The
features deliberately span the four behavioural axes that separate the attacker
classes:

* **timing** -- automation signature (CV, median ICI, superhuman fraction): the
  Phase-1 ISI/ICI thesis, reused verbatim from ``mirage.analysis.timing``.
* **content** -- *what* was run: tool-signature family (one-hot) and command-
  diversity stats.
* **intent** -- bait interactions and their escalation (read → copy → exfil): the
  highest-signal axis, now that the core emits a real bait subsystem.
* **engagement / sophistication** -- dwell time, working-directory exploration,
  credential breadth, and SSH-client-banner automation flags.

Everything here is stdlib + numpy (no torch), so features can be extracted and
weak-labelled without a model present -- the graceful-degradation contract the
rest of MIRAGE keeps.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from ..analysis.timing import compute_timing_features
from ..viz.tool_signature import TOOL_SIGNATURES, infer_tool_signature
from .ingest import ProductionSession

__all__ = ["IntelFeatures", "extract_features", "FEATURE_NAMES"]

#: SSH client-banner substrings that betray automated tooling (lowercased match).
#: Real interactive clients announce OpenSSH/PuTTY; libraries/scanners announce
#: their library, which is a strong bot tell.
_AUTOMATED_BANNER_MARKERS: tuple[str, ...] = (
    "libssh", "paramiko", "go", "python", "nmap", "masscan", "zgrab", "research",
)


def _safe(value: float, default: float = 0.0) -> float:
    """Replace NaN/inf with a finite default (classifiers dislike NaNs)."""
    return float(value) if math.isfinite(value) else default


@dataclass
class IntelFeatures:
    """A named, numeric feature vector for one session.

    Attributes:
        vector: ``[D]`` float32 feature vector (order matches :data:`FEATURE_NAMES`).
        names: The feature names, aligned with ``vector``.
        tool_signature: The inferred tool family (kept for reporting / MITRE).
        timing_label: Coarse timing label (automated / human / unknown).
    """

    vector: np.ndarray
    names: list[str]
    tool_signature: str
    timing_label: str

    def as_dict(self) -> dict[str, float]:
        """Feature name → value mapping (for inspection and explanations)."""
        return {name: float(v) for name, v in zip(self.names, self.vector)}


# Feature order is part of the model contract: append-only, never reorder.
FEATURE_NAMES: list[str] = [
    "n_commands",
    "n_unique_commands",
    "command_diversity",
    "log_duration_ms",
    "commands_per_min",
    # timing
    "timing_cv",
    "log_median_ici",
    "mean_log_ici",
    "frac_superhuman",
    "n_deltas",
    # timing label one-hot
    "timing_is_automated",
    "timing_is_human",
    "timing_is_unknown",
    # bait / intent
    "n_bait_hits",
    "n_distinct_bait_types",
    "max_bait_escalation",
    "has_exfil_attempt",
    # auth
    "n_auth_attempts",
    "n_distinct_credentials",
    "n_distinct_usernames",
    "any_auth_success",
    # engagement / exploration
    "n_distinct_cwd",
    "max_cwd_depth",
    "banner_is_automated",
    "banner_len",
] + [f"tool_is_{name}" for name in TOOL_SIGNATURES]


def extract_features(prod: ProductionSession) -> IntelFeatures:
    """Extract the behavioural feature vector from a production session."""
    session = prod.session
    raws = session.raw_commands()
    n_commands = len(raws)
    n_unique = len(set(raws))
    diversity = (n_unique / n_commands) if n_commands else 0.0

    timing = compute_timing_features(session)
    from ..analysis.timing import classify_session

    timing_label = classify_session(session, features=timing)
    tool_sig = infer_tool_signature(raws)

    duration_ms = float(session.effective_duration_ms)
    minutes = max(duration_ms / 60000.0, 1e-6)
    commands_per_min = n_commands / minutes

    # Bait / intent.
    n_bait = len(prod.bait_events)
    distinct_bait_types = len({b.bait_type for b in prod.bait_events})
    max_escalation = float(prod.max_bait_escalation)
    has_exfil = float(any(b.access_type == "exfil_attempt" for b in prod.bait_events))

    # Auth.
    n_auth = len(prod.auth_attempts)
    distinct_creds = len({a.credential for a in prod.auth_attempts})
    distinct_users = len({a.username for a in prod.auth_attempts})
    any_success = float(any(a.success for a in prod.auth_attempts))

    # Exploration.
    cwds = [c for c in prod.working_directories if c]
    distinct_cwd = len(set(cwds))
    max_depth = max((c.count("/") for c in cwds), default=0)

    banner = (prod.ssh_banner or "").lower()
    banner_automated = float(any(m in banner for m in _AUTOMATED_BANNER_MARKERS))

    tool_onehot = [1.0 if tool_sig == name else 0.0 for name in TOOL_SIGNATURES]

    values: list[float] = [
        float(n_commands),
        float(n_unique),
        float(diversity),
        math.log1p(duration_ms),
        float(commands_per_min),
        # timing
        _safe(timing.cv),
        math.log1p(_safe(timing.median_ms)),
        _safe(timing.mean_log_ici),
        _safe(timing.frac_superhuman),
        float(timing.n_deltas),
        # timing label one-hot
        float(timing_label == "automated"),
        float(timing_label == "human"),
        float(timing_label == "unknown"),
        # bait
        float(n_bait),
        float(distinct_bait_types),
        max_escalation,
        has_exfil,
        # auth
        float(n_auth),
        float(distinct_creds),
        float(distinct_users),
        any_success,
        # exploration
        float(distinct_cwd),
        float(max_depth),
        banner_automated,
        float(len(banner)),
        # tool family one-hot
        *tool_onehot,
    ]
    vector = np.asarray(values, dtype=np.float32)
    assert vector.shape[0] == len(FEATURE_NAMES), "feature/name length mismatch"
    return IntelFeatures(
        vector=vector,
        names=list(FEATURE_NAMES),
        tool_signature=tool_sig,
        timing_label=timing_label,
    )
