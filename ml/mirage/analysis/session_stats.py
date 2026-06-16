"""Corpus summary statistics for MIRAGE Phase-1 data.

Loads a directory (or file) of honeypot logs and emits a single summary JSON
describing the corpus: vocabulary size, median session length, session-duration
statistics, bait-interaction rates, and the share of sessions that look
automated vs. human under the inter-command timing heuristic.

Usage:
    python -m mirage.analysis.session_stats \
        --input data/cowrie/ --output summary.json --mode command --top-k 500

    # Bootstrap a synthetic corpus if you have no real logs yet:
    python -m mirage.analysis.session_stats --synthetic --output summary.json
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from ..data.loader import DataLoader
from ..data.schema import Session
from ..data.synthetic import write_synthetic_log
from ..tokenizer.tokenizer import CommandTokenizer, TokenizerConfig
from .timing import (
    TimingHeuristicConfig,
    classify_session,
    compute_timing_features,
)

__all__ = ["compute_summary", "main"]


def _percentile(values: list[float], q: float) -> float:
    """Linear-interpolation percentile (``q`` in ``[0, 100]``)."""
    if not values:
        return math.nan
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (q / 100.0) * (len(ordered) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return ordered[lo]
    frac = rank - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def compute_summary(
    sessions: list[Session],
    tokenizer: CommandTokenizer,
    timing_config: TimingHeuristicConfig | None = None,
) -> dict[str, Any]:
    """Compute the corpus summary dictionary.

    Args:
        sessions: All loaded sessions.
        tokenizer: A tokenizer already fitted on ``sessions`` (provides vocab).
        timing_config: Thresholds for the timing heuristic.

    Returns:
        A JSON-serializable summary dictionary.
    """
    timing_config = timing_config or TimingHeuristicConfig()

    n_sessions = len(sessions)
    command_counts = [s.n_commands for s in sessions]
    durations_s = [s.effective_duration_ms / 1000.0 for s in sessions]

    label_counts: Counter[str] = Counter()
    bait_sessions = 0
    bait_type_counts: Counter[str] = Counter()
    all_median_icis: list[float] = []
    all_cvs: list[float] = []

    for session in sessions:
        feats = compute_timing_features(session)
        label = classify_session(session, timing_config, features=feats)
        label_counts[label] += 1
        if not math.isnan(feats.median_ms):
            all_median_icis.append(feats.median_ms)
        if not math.isnan(feats.cv):
            all_cvs.append(feats.cv)
        if session.bait_interactions:
            bait_sessions += 1
            for bait in session.bait_interactions:
                bait_type_counts[bait.bait_type] += 1

    def pct(label: str) -> float:
        return 100.0 * label_counts.get(label, 0) / n_sessions if n_sessions else 0.0

    summary: dict[str, Any] = {
        "n_sessions": n_sessions,
        "vocab_size": tokenizer.vocab_size,
        "vocab_top_k": tokenizer.config.top_k,
        "tokenizer_mode": tokenizer.config.mode,
        "session_length_commands": {
            "median": statistics.median(command_counts) if command_counts else 0,
            "mean": statistics.fmean(command_counts) if command_counts else 0.0,
            "p90": _percentile([float(c) for c in command_counts], 90),
            "max": max(command_counts) if command_counts else 0,
        },
        "session_duration_seconds": {
            "median": statistics.median(durations_s) if durations_s else 0.0,
            "mean": statistics.fmean(durations_s) if durations_s else 0.0,
            "p90": _percentile(durations_s, 90),
        },
        "timing_classification": {
            "pct_automated": round(pct("automated"), 2),
            "pct_human": round(pct("human"), 2),
            "pct_unknown": round(pct("unknown"), 2),
            "counts": dict(label_counts),
            "median_ici_ms_overall": (
                statistics.median(all_median_icis) if all_median_icis else math.nan
            ),
            "median_cv_overall": (
                statistics.median(all_cvs) if all_cvs else math.nan
            ),
            "heuristic_thresholds": {
                "automated_median_ms": timing_config.automated_median_ms,
                "automated_cv": timing_config.automated_cv,
                "human_median_ms": timing_config.human_median_ms,
                "human_cv": timing_config.human_cv,
                "superhuman_ms": timing_config.superhuman_ms,
            },
        },
        "bait": {
            "pct_sessions_with_bait": (
                round(100.0 * bait_sessions / n_sessions, 2) if n_sessions else 0.0
            ),
            "interactions_by_type": dict(bait_type_counts),
        },
    }
    return summary


def _load_sessions(args: argparse.Namespace) -> list[Session]:
    """Load sessions from real logs or a freshly generated synthetic corpus."""
    loader = DataLoader(min_commands=args.min_commands)
    if args.synthetic:
        tmp_dir = Path(tempfile.mkdtemp(prefix="mirage_synth_"))
        log_path = tmp_dir / "synthetic_cowrie.json"
        write_synthetic_log(log_path, n_sessions=args.synthetic_sessions)
        return loader.load_file(log_path)

    input_path = Path(args.input)
    if input_path.is_dir():
        return loader.load_dir(input_path, pattern=args.pattern)
    return loader.load_file(input_path)


def main(argv: list[str] | None = None) -> dict[str, Any]:
    """CLI entry point. Returns the summary dict (also written to ``--output``)."""
    parser = argparse.ArgumentParser(description=__doc__)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="Log file or directory of cowrie logs.")
    src.add_argument(
        "--synthetic",
        action="store_true",
        help="Generate and analyze a synthetic corpus instead of real logs.",
    )
    parser.add_argument(
        "--synthetic-sessions", type=int, default=400,
        help="Number of synthetic sessions when --synthetic is used.",
    )
    parser.add_argument(
        "--pattern", default="*.json*",
        help="Glob for log files when --input is a directory.",
    )
    parser.add_argument("--output", default="summary.json", help="Output JSON path.")
    parser.add_argument(
        "--mode", choices=["command", "full"], default="command",
        help="Tokenizer normalization mode.",
    )
    parser.add_argument("--top-k", type=int, default=500, help="Vocabulary size.")
    parser.add_argument(
        "--min-commands", type=int, default=1,
        help="Drop sessions with fewer than this many commands.",
    )
    args = parser.parse_args(argv)

    sessions = _load_sessions(args)
    tokenizer = CommandTokenizer(
        TokenizerConfig(mode=args.mode, top_k=args.top_k)
    ).fit(sessions)

    summary = compute_summary(sessions, tokenizer)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(json.dumps(summary, indent=2, default=str))
    print(f"\nWrote summary -> {output_path}")
    return summary


if __name__ == "__main__":  # pragma: no cover
    main()
