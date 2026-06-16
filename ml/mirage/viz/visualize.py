"""Visualization & clustering-quality script for Phase-2 embeddings.

Produces the three figures/metrics that test the Phase-2 hypothesis:

1. **UMAP of the 128-d vectors**, colored by inferred tool signature. If UMAP is
   not installed we fall back to PCA (same API), so the script always runs.
2. **Trajectory plots** for a handful of representative sessions, showing how each
   moves through embedding space as commands accumulate, with intent-shift
   moments and the convergence point annotated.
3. **Silhouette score** as a scalar clustering-quality metric, computed both
   against the inferred tool labels and against unsupervised KMeans clusters.

Run::

    python -m mirage.viz.visualize \\
        --checkpoint artifacts/embedder/best.pt \\
        --tokenizer artifacts/embedder/tokenizer \\
        --input /path/to/cowrie/logs \\
        --output-dir artifacts/figures

    # or, for a no-data smoke render:
    python -m mirage.viz.visualize --checkpoint ... --tokenizer ... --synthetic
"""

from __future__ import annotations

import argparse
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch

from ..data.loader import DataLoader as SessionLoader
from ..data.schema import Session
from ..models.embedding import SessionEmbedder, SessionEmbedderConfig
from ..models.trajectory import TemporalTrajectoryAnalyzer, TrajectoryConfig
from ..tokenizer.tokenizer import CommandTokenizer
from .tool_signature import TOOL_SIGNATURES, infer_tool_signature

__all__ = ["EmbeddedCorpus", "embed_corpus", "clustering_quality", "main"]


# ---------------------------------------------------------------------------
# Model / data loading
# ---------------------------------------------------------------------------


def _load_model(checkpoint: Path, device: torch.device) -> SessionEmbedder:
    """Rebuild a :class:`SessionEmbedder` from a training checkpoint."""
    ckpt = torch.load(checkpoint, map_location=device)
    model_cfg = SessionEmbedderConfig(**ckpt["config"])
    model = SessionEmbedder(model_cfg).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    return model


def _load_sessions(args: argparse.Namespace) -> list[Session]:
    loader = SessionLoader(min_commands=args.min_commands)
    if args.synthetic:
        from ..data.synthetic import write_synthetic_log

        tmp = Path(tempfile.mkdtemp(prefix="mirage_synth_"))
        log_path = tmp / "synthetic_cowrie.json"
        write_synthetic_log(log_path, n_sessions=args.synthetic_sessions)
        return loader.load_file(log_path)
    path = Path(args.input)
    if path.is_dir():
        return loader.load_dir(path, pattern=args.pattern)
    return loader.load_file(path)


# ---------------------------------------------------------------------------
# Embedding a corpus
# ---------------------------------------------------------------------------


@dataclass
class EmbeddedCorpus:
    """All artifacts needed by the figures.

    Attributes:
        embeddings: ``[N, D]`` pooled session vectors (numpy).
        labels: Length-``N`` inferred tool-signature labels.
        sessions: The underlying sessions (row-aligned to ``embeddings``).
        hidden_states: Per-session ``[L_i, D]`` hidden-state arrays (numpy),
            kept for trajectory plots.
    """

    embeddings: np.ndarray
    labels: list[str]
    sessions: list[Session]
    hidden_states: list[np.ndarray]


@torch.no_grad()
def embed_corpus(
    model: SessionEmbedder,
    tokenizer: CommandTokenizer,
    sessions: list[Session],
    device: torch.device,
    max_length: int = 256,
    batch_size: int = 128,
    standardize_timing: bool = True,
) -> EmbeddedCorpus:
    """Embed every session and collect pooled vectors + hidden states + labels."""
    embeddings: list[np.ndarray] = []
    hidden: list[np.ndarray] = []
    labels: list[str] = []

    for start in range(0, len(sessions), batch_size):
        chunk = sessions[start : start + batch_size]
        encs = tokenizer.encode_batch(
            chunk, max_length=max_length, standardize_timing=standardize_timing
        )
        max_len = max(e.length for e in encs)
        b = len(encs)
        input_ids = torch.full((b, max_len), tokenizer.pad_id, dtype=torch.long)
        timing = torch.zeros((b, max_len), dtype=torch.float32)
        mask = torch.zeros((b, max_len), dtype=torch.long)
        for i, e in enumerate(encs):
            input_ids[i, : e.length] = torch.tensor(e.input_ids[: e.length])
            timing[i, : e.length] = torch.tensor(e.timing[: e.length])
            mask[i, : e.length] = 1

        out = model(
            input_ids.to(device), timing.to(device), mask.to(device)
        )
        embeddings.append(out.pooled.cpu().numpy())
        for i, e in enumerate(encs):
            hidden.append(out.hidden_states[i, : e.length].cpu().numpy())
        for s in chunk:
            labels.append(infer_tool_signature(s.raw_commands()))

    return EmbeddedCorpus(
        embeddings=np.concatenate(embeddings, axis=0),
        labels=labels,
        sessions=sessions,
        hidden_states=hidden,
    )


# ---------------------------------------------------------------------------
# Dimensionality reduction (UMAP -> PCA fallback)
# ---------------------------------------------------------------------------


def _reduce_2d(x: np.ndarray, seed: int = 0) -> tuple[np.ndarray, str]:
    """Project ``[N, D]`` to ``[N, 2]`` with UMAP if available, else PCA.

    Returns the projection and the name of the method actually used (for the
    figure title / provenance).
    """
    try:
        import umap  # type: ignore

        reducer = umap.UMAP(
            n_components=2, n_neighbors=15, min_dist=0.1, random_state=seed
        )
        return reducer.fit_transform(x), "UMAP"
    except Exception:
        from sklearn.decomposition import PCA

        return PCA(n_components=2, random_state=seed).fit_transform(x), "PCA"


# ---------------------------------------------------------------------------
# Figure 1: embedding map
# ---------------------------------------------------------------------------


def plot_embedding_umap(
    corpus: EmbeddedCorpus, output_path: Path, seed: int = 0
) -> str:
    """Scatter the 2-D-reduced embeddings, colored by inferred tool signature."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    coords, method = _reduce_2d(corpus.embeddings, seed=seed)
    fig, ax = plt.subplots(figsize=(9, 7))
    present = [lab for lab in TOOL_SIGNATURES if lab in set(corpus.labels)]
    cmap = plt.get_cmap("tab10")
    for idx, label in enumerate(present):
        mask = np.array([l == label for l in corpus.labels])
        ax.scatter(
            coords[mask, 0], coords[mask, 1],
            s=14, alpha=0.7, color=cmap(idx % 10), label=f"{label} (n={mask.sum()})",
        )
    ax.set_title(f"MIRAGE session embeddings ({method}), colored by inferred tool")
    ax.set_xlabel(f"{method}-1")
    ax.set_ylabel(f"{method}-2")
    ax.legend(loc="best", fontsize=8, framealpha=0.9)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return method


# ---------------------------------------------------------------------------
# Figure 2: trajectories
# ---------------------------------------------------------------------------


def _representative_indices(corpus: EmbeddedCorpus, n: int = 5) -> list[int]:
    """Pick ``n`` representative sessions: spread across tool families, favoring
    longer sessions (more interesting trajectories)."""
    by_label: dict[str, list[int]] = {}
    for i, lab in enumerate(corpus.labels):
        by_label.setdefault(lab, []).append(i)
    # Within each family, prefer the longest session (richest trajectory).
    for lab, idxs in by_label.items():
        idxs.sort(key=lambda i: corpus.sessions[i].n_commands, reverse=True)

    chosen: list[int] = []
    # Round-robin across families until we have n.
    families = sorted(by_label, key=lambda k: -len(by_label[k]))
    pos = 0
    while len(chosen) < n and any(by_label.values()):
        fam = families[pos % len(families)]
        if by_label[fam]:
            chosen.append(by_label[fam].pop(0))
        pos += 1
        if pos > 1000:
            break
    return chosen[:n]


def plot_session_trajectories(
    corpus: EmbeddedCorpus,
    output_path: Path,
    analyzer: TemporalTrajectoryAnalyzer,
    indices: list[int] | None = None,
) -> list[int]:
    """Plot how representative sessions move through embedding space over time.

    A single PCA is fit on the *pooled* set of all plotted trajectory points so
    the paths share one comparable 2-D frame (PCA is linear, so a projected path
    is a faithful shadow of the true path). Intent-shift moments (curvature peaks)
    are marked with stars and the convergence point with a square.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.decomposition import PCA

    if indices is None:
        indices = _representative_indices(corpus, n=5)

    analyses = []
    for i in indices:
        hs = torch.from_numpy(corpus.hidden_states[i])
        analyses.append(analyzer.analyze(hs))

    stacked = np.concatenate([a.trajectory.numpy() for a in analyses], axis=0)
    pca = PCA(n_components=2, random_state=0).fit(stacked)

    fig, ax = plt.subplots(figsize=(9, 7))
    cmap = plt.get_cmap("tab10")
    for k, (i, feat) in enumerate(zip(indices, analyses)):
        path = pca.transform(feat.trajectory.numpy())
        color = cmap(k % 10)
        label = f"{corpus.labels[i]} | {corpus.sessions[i].n_commands} cmds"
        ax.plot(path[:, 0], path[:, 1], "-", color=color, alpha=0.8, lw=1.6, label=label)
        ax.scatter(path[0, 0], path[0, 1], color=color, marker="o", s=40, zorder=3)  # start
        # Intent-shift moments (curvature peaks).
        shift_idx = feat.intent_shift_indices.numpy()
        if shift_idx.size:
            ax.scatter(
                path[shift_idx, 0], path[shift_idx, 1],
                color=color, marker="*", s=90, edgecolor="black", linewidth=0.4, zorder=4,
            )
        # Convergence point.
        ax.scatter(
            path[-1, 0], path[-1, 1],
            color=color, marker="s", s=55, edgecolor="black", linewidth=0.5, zorder=4,
        )
    ax.set_title(
        "Session trajectories through embedding space (PCA)\n"
        "o = start   * = intent-shift moment   ■ = convergence point"
    )
    ax.set_xlabel("trajectory PC-1")
    ax.set_ylabel("trajectory PC-2")
    ax.legend(loc="best", fontsize=8, framealpha=0.9)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return indices


# ---------------------------------------------------------------------------
# Metric: clustering quality (silhouette)
# ---------------------------------------------------------------------------


def clustering_quality(corpus: EmbeddedCorpus, seed: int = 0) -> dict[str, Any]:
    """Silhouette score against (a) inferred tool labels and (b) KMeans clusters.

    Silhouette in ``[-1, 1]``: higher means tighter, better-separated clusters. A
    positive score against the *inferred tool labels* is direct evidence for the
    Phase-2 hypothesis -- the unsupervised embedding separates tool families it
    was never trained on.
    """
    from sklearn.cluster import KMeans
    from sklearn.metrics import silhouette_score

    x = corpus.embeddings
    result: dict[str, Any] = {"n_sessions": int(x.shape[0])}

    # (a) Against inferred tool labels (drop singleton families silhouette can't use).
    labels = np.array(corpus.labels)
    uniq, counts = np.unique(labels, return_counts=True)
    keep = set(uniq[counts >= 2])
    mask = np.array([l in keep for l in labels])
    if mask.sum() >= 2 and len(keep) >= 2:
        result["silhouette_tool_labels"] = float(
            silhouette_score(x[mask], labels[mask])
        )
        result["n_tool_families"] = int(len(keep))
    else:
        result["silhouette_tool_labels"] = float("nan")
        result["n_tool_families"] = int(len(keep))

    # (b) Against unsupervised KMeans (k = number of present tool families, >=2).
    k = max(2, min(len(uniq), 8))
    if x.shape[0] > k:
        km = KMeans(n_clusters=k, n_init=10, random_state=seed).fit(x)
        result["silhouette_kmeans"] = float(silhouette_score(x, km.labels_))
        result["kmeans_k"] = int(k)
    else:
        result["silhouette_kmeans"] = float("nan")
        result["kmeans_k"] = int(k)

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> dict[str, Any]:
    """CLI entry point: embed a corpus, render figures, print the metrics."""
    import json

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--checkpoint", required=True, help="Path to best.pt / last.pt.")
    p.add_argument("--tokenizer", required=True, help="Tokenizer directory.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="Cowrie log file or directory.")
    src.add_argument("--synthetic", action="store_true")
    p.add_argument("--synthetic-sessions", type=int, default=800)
    p.add_argument("--pattern", default="*.json*")
    p.add_argument("--min-commands", type=int, default=2)
    p.add_argument("--max-length", type=int, default=256)
    p.add_argument("--no-standardize-timing", action="store_true")
    p.add_argument("--output-dir", default="artifacts/figures")
    p.add_argument("--device", default=None)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--n-trajectories", type=int, default=5)
    args = p.parse_args(argv)

    device = torch.device(
        args.device or ("cuda" if torch.cuda.is_available() else "cpu")
    )
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model = _load_model(Path(args.checkpoint), device)
    tokenizer = CommandTokenizer.load(args.tokenizer)
    sessions = _load_sessions(args)

    corpus = embed_corpus(
        model, tokenizer, sessions, device,
        max_length=args.max_length,
        standardize_timing=not args.no_standardize_timing,
    )

    method = plot_embedding_umap(corpus, output_dir / "embedding_map.png", seed=args.seed)
    analyzer = TemporalTrajectoryAnalyzer(TrajectoryConfig(mode="prefix"))
    traj_idx = plot_session_trajectories(
        corpus, output_dir / "trajectories.png", analyzer,
        indices=_representative_indices(corpus, n=args.n_trajectories),
    )
    metrics = clustering_quality(corpus, seed=args.seed)
    metrics["reduction_method"] = method
    metrics["trajectory_session_ids"] = [corpus.sessions[i].session_id for i in traj_idx]

    (output_dir / "clustering_metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    print(json.dumps(metrics, indent=2))
    print(f"\nFigures + metrics written to {output_dir}/")
    return metrics


if __name__ == "__main__":  # pragma: no cover
    main()
