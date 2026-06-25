"""Re-identification evaluation: recall@k, mAP, and t-SNE geometry.

These are the standard **open/closed-set re-identification** metrics, transferred
directly from their use in person/vehicle re-ID (and identical in spirit to
cross-session neuron matching): enrol a **gallery** of known-identity sessions,
then for each held-out **probe** (a genuine later reconnection) rank the gallery
by embedding similarity and ask whether a same-identity session surfaces near the
top.

* **recall@k** (a.k.a. CMC top-k hit rate) -- fraction of probes for which *at
  least one* same-identity gallery session appears in the top ``k`` neighbours.
  ``recall@1`` is the strict "nearest neighbour is the same attacker" rate.
* **mAP** -- mean average precision, which (unlike recall@k) rewards ranking
  *all* of an identity's gallery sessions highly, not just the first hit. It is
  the more honest summary when identities have several gallery sessions.

Retrieval is in the model's projection space ``z`` by default (the unit-sphere
metric the NT-Xent loss actually shaped), with cosine similarity. The t-SNE
helpers produce the paper's "before vs after contrastive training" figure.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import numpy as np
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader, Subset

from .dataset import ReIDDataset, ReIDEvalCollator
from .model import ContrastiveReIDModel, ReIDSpace

__all__ = [
    "EmbeddingBank",
    "embed_dataset",
    "recall_at_k",
    "average_precision",
    "mean_average_precision",
    "reid_evaluate",
    "tsne_coordinates",
    "plot_tsne_comparison",
]


@dataclass
class EmbeddingBank:
    """A set of session embeddings with aligned identity/toolkit labels.

    Attributes:
        vectors: ``[N, D]`` float tensor of embeddings (L2-normalised on build).
        identities: Length-``N`` identity labels.
        toolkits: Length-``N`` toolkit labels.
    """

    vectors: torch.Tensor
    identities: list[str]
    toolkits: list[str]

    def __len__(self) -> int:
        return self.vectors.size(0)


def embed_dataset(
    model: ContrastiveReIDModel,
    dataset: ReIDDataset,
    indices: Sequence[int] | None = None,
    space: ReIDSpace = "projection",
    batch_size: int = 128,
    device: torch.device | str | None = None,
) -> EmbeddingBank:
    """Encode (a subset of) a dataset into an :class:`EmbeddingBank`.

    Args:
        model: The re-ID model.
        dataset: A :class:`ReIDDataset`.
        indices: Optional subset of row indices (e.g. gallery or probe indices);
            defaults to the whole dataset.
        space: ``"projection"`` (64-d metric, default) or ``"backbone"`` (128-d
            representation).
        batch_size: Embedding batch size.
        device: Compute device; defaults to the model's device.

    Returns:
        An :class:`EmbeddingBank` with L2-normalised vectors (so dot product is
        cosine similarity) and aligned labels, in ``indices`` order.
    """
    device = torch.device(device) if device is not None else next(model.parameters()).device
    subset = Subset(dataset, list(indices)) if indices is not None else dataset
    loader = DataLoader(
        subset, batch_size=batch_size, shuffle=False, collate_fn=ReIDEvalCollator(dataset.tokenizer)
    )
    vecs: list[torch.Tensor] = []
    identities: list[str] = []
    toolkits: list[str] = []
    was_training = model.training
    model.eval()
    try:
        for view, batch_ids, batch_kits in loader:
            view = view.to(device)
            z = model.embed(view.input_ids, view.timing, view.attention_mask, space=space)
            vecs.append(F.normalize(z, dim=-1).cpu())
            identities.extend(batch_ids)
            toolkits.extend(batch_kits)
    finally:
        model.train(was_training)
    vectors = torch.cat(vecs, dim=0) if vecs else torch.empty(0)
    return EmbeddingBank(vectors=vectors, identities=identities, toolkits=toolkits)


def _similarity(probe: torch.Tensor, gallery: torch.Tensor) -> torch.Tensor:
    """Cosine similarity matrix ``[P, G]`` (inputs assumed L2-normalised)."""
    return probe @ gallery.t()


def recall_at_k(
    gallery: EmbeddingBank,
    probe: EmbeddingBank,
    ks: Sequence[int] = (1, 5, 10),
) -> dict[int, float]:
    """Compute recall@k (CMC hit rate) for each ``k`` in ``ks``.

    A probe scores a hit@k if any of its top-``k`` gallery neighbours shares its
    identity. Gallery and probe are disjoint (the reconnection split), so no self-
    match needs excluding.

    Returns:
        ``{k: recall_at_k}`` with values in ``[0, 1]``. ``k`` is clamped to the
        gallery size.
    """
    if len(probe) == 0 or len(gallery) == 0:
        return {k: 0.0 for k in ks}
    sims = _similarity(probe.vectors, gallery.vectors)  # [P, G]
    gallery_ids = np.asarray(gallery.identities)
    probe_ids = np.asarray(probe.identities)
    max_k = min(max(ks), sims.size(1))
    # Top-(max_k) gallery indices per probe, highest similarity first.
    top = torch.topk(sims, k=max_k, dim=1).indices.numpy()  # [P, max_k]

    out: dict[int, float] = {}
    for k in ks:
        kk = min(k, sims.size(1))
        hits = 0
        for p in range(top.shape[0]):
            neighbour_ids = gallery_ids[top[p, :kk]]
            if np.any(neighbour_ids == probe_ids[p]):
                hits += 1
        out[k] = hits / top.shape[0]
    return out


def average_precision(ranked_relevant: np.ndarray) -> float:
    """Average precision for one ranked list of relevance flags (1 == same id).

    ``ranked_relevant[r]`` is 1 if the gallery item at rank ``r`` (0 == most
    similar) shares the probe's identity. AP is the mean of precision@r over the
    ranks where a relevant item occurs; 0 if there are no relevant items.
    """
    total_relevant = int(ranked_relevant.sum())
    if total_relevant == 0:
        return 0.0
    cum_hits = np.cumsum(ranked_relevant)
    ranks = np.arange(1, len(ranked_relevant) + 1)
    precision_at_hits = (cum_hits / ranks)[ranked_relevant.astype(bool)]
    return float(precision_at_hits.mean())


def mean_average_precision(gallery: EmbeddingBank, probe: EmbeddingBank) -> float:
    """Mean average precision over all probes (full gallery ranking)."""
    if len(probe) == 0 or len(gallery) == 0:
        return 0.0
    sims = _similarity(probe.vectors, gallery.vectors)
    order = torch.argsort(sims, dim=1, descending=True).numpy()  # [P, G]
    gallery_ids = np.asarray(gallery.identities)
    probe_ids = np.asarray(probe.identities)
    aps = []
    for p in range(order.shape[0]):
        ranked_ids = gallery_ids[order[p]]
        relevant = (ranked_ids == probe_ids[p]).astype(np.float64)
        aps.append(average_precision(relevant))
    return float(np.mean(aps)) if aps else 0.0


def reid_evaluate(
    model: ContrastiveReIDModel,
    dataset: ReIDDataset,
    gallery_indices: Sequence[int],
    probe_indices: Sequence[int],
    ks: Sequence[int] = (1, 5, 10),
    space: ReIDSpace = "projection",
    device: torch.device | str | None = None,
) -> dict[str, float]:
    """Run the full re-ID protocol and return recall@k + mAP.

    Returns:
        ``{"recall@1": ..., "recall@5": ..., "recall@10": ..., "mAP": ...,
        "n_gallery": ..., "n_probe": ...}``.
    """
    gallery = embed_dataset(model, dataset, gallery_indices, space=space, device=device)
    probe = embed_dataset(model, dataset, probe_indices, space=space, device=device)
    recalls = recall_at_k(gallery, probe, ks=ks)
    metrics: dict[str, float] = {f"recall@{k}": v for k, v in recalls.items()}
    metrics["mAP"] = mean_average_precision(gallery, probe)
    metrics["n_gallery"] = float(len(gallery))
    metrics["n_probe"] = float(len(probe))
    return metrics


# ---------------------------------------------------------------------------
# t-SNE geometry (the "before vs after contrastive training" figure)
# ---------------------------------------------------------------------------


def tsne_coordinates(
    vectors: torch.Tensor,
    perplexity: float = 30.0,
    seed: int = 0,
    metric: str = "cosine",
) -> np.ndarray:
    """2-D t-SNE embedding of ``[N, D]`` vectors (for visual inspection).

    Perplexity is automatically clamped below the sample count (sklearn requires
    ``perplexity < n_samples``), so this is safe on small held-out sets.
    """
    from sklearn.manifold import TSNE

    x = vectors.detach().cpu().numpy()
    n = x.shape[0]
    perp = float(max(2.0, min(perplexity, (n - 1) / 3.0)))
    tsne = TSNE(
        n_components=2,
        perplexity=perp,
        metric=metric,
        init="pca" if metric == "euclidean" else "random",
        random_state=seed,
    )
    return tsne.fit_transform(x)


def plot_tsne_comparison(
    before: EmbeddingBank,
    after: EmbeddingBank,
    output_path: str | Path,
    color_by: str = "identity",
    perplexity: float = 30.0,
    seed: int = 0,
    max_legend: int = 12,
) -> Path:
    """Save a two-panel t-SNE figure: embeddings *before* vs *after* training.

    Both panels colour points by ``color_by`` (``"identity"`` or ``"toolkit"``),
    so the reader sees same-identity (or same-toolkit) points collapse together
    after contrastive training. Returns the written path.
    """
    import matplotlib

    matplotlib.use("Agg")  # headless: write files, never open a window
    import matplotlib.pyplot as plt

    labels_before = getattr(before, color_by + "s")
    labels_after = getattr(after, color_by + "s")
    coords_before = tsne_coordinates(before.vectors, perplexity, seed)
    coords_after = tsne_coordinates(after.vectors, perplexity, seed)

    uniq = sorted(set(labels_before) | set(labels_after))
    cmap = plt.get_cmap("tab20" if len(uniq) > 10 else "tab10")
    color_of = {lab: cmap(i % cmap.N) for i, lab in enumerate(uniq)}

    fig, axes = plt.subplots(1, 2, figsize=(13, 6))
    for ax, coords, labels, title in (
        (axes[0], coords_before, labels_before, "Before contrastive training"),
        (axes[1], coords_after, labels_after, "After contrastive training"),
    ):
        for lab in uniq:
            mask = np.asarray(labels) == lab
            if mask.any():
                ax.scatter(
                    coords[mask, 0], coords[mask, 1], s=14, alpha=0.8,
                    color=color_of[lab], label=lab if len(uniq) <= max_legend else None,
                )
        ax.set_title(title)
        ax.set_xticks([])
        ax.set_yticks([])
    if len(uniq) <= max_legend:
        axes[1].legend(loc="best", fontsize=8, title=color_by)
    fig.suptitle(f"MIRAGE re-ID embeddings (t-SNE), coloured by {color_by}")
    fig.tight_layout()

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out
