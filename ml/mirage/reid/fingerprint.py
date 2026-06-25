"""Behavioural fingerprint analysis: what makes an attacker re-identifiable.

Three questions the paper needs answered, each implemented here:

1. **Where does identity live in the command stream?** -- the *mutual information*
   between the token at each position and the identity label, plus which
   individual commands and bigrams are most identity-revealing. This is the
   information-theoretic counterpart of asking *which time bins of a neural
   response carry the most information about stimulus identity* (Bialek-style
   stimulus reconstruction): we localise the discriminative structure rather than
   treating the session as a bag of commands.

2. **Does timing rhythm generalise independently of content?** -- re-ID under
   *channel ablation*: embed with only the timing channel (tokens masked to
   ``<oov>``) vs only the content channel (timing zeroed) vs both. If timing-only
   re-ID beats chance, an attacker's **cadence is a biometric** that survives even
   when the commands are hidden -- the ICI-statistics-as-identity hypothesis,
   directly analogous to identifying a neuron from its ISI distribution alone.

3. **Can we fingerprint the toolkit rather than the individual?** -- a linear
   probe and an unsupervised clustering of the embeddings against the *toolkit*
   label (e.g. Metasploit vs Cobalt Strike on real captures; the simulated
   toolkits here). High probe accuracy means the representation also encodes the
   coarse "cell type", not only the individual -- a separable, lower-resolution
   fingerprint usable when per-individual re-ID is not the goal.

The MI routines are sklearn-only (no model needed); the ablation and toolkit
routines consume a trained :class:`~mirage.reid.model.ContrastiveReIDModel`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
import torch

from ..tokenizer.tokenizer import CommandTokenizer
from .dataset import ReIDDataset, ReIDExample
from .evaluate import EmbeddingBank, embed_dataset, recall_at_k
from .model import ContrastiveReIDModel, ReIDSpace

__all__ = [
    "PositionalMI",
    "sessions_to_token_sequences",
    "positional_mutual_information",
    "most_discriminative_commands",
    "channel_ablation_reid",
    "linear_probe_accuracy",
    "toolkit_fingerprint",
    "toolkit_cluster_purity",
]


# ---------------------------------------------------------------------------
# 1. Where in the command stream does identity live?
# ---------------------------------------------------------------------------


@dataclass
class PositionalMI:
    """Mutual information between the command at each position and identity.

    Attributes:
        positions: Command positions analysed (0 == first command).
        mutual_information: Normalised MI in ``[0, 1]`` per position (1 == the
            token at that position fully determines identity).
        support: Number of sessions long enough to contribute at each position.
    """

    positions: list[int]
    mutual_information: list[float]
    support: list[int]


def sessions_to_token_sequences(
    dataset: ReIDDataset, strip_specials: bool = True
) -> list[list[int]]:
    """Extract per-session token-id sequences from a dataset (specials removed).

    Uses the already-encoded ``input_ids`` on each :class:`ReIDExample`; the
    special anchors (``<bos>``/``<eos>``/``<pad>``) are dropped so position 0 is
    the first *command*.
    """
    tok = dataset.tokenizer
    specials = {tok.pad_id, tok.bos_id, tok.eos_id}
    sequences: list[list[int]] = []
    for ex in dataset.examples:
        if strip_specials:
            sequences.append([t for t in ex.input_ids if t not in specials])
        else:
            sequences.append(list(ex.input_ids))
    return sequences


def positional_mutual_information(
    token_sequences: Sequence[Sequence[int]],
    identities: Sequence[str],
    max_positions: int | None = None,
    min_support: int = 5,
) -> PositionalMI:
    """MI between the token at each position and the identity label.

    For each position ``p`` we gather ``(token_at_p, identity)`` over every session
    long enough to reach ``p`` and compute the normalised mutual information. A
    position with high MI is one where *which command an attacker runs there*
    strongly betrays *who they are*.

    Args:
        token_sequences: Per-session command-token id sequences (specials removed).
        identities: Per-session identity labels (aligned with ``token_sequences``).
        max_positions: Cap on positions analysed; defaults to the longest session.
        min_support: Skip positions with fewer than this many contributing
            sessions (MI is unreliable on tiny samples).

    Returns:
        A :class:`PositionalMI`.
    """
    from sklearn.metrics import normalized_mutual_info_score

    if len(token_sequences) != len(identities):
        raise ValueError("token_sequences and identities must align")
    longest = max((len(s) for s in token_sequences), default=0)
    limit = longest if max_positions is None else min(max_positions, longest)

    positions: list[int] = []
    mis: list[float] = []
    support: list[int] = []
    for p in range(limit):
        toks: list[int] = []
        ids: list[str] = []
        for seq, identity in zip(token_sequences, identities):
            if len(seq) > p:
                toks.append(seq[p])
                ids.append(identity)
        if len(toks) < min_support:
            continue
        positions.append(p)
        mis.append(float(normalized_mutual_info_score(ids, toks)))
        support.append(len(toks))
    return PositionalMI(positions=positions, mutual_information=mis, support=support)


def most_discriminative_commands(
    dataset: ReIDDataset,
    identities: Sequence[str] | None = None,
    top_n: int = 15,
    use_bigrams: bool = True,
) -> list[tuple[str, float]]:
    """Rank commands (and optional bigrams) by how much they reveal identity.

    For each command (or adjacent-command bigram) we form the binary feature
    "this session contains it" and compute its normalised MI with identity. The
    highest-MI features are the **signature subsequences** -- the idiosyncratic
    commands that pin down *who* an attacker is.

    Args:
        dataset: The encoded dataset (also supplies the tokenizer for decoding).
        identities: Per-session identities; defaults to ``dataset.identities``.
        top_n: Number of features to return.
        use_bigrams: Also score adjacent-command bigrams (captures short
            *subsequences*, not only single commands).

    Returns:
        ``[(feature_string, normalised_mi), ...]`` sorted by MI descending.
    """
    from sklearn.metrics import normalized_mutual_info_score

    ids = list(identities) if identities is not None else dataset.identities
    tok = dataset.tokenizer
    sequences = sessions_to_token_sequences(dataset, strip_specials=True)

    # Collect the feature vocabulary (unigrams + bigrams) present in the corpus.
    feature_sessions: list[set[str]] = []
    vocabulary: set[str] = set()
    for seq in sequences:
        feats: set[str] = set()
        decoded = tok.decode(seq, skip_special=True)
        for token in decoded:
            feats.add(token)
        if use_bigrams:
            for a, b in zip(decoded, decoded[1:]):
                feats.add(f"{a} → {b}")
        feature_sessions.append(feats)
        vocabulary |= feats

    scored: list[tuple[str, float]] = []
    for feature in vocabulary:
        present = [1 if feature in feats else 0 for feats in feature_sessions]
        # Skip features that are everywhere or nowhere (MI is 0 and uninformative).
        if 0 < sum(present) < len(present):
            mi = float(normalized_mutual_info_score(ids, present))
            scored.append((feature, mi))
    scored.sort(key=lambda kv: kv[1], reverse=True)
    return scored[:top_n]


# ---------------------------------------------------------------------------
# 2. Does timing rhythm generalise independently of content?
# ---------------------------------------------------------------------------


def _clone_with_examples(
    dataset: ReIDDataset, examples: list[ReIDExample]
) -> ReIDDataset:
    """Lightweight copy of a dataset with replaced examples (no re-tokenising)."""
    clone = ReIDDataset.__new__(ReIDDataset)
    clone.tokenizer = dataset.tokenizer
    clone.examples = examples
    return clone


def _ablate(dataset: ReIDDataset, mode: str) -> ReIDDataset:
    """Return a dataset variant with one channel ablated.

    ``"timing_only"`` masks every command token to ``<oov>`` (content destroyed,
    cadence intact); ``"content_only"`` zeros the timing channel (cadence
    destroyed, content intact); ``"both"`` is the original.
    """
    if mode == "both":
        return dataset
    tok = dataset.tokenizer
    specials = {tok.pad_id, tok.bos_id, tok.eos_id}
    new_examples: list[ReIDExample] = []
    for ex in dataset.examples:
        if mode == "timing_only":
            ids = [t if t in specials else tok.oov_id for t in ex.input_ids]
            tim = list(ex.timing)
        elif mode == "content_only":
            ids = list(ex.input_ids)
            tim = [0.0] * len(ex.timing)
        else:
            raise ValueError(f"unknown ablation mode {mode!r}")
        new_examples.append(
            ReIDExample(input_ids=ids, timing=tim, identity=ex.identity, toolkit=ex.toolkit)
        )
    return _clone_with_examples(dataset, new_examples)


def channel_ablation_reid(
    model: ContrastiveReIDModel,
    dataset: ReIDDataset,
    gallery_indices: Sequence[int],
    probe_indices: Sequence[int],
    ks: Sequence[int] = (1, 5),
    space: ReIDSpace = "projection",
    device: torch.device | str | None = None,
) -> dict[str, dict[int, float]]:
    """Re-ID recall under content/timing channel ablation.

    Embeds gallery and probe three ways -- both channels, content-only,
    timing-only -- and reports recall@k for each. Timing-only recall above chance
    is the evidence that **cadence rhythm is an identity fingerprint independent
    of command content**.

    Returns:
        ``{"both": {k: recall}, "content_only": {...}, "timing_only": {...}}``.
    """
    results: dict[str, dict[int, float]] = {}
    for mode in ("both", "content_only", "timing_only"):
        ablated = _ablate(dataset, mode)
        gallery = embed_dataset(model, ablated, gallery_indices, space=space, device=device)
        probe = embed_dataset(model, ablated, probe_indices, space=space, device=device)
        results[mode] = recall_at_k(gallery, probe, ks=ks)
    return results


# ---------------------------------------------------------------------------
# 3. Fingerprinting the toolkit rather than the individual
# ---------------------------------------------------------------------------


def linear_probe_accuracy(
    train_vectors: np.ndarray,
    train_labels: Sequence[str],
    test_vectors: np.ndarray,
    test_labels: Sequence[str],
    seed: int = 0,
) -> float:
    """Accuracy of a logistic-regression linear probe on frozen embeddings."""
    from sklearn.linear_model import LogisticRegression

    clf = LogisticRegression(max_iter=1000, random_state=seed)
    clf.fit(train_vectors, list(train_labels))
    return float(clf.score(test_vectors, list(test_labels)))


def toolkit_fingerprint(
    model: ContrastiveReIDModel,
    dataset: ReIDDataset,
    train_indices: Sequence[int],
    test_indices: Sequence[int],
    space: ReIDSpace = "backbone",
    device: torch.device | str | None = None,
    seed: int = 0,
) -> dict[str, float]:
    """Linear-probe accuracy for predicting the *toolkit* from the embedding.

    Uses the backbone representation ``h`` by default (the transfer space, per
    SimCLR practice). Reports probe accuracy and the majority-class baseline, so
    "above chance" is unambiguous.

    Returns:
        ``{"toolkit_probe_accuracy": ..., "majority_baseline": ...,
        "n_classes": ...}``.
    """
    train = embed_dataset(model, dataset, train_indices, space=space, device=device)
    test = embed_dataset(model, dataset, test_indices, space=space, device=device)
    acc = linear_probe_accuracy(
        train.vectors.numpy(), train.toolkits, test.vectors.numpy(), test.toolkits, seed=seed
    )
    # Majority-class baseline on the test split.
    values, counts = np.unique(np.asarray(test.toolkits), return_counts=True)
    majority = float(counts.max() / counts.sum()) if counts.size else 0.0
    return {
        "toolkit_probe_accuracy": acc,
        "majority_baseline": majority,
        "n_classes": float(len(set(train.toolkits))),
    }


def toolkit_cluster_purity(
    bank: EmbeddingBank, seed: int = 0
) -> dict[str, float]:
    """Unsupervised KMeans clustering of embeddings vs the toolkit labels.

    Clusters the embeddings into ``n_toolkits`` groups and scores agreement with
    the true toolkit labels (adjusted Rand index + homogeneity). High scores mean
    toolkits separate in the embedding space *without supervision*.

    Returns:
        ``{"adjusted_rand": ..., "homogeneity": ..., "n_clusters": ...}``.
    """
    from sklearn.cluster import KMeans
    from sklearn.metrics import adjusted_rand_score, homogeneity_score

    labels = np.asarray(bank.toolkits)
    n_clusters = len(set(bank.toolkits))
    if n_clusters < 2 or len(bank) < n_clusters:
        return {"adjusted_rand": 0.0, "homogeneity": 0.0, "n_clusters": float(n_clusters)}
    km = KMeans(n_clusters=n_clusters, random_state=seed, n_init=10)
    pred = km.fit_predict(bank.vectors.numpy())
    return {
        "adjusted_rand": float(adjusted_rand_score(labels, pred)),
        "homogeneity": float(homogeneity_score(labels, pred)),
        "n_clusters": float(n_clusters),
    }
