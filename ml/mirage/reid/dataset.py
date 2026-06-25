"""Datasets and contrastive collation for re-identification training.

Bridges an identity-labelled corpus (or any ``list[Session]`` plus identity
labels) to the Phase-3 contrastive trainer. Mirrors the Phase-2 dataset/collator
contract -- pre-encode once, augment-and-pad per batch -- but with two
differences that matter for re-ID:

* the collator draws its two views with the **identity-preserving**
  :class:`~mirage.reid.augment.ReIDAugmenter` (drop / reorder / jitter), and
* the dataset carries **identity and toolkit labels** alongside each encoded
  session so the evaluation/fingerprint suites can recover ground truth without
  re-tokenising.

The two-view layout is exactly what NT-Xent expects: ``view1[i]`` and ``view2[i]``
are two augmentations of session ``i`` (its positive pair); all other rows in the
batch are negatives. We reuse Phase-2's ``EncodedExample`` / ``BatchView``
containers verbatim so the encoder forward signature is unchanged.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Sequence

import torch
from torch.utils.data import Dataset

from ..data.schema import Session
from ..tokenizer.tokenizer import CommandTokenizer
from ..training.dataset import BatchView, EncodedExample
from .augment import ReIDAugmentConfig, ReIDAugmenter
from .data import IdentityCorpus

__all__ = ["ReIDExample", "ReIDDataset", "ReIDCollator", "ReIDEvalCollator"]


@dataclass
class ReIDExample:
    """One pre-encoded session with its re-ID ground truth.

    Attributes:
        input_ids: Token-id channel (unpadded, includes special tokens).
        timing: Aligned log-ICI channel.
        identity: Ground-truth identity label (the re-ID class).
        toolkit: Toolkit/family label (the coarse fingerprint class).
    """

    input_ids: list[int]
    timing: list[float]
    identity: str
    toolkit: str

    @property
    def encoded(self) -> EncodedExample:
        """View as a Phase-2 :class:`EncodedExample` (channels only)."""
        return EncodedExample(input_ids=self.input_ids, timing=self.timing)


class ReIDDataset(Dataset):
    """Torch dataset of pre-encoded, identity-labelled sessions.

    Args:
        sessions: Sessions to encode.
        identity_labels: Per-session identity ground truth (same length as
            ``sessions``).
        tokenizer: A fitted :class:`CommandTokenizer`.
        toolkit_labels: Optional per-session toolkit labels; defaults to
            ``"unknown"``.
        max_length: Optional cap on commands encoded per session.
        standardize_timing: Whether to z-score the timing channel with the
            tokenizer's corpus statistics. (When ``True``, pass the matching
            ``timing_std`` to :class:`ReIDCollator` so jitter stays calibrated.)
    """

    def __init__(
        self,
        sessions: Sequence[Session],
        identity_labels: Sequence[str],
        tokenizer: CommandTokenizer,
        toolkit_labels: Sequence[str] | None = None,
        max_length: int | None = None,
        standardize_timing: bool = True,
    ) -> None:
        if len(sessions) != len(identity_labels):
            raise ValueError("sessions and identity_labels must align")
        toolkit_labels = toolkit_labels or ["unknown"] * len(sessions)
        if len(toolkit_labels) != len(sessions):
            raise ValueError("toolkit_labels must align with sessions")

        self.tokenizer = tokenizer
        self.examples: list[ReIDExample] = []
        for session, identity, toolkit in zip(sessions, identity_labels, toolkit_labels):
            enc = tokenizer.encode(
                session, max_length=max_length, standardize_timing=standardize_timing
            )
            self.examples.append(
                ReIDExample(
                    input_ids=list(enc.input_ids),
                    timing=list(enc.timing),
                    identity=identity,
                    toolkit=toolkit,
                )
            )

    @classmethod
    def from_corpus(
        cls,
        corpus: IdentityCorpus,
        tokenizer: CommandTokenizer,
        max_length: int | None = None,
        standardize_timing: bool = True,
    ) -> "ReIDDataset":
        """Build directly from an :class:`IdentityCorpus`."""
        return cls(
            sessions=corpus.sessions,
            identity_labels=corpus.identity_labels,
            tokenizer=tokenizer,
            toolkit_labels=corpus.toolkit_labels,
            max_length=max_length,
            standardize_timing=standardize_timing,
        )

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, idx: int) -> ReIDExample:
        return self.examples[idx]

    # -- Convenience accessors used by the eval/fingerprint suites ----------

    @property
    def identities(self) -> list[str]:
        return [ex.identity for ex in self.examples]

    @property
    def toolkits(self) -> list[str]:
        return [ex.toolkit for ex in self.examples]


def _pad_views(
    ids_list: list[list[int]], tim_list: list[list[float]], pad_id: int
) -> BatchView:
    """Right-pad a set of aligned channels into a :class:`BatchView`."""
    max_len = max(len(ids) for ids in ids_list)
    b = len(ids_list)
    input_ids = torch.full((b, max_len), pad_id, dtype=torch.long)
    timing = torch.zeros((b, max_len), dtype=torch.float32)
    attention_mask = torch.zeros((b, max_len), dtype=torch.long)
    for i, (ids, tim) in enumerate(zip(ids_list, tim_list)):
        length = len(ids)
        input_ids[i, :length] = torch.tensor(ids, dtype=torch.long)
        timing[i, :length] = torch.tensor(tim, dtype=torch.float32)
        attention_mask[i, :length] = 1
    return BatchView(input_ids=input_ids, timing=timing, attention_mask=attention_mask)


class ReIDCollator:
    """Collate sessions into a two-view, padded contrastive batch.

    For every example it draws two independent identity-preserving views, then
    right-pads each view to its own max length. Returns ``(view1, view2)``.

    Args:
        tokenizer: Fitted tokenizer (provides pad/bos/eos ids for anchoring).
        augment_config: Augmentation strengths; defaults to the Phase-3 spec.
        timing_std: Std the timing channel was standardized with (pass
            ``tokenizer.config.timing_std`` when the dataset used
            ``standardize_timing=True``; leave at ``1.0`` otherwise). Wired into the
            augmenter so timing jitter is an exact +-``jitter_frac`` on the latency.
        seed: Optional base seed for deterministic, reproducible augmentation.
    """

    def __init__(
        self,
        tokenizer: CommandTokenizer,
        augment_config: ReIDAugmentConfig | None = None,
        timing_std: float = 1.0,
        seed: int | None = None,
    ) -> None:
        self.pad_id = tokenizer.pad_id
        config = augment_config or ReIDAugmentConfig()
        config.timing_std = timing_std
        protected = {tokenizer.pad_id, tokenizer.bos_id, tokenizer.eos_id}
        rng = random.Random(seed) if seed is not None else None
        self.augmenter = ReIDAugmenter(protected_ids=protected, config=config, rng=rng)

    def __call__(self, batch: list[ReIDExample]) -> tuple[BatchView, BatchView]:
        return self._build_view(batch), self._build_view(batch)

    def _build_view(self, batch: list[ReIDExample]) -> BatchView:
        aug_ids: list[list[int]] = []
        aug_tim: list[list[float]] = []
        for ex in batch:
            ids, tim = self.augmenter(ex.input_ids, ex.timing)
            aug_ids.append(ids)
            aug_tim.append(tim)
        return _pad_views(aug_ids, aug_tim, self.pad_id)


class ReIDEvalCollator:
    """Collate sessions into a single, un-augmented padded batch.

    Used to embed gallery/probe sessions deterministically for recall@k, t-SNE,
    and fingerprint analysis. Also returns the aligned identity/toolkit labels so
    the caller never has to re-derive them.
    """

    def __init__(self, tokenizer: CommandTokenizer) -> None:
        self.pad_id = tokenizer.pad_id

    def __call__(
        self, batch: list[ReIDExample]
    ) -> tuple[BatchView, list[str], list[str]]:
        view = _pad_views(
            [ex.input_ids for ex in batch],
            [ex.timing for ex in batch],
            self.pad_id,
        )
        identities = [ex.identity for ex in batch]
        toolkits = [ex.toolkit for ex in batch]
        return view, identities, toolkits
