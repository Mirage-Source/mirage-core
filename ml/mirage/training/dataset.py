"""Dataset and contrastive collation for session embedding training.

Bridges the Phase-1 data stack (``CommandTokenizer`` -> ``EncodedSession``) to the
Phase-2 contrastive trainer. The dataset pre-encodes each session once into the
two aligned channels; the collator turns every session into **two augmented
views** and pads each view independently into batch tensors ready for
:class:`~mirage.models.embedding.SessionEmbedder`.

The two-view batch layout is what NT-Xent expects: ``view1[i]`` and ``view2[i]``
are two augmentations of session ``i``, so they form the positive pair while all
other rows are negatives.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Sequence

import torch
from torch.utils.data import Dataset

from ..data.schema import Session
from ..tokenizer.tokenizer import CommandTokenizer
from .augment import AugmentConfig, SessionAugmenter

__all__ = ["EncodedExample", "SessionDataset", "ContrastiveCollator", "BatchView"]


@dataclass
class EncodedExample:
    """One pre-encoded session: the two aligned channels, no padding."""

    input_ids: list[int]
    timing: list[float]


@dataclass
class BatchView:
    """One padded view of a contrastive batch.

    Attributes:
        input_ids: ``[B, L]`` long tensor of token ids.
        timing: ``[B, L]`` float tensor of log-ICI values.
        attention_mask: ``[B, L]`` tensor, ``1`` for real positions.
    """

    input_ids: torch.Tensor
    timing: torch.Tensor
    attention_mask: torch.Tensor

    def to(self, device: torch.device | str) -> "BatchView":
        """Move all tensors to ``device`` (returns a new :class:`BatchView`)."""
        return BatchView(
            input_ids=self.input_ids.to(device),
            timing=self.timing.to(device),
            attention_mask=self.attention_mask.to(device),
        )


class SessionDataset(Dataset):
    """Torch dataset of pre-encoded MIRAGE sessions.

    Each item is an :class:`EncodedExample` -- the two aligned channels for one
    session, *unpadded* and including any special tokens. Augmentation and
    padding happen in :class:`ContrastiveCollator` so each epoch sees fresh views.

    Args:
        sessions: Sessions to train on (already loaded by the Phase-1 loader).
        tokenizer: A fitted :class:`CommandTokenizer`.
        max_length: Optional cap on the number of commands encoded per session
            (special tokens are added on top). Long sessions are truncated here.
        standardize_timing: Whether to z-score the timing channel using the
            tokenizer's corpus statistics.
    """

    def __init__(
        self,
        sessions: Sequence[Session],
        tokenizer: CommandTokenizer,
        max_length: int | None = None,
        standardize_timing: bool = True,
    ) -> None:
        self.tokenizer = tokenizer
        self.examples: list[EncodedExample] = []
        for session in sessions:
            enc = tokenizer.encode(
                session,
                max_length=max_length,
                standardize_timing=standardize_timing,
            )
            self.examples.append(
                EncodedExample(input_ids=list(enc.input_ids), timing=list(enc.timing))
            )

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, idx: int) -> EncodedExample:
        return self.examples[idx]


class ContrastiveCollator:
    """Collate sessions into a two-view, padded contrastive batch.

    For every example it draws two independent augmented views, then right-pads
    each view's batch to that view's own max length. Returns a ``(view1, view2)``
    pair of :class:`BatchView`.

    Args:
        tokenizer: The fitted tokenizer (provides pad/oov/special ids).
        augment_config: Augmentation strengths; defaults if omitted.
        seed: Optional base seed; when set, the collator is deterministic across
            runs (useful for debugging / reproducible ablations).
    """

    def __init__(
        self,
        tokenizer: CommandTokenizer,
        augment_config: AugmentConfig | None = None,
        seed: int | None = None,
    ) -> None:
        self.pad_id = tokenizer.pad_id
        protected = {tokenizer.pad_id, tokenizer.bos_id, tokenizer.eos_id}
        rng = random.Random(seed) if seed is not None else None
        self.augmenter = SessionAugmenter(
            oov_id=tokenizer.oov_id,
            protected_ids=protected,
            config=augment_config,
            rng=rng,
        )

    def __call__(
        self, batch: list[EncodedExample]
    ) -> tuple[BatchView, BatchView]:
        view1 = self._build_view(batch)
        view2 = self._build_view(batch)
        return view1, view2

    def _build_view(self, batch: list[EncodedExample]) -> BatchView:
        aug_ids: list[list[int]] = []
        aug_tim: list[list[float]] = []
        for ex in batch:
            ids, tim = self.augmenter(ex.input_ids, ex.timing)
            aug_ids.append(ids)
            aug_tim.append(tim)
        return self._pad(aug_ids, aug_tim)

    def _pad(
        self, ids_list: list[list[int]], tim_list: list[list[float]]
    ) -> BatchView:
        max_len = max(len(ids) for ids in ids_list)
        b = len(ids_list)
        input_ids = torch.full((b, max_len), self.pad_id, dtype=torch.long)
        timing = torch.zeros((b, max_len), dtype=torch.float32)
        attention_mask = torch.zeros((b, max_len), dtype=torch.long)
        for i, (ids, tim) in enumerate(zip(ids_list, tim_list)):
            length = len(ids)
            input_ids[i, :length] = torch.tensor(ids, dtype=torch.long)
            timing[i, :length] = torch.tensor(tim, dtype=torch.float32)
            attention_mask[i, :length] = 1
        return BatchView(
            input_ids=input_ids, timing=timing, attention_mask=attention_mask
        )


class EvalCollator:
    """Collate sessions into a single padded (un-augmented) batch.

    Used to embed sessions for visualization / clustering, where we want the
    deterministic encoding rather than augmented views.
    """

    def __init__(self, tokenizer: CommandTokenizer) -> None:
        self.pad_id = tokenizer.pad_id

    def __call__(self, batch: list[EncodedExample]) -> BatchView:
        max_len = max(len(ex.input_ids) for ex in batch)
        b = len(batch)
        input_ids = torch.full((b, max_len), self.pad_id, dtype=torch.long)
        timing = torch.zeros((b, max_len), dtype=torch.float32)
        attention_mask = torch.zeros((b, max_len), dtype=torch.long)
        for i, ex in enumerate(batch):
            length = len(ex.input_ids)
            input_ids[i, :length] = torch.tensor(ex.input_ids, dtype=torch.long)
            timing[i, :length] = torch.tensor(ex.timing, dtype=torch.float32)
            attention_mask[i, :length] = 1
        return BatchView(
            input_ids=input_ids, timing=timing, attention_mask=attention_mask
        )
