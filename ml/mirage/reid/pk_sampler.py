from __future__ import annotations

import random
from typing import Iterator, Sequence

__all__ = ["PKBatchSampler"]


class PKBatchSampler:
    """Yields batches as P identities x K sessions each (real, unbalanced groups).

    Standard P-K batch sampling for metric learning (Hermans et al. 2017's
    triplet-loss convention), generalized to identity groups of very unequal,
    real size: MIRAGE's 1,339 multi-session addresses range from 2 sessions to
    3,805. An identity with fewer than ``k`` available sessions has its
    available sessions **resampled with replacement** to fill the remaining
    slots, rather than the batch shrinking or the identity being skipped -- the
    collator then applies a fresh random augmentation to every slot (including
    the resampled ones), so a repeated real session still yields a distinct
    embedding rather than a literal duplicate. An identity with exactly one
    session degenerates cleanly to ``k`` independently-augmented views of that
    one session: the augmentation-only fallback for addresses with no repeat
    traffic falls out of this rule automatically, rather than needing a
    separate code path.

    Args:
        identity_labels: Per-dataset-row identity label, row-aligned to the
            dataset the yielded indices index into (e.g.
            ``ReIDDataset.identities``).
        p: Distinct identities per batch. Needs >= 2 so every anchor has at
            least one other identity in the batch to contrast against.
        k: Sessions sampled per identity per batch.
        batches_per_epoch: Number of batches one iteration yields.
        seed: RNG seed for reproducibility.

    Raises:
        ValueError: If ``p < 2``, ``k < 1``, or fewer than ``p`` distinct
            identities exist in ``identity_labels``.
    """

    def __init__(
        self,
        identity_labels: Sequence[str],
        p: int = 16,
        k: int = 4,
        batches_per_epoch: int = 100,
        seed: int | None = None,
    ) -> None:
        if p < 2:
            raise ValueError("p must be >= 2 (need another identity in-batch to contrast against)")
        if k < 1:
            raise ValueError("k must be >= 1")

        by_identity: dict[str, list[int]] = {}
        for idx, identity in enumerate(identity_labels):
            by_identity.setdefault(identity, []).append(idx)
        if len(by_identity) < p:
            raise ValueError(
                f"only {len(by_identity)} distinct identities available, need at least p={p}"
            )

        self.by_identity = by_identity
        self.identities = list(by_identity.keys())
        self.p = p
        self.k = k
        self.batches_per_epoch = batches_per_epoch
        self.rng = random.Random(seed)

    def __len__(self) -> int:
        return self.batches_per_epoch

    @property
    def batch_size(self) -> int:
        return self.p * self.k

    def __iter__(self) -> Iterator[list[int]]:
        for _ in range(self.batches_per_epoch):
            chosen_identities = self.rng.sample(self.identities, self.p)
            batch: list[int] = []
            for identity in chosen_identities:
                available = self.by_identity[identity]
                if len(available) >= self.k:
                    batch.extend(self.rng.sample(available, self.k))
                else:
                    picks = list(available)
                    while len(picks) < self.k:
                        picks.append(self.rng.choice(available))
                    batch.extend(picks)
            yield batch
