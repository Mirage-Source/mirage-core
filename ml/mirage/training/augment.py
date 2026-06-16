"""Channel-aware session augmentations for contrastive learning.

A contrastive objective is only as good as its augmentations: the two views of a
session must be *different enough* that the encoder cannot cheat, yet preserve
the session's behavioral identity (its tool signature) so the positive pair
remains semantically valid. Standard NLP token augmentations ignore the timing
channel; ours operate on **both aligned channels at once** so the dual-channel
contract (one timing value per token) is never broken.

Four augmentations, each with a neuroscience-flavored rationale:

* **temporal crop** -- keep a contiguous sub-window of commands. Analogous to
  taking a random time-window of a spike train: a tool's behavior is
  approximately stationary, so a sub-window is still recognizably the same tool.
* **command dropout** -- delete a random subset of (token, timing) positions.
  Like dropping spikes / subsampling units; forces the encoder to rely on the
  overall pattern, not any single command.
* **span mask** -- replace a contiguous run of tokens with ``<oov>`` while
  *keeping their timing*. Tests whether the timing channel alone carries the
  cadence signature when content is hidden.
* **timing jitter** -- add small Gaussian noise to the log-ICI channel. Models
  natural variation in inter-command latency (network RTT, scheduler jitter)
  without changing which commands ran.

Special tokens (``<pad>``, ``<bos>``, ``<eos>``) are protected from dropout and
masking so structural anchors survive; timing jitter applies to all positions.
This module is stdlib-only (operates on Python lists) so it is unit-testable
without torch or the Phase-1 stack.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

__all__ = ["AugmentConfig", "SessionAugmenter"]


@dataclass
class AugmentConfig:
    """Probabilities and strengths for each augmentation.

    Attributes:
        crop_prob: Probability of applying a temporal crop.
        crop_min_frac: Minimum fraction of commands a crop retains.
        dropout_prob: Probability of applying command dropout.
        dropout_frac: Expected fraction of positions dropped when it fires.
        span_mask_prob: Probability of applying a span mask.
        span_mask_max_frac: Maximum fraction of the sequence a mask span covers.
        timing_jitter_prob: Probability of applying timing jitter.
        timing_jitter_std: Std of the Gaussian noise added in the log-ICI domain.
        min_length: Never reduce a view below this many positions (keeps a usable
            sequence even for short sessions).
    """

    crop_prob: float = 0.5
    crop_min_frac: float = 0.6
    dropout_prob: float = 0.5
    dropout_frac: float = 0.1
    span_mask_prob: float = 0.5
    span_mask_max_frac: float = 0.2
    timing_jitter_prob: float = 0.7
    timing_jitter_std: float = 0.3
    min_length: int = 2


class SessionAugmenter:
    """Produce stochastic, channel-aligned views of an encoded session.

    Operates on plain aligned lists ``(input_ids, timing)`` -- the two channels
    emitted by ``CommandTokenizer.encode`` -- and returns a new aligned pair. The
    pipeline applies each augmentation independently with its configured
    probability, in a fixed order (crop -> dropout -> span-mask -> jitter).

    Args:
        oov_id: Vocabulary id used as the mask token for span masking.
        protected_ids: Token ids (pad/bos/eos) exempt from dropout and masking.
        config: Augmentation probabilities/strengths.
        rng: Optional :class:`random.Random` for reproducibility; a fresh one is
            created if omitted.
    """

    def __init__(
        self,
        oov_id: int,
        protected_ids: set[int],
        config: AugmentConfig | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.oov_id = oov_id
        self.protected_ids = set(protected_ids)
        self.config = config or AugmentConfig()
        self.rng = rng or random.Random()

    def __call__(
        self, input_ids: list[int], timing: list[float]
    ) -> tuple[list[int], list[float]]:
        """Return one augmented view of the (ids, timing) pair."""
        if len(input_ids) != len(timing):
            raise ValueError("input_ids and timing must be the same length")
        ids = list(input_ids)
        tim = list(timing)
        cfg = self.config

        if self.rng.random() < cfg.crop_prob:
            ids, tim = self._temporal_crop(ids, tim)
        if self.rng.random() < cfg.dropout_prob:
            ids, tim = self._command_dropout(ids, tim)
        if self.rng.random() < cfg.span_mask_prob:
            ids, tim = self._span_mask(ids, tim)
        if self.rng.random() < cfg.timing_jitter_prob:
            tim = self._timing_jitter(tim)

        return ids, tim

    # -- Individual augmentations ------------------------------------------

    def _temporal_crop(
        self, ids: list[int], tim: list[float]
    ) -> tuple[list[int], list[float]]:
        """Keep a contiguous sub-window of at least ``crop_min_frac`` positions."""
        n = len(ids)
        keep = max(self.config.min_length, int(round(n * self.config.crop_min_frac)))
        if keep >= n:
            return ids, tim
        start = self.rng.randint(0, n - keep)
        end = start + keep
        return ids[start:end], tim[start:end]

    def _command_dropout(
        self, ids: list[int], tim: list[float]
    ) -> tuple[list[int], list[float]]:
        """Drop a random subset of non-protected positions."""
        n = len(ids)
        out_ids: list[int] = []
        out_tim: list[float] = []
        for i in range(n):
            protected = ids[i] in self.protected_ids
            drop = (
                not protected
                and self.rng.random() < self.config.dropout_frac
                and (n - len(out_ids)) > self.config.min_length
            )
            if not drop:
                out_ids.append(ids[i])
                out_tim.append(tim[i])
        if len(out_ids) < self.config.min_length:
            return ids, tim
        return out_ids, out_tim

    def _span_mask(
        self, ids: list[int], tim: list[float]
    ) -> tuple[list[int], list[float]]:
        """Replace a contiguous span of tokens with ``<oov>`` (timing untouched)."""
        n = len(ids)
        max_span = max(1, int(round(n * self.config.span_mask_max_frac)))
        span = self.rng.randint(1, max_span)
        if span >= n:
            return ids, tim
        start = self.rng.randint(0, n - span)
        out_ids = list(ids)
        for i in range(start, start + span):
            if out_ids[i] not in self.protected_ids:
                out_ids[i] = self.oov_id
        return out_ids, tim

    def _timing_jitter(self, tim: list[float]) -> list[float]:
        """Add Gaussian noise (log-ICI domain) to every timing value."""
        std = self.config.timing_jitter_std
        return [t + self.rng.gauss(0.0, std) for t in tim]
