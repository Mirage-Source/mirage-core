"""Identity-preserving session augmentations for contrastive re-identification.

Phase 3 re-identification asks a different question from Phase 2's clustering, so
it needs a different augmentation regime. In Phase 2 the two views of a session
only had to share a *tool* signature; here the two views must share an
**individual attacker's identity** while differing in surface form as strongly as
two genuine reconnections from the same actor would. The augmentations below are
the *training-time stand-in* for the real-world nuisance transformations a
re-identifier must be invariant to:

* **command dropout (A)** -- delete ~20% of the commands. Models **incomplete
  capture**: a dropped TCP segment, a session torn down early, a command the
  sensor missed. Neuroscience analogue: **partial observation / unit dropout** in
  a population recording -- you re-identify a neuron from a *subset* of the trials
  it appeared in.
* **non-sequential shuffle (B)** -- locally permute the command order. Models a
  **reordered reconnection**: the same actor running the same toolkit but issuing
  steps in a different sequence (different mood, different shell history, a
  reordered script). Analogue: **trial-order invariance** -- identity must persist
  under permutation of the observation index.
* **timing jitter (C)** -- scale each inter-command interval by +-10%. Models
  **network noise / RTT jitter** between the attacker and the sensor. Analogue:
  **measurement noise on event times** (ISI jitter), the temporal counterpart of
  additive recording noise.

Why these three and not Phase 2's four
--------------------------------------
Phase 2 (``mirage.training.augment.SessionAugmenter``) used crop / dropout /
span-mask / jitter to teach *tool*-level invariance. For *identity* the decisive
new operator is **B (reorder)**: an individual's identity lives in *which*
commands they favour and *how fast* they type them, not in the exact order, so we
must explicitly break order while preserving the multiset of marks and their
cadence. Span-masking (hiding content) is dropped here because it erases exactly
the idiosyncratic command preferences that distinguish *individuals within a
tool* -- the hardest and most valuable re-ID case.

The augmenter operates on the two aligned channels emitted by
``CommandTokenizer.encode`` -- ``(input_ids, timing)`` -- and never breaks their
1:1 alignment. Special tokens (``<pad>``/``<bos>``/``<eos>``) are *anchors*: they
are never dropped, never moved, and never jittered, so structural scaffolding
survives every view. The module is stdlib-only (plain Python lists) so it unit-
tests without torch.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

__all__ = ["ReIDAugmentConfig", "ReIDAugmenter"]


@dataclass
class ReIDAugmentConfig:
    """Probabilities and strengths for the three re-ID augmentations.

    Each augmentation fires independently with its ``*_prob`` so the two views of
    a session are stochastically different (the contrastive objective needs the
    views to differ, or the encoder learns nothing). The *strengths*
    (``drop_frac``, ``jitter_frac``) are pinned to the Phase-3 spec.

    Attributes:
        drop_prob: Probability of applying command dropout (augmentation A).
        drop_frac: Expected fraction of (non-anchor) commands dropped when A
            fires. Spec: ``0.20``.
        shuffle_prob: Probability of applying the reorder (augmentation B).
        shuffle_window: Locality radius of the permutation. Each command may move
            at most ~``shuffle_window`` positions from its original index, modelling
            a *plausibly* reordered reconnection rather than a total scramble. Set
            to ``0`` for a full (unbounded) interior permutation.
        jitter_prob: Probability of applying timing jitter (augmentation C).
        jitter_frac: Multiplicative jitter on each inter-command interval; spec
            ``0.10`` => each ICI is scaled by a factor in ``[0.9, 1.1]``.
        timing_std: Standard deviation used by the tokenizer to z-score the timing
            channel. The jitter is defined as a *multiplicative* +-``jitter_frac``
            on the raw latency, which is an **additive** ``log(factor)`` offset in
            the log-ICI domain; dividing that offset by ``timing_std`` keeps the
            perturbation a true +-``jitter_frac`` on the latency even after
            standardization. Leave at ``1.0`` to operate directly in log-ICI units.
        min_length: Never reduce a view below this many positions, so even short
            sessions yield a usable sequence after dropout.
    """

    drop_prob: float = 0.9
    drop_frac: float = 0.20
    shuffle_prob: float = 0.9
    shuffle_window: int = 3
    jitter_prob: float = 0.9
    jitter_frac: float = 0.10
    timing_std: float = 1.0
    min_length: int = 2

    def __post_init__(self) -> None:
        if not 0.0 <= self.drop_frac < 1.0:
            raise ValueError("drop_frac must be in [0, 1)")
        if not 0.0 <= self.jitter_frac < 1.0:
            raise ValueError("jitter_frac must be in [0, 1)")
        if self.shuffle_window < 0:
            raise ValueError("shuffle_window must be >= 0 (0 == full shuffle)")
        if self.timing_std <= 0:
            raise ValueError("timing_std must be positive")


class ReIDAugmenter:
    """Produce an identity-preserving, surface-form-perturbed view of a session.

    Operates on the aligned ``(input_ids, timing)`` pair from
    ``CommandTokenizer.encode`` and returns a new aligned pair. The three
    augmentations are applied in the fixed order **drop -> shuffle -> jitter**,
    each gated by its configured probability. Order matters: dropping first means
    the shuffle and jitter act on the surviving commands (so the kept ICIs are the
    ones that actually get reordered/perturbed), matching how a real truncated-
    then-reordered reconnection would look.

    Args:
        protected_ids: Token ids that are structural anchors (``<pad>``/``<bos>``/
            ``<eos>``) -- exempt from drop, shuffle and jitter.
        config: Augmentation probabilities/strengths; defaults to the Phase-3 spec.
        rng: Optional :class:`random.Random` for reproducibility; a fresh one is
            created if omitted.
    """

    def __init__(
        self,
        protected_ids: set[int],
        config: ReIDAugmentConfig | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.protected_ids = set(protected_ids)
        self.config = config or ReIDAugmentConfig()
        self.rng = rng or random.Random()

    def __call__(
        self, input_ids: list[int], timing: list[float]
    ) -> tuple[list[int], list[float]]:
        """Return one augmented view of the ``(ids, timing)`` pair."""
        if len(input_ids) != len(timing):
            raise ValueError("input_ids and timing must be the same length")
        ids = list(input_ids)
        tim = list(timing)
        cfg = self.config

        if self.rng.random() < cfg.drop_prob:
            ids, tim = self._command_dropout(ids, tim)
        if self.rng.random() < cfg.shuffle_prob:
            ids, tim = self._reorder(ids, tim)
        if self.rng.random() < cfg.jitter_prob:
            tim = self._timing_jitter(ids, tim)

        return ids, tim

    # -- Augmentation A: command dropout -----------------------------------

    def _command_dropout(
        self, ids: list[int], tim: list[float]
    ) -> tuple[list[int], list[float]]:
        """Delete a random ~``drop_frac`` subset of non-anchor commands.

        Anchors (bos/eos/pad) are always kept. We stop dropping once the view
        would fall below ``min_length`` so the contrastive encoder always sees a
        usable sequence even for short sessions.
        """
        n = len(ids)
        out_ids: list[int] = []
        out_tim: list[float] = []
        kept_droppable = sum(1 for i in range(n) if ids[i] not in self.protected_ids)
        for i in range(n):
            anchor = ids[i] in self.protected_ids
            room = (len(out_ids) + (n - i)) > self.config.min_length
            drop = (
                not anchor
                and kept_droppable > 1
                and room
                and self.rng.random() < self.config.drop_frac
            )
            if drop:
                kept_droppable -= 1
                continue
            out_ids.append(ids[i])
            out_tim.append(tim[i])
        if len(out_ids) < self.config.min_length:
            return ids, tim
        return out_ids, out_tim

    # -- Augmentation B: non-sequential reorder ----------------------------

    def _reorder(
        self, ids: list[int], tim: list[float]
    ) -> tuple[list[int], list[float]]:
        """Locally permute the order of non-anchor commands.

        The ``(id, timing)`` pair of each command moves **together**, so each
        command keeps its own pre-gap (its think-time travels with it) -- the
        cadence multiset is preserved, only the sequence is scrambled. Anchors stay
        pinned at their original indices. With ``shuffle_window > 0`` the
        permutation is *bounded*: a command moves at most ~``shuffle_window``
        positions, modelling a plausibly reordered reconnection rather than a total
        scramble. ``shuffle_window == 0`` gives a full interior permutation.
        """
        positions = [i for i in range(len(ids)) if ids[i] not in self.protected_ids]
        if len(positions) < 2:
            return ids, tim

        pairs = [(ids[i], tim[i]) for i in positions]
        window = self.config.shuffle_window
        if window <= 0:
            order = list(range(len(pairs)))
            self.rng.shuffle(order)
        else:
            # Bounded permutation: perturb each index by uniform noise of width
            # +-window and re-sort. argsort of (index + noise) yields a permutation
            # in which no element strays much further than `window` slots.
            keyed = [
                (rank + self.rng.uniform(-window, window), rank)
                for rank in range(len(pairs))
            ]
            keyed.sort()
            order = [rank for _, rank in keyed]

        out_ids = list(ids)
        out_tim = list(tim)
        for slot, src in zip(positions, order):
            out_ids[slot], out_tim[slot] = pairs[src]
        return out_ids, out_tim

    # -- Augmentation C: timing jitter -------------------------------------

    def _timing_jitter(self, ids: list[int], tim: list[float]) -> list[float]:
        """Scale each non-anchor inter-command interval by a factor in
        ``[1 - jitter_frac, 1 + jitter_frac]``.

        The timing channel lives in the log-ICI domain, so a multiplicative factor
        ``f`` on the raw latency is an **additive** ``log(f)`` offset here; we
        divide by ``timing_std`` so the perturbation stays a true +-``jitter_frac``
        on the latency even when the channel has been standardized (see
        :class:`ReIDAugmentConfig.timing_std`).
        """
        frac = self.config.jitter_frac
        std = self.config.timing_std
        out = list(tim)
        for i in range(len(out)):
            if ids[i] in self.protected_ids:
                continue
            factor = 1.0 + self.rng.uniform(-frac, frac)
            out[i] = out[i] + math.log(factor) / std
        return out
