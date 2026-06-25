"""Phase 3 -- contrastive attacker re-identification.

This subpackage learns to recognise the **same attacker across sessions** -- the
publishable novelty of MIRAGE. It is mathematically the same problem as
**cross-session neural re-identification** in a BCI: an identity (a neuron / an
attacker) must be recovered across trials (recording sessions / reconnections)
despite **behavioural drift, partial observation, and adversarial noise**. We
solve it with SimCLR-style metric learning -- the same contrastive machinery used
for behaviour-aware neural embeddings (CEBRA) -- and then *stress-test* it with an
adversary who actively tries to evade re-identification, which (to our knowledge)
is new to honeypot ML.

Pipeline
--------
* :mod:`~mirage.reid.augment` -- identity-preserving augmentations (command drop,
  non-sequential reorder, timing jitter): the nuisance transforms re-ID must be
  invariant to.
* :mod:`~mirage.reid.data` / :mod:`~mirage.reid.dataset` -- identity-labelled
  corpora (multiple sessions per attacker) and two-view contrastive collation.
* :mod:`~mirage.reid.model` -- :class:`ContrastiveReIDModel` = Phase-2 backbone +
  64-d projection head.
* :mod:`~mirage.reid.loss` -- NT-Xent / InfoNCE at ``tau=0.07``.
* :mod:`~mirage.reid.train` -- self-supervised training + augmentation ablation.
* :mod:`~mirage.reid.evaluate` -- recall@k, mAP, t-SNE before/after.
* :mod:`~mirage.reid.adversarial` -- the learned evasion attacker + robustness eval.
* :mod:`~mirage.reid.fingerprint` -- positional mutual information, timing-vs-
  content ablation, toolkit fingerprinting.
"""

from __future__ import annotations

from .augment import ReIDAugmentConfig, ReIDAugmenter
from .data import (
    IdentityCorpus,
    IdentityProfile,
    make_identity_corpus,
    reconnection_split,
)
from .dataset import ReIDCollator, ReIDDataset, ReIDEvalCollator, ReIDExample
from .loss import REID_TEMPERATURE, NTXentLoss, reid_ntxent_loss
from .model import (
    ContrastiveReIDModel,
    ProjectionHead,
    ReIDModelConfig,
    ReIDModelOutput,
)

__all__ = [
    # augment
    "ReIDAugmentConfig",
    "ReIDAugmenter",
    # data
    "IdentityCorpus",
    "IdentityProfile",
    "make_identity_corpus",
    "reconnection_split",
    # dataset
    "ReIDDataset",
    "ReIDExample",
    "ReIDCollator",
    "ReIDEvalCollator",
    # model
    "ContrastiveReIDModel",
    "ReIDModelConfig",
    "ReIDModelOutput",
    "ProjectionHead",
    # loss
    "NTXentLoss",
    "reid_ntxent_loss",
    "REID_TEMPERATURE",
]
