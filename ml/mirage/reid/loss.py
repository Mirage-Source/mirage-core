from __future__ import annotations

from typing import Hashable, Sequence

import torch
import torch.nn as nn

from ..training.objective import NTXentLoss, SupConLoss, alignment_loss, uniformity_loss

__all__ = [
    "NTXentLoss",
    "SupConLoss",
    "alignment_loss",
    "uniformity_loss",
    "reid_ntxent_loss",
    "CampaignAwareReIDLoss",
    "campaign_aware_reid_loss",
    "UNKNOWN_TOOLKIT",
]

#: Phase-3 contrastive temperature (SimCLR/MoCo default; spec value).
REID_TEMPERATURE: float = 0.07

#: Placeholder toolkit label for a session with no verified shared-tooling
#: group (i.e. everything outside a confirmed campaign, see
#: ``mirage.reid.campaign``). Never treated as a real group by
#: :class:`CampaignAwareReIDLoss` -- see its docstring.
UNKNOWN_TOOLKIT: str = "unknown"


def reid_ntxent_loss(temperature: float = REID_TEMPERATURE) -> NTXentLoss:
    """Construct the re-ID NT-Xent criterion at the spec temperature ``tau=0.07``.

    Args:
        temperature: Softmax temperature; defaults to :data:`REID_TEMPERATURE`.

    Returns:
        A configured :class:`~mirage.training.objective.NTXentLoss`.
    """
    return NTXentLoss(temperature=temperature)


class CampaignAwareReIDLoss(nn.Module):
    """Two-granularity SupCon over real sessions: identity (fine) + toolkit (coarse).

    Real source-address identity is verified ground truth for every session
    (row-level fact, not an inference); campaign-tier toolkit membership is
    verified ground truth *only* for confirmed campaign addresses
    (:mod:`mirage.reid.campaign`) and is a placeholder (:data:`UNKNOWN_TOOLKIT`)
    everywhere else. The two terms are therefore weighted asymmetrically: the
    identity term pulls same-address sessions together at full strength (that's
    a proven fact), the toolkit term pulls same-campaign-tier sessions together
    at a *fraction* of that strength (that's a proven-shared-tooling fact, not a
    proven-shared-identity one -- see the preprint's Section VI-A "What we do
    not claim"), and :data:`UNKNOWN_TOOLKIT` rows never anchor the toolkit term
    at all, so "we don't know this session's toolkit" is never conflated with
    "this session shares a toolkit with every other unlabeled session."

    Args:
        identity_temperature: SupCon temperature for the identity term.
        toolkit_temperature: SupCon temperature for the toolkit term.
        coarse_weight: Multiplier on the toolkit term relative to the identity
            term; must be in ``[0, 1]`` since the coarse signal is weaker
            evidence than the fine one by construction.
        unknown_toolkit: The placeholder label excluded from the toolkit term's
            anchor set.
    """

    def __init__(
        self,
        identity_temperature: float = REID_TEMPERATURE,
        toolkit_temperature: float = REID_TEMPERATURE,
        coarse_weight: float = 0.3,
        unknown_toolkit: Hashable = UNKNOWN_TOOLKIT,
    ) -> None:
        super().__init__()
        if not 0.0 <= coarse_weight <= 1.0:
            raise ValueError("coarse_weight must be in [0, 1]")
        self.identity_criterion = SupConLoss(temperature=identity_temperature)
        self.toolkit_criterion = SupConLoss(
            temperature=toolkit_temperature, ignore_label=unknown_toolkit
        )
        self.coarse_weight = coarse_weight

    def forward(
        self,
        z: torch.Tensor,
        identity_labels: Sequence[Hashable],
        toolkit_labels: Sequence[Hashable],
    ) -> torch.Tensor:
        """Combine the identity and toolkit SupCon terms for one batch of embeddings."""
        fine = self.identity_criterion(z, identity_labels)
        coarse = self.toolkit_criterion(z, toolkit_labels)
        return fine + self.coarse_weight * coarse


def campaign_aware_reid_loss(
    coarse_weight: float = 0.3,
    identity_temperature: float = REID_TEMPERATURE,
    toolkit_temperature: float = REID_TEMPERATURE,
) -> CampaignAwareReIDLoss:
    """Construct the real-data re-ID criterion at the spec defaults."""
    return CampaignAwareReIDLoss(
        identity_temperature=identity_temperature,
        toolkit_temperature=toolkit_temperature,
        coarse_weight=coarse_weight,
    )
