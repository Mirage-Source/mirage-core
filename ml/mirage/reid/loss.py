from __future__ import annotations

from ..training.objective import NTXentLoss, alignment_loss, uniformity_loss

__all__ = ["NTXentLoss", "alignment_loss", "uniformity_loss", "reid_ntxent_loss"]

#: Phase-3 contrastive temperature (SimCLR/MoCo default; spec value).
REID_TEMPERATURE: float = 0.07


def reid_ntxent_loss(temperature: float = REID_TEMPERATURE) -> NTXentLoss:
    """Construct the re-ID NT-Xent criterion at the spec temperature ``tau=0.07``.

    Args:
        temperature: Softmax temperature; defaults to :data:`REID_TEMPERATURE`.

    Returns:
        A configured :class:`~mirage.training.objective.NTXentLoss`.
    """
    return NTXentLoss(temperature=temperature)
