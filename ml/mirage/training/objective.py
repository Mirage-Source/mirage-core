"""Contrastive objective for session embeddings (torch-only).

We use **NT-Xent** (the normalized temperature-scaled cross-entropy of SimCLR),
which is InfoNCE over L2-normalized embeddings. This is the same family of
contrastive loss CEBRA uses to align neural and behavioral views; here the two
"views" are two augmentations of the same attacker session.

Given a batch of ``N`` sessions, each encoded under two augmentations, we have
``2N`` embeddings. For each anchor, its positive is the *other* view of the same
session and the negatives are the remaining ``2N - 2`` embeddings. Minimizing the
loss maximizes the cosine similarity of the positive pair relative to all
negatives -- pulling same-session (and, transitively, same-tool) sessions
together while spreading the rest over the hypersphere.

We also expose the **alignment** and **uniformity** metrics of Wang & Isola
(2020) as diagnostics: alignment measures how close positive pairs are;
uniformity measures how evenly embeddings cover the sphere. Logging both
explains *why* a run's clustering improves or collapses, which is useful for the
paper's analysis.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

__all__ = ["NTXentLoss", "alignment_loss", "uniformity_loss"]


class NTXentLoss(nn.Module):
    """Normalized temperature-scaled cross-entropy (SimCLR / InfoNCE) loss.

    Args:
        temperature: Softmax temperature ``tau``. Lower values sharpen the
            contrast (harder negatives) but can destabilize early training;
            0.1-0.5 is the usual range. Default 0.2.

    Shapes:
        Both inputs are ``[N, D]`` -- the embeddings of view 1 and view 2 for the
        same ``N`` sessions, row-aligned (row ``i`` of each is one session).
    """

    def __init__(self, temperature: float = 0.2) -> None:
        super().__init__()
        if temperature <= 0:
            raise ValueError("temperature must be positive")
        self.temperature = temperature

    def forward(self, z1: torch.Tensor, z2: torch.Tensor) -> torch.Tensor:
        """Compute the symmetric NT-Xent loss over a two-view batch.

        Args:
            z1: ``[N, D]`` embeddings of the first view.
            z2: ``[N, D]`` embeddings of the second view (row-aligned to ``z1``).

        Returns:
            Scalar loss tensor.
        """
        if z1.shape != z2.shape:
            raise ValueError(f"view shapes must match; got {z1.shape} vs {z2.shape}")
        n = z1.size(0)
        device = z1.device

        z = torch.cat([z1, z2], dim=0)  # [2N, D]
        z = F.normalize(z, dim=1)

        # Cosine-similarity logits, scaled by temperature.
        sim = (z @ z.t()) / self.temperature  # [2N, 2N]
        # Mask self-similarity so an anchor never matches itself.
        self_mask = torch.eye(2 * n, dtype=torch.bool, device=device)
        sim = sim.masked_fill(self_mask, float("-inf"))

        # Positive index for anchor i is its partner view: i <-> i+n (mod 2N).
        targets = torch.cat(
            [torch.arange(n, 2 * n, device=device), torch.arange(0, n, device=device)]
        )
        return F.cross_entropy(sim, targets)


@torch.no_grad()
def alignment_loss(z1: torch.Tensor, z2: torch.Tensor, alpha: float = 2.0) -> float:
    """Alignment metric (Wang & Isola, 2020): mean positive-pair distance.

    Lower is better -- positive pairs (two views of one session) sit close on the
    unit sphere. Diagnostic only; not optimized directly.
    """
    z1 = F.normalize(z1, dim=1)
    z2 = F.normalize(z2, dim=1)
    return float((z1 - z2).norm(dim=1).pow(alpha).mean().item())


@torch.no_grad()
def uniformity_loss(z: torch.Tensor, t: float = 2.0) -> float:
    """Uniformity metric (Wang & Isola, 2020): log mean Gaussian potential.

    Lower (more negative) means embeddings spread more evenly over the sphere --
    a guard against representational collapse. Diagnostic only.
    """
    z = F.normalize(z, dim=1)
    sq_pdist = torch.pdist(z, p=2).pow(2)
    return float(sq_pdist.mul(-t).exp().mean().log().item())
