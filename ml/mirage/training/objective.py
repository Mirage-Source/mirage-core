
from __future__ import annotations

from typing import Hashable, Sequence

import torch
import torch.nn as nn
import torch.nn.functional as F

__all__ = ["NTXentLoss", "SupConLoss", "alignment_loss", "uniformity_loss"]


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


class SupConLoss(nn.Module):
    """Supervised contrastive loss (Khosla et al., 2020, NeurIPS).

    Generalizes :class:`NTXentLoss` from exactly-one-positive-per-anchor (two
    augmented views of the same example) to an arbitrary number of positives per
    anchor, identified by a caller-supplied label. This is what real, multi-
    session ground-truth identities need: unlike synthetic-corpus training,
    where every batch row is a distinct example, a batch of real sessions can
    contain several rows that are *known* (not augmented) positives of each
    other -- e.g. three sessions from the same source address.

    Args:
        temperature: Softmax temperature ``tau`` (SupCon default 0.07).
        ignore_label: A label value that is never used as an anchor -- no loss
            term is computed for rows carrying it, though such rows still act as
            ordinary negatives for every other anchor's denominator. Use this for
            a "no verified group" placeholder label (e.g. ``"unknown"``): treating
            every such row as if it shares one real group would assert an
            identity claim with no supporting evidence, exactly the failure mode
            this project's audit discipline exists to catch.
    """

    def __init__(
        self, temperature: float = 0.07, ignore_label: Hashable | None = None
    ) -> None:
        super().__init__()
        if temperature <= 0:
            raise ValueError("temperature must be positive")
        self.temperature = temperature
        self.ignore_label = ignore_label

    def forward(self, z: torch.Tensor, labels: Sequence[Hashable]) -> torch.Tensor:
        """Compute the mean SupCon loss over every eligible anchor in ``z``.

        Args:
            z: ``[N, D]`` embeddings, one row per example (any number of rows may
                share a label; rows need not be pre-paired into views).
            labels: Length-``N`` sequence of hashable group labels, row-aligned
                to ``z``.

        Returns:
            Scalar loss tensor, averaged over anchors that have both at least one
            same-label positive elsewhere in the batch and a label other than
            :attr:`ignore_label`. ``0.0`` (no grad) if no anchor qualifies -- a
            degenerate batch contributes nothing rather than raising, since which
            batches qualify depends on random sampling.
        """
        n = z.size(0)
        if len(labels) != n:
            raise ValueError(f"labels length ({len(labels)}) must match z rows ({n})")
        device = z.device

        z = F.normalize(z, dim=1)
        sim = (z @ z.t()) / self.temperature  # [N, N]
        self_mask = torch.eye(n, dtype=torch.bool, device=device)
        sim = sim.masked_fill(self_mask, float("-inf"))
        log_prob = sim - torch.logsumexp(sim, dim=1, keepdim=True)  # [N, N]

        label_list = list(labels)
        same_label = torch.zeros((n, n), dtype=torch.bool, device=device)
        for i in range(n):
            for j in range(n):
                if i != j and label_list[i] == label_list[j]:
                    same_label[i, j] = True

        n_positives = same_label.sum(dim=1)  # [N]
        is_anchor = n_positives > 0
        if self.ignore_label is not None:
            not_ignored = torch.tensor(
                [lab != self.ignore_label for lab in label_list], device=device
            )
            is_anchor = is_anchor & not_ignored

        if not bool(is_anchor.any()):
            return z.sum() * 0.0  # zero, but keeps autograd graph well-defined

        # torch.where, not same_label * log_prob: log_prob's masked diagonal is
        # -inf, and multiplying that by the boolean-derived 0 at non-positive
        # positions computes 0 * -inf = nan (IEEE 754), silently poisoning
        # every anchor's sum regardless of its own positives. `where` selects
        # the value outright instead of multiplying, so no such nan appears.
        zero = log_prob.new_zeros(())
        per_anchor_mean_log_prob = torch.where(same_label, log_prob, zero).sum(dim=1) / n_positives.clamp(min=1)
        return -per_anchor_mean_log_prob[is_anchor].mean()


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
