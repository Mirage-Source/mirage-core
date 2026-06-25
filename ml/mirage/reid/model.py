"""Contrastive re-identification model: Phase-2 backbone + projection head.

This is the Phase-3 network. It follows the SimCLR decomposition exactly:

    x --(backbone f)--> h (128-d behavioural embedding)
                          \
                           --(projection g)--> z (64-d, unit-normalised)

* the **backbone** ``f`` is the Phase-2
  :class:`~mirage.models.embedding.SessionEmbedder` -- reused verbatim, optionally
  warm-started from a Phase-2 checkpoint -- producing the 128-d session embedding
  ``h``;
* the **projection head** ``g`` is a 2-layer MLP mapping ``h`` to a 64-d unit
  vector ``z``.

The contrastive NT-Xent loss is computed on ``z`` (the *metric* space, where the
objective shapes cosine geometry), while ``h`` is retained as the general-purpose
*representation*. Chen et al. (2020) showed this split matters: ``g`` is trained
to be invariant to the augmentation and therefore *discards* nuisance-correlated
information that downstream tasks may still want, so the representation ``h`` is
kept for transfer (here: linear toolkit probing, trajectory analysis), while
retrieval/re-ID uses ``z``.

Neuroscience framing. ``h`` is the analogue of a neuron's **latent embedding**
from population activity; ``z`` is the **identity-discriminative metric** learned
on top of it. Re-identifying an attacker across reconnections is computing nearest
neighbours in ``z`` -- mathematically identical to re-identifying a neuron across
recording sessions by matching its embedding under a learned metric that is
invariant to the cross-session nuisance transform.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import torch
import torch.nn as nn
import torch.nn.functional as F

from ..models.embedding import SessionEmbedder, SessionEmbedderConfig

__all__ = [
    "ProjectionHead",
    "ReIDModelConfig",
    "ReIDModelOutput",
    "ContrastiveReIDModel",
]

#: Which space to expose for retrieval. ``"projection"`` (the trained metric) is
#: the default for recall@k; ``"backbone"`` (the representation) is available for
#: transfer/probing.
ReIDSpace = Literal["projection", "backbone"]


class ProjectionHead(nn.Module):
    """2-layer MLP projection head ``g`` mapping the embedding to a unit metric.

    ``z = normalize( W2 . ReLU( BN( W1 . h ) ) )``. BatchNorm on the hidden layer
    follows SimCLR and stabilises the contrastive geometry; it uses running
    statistics at eval time, so single-example inference (e.g. inside the
    adversarial attack) is well-defined. The output is L2-normalised so it lands on
    the unit hypersphere where NT-Xent's cosine similarities live.

    Args:
        in_dim: Embedding width ``h`` (backbone ``embedding_dim``; spec 128).
        hidden_dim: Hidden width of the MLP.
        out_dim: Projection width ``z`` (spec 64).
        use_bn: Apply BatchNorm to the hidden activations (SimCLR default).
    """

    def __init__(
        self,
        in_dim: int = 128,
        hidden_dim: int = 128,
        out_dim: int = 64,
        use_bn: bool = True,
    ) -> None:
        super().__init__()
        self.fc1 = nn.Linear(in_dim, hidden_dim)
        self.bn = nn.BatchNorm1d(hidden_dim) if use_bn else nn.Identity()
        self.act = nn.ReLU(inplace=True)
        self.fc2 = nn.Linear(hidden_dim, out_dim)
        self.out_dim = out_dim

    def forward(self, h: torch.Tensor) -> torch.Tensor:
        """Project ``[B, in_dim]`` embeddings to ``[B, out_dim]`` unit vectors."""
        z = self.fc2(self.act(self.bn(self.fc1(h))))
        return F.normalize(z, dim=-1)


@dataclass
class ReIDModelConfig:
    """Configuration for :class:`ContrastiveReIDModel`.

    Attributes:
        backbone: The Phase-2 :class:`SessionEmbedderConfig` for ``f``.
        projection_hidden_dim: Hidden width of the projection MLP ``g``.
        projection_dim: Output width of ``g`` (the metric dimensionality; spec 64).
        projection_use_bn: Whether ``g`` uses BatchNorm (SimCLR default).
    """

    backbone: SessionEmbedderConfig
    projection_hidden_dim: int = 128
    projection_dim: int = 64
    projection_use_bn: bool = True


@dataclass
class ReIDModelOutput:
    """Outputs of a :class:`ContrastiveReIDModel` forward pass.

    Attributes:
        embedding: ``[B, 128]`` backbone embedding ``h`` (the representation).
        projection: ``[B, 64]`` unit-normalised metric vector ``z`` (for NT-Xent
            and for retrieval).
        hidden_states: ``[B, L, d_model]`` per-position states (for trajectory /
            adversarial use).
        attention_mask: ``[B, L]`` passthrough mask.
    """

    embedding: torch.Tensor
    projection: torch.Tensor
    hidden_states: torch.Tensor
    attention_mask: torch.Tensor


class ContrastiveReIDModel(nn.Module):
    """SimCLR-style re-identification model (backbone ``f`` + projection ``g``).

    Args:
        config: A :class:`ReIDModelConfig`.
    """

    def __init__(self, config: ReIDModelConfig) -> None:
        super().__init__()
        self.config = config
        self.backbone = SessionEmbedder(config.backbone)
        self.projection_head = ProjectionHead(
            in_dim=config.backbone.embedding_dim,
            hidden_dim=config.projection_hidden_dim,
            out_dim=config.projection_dim,
            use_bn=config.projection_use_bn,
        )

    # -- Forward ------------------------------------------------------------

    def forward(
        self,
        input_ids: torch.Tensor,
        timing: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> ReIDModelOutput:
        """Encode a batch and return both ``h`` (embedding) and ``z`` (projection)."""
        out = self.backbone(input_ids, timing, attention_mask)
        z = self.projection_head(out.pooled)
        return ReIDModelOutput(
            embedding=out.pooled,
            projection=z,
            hidden_states=out.hidden_states,
            attention_mask=out.attention_mask,
        )

    def project(
        self,
        input_ids: torch.Tensor,
        timing: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """Return only the 64-d unit projection ``z`` (the contrastive metric)."""
        return self.forward(input_ids, timing, attention_mask).projection

    @torch.no_grad()
    def embed(
        self,
        input_ids: torch.Tensor,
        timing: torch.Tensor,
        attention_mask: torch.Tensor,
        space: ReIDSpace = "projection",
    ) -> torch.Tensor:
        """Encode sessions for retrieval (eval mode, no grad).

        Args:
            space: ``"projection"`` returns the 64-d metric ``z`` (default, used
                for recall@k); ``"backbone"`` returns the 128-d representation ``h``.
        """
        was_training = self.training
        self.eval()
        try:
            out = self.forward(input_ids, timing, attention_mask)
        finally:
            self.train(was_training)
        return out.projection if space == "projection" else out.embedding

    # -- Backbone warm-start / freezing ------------------------------------

    def load_backbone_state_dict(
        self, state_dict: dict[str, torch.Tensor], strict: bool = True
    ) -> None:
        """Load Phase-2 backbone weights (the ``state_dict`` saved by Phase-2 train)."""
        self.backbone.load_state_dict(state_dict, strict=strict)

    @classmethod
    def from_backbone_checkpoint(
        cls,
        checkpoint_path: str | Path,
        projection_hidden_dim: int = 128,
        projection_dim: int = 64,
        projection_use_bn: bool = True,
        map_location: str | torch.device = "cpu",
    ) -> "ContrastiveReIDModel":
        """Build a re-ID model around a pretrained Phase-2 backbone.

        Rebuilds the backbone architecture from the checkpoint's stored config,
        loads its weights, and attaches a **fresh** (randomly initialised)
        projection head to be trained in Phase 3.

        Args:
            checkpoint_path: Path to a Phase-2 checkpoint
                (``{"state_dict": ..., "config": asdict(SessionEmbedderConfig)}``,
                as written by ``mirage.training.train._save_checkpoint``).
            projection_hidden_dim: Hidden width of the new projection head.
            projection_dim: Output width of the new projection head.
            projection_use_bn: BatchNorm in the projection head.
            map_location: Device for ``torch.load``.

        Returns:
            A :class:`ContrastiveReIDModel` with a warm-started backbone.
        """
        ckpt = torch.load(checkpoint_path, map_location=map_location)
        backbone_cfg = SessionEmbedderConfig(**ckpt["config"])
        model = cls(
            ReIDModelConfig(
                backbone=backbone_cfg,
                projection_hidden_dim=projection_hidden_dim,
                projection_dim=projection_dim,
                projection_use_bn=projection_use_bn,
            )
        )
        model.load_backbone_state_dict(ckpt["state_dict"], strict=True)
        return model

    def freeze_backbone(self) -> None:
        """Freeze the backbone (train only the projection head -- a linear-probe
        style Phase-3 that isolates the head's contribution)."""
        for param in self.backbone.parameters():
            param.requires_grad_(False)

    def unfreeze_backbone(self) -> None:
        """Unfreeze the backbone (full end-to-end fine-tuning)."""
        for param in self.backbone.parameters():
            param.requires_grad_(True)

    def num_parameters(self, trainable_only: bool = True) -> int:
        """Count parameters (for the paper's model card)."""
        params = self.parameters()
        if trainable_only:
            return sum(p.numel() for p in params if p.requires_grad)
        return sum(p.numel() for p in params)
