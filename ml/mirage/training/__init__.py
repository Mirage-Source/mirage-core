"""Phase-2 training pipeline: CEBRA-style contrastive session embeddings.

Cowrie corpora carry no ground-truth tool labels, so we learn the embedding
**self-supervised**. Each session is augmented into two correlated *views*; the
objective (NT-Xent / InfoNCE) pulls a session's two views together and pushes
different sessions apart. Because sessions from the same tool share a command
*skeleton* and a timing *cadence*, their views survive augmentation as near
neighbours -- which is exactly what makes same-tool sessions cluster in the
learned space (the Phase-2 hypothesis).

Modules:
    dataset    SessionDataset + contrastive two-view collation (uses Phase-1
               tokenizer / loader).
    augment    Channel-aware session augmentations (dropout, span-mask, timing
               jitter, temporal crop).
    objective  NTXentLoss + alignment/uniformity diagnostics (torch-only).
    schedule   Cosine-with-warmup learning-rate schedule (torch-only).
    train      End-to-end training loop with gradient checkpointing and
               wandb-or-CSV logging.
"""

from __future__ import annotations

from .objective import NTXentLoss, alignment_loss, uniformity_loss
from .schedule import cosine_warmup_schedule

__all__ = [
    "NTXentLoss",
    "alignment_loss",
    "uniformity_loss",
    "cosine_warmup_schedule",
]
