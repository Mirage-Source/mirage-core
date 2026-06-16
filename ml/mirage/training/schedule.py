"""Learning-rate schedule: cosine decay with linear warmup (torch-only).

A short linear warmup stabilizes the Transformer's early steps (the attention
softmax and LayerNorm statistics are volatile before the embeddings organize),
after which a cosine decay anneals the rate smoothly to a small floor. This is
the standard schedule for contrastive Transformer pretraining and is exposed as a
plain :class:`~torch.optim.lr_scheduler.LambdaLR` factory so it composes with any
optimizer.
"""

from __future__ import annotations

import math

from torch.optim import Optimizer
from torch.optim.lr_scheduler import LambdaLR

__all__ = ["cosine_warmup_schedule"]


def cosine_warmup_schedule(
    optimizer: Optimizer,
    warmup_steps: int,
    total_steps: int,
    min_lr_ratio: float = 0.01,
    last_epoch: int = -1,
) -> LambdaLR:
    """Build a cosine-decay-with-linear-warmup LR scheduler.

    The returned scheduler should be ``.step()``-ed **once per optimizer step**
    (not per epoch). The multiplier rises linearly from ~0 to 1 over
    ``warmup_steps``, then follows a half-cosine from 1 down to ``min_lr_ratio``
    by ``total_steps``, and holds the floor thereafter.

    Args:
        optimizer: The optimizer whose base LR(s) are scaled by this multiplier.
        warmup_steps: Number of warmup steps (linear ramp). ``0`` disables warmup.
        total_steps: Total planned optimizer steps (warmup + decay).
        min_lr_ratio: Final LR as a fraction of the base LR (the cosine floor).
        last_epoch: Passed through to :class:`LambdaLR` for resuming.

    Returns:
        A :class:`~torch.optim.lr_scheduler.LambdaLR`.
    """
    if total_steps <= 0:
        raise ValueError("total_steps must be positive")
    if warmup_steps < 0 or warmup_steps > total_steps:
        raise ValueError("require 0 <= warmup_steps <= total_steps")

    def lr_lambda(step: int) -> float:
        if warmup_steps > 0 and step < warmup_steps:
            # Linear ramp; +1 so step 0 is a small non-zero LR rather than exactly 0.
            return (step + 1) / (warmup_steps + 1)
        progress = (step - warmup_steps) / max(1, total_steps - warmup_steps)
        progress = min(1.0, max(0.0, progress))
        cosine = 0.5 * (1.0 + math.cos(math.pi * progress))
        return min_lr_ratio + (1.0 - min_lr_ratio) * cosine

    return LambdaLR(optimizer, lr_lambda, last_epoch=last_epoch)
