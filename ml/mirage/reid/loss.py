r"""The contrastive objective for re-identification: NT-Xent / InfoNCE.

We reuse Phase-2's :class:`~mirage.training.objective.NTXentLoss` unchanged -- it
is already the symmetric, L2-normalised, temperature-scaled cross-entropy we want
-- and fix the temperature to the Phase-3 spec value ``tau = 0.07`` (the SimCLR /
MoCo default; a low temperature emphasises hard negatives, which is what forces
*within-toolkit individual* separation rather than mere toolkit clustering).

The math (InfoNCE objective)
----------------------------
A batch of ``N`` sessions is encoded under two augmentations into ``2N``
projection vectors. L2-normalise each, ``z_i = g(f(x_i)) / ||.||``, so the dot
product ``z_i . z_j`` is a cosine similarity in ``[-1, 1]``. For an anchor ``i``
whose positive (the other view of the same session) is ``j(i)``, the per-anchor
loss is the cross-entropy of "pick the positive out of all other samples":

.. math::

    \ell_i = -\log
        \frac{\exp(\mathrm{sim}(z_i, z_{j(i)}) / \tau)}
             {\sum_{k=1}^{2N} \mathbf{1}_{[k \neq i]}\,
              \exp(\mathrm{sim}(z_i, z_k) / \tau)}

and the batch loss is the mean ``(1/2N) \sum_i \ell_i``. The denominator runs
over **all** other ``2N - 1`` samples (the positive plus the ``2N - 2``
in-batch negatives): every other session in the batch is treated as a negative,
so no negative sampling or memory bank is needed.

Why this *is* InfoNCE (and why a BCI person will recognise it). Writing the
numerator term as the positive and the denominator as positive-plus-negatives,
``\ell_i`` is exactly the InfoNCE bound of van den Oord et al. (2018): minimising
it maximises a lower bound on the mutual information ``I(z_i; z_{j(i)})`` between
the two views, i.e. it keeps **only the information shared across the nuisance
transformation** (drop / reorder / jitter) and discards the rest. That shared,
transformation-invariant content is precisely the attacker's identity -- the same
reason a contrastive objective over two views of a neural trial isolates the
latent that is stable across the trial-to-trial nuisance variables (CEBRA's
operating principle). Lowering ``\tau`` sharpens the softmax, up-weighting the
hardest negatives (the most similar *other* identities), which is what drives
fine-grained re-identification.

``alignment_loss`` (positive pairs should be close) and ``uniformity_loss``
(embeddings should spread over the sphere) from Wang & Isola (2020) are re-
exported as collapse diagnostics for the training logs.
"""

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
