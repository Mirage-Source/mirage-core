r"""Adversarial robustness of re-identification (novel sub-contribution).

The threat model is an **evasive attacker**: one who knows they are being re-
identified across sessions and deliberately perturbs their behaviour to *break the
match* -- the behavioural-biometrics analogue of an adversarial example. To our
knowledge no prior honeypot-ML work measures this, so the question this module
answers is publishable on its own: *how much must an attacker change their session
to escape re-identification, and how much does that degrade recall@k?*

Formalisation
-------------
Re-ID lives in the projection space ``z``; each identity has a centroid
``c = mean of its clean z`` (unit-normalised). An evasive probe wants its
embedding pushed **away from its own centroid** while changing as little
behaviour as possible. We attack in the backbone's **input token-embedding
space**: for a session with token embeddings ``E``, the adversary adds a
perturbation ``delta`` to obtain ``E + delta`` and hence an adversarial embedding
``z_adv = g(f(E + delta))``. The perturbation is constrained to an L2 ball of
radius ``epsilon`` per command (a *behavioural budget*: the attacker can only
nudge each command so far before it stops doing its job). The objective is

    minimise   cos(z_adv, c)        +  lambda * ||delta||^2
               \_____________/         \_____________/
               evade own identity      stealth / minimal edit

Minimising the cosine to the own-centroid maximises embedding-space distance from
the attacker's own cluster -- exactly "an attacker trying to evade re-ID."

Two attackers are provided:

* :class:`AdversarialSessionGenerator` -- a *learned* amortised attacker (a small
  network trained once to perturb any session). This is the headline: it models a
  capable adversary who has *learned* a general evasion policy.
* :func:`pgd_attack` -- a per-session projected-gradient-descent baseline (the
  standard white-box attack), for comparison and as an upper bound on per-session
  evasion at a given budget.

:func:`decode_to_commands` projects a perturbed embedding back to the nearest
vocabulary tokens, turning the continuous attack into an interpretable command
sequence -- "what would the attacker actually type to evade?" -- which is what
makes this a behavioural, not merely numerical, result.

Why operate in embedding space rather than emit discrete tokens directly: it
keeps the attack differentiable end-to-end through the frozen re-ID model (so the
learned attacker is trainable and the PGD baseline is exact), while
:func:`decode_to_commands` recovers the discrete view for analysis. This mirrors
adversarial-example practice in vision, transposed to a discrete behavioural
sequence via its embedding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Subset

from ..tokenizer.tokenizer import CommandTokenizer
from ..training.dataset import BatchView
from .dataset import ReIDDataset, ReIDEvalCollator
from .evaluate import EmbeddingBank, embed_dataset, recall_at_k
from .model import ContrastiveReIDModel

__all__ = [
    "AdversarialConfig",
    "AdversarialSessionGenerator",
    "identity_centroids",
    "train_adversary",
    "attack_dataset",
    "pgd_attack",
    "decode_to_commands",
    "evaluate_adversarial_robustness",
]


@dataclass
class AdversarialConfig:
    """Hyperparameters for the learned adversarial attacker.

    Attributes:
        epsilon: L2 radius of the per-command perturbation ball, in raw token-
            embedding units (a typical token vector has norm ~1, so ``epsilon`` is
            roughly the fraction of a command's embedding the attacker may move).
        hidden_dim: Hidden width of the generator MLP.
        budget_lambda: Weight of the stealth penalty ``||delta||^2`` (encourages
            sub-budget, minimal edits).
        lr: Adam learning rate for the generator.
        epochs: Training epochs over the attack set.
        batch_size: Attack-training batch size.
        seed: RNG seed.
    """

    epsilon: float = 0.5
    hidden_dim: int = 128
    budget_lambda: float = 0.05
    lr: float = 1e-3
    epochs: int = 10
    batch_size: int = 64
    seed: int = 0


# ---------------------------------------------------------------------------
# Running the frozen re-ID model from continuous input embeddings
# ---------------------------------------------------------------------------


def _project_from_token_embeddings(
    model: ContrastiveReIDModel,
    token_embeds: torch.Tensor,
    timing: torch.Tensor,
    attention_mask: torch.Tensor,
) -> torch.Tensor:
    """Run backbone ``f`` + head ``g`` starting from (perturbed) token embeddings.

    Replicates :meth:`SessionEmbedder.forward` from the point *after* the embedding
    lookup, using only the backbone's public sub-modules, so we can inject a
    continuous perturbation in embedding space without modifying Phase-2 code.

    Args:
        token_embeds: ``[B, L, d_model]`` *un-scaled* token embeddings (the lookup
            output, before ``embed_scale``), already perturbed.
        timing: ``[B, L]`` log-ICI channel.
        attention_mask: ``[B, L]`` (1 == valid).

    Returns:
        ``[B, proj_dim]`` unit-normalised projection ``z`` (the re-ID metric).
    """
    backbone = model.backbone
    x = token_embeds * backbone.embed_scale
    if backbone.timing_encoder is not None:
        x = x + backbone.timing_encoder(timing.unsqueeze(-1).to(x.dtype))
    x = backbone.positional_encoding(x)
    x = backbone.input_dropout(x)

    key_padding_mask = attention_mask == 0
    for layer in backbone.layers:
        x = layer(x, src_key_padding_mask=key_padding_mask)
    hidden = backbone.final_norm(x)

    mask_f = attention_mask.unsqueeze(-1).to(hidden.dtype)
    pooled = (hidden * mask_f).sum(dim=1) / mask_f.sum(dim=1).clamp(min=1.0)
    pooled = backbone.output_projection(pooled)
    return model.projection_head(pooled)


def _token_embeddings(model: ContrastiveReIDModel, input_ids: torch.Tensor) -> torch.Tensor:
    """The backbone's un-scaled token-embedding lookup ``E`` for ``input_ids``."""
    return model.backbone.token_embedding(input_ids)


# ---------------------------------------------------------------------------
# Identity centroids (the cluster the attacker flees)
# ---------------------------------------------------------------------------


def identity_centroids(bank: EmbeddingBank) -> dict[str, torch.Tensor]:
    """Unit-normalised per-identity centroids from a clean embedding bank.

    The centroid is the attacker's "home" in the re-ID metric; evasion is defined
    relative to it.
    """
    sums: dict[str, torch.Tensor] = {}
    counts: dict[str, int] = {}
    for vec, identity in zip(bank.vectors, bank.identities):
        if identity not in sums:
            sums[identity] = torch.zeros_like(vec)
            counts[identity] = 0
        sums[identity] = sums[identity] + vec
        counts[identity] += 1
    return {idn: F.normalize(s / counts[idn], dim=-1) for idn, s in sums.items()}


# ---------------------------------------------------------------------------
# Learned adversarial attacker
# ---------------------------------------------------------------------------


class AdversarialSessionGenerator(nn.Module):
    """Amortised, budget-constrained evasion attacker.

    Maps each command's token embedding (conditioned on the whole-session context
    and its timing) to a perturbation, projected onto the per-command L2 ball of
    radius ``epsilon``. Trained to push sessions away from their own identity
    centroid (see :func:`train_adversary`).

    Args:
        embed_dim: Backbone embedding width ``d_model``.
        hidden_dim: Hidden width of the per-position MLP.
        epsilon: L2 radius of the perturbation ball per command.
    """

    def __init__(self, embed_dim: int, hidden_dim: int = 128, epsilon: float = 0.5) -> None:
        super().__init__()
        self.epsilon = epsilon
        # Per-position input: token embedding (d) + session context (d) + timing (1).
        self.net = nn.Sequential(
            nn.Linear(2 * embed_dim + 1, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, embed_dim),
        )

    def _project_to_ball(
        self, delta: torch.Tensor, attention_mask: torch.Tensor
    ) -> torch.Tensor:
        """Clip each position's perturbation to the epsilon ball; zero the pads."""
        norm = delta.norm(dim=-1, keepdim=True).clamp(min=1e-12)
        factor = (self.epsilon / norm).clamp(max=1.0)
        delta = delta * factor
        return delta * attention_mask.unsqueeze(-1).to(delta.dtype)

    def forward(
        self,
        token_embeds: torch.Tensor,
        timing: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """Return the per-command perturbation ``delta`` (``[B, L, d_model]``)."""
        mask_f = attention_mask.unsqueeze(-1).to(token_embeds.dtype)
        # Masked-mean session context, broadcast to every position.
        context = (token_embeds * mask_f).sum(dim=1) / mask_f.sum(dim=1).clamp(min=1.0)
        context = context.unsqueeze(1).expand(-1, token_embeds.size(1), -1)
        feats = torch.cat([token_embeds, context, timing.unsqueeze(-1)], dim=-1)
        raw = self.net(feats)
        return self._project_to_ball(raw, attention_mask)

    def attack(
        self, model: ContrastiveReIDModel, view: BatchView
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Produce ``(z_adv, delta)`` for a batch under the frozen re-ID ``model``."""
        embeds = _token_embeddings(model, view.input_ids)
        delta = self.forward(embeds, view.timing, view.attention_mask)
        z_adv = _project_from_token_embeddings(
            model, embeds + delta, view.timing, view.attention_mask
        )
        return z_adv, delta


def _freeze(model: ContrastiveReIDModel) -> None:
    """Freeze every parameter of the re-ID model (we attack a fixed model)."""
    for param in model.parameters():
        param.requires_grad_(False)


def train_adversary(
    model: ContrastiveReIDModel,
    dataset: ReIDDataset,
    attack_indices: Sequence[int],
    centroids: dict[str, torch.Tensor],
    config: AdversarialConfig | None = None,
    device: torch.device | str | None = None,
) -> AdversarialSessionGenerator:
    """Train the learned attacker to evade re-identification.

    The re-ID ``model`` is frozen and run in eval mode (deterministic); gradients
    flow through it only to shape the generator. Objective per session:
    ``cos(z_adv, own_centroid) + lambda * ||delta||^2`` (minimised).

    Args:
        model: The (already trained) re-ID model under attack.
        dataset: Dataset the attack indices refer to.
        attack_indices: Sessions the attacker learns to perturb.
        centroids: Per-identity clean centroids (see :func:`identity_centroids`).
        config: Attack hyperparameters.
        device: Compute device; defaults to the model's device.

    Returns:
        The trained :class:`AdversarialSessionGenerator`.
    """
    config = config or AdversarialConfig()
    device = torch.device(device) if device is not None else next(model.parameters()).device
    torch.manual_seed(config.seed)
    _freeze(model)
    model.eval()

    generator = AdversarialSessionGenerator(
        embed_dim=model.config.backbone.d_model,
        hidden_dim=config.hidden_dim,
        epsilon=config.epsilon,
    ).to(device)
    optimizer = torch.optim.Adam(generator.parameters(), lr=config.lr)

    centroid_mat = {k: v.to(device) for k, v in centroids.items()}
    loader = DataLoader(
        Subset(dataset, list(attack_indices)),
        batch_size=config.batch_size,
        shuffle=True,
        collate_fn=ReIDEvalCollator(dataset.tokenizer),
    )

    for _ in range(config.epochs):
        for view, identities, _toolkits in loader:
            view = view.to(device)
            targets = torch.stack([centroid_mat[i] for i in identities], dim=0)  # [B, P]
            z_adv, delta = generator.attack(model, view)
            evade = (z_adv * targets).sum(dim=-1).mean()  # mean cos to own centroid
            budget = delta.pow(2).sum(dim=-1).mean()
            loss = evade + config.budget_lambda * budget
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()
    return generator


@torch.no_grad()
def attack_dataset(
    model: ContrastiveReIDModel,
    generator: AdversarialSessionGenerator,
    dataset: ReIDDataset,
    indices: Sequence[int],
    device: torch.device | str | None = None,
    batch_size: int = 128,
) -> tuple[EmbeddingBank, float]:
    """Embed ``indices`` *after* the learned attack; return the bank + mean budget.

    Returns:
        ``(adversarial_bank, mean_perturbation_norm)`` where the bank's vectors are
        the unit-normalised adversarial projections and the float is the mean
        per-command L2 perturbation actually used (a stealth/budget readout).
    """
    device = torch.device(device) if device is not None else next(model.parameters()).device
    model.eval()
    generator.eval()
    loader = DataLoader(
        Subset(dataset, list(indices)),
        batch_size=batch_size,
        shuffle=False,
        collate_fn=ReIDEvalCollator(dataset.tokenizer),
    )
    vecs: list[torch.Tensor] = []
    identities: list[str] = []
    toolkits: list[str] = []
    pert_sum = 0.0
    pert_count = 0
    for view, batch_ids, batch_kits in loader:
        view = view.to(device)
        z_adv, delta = generator.attack(model, view)
        vecs.append(F.normalize(z_adv, dim=-1).cpu())
        identities.extend(batch_ids)
        toolkits.extend(batch_kits)
        per_cmd = delta.norm(dim=-1)  # [B, L]
        valid = view.attention_mask.bool()
        pert_sum += float(per_cmd[valid].sum().item())
        pert_count += int(valid.sum().item())
    bank = EmbeddingBank(
        vectors=torch.cat(vecs, dim=0) if vecs else torch.empty(0),
        identities=identities,
        toolkits=toolkits,
    )
    return bank, (pert_sum / pert_count if pert_count else 0.0)


# ---------------------------------------------------------------------------
# PGD baseline (per-session white-box attack)
# ---------------------------------------------------------------------------


def pgd_attack(
    model: ContrastiveReIDModel,
    view: BatchView,
    targets: torch.Tensor,
    epsilon: float = 0.5,
    steps: int = 20,
    step_size: float = 0.1,
) -> tuple[torch.Tensor, torch.Tensor]:
    """Projected-gradient-descent evasion for one batch (the white-box baseline).

    Optimises a per-command perturbation directly (no learned network) to minimise
    the cosine similarity between the adversarial projection and the per-example
    target centroid, projecting onto the epsilon ball each step.

    Args:
        model: Frozen re-ID model.
        view: A batch.
        targets: ``[B, proj_dim]`` per-example own-identity centroids.
        epsilon: L2 ball radius per command.
        steps: PGD iterations.
        step_size: Gradient step size.

    Returns:
        ``(z_adv, delta)`` for the batch.
    """
    _freeze(model)
    model.eval()
    embeds = _token_embeddings(model, view.input_ids).detach()
    mask = view.attention_mask
    delta = torch.zeros_like(embeds, requires_grad=True)

    for _ in range(steps):
        z_adv = _project_from_token_embeddings(model, embeds + delta, view.timing, mask)
        loss = (z_adv * targets).sum(dim=-1).mean()  # minimise cos to own centroid
        grad = torch.autograd.grad(loss, delta)[0]
        with torch.no_grad():
            delta = delta - step_size * grad.sign()
            norm = delta.norm(dim=-1, keepdim=True).clamp(min=1e-12)
            delta = delta * (epsilon / norm).clamp(max=1.0)
            delta = delta * mask.unsqueeze(-1).to(delta.dtype)
        delta.requires_grad_(True)

    with torch.no_grad():
        z_adv = _project_from_token_embeddings(model, embeds + delta, view.timing, mask)
    return z_adv.detach(), delta.detach()


# ---------------------------------------------------------------------------
# Interpretability: decode an adversarial session back to commands
# ---------------------------------------------------------------------------


@torch.no_grad()
def decode_to_commands(
    model: ContrastiveReIDModel,
    perturbed_embeds: torch.Tensor,
    attention_mask: torch.Tensor,
    tokenizer: CommandTokenizer,
) -> list[list[str]]:
    """Map perturbed token embeddings back to the nearest vocabulary commands.

    For each valid position, picks the vocabulary token whose embedding is most
    cosine-similar to the perturbed vector -- recovering the discrete command
    sequence the continuous attack corresponds to. This answers, concretely,
    *which command substitutions evade re-identification.*
    """
    weight = model.backbone.token_embedding.weight  # [V, d]
    w_norm = F.normalize(weight, dim=-1)
    e_norm = F.normalize(perturbed_embeds, dim=-1)  # [B, L, d]
    sims = e_norm @ w_norm.t()  # [B, L, V]
    nearest = sims.argmax(dim=-1)  # [B, L]

    out: list[list[str]] = []
    for b in range(nearest.size(0)):
        valid = attention_mask[b].bool()
        ids = nearest[b][valid].tolist()
        out.append(tokenizer.decode(ids, skip_special=True))
    return out


# ---------------------------------------------------------------------------
# End-to-end robustness evaluation
# ---------------------------------------------------------------------------


def evaluate_adversarial_robustness(
    model: ContrastiveReIDModel,
    generator: AdversarialSessionGenerator,
    dataset: ReIDDataset,
    gallery_indices: Sequence[int],
    probe_indices: Sequence[int],
    ks: Sequence[int] = (1, 5, 10),
    device: torch.device | str | None = None,
) -> dict[str, float]:
    """Measure how much the learned attack degrades recall@k.

    Gallery stays clean (enrolled, trusted); only the **probes** are adversarial
    (the returning attacker now evades). Reports clean recall@k, adversarial
    recall@k, the absolute degradation, and the mean perturbation budget used.

    Returns:
        ``{"clean_recall@k": ..., "adv_recall@k": ..., "recall_drop@k": ...,
        "mean_perturbation": ...}``.
    """
    gallery = embed_dataset(model, dataset, gallery_indices, device=device)
    clean_probe = embed_dataset(model, dataset, probe_indices, device=device)
    adv_probe, mean_pert = attack_dataset(model, generator, dataset, probe_indices, device=device)

    clean = recall_at_k(gallery, clean_probe, ks=ks)
    adv = recall_at_k(gallery, adv_probe, ks=ks)
    metrics: dict[str, float] = {}
    for k in ks:
        metrics[f"clean_recall@{k}"] = clean[k]
        metrics[f"adv_recall@{k}"] = adv[k]
        metrics[f"recall_drop@{k}"] = clean[k] - adv[k]
    metrics["mean_perturbation"] = mean_pert
    return metrics
