"""Deception policies: a learnable network plus fixed baselines.

The learned :class:`DeceptionPolicy` is a small stochastic policy network trained
with REINFORCE (see :mod:`mirage.deception.train`). The baselines are the controls
the paper compares against:

* :class:`FixedPolicy` (``MINIMAL``) -- **today's honeypot**: the same terse
  response no matter what. The null hypothesis.
* :class:`RandomPolicy` -- random strategy each turn (a deception-effort control).
* :class:`HeuristicPolicy` -- a hand-written, near-optimal rule (enrich on recon,
  surface bait on sensitive probes, fake success on risky ops). An *informed
  ceiling*: the learned policy should approach it without being told the rules.

All policies share ``select_action(obs) -> int`` so the evaluation harness treats
them uniformly.
"""

from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn

from .actions import DeceptionAction
from .environment import COMMAND_CATEGORIES

__all__ = ["DeceptionPolicy", "FixedPolicy", "RandomPolicy", "HeuristicPolicy"]

_SENSITIVE_IDX = {COMMAND_CATEGORIES.index(c) for c in ("read_sensitive", "escalate", "exfil")}


def _category_from_obs(obs: np.ndarray) -> int:
    """Recover the current command-category index from an observation vector."""
    return int(np.argmax(obs[1 : 1 + len(COMMAND_CATEGORIES)]))


class DeceptionPolicy(nn.Module):
    """A stochastic MLP policy over deception actions.

    Args:
        obs_dim: Observation dimensionality (``env.obs_dim``).
        n_actions: Number of actions (``env.n_actions``).
        hidden_dim: Hidden width.
    """

    def __init__(self, obs_dim: int, n_actions: int, hidden_dim: int = 64) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(obs_dim, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, n_actions),
        )

    def forward(self, obs: torch.Tensor) -> torch.Tensor:
        """Return action logits for ``[B, obs_dim]`` (or ``[obs_dim]``) observations."""
        return self.net(obs)

    def distribution(self, obs: torch.Tensor) -> torch.distributions.Categorical:
        return torch.distributions.Categorical(logits=self.forward(obs))

    def act(self, obs: np.ndarray) -> tuple[int, torch.Tensor, torch.Tensor]:
        """Sample an action; return ``(action, log_prob, entropy)`` for training."""
        obs_t = torch.as_tensor(obs, dtype=torch.float32)
        dist = self.distribution(obs_t)
        action = dist.sample()
        return int(action.item()), dist.log_prob(action), dist.entropy()

    @torch.no_grad()
    def select_action(self, obs: np.ndarray, greedy: bool = True) -> int:
        """Choose an action for evaluation (greedy by default)."""
        obs_t = torch.as_tensor(obs, dtype=torch.float32)
        logits = self.forward(obs_t)
        if greedy:
            return int(torch.argmax(logits).item())
        return int(torch.distributions.Categorical(logits=logits).sample().item())


class FixedPolicy:
    """Always returns the same action (e.g. ``MINIMAL`` = the static honeypot)."""

    def __init__(self, action: DeceptionAction = DeceptionAction.MINIMAL) -> None:
        self.action = int(action)

    def select_action(self, obs: np.ndarray, greedy: bool = True) -> int:
        return self.action


class RandomPolicy:
    """Uniformly random deception action (a deception-effort control)."""

    def __init__(self, n_actions: int, seed: int | None = None) -> None:
        self.n_actions = n_actions
        self._rng = np.random.default_rng(seed)

    def select_action(self, obs: np.ndarray, greedy: bool = True) -> int:
        return int(self._rng.integers(self.n_actions))


class HeuristicPolicy:
    """Hand-written, category-conditioned strategy -- the informed ceiling.

    Surface bait the moment the attacker probes something sensitive (capture
    intent), enrich basic recon/download to sustain curiosity, fake success on
    risky operations to draw the next stage.
    """

    def select_action(self, obs: np.ndarray, greedy: bool = True) -> int:
        category = _category_from_obs(obs)
        if category in _SENSITIVE_IDX:
            return int(DeceptionAction.SURFACE_BAIT)
        cat_name = COMMAND_CATEGORIES[category]
        if cat_name == "download":
            return int(DeceptionAction.FAKE_SUCCESS)
        return int(DeceptionAction.ENRICH)
