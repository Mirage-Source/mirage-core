"""Train and evaluate adaptive deception policies (REINFORCE).

Trains the :class:`~mirage.deception.policy.DeceptionPolicy` on the attacker
simulator with the REINFORCE policy-gradient algorithm, then compares it against
the fixed baselines -- crucially against ``MINIMAL`` (today's static honeypot) --
on the metrics that matter for an intelligence-gathering honeypot: total
intelligence extracted, commands captured, bait interactions elicited, and how
long attackers are kept engaged.

The headline result the paper wants: a *learned, adaptive* response policy keeps
attackers engaged longer and extracts more intent-revealing bait interactions
than the static honeypot, **without being told the rules** -- approaching the
hand-written heuristic ceiling from interaction alone.

Run::

    python -m mirage.deception.train --episodes 3000
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, replace
from typing import Any, Protocol

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from .environment import DeceptionConfig, DeceptionEnv
from .policy import DeceptionPolicy, FixedPolicy, HeuristicPolicy, RandomPolicy
from .actions import DeceptionAction


class _ValueNetwork(nn.Module):
    """State-value critic ``V(s)`` -- the REINFORCE baseline.

    Subtracting a learned per-state value from the return turns the high-variance
    Monte-Carlo gradient into a lower-variance advantage estimate, which is what
    lets the policy actually credit the rare, high-payoff bait-surfacing action
    instead of collapsing onto the safe "just enrich" local optimum.
    """

    def __init__(self, obs_dim: int, hidden_dim: int = 64) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(obs_dim, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, obs: torch.Tensor) -> torch.Tensor:
        return self.net(obs).squeeze(-1)

__all__ = [
    "Policy",
    "train_deception_policy",
    "evaluate_policy",
    "compare_policies",
    "main",
]


class Policy(Protocol):
    """Anything with a ``select_action`` is evaluable."""

    def select_action(self, obs: np.ndarray, greedy: bool = ...) -> int: ...


def train_deception_policy(
    config: DeceptionConfig | None = None,
    policy: DeceptionPolicy | None = None,
    episodes: int = 4000,
    batch_episodes: int = 16,
    lr: float = 3e-3,
    gamma: float = 0.99,
    entropy_coef: float = 0.03,
    value_coef: float = 0.5,
    seed: int = 0,
    verbose: bool = False,
) -> tuple[DeceptionPolicy, list[float]]:
    """Train a deception policy with batched advantage actor-critic (A2C).

    Each update aggregates a **batch of whole episodes**, normalising the
    advantage across the batch. Batching is what stabilises learning of the
    *combined* strategy (sustain engagement with enrich, then surface bait on a
    sensitive probe) -- per-episode updates are too high-variance to hold both.

    Args:
        config: Environment config (a fresh default is used if omitted).
        policy: Policy to train (a new one is built if omitted).
        episodes: Total training episodes (rounded down to a multiple of the batch).
        batch_episodes: Episodes aggregated per gradient update.
        lr / gamma / entropy_coef / value_coef: Optimization / RL hyperparameters.
        seed: RNG seed for the env and torch.
        verbose: Print a periodic moving-average return.

    Returns:
        ``(trained_policy, return_history)`` -- one history entry per episode.
    """
    torch.manual_seed(seed)
    env = DeceptionEnv(replace(config or DeceptionConfig(), seed=seed))
    policy = policy or DeceptionPolicy(env.obs_dim, env.n_actions)
    critic = _ValueNetwork(env.obs_dim)
    optimizer = torch.optim.Adam(
        list(policy.parameters()) + list(critic.parameters()), lr=lr
    )

    history: list[float] = []
    moving_avg = 0.0
    iterations = max(1, episodes // batch_episodes)
    for it in range(iterations):
        obs_batch: list[np.ndarray] = []
        log_probs: list[torch.Tensor] = []
        entropies: list[torch.Tensor] = []
        returns: list[float] = []

        for _ in range(batch_episodes):
            obs = env.reset()
            ep_obs: list[np.ndarray] = []
            ep_log: list[torch.Tensor] = []
            ep_ent: list[torch.Tensor] = []
            ep_rewards: list[float] = []
            done = False
            while not done:
                ep_obs.append(obs)
                action, log_prob, entropy = policy.act(obs)
                obs, reward, done, _ = env.step(action)
                ep_log.append(log_prob)
                ep_ent.append(entropy)
                ep_rewards.append(reward)

            obs_batch.extend(ep_obs)
            log_probs.extend(ep_log)
            entropies.extend(ep_ent)
            returns.extend(_discounted_returns(ep_rewards, gamma))
            ep_return = float(sum(ep_rewards))
            history.append(ep_return)
            moving_avg = (
                0.98 * moving_avg + 0.02 * ep_return if history[:-1] else ep_return
            )

        returns_t = torch.tensor(returns, dtype=torch.float32)
        values = critic(torch.as_tensor(np.stack(obs_batch), dtype=torch.float32))
        advantages = returns_t - values.detach()
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

        policy_loss = -(torch.stack(log_probs) * advantages).mean()
        value_loss = value_coef * F.mse_loss(values, returns_t)
        entropy_loss = -entropy_coef * torch.stack(entropies).mean()
        loss = policy_loss + value_loss + entropy_loss

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        if verbose and (it % 20 == 0 or it == iterations - 1):
            print(f"[deception] iter {it:4d}/{iterations} avg_return={moving_avg:.2f}")

    return policy, history


def _discounted_returns(rewards: list[float], gamma: float) -> list[float]:
    """Compute discounted return-to-go for each timestep."""
    out = [0.0] * len(rewards)
    running = 0.0
    for t in reversed(range(len(rewards))):
        running = rewards[t] + gamma * running
        out[t] = running
    return out


@dataclass
class PolicyMetrics:
    """Mean evaluation metrics for a policy over many episodes."""

    mean_return: float
    mean_commands: float
    mean_bait: float
    mean_length: float
    bait_episode_rate: float  # fraction of episodes with >=1 bait interaction

    def as_dict(self) -> dict[str, float]:
        return {
            "mean_return": self.mean_return,
            "mean_commands": self.mean_commands,
            "mean_bait": self.mean_bait,
            "mean_length": self.mean_length,
            "bait_episode_rate": self.bait_episode_rate,
        }


def evaluate_policy(
    policy: Policy,
    config: DeceptionConfig | None = None,
    episodes: int = 1000,
    seed: int = 12345,
    greedy: bool = True,
) -> PolicyMetrics:
    """Evaluate a policy over ``episodes`` independent attacker sessions.

    All policies are evaluated on the same env seed so the archetype/command
    stream is comparable; differences in the metrics come from the policy.
    """
    env = DeceptionEnv(replace(config or DeceptionConfig(), seed=seed))
    returns, commands, baits, lengths, bait_eps = [], [], [], [], 0
    for _ in range(episodes):
        obs = env.reset()
        done = False
        total = 0.0
        steps = 0
        while not done:
            action = policy.select_action(obs, greedy=greedy)
            obs, reward, done, info = env.step(action)
            total += reward
            steps += 1
        returns.append(total)
        commands.append(info["commands_captured"])
        baits.append(info["bait_captured"])
        lengths.append(steps)
        bait_eps += 1 if info["bait_captured"] > 0 else 0

    return PolicyMetrics(
        mean_return=float(np.mean(returns)),
        mean_commands=float(np.mean(commands)),
        mean_bait=float(np.mean(baits)),
        mean_length=float(np.mean(lengths)),
        bait_episode_rate=bait_eps / episodes,
    )


def compare_policies(
    learned: DeceptionPolicy,
    config: DeceptionConfig | None = None,
    episodes: int = 1000,
    seed: int = 12345,
) -> dict[str, dict[str, float]]:
    """Evaluate the learned policy against the fixed baselines.

    Returns:
        ``{policy_name: metrics_dict}`` for ``static_minimal`` (today's honeypot),
        ``random``, ``heuristic_ceiling``, and ``learned``.
    """
    env = DeceptionEnv(replace(config or DeceptionConfig(), seed=seed))
    contenders: dict[str, Policy] = {
        "static_minimal": FixedPolicy(DeceptionAction.MINIMAL),
        "random": RandomPolicy(env.n_actions, seed=seed),
        "heuristic_ceiling": HeuristicPolicy(),
        "learned": learned,
    }
    return {
        name: evaluate_policy(pol, config=config, episodes=episodes, seed=seed).as_dict()
        for name, pol in contenders.items()
    }


def main(argv: list[str] | None = None) -> dict[str, Any]:
    """CLI: train a policy and print the baseline comparison."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--episodes", type=int, default=2500)
    parser.add_argument("--eval-episodes", type=int, default=1000)
    parser.add_argument("--lr", type=float, default=1e-2)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-steps", type=int, default=25)
    args = parser.parse_args(argv)

    config = DeceptionConfig(max_steps=args.max_steps)
    policy, _ = train_deception_policy(
        config=config, episodes=args.episodes, lr=args.lr, seed=args.seed, verbose=True
    )
    comparison = compare_policies(policy, config=config, episodes=args.eval_episodes)
    print(json.dumps(comparison, indent=2))
    return comparison


if __name__ == "__main__":  # pragma: no cover
    main()
