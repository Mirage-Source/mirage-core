from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

import numpy as np
import torch
import torch.nn.functional as F

from .actions import DeceptionAction
from .bandit import LinUCBBandit, train_bandit
from .environment import DeceptionConfig, DeceptionEnv
from .policy import DeceptionPolicy, FixedPolicy, HeuristicPolicy, RandomPolicy, ValueNetwork
from .ppo import PPOConfig, train_ppo

__all__ = [
    "Policy",
    "train_deception_policy",
    "evaluate_policy",
    "PolicyMetrics",
    "build_baselines",
    "compare_policies",
    "save_policy_checkpoint",
    "load_policy_checkpoint",
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
    This is the middle point of the bandit-to-PPO spectrum: full episodic
    credit assignment (unlike the bandit), but a single on-policy gradient step
    per batch with no clipping (unlike PPO).

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
    critic = ValueNetwork(env.obs_dim)
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
            print(f"[reinforce] iter {it:4d}/{iterations} avg_return={moving_avg:.2f}")

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


def build_baselines(n_actions: int, seed: int = 0) -> dict[str, Policy]:
    """The fixed controls every learned policy is compared against.

    ``static_minimal`` is today's honeypot (the null hypothesis); ``random`` is
    a deception-effort control; ``heuristic_ceiling`` is the hand-written,
    near-optimal rule the learned policies should approach without being told
    the rules.
    """
    return {
        "static_minimal": FixedPolicy(DeceptionAction.MINIMAL),
        "random": RandomPolicy(n_actions, seed=seed),
        "heuristic_ceiling": HeuristicPolicy(),
    }


def compare_policies(
    policies: dict[str, Policy],
    config: DeceptionConfig | None = None,
    episodes: int = 1000,
    seed: int = 12345,
) -> dict[str, dict[str, float]]:
    """Evaluate an arbitrary named set of policies on identical episodes.

    Returns:
        ``{policy_name: metrics_dict}``, one entry per key in ``policies``.
    """
    return {
        name: evaluate_policy(pol, config=config, episodes=episodes, seed=seed).as_dict()
        for name, pol in policies.items()
    }


def save_policy_checkpoint(
    path: str | Path, policy: DeceptionPolicy, obs_dim: int, n_actions: int, hidden_dim: int = 64
) -> None:
    """Save a trained actor (REINFORCE or PPO) to a self-describing ``.pt`` file.

    Only the actor is saved -- it is all :func:`evaluate_policy` /
    ``select_action`` need. Resuming *training* would also need the critic,
    which is out of scope for a deployment/evaluation checkpoint.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": policy.state_dict(),
            "obs_dim": obs_dim,
            "n_actions": n_actions,
            "hidden_dim": hidden_dim,
        },
        path,
    )


def load_policy_checkpoint(path: str | Path) -> DeceptionPolicy:
    """Load a checkpoint written by :func:`save_policy_checkpoint`."""
    ckpt = torch.load(Path(path), map_location="cpu", weights_only=False)
    policy = DeceptionPolicy(ckpt["obs_dim"], ckpt["n_actions"], hidden_dim=ckpt.get("hidden_dim", 64))
    policy.load_state_dict(ckpt["state_dict"])
    policy.eval()
    return policy


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--algo",
        choices=["all", "bandit", "reinforce", "ppo"],
        default="all",
        help="Which learned polic(y/ies) to train (default: all three).",
    )
    parser.add_argument("--max-steps", type=int, default=25, help="Environment episode length cap.")
    parser.add_argument("--seed", type=int, default=0, help="Training RNG seed.")
    parser.add_argument("--eval-episodes", type=int, default=1000)
    parser.add_argument("--eval-seed", type=int, default=12345)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="If set, save each trained policy's checkpoint here (e.g. artifacts/deception).",
    )

    bandit_group = parser.add_argument_group("bandit (LinUCB)")
    bandit_group.add_argument("--bandit-episodes", type=int, default=4000)
    bandit_group.add_argument("--bandit-alpha", type=float, default=1.0)
    bandit_group.add_argument("--bandit-ridge-lambda", type=float, default=1.0)

    reinforce_group = parser.add_argument_group("REINFORCE / A2C")
    reinforce_group.add_argument("--reinforce-episodes", type=int, default=2500)
    reinforce_group.add_argument("--reinforce-lr", type=float, default=1e-2)

    ppo_group = parser.add_argument_group("PPO")
    ppo_group.add_argument("--ppo-iterations", type=int, default=150)
    ppo_group.add_argument("--ppo-episodes-per-iter", type=int, default=32)
    ppo_group.add_argument("--ppo-lr", type=float, default=3e-4)
    ppo_group.add_argument("--ppo-clip", type=float, default=0.2)
    ppo_group.add_argument("--ppo-epochs", type=int, default=4)

    parser.add_argument("--quiet", action="store_true", help="Suppress per-algorithm training logs.")
    return parser


def main(argv: list[str] | None = None) -> dict[str, Any]:
    """CLI: train the requested polic(y/ies) and print the baseline comparison."""
    args = _build_arg_parser().parse_args(argv)
    verbose = not args.quiet

    config = DeceptionConfig(max_steps=args.max_steps)
    probe_env = DeceptionEnv(replace(config, seed=args.seed))
    obs_dim, n_actions = probe_env.obs_dim, probe_env.n_actions

    policies: dict[str, Policy] = build_baselines(n_actions, seed=args.seed)
    training_summary: dict[str, dict[str, float]] = {}
    checkpoints: dict[str, Any] = {}

    if args.algo in ("all", "bandit"):
        if verbose:
            print(f"[bandit] training LinUCB for {args.bandit_episodes} episodes...")
        bandit, bandit_hist = train_bandit(
            config=config,
            episodes=args.bandit_episodes,
            alpha=args.bandit_alpha,
            ridge_lambda=args.bandit_ridge_lambda,
            seed=args.seed,
        )
        policies["bandit_linucb"] = bandit
        checkpoints["bandit_linucb"] = bandit
        training_summary["bandit_linucb"] = {
            "episodes": args.bandit_episodes,
            "final_100ep_avg_return": float(np.mean(bandit_hist[-100:])),
        }

    if args.algo in ("all", "reinforce"):
        reinforce_policy, reinforce_hist = train_deception_policy(
            config=config,
            episodes=args.reinforce_episodes,
            lr=args.reinforce_lr,
            seed=args.seed,
            verbose=verbose,
        )
        policies["reinforce_a2c"] = reinforce_policy
        checkpoints["reinforce_a2c"] = reinforce_policy
        training_summary["reinforce_a2c"] = {
            "episodes": args.reinforce_episodes,
            "final_100ep_avg_return": float(np.mean(reinforce_hist[-100:])),
        }

    if args.algo in ("all", "ppo"):
        ppo_cfg = PPOConfig(
            iterations=args.ppo_iterations,
            episodes_per_iteration=args.ppo_episodes_per_iter,
            lr=args.ppo_lr,
            clip_eps=args.ppo_clip,
            epochs=args.ppo_epochs,
            seed=args.seed,
        )
        ppo_policy, _ppo_critic, ppo_hist = train_ppo(config=config, ppo_config=ppo_cfg, verbose=verbose)
        policies["ppo"] = ppo_policy
        checkpoints["ppo"] = ppo_policy
        training_summary["ppo"] = {
            "episodes": len(ppo_hist),
            "final_100ep_avg_return": float(np.mean(ppo_hist[-100:])),
        }

    comparison = compare_policies(
        policies, config=config, episodes=args.eval_episodes, seed=args.eval_seed
    )

    if args.output_dir:
        out = Path(args.output_dir)
        if "bandit_linucb" in checkpoints:
            checkpoints["bandit_linucb"].save(out / "bandit_linucb.npz")
        if "reinforce_a2c" in checkpoints:
            save_policy_checkpoint(out / "reinforce_a2c.pt", checkpoints["reinforce_a2c"], obs_dim, n_actions)
        if "ppo" in checkpoints:
            save_policy_checkpoint(out / "ppo.pt", checkpoints["ppo"], obs_dim, n_actions)
        if verbose:
            print(f"[checkpoints] saved to {out}/")

    result = {"training": training_summary, "comparison": comparison}
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":  # pragma: no cover
    main()
