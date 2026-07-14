from __future__ import annotations

from dataclasses import dataclass, replace

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from .environment import DeceptionConfig, DeceptionEnv
from .policy import DeceptionPolicy, ValueNetwork

__all__ = ["PPOConfig", "compute_gae", "train_ppo"]


@dataclass
class PPOConfig:
    """PPO hyperparameters.

    Attributes:
        iterations: Number of rollout-then-update cycles.
        episodes_per_iteration: Whole episodes collected per rollout.
        epochs: Passes over the collected batch per update.
        minibatch_size: Minibatch size within each epoch pass.
        clip_eps: PPO clipping range for the probability ratio.
        gamma: Discount factor.
        gae_lambda: GAE bias/variance trade-off (1.0 == plain Monte-Carlo advantage).
        lr: Adam learning rate (shared by actor and critic).
        entropy_coef: Entropy-bonus weight (encourages continued exploration).
        value_coef: Value-loss weight in the combined objective.
        max_grad_norm: Gradient-norm clip applied to actor + critic jointly.
        target_kl: If the approximate KL from the behavior policy exceeds
            ``1.5 * target_kl`` partway through an epoch pass, stop updating on
            this batch early. ``None`` disables early stopping.
        hidden_dim: Hidden width for both the actor and the critic.
        seed: RNG seed for the environment and torch.
    """

    iterations: int = 150
    episodes_per_iteration: int = 32
    epochs: int = 4
    minibatch_size: int = 64
    clip_eps: float = 0.2
    gamma: float = 0.99
    gae_lambda: float = 0.95
    lr: float = 3e-4
    entropy_coef: float = 0.01
    value_coef: float = 0.5
    max_grad_norm: float = 0.5
    target_kl: float | None = 0.02
    hidden_dim: int = 64
    seed: int = 0


def compute_gae(
    rewards: list[float],
    values: list[float],
    dones: list[bool],
    gamma: float,
    gae_lambda: float,
) -> tuple[np.ndarray, np.ndarray]:
    """Generalized Advantage Estimation for a single trajectory.

    Args:
        rewards: Per-step rewards, length ``T``.
        values: Critic's ``V(s_t)`` at each visited state, length ``T``.
        dones: Whether the episode ended *after* this step, length ``T``. The
            environments used here always terminate the episode on the final
            recorded step, so ``dones[-1] is True`` and no bootstrap value
            beyond the buffer is required.
        gamma: Discount factor.
        gae_lambda: GAE trade-off parameter.

    Returns:
        ``(advantages, returns)``, each length ``T``. ``returns = advantages +
        values`` are the value-function regression targets.
    """
    t_steps = len(rewards)
    advantages = np.zeros(t_steps, dtype=np.float64)
    last_gae = 0.0
    for t in reversed(range(t_steps)):
        next_value = 0.0 if dones[t] else values[t + 1]
        delta = rewards[t] + gamma * next_value * (1.0 - dones[t]) - values[t]
        last_gae = delta + gamma * gae_lambda * (1.0 - dones[t]) * last_gae
        advantages[t] = last_gae
    returns = advantages + np.asarray(values, dtype=np.float64)
    return advantages, returns


def _collect_rollout(
    env: DeceptionEnv,
    policy: DeceptionPolicy,
    critic: ValueNetwork,
    cfg: PPOConfig,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, list[float]]:
    """Run ``cfg.episodes_per_iteration`` episodes under the current policy.

    Returns flattened ``(obs, actions, old_log_probs, advantages, returns)``
    arrays (concatenated across episodes, advantages computed per-episode
    before flattening) plus the list of per-episode returns for logging.
    """
    obs_buf: list[np.ndarray] = []
    act_buf: list[int] = []
    logp_buf: list[float] = []
    adv_buf: list[float] = []
    ret_buf: list[float] = []
    ep_returns: list[float] = []

    for _ in range(cfg.episodes_per_iteration):
        obs = env.reset()
        ep_obs: list[np.ndarray] = []
        ep_act: list[int] = []
        ep_logp: list[float] = []
        ep_val: list[float] = []
        ep_rew: list[float] = []
        ep_done: list[bool] = []
        done = False
        while not done:
            obs_t = torch.as_tensor(obs, dtype=torch.float32)
            with torch.no_grad():
                dist = policy.distribution(obs_t)
                action = dist.sample()
                log_prob = dist.log_prob(action)
                value = critic(obs_t.unsqueeze(0)).squeeze(0)
            next_obs, reward, done, _ = env.step(int(action.item()))

            ep_obs.append(obs)
            ep_act.append(int(action.item()))
            ep_logp.append(float(log_prob.item()))
            ep_val.append(float(value.item()))
            ep_rew.append(reward)
            ep_done.append(done)
            obs = next_obs

        advantages, returns = compute_gae(ep_rew, ep_val, ep_done, cfg.gamma, cfg.gae_lambda)
        obs_buf.extend(ep_obs)
        act_buf.extend(ep_act)
        logp_buf.extend(ep_logp)
        adv_buf.extend(advantages.tolist())
        ret_buf.extend(returns.tolist())
        ep_returns.append(float(sum(ep_rew)))

    return (
        np.stack(obs_buf),
        np.asarray(act_buf, dtype=np.int64),
        np.asarray(logp_buf, dtype=np.float32),
        np.asarray(adv_buf, dtype=np.float32),
        np.asarray(ret_buf, dtype=np.float32),
        ep_returns,
    )


def train_ppo(
    config: DeceptionConfig | None = None,
    ppo_config: PPOConfig | None = None,
    policy: DeceptionPolicy | None = None,
    critic: ValueNetwork | None = None,
    verbose: bool = False,
) -> tuple[DeceptionPolicy, ValueNetwork, list[float]]:
    """Train a :class:`DeceptionPolicy` actor + :class:`ValueNetwork` critic with PPO.

    Args:
        config: Environment config (a fresh default is used if omitted).
        ppo_config: PPO hyperparameters (defaults if omitted).
        policy / critic: Continue training existing networks (new ones are
            built if omitted). Both must already match ``env.obs_dim`` /
            ``env.n_actions`` if supplied.
        verbose: Print a periodic moving-average return.

    Returns:
        ``(trained_policy, trained_critic, return_history)`` -- one history
        entry per episode. ``trained_policy`` alone is sufficient for
        evaluation/deployment (it satisfies the same ``select_action``
        interface as every other policy in this package); the critic is
        returned only in case training is to be resumed.
    """
    cfg = ppo_config or PPOConfig()
    torch.manual_seed(cfg.seed)
    env = DeceptionEnv(replace(config or DeceptionConfig(), seed=cfg.seed))

    policy = policy or DeceptionPolicy(env.obs_dim, env.n_actions, hidden_dim=cfg.hidden_dim)
    critic = critic or ValueNetwork(env.obs_dim, hidden_dim=cfg.hidden_dim)
    params = list(policy.parameters()) + list(critic.parameters())
    optimizer = torch.optim.Adam(params, lr=cfg.lr)

    history: list[float] = []
    moving_avg = 0.0

    for it in range(cfg.iterations):
        obs_np, act_np, old_logp_np, adv_np, ret_np, ep_returns = _collect_rollout(
            env, policy, critic, cfg
        )
        for r in ep_returns:
            moving_avg = 0.98 * moving_avg + 0.02 * r if history else r
            history.append(r)

        obs_t = torch.as_tensor(obs_np, dtype=torch.float32)
        act_t = torch.as_tensor(act_np, dtype=torch.long)
        old_logp_t = torch.as_tensor(old_logp_np, dtype=torch.float32)
        adv_t = torch.as_tensor(adv_np, dtype=torch.float32)
        ret_t = torch.as_tensor(ret_np, dtype=torch.float32)
        adv_t = (adv_t - adv_t.mean()) / (adv_t.std() + 1e-8)

        n = obs_t.shape[0]
        stop_early = False
        for _epoch in range(cfg.epochs):
            perm = torch.randperm(n)
            for start in range(0, n, cfg.minibatch_size):
                idx = perm[start : start + cfg.minibatch_size]
                mb_obs, mb_act = obs_t[idx], act_t[idx]
                mb_old_logp, mb_adv, mb_ret = old_logp_t[idx], adv_t[idx], ret_t[idx]

                dist = policy.distribution(mb_obs)
                new_logp = dist.log_prob(mb_act)
                entropy = dist.entropy()
                new_value = critic(mb_obs)

                ratio = torch.exp(new_logp - mb_old_logp)
                surr1 = ratio * mb_adv
                surr2 = torch.clamp(ratio, 1.0 - cfg.clip_eps, 1.0 + cfg.clip_eps) * mb_adv
                policy_loss = -torch.min(surr1, surr2).mean()
                value_loss = F.mse_loss(new_value, mb_ret)
                entropy_loss = -cfg.entropy_coef * entropy.mean()
                loss = policy_loss + cfg.value_coef * value_loss + entropy_loss

                optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(params, cfg.max_grad_norm)
                optimizer.step()

                approx_kl = float((mb_old_logp - new_logp).mean().item())
                if cfg.target_kl is not None and approx_kl > 1.5 * cfg.target_kl:
                    stop_early = True
                    break
            if stop_early:
                break

        if verbose and (it % 10 == 0 or it == cfg.iterations - 1):
            print(f"[ppo] iter {it:4d}/{cfg.iterations} avg_return={moving_avg:.2f}")

    return policy, critic, history
