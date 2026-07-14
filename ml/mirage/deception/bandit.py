from __future__ import annotations

import math
from dataclasses import replace
from pathlib import Path

import numpy as np

from .environment import DeceptionConfig, DeceptionEnv

__all__ = ["LinUCBBandit", "train_bandit"]


class LinUCBBandit:
    """Disjoint linear contextual bandit with an upper-confidence-bound rule.

    One ridge-regression model per action: ``A_a = ridge_lambda * I + sum x xᵀ``,
    ``b_a = sum r * x``, ``theta_a = A_a⁻¹ b_a``. The action selected while
    exploring maximises ``theta_aᵀx + alpha * sqrt(xᵀ A_a⁻¹ x)`` -- predicted
    reward plus a confidence bonus that shrinks as that action is tried more in
    similar contexts (Li et al., 2010, "A Contextual-Bandit Approach to
    Personalized News Article Recommendation").

    Args:
        obs_dim: Observation dimensionality.
        n_actions: Number of actions.
        alpha: Exploration strength (higher == more optimistic under uncertainty).
        ridge_lambda: Ridge regularisation strength (keeps ``A_a`` invertible
            from the first observation).
    """

    def __init__(
        self,
        obs_dim: int,
        n_actions: int,
        alpha: float = 1.0,
        ridge_lambda: float = 1.0,
    ) -> None:
        self.obs_dim = obs_dim
        self.n_actions = n_actions
        self.alpha = alpha
        self.ridge_lambda = ridge_lambda
        self.A = np.stack([ridge_lambda * np.eye(obs_dim) for _ in range(n_actions)])
        self.b = np.zeros((n_actions, obs_dim))

    def _theta(self, action: int) -> np.ndarray:
        return np.linalg.solve(self.A[action], self.b[action])

    def _ucb_scores(self, x: np.ndarray) -> np.ndarray:
        """Predicted reward + confidence bonus for every action, given context ``x``."""
        scores = np.zeros(self.n_actions)
        for a in range(self.n_actions):
            A_inv = np.linalg.inv(self.A[a])
            theta = A_inv @ self.b[a]
            mean = float(theta @ x)
            bonus = self.alpha * math.sqrt(max(float(x @ A_inv @ x), 0.0))
            scores[a] = mean + bonus
        return scores

    def select_action(self, obs: np.ndarray, greedy: bool = True) -> int:
        """Choose an action. ``greedy=True`` drops the UCB bonus (pure exploitation,
        used for evaluation, so the bandit is compared to other policies on equal
        footing); ``greedy=False`` uses the full UCB rule (used while training)."""
        x = np.asarray(obs, dtype=np.float64)
        if greedy:
            means = np.array([float(self._theta(a) @ x) for a in range(self.n_actions)])
            return int(np.argmax(means))
        return int(np.argmax(self._ucb_scores(x)))

    def update(self, obs: np.ndarray, action: int, reward: float) -> None:
        """Incorporate one (context, action, immediate reward) observation."""
        x = np.asarray(obs, dtype=np.float64)
        self.A[action] += np.outer(x, x)
        self.b[action] += reward * x

    def save(self, path: str | Path) -> None:
        """Serialize to a single ``.npz`` file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        np.savez(
            path,
            A=self.A,
            b=self.b,
            alpha=np.asarray(self.alpha),
            ridge_lambda=np.asarray(self.ridge_lambda),
            obs_dim=np.asarray(self.obs_dim),
            n_actions=np.asarray(self.n_actions),
        )

    @classmethod
    def load(cls, path: str | Path) -> "LinUCBBandit":
        with np.load(Path(path)) as data:
            bandit = cls(
                obs_dim=int(data["obs_dim"]),
                n_actions=int(data["n_actions"]),
                alpha=float(data["alpha"]),
                ridge_lambda=float(data["ridge_lambda"]),
            )
            bandit.A = data["A"]
            bandit.b = data["b"]
        return bandit


def train_bandit(
    config: DeceptionConfig | None = None,
    bandit: LinUCBBandit | None = None,
    episodes: int = 4000,
    alpha: float = 1.0,
    ridge_lambda: float = 1.0,
    seed: int = 0,
) -> tuple[LinUCBBandit, list[float]]:
    """Train a LinUCB bandit against the attacker simulator, one turn at a time.

    Each step is treated as an *independent* contextual-bandit decision: the
    bandit updates on the immediate reward that step returns and never sees a
    return-to-go. Episode return is tracked only for reporting/comparison, not
    used in the update rule -- that is precisely the myopia under test.

    Args:
        config: Environment config (a fresh default is used if omitted).
        bandit: Bandit to continue training (a new one is built if omitted).
        episodes: Number of attacker sessions to train against.
        alpha / ridge_lambda: LinUCB hyperparameters (only used if ``bandit`` is
            not supplied).
        seed: RNG seed for the environment.

    Returns:
        ``(trained_bandit, return_history)`` -- one history entry per episode.
    """
    env = DeceptionEnv(replace(config or DeceptionConfig(), seed=seed))
    bandit = bandit or LinUCBBandit(env.obs_dim, env.n_actions, alpha=alpha, ridge_lambda=ridge_lambda)

    history: list[float] = []
    for _ in range(episodes):
        obs = env.reset()
        done = False
        episode_return = 0.0
        while not done:
            action = bandit.select_action(obs, greedy=False)
            next_obs, reward, done, _ = env.step(action)
            bandit.update(obs, action, reward)
            obs = next_obs
            episode_return += reward
        history.append(episode_return)

    return bandit, history
