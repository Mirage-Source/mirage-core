"""A simulated attacker environment for learning deception policies.

To learn *when* to deceive, the policy needs to interact with an attacker that
**reacts** to its choices -- and we cannot A/B-test strategies on live intruders
without a control channel into the (currently hardcoded) shell. So we build a
controllable, seedable **attacker simulator**: a small reinforcement-learning
environment whose dynamics encode an explicit, inspectable hypothesis about how
attacker engagement and intent-revelation respond to honeypot behavior.

This is the same move as a model-based RL testbed in robotics or a generative
behavioral model in computational neuroscience: a known generative process you
can train and probe against before deploying to the real, noisy system. The
"physics" below (how each command category × deception action shifts engagement,
suspicion, and intelligence yield) is the falsifiable model -- it is meant to be
**re-fit against real captured reactions** once the core exposes a response hook,
at which point the same policy fine-tunes online.

Episode dynamics
----------------
An episode is one attacker session. Each turn:

1. the attacker issues a command in one of five **categories** (recon → download
   → read_sensitive → escalate → exfil), drawn from its hidden archetype;
2. the honeypot observes the command and the session so far and picks a
   :class:`~mirage.deception.actions.DeceptionAction`;
3. the action shifts the attacker's hidden **goodwill** (engagement reservoir):
   plausible, curiosity-feeding responses raise it; clumsy or frustrating ones
   raise **suspicion** and lower it;
4. the honeypot **captures** the command (+1 base intel), plus a novelty bonus for
   a newly-seen category and a large **bait** payoff when it surfaces a planted
   secret *at the moment* the attacker probes something sensitive -- that is the
   jackpot, because it converts a visit into evidence of read→copy→exfil intent;
5. the attacker continues with probability ``sigmoid(goodwill)`` (and below
   ``max_steps``), else disconnects.

The cumulative reward is total intelligence extracted. A static "always minimal"
honeypot (today's behavior) accumulates little; the policy's job is to learn the
category-conditioned strategy that keeps attackers engaged and baits them into
revealing intent.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

import numpy as np

from .actions import DeceptionAction, N_ACTIONS

__all__ = [
    "COMMAND_CATEGORIES",
    "ARCHETYPES",
    "AttackerArchetype",
    "DeceptionConfig",
    "DeceptionEnv",
]

#: Attacker command categories, in rough kill-chain order.
COMMAND_CATEGORIES: tuple[str, ...] = (
    "recon", "download", "read_sensitive", "escalate", "exfil",
)
_CAT_INDEX = {c: i for i, c in enumerate(COMMAND_CATEGORIES)}
#: Categories where surfacing bait reveals intent (the jackpot window).
_SENSITIVE = {"read_sensitive", "escalate", "exfil"}


@dataclass(frozen=True)
class AttackerArchetype:
    """A hidden attacker profile driving command choice and persistence.

    Attributes:
        name: Archetype label (matches the Phase-4 taxonomy).
        preferences: Unnormalized affinity over :data:`COMMAND_CATEGORIES`.
        persistence: Starting goodwill (higher == stays longer by default).
    """

    name: str
    preferences: tuple[float, ...]
    persistence: float

    def distribution(self) -> np.ndarray:
        p = np.asarray(self.preferences, dtype=np.float64)
        return p / p.sum()


#: The four archetypes, mirroring the Phase-4 classes. Scanners are shallow and
#: impatient; APTs probe sensitive resources and stay longer.
ARCHETYPES: tuple[AttackerArchetype, ...] = (
    AttackerArchetype("automated_scanner", (6, 3, 0.3, 0.2, 0.1), persistence=0.2),
    AttackerArchetype("script_kiddie", (3, 5, 1.0, 1.0, 0.5), persistence=0.6),
    AttackerArchetype("manual_recon", (6, 2, 2.0, 1.0, 0.3), persistence=1.0),
    AttackerArchetype("apt", (2, 2, 3.0, 3.0, 2.5), persistence=1.4),
)


def _effects(category: str, action: DeceptionAction) -> tuple[float, float, float, float]:
    """The deception physics: ``(engagement, suspicion, bait_gain, capture_bonus)``.

    Encodes how each (command category, response strategy) pair moves the
    attacker. This is the model's core hypothesis -- deliberately small and
    auditable so it can be swept and later re-fit on real data.
    """
    eng = susp = bait = cap = 0.0
    sensitive = category in _SENSITIVE

    if action == DeceptionAction.MINIMAL:
        # Plain and realistic: mildly reassuring, but feeds no curiosity.
        susp = -0.10
    elif action == DeceptionAction.ENRICH:
        if category in ("recon", "download"):
            eng, cap = 0.55, 0.3       # convincing detail keeps exploration going
        else:
            eng, susp = 0.05, 0.10     # over-elaborating a sensitive op is slightly off
    elif action == DeceptionAction.SURFACE_BAIT:
        if sensitive:
            eng, susp, bait = 0.45, -0.05, 3.0   # jackpot: intent revealed on bait
        else:
            susp = 0.60                # a secret appearing during basic recon is suspicious
    elif action == DeceptionAction.STALL:
        if category == "escalate":
            eng, susp = 0.10, -0.10    # permission-denied is realistic for privilege ops
        else:
            eng, susp = -0.45, 0.35    # friction elsewhere frustrates / tips the hand
    elif action == DeceptionAction.FAKE_SUCCESS:
        if category in ("download", "escalate"):
            eng, cap = 0.50, 0.5       # draws out the next stage; reveals intent
        else:
            susp = 0.35
    return eng, susp, bait, cap


@dataclass
class DeceptionConfig:
    """Environment configuration.

    Attributes:
        max_steps: Hard cap on commands per episode.
        decay: Per-step goodwill decay (models finite patience).
        archetype_weights: Sampling weights over :data:`ARCHETYPES` (defaults
            uniform); set to emphasise the realistic bot-heavy mix if desired.
        novelty_bonus: Reward for the first command in a new category.
        seed: RNG seed.
    """

    max_steps: int = 25
    decay: float = 0.18
    archetype_weights: tuple[float, ...] | None = None
    novelty_bonus: float = 0.5
    seed: int | None = None


class DeceptionEnv:
    """A Gym-style single-agent environment for deception-policy learning.

    Observations are fixed-length float vectors (see :meth:`_observe`); actions
    are :class:`DeceptionAction` indices. ``step`` returns
    ``(obs, reward, done, info)``.
    """

    def __init__(self, config: DeceptionConfig | None = None) -> None:
        self.config = config or DeceptionConfig()
        self.rng = random.Random(self.config.seed)
        self._np_rng = np.random.default_rng(self.config.seed)
        self.obs_dim = 1 + len(COMMAND_CATEGORIES) + 4  # step, cat one-hot, 4 counters
        self.n_actions = N_ACTIONS
        self._reset_state()

    # -- State management ---------------------------------------------------

    def _reset_state(self) -> None:
        self.archetype: AttackerArchetype = ARCHETYPES[0]
        self.goodwill = 0.0
        self.step_idx = 0
        self.current_category = "recon"
        self.seen_categories: set[str] = set()
        self.commands_captured = 0
        self.bait_captured = 0
        self.done = True

    def reset(self) -> np.ndarray:
        """Start a new episode; returns the initial observation."""
        weights = self.config.archetype_weights
        self.archetype = self.rng.choices(
            ARCHETYPES, weights=list(weights) if weights else None, k=1
        )[0]
        self.goodwill = self.archetype.persistence
        self.step_idx = 0
        self.seen_categories = set()
        self.commands_captured = 0
        self.bait_captured = 0
        self.done = False
        self.current_category = self._sample_category()
        return self._observe()

    def _sample_category(self) -> str:
        idx = int(self._np_rng.choice(len(COMMAND_CATEGORIES), p=self.archetype.distribution()))
        return COMMAND_CATEGORIES[idx]

    def _observe(self) -> np.ndarray:
        """Build the observation the policy conditions on (attacker state is hidden)."""
        obs = np.zeros(self.obs_dim, dtype=np.float32)
        obs[0] = self.step_idx / self.config.max_steps
        obs[1 + _CAT_INDEX[self.current_category]] = 1.0
        base = 1 + len(COMMAND_CATEGORIES)
        obs[base + 0] = self.commands_captured / self.config.max_steps
        obs[base + 1] = len(self.seen_categories) / len(COMMAND_CATEGORIES)
        obs[base + 2] = min(self.bait_captured, 3) / 3.0
        obs[base + 3] = 1.0 if self.current_category in _SENSITIVE else 0.0
        return obs

    # -- Transition ---------------------------------------------------------

    def step(self, action: int) -> tuple[np.ndarray, float, bool, dict]:
        """Apply a deception action; return ``(obs, reward, done, info)``."""
        if self.done:
            raise RuntimeError("step() called on a finished episode; call reset()")
        act = DeceptionAction(int(action))
        category = self.current_category
        eng, susp, bait_gain, cap_bonus = _effects(category, act)

        # Capture this command (+ novelty + bait payoff).
        reward = 1.0 + cap_bonus
        if category not in self.seen_categories:
            reward += self.config.novelty_bonus
            self.seen_categories.add(category)
        if bait_gain > 0:
            self.bait_captured += 1
            reward += bait_gain
        self.commands_captured += 1

        # Update the hidden engagement reservoir and decide whether to continue.
        self.goodwill += (eng - susp) - self.config.decay
        self.step_idx += 1

        continue_prob = 1.0 / (1.0 + math.exp(-self.goodwill))
        attacker_leaves = self.rng.random() > continue_prob
        if attacker_leaves or self.step_idx >= self.config.max_steps:
            self.done = True
        else:
            self.current_category = self._sample_category()

        info = {
            "category": category,
            "action": act.name,
            "archetype": self.archetype.name,
            "goodwill": self.goodwill,
            "bait_captured": self.bait_captured,
            "commands_captured": self.commands_captured,
        }
        return self._observe(), float(reward), self.done, info
