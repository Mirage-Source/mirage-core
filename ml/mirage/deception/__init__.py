"""Phase 5 -- adaptive deception: the intelligent, self-steering honeypot.

The static shell answers every attacker the same way. Phase 5 replaces that with
a **learned policy** that chooses how to respond turn-by-turn -- enrich, surface
bait, stall, fake success, or stay minimal -- to keep attackers engaged and bait
them into revealing intent. Because the live shell exposes no response hook yet,
the policy is trained against a controllable **attacker simulator** whose
dynamics encode an explicit, re-fittable hypothesis about how engagement and
intent-revelation respond to honeypot behavior; the same policy fine-tunes online
once the core can act on its choices.

It composes with the rest of MIRAGE: the simulator's reward is the very
intelligence Phase 4 extracts (commands, bait escalation), and the eventual live
state will be the Phase-2/3 embedding + Phase-4 features of the session so far.

Modules
-------
* :mod:`~mirage.deception.actions` -- the deception action space.
* :mod:`~mirage.deception.environment` -- the attacker simulator (RL env).
* :mod:`~mirage.deception.policy` -- learned policy + fixed/heuristic baselines.
* :mod:`~mirage.deception.train` -- REINFORCE training + baseline comparison.
"""

from __future__ import annotations

from .actions import ACTION_DESCRIPTIONS, DeceptionAction
from .environment import (
    ARCHETYPES,
    COMMAND_CATEGORIES,
    AttackerArchetype,
    DeceptionConfig,
    DeceptionEnv,
)
from .policy import DeceptionPolicy, FixedPolicy, HeuristicPolicy, RandomPolicy

__all__ = [
    "DeceptionAction",
    "ACTION_DESCRIPTIONS",
    "DeceptionEnv",
    "DeceptionConfig",
    "AttackerArchetype",
    "ARCHETYPES",
    "COMMAND_CATEGORIES",
    "DeceptionPolicy",
    "FixedPolicy",
    "RandomPolicy",
    "HeuristicPolicy",
]
