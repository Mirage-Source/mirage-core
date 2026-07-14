from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from threading import Lock

import numpy as np

from ..data.bait import BAIT_PATTERNS
from .actions import DeceptionAction
from .environment import COMMAND_CATEGORIES

__all__ = [
    "categorize_live_command",
    "LiveSessionTracker",
    "LiveDeceptionEngine",
]

_CAT_INDEX = {c: i for i, c in enumerate(COMMAND_CATEGORIES)}
_SENSITIVE = {"read_sensitive", "escalate", "exfil"}

# Reuse the same planted-secret regexes the offline bait inference uses
# (mirage.data.bait) as the strongest possible read_sensitive signal: if a
# command matches one of these, it is touching (or trying to touch) a
# credential-class file, live or offline.
_SENSITIVE_FILE_RE = re.compile(
    "|".join(p.pattern for _bait_type, p in BAIT_PATTERNS), re.IGNORECASE
)

# Ordered (category, pattern) rules; first match wins. Order encodes priority
# -- higher-intent / more specific categories are checked before generic ones,
# so e.g. `curl --data @/etc/shadow https://...` is classified exfil, not
# merely download or read_sensitive.
_EXFIL_RE = re.compile(
    r"(?:curl|wget)\b.*?(?:-d\b|--data|-F\b|--upload-file|-T\b)|"
    r"\bnc\b\s+-?\w*\s*\d{1,3}(?:\.\d{1,3}){3}|"
    r"\bscp\b.*?@.*?:|"
    r"base64\s+.*?\|\s*(?:curl|nc)",
    re.IGNORECASE,
)
_ESCALATE_RE = re.compile(
    r"\bsudo\b|\bsu\b(?:\s|$)|chmod\s+\+?[24]?7?7?s|setuid|setcap|"
    r"useradd|adduser|passwd\s+root|/etc/sudoers|crontab\s+-e|"
    r"authorized_keys",
    re.IGNORECASE,
)
_DOWNLOAD_RE = re.compile(
    r"\b(?:wget|curl|tftp|ftpget)\b",
    re.IGNORECASE,
)

_CATEGORY_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("exfil", _EXFIL_RE),
    ("read_sensitive", _SENSITIVE_FILE_RE),
    ("escalate", _ESCALATE_RE),
    ("download", _DOWNLOAD_RE),
]


def categorize_live_command(command: str) -> str:
    """Classify one raw command line into a :data:`COMMAND_CATEGORIES` bucket.

    Falls back to ``"recon"`` -- the majority class in every archetype's
    distribution (see :data:`~mirage.deception.environment.ARCHETYPES`) -- for
    anything unmatched, which includes plain enumeration commands
    (``ls``, ``whoami``, ``uname``, ``pwd``, ``id``, ``ps``, ...).
    """
    if not command or not command.strip():
        return "recon"
    for category, pattern in _CATEGORY_RULES:
        if pattern.search(command):
            return category
    return "recon"


@dataclass
class LiveSessionTracker:
    """Running counters for one live session, mirroring ``DeceptionEnv`` state.

    Attributes:
        max_steps: Same normalisation denominator used in training
            (``DeceptionConfig.max_steps``); does not cut the session off --
            a real attacker's session isn't capped by this adapter, only the
            step/commands-captured features saturate at 1.0 past this point,
            same as an episode that reached ``max_steps`` in training would
            have shown right before terminating.
    """

    max_steps: int = 25
    step_idx: int = 0
    commands_captured: int = 0
    bait_captured: int = 0
    seen_categories: set = field(default_factory=set)
    last_seen: float = field(default_factory=time.monotonic)

    def observe(self, category: str) -> "list[float]":
        """Build the observation vector for the command that just arrived,
        *before* that command's counters are folded in -- matching
        ``DeceptionEnv._observe``, which reports the state the policy
        conditions its choice on, prior to applying this turn's effects."""
        obs_dim = 1 + len(COMMAND_CATEGORIES) + 4
        obs = [0.0] * obs_dim
        obs[0] = min(self.step_idx / self.max_steps, 1.0)
        obs[1 + _CAT_INDEX[category]] = 1.0
        base = 1 + len(COMMAND_CATEGORIES)
        obs[base + 0] = min(self.commands_captured / self.max_steps, 1.0)
        obs[base + 1] = len(self.seen_categories) / len(COMMAND_CATEGORIES)
        obs[base + 2] = min(self.bait_captured, 3) / 3.0
        obs[base + 3] = 1.0 if category in _SENSITIVE else 0.0
        return obs

    def advance(self, category: str, bait_hit: bool) -> None:
        """Fold this turn's command into the running counters."""
        self.commands_captured += 1
        self.seen_categories.add(category)
        if bait_hit:
            self.bait_captured += 1
        self.step_idx += 1
        self.last_seen = time.monotonic()


class LiveDeceptionEngine:
    """Owns one :class:`LiveSessionTracker` per live session and the loaded policy.

    Thread-safe (a single lock guards the tracker dict; per-call policy
    inference is cheap -- a few small linear layers or a ridge-regression
    lookup -- so a coarse lock is not a bottleneck at honeypot traffic rates).
    Stale trackers (no command for ``session_ttl_seconds``) are evicted
    opportunistically on each call so long-running deployment doesn't leak
    memory across an unbounded stream of sessions, without requiring the
    caller to explicitly signal session end.
    """

    def __init__(self, policy, max_steps: int = 25, session_ttl_seconds: float = 900.0) -> None:
        self._policy = policy
        self._max_steps = max_steps
        self._ttl = session_ttl_seconds
        self._sessions: dict[str, LiveSessionTracker] = {}
        self._lock = Lock()

    def _get_tracker(self, session_id: str) -> LiveSessionTracker:
        tracker = self._sessions.get(session_id)
        if tracker is None:
            tracker = LiveSessionTracker(max_steps=self._max_steps)
            self._sessions[session_id] = tracker
        return tracker

    def _evict_stale(self) -> None:
        now = time.monotonic()
        stale = [sid for sid, t in self._sessions.items() if now - t.last_seen > self._ttl]
        for sid in stale:
            del self._sessions[sid]

    def decide(self, session_id: str, command: str, bait_hit: bool = False) -> dict:
        """Classify, observe, decide, and advance state for one live command.

        Returns:
            ``{"action": int, "action_name": str, "category": str}``.
        """
        category = categorize_live_command(command)
        with self._lock:
            self._evict_stale()
            tracker = self._get_tracker(session_id)
            obs = np.asarray(tracker.observe(category), dtype=np.float32)
            action = self._policy.select_action(obs, greedy=True)
            tracker.advance(category, bait_hit)

        return {
            "action": int(action),
            "action_name": DeceptionAction(int(action)).name,
            "category": category,
        }


def load_engine_from_env() -> LiveDeceptionEngine:
    """Build a :class:`LiveDeceptionEngine` from ``MIRAGE_DECEPTION_*`` env vars.

    Reads ``MIRAGE_DECEPTION_CHECKPOINT`` (required), ``MIRAGE_DECEPTION_ALGO``
    (``ppo`` | ``reinforce`` | ``bandit``, default ``ppo``),
    ``MIRAGE_DECEPTION_MAX_STEPS`` (default 25), and
    ``MIRAGE_DECEPTION_SESSION_TTL_SECONDS`` (default 900).
    """
    import os

    from .bandit import LinUCBBandit
    from .train import load_policy_checkpoint

    checkpoint = os.environ.get("MIRAGE_DECEPTION_CHECKPOINT")
    if not checkpoint:
        raise RuntimeError(
            "MIRAGE_DECEPTION_CHECKPOINT is not set -- point it at one of "
            "artifacts/deception/{ppo.pt,reinforce_a2c.pt,bandit_linucb.npz}."
        )
    algo = os.environ.get("MIRAGE_DECEPTION_ALGO", "ppo").lower()
    max_steps = int(os.environ.get("MIRAGE_DECEPTION_MAX_STEPS", "25"))
    ttl = float(os.environ.get("MIRAGE_DECEPTION_SESSION_TTL_SECONDS", "900"))

    if algo == "bandit":
        policy = LinUCBBandit.load(checkpoint)
    elif algo in ("ppo", "reinforce"):
        policy = load_policy_checkpoint(checkpoint)
    else:
        raise ValueError(f"Unknown MIRAGE_DECEPTION_ALGO={algo!r} (expected ppo|reinforce|bandit)")

    return LiveDeceptionEngine(policy, max_steps=max_steps, session_ttl_seconds=ttl)
