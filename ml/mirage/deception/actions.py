"""The deception action space -- what an *intelligent* honeypot can choose to do.

Today's MIRAGE shell is a fixed state machine: it answers a handful of commands
and returns ``command not found`` for the rest. That is a *static* deception
policy -- it does the same thing regardless of who is connected or what they are
after, so a curious attacker disengages the moment the illusion cracks. The
premise of Phase 5 is that the honeypot should instead **choose its response
strategy in real time** to maximize how long an attacker stays and how much
intelligence they reveal.

This module defines the discrete strategy choices the policy selects among. Each
maps to a concrete way the (future LLM-driven) shell could answer the *next*
command -- the actions are deliberately response-*strategies*, not literal shell
output, so the same policy works whether the output is templated or LLM-
generated, and so it can be wired into the core's ``ResponseSource`` hook later
without retraining.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["DeceptionAction", "ACTION_DESCRIPTIONS"]


class DeceptionAction(IntEnum):
    """A deception response strategy the honeypot may choose each turn.

    Integer values are the policy's action indices (stable -- do not reorder).
    """

    MINIMAL = 0          # Terse, realistic, low-effort response (today's default).
    ENRICH = 1           # Fabricate rich, believable output to feed curiosity.
    SURFACE_BAIT = 2     # Make a planted secret discoverable on this turn.
    STALL = 3            # Slow / permission-denied / "try again" friction.
    FAKE_SUCCESS = 4     # Pretend a risky action succeeded to elicit the next stage.


#: Human-readable rationale for each action (for dashboards / the paper).
ACTION_DESCRIPTIONS: dict[DeceptionAction, str] = {
    DeceptionAction.MINIMAL: "Answer plainly and realistically; spend no deception effort.",
    DeceptionAction.ENRICH: "Return convincing, detailed output to keep a curious attacker exploring.",
    DeceptionAction.SURFACE_BAIT: "Expose a planted credential/key so intent (read→copy→exfil) is revealed.",
    DeceptionAction.STALL: "Introduce friction (latency, permission denied) to slow or test the attacker.",
    DeceptionAction.FAKE_SUCCESS: "Fake success of a risky operation to draw out the attacker's next step.",
}

#: Number of actions in the space.
N_ACTIONS = len(DeceptionAction)
