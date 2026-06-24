"""Attacker taxonomy and programmatic weak labels.

The live honeypot has **no ground-truth attacker labels** -- nobody annotates who
each connection was. So, exactly as Phase 1 did for timing and tool signatures, we
generate **weak labels** programmatically from interpretable signals, then train a
smooth, embedding-aware classifier to distil and generalise them (with calibrated
confidence). This is the Snorkel-style weak-supervision pattern: cheap, noisy,
transparent labels in; a better-calibrated learned model out.

The four classes (the README's taxonomy), ordered by hands-on sophistication:

* **automated_scanner** -- a bot: fast/regular cadence, shallow, often brute-force
  or a one-shot scripted payload drop. The bulk of internet background radiation.
* **script_kiddie** -- ran a recognisable offensive *toolkit* they did not write
  (dropper / miner / DDoS botnet) but with some interaction.
* **manual_recon** -- a human exploring by hand: bursty/slow cadence, enumeration,
  no automated payload.
* **apt** -- high-intent / hands-on-keyboard: bait **copy/exfil**, persistence +
  defence-evasion, multi-stage. The sessions worth waking someone up for.

The labelling function is deliberately auditable -- every label carries a short
rationale string -- so the weak supervision can be inspected and swept for the
paper, never a black box.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .features import IntelFeatures, extract_features
from .ingest import ProductionSession

__all__ = [
    "AttackerClass",
    "ATTACKER_CLASSES",
    "WeakLabel",
    "weak_label",
]

AttackerClass = Literal["automated_scanner", "script_kiddie", "manual_recon", "apt"]
#: Canonical order — also the class-index order used by the classifier head.
ATTACKER_CLASSES: tuple[AttackerClass, ...] = (
    "automated_scanner",
    "script_kiddie",
    "manual_recon",
    "apt",
)


@dataclass
class WeakLabel:
    """A programmatic weak label with its confidence and rationale.

    Attributes:
        attacker_class: The assigned class.
        confidence: Heuristic confidence in ``[0, 1]`` (used to weight the label
            during training, not as the model's output confidence).
        rationale: Short human-readable justification (auditable supervision).
    """

    attacker_class: AttackerClass
    confidence: float
    rationale: str


def weak_label(
    prod: ProductionSession, features: IntelFeatures | None = None
) -> WeakLabel:
    """Assign a weak attacker-class label from interpretable behavioural signals.

    Decision order (highest intent first): APT → script-kiddie → manual recon →
    automated scanner, with sensible fallbacks. See the module docstring.
    """
    f = features or extract_features(prod)
    fd = f.as_dict()
    tool = f.tool_signature
    timing = f.timing_label

    n_cmd = fd["n_commands"]
    escalation = fd["max_bait_escalation"]
    has_exfil = fd["has_exfil_attempt"] > 0
    automated = timing == "automated" or fd["frac_superhuman"] >= 0.8
    human = timing == "human"

    # 1. APT — data-theft intent or hands-on persistence/evasion.
    if has_exfil or escalation >= 2:
        return WeakLabel("apt", 0.9, "bait copy/exfil — clear data-theft intent")
    if tool in {"persistence", "defense_evasion"} and n_cmd >= 5 and not automated:
        return WeakLabel("apt", 0.7, f"hands-on {tool} across multiple commands")

    # 2. Script kiddie — ran a recognisable offensive toolkit.
    if tool in {"dropper", "miner", "ddos_botnet"}:
        if automated and n_cmd <= 4:
            return WeakLabel("automated_scanner", 0.7, f"fast scripted {tool} drop")
        return WeakLabel("script_kiddie", 0.7, f"ran {tool} toolkit with interaction")

    # 3. Manual recon — human-paced enumeration, no payload.
    if human and tool in {"recon", "other"}:
        return WeakLabel("manual_recon", 0.7, "human cadence, recon/exploration only")

    # 4. Automated scanner — fast/shallow/brute-force.
    if automated:
        return WeakLabel("automated_scanner", 0.7, "automated cadence, no payload")
    if fd["n_auth_attempts"] >= 3 and n_cmd <= 2:
        return WeakLabel("automated_scanner", 0.6, "brute-force, little/no shell activity")

    # Fallback: lean on timing, with a bot-dominated prior.
    if human:
        return WeakLabel("manual_recon", 0.5, "human timing, otherwise ambiguous")
    return WeakLabel("automated_scanner", 0.4, "default prior (traffic is bot-dominated)")
