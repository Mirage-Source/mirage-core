"""Threat-intelligence summarization of an enriched session.

Produces the ``session_summary`` the core leaves empty: a concise, analyst-grade
natural-language characterization of what an attacker did and why it matters. Two
backends, with the same graceful-degradation contract as the rest of MIRAGE:

* **template** (always available, no dependencies) -- a deterministic, extractive
  summary assembled from the structured intelligence (class, tools, MITRE, bait,
  timing). Never makes a network call.
* **LLM** (optional) -- a Claude-generated analyst summary via the official
  ``anthropic`` SDK, returning a short narrative plus a severity rating and
  recommended defensive actions. Falls back to the template automatically if the
  SDK is absent, no API key is configured, or the call fails -- so the pipeline is
  never blocked on an external service.

The LLM path defaults to ``claude-opus-4-8`` (override via ``MIRAGE_INTEL_MODEL``
for cost/latency, e.g. ``claude-haiku-4-5`` for high-volume enrichment). It uses
structured outputs so the result is always valid JSON, and a system prompt that
frames the task as **defensive** threat intelligence over an owned honeypot.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .ingest import ProductionSession
from .mitre import TechniqueHit

__all__ = ["ThreatIntelSummary", "summarize_session", "DEFAULT_MODEL"]

#: Default Claude model for the LLM summarizer. Override with MIRAGE_INTEL_MODEL.
DEFAULT_MODEL = "claude-opus-4-8"

_SEVERITIES = ("low", "medium", "high", "critical")

_SYSTEM_PROMPT = (
    "You are a defensive threat-intelligence analyst reviewing captured sessions "
    "from an SSH honeypot operated by your own organization on infrastructure it "
    "owns. Every session is an unauthorized intrusion attempt against a decoy; "
    "your job is to characterize the attacker's behavior and intent for the "
    "defenders' threat-intel record. Be precise, factual, and concise. Do not "
    "speculate beyond the evidence. Never include instructions for carrying out "
    "an attack."
)

_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "2-4 sentence analyst summary of the attacker's behavior and intent.",
        },
        "severity": {"type": "string", "enum": list(_SEVERITIES)},
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "1-3 concrete defensive recommendations.",
        },
    },
    "required": ["summary", "severity", "recommended_actions"],
    "additionalProperties": False,
}


@dataclass
class ThreatIntelSummary:
    """A structured threat-intel summary of a session.

    Attributes:
        summary: The natural-language analyst summary (the ``session_summary``).
        severity: Coarse severity rating (low / medium / high / critical).
        recommended_actions: Defensive recommendations.
        source: ``"llm"`` or ``"template"`` -- provenance of the summary.
    """

    summary: str
    severity: str = "low"
    recommended_actions: list[str] = field(default_factory=list)
    source: str = "template"


def _severity_from_signals(prod: ProductionSession, attacker_class: str) -> str:
    """Heuristic severity used by the template backend (and as an LLM fallback)."""
    if attacker_class == "apt" or prod.max_bait_escalation >= 2:
        return "critical"
    if prod.max_bait_escalation == 1 or attacker_class == "script_kiddie":
        return "high"
    if attacker_class == "manual_recon":
        return "medium"
    return "low"


def _template_summary(
    prod: ProductionSession,
    attacker_class: str,
    tool_signature: str,
    timing_label: str,
    techniques: list[TechniqueHit],
) -> ThreatIntelSummary:
    """Deterministic, dependency-free extractive summary."""
    n_cmds = prod.session.n_commands
    n_auth = len(prod.auth_attempts)
    technique_str = ", ".join(f"{t.technique.id} ({t.technique.name})" for t in techniques[:5])
    bait_str = ""
    if prod.bait_events:
        kinds = sorted({b.bait_type for b in prod.bait_events})
        accesses = sorted({b.access_type for b in prod.bait_events})
        bait_str = (
            f" Interacted with planted {', '.join(kinds)} bait "
            f"({', '.join(accesses)})."
        )

    summary = (
        f"{timing_label.capitalize()}-paced {attacker_class.replace('_', ' ')} from "
        f"{prod.client_ip} ran {n_cmds} command(s) after {n_auth} credential "
        f"attempt(s); tool signature: {tool_signature}.{bait_str}"
    )
    if technique_str:
        summary += f" Mapped ATT&CK techniques: {technique_str}."

    return ThreatIntelSummary(
        summary=summary,
        severity=_severity_from_signals(prod, attacker_class),
        recommended_actions=_template_actions(prod, attacker_class),
        source="template",
    )


def _template_actions(prod: ProductionSession, attacker_class: str) -> list[str]:
    """Canned defensive recommendations for the template backend."""
    actions = [f"Block/track source IP {prod.client_ip} and review correlated sessions."]
    if prod.max_bait_escalation >= 1:
        actions.append(
            "Rotate any credentials/keys matching the planted bait; the decoy was accessed."
        )
    if attacker_class in ("apt", "script_kiddie"):
        actions.append("Capture and analyze any fetched payloads for IOC extraction.")
    return actions[:3]


def _build_user_prompt(
    prod: ProductionSession,
    attacker_class: str,
    confidence: float,
    tool_signature: str,
    timing_label: str,
    techniques: list[TechniqueHit],
) -> str:
    """Render the structured session facts into a compact prompt."""
    commands = prod.session.raw_commands()
    command_block = "\n".join(f"  {i+1}. {c}" for i, c in enumerate(commands[:40]))
    technique_lines = "\n".join(
        f"  - {t.technique.id} {t.technique.name} [{t.technique.tactic}]" for t in techniques
    )
    bait_lines = "\n".join(
        f"  - {b.bait_type} ({b.access_type})" for b in prod.bait_events
    ) or "  (none)"
    creds = ", ".join(
        f"{a.username}:{a.credential}" for a in prod.auth_attempts[:10]
    ) or "(none)"

    return (
        f"Honeypot session {prod.session.session_id}\n"
        f"Source IP: {prod.client_ip}\n"
        f"SSH client banner: {prod.ssh_banner or 'unknown'}\n"
        f"Outcome: {prod.outcome or 'unknown'}\n"
        f"Preliminary classification: {attacker_class} (confidence {confidence:.2f})\n"
        f"Timing profile: {timing_label}; tool signature: {tool_signature}\n"
        f"Credential attempts: {creds}\n"
        f"Commands ({len(commands)}):\n{command_block or '  (none)'}\n"
        f"Bait interactions:\n{bait_lines}\n"
        f"MITRE ATT&CK techniques observed:\n{technique_lines or '  (none)'}\n\n"
        "Write the analyst summary, severity, and recommended defensive actions."
    )


def summarize_session(
    prod: ProductionSession,
    attacker_class: str,
    confidence: float,
    tool_signature: str,
    timing_label: str,
    techniques: list[TechniqueHit],
    use_llm: bool = False,
    model: str | None = None,
    client: Any | None = None,
) -> ThreatIntelSummary:
    """Summarize a session, optionally via Claude.

    Args:
        prod: The parsed session.
        attacker_class: The classifier's (or weak labeler's) attacker class.
        confidence: Classifier confidence.
        tool_signature / timing_label: Weak labels for context.
        techniques: MITRE technique hits from :func:`mirage.intel.mitre.map_mitre`.
        use_llm: If ``True``, attempt the Claude-backed summary (falls back to the
            template on any failure).
        model: Claude model id; defaults to ``MIRAGE_INTEL_MODEL`` env or
            :data:`DEFAULT_MODEL`.
        client: Optional pre-constructed ``anthropic.Anthropic`` client (for tests
            / dependency injection).

    Returns:
        A :class:`ThreatIntelSummary` (``source`` indicates which backend produced it).
    """
    template = _template_summary(prod, attacker_class, tool_signature, timing_label, techniques)
    if not use_llm:
        return template

    try:
        return _llm_summary(
            prod, attacker_class, confidence, tool_signature, timing_label,
            techniques, model=model, client=client, fallback_severity=template.severity,
        )
    except Exception:  # pragma: no cover - network/dependency failure path
        # Graceful degradation: never block enrichment on the external service.
        return template


def _llm_summary(
    prod: ProductionSession,
    attacker_class: str,
    confidence: float,
    tool_signature: str,
    timing_label: str,
    techniques: list[TechniqueHit],
    model: str | None,
    client: Any | None,
    fallback_severity: str,
) -> ThreatIntelSummary:
    """Call Claude for a structured analyst summary (official anthropic SDK)."""
    if client is None:
        import anthropic  # imported lazily so the package has no hard dependency

        client = anthropic.Anthropic()  # resolves ANTHROPIC_API_KEY from the env

    model = model or os.getenv("MIRAGE_INTEL_MODEL", DEFAULT_MODEL)
    user_prompt = _build_user_prompt(
        prod, attacker_class, confidence, tool_signature, timing_label, techniques
    )

    response = client.messages.create(
        model=model,
        max_tokens=1024,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
        output_config={"format": {"type": "json_schema", "schema": _OUTPUT_SCHEMA}},
    )
    text = next((b.text for b in response.content if b.type == "text"), "")
    data = json.loads(text)

    severity = data.get("severity", fallback_severity)
    if severity not in _SEVERITIES:
        severity = fallback_severity
    return ThreatIntelSummary(
        summary=data["summary"],
        severity=severity,
        recommended_actions=list(data.get("recommended_actions", []))[:3],
        source="llm",
    )
