"""STIX 2.1 bundle export for sharing session intelligence.

Renders an enriched session as a STIX 2.1 bundle so MIRAGE's findings can be
ingested by any TAXII/STIX-aware platform (MISP, OpenCTI, a SIEM). We hand-build
the JSON (stdlib only) rather than depend on the ``stix2`` library, keeping the
package dependency-light and the output inspectable; the structure follows the
STIX 2.1 spec for the object types an SSH honeypot produces:

* an **identity** SDO for the MIRAGE sensor (the source of the intel),
* an **indicator** SDO for the attacker's source IP,
* one **attack-pattern** SDO per observed MITRE ATT&CK technique (with an
  ``external_reference`` into the ATT&CK catalogue), and
* **relationship** SROs tying the indicator to the techniques it ``indicates``.

If the ``stix2`` library is installed you may prefer to re-serialize through it
for strict validation; the dict produced here is already spec-shaped.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .ingest import ProductionSession
from .mitre import TechniqueHit

__all__ = ["to_stix_bundle", "MIRAGE_IDENTITY_NAME"]

MIRAGE_IDENTITY_NAME = "MIRAGE SSH Honeypot"
_ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _id(stix_type: str) -> str:
    """STIX 2.1 object id: ``<type>--<uuidv4>``."""
    return f"{stix_type}--{uuid.uuid4()}"


def _technique_url(technique_id: str) -> str:
    """ATT&CK web URL for a technique id (sub-techniques use a slashed path)."""
    return _ATTACK_BASE_URL + technique_id.replace(".", "/")


def to_stix_bundle(
    prod: ProductionSession,
    attacker_class: str,
    confidence: float,
    techniques: list[TechniqueHit],
    summary: str | None = None,
) -> dict[str, Any]:
    """Build a STIX 2.1 bundle from an enriched session.

    Args:
        prod: The parsed session.
        attacker_class: Predicted attacker class (used in the indicator labels).
        confidence: Classifier confidence (recorded on the indicator).
        techniques: MITRE technique hits.
        summary: Optional analyst summary, attached as the indicator description.

    Returns:
        A STIX 2.1 ``bundle`` dict ready to ``json.dumps`` or POST to a TAXII server.
    """
    now = _now_iso()
    identity_id = _id("identity")
    objects: list[dict[str, Any]] = []

    # The sensor that produced the intel.
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": MIRAGE_IDENTITY_NAME,
            "identity_class": "system",
            "description": "AI-augmented SSH honeypot; defensive research sensor.",
        }
    )

    # Indicator for the attacker's source IP.
    indicator_id = _id("indicator")
    objects.append(
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": f"SSH honeypot intrusion from {prod.client_ip}",
            "description": summary or f"Observed {attacker_class} activity.",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{prod.client_ip}']",
            "pattern_type": "stix",
            "valid_from": now,
            "labels": [attacker_class, f"confidence:{confidence:.2f}"],
            "confidence": int(round(max(0.0, min(1.0, confidence)) * 100)),
        }
    )

    # One attack-pattern per MITRE technique, plus a relationship to the indicator.
    for hit in techniques:
        tech = hit.technique
        ap_id = _id("attack-pattern")
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "name": tech.name,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech.id,
                        "url": _technique_url(tech.id),
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": tech.tactic.lower().replace(" ", "-"),
                    }
                ],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _id("relationship"),
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": ap_id,
                "description": hit.evidence,
            }
        )

    return {
        "type": "bundle",
        "id": _id("bundle"),
        "objects": objects,
    }
