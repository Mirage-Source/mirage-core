"""The real-time intelligence pipeline: session document -> intelligence.

This is the orchestrator that turns one live-core ``session_document`` into the
structured intelligence the core's ``sessions`` table is waiting for
(``attacker_class``, ``classifier_confidence``, ``cluster_id``,
``mitre_techniques``, ``session_summary``) plus richer side outputs (tool
signature, timing label, severity, STIX bundle). It is pure compute -- no
database I/O -- so it slots behind any driver (the existing polling worker, an
API backfill, a batch job) without coupling the ML to the transport.

Graceful degradation is preserved end to end:

* **No trained classifier** -> fall back to the interpretable weak label
  (``mirage.intel.taxonomy.weak_label``), so a class + confidence is always
  produced.
* **No LLM / API key** -> the deterministic template summary
  (``mirage.intel.summarize``).
* **No embedding** -> features-only classification.

So the pipeline runs the moment a session lands, and only *improves* as the
trained classifier and the LLM summarizer are switched on.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np

from .classifier import SessionClassifier, classify
from .features import extract_features
from .ingest import parse_session_document
from .mitre import map_mitre
from .stix import to_stix_bundle
from .summarize import ThreatIntelSummary, summarize_session
from .taxonomy import weak_label

__all__ = ["IntelligenceResult", "IntelPipeline", "enrich_session_document"]


@dataclass
class IntelligenceResult:
    """The full intelligence for one session.

    The first five fields map 1:1 onto the core's ``sessions`` intelligence
    columns; the rest are MIRAGE-side enrichment.

    Attributes:
        session_id: The session this intelligence describes.
        attacker_class: Predicted attacker class.
        classifier_confidence: Confidence in ``[0, 1]``.
        cluster_id: Phase-3 cluster id (``None`` unless a clusterer is wired in).
        mitre_techniques: Ordered ATT&CK technique ids.
        session_summary: Natural-language analyst summary.
        tool_signature: Weak tool-family label.
        timing_label: Automated / human / unknown.
        severity: low / medium / high / critical.
        recommended_actions: Defensive recommendations.
        classifier_source: ``"model"`` (trained classifier) or ``"weak_label"``.
        summary_source: ``"llm"`` or ``"template"``.
        stix_bundle: Optional STIX 2.1 bundle.
        features: The extracted feature vector as a name->value dict.
    """

    session_id: str
    attacker_class: str
    classifier_confidence: float
    cluster_id: str | None
    mitre_techniques: list[str]
    session_summary: str
    tool_signature: str
    timing_label: str
    severity: str
    recommended_actions: list[str] = field(default_factory=list)
    classifier_source: str = "weak_label"
    summary_source: str = "template"
    stix_bundle: dict[str, Any] | None = None
    features: dict[str, float] = field(default_factory=dict)

    def to_intelligence_columns(self) -> dict[str, Any]:
        """Project onto the core's ``sessions`` intelligence columns (for writeback)."""
        return {
            "attacker_class": self.attacker_class,
            "classifier_confidence": self.classifier_confidence,
            "cluster_id": self.cluster_id,
            "mitre_techniques": self.mitre_techniques,
            "session_summary": self.session_summary,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IntelPipeline:
    """Configured enrichment pipeline; call :meth:`enrich` per session document.

    Args:
        classifier: Optional trained :class:`SessionClassifier`. If omitted, the
            pipeline uses the interpretable weak label (degraded mode).
        use_llm: Whether to attempt the Claude-backed summary (falls back to the
            template automatically).
        model: Claude model id for the summarizer (defaults handled downstream).
        include_stix: Whether to attach a STIX 2.1 bundle to each result.
        llm_client: Optional injected anthropic client (testing / reuse).
    """

    def __init__(
        self,
        classifier: SessionClassifier | None = None,
        use_llm: bool = False,
        model: str | None = None,
        include_stix: bool = True,
        llm_client: Any | None = None,
    ) -> None:
        self.classifier = classifier
        self.use_llm = use_llm
        self.model = model
        self.include_stix = include_stix
        self.llm_client = llm_client

    def enrich(
        self,
        document: dict[str, Any],
        embedding: np.ndarray | None = None,
        cluster_id: str | None = None,
    ) -> IntelligenceResult:
        """Enrich one ``session_document`` into an :class:`IntelligenceResult`.

        Args:
            document: A core ``session_document`` dict.
            embedding: Optional 128-d behavioral embedding for the classifier.
            cluster_id: Optional precomputed Phase-3 cluster id.
        """
        prod = parse_session_document(document)
        feats = extract_features(prod)

        # -- Classification: trained model if present, else weak label ------
        if self.classifier is not None:
            result = classify(self.classifier, prod, features=feats, embedding=embedding)
            attacker_class = result.attacker_class
            confidence = result.confidence
            classifier_source = "model"
        else:
            wl = weak_label(prod, feats)
            attacker_class = wl.attacker_class
            confidence = wl.confidence
            classifier_source = "weak_label"

        # -- MITRE ATT&CK mapping ------------------------------------------
        techniques = map_mitre(prod)
        technique_ids = [t.technique.id for t in techniques]

        # -- Summary (LLM or template) -------------------------------------
        summary: ThreatIntelSummary = summarize_session(
            prod,
            attacker_class=attacker_class,
            confidence=confidence,
            tool_signature=feats.tool_signature,
            timing_label=feats.timing_label,
            techniques=techniques,
            use_llm=self.use_llm,
            model=self.model,
            client=self.llm_client,
        )

        # -- STIX export ----------------------------------------------------
        stix_bundle = (
            to_stix_bundle(prod, attacker_class, confidence, techniques, summary.summary)
            if self.include_stix
            else None
        )

        return IntelligenceResult(
            session_id=prod.session.session_id,
            attacker_class=attacker_class,
            classifier_confidence=float(confidence),
            cluster_id=cluster_id,
            mitre_techniques=technique_ids,
            session_summary=summary.summary,
            tool_signature=feats.tool_signature,
            timing_label=feats.timing_label,
            severity=summary.severity,
            recommended_actions=summary.recommended_actions,
            classifier_source=classifier_source,
            summary_source=summary.source,
            stix_bundle=stix_bundle,
            features=feats.as_dict(),
        )


def enrich_session_document(
    document: dict[str, Any],
    classifier: SessionClassifier | None = None,
    use_llm: bool = False,
    model: str | None = None,
    embedding: np.ndarray | None = None,
    cluster_id: str | None = None,
    include_stix: bool = True,
    llm_client: Any | None = None,
) -> IntelligenceResult:
    """One-shot convenience wrapper around :class:`IntelPipeline`."""
    pipeline = IntelPipeline(
        classifier=classifier,
        use_llm=use_llm,
        model=model,
        include_stix=include_stix,
        llm_client=llm_client,
    )
    return pipeline.enrich(document, embedding=embedding, cluster_id=cluster_id)
