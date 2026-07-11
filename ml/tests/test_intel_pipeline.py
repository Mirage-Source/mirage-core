"""End-to-end smoke test of the exact degraded-mode path bridge/worker.py runs
in production today: no trained classifier, no embedding, no LLM.
"""

from __future__ import annotations

import random

from mirage.intel.pipeline import IntelPipeline
from mirage.intel.synthetic import make_session_document


def test_pipeline_enrich_degraded_mode_produces_full_result() -> None:
    pipeline = IntelPipeline(classifier=None, use_llm=False, include_stix=True)
    doc = make_session_document("script_kiddie", random.Random(3), 0)

    result = pipeline.enrich(doc)

    assert result.attacker_class in (
        "automated_scanner", "script_kiddie", "manual_recon", "apt",
    )
    assert 0.0 <= result.classifier_confidence <= 1.0
    assert result.classifier_source == "weak_label"
    assert result.summary_source == "template"
    assert result.session_summary
    assert isinstance(result.mitre_techniques, list)
    assert result.stix_bundle is not None


def test_pipeline_enrich_without_stix() -> None:
    pipeline = IntelPipeline(classifier=None, use_llm=False, include_stix=False)
    doc = make_session_document("automated_scanner", random.Random(9), 0)

    result = pipeline.enrich(doc)

    assert result.stix_bundle is None
