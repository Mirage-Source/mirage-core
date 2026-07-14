
from __future__ import annotations

import random

import pytest

from mirage.intel.features import extract_features
from mirage.intel.ingest import parse_session_document
from mirage.intel.synthetic import make_session_document
from mirage.intel.taxonomy import ATTACKER_CLASSES, weak_label


@pytest.mark.parametrize("attacker_class", ATTACKER_CLASSES)
def test_weak_label_recovers_the_intended_archetype(attacker_class: str) -> None:
    rng = random.Random(42)
    hits = 0
    n = 20
    for i in range(n):
        doc = make_session_document(attacker_class, rng, i)
        prod = parse_session_document(doc)
        label = weak_label(prod, extract_features(prod))
        if label.attacker_class == attacker_class:
            hits += 1

    # The synthetic archetypes are designed so the heuristic mostly recovers
    # the intended class (see mirage.intel.synthetic docstring) -- not 100%,
    # but well above chance (1/4).
    assert hits / n >= 0.5, f"weak_label only recovered {hits}/{n} for {attacker_class}"


def test_weak_label_always_has_a_rationale() -> None:
    rng = random.Random(0)
    doc = make_session_document("apt", rng, 0)
    prod = parse_session_document(doc)
    label = weak_label(prod, extract_features(prod))

    assert label.rationale
    assert 0.0 <= label.confidence <= 1.0
