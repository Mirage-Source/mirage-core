"""
Plain-assert smoke tests for the kappa/confusion-matrix arithmetic in
compute_label_agreement.py -- verifies the math against hand-computed
values on a synthetic confusion table. This is NOT a claim about the
classifier's real accuracy (that requires actual hand-labeled sessions,
which don't exist until Mirage is redeployed) -- it's just checking the
formulas are implemented correctly.

No pytest dependency, consistent with scripts/ only ever installing
scripts/requirements.txt in CI (see .github/workflows/publish-dataset.yml).

Usage:
    python3 scripts/tests/test_compute_label_agreement.py
"""

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from compute_label_agreement import (  # noqa: E402
    cohens_kappa,
    confusion_matrix,
    join_labels,
    per_class_metrics,
    raw_accuracy,
)


def close(a: float, b: float, tol: float = 1e-9) -> bool:
    if a != a and b != b:  # both NaN
        return True
    return math.isclose(a, b, abs_tol=tol)


def test_perfect_agreement():
    classes = ("a", "b")
    pairs = [("a", "a")] * 10 + [("b", "b")] * 10
    matrix = confusion_matrix(pairs, classes)
    assert cohens_kappa(matrix, classes) == 1.0
    assert raw_accuracy(matrix, classes) == 1.0


def test_single_class_kappa_is_undefined():
    classes = ("a", "b")
    pairs = [("a", "a")] * 5
    matrix = confusion_matrix(pairs, classes)
    kappa = cohens_kappa(matrix, classes)
    assert kappa != kappa, f"expected NaN when pe=1, got {kappa}"


def test_known_confusion_table():
    # Hand-computed reference case:
    #   (a,a)x40 (a,b)x10 (b,a)x5 (b,b)x45  -> n=100
    #   po=0.85, row_totals a=50/b=50, col_totals a=45/b=55
    #   pe = .5*.45 + .5*.55 = 0.5  -> kappa = (0.85-0.5)/0.5 = 0.7
    classes = ("a", "b")
    pairs = (
        [("a", "a")] * 40 + [("a", "b")] * 10
        + [("b", "a")] * 5 + [("b", "b")] * 45
    )
    matrix = confusion_matrix(pairs, classes)
    assert matrix == {"a": {"a": 40, "b": 10}, "b": {"a": 5, "b": 45}}

    assert close(raw_accuracy(matrix, classes), 0.85)
    assert close(cohens_kappa(matrix, classes), 0.7)

    per_class = per_class_metrics(matrix, classes)
    assert close(per_class["a"]["precision"], 40 / 45)
    assert close(per_class["a"]["recall"], 40 / 50)
    assert close(per_class["b"]["precision"], 45 / 55)
    assert close(per_class["b"]["recall"], 45 / 50)
    expected_f1_a = 2 * (40 / 45) * (40 / 50) / ((40 / 45) + (40 / 50))
    assert close(per_class["a"]["f1"], expected_f1_a)


def test_join_labels_excludes_unsure_and_unmatched():
    gold_rows = [
        {"session_id": "s1", "human_label": "apt"},
        {"session_id": "s2", "human_label": "unsure"},
        {"session_id": "s3", "human_label": "automated_scanner"},  # no prediction on record
        {"session_id": "s4", "human_label": "script_kiddie"},
    ]
    prediction_rows = [
        {"session_id": "s1", "attacker_class": "apt"},
        {"session_id": "s4", "attacker_class": "automated_scanner"},
    ]
    pairs, n_unsure, n_unmatched = join_labels(gold_rows, prediction_rows)
    assert pairs == [("apt", "apt"), ("script_kiddie", "automated_scanner")]
    assert n_unsure == 1
    assert n_unmatched == 1


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\n{len(tests)} tests passed")
