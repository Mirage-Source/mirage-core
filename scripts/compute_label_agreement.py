"""
compute_label_agreement.py

Joins gold_labels.jsonl (human) against heuristic_predictions.jsonl (the
weak_label() heuristic's own guess, captured blind at sampling time -- see
sample_for_labeling.py) and reports how well they agree.

Headline metric is Cohen's kappa, not raw accuracy: real honeypot traffic
is bot-dominated, so a heuristic that just always guessed
"automated_scanner" would still score a high raw accuracy without having
learned anything about the rarer classes (script_kiddie/manual_recon/apt)
that are actually in question. Kappa corrects for that chance agreement.
Raw accuracy is still reported, explicitly labeled as inflated.

Usage:
    python compute_label_agreement.py --labels-dir data/labels \
                                       --out data/labels/agreement_report.md
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ATTACKER_CLASSES = ("automated_scanner", "script_kiddie", "manual_recon", "apt")

_KAPPA_INTERPRETATION = [
    (0.81, "almost perfect"),
    (0.61, "substantial"),
    (0.41, "moderate"),
    (0.21, "fair"),
    (0.01, "slight"),
    (float("-inf"), "poor / no better than chance"),
]


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def join_labels(
    gold_rows: list[dict], prediction_rows: list[dict]
) -> tuple[list[tuple[str, str]], int, int]:
    """Returns (pairs, n_unsure_excluded, n_unmatched) where pairs is a list
    of (human_label, heuristic_label), restricted to sessions with a
    definite human label and a heuristic prediction."""
    predictions = {r["session_id"]: r["attacker_class"] for r in prediction_rows}
    pairs = []
    n_unsure = 0
    n_unmatched = 0
    for row in gold_rows:
        if row["human_label"] == "unsure":
            n_unsure += 1
            continue
        pred = predictions.get(row["session_id"])
        if pred is None:
            n_unmatched += 1
            continue
        pairs.append((row["human_label"], pred))
    return pairs, n_unsure, n_unmatched


def confusion_matrix(
    pairs: list[tuple[str, str]], classes: tuple[str, ...]
) -> dict[str, dict[str, int]]:
    """matrix[true_class][pred_class] = count."""
    matrix = {t: {p: 0 for p in classes} for t in classes}
    for true, pred in pairs:
        matrix[true][pred] += 1
    return matrix


def cohens_kappa(matrix: dict[str, dict[str, int]], classes: tuple[str, ...]) -> float:
    n = sum(matrix[t][p] for t in classes for p in classes)
    if n == 0:
        return float("nan")
    po = sum(matrix[c][c] for c in classes) / n
    row_totals = {t: sum(matrix[t][p] for p in classes) for t in classes}
    col_totals = {p: sum(matrix[t][p] for t in classes) for p in classes}
    pe = sum((row_totals[c] / n) * (col_totals[c] / n) for c in classes)
    if pe == 1:
        return float("nan")
    return (po - pe) / (1 - pe)


def kappa_interpretation(kappa: float) -> str:
    if kappa != kappa:  # NaN
        return "undefined (no data)"
    for threshold, label in _KAPPA_INTERPRETATION:
        if kappa >= threshold:
            return label
    return "poor / no better than chance"


def per_class_metrics(
    matrix: dict[str, dict[str, int]], classes: tuple[str, ...]
) -> dict[str, dict[str, float]]:
    row_totals = {t: sum(matrix[t][p] for p in classes) for t in classes}
    col_totals = {p: sum(matrix[t][p] for t in classes) for p in classes}
    out = {}
    for c in classes:
        tp = matrix[c][c]
        precision = tp / col_totals[c] if col_totals[c] else float("nan")
        recall = tp / row_totals[c] if row_totals[c] else float("nan")
        if precision == precision and recall == recall and (precision + recall) > 0:
            f1 = 2 * precision * recall / (precision + recall)
        else:
            f1 = float("nan")
        out[c] = {
            "precision": precision, "recall": recall, "f1": f1,
            "support": row_totals[c],
        }
    return out


def raw_accuracy(matrix: dict[str, dict[str, int]], classes: tuple[str, ...]) -> float:
    n = sum(matrix[t][p] for t in classes for p in classes)
    if n == 0:
        return float("nan")
    return sum(matrix[c][c] for c in classes) / n


def _fmt(x: float) -> str:
    return "n/a" if x != x else f"{x:.3f}"


def render_report(
    pairs, n_unsure, n_unmatched, n_gold_total, matrix, kappa, per_class, accuracy
) -> str:
    n = len(pairs)
    macro_f1_values = [m["f1"] for m in per_class.values() if m["f1"] == m["f1"]]
    macro_f1 = sum(macro_f1_values) / len(macro_f1_values) if macro_f1_values else float("nan")

    lines = [
        "# Label agreement: human review vs. weak_label() heuristic",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        f"- {n_gold_total} sessions hand-labeled total",
        f"- {n_unsure} marked \"unsure\" by the reviewer (excluded from metrics below)",
        f"- {n_unmatched} had no heuristic prediction on record (excluded)",
        f"- **{n} sessions used for agreement metrics**",
        "",
        "## Caveats",
        "",
        "- The sample is stratified by the heuristic's own predicted class, not a "
        "random draw of real traffic -- this measures per-class agreement, **not** "
        "expected accuracy on the true (bot-dominated) class distribution.",
        "- Single reviewer, no second rater -- no inter-rater reliability check on "
        "the human labels themselves.",
        "- Classes with small support have wide uncertainty on their per-class "
        "precision/recall; treat single-digit-support rows as indicative, not precise.",
        "",
        "## Headline: Cohen's kappa",
        "",
        f"**kappa = {_fmt(kappa)}** ({kappa_interpretation(kappa)})",
        "",
        "Chance-corrected agreement between the human label and the heuristic's "
        "prediction. Reported instead of leading with raw accuracy because real "
        "traffic is bot-dominated: a heuristic that always guessed "
        "`automated_scanner` would still score a high raw accuracy without having "
        "learned anything about the rarer classes.",
        "",
        f"Raw accuracy (for reference, inflated by class imbalance): {_fmt(accuracy)}",
        f"Macro-F1: {_fmt(macro_f1)}",
        "",
        "## Confusion matrix (rows = human label, columns = heuristic prediction)",
        "",
        "| human \\ heuristic | " + " | ".join(ATTACKER_CLASSES) + " |",
        "|---|" + "---|" * len(ATTACKER_CLASSES),
    ]
    for t in ATTACKER_CLASSES:
        row = " | ".join(str(matrix[t][p]) for p in ATTACKER_CLASSES)
        lines.append(f"| {t} | {row} |")

    lines += ["", "## Per-class precision / recall / F1 (human label as ground truth)", ""]
    lines.append("| class | support | precision | recall | f1 |")
    lines.append("|---|---|---|---|---|")
    for c in ATTACKER_CLASSES:
        m = per_class[c]
        lines.append(
            f"| {c} | {m['support']} | {_fmt(m['precision'])} | "
            f"{_fmt(m['recall'])} | {_fmt(m['f1'])} |"
        )

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels-dir", default="data/labels")
    parser.add_argument("--out", default=None, help="default: <labels-dir>/agreement_report.md")
    args = parser.parse_args()

    labels_dir = Path(args.labels_dir)
    out_path = Path(args.out) if args.out else labels_dir / "agreement_report.md"

    gold_rows = load_jsonl(labels_dir / "gold_labels.jsonl")
    prediction_rows = load_jsonl(labels_dir / "heuristic_predictions.jsonl")

    if not gold_rows:
        print("No labels in gold_labels.jsonl yet -- nothing to compute.")
        return

    pairs, n_unsure, n_unmatched = join_labels(gold_rows, prediction_rows)
    matrix = confusion_matrix(pairs, ATTACKER_CLASSES)
    kappa = cohens_kappa(matrix, ATTACKER_CLASSES)
    per_class = per_class_metrics(matrix, ATTACKER_CLASSES)
    accuracy = raw_accuracy(matrix, ATTACKER_CLASSES)

    report = render_report(
        pairs, n_unsure, n_unmatched, len(gold_rows), matrix, kappa, per_class, accuracy
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
