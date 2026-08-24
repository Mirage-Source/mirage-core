"""
sample_for_labeling.py

Draws a stratified sample of real sessions (stratified by the weak-label
heuristic's own predicted attacker_class, since real traffic is
bot-dominated and a pure random sample would surface too few apt/
manual_recon examples to say anything about them) and splits the result
into two files so blind human review is structural, not just a CLI
convention:

  - labeling_queue.jsonl        -- what the human reviewer sees. No
                                    attacker_class/classifier_confidence.
  - heuristic_predictions.jsonl -- session_id -> heuristic's own
                                    attacker_class/classifier_confidence.
                                    Never read by label_sessions.py.

Already-labeled sessions (present in gold_labels.jsonl) are excluded so
reruns don't re-queue work that's already done.

Usage:
    python sample_for_labeling.py --api-url  \
                                   --api-key $API_KEY \
                                   --out-dir data/labels \
                                   --per-class 50 \
                                   --seed 0
"""

import argparse
import json
import random
import sys
from pathlib import Path

from export_commands_dataset import fetch_all_commands
from export_dataset import fetch_export

# Mirrors ml/mirage/intel/taxonomy.py::ATTACKER_CLASSES. Duplicated (rather
# than imported) because scripts/ deliberately has no dependency on the ml
# package -- it only ever installs scripts/requirements.txt (see
# .github/workflows/publish-dataset.yml). Keep these two in sync by hand.
ATTACKER_CLASSES = ("automated_scanner", "script_kiddie", "manual_recon", "apt")


def group_commands_by_session(commands: list[dict]) -> dict[str, list[dict]]:
    by_session: dict[str, list[dict]] = {}
    for c in commands:
        by_session.setdefault(c["session_id"], []).append(c)
    for cmds in by_session.values():
        cmds.sort(key=lambda c: c["sequence_number"])
    return by_session


def build_queue_record(session: dict, commands: list[dict]) -> dict:
    """The blind view: everything a human needs to judge intent, nothing
    that reveals what the heuristic already decided."""
    return {
        "session_id": session["session_id"],
        "ssh_client_banner": session["ssh_client_banner"],
        "start_ms": session["start_ms"],
        "duration_ms": session["duration_ms"],
        "command_count": session["command_count"],
        "bait_hit_count": session["bait_hit_count"],
        "auth_attempt_count": session["auth_attempt_count"],
        "unique_usernames_tried": session["unique_usernames_tried"],
        "top_username": session["top_username"],
        "commands": [
            {
                "sequence_number": c["sequence_number"],
                "timestamp_ms": c["timestamp_ms"],
                "working_directory": c["working_directory"],
                "raw_command": c["raw_command"],
                "response": c["response"],
                "bait_hit": c["bait_hit"],
                "bait_type": c["bait_type"],
            }
            for c in commands
        ],
    }


def stratified_sample(
    sessions: list[dict],
    per_class: int,
    already_labeled: set[str],
    seed: int,
) -> dict[str, list[dict]]:
    """Group unlabeled, classified sessions by heuristic attacker_class and
    take up to `per_class` of each, deterministically for a given seed."""
    by_class: dict[str, list[dict]] = {c: [] for c in ATTACKER_CLASSES}
    for s in sessions:
        cls = s.get("attacker_class")
        if cls not in by_class:
            continue  # unclassified (not yet enriched) -- nothing to compare against
        if s["session_id"] in already_labeled:
            continue
        by_class[cls].append(s)

    rng = random.Random(seed)
    sampled: dict[str, list[dict]] = {}
    for cls, rows in by_class.items():
        rng.shuffle(rows)
        sampled[cls] = rows[:per_class]
    return sampled


def load_jsonl_by_key(path: Path, key: str) -> dict[str, dict]:
    if not path.exists():
        return {}
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            out[row[key]] = row
    return out


def write_jsonl_sorted(path: Path, rows_by_key: dict[str, dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for key in sorted(rows_by_key):
            f.write(json.dumps(rows_by_key[key]) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--out-dir", default="data/labels")
    parser.add_argument(
        "--per-class", type=int, default=50,
        help="max sessions to sample per heuristic-predicted attacker_class",
    )
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    gold_path = out_dir / "gold_labels.jsonl"
    queue_path = out_dir / "labeling_queue.jsonl"
    predictions_path = out_dir / "heuristic_predictions.jsonl"

    already_labeled = set(load_jsonl_by_key(gold_path, "session_id"))
    print(f"{len(already_labeled)} sessions already labeled, excluding from sample", file=sys.stderr)

    print(f"Fetching export from {args.api_url}/api/export ...", file=sys.stderr)
    export = fetch_export(args.api_url, args.api_key)
    sessions = export["sessions"]
    print(f"Got {len(sessions)} sessions", file=sys.stderr)

    print(f"Fetching commands from {args.api_url}/api/export/commands ...", file=sys.stderr)
    commands = fetch_all_commands(args.api_url, args.api_key)
    print(f"Got {len(commands)} commands", file=sys.stderr)
    commands_by_session = group_commands_by_session(commands)

    sampled = stratified_sample(sessions, args.per_class, already_labeled, args.seed)
    for cls in ATTACKER_CLASSES:
        print(f"  {cls}: sampled {len(sampled[cls])}", file=sys.stderr)

    existing_queue = load_jsonl_by_key(queue_path, "session_id")
    existing_predictions = load_jsonl_by_key(predictions_path, "session_id")

    for cls, rows in sampled.items():
        for s in rows:
            sid = s["session_id"]
            cmds = commands_by_session.get(sid, [])
            existing_queue[sid] = build_queue_record(s, cmds)
            existing_predictions[sid] = {
                "session_id": sid,
                "attacker_class": s["attacker_class"],
                "classifier_confidence": s["classifier_confidence"],
            }

    # Drop anything that's since been labeled, in case this dir is reused
    # across runs after label_sessions.py has already caught up.
    for sid in already_labeled:
        existing_queue.pop(sid, None)

    write_jsonl_sorted(queue_path, existing_queue)
    write_jsonl_sorted(predictions_path, existing_predictions)
    print(f"Wrote {len(existing_queue)} sessions to {queue_path}", file=sys.stderr)
    print(f"Wrote {len(existing_predictions)} predictions to {predictions_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
