"""
label_sessions.py

Interactive CLI for hand-labeling sessions sampled by
sample_for_labeling.py. Reads only labeling_queue.jsonl -- deliberately
never opens heuristic_predictions.jsonl -- so the reviewer can't see (and
anchor on) the weak-label heuristic's own guess while labeling. That file
is only read later, by compute_label_agreement.py, to compute agreement.

Each label is appended to gold_labels.jsonl as soon as it's entered, so a
Ctrl-C mid-session never loses already-completed work.

Usage:
    python label_sessions.py --labels-dir data/labels
"""

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ATTACKER_CLASSES = ("automated_scanner", "script_kiddie", "manual_recon", "apt")


def reviewer_identity() -> str:
    try:
        email = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if email:
            return email
    except (OSError, subprocess.SubprocessError):
        pass
    import os
    return os.environ.get("USER", "unknown")


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


def already_labeled_session_ids(gold_path: Path) -> set[str]:
    return {row["session_id"] for row in load_jsonl(gold_path)}


def format_session(record: dict) -> str:
    lines = [
        f"session_id={record['session_id']}  banner={record['ssh_client_banner']!r}",
        f"duration_ms={record['duration_ms']}  commands={record['command_count']}  "
        f"bait_hits={record['bait_hit_count']}  auth_attempts={record['auth_attempt_count']} "
        f"(usernames tried: {record['unique_usernames_tried']}, top={record['top_username']!r})",
        "",
    ]
    start = record["start_ms"]
    for c in record["commands"]:
        delta = c["timestamp_ms"] - start
        lines.append(f"  [{c['sequence_number']:>3}] t=+{delta}ms cwd={c['working_directory']}")
        lines.append(f"        $ {c['raw_command']}")
        if c["response"]:
            resp = c["response"]
            if len(resp) > 400:
                resp = resp[:400] + "... [truncated]"
            lines.append(f"        -> {resp}")
        if c["bait_hit"]:
            lines.append(f"        [BAIT HIT: {c['bait_type']}]")
    return "\n".join(lines)


def prompt_label() -> str | None:
    """Returns an AttackerClass, 'unsure', or None (skip -- revisit later)."""
    options = "  ".join(f"[{i + 1}] {c}" for i, c in enumerate(ATTACKER_CLASSES))
    while True:
        choice = input(f"{options}  [u] unsure  [s] skip  [q] quit\n> ").strip().lower()
        if choice == "q":
            raise KeyboardInterrupt
        if choice == "s":
            return None
        if choice == "u":
            return "unsure"
        if choice.isdigit() and 1 <= int(choice) <= len(ATTACKER_CLASSES):
            return ATTACKER_CLASSES[int(choice) - 1]
        print(f"unrecognized input: {choice!r}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels-dir", default="data/labels")
    args = parser.parse_args()

    labels_dir = Path(args.labels_dir)
    queue_path = labels_dir / "labeling_queue.jsonl"
    gold_path = labels_dir / "gold_labels.jsonl"

    queue = load_jsonl(queue_path)
    done = already_labeled_session_ids(gold_path)
    remaining = [r for r in queue if r["session_id"] not in done]

    print(f"{len(remaining)} sessions to label ({len(done)} already done)")
    reviewer = reviewer_identity()

    labeled_this_run = 0
    try:
        for i, record in enumerate(remaining, start=1):
            print(f"\n{'=' * 70}\n[{i}/{len(remaining)}]")
            print(format_session(record))
            human_label = prompt_label()
            if human_label is None:
                continue

            rationale = input("rationale (optional): ").strip()
            row = {
                "session_id": record["session_id"],
                "human_label": human_label,
                "rationale": rationale,
                "reviewer": reviewer,
                "labeled_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(gold_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            labeled_this_run += 1
    except (KeyboardInterrupt, EOFError):
        pass

    print(f"\nLabeled {labeled_this_run} sessions this run. Progress saved to {gold_path}")


if __name__ == "__main__":
    main()
