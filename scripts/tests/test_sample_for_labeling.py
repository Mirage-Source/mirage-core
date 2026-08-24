"""
Plain-assert smoke tests for the stratify/join/blind-split logic in
sample_for_labeling.py, against fixture data (no network calls). Confirms:
  - the queue record never carries attacker_class/classifier_confidence
    (the thing that makes blind labeling structural, not a CLI convention)
  - stratified_sample respects the per-class cap and excludes
    already-labeled session_ids
  - unclassified sessions (heuristic hasn't run) are dropped, not sampled

Usage:
    python3 scripts/tests/test_sample_for_labeling.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sample_for_labeling import (  # noqa: E402
    ATTACKER_CLASSES,
    build_queue_record,
    group_commands_by_session,
    stratified_sample,
)


def _session(session_id: str, attacker_class: str | None) -> dict:
    return {
        "session_id": session_id,
        "ssh_client_banner": "SSH-2.0-libssh",
        "start_ms": 1000,
        "duration_ms": 5000,
        "command_count": 1,
        "bait_hit_count": 0,
        "auth_attempt_count": 1,
        "unique_usernames_tried": 1,
        "top_username": "root",
        "attacker_class": attacker_class,
        "classifier_confidence": 0.7,
    }


def test_build_queue_record_never_leaks_attacker_class():
    session = _session("s1", "apt")
    commands = [{
        "session_id": "s1", "sequence_number": 0, "timestamp_ms": 1500,
        "working_directory": "/root", "raw_command": "cat /etc/shadow",
        "response": "root:x:...", "bait_hit": True, "bait_type": "credential_file",
    }]
    record = build_queue_record(session, commands)
    assert "attacker_class" not in record
    assert "classifier_confidence" not in record
    assert record["commands"][0]["raw_command"] == "cat /etc/shadow"


def test_group_commands_by_session_sorts_by_sequence():
    commands = [
        {"session_id": "s1", "sequence_number": 2, "raw_command": "c"},
        {"session_id": "s1", "sequence_number": 0, "raw_command": "a"},
        {"session_id": "s1", "sequence_number": 1, "raw_command": "b"},
        {"session_id": "s2", "sequence_number": 0, "raw_command": "x"},
    ]
    grouped = group_commands_by_session(commands)
    assert [c["raw_command"] for c in grouped["s1"]] == ["a", "b", "c"]
    assert [c["raw_command"] for c in grouped["s2"]] == ["x"]


def test_stratified_sample_respects_cap_and_exclusions():
    sessions = (
        [_session(f"scanner-{i}", "automated_scanner") for i in range(10)]
        + [_session(f"apt-{i}", "apt") for i in range(3)]
        + [_session("unclassified-1", None)]
    )
    already_labeled = {"scanner-0", "apt-0"}

    sampled = stratified_sample(sessions, per_class=5, already_labeled=already_labeled, seed=0)

    assert set(sampled.keys()) == set(ATTACKER_CLASSES)
    assert len(sampled["automated_scanner"]) == 5  # capped at per_class, 9 available
    assert len(sampled["apt"]) == 2  # only 2 left after excluding apt-0
    assert "scanner-0" not in {s["session_id"] for s in sampled["automated_scanner"]}
    assert "apt-0" not in {s["session_id"] for s in sampled["apt"]}
    assert sampled["script_kiddie"] == []
    assert sampled["manual_recon"] == []
    # unclassified-1 must not appear anywhere -- no heuristic prediction to compare against
    all_sampled_ids = {s["session_id"] for rows in sampled.values() for s in rows}
    assert "unclassified-1" not in all_sampled_ids


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"\n{len(tests)} tests passed")
