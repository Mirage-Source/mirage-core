from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mirage.data.schema import Command, Session
from mirage.reid.campaign import CampaignMembership, CampaignResult
from mirage.reid.loss import UNKNOWN_TOOLKIT
from mirage.reid.real_data import (
    build_real_identity_corpus,
    load_real_identity_corpus,
    save_real_identity_corpus,
    toolkit_label_for,
)


def _session(session_id: str, ip: str) -> Session:
    return Session(session_id=session_id, ip=ip, start_time=datetime(2026, 1, 1, tzinfo=timezone.utc))


def _campaign() -> CampaignResult:
    return CampaignResult(
        members=[
            CampaignMembership(ip="1.1.1.1", tier=1, session_count=761),
            CampaignMembership(ip="2.2.2.2", tier=3, session_count=2283),
        ]
    )


def test_toolkit_label_for_campaign_member_includes_tier() -> None:
    assert toolkit_label_for("1.1.1.1", _campaign()) == "campaign_tier1"
    assert toolkit_label_for("2.2.2.2", _campaign()) == "campaign_tier3"


def test_toolkit_label_for_non_member_is_unknown() -> None:
    assert toolkit_label_for("9.9.9.9", _campaign()) == UNKNOWN_TOOLKIT


def test_build_real_identity_corpus_groups_by_ip() -> None:
    sessions = [
        _session("s1", "1.1.1.1"),
        _session("s2", "1.1.1.1"),
        _session("s3", "9.9.9.9"),
    ]
    corpus = build_real_identity_corpus(sessions, _campaign())

    assert len(corpus) == 3
    assert corpus.identity_labels.count("1.1.1.1") == 2
    assert corpus.identity_labels.count("9.9.9.9") == 1
    # Every row's toolkit label matches its own ip's campaign status.
    for session, identity, toolkit in zip(corpus.sessions, corpus.identity_labels, corpus.toolkit_labels):
        assert identity == session.ip
        assert toolkit == toolkit_label_for(session.ip, _campaign())


def test_build_real_identity_corpus_drops_addresses_below_min_sessions() -> None:
    sessions = [
        _session("s1", "1.1.1.1"),
        _session("s2", "1.1.1.1"),
        _session("s3", "solo"),  # only one session for this address
    ]
    corpus = build_real_identity_corpus(sessions, _campaign(), min_sessions_per_identity=2)

    assert corpus.identity_labels == ["1.1.1.1", "1.1.1.1"]


def test_build_real_identity_corpus_rejects_empty_ip() -> None:
    sessions = [_session("s1", "")]
    with pytest.raises(ValueError):
        build_real_identity_corpus(sessions, _campaign())


def test_save_and_load_real_identity_corpus_round_trips(tmp_path) -> None:
    s1 = _session("s1", "1.1.1.1")
    s1.commands.append(Command(timestamp=s1.start_time, raw="uname -a", ms_offset=0))
    s2 = _session("s2", "9.9.9.9")
    corpus = build_real_identity_corpus([s1, s2], _campaign())

    path = tmp_path / "corpus.jsonl"
    save_real_identity_corpus(corpus, path)
    loaded = load_real_identity_corpus(path)

    assert loaded.identity_labels == corpus.identity_labels
    assert loaded.toolkit_labels == corpus.toolkit_labels
    assert [s.session_id for s in loaded.sessions] == [s.session_id for s in corpus.sessions]
    assert loaded.sessions[0].raw_commands() == ["uname -a"]
