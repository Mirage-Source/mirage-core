from __future__ import annotations

import pytest

from mirage.reid.campaign import (
    CampaignResult,
    credential_sets_match,
    detect_campaign,
    divisibility_candidates,
)


def test_divisibility_candidates_keeps_only_exact_multiples() -> None:
    counts = {"a": 761, "b": 1522, "c": 700, "d": 761 * 5, "e": 0}
    out = divisibility_candidates(counts, wordlist_len=761)
    assert out == {"a": 1, "b": 2, "d": 5}


def test_divisibility_candidates_rejects_nonpositive_wordlist() -> None:
    with pytest.raises(ValueError):
        divisibility_candidates({"a": 761}, wordlist_len=0)
    with pytest.raises(ValueError):
        divisibility_candidates({"a": 761}, wordlist_len=-761)


def test_divisibility_candidates_empty_input() -> None:
    assert divisibility_candidates({}, wordlist_len=761) == {}


def test_credential_sets_match_true_when_identical() -> None:
    pairs = frozenset({("root", "123456"), ("admin", "admin")})
    assert credential_sets_match({"a": pairs, "b": pairs, "c": frozenset(pairs)})


def test_credential_sets_match_false_on_any_mismatch() -> None:
    pairs = frozenset({("root", "123456")})
    other = frozenset({("root", "password")})
    assert not credential_sets_match({"a": pairs, "b": pairs, "c": other})


def test_credential_sets_match_vacuously_true_when_empty() -> None:
    assert credential_sets_match({})


def _wordlist(n: int, salt: str = "") -> frozenset[tuple[str, str]]:
    return frozenset((f"user{i}{salt}", f"pass{i}{salt}") for i in range(n))


def test_detect_campaign_reproduces_a_tiered_ladder() -> None:
    # Mirrors the shape of the preprint's Table II at a small scale: two tier-1
    # addresses, one tier-2, sharing one 5-entry wordlist.
    shared = _wordlist(5)
    session_counts = {"1.1.1.1": 5, "2.2.2.2": 5, "3.3.3.3": 10, "noise": 7}
    pair_sets = {"1.1.1.1": shared, "2.2.2.2": shared, "3.3.3.3": shared}

    result = detect_campaign(session_counts, pair_sets, wordlist_len=5)

    assert sorted(result.ips) == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert result.total_sessions == 20
    assert result.tier_summary() == {1: (2, 10), 2: (1, 10)}
    assert result.excluded == []


def test_detect_campaign_excludes_a_coincidental_divisor() -> None:
    # An address hits a multiple of the wordlist length by chance but runs a
    # completely different credential list -- the negative-control scenario
    # from Section VI-B: the test must have specificity, not just sensitivity.
    shared = _wordlist(5)
    unrelated = _wordlist(5, salt="_x")
    session_counts = {"1.1.1.1": 5, "2.2.2.2": 5, "coincidence": 5}
    pair_sets = {"1.1.1.1": shared, "2.2.2.2": shared, "coincidence": unrelated}

    result = detect_campaign(session_counts, pair_sets, wordlist_len=5)

    assert sorted(result.ips) == ["1.1.1.1", "2.2.2.2"]
    assert result.excluded == ["coincidence"]


def test_detect_campaign_no_candidates_is_empty_result() -> None:
    result = detect_campaign({"a": 700}, {}, wordlist_len=761)
    assert result == CampaignResult()


def test_detect_campaign_candidate_missing_credential_data_is_excluded() -> None:
    # A divisibility candidate we have no auth_attempts rows for at all (e.g.
    # partial ingest) must not be silently counted as a confirmed member.
    shared = _wordlist(5)
    session_counts = {"1.1.1.1": 5, "2.2.2.2": 5, "unknown": 5}
    pair_sets = {"1.1.1.1": shared, "2.2.2.2": shared}

    result = detect_campaign(session_counts, pair_sets, wordlist_len=5)

    assert sorted(result.ips) == ["1.1.1.1", "2.2.2.2"]
    assert result.excluded == ["unknown"]
