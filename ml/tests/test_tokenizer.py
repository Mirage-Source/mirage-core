"""CommandTokenizer fit/encode/save/load round-trip on a synthetic corpus."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from mirage.data.loader import DataLoader
from mirage.data.schema import AuthAttempt, Session
from mirage.data.synthetic import write_synthetic_log
from mirage.tokenizer.tokenizer import CommandTokenizer, TokenizerConfig


def _load_synthetic_sessions(tmp_path: Path, n: int = 30):
    log_path = tmp_path / "synthetic_cowrie.json"
    write_synthetic_log(log_path, n_sessions=n, seed=2)
    return DataLoader(min_commands=1).load_file(log_path)


def test_fit_encode_and_save_load_round_trip(tmp_path: Path) -> None:
    sessions = _load_synthetic_sessions(tmp_path)
    tokenizer = CommandTokenizer(TokenizerConfig()).fit(sessions)

    encoded = tokenizer.encode(sessions[0])
    assert len(encoded.input_ids) == len(encoded.timing) == len(encoded.attention_mask)
    assert encoded.length <= len(encoded.input_ids)

    save_dir = tmp_path / "tokenizer"
    tokenizer.save(save_dir)
    reloaded = CommandTokenizer.load(save_dir)

    assert reloaded.vocab_size == tokenizer.vocab_size
    re_encoded = reloaded.encode(sessions[0])
    assert re_encoded.input_ids == encoded.input_ids


def _auth_only_session(session_id: str, banner: str, username: str, credential: str) -> Session:
    return Session(
        session_id=session_id,
        ip="1.2.3.4",
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_ms=2500,
        ssh_client_banner=banner,
        auth_attempts=[AuthAttempt(username=username, credential=credential)],
    )


def test_zero_command_sessions_no_longer_collapse_to_the_same_encoding() -> None:
    a = _auth_only_session("a", "SSH-2.0-Go", "root", "123456")
    b = _auth_only_session("b", "SSH-2.0-libssh_0.9.6", "admin", "admin")
    tok = CommandTokenizer(TokenizerConfig()).fit([a, b])

    enc_a = tok.encode(a)
    enc_b = tok.encode(b)

    assert enc_a.input_ids != enc_b.input_ids
    # <bos>, <dur>, banner, credential, <eos> -- no commands to add.
    assert len(enc_a.input_ids) == 5
    assert tok.decode(enc_a.input_ids, skip_special=False)[2] == "banner:SSH-2.0-Go"
    assert tok.decode(enc_a.input_ids, skip_special=False)[3] == "cred:root:123456"


def test_metadata_disabled_reproduces_the_old_two_token_encoding() -> None:
    a = _auth_only_session("a", "SSH-2.0-Go", "root", "123456")
    tok = CommandTokenizer(TokenizerConfig(use_metadata=False)).fit([a])
    enc = tok.encode(a)
    assert enc.input_ids == [tok.bos_id, tok.eos_id]


def test_duration_is_carried_in_the_timing_channel_not_a_bucketed_token() -> None:
    short = _auth_only_session("short", "SSH-2.0-Go", "root", "x")
    short.duration_ms = 100
    long = _auth_only_session("long", "SSH-2.0-Go", "root", "x")
    long.duration_ms = 100_000
    tok = CommandTokenizer(TokenizerConfig()).fit([short, long])

    enc_short = tok.encode(short, standardize_timing=True)
    enc_long = tok.encode(long, standardize_timing=True)

    dur_position = 1  # <bos>, <dur>, ...
    assert enc_short.input_ids[dur_position] == tok.dur_id == enc_long.input_ids[dur_position]
    assert enc_short.timing[dur_position] != enc_long.timing[dur_position]


def test_metadata_tokens_are_capped_separately_from_command_top_k() -> None:
    # A near-ubiquitous banner must not crowd out real command tokens sharing
    # the same fit() pass, because they're counted into separate budgets.
    sessions = []
    for i in range(5):
        s = _auth_only_session(f"s{i}", "SSH-2.0-Go", "root", "x")
        from mirage.data.schema import Command

        s.commands.append(Command(timestamp=s.start_time, raw="uname -a", ms_offset=0))
        sessions.append(s)
    tok = CommandTokenizer(TokenizerConfig(top_k=500, metadata_top_k=1)).fit(sessions)
    assert "uname" in tok._token_to_id
    assert "banner:SSH-2.0-Go" in tok._token_to_id


def test_metadata_ids_and_dur_id_are_exposed_for_augmentation_protection() -> None:
    a = _auth_only_session("a", "SSH-2.0-Go", "root", "123456")
    tok = CommandTokenizer(TokenizerConfig()).fit([a])
    enc = a
    encoded = tok.encode(enc)
    banner_id = encoded.input_ids[2]
    cred_id = encoded.input_ids[3]
    assert tok.dur_id in tok.metadata_ids
    assert banner_id in tok.metadata_ids
    assert cred_id in tok.metadata_ids
    assert tok.bos_id not in tok.metadata_ids
