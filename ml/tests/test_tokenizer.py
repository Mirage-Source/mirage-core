"""CommandTokenizer fit/encode/save/load round-trip on a synthetic corpus."""

from __future__ import annotations

from pathlib import Path

from mirage.data.loader import DataLoader
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
