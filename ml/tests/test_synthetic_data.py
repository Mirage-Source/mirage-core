
from __future__ import annotations

from pathlib import Path

from mirage.data.loader import DataLoader
from mirage.data.synthetic import write_synthetic_log


def test_write_synthetic_log_round_trips_through_loader(tmp_path: Path) -> None:
    log_path = tmp_path / "synthetic_cowrie.json"
    write_synthetic_log(log_path, n_sessions=25, seed=1)

    sessions = DataLoader(min_commands=1).load_file(log_path)

    assert len(sessions) == 25
    assert all(s.n_commands >= 1 for s in sessions)
    assert all(s.ip for s in sessions)
    assert all(s.session_id.startswith("synthetic-") for s in sessions)


def test_write_synthetic_log_is_deterministic_for_a_given_seed(tmp_path: Path) -> None:
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    write_synthetic_log(a, n_sessions=10, seed=7)
    write_synthetic_log(b, n_sessions=10, seed=7)

    assert a.read_text() == b.read_text()
