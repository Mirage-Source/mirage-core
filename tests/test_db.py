"""Tests for the DB write layer (bridge/db.py) using a fake cursor.

These don't touch a real database -- they verify the SQL statements are well
formed (placeholder count matches parameter count, both expected statements are
issued, transaction committed). A live round-trip is covered by the docker-compose
integration, not unit tests.
"""

from __future__ import annotations

import pytest

# db.py imports psycopg2 at module load; skip the whole module if it's absent
# (psycopg2 is a deployment dependency installed in the worker image).
pytest.importorskip("psycopg2")

from bridge.db import write_enrichment, mark_failed  # noqa: E402
from bridge.enrich import EnrichmentResult  # noqa: E402


class _FakeCursor:
    def __init__(self, log):
        self._log = log

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self._log.append((sql, params))


class _FakeConn:
    def __init__(self):
        self.statements: list[tuple[str, tuple]] = []
        self.commits = 0

    def cursor(self):
        return _FakeCursor(self.statements)

    def commit(self):
        self.commits += 1


def _placeholder_count(sql: str) -> int:
    return sql.count("%s")


def test_write_enrichment_statements_and_param_counts():
    conn = _FakeConn()
    result = EnrichmentResult(
        session_id="abc",
        attacker_class="dropper",
        classifier_confidence=0.75,
        cluster_id=None,
        mitre_techniques=["T1105", "T1059"],
        session_summary="a summary",
        tool_signature="dropper",
        timing_label="automated",
        timing_cv=0.12,
        timing_median_ms=90.0,
        embedding=[0.1, 0.2, 0.3],
        embedding_dim=3,
        model_version="test-v1",
        trajectory={
            "path_length": 1.0, "mean_speed": 0.5, "total_curvature": 2.0,
            "straightness": 0.3, "convergence_step": 4, "intent_shift_count": 1,
            "shape_signature": [[0.0, 1.0]],
        },
    )
    write_enrichment(conn, result)

    assert len(conn.statements) == 2  # UPDATE sessions + INSERT embeddings
    update_sql, update_params = conn.statements[0]
    insert_sql, insert_params = conn.statements[1]
    assert "UPDATE sessions" in update_sql
    assert "INSERT INTO session_embeddings" in insert_sql
    # Placeholder/param parity catches off-by-one SQL bugs.
    assert _placeholder_count(update_sql) == len(update_params)
    assert _placeholder_count(insert_sql) == len(insert_params)
    assert conn.commits == 1


def test_write_enrichment_degraded_null_embedding():
    """Degraded-mode result (no embedding) must still write cleanly."""
    conn = _FakeConn()
    result = EnrichmentResult(
        session_id="xyz",
        attacker_class="recon",
        classifier_confidence=0.66,
        cluster_id=None,
        mitre_techniques=["T1082"],
        session_summary="recon summary",
        tool_signature="recon",
        timing_label="automated",
        timing_cv=None,
        timing_median_ms=None,
        embedding=None,
        embedding_dim=None,
        model_version=None,
        trajectory=None,
    )
    write_enrichment(conn, result)
    _, insert_params = conn.statements[1]
    # embedding param is NULL but the row is still inserted.
    assert insert_params[3] is None  # embedding JSON
    assert conn.commits == 1


def test_mark_failed_issues_update_and_commits():
    conn = _FakeConn()
    mark_failed(conn, "poison", "boom")
    assert len(conn.statements) == 1
    sql, params = conn.statements[0]
    assert "attacker_class = 'error'" in sql
    assert _placeholder_count(sql) == len(params)
    assert conn.commits == 1
