"""PostgreSQL access for the enrichment bridge.

Reads un-enriched sessions the Go core has written and writes the ML results
back into the waiting intelligence columns plus the ``session_embeddings`` table.
Uses ``psycopg2`` (the same database the Go core's ``lib/pq`` writes to).

A session is considered *pending* when its ``attacker_class`` is still ``NULL``.
Once we write any class (including the ``"error"`` sentinel for a poison session),
it is no longer re-fetched -- so the worker makes monotonic progress and never
loops on a bad row.
"""

from __future__ import annotations

import json
import time
from typing import Any

import psycopg2
import psycopg2.extras

from .config import BridgeConfig
from .enrich import EnrichmentResult

__all__ = [
    "connect_with_retry",
    "ensure_schema",
    "fetch_pending",
    "write_enrichment",
    "mark_failed",
    "ML_SCHEMA_DDL",
]


#: Idempotent DDL for the ML tables. Mirrors db/init/002_ml_intelligence.sql so
#: the worker is self-sufficient even if the migration was never applied.
ML_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS session_embeddings (
    session_id TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    model_version TEXT,
    embedding_dim INTEGER,
    embedding JSONB,
    tool_signature TEXT,
    timing_label TEXT,
    timing_cv DOUBLE PRECISION,
    timing_median_ms DOUBLE PRECISION,
    trajectory_path_length DOUBLE PRECISION,
    trajectory_mean_speed DOUBLE PRECISION,
    trajectory_total_curvature DOUBLE PRECISION,
    trajectory_straightness DOUBLE PRECISION,
    trajectory_convergence_step INTEGER,
    intent_shift_count INTEGER,
    shape_signature JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_session_embeddings_tool
    ON session_embeddings(tool_signature);
CREATE INDEX IF NOT EXISTS idx_session_embeddings_timing
    ON session_embeddings(timing_label);
"""


def connect_with_retry(
    config: BridgeConfig, retries: int = 30, delay_s: float = 2.0
) -> "psycopg2.extensions.connection":
    """Connect to Postgres, retrying while the DB container comes up.

    Args:
        config: Bridge config (provides the DSN).
        retries: Maximum connection attempts.
        delay_s: Seconds between attempts.

    Returns:
        An open psycopg2 connection (autocommit off).

    Raises:
        psycopg2.OperationalError: If all attempts fail.
    """
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(config.dsn())
            conn.autocommit = False
            return conn
        except psycopg2.OperationalError as exc:
            last_exc = exc
            print(f"[db] connect attempt {attempt}/{retries} failed; retrying in {delay_s}s")
            time.sleep(delay_s)
    assert last_exc is not None
    raise last_exc


def ensure_schema(conn: "psycopg2.extensions.connection") -> None:
    """Create the ML tables if they do not already exist (idempotent)."""
    with conn.cursor() as cur:
        cur.execute(ML_SCHEMA_DDL)
    conn.commit()


def fetch_pending(
    conn: "psycopg2.extensions.connection",
    batch_size: int,
    require_finished: bool = True,
) -> list[tuple[str, dict[str, Any]]]:
    """Fetch up to ``batch_size`` sessions awaiting enrichment.

    Args:
        conn: Open connection.
        batch_size: Max rows to return.
        require_finished: Exclude sessions whose ``outcome`` is ``"active"``.

    Returns:
        A list of ``(session_id, session_document)`` tuples, oldest first.
    """
    where = "attacker_class IS NULL"
    if require_finished:
        where += " AND outcome <> 'active'"
    sql = (
        f"SELECT session_id, session_document FROM sessions "
        f"WHERE {where} ORDER BY start_ms ASC LIMIT %s"
    )
    out: list[tuple[str, dict[str, Any]]] = []
    with conn.cursor() as cur:
        cur.execute(sql, (batch_size,))
        for session_id, doc in cur.fetchall():
            # psycopg2 returns jsonb as a parsed object; tolerate a raw string too.
            if isinstance(doc, str):
                doc = json.loads(doc)
            out.append((session_id, doc))
    return out


def write_enrichment(
    conn: "psycopg2.extensions.connection", result: EnrichmentResult
) -> None:
    """Persist an enrichment result: update ``sessions`` + upsert embeddings.

    Both writes happen in one transaction so a session's intelligence columns and
    its embedding row never disagree.
    """
    traj = result.trajectory or {}
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sessions SET
                attacker_class = %s,
                classifier_confidence = %s,
                cluster_id = %s,
                mitre_techniques = %s::jsonb,
                session_summary = %s
            WHERE session_id = %s
            """,
            (
                result.attacker_class,
                result.classifier_confidence,
                result.cluster_id,
                json.dumps(result.mitre_techniques),
                result.session_summary,
                result.session_id,
            ),
        )
        cur.execute(
            """
            INSERT INTO session_embeddings (
                session_id, model_version, embedding_dim, embedding,
                tool_signature, timing_label, timing_cv, timing_median_ms,
                trajectory_path_length, trajectory_mean_speed,
                trajectory_total_curvature, trajectory_straightness,
                trajectory_convergence_step, intent_shift_count, shape_signature
            ) VALUES (
                %s, %s, %s, %s::jsonb,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s,
                %s, %s, %s::jsonb
            )
            ON CONFLICT (session_id) DO UPDATE SET
                model_version = EXCLUDED.model_version,
                embedding_dim = EXCLUDED.embedding_dim,
                embedding = EXCLUDED.embedding,
                tool_signature = EXCLUDED.tool_signature,
                timing_label = EXCLUDED.timing_label,
                timing_cv = EXCLUDED.timing_cv,
                timing_median_ms = EXCLUDED.timing_median_ms,
                trajectory_path_length = EXCLUDED.trajectory_path_length,
                trajectory_mean_speed = EXCLUDED.trajectory_mean_speed,
                trajectory_total_curvature = EXCLUDED.trajectory_total_curvature,
                trajectory_straightness = EXCLUDED.trajectory_straightness,
                trajectory_convergence_step = EXCLUDED.trajectory_convergence_step,
                intent_shift_count = EXCLUDED.intent_shift_count,
                shape_signature = EXCLUDED.shape_signature,
                created_at = now()
            """,
            (
                result.session_id,
                result.model_version,
                result.embedding_dim,
                json.dumps(result.embedding) if result.embedding is not None else None,
                result.tool_signature,
                result.timing_label,
                result.timing_cv,
                result.timing_median_ms,
                traj.get("path_length"),
                traj.get("mean_speed"),
                traj.get("total_curvature"),
                traj.get("straightness"),
                traj.get("convergence_step"),
                traj.get("intent_shift_count"),
                json.dumps(traj.get("shape_signature")) if traj.get("shape_signature") is not None else None,
            ),
        )
    conn.commit()


def mark_failed(
    conn: "psycopg2.extensions.connection", session_id: str, message: str
) -> None:
    """Mark a session that failed enrichment so it is not retried forever.

    Sets ``attacker_class = 'error'`` (removing it from the pending set) and
    records the reason in ``session_summary`` for later inspection.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sessions SET
                attacker_class = 'error',
                classifier_confidence = NULL,
                session_summary = %s
            WHERE session_id = %s
            """,
            (f"enrichment failed: {message}"[:1000], session_id),
        )
    conn.commit()
