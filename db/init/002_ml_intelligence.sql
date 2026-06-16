-- 002_ml_intelligence.sql
-- Phase-2 ML enrichment tables, applied AFTER the core's 001_initial.sql.
-- Mounted into the postgres container's /docker-entrypoint-initdb.d so it runs
-- automatically on first database init (files run in alphabetical order).
--
-- The enrichment worker also creates this table idempotently on startup
-- (bridge/db.py::ML_SCHEMA_DDL), so the system is robust whether or not these
-- migrations were applied manually. Keep the two in sync.

CREATE TABLE IF NOT EXISTS session_embeddings (
    session_id TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,

    -- Provenance of the embedding (which trained model produced it).
    model_version TEXT,
    embedding_dim INTEGER,
    -- The 128-d behavioral vector. Stored as a JSON array for portability; for
    -- Phase-3 nearest-neighbour attacker re-identification at scale, migrate this
    -- to a pgvector `vector(128)` column and add an ivfflat/hnsw index.
    embedding JSONB,

    -- Weak labels / Phase-1 timing summary (always populated, even in degraded mode).
    tool_signature TEXT,
    timing_label TEXT,
    timing_cv DOUBLE PRECISION,
    timing_median_ms DOUBLE PRECISION,

    -- Phase-2 trajectory geometry (the motor-cortex analysis).
    trajectory_path_length DOUBLE PRECISION,
    trajectory_mean_speed DOUBLE PRECISION,
    trajectory_total_curvature DOUBLE PRECISION,
    trajectory_straightness DOUBLE PRECISION,
    trajectory_convergence_step INTEGER,
    intent_shift_count INTEGER,
    -- [resample_points x dim] translation/scale-normalized trajectory-shape
    -- descriptor, for cross-session shape comparison (Phase-2 hypothesis).
    shape_signature JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_session_embeddings_tool
    ON session_embeddings(tool_signature);
CREATE INDEX IF NOT EXISTS idx_session_embeddings_timing
    ON session_embeddings(timing_label);

-- Convenience view: the core session intelligence joined to the ML embedding row.
-- Handy for dashboards and for Phase-3 clustering queries.
CREATE OR REPLACE VIEW enriched_sessions AS
SELECT
    s.session_id,
    s.client_ip,
    s.start_ms,
    s.duration_ms,
    s.command_count,
    s.bait_hit_count,
    s.outcome,
    s.attacker_class,
    s.classifier_confidence,
    s.cluster_id,
    s.mitre_techniques,
    s.session_summary,
    e.tool_signature,
    e.timing_label,
    e.timing_cv,
    e.timing_median_ms,
    e.model_version,
    e.embedding_dim,
    e.trajectory_straightness,
    e.trajectory_convergence_step,
    e.intent_shift_count,
    e.created_at AS enriched_at
FROM sessions s
LEFT JOIN session_embeddings e USING (session_id);
