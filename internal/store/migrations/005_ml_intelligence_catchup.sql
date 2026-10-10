-- Catch-up for db/init/002_ml_intelligence.sql on already-running deployments.
--
-- db/init/ scripts only execute on first container start against an empty
-- Postgres data directory (see 003_deception.sql's comment for the same
-- caveat). The production VPS was already running before 002 was added, so
-- its ALTER TABLEs (stix_bundle, severity, recommended_actions) never ran
-- there -- querying the enriched_sessions view failed with
-- "column severity does not exist" until this was applied by hand:
--
--     docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < internal/store/migrations/005_ml_intelligence_catchup.sql
--
-- Idempotent (IF NOT EXISTS / DROP+CREATE throughout), safe to re-run,
-- including against a fresh instance that already has these columns from
-- db/init/002_ml_intelligence.sql.
--
-- Uses DROP + CREATE rather than CREATE OR REPLACE for the view: Postgres
-- only allows CREATE OR REPLACE VIEW to *append* trailing columns to an
-- existing view, not reorder/rename them, and on the VPS this view predated
-- the ML columns with a different column order -- CREATE OR REPLACE failed
-- with "cannot change name of view column ... to severity" until this was
-- switched to an unconditional drop.

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS stix_bundle JSONB;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS severity TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS recommended_actions JSONB;

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

DROP VIEW IF EXISTS enriched_sessions;

CREATE VIEW enriched_sessions AS
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
    s.severity,
    s.recommended_actions,
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
