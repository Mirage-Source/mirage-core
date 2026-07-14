

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS stix_bundle JSONB;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS severity TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS recommended_actions JSONB;

CREATE TABLE IF NOT EXISTS session_embeddings (
    session_id TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,

    -- Provenance of the embedding (which trained model produced it).
    model_version TEXT,
    embedding_dim INTEGER,

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

    shape_signature JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_session_embeddings_tool
    ON session_embeddings(tool_signature);
CREATE INDEX IF NOT EXISTS idx_session_embeddings_timing
    ON session_embeddings(timing_label);


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
