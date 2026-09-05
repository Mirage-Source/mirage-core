-- Backs the operator console's Control tab (mirage-web docs/API-GAPS.md §4).
-- Scoped deliberately narrow: only the two deception-policy switches
-- (deception_enabled, deception_apply_actions) are dashboard-writable today.
-- Mirrors internal/store/migrations/010_runtime_flags.sql, which is what
-- gets hand-applied to the already-running production sensor -- see
-- DEPLOYMENT.md §3 for why db/init and migrations/ are two separate copies.

CREATE TABLE IF NOT EXISTS runtime_flags (
    key        TEXT PRIMARY KEY,
    enabled    BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT
);

INSERT INTO runtime_flags (key, enabled) VALUES
    ('deception_enabled', false),
    ('deception_apply_actions', false)
ON CONFLICT (key) DO NOTHING;
