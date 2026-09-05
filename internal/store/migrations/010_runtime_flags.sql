-- Backs the operator console's Control tab (mirage-web docs/API-GAPS.md §4).
-- Scoped deliberately narrow: only the two deception-policy switches
-- (deception_enabled, deception_apply_actions) are dashboard-writable today.
-- llm_shell_enabled, stix_enabled, and intel_use_llm stay env-only, owned by
-- other services -- see the DECISIONS.md entry this migration lands with.
--
-- Idempotent: safe to re-run, safe even if already applied via db/init.
--
--     docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < internal/store/migrations/010_runtime_flags.sql

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
