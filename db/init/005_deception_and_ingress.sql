-- Brings db/init back in sync with internal/store/migrations/ -- a fresh
-- clone was missing commands.deception_action, commands.response_text/
-- exit_code, and sessions.ingress_source/proxy_node_id entirely, caught by
-- internal/server/e2e_test.go's real end-to-end test failing with
-- "column ... does not exist" against a from-scratch database. Mirrors
-- internal/store/migrations/003_deception.sql, 004_command_response.sql,
-- and 007_ingress_source.sql, which are what get hand-applied to the
-- already-running production sensor -- see DEPLOYMENT.md §3 for why
-- db/init and migrations/ are two separate copies.

ALTER TABLE commands ADD COLUMN IF NOT EXISTS deception_action TEXT;

CREATE INDEX IF NOT EXISTS idx_commands_deception_action
    ON commands (deception_action)
    WHERE deception_action IS NOT NULL;

ALTER TABLE commands ADD COLUMN IF NOT EXISTS response_text TEXT;
ALTER TABLE commands ADD COLUMN IF NOT EXISTS exit_code INTEGER;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ingress_source TEXT NOT NULL DEFAULT 'direct';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS proxy_node_id TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_ingress_source
    ON sessions (ingress_source)
    WHERE ingress_source <> 'direct';
