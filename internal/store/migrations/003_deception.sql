-- Adaptive deception policy (bandit / REINFORCE-A2C / PPO).
--
-- Records which action (MINIMAL, ENRICH, SURFACE_BAIT, STALL, FAKE_SUCCESS)
-- the deception policy chose for each command, when the policy is enabled
-- (MIRAGE_DECEPTION_ENABLED=true). NULL for every command handled while the
-- feature is disabled, and for every command that predates this migration.
--
-- IMPORTANT -- this file will NOT run automatically against an
-- already-running deployment. Files under db/init/ are only executed by the
-- postgres image on first container start, against an empty data directory
-- (see https://hub.docker.com/_/postgres, "Initialization scripts"). Since
-- this server is already running with data on disk, apply it by hand once,
-- e.g.:
--
--     docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < db/init/003_deception.sql
--
-- ADD COLUMN ... TEXT (nullable, no default) is a metadata-only change on
-- PostgreSQL -- it does not rewrite the existing table and takes a brief
-- ACCESS EXCLUSIVE lock, so it is safe to run against a live table.

ALTER TABLE commands ADD COLUMN IF NOT EXISTS deception_action TEXT;

CREATE INDEX IF NOT EXISTS idx_commands_deception_action
    ON commands (deception_action)
    WHERE deception_action IS NOT NULL;
