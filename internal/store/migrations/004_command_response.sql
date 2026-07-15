-- Response capture for the commands export/LLM-training-data feature.
--
-- Until now, nothing persisted the honeypot's actual response text or exit
-- code per command -- only the command itself, cwd, and response metadata
-- (response_source, deception_action). For training data the response is
-- the "answer" half of every example, so this adds real capture of it
-- rather than trying to derive it after the fact (derivation by replaying
-- through internal/shell breaks the moment a non-deterministic response
-- source is used -- see session.ResponseSourceLLM, already a defined enum
-- value for exactly that case).
--
-- IMPORTANT -- this file will NOT run automatically against an
-- already-running deployment. Files under db/init/ are only executed by the
-- postgres image on first container start, against an empty data directory
-- (see https://hub.docker.com/_/postgres, "Initialization scripts"). Since
-- this server is already running with data on disk, apply it by hand once,
-- e.g.:
--
--     docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < internal/store/migrations/004_command_response.sql
--
-- ADD COLUMN ... (nullable, no default) is a metadata-only change on
-- PostgreSQL -- it does not rewrite the existing table and takes a brief
-- ACCESS EXCLUSIVE lock, so it is safe to run against a live table.
--
-- NULL means "predates this migration" for every existing row, same
-- convention deception_action already established (see 003_deception.sql).

ALTER TABLE commands ADD COLUMN IF NOT EXISTS response_text TEXT;
ALTER TABLE commands ADD COLUMN IF NOT EXISTS exit_code INTEGER;
