-- Apply by hand on a running deployment. NULL means the row predates this migration.
ALTER TABLE commands ADD COLUMN IF NOT EXISTS command_chain JSONB;

CREATE INDEX IF NOT EXISTS idx_commands_command_chain
    ON commands USING GIN (command_chain);
