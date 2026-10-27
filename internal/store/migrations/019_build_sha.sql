-- Commit the sensor binary was built from (internal/buildinfo), stamped on every
-- session from schema_version 1.2. node_id is the emulated OS and schema_version
-- is shared by every build of an era, so before this column builds could only be
-- told apart by inference. Rows written before it stay '' (unknown), which is
-- different from the 'unknown' an unstamped build writes on purpose.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS build_sha TEXT NOT NULL DEFAULT '';
