-- Files a client uploaded over scp or sftp. Content is never stored on the
-- sensor: only the sha256 (NULL when the transfer did not complete).
CREATE TABLE IF NOT EXISTS file_transfers (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    timestamp_ms BIGINT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    size BIGINT NOT NULL,
    sha256 TEXT,
    complete BOOLEAN NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_file_transfers_session_id ON file_transfers(session_id);
CREATE INDEX IF NOT EXISTS idx_file_transfers_sha256 ON file_transfers(sha256) WHERE sha256 IS NOT NULL;
