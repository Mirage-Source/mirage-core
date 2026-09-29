CREATE TABLE IF NOT EXISTS telnet_session_meta (
    session_id TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    negotiated BOOLEAN NOT NULL,
    client_options SMALLINT[] NOT NULL DEFAULT '{}',
    terminal_type TEXT,
    window_width INTEGER,
    window_height INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sessions_protocol_non_ssh
    ON sessions (protocol, start_ms)
    WHERE protocol <> 'ssh';
