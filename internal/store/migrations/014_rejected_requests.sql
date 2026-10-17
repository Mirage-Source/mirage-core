-- SSH requests the sensor refused: channel opens other than "session"
-- (direct-tcpip carries the host:port the client wanted to reach) and
-- subsystem requests such as sftp. Capped per session in the sensor.
CREATE TABLE IF NOT EXISTS rejected_requests (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    timestamp_ms BIGINT NOT NULL,
    kind TEXT NOT NULL,
    type TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_rejected_requests_session_id ON rejected_requests(session_id);
