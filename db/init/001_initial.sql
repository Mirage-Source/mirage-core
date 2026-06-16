CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,

    schema_version TEXT NOT NULL,
    node_id TEXT NOT NULL,
    protocol TEXT NOT NULL,

    client_ip TEXT NOT NULL,
    client_port INTEGER NOT NULL,
    server_port INTEGER NOT NULL,
    ssh_client_banner TEXT NOT NULL,

    start_ms BIGINT NOT NULL,
    end_ms BIGINT,
    duration_ms BIGINT,

    outcome TEXT NOT NULL,

    command_count INTEGER NOT NULL DEFAULT 0,
    bait_hit_count INTEGER NOT NULL DEFAULT 0,

    attacker_class TEXT,
    classifier_confidence DOUBLE PRECISION,
    cluster_id TEXT,
    mitre_techniques JSONB,
    session_summary TEXT,

    session_document JSONB
);

CREATE TABLE auth_attempts (
    id BIGSERIAL PRIMARY KEY,

    session_id TEXT NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    method TEXT NOT NULL,
    username TEXT NOT NULL,
    credential TEXT NOT NULL,
    success BOOLEAN NOT NULL,

    CONSTRAINT fk_auth_attempts_session
        FOREIGN KEY (session_id)
        REFERENCES sessions(session_id)
        ON DELETE CASCADE
);

CREATE TABLE commands (
    event_id TEXT PRIMARY KEY,

    session_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    inter_command_delay_ms BIGINT,
    raw_input_b64 TEXT NOT NULL,
    parsed_command TEXT NOT NULL,
    parsed_args JSONB NOT NULL,
    working_directory TEXT NOT NULL,
    response_source TEXT NOT NULL,

    CONSTRAINT fk_commands_session
        FOREIGN KEY (session_id)
        REFERENCES sessions(session_id)
        ON DELETE CASCADE,

    CONSTRAINT uq_commands_session_sequence
        UNIQUE (session_id, sequence_number)
);

CREATE TABLE bait_interactions (
    event_id TEXT PRIMARY KEY,

    session_id TEXT NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    bait_id TEXT NOT NULL,
    bait_type TEXT NOT NULL,
    access_type TEXT NOT NULL,
    triggered_by_command_event_id TEXT NOT NULL,

    CONSTRAINT fk_bait_session
        FOREIGN KEY (session_id)
        REFERENCES sessions(session_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_bait_command
        FOREIGN KEY (triggered_by_command_event_id)
        REFERENCES commands(event_id)
);

CREATE INDEX idx_sessions_client_ip ON sessions(client_ip);
CREATE INDEX idx_sessions_start_ms ON sessions(start_ms);
CREATE INDEX idx_auth_attempts_session_id ON auth_attempts(session_id);
CREATE INDEX idx_commands_session_id ON commands(session_id);
CREATE INDEX idx_bait_interactions_session_id ON bait_interactions(session_id);
