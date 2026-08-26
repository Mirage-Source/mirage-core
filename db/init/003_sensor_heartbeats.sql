-- Standing liveness signal for the downtime-vs-silence validity check
-- (internal/validity, HeartbeatGapCheck). "Sensor was down" and "sensor was
-- up but nobody connected" are indistinguishable from session-arrival data
-- alone by construction, so this table exists purely to answer that one
-- question: it's written on a fixed ticker by the SSH server
-- (cmd/mirage/main.go), independent of whether any session happened.
--
-- sensor_id is a free-text label from the SENSOR_ID env var (default
-- "default"), NOT sessions.node_id -- that field is hardcoded to "Ubuntu",
-- the emulated-OS identity string shown to attackers, not a deployment
-- identifier.

CREATE TABLE IF NOT EXISTS sensor_heartbeats (
    sensor_id TEXT NOT NULL,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sensor_heartbeats_sensor_ts
    ON sensor_heartbeats (sensor_id, ts DESC);
