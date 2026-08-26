-- Same table as db/init/003_sensor_heartbeats.sql -- see that file for the
-- full rationale. This is the hand-apply copy for an already-running
-- deployment (db/init/ only executes on first container start against an
-- empty data directory).
--
--     docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < internal/store/migrations/008_sensor_heartbeats.sql

CREATE TABLE IF NOT EXISTS sensor_heartbeats (
    sensor_id TEXT NOT NULL,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sensor_heartbeats_sensor_ts
    ON sensor_heartbeats (sensor_id, ts DESC);
