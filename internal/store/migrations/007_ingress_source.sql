-- PROXY protocol v1 support (internal/proxyproto), gated by the opt-in
-- TRUST_PROXY_PROTOCOL env var (default false -- see internal/server/server.go).
--
-- Until now, sessions.client_ip/client_port were always exactly whatever
-- conn.RemoteAddr() reported -- correct as long as attackers connect
-- directly, wrong the moment Mirage sits behind something that forwards
-- connections at the TCP layer (a load balancer, a relay/sensor node,
-- etc.), since every session would then get logged with the relay's
-- address instead of the real client's. These two columns record which
-- case produced a given row, so that distinction is never silently lost:
--
--   ingress_source = 'direct'  -- client_ip/client_port are the real TCP
--                                 peer, exactly as before this migration.
--   ingress_source = 'proxied' -- a PROXY v1 header was parsed off this
--                                 connection; client_ip/client_port are the
--                                 header's claimed original client, and
--                                 proxy_node_id identifies which relay/
--                                 sensor node it came through.
--
-- proxy_node_id is the header's dst-ip field kept verbatim/opaque (it isn't
-- necessarily a real IP -- see proxyproto.Conn.RealRemoteAddr's doc
-- comment) and is NULL whenever ingress_source is 'direct'.
--
-- IMPORTANT -- this file will NOT run automatically against an
-- already-running deployment. Files under db/init/ are only executed by the
-- postgres image on first container start, against an empty data directory
-- (see https://hub.docker.com/_/postgres, "Initialization scripts"). Since
-- this server is already running with data on disk, apply it by hand once,
-- e.g.:
--
--     docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < internal/store/migrations/007_ingress_source.sql
--
-- ADD COLUMN ... TEXT NOT NULL DEFAULT 'direct' is still a metadata-only
-- change here, not a full table rewrite: PostgreSQL 11+ optimizes ADD
-- COLUMN with a constant DEFAULT by storing the default in the catalog
-- rather than writing it into every existing row, so this takes a brief
-- ACCESS EXCLUSIVE lock the same way 003_deception.sql/004_command_response.sql
-- did, not a long one proportional to table size. Every row that predates
-- this migration correctly reads as 'direct', which is exactly what it was.

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ingress_source TEXT NOT NULL DEFAULT 'direct';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS proxy_node_id TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_ingress_source
    ON sessions (ingress_source)
    WHERE ingress_source <> 'direct';
