-- Read-only Postgres role for Grafana to query enriched_sessions directly,
-- instead of Grafana only ever seeing Prometheus counters.
--
-- Same hand-apply caveat as the other files in this directory -- run once
-- against the live DB:
--
--     docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < internal/store/migrations/006_grafana_readonly_role.sql
--
-- Deliberately scoped to SELECT on the tables/view a dashboard needs, not
-- the whole schema -- Grafana users with query-edit rights can run
-- arbitrary SQL through this role, so it must never be able to write or see
-- more than intended. Password is set separately (see the ALTER ROLE ...
-- PASSWORD step in the deploy notes below); this file only creates the role
-- shape and grants.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana_ro') THEN
        CREATE ROLE grafana_ro LOGIN;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE mirage TO grafana_ro;
GRANT USAGE ON SCHEMA public TO grafana_ro;
GRANT SELECT ON sessions, commands, auth_attempts, bait_interactions,
    session_embeddings, enriched_sessions TO grafana_ro;

-- Any tables added later stay read-only-visible to grafana_ro without a
-- follow-up grant.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_ro;
