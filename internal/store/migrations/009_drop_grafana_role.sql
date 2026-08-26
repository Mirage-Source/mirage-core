-- Retires the grafana_ro role created by 006_grafana_readonly_role.sql --
-- Prometheus+Grafana are being replaced by a dashboard embedded directly in
-- mirage-api (see internal/validity, internal/api/validity.go), which
-- queries Postgres with the same credentials the rest of the API already
-- uses, so this dedicated read-only role has no remaining consumer.
--
-- Idempotent: a no-op on any database that never ran migration 006 (e.g. a
-- fresh deploy from db/init, which never created this role in the first
-- place).
--
--     docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < internal/store/migrations/009_drop_grafana_role.sql

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana_ro') THEN
        EXECUTE 'REASSIGN OWNED BY grafana_ro TO ' || current_user;
        EXECUTE 'DROP OWNED BY grafana_ro';
        DROP ROLE grafana_ro;
    END IF;
END
$$;
