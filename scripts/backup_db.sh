#!/bin/sh
# Dumps the mirage Postgres database, compressed, into $BACKUP_DIR, and prunes
# backups older than $RETENTION_DAYS. Run from the repo root (docker-compose.yml
# must be in the current directory) via cron on the host, not inside a container.
#
# Usage:
#   ./scripts/backup_db.sh
#
# Env overrides:
#   BACKUP_DIR       (default: ./backups)
#   RETENTION_DAYS   (default: 14)
#   DB_USER          (default: mirage)
#   DB_NAME          (default: mirage)

set -eu

BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
DB_USER="${DB_USER:-mirage}"
DB_NAME="${DB_NAME:-mirage}"

mkdir -p "$BACKUP_DIR"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
out_file="$BACKUP_DIR/mirage-${timestamp}.sql.gz"
tmp_file="${out_file}.tmp"

docker compose exec -T postgres pg_dump -U "$DB_USER" -d "$DB_NAME" | gzip > "$tmp_file"

# gzip -t verifies the archive isn't truncated/corrupt before we trust it.
gzip -t "$tmp_file"
mv "$tmp_file" "$out_file"

echo "Backup written: $out_file ($(du -h "$out_file" | cut -f1))"

find "$BACKUP_DIR" -name 'mirage-*.sql.gz' -mtime "+${RETENTION_DAYS}" -print -delete
