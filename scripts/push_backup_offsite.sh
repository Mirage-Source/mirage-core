#!/bin/sh
# Pushes the most recent local DB backups (scripts/backup_db.sh) to a private
# offsite git repo, as a single fresh orphan commit each run so the repo's
# history never grows unbounded no matter how long the cron runs.
#
# Requires a git credential file readable only by root at $CRED_FILE, e.g.:
#   https://<user>:<fine-grained-PAT scoped to the offsite repo>@github.com
#
# Usage:
#   ./scripts/push_backup_offsite.sh
#
# Env overrides:
#   LOCAL_BACKUP_DIR  (default: ./backups)
#   OFFSITE_DIR       (default: /root/mirage-backups-offsite)
#   OFFSITE_REPO_URL  (default: https://github.com/Mirage-Source/mirage-backups.git)
#   CRED_FILE         (default: /root/.git-credentials-backups)
#   KEEP_N            (default: 5)

set -eu

LOCAL_BACKUP_DIR="${LOCAL_BACKUP_DIR:-./backups}"
OFFSITE_DIR="${OFFSITE_DIR:-/root/mirage-backups-offsite}"
OFFSITE_REPO_URL="${OFFSITE_REPO_URL:-https://github.com/Mirage-Source/mirage-backups.git}"
CRED_FILE="${CRED_FILE:-/root/.git-credentials-backups}"
KEEP_N="${KEEP_N:-5}"

if [ ! -f "$CRED_FILE" ]; then
    echo "Missing credential file: $CRED_FILE" >&2
    exit 1
fi

latest=$(ls -1t "$LOCAL_BACKUP_DIR"/mirage-*.sql.gz 2>/dev/null | head -n 1 || true)
if [ -z "$latest" ]; then
    echo "No local backups found in $LOCAL_BACKUP_DIR; nothing to push." >&2
    exit 1
fi

if [ ! -d "$OFFSITE_DIR/.git" ]; then
    git -c "credential.helper=store --file=$CRED_FILE" clone "$OFFSITE_REPO_URL" "$OFFSITE_DIR"
fi

cd "$OFFSITE_DIR"
git config credential.helper "store --file=$CRED_FILE"
git config user.email "backups@mirage.local"
git config user.name "mirage-backup-bot"

# Fresh orphan commit every run -- keeps the repo's total size bounded at
# roughly KEEP_N backups worth, forever, instead of accumulating one commit
# per day indefinitely.
git checkout --orphan latest-tmp 2>/dev/null || git checkout latest-tmp
find . -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +

ls -1t "$LOCAL_BACKUP_DIR"/mirage-*.sql.gz | head -n "$KEEP_N" | while read -r f; do
    cp "$f" .
done

git add -A
git commit -m "backup snapshot $(date -u +%Y-%m-%dT%H:%M:%SZ)" --quiet
git branch -M main
git push --force origin main

echo "Pushed offsite: $(ls "$OFFSITE_DIR"/mirage-*.sql.gz | wc -l) file(s) at $(du -sh "$OFFSITE_DIR" | cut -f1)"
