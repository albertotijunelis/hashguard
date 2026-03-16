#!/bin/sh
# HashGuard — Daily PostgreSQL backup to S3
# Runs inside the backup container via docker-compose.production.yml

set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/tmp/hashguard_${TIMESTAMP}.sql.gz"
S3_KEY="backups/db/hashguard_${TIMESTAMP}.sql.gz"

echo "[$(date)] Starting database backup..."

# Dump and compress
pg_dump -Fc --no-acl --no-owner | gzip > "${BACKUP_FILE}"

FILESIZE=$(stat -c%s "${BACKUP_FILE}" 2>/dev/null || stat -f%z "${BACKUP_FILE}")
echo "[$(date)] Backup created: ${BACKUP_FILE} (${FILESIZE} bytes)"

# Upload to S3
aws s3 cp "${BACKUP_FILE}" "s3://${HG_S3_BUCKET}/${S3_KEY}" --quiet
echo "[$(date)] Uploaded to s3://${HG_S3_BUCKET}/${S3_KEY}"

# Cleanup local file
rm -f "${BACKUP_FILE}"

# Prune backups older than 30 days
CUTOFF=$(date -d "-30 days" +%Y%m%d 2>/dev/null || date -v-30d +%Y%m%d)
aws s3 ls "s3://${HG_S3_BUCKET}/backups/db/" | while read -r line; do
  FILE=$(echo "$line" | awk '{print $4}')
  FILE_DATE=$(echo "$FILE" | grep -oP '\d{8}' | head -1)
  if [ -n "$FILE_DATE" ] && [ "$FILE_DATE" -lt "$CUTOFF" ] 2>/dev/null; then
    aws s3 rm "s3://${HG_S3_BUCKET}/backups/db/${FILE}" --quiet
    echo "[$(date)] Pruned old backup: ${FILE}"
  fi
done

echo "[$(date)] Backup complete."
