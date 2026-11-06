#!/usr/bin/env bash
set -euo pipefail

# Run inside the database container. Backups are staged and verified before
# their final directory name becomes visible to an operator.
backup_root=/var/lib/postgresql/base_backups
if [[ $(psql -U postgres -Atqc 'SHOW archive_mode') != on ]]; then
  echo 'WAL archiving is not enabled' >&2
  exit 1
fi
if [[ ! -d $backup_root || ! -w $backup_root ]]; then
  echo 'The physical-backup volume is not writable' >&2
  exit 1
fi
export PGPASSWORD="${PGPASSWORD:-${POSTGRES_PASSWORD:-}}"
name="base-$(date -u +%Y%m%dT%H%M%SZ)-$$"
stage="$backup_root/.$name.partial"
final="$backup_root/$name"
mkdir -m 0700 -- "$stage"
completed=0
cleanup() {
  if (( completed == 0 )); then
    rm -rf -- "$stage"
  fi
}
trap cleanup EXIT
pg_basebackup -h 127.0.0.1 -U postgres --no-password \
  -D "$stage" -Fp -Xs --checkpoint=fast
pg_verifybackup "$stage"
psql -U postgres -Atqc 'SELECT pg_switch_wal()' >/dev/null
mv -- "$stage" "$final"
sync
completed=1
printf '%s\n' "$name"
