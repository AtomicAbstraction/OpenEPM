#!/usr/bin/env bash
set -euo pipefail

# One-shot recovery initializer. Only a fresh, empty PGDATA is accepted.
if (( $# < 1 || $# > 2 )); then
  echo 'Usage: restore_postgres_physical.sh BACKUP_NAME [UTC_TARGET_TIME]' >&2
  exit 2
fi
backup_name=$1
target_time=${2:-}
if [[ ! $backup_name =~ ^base-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]]; then
  echo 'Invalid backup name' >&2
  exit 2
fi
if [[ -n $target_time && ! $target_time =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$ ]]; then
  echo 'Target time must be an ISO-8601 UTC timestamp' >&2
  exit 2
fi
backup="/var/lib/postgresql/base_backups/$backup_name"
archive=/var/lib/postgresql/wal_archive
data=${PGDATA:?PGDATA is required}
if [[ ! -d $backup || ! -f $backup/backup_manifest || ! -d $archive ]]; then
  echo 'Physical backup or WAL archive is unavailable' >&2
  exit 1
fi
mkdir -p -- "$data"
if [[ -n $(find "$data" -mindepth 1 -print -quit) ]]; then
  echo 'Recovery refuses nonempty PGDATA' >&2
  exit 1
fi
pg_verifybackup "$backup"
cp -a -- "$backup/." "$data/"
rm -f -- "$data/postmaster.pid" "$data/standby.signal"
touch "$data/recovery.signal"
printf "restore_command = 'cp /var/lib/postgresql/wal_archive/%%f %%p'\n" \
  >> "$data/postgresql.auto.conf"
if [[ -n $target_time ]]; then
  postgres_target="${target_time/T/ }"
  postgres_target="${postgres_target%Z}+00"
  printf "recovery_target_time = '%s'\nrecovery_target_action = 'promote'\n" \
    "$postgres_target" >> "$data/postgresql.auto.conf"
fi
chmod 0700 "$data"
chown -R postgres:postgres "$data"
ready_marker=/var/lib/postgresql/.openepm-recovery-ready
printf '%s\n%s\n' "$backup_name" "$target_time" > "$ready_marker"
chmod 0600 "$ready_marker"
chown postgres:postgres "$ready_marker"
printf 'Prepared fresh recovery data from %s%s\n' "$backup_name" \
  "${target_time:+ at $target_time}"
