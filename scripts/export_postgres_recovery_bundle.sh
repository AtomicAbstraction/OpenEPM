#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^base-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]]; then
  echo 'Usage: export_postgres_recovery_bundle.sh BACKUP_NAME' >&2
  exit 2
fi
backup_name=$1
source_backup="/var/lib/postgresql/base_backups/$backup_name"
source_archive=/var/lib/postgresql/wal_archive
destination=/bundle
if [[ ! -d $source_backup || ! -d $source_archive || ! -d $destination ||
      ! -w $destination || ! -f $destination/.openepm-host-visible ]]; then
  echo 'Backup, WAL archive or host-prepared bundle destination is unavailable' >&2
  exit 1
fi
if [[ ! ${EPM_BUNDLE_UID:-} =~ ^[0-9]+$ || ! ${EPM_BUNDLE_GID:-} =~ ^[0-9]+$ ]]; then
  echo 'Numeric EPM_BUNDLE_UID and EPM_BUNDLE_GID are required' >&2
  exit 2
fi
name="openepm-$backup_name"
stage="$destination/.$name.partial.$$"
final="$destination/$name"
if [[ -e $final ]]; then
  echo 'Bundle destination already exists' >&2
  exit 1
fi
mkdir -m 0700 -- "$stage"
completed=0
cleanup() {
  if (( completed == 0 )); then rm -rf -- "$stage"; fi
}
trap cleanup EXIT
mkdir -m 0700 "$stage/base" "$stage/wal_archive"
pg_verifybackup "$source_backup"
cp -a -- "$source_backup" "$stage/base/"
cp -a -- "$source_archive/." "$stage/wal_archive/"
if [[ -n $(find "$stage" -type l -print -quit) ]]; then
  echo 'Symlinks in a physical backup bundle are unsupported' >&2
  exit 1
fi
pg_verifybackup "$stage/base/$backup_name"
while IFS= read -r -d '' file; do
  relative=${file#"$stage/wal_archive/"}
  if ! cmp -s -- "$file" "$source_archive/$relative"; then
    echo 'A WAL archive file changed during export' >&2
    exit 1
  fi
done < <(find "$stage/wal_archive" -type f -print0)
printf 'format=openepm-physical-recovery-v1\nbackup=%s\n' \
  "$backup_name" > "$stage/MANIFEST"
(cd "$stage" && find . -type f ! -path './SHA256SUMS' -print0 |
  LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)
chown -R "${EPM_BUNDLE_UID}:${EPM_BUNDLE_GID}" "$stage"
mv -- "$stage" "$final"
sync
completed=1
printf '%s\n' "$name"
