#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^openepm-base-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]]; then
  echo 'Usage: import_postgres_recovery_bundle.sh BUNDLE_NAME' >&2
  exit 2
fi
name=$1
backup_name=${name#openepm-}
bundle="/bundle/$name"
backups=/var/lib/postgresql/base_backups
archive=/var/lib/postgresql/wal_archive
if [[ ! -d $bundle || ! -f /bundle/.openepm-host-visible ||
      ! -d $backups || ! -d $archive ]]; then
  echo 'Host-prepared bundle or destination volumes are unavailable' >&2
  exit 1
fi
if [[ -n $(find "$backups" -mindepth 1 -print -quit) ||
      -n $(find "$archive" -mindepth 1 -print -quit) ]]; then
  echo 'Import requires fresh empty backup and WAL volumes' >&2
  exit 1
fi
if [[ -n $(find "$bundle" -type l -print -quit) ]]; then
  echo 'Bundle symlinks are unsupported' >&2
  exit 1
fi
if [[ ! -f $bundle/MANIFEST || ! -f $bundle/SHA256SUMS ||
      ! -d $bundle/base/$backup_name || ! -d $bundle/wal_archive ]]; then
  echo 'Recovery bundle layout is invalid' >&2
  exit 1
fi
expected_manifest=$(printf 'format=openepm-physical-recovery-v1\nbackup=%s' "$backup_name")
if [[ $(cat "$bundle/MANIFEST") != "$expected_manifest" ]]; then
  echo 'Recovery bundle manifest does not match the requested backup' >&2
  exit 1
fi
recomputed=$(mktemp)
trap 'rm -f -- "$recomputed"' EXIT
(cd "$bundle" && find . -type f ! -path './SHA256SUMS' -print0 |
  LC_ALL=C sort -z | xargs -0 sha256sum > "$recomputed")
if ! cmp -s "$recomputed" "$bundle/SHA256SUMS"; then
  echo 'Recovery bundle checksum manifest is inconsistent' >&2
  exit 1
fi
pg_verifybackup "$bundle/base/$backup_name"
cp -a -- "$bundle/base/$backup_name" "$backups/"
cp -a -- "$bundle/wal_archive/." "$archive/"
chown -R postgres:postgres "$backups" "$archive"
pg_verifybackup "$backups/$backup_name"
printf 'Imported %s into fresh backup and WAL volumes\n' "$name"
