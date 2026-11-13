#!/usr/bin/env python3
"""Create one bounded owner-only logical backup of the shared Mac pilot.

Dry-plan mode never contacts Docker. Execution is fixed to the established
pilot database container and writes only to its protected backup volume. The
database itself is read through ``pg_dump`` and is never modified.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile


SOURCE_CONTAINER = "openepm-macos-pilot-db-1"
COMPOSE_PROJECT = "openepm-macos-pilot"
COMPOSE_SERVICE = "db"
SOURCE_PROFILES = {
    "pilot": {
        "container": SOURCE_CONTAINER,
        "project": COMPOSE_PROJECT,
        "service": COMPOSE_SERVICE,
        "namePrefix": "pilot-pre-upgrade",
    },
    "owner-uat": {
        "container": "openepm-owner-uat-green-db-1",
        "project": "openepm-owner-uat-green",
        "service": "db",
        "namePrefix": "pilot-owner-uat",
    },
}
BACKUP_ROOT = "/var/lib/postgresql/base_backups"
UTC_INSTANT = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})Z$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")


class BackupError(ValueError):
    pass


def bounded_instant(value: str | None) -> tuple[str, str]:
    if value is None:
        value = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    match = UTC_INSTANT.fullmatch(value)
    if match is None:
        raise BackupError("captured-at UTC must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime(
            *(int(match.group(field)) for field in (
                "year", "month", "day", "hour", "minute", "second")),
            tzinfo=timezone.utc)
    except ValueError as error:
        raise BackupError("captured-at UTC is not a real instant") from error
    canonical = parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    compact = parsed.strftime("%Y%m%dT%H%M%SZ")
    return canonical, compact


def plan(output: Path, captured_at_utc: str | None = None,
         source_profile: str = "pilot") -> dict[str, object]:
    if not output.is_absolute():
        raise BackupError("backup evidence output must be an absolute path")
    if output.exists():
        raise BackupError("backup evidence output already exists")
    profile = SOURCE_PROFILES.get(source_profile)
    if profile is None:
        raise BackupError("backup source profile is not allowlisted")
    captured, compact = bounded_instant(captured_at_utc)
    name = f"{profile['namePrefix']}-{compact}.dump"
    return {
        "format": "openepm-macos-pilot-protected-backup-plan-v1",
        "capturedAtUtc": captured,
        "backupName": name,
        "pathInsideProtectedBackupVolume": f"{BACKUP_ROOT}/{name}",
        "sourceProfile": source_profile,
        "sourceContainer": profile["container"],
        "sourceComposeProject": profile["project"],
        "sourceComposeService": profile["service"],
        "databaseName": "postgres",
        "backupFormat": "PostgreSQL custom",
        "ownerOnlyMode": "0600",
        "sharedBusinessMutation": False,
        "protectedBackupVolumeMutation": True,
        "output": str(output),
    }


def docker(*arguments: str) -> str:
    completed = subprocess.run(
        ["docker", *arguments], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        message = completed.stderr.strip() or "docker command failed"
        raise RuntimeError(message)
    return completed.stdout.strip()


def require_exact_source(value: dict[str, object] | None = None) -> dict[str, object]:
    if value is None:
        value = plan(Path("/tmp/openepm-unused-backup-evidence.json"))
    container = value.get("sourceContainer")
    project = value.get("sourceComposeProject")
    service = value.get("sourceComposeService")
    profile_name = value.get("sourceProfile")
    profile = SOURCE_PROFILES.get(profile_name) if isinstance(
        profile_name, str) else None
    if profile is None or container != profile["container"] \
            or project != profile["project"] or service != profile["service"]:
        raise RuntimeError("backup source profile differs from its allowlist")
    raw = docker("inspect", str(container))
    try:
        values = json.loads(raw)
        value = values[0]
        labels = value["Config"]["Labels"]
        state = value["State"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("pilot database container inspection is invalid") from error
    if labels.get("com.docker.compose.project") != project \
            or labels.get("com.docker.compose.service") != service:
        raise RuntimeError("fixed source is not the expected pilot database service")
    if state.get("Running") is not True:
        raise RuntimeError("pilot database container is not running")
    health = state.get("Health", {}).get("Status")
    if health != "healthy":
        raise RuntimeError("pilot database container is not healthy")
    image = value.get("Image")
    if not isinstance(image, str) or IMAGE.fullmatch(image) is None:
        raise RuntimeError("pilot database image identity is invalid")
    return {"databaseContainerImage": image, "databaseHealthy": True}


BACKUP_SCRIPT = r"""
set -euo pipefail
root=/var/lib/postgresql/base_backups
name=$1
token=$2
stage="$root/.$name.partial-$token"
final="$root/$name"
test -d "$root" && test -w "$root"
test ! -e "$stage" && test ! -e "$final"
umask 077
cleanup() { rm -f -- "$stage"; }
trap cleanup EXIT HUP INT TERM
pg_dump -U postgres -d postgres --format=custom --no-owner \
  --file "$stage"
chmod 0600 "$stage"
catalog=$(pg_restore --list "$stage" | wc -l | tr -d '[:space:]')
acls=$(pg_restore --list "$stage" | awk '/ ACL | DEFAULT ACL / {n++} END {print n+0}')
case "$catalog" in ''|*[!0-9]*) exit 70;; esac
case "$acls" in ''|*[!0-9]*) exit 70;; esac
test "$catalog" -gt 0
test "$acls" -gt 0
digest=$(sha256sum "$stage" | awk '{print $1}')
bytes=$(stat -c '%s' "$stage")
mode=$(stat -c '%a' "$stage")
test "$mode" = 600
mv -- "$stage" "$final"
sync
trap - EXIT HUP INT TERM
printf '%s\t%s\t%s\t%s\t%s\n' "$bytes" "$digest" "$catalog" "$acls" "$mode"
""".strip()


def execute(value: dict[str, object]) -> dict[str, object]:
    if os.environ.get("EPM_PILOT_BACKUP_CREATE") != "1":
        raise BackupError("protected backup creation opt-in is required")
    source = require_exact_source(value)
    token = secrets.token_hex(8)
    receipt = docker(
        "exec", str(value["sourceContainer"]), "bash", "-o", "pipefail", "-ec",
        BACKUP_SCRIPT, "--", str(value["backupName"]), token)
    fields = receipt.split("\t")
    if len(fields) != 5:
        raise RuntimeError("backup receipt shape is invalid")
    bytes_text, digest, catalog_text, acl_text, mode = fields
    if not bytes_text.isdecimal() or int(bytes_text) <= 0:
        raise RuntimeError("backup byte count is invalid")
    if DIGEST.fullmatch(digest) is None:
        raise RuntimeError("backup SHA-256 is invalid")
    if not catalog_text.isdecimal() or int(catalog_text) <= 0:
        raise RuntimeError("backup catalogue count is invalid")
    if not acl_text.isdecimal() or int(acl_text) <= 0:
        raise RuntimeError("backup contains no PostgreSQL privilege ACL entries")
    if mode != "600":
        raise RuntimeError("backup is not owner-only")
    return {
        **value,
        **source,
        "format": "openepm-macos-pilot-protected-backup-v1",
        "planFormat": value["format"],
        "status": "protected-backup-created",
        "backup": {
            "bytes": int(bytes_text),
            "sha256": digest,
            "catalogEntries": int(catalog_text),
            "aclEntries": int(acl_text),
            "catalogReadable": True,
            "mode": "0600",
            "partialRemovedOrAtomicallyPublished": True,
        },
        "secretsRetained": False,
    }


def write_evidence(output: Path, value: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="." + output.name + ".", suffix=".partial", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captured-at-utc")
    parser.add_argument("--source-profile", choices=tuple(SOURCE_PROFILES),
                        default="pilot")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        value = plan(arguments.output, arguments.captured_at_utc,
                     arguments.source_profile)
        if not arguments.execute:
            print(json.dumps(value, sort_keys=True))
            return 0
        result = execute(value)
        write_evidence(arguments.output, result)
    except (BackupError, OSError, RuntimeError) as error:
        parser.error(str(error))
    print(json.dumps({"passed": True, "output": str(arguments.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
