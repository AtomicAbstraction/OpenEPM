#!/usr/bin/env python3
"""Restore the latest protected owner-UAT backup into disposable PostgreSQL."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts.macos_pilot_owner_uat_controller import FORMAT, IMAGE, PROJECT
from scripts.qualify_macos_pilot_backup_restore import (
    create_group_roles, docker, file_digest, scalar, wait_ready)


def qualify(state_root: Path) -> dict:
    if os.environ.get("EPM_OWNER_UAT_BACKUP_RESTORE_DISPOSABLE") != "1":
        raise ValueError("owned disposable restore opt-in is required")
    root = state_root.resolve()
    state_path = root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if (state.get("format") != FORMAT or state.get("project") != PROJECT
            or state.get("state") != "active"):
        raise ValueError("active owner UAT state is required")
    backup = state.get("lastBackup")
    if not isinstance(backup, dict) or backup not in state.get("backupHistory", []):
        raise ValueError("recorded owner UAT backup is required")
    name = backup.get("name")
    path = root / "backups" / str(name)
    metadata = path.stat(follow_symlinks=False)
    if (path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_size != backup.get("bytes")
            or file_digest(path) != backup.get("sha256")):
        raise ValueError("protected owner UAT backup differs")
    image = state.get("databaseImage")
    if IMAGE.fullmatch(str(image)) is None or image != backup.get("databaseImage"):
        raise ValueError("owner UAT database image differs")
    token = uuid.uuid4().hex[:12]
    container = "openepm_owner_uat_restore_" + token
    volume = container + "_data"
    password = secrets.token_urlsafe(24)
    container_created = False
    volume_created = False
    try:
        docker("volume", "create", volume)
        volume_created = True
        docker("run", "-d", "--name", container,
               "--label", "openepm.disposable=owner-uat-backup-restore",
               "-v", volume + ":/var/lib/postgresql",
               "-e", "POSTGRES_PASSWORD=" + password, str(image))
        container_created = True
        wait_ready(container)
        docker("cp", str(path), container + ":/tmp/owner-uat.dump")
        docker("exec", "-u", "0:0", container, "chmod", "0444",
               "/tmp/owner-uat.dump")
        listing = docker("exec", container, "pg_restore", "--list",
                         "/tmp/owner-uat.dump")
        entries = sum(1 for line in listing.splitlines()
                      if line and not line.startswith(";"))
        if entries != backup.get("catalogEntries"):
            raise ValueError("owner UAT backup catalogue differs")
        create_group_roles(container)
        docker("exec", container, "pg_restore", "-U", "postgres", "-d",
               "postgres", "--exit-on-error", "--no-owner",
               "/tmp/owner-uat.dump")
        schema = int(scalar(container,
            "SELECT max(version) FROM epm.schema_migration"))
        applications = int(scalar(container,
            "SELECT count(*) FROM epm.application"))
        if (schema != state.get("expectedSchema")
                or schema != backup.get("schema")
                or applications != state.get("expectedApplications")
                or applications != backup.get("applications")):
            raise ValueError("restored owner UAT inventory differs")
        return {
            "format": "openepm-owner-uat-current-backup-restore-v1",
            "status": "passed",
            "qualifiedAt": datetime.now(timezone.utc).isoformat(),
            "backup": backup,
            "restoredSchema": schema,
            "restoredApplications": applications,
            "catalogEntries": entries,
            "disposable": True,
            "sharedBusinessDataChanged": False,
            "cleanupComplete": True,
        }
    finally:
        if container_created:
            docker("rm", "-f", "-v", container)
        if volume_created:
            docker("volume", "rm", volume)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=
                        ROOT / "deploy/macos-pilot/.runtime/owner-uat")
    args = parser.parse_args()
    print(json.dumps(qualify(args.state_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
