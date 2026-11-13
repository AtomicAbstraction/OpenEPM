#!/usr/bin/env python3
"""Live, opt-in qualification of the exact owned-Docker-run boundary.

The fixture borrows an existing image, creates only uniquely named disposable
resources, protects one explicitly supplied live container, and removes every
fixture resource.  It never prunes or infers ownership from names or age.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError:
    from operator_import_path import ensure_project_root

ensure_project_root()

from scripts.audit_disposable_docker_cleanup_candidates import (
    CleanupPending,
    OwnedDockerRun,
    bound_command,
    cleanup,
    context_identity,
    docker,
    reconcile,
    retention_policy,
)


def _child(path: Path, prefix: str, protected: str) -> None:
    policy = copy.deepcopy(retention_policy())
    policy["limits"]["runLeaseSeconds"] = 1
    run = OwnedDockerRun(path, purpose="abandoned cleanup qualification",
                         policy=policy)
    run.__enter__()
    run.protect_container(protected)
    run.volume(prefix + "-abandoned-volume")
    run.container(prefix + "-abandoned-container", "alpine:3.22",
                  "sleep", "60")
    # Simulate a hard process loss: the durable manifest remains, while the OS
    # releases the owner lock.  The parent must respect the lease and reconcile.
    os._exit(0)


def _assert_active(container: str, exact_id: str, command) -> None:
    current = json.loads(command("container", "inspect", container))[0]
    if current["Id"] != exact_id or not current["State"]["Running"]:
        raise AssertionError("PROTECTED_RUNTIME_CHANGED")


def qualify(protected: str) -> dict:
    if os.environ.get("EPM_OWNED_DOCKER_CLEANUP_DISPOSABLE") != "1":
        raise SystemExit("Owned disposable Docker opt-in required")
    current = context_identity()
    command = bound_command(docker, current["context"])
    protected_row = json.loads(command("container", "inspect", protected))[0]
    protected_id = protected_row["Id"]
    if not protected_row["State"]["Running"]:
        raise AssertionError("PROTECTED_RUNTIME_NOT_RUNNING")
    command("image", "inspect", "alpine:3.22")
    prefix = "openepm-cleanup-" + uuid.uuid4().hex[:12]
    foreign = prefix + "-foreign-container"
    success_report = failure_report = pending_report = final_report = None
    abandoned_preview = abandoned_final = abandoned_repeat = None
    with tempfile.TemporaryDirectory(prefix="openepm-cleanup-qualification-") as root:
        root_path = Path(root)
        try:
            with OwnedDockerRun(root_path / "success.json",
                                purpose="successful cleanup qualification") as run:
                run.protect_container(protected)
                volume = run.volume(prefix + "-success-volume")
                run.container(prefix + "-success-container", "--mount",
                              "type=volume,src=" + volume + ",dst=/owned",
                              "alpine:3.22", "true")
            success_report = run.report

            try:
                with OwnedDockerRun(root_path / "failure.json",
                                    purpose="failed cleanup qualification") as run:
                    run.protect_container(protected)
                    run.container(prefix + "-failure-container",
                                  "alpine:3.22", "sleep", "60")
                    raise RuntimeError("deliberate qualification failure")
            except RuntimeError as error:
                if str(error) != "deliberate qualification failure":
                    raise
                failure_report = run.report

            pending_path = root_path / "pending.json"
            try:
                with OwnedDockerRun(pending_path,
                                    purpose="protected reference qualification") as run:
                    run.protect_container(protected)
                    held = run.volume(prefix + "-held-volume")
                    run.volume(prefix + "-safe-volume")
                    command("container", "create", "--name", foreign,
                            "--mount", "type=volume,src=" + held + ",dst=/held",
                            "alpine:3.22", "sleep", "60")
                    command("container", "start", foreign)
            except CleanupPending:
                pending_report = run.report
            command("container", "stop", "--time", "1", foreign)
            command("container", "rm", foreign)
            foreign = ""
            final_report = reconcile(pending_path, execute=True)

            abandoned_path = root_path / "abandoned.json"
            child = os.spawnve(os.P_WAIT, sys.executable,
                [sys.executable, str(Path(__file__).resolve()),
                 "--abandon-child", str(abandoned_path), prefix, protected],
                dict(os.environ, EPM_OWNED_DOCKER_CLEANUP_DISPOSABLE="1"))
            if child != 0:
                raise AssertionError("ABANDONED_CHILD_FAILED")
            abandoned_preview = reconcile(abandoned_path, execute=True)
            if abandoned_preview["pending"][0]["reasons"] != ["run_lease_live"]:
                raise AssertionError("LIVE_LEASE_NOT_PROTECTED")
            abandoned_manifest = json.loads(abandoned_path.read_text())
            time.sleep(1.1)
            abandoned_final = reconcile(abandoned_path, execute=True)
            abandoned_repeat = cleanup(abandoned_manifest, execute=True,
                                       command=docker)
            reconcile_completed = {
                "cleanupVerified": (not abandoned_path.exists()
                    and abandoned_repeat["cleanupVerified"]
                    and not abandoned_repeat["removed"]),
                "remainingManifest": abandoned_path.exists(),
                "remainingLock": Path(str(abandoned_path) + ".lock").exists(),
            }
            if not abandoned_final["cleanupVerified"] or not reconcile_completed[
                    "cleanupVerified"]:
                raise AssertionError("ABANDONED_RECONCILIATION_INCOMPLETE")
        finally:
            if foreign:
                try:
                    command("container", "stop", "--time", "1", foreign)
                except Exception:
                    pass
                try:
                    command("container", "rm", foreign)
                except Exception:
                    pass
        _assert_active(protected, protected_id, command)
    if not (success_report and success_report["cleanupVerified"]
            and failure_report and failure_report["cleanupVerified"]
            and pending_report and pending_report["status"] == "cleanup_pending"
            and final_report and final_report["cleanupVerified"]):
        raise AssertionError("CLEANUP_QUALIFICATION_INCOMPLETE")
    return {
        "format": "openepm-owned-docker-run-qualification-v1",
        "status": "passed",
        "daemonId": current["daemonId"],
        "context": current["context"],
        "protectedContainer": protected,
        "protectedContainerId": protected_id,
        "success": success_report,
        "failure": failure_report,
        "protectedReference": pending_report,
        "protectedReferenceReconciled": final_report,
        "abandonedLeaseProtection": abandoned_preview,
        "abandonedReconciled": abandoned_final,
        "repeatAbsence": abandoned_repeat,
        "borrowedImageRetained": "alpine:3.22",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protected-container")
    parser.add_argument("--abandon-child", nargs=3,
                        metavar=("MANIFEST", "PREFIX", "PROTECTED"))
    arguments = parser.parse_args()
    if arguments.abandon_child:
        manifest, prefix, protected = arguments.abandon_child
        _child(Path(manifest), prefix, protected)
    if not arguments.protected_container:
        parser.error("--protected-container is required")
    print(json.dumps(qualify(arguments.protected_container), sort_keys=True,
                     separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
