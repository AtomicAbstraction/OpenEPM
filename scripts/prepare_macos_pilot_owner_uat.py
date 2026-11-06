#!/usr/bin/env python3
"""Seal a no-effect preparation plan for the one-owner writable Mac UAT.

The plan deliberately performs no Docker, database, ingress or authorization
operation.  It binds the protected read-only review generation to the existing
qualified blue/green activation machinery and makes the final writable switch
an explicit, separately authorized action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts import macos_pilot_ui_review as review_controller


SHA = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVIEW_FORMAT = "openepm-macos-pilot-ui-review-state-v1"
PLAN_FORMAT = "openepm-macos-pilot-owner-uat-plan-v1"
REQUIRED_ENDPOINTS = ("web", "platform", "workspace", "application")


class OwnerUatPlanError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _review(value: object) -> dict:
    if not isinstance(value, dict) \
            or value.get("format") != REVIEW_FORMAT \
            or value.get("state") != "active" \
            or value.get("verified") is not True \
            or value.get("authoritativePilotMutation") is not False \
            or value.get("databaseReadOnly") is not True \
            or value.get("publicWebOnly") is not True \
            or IMAGE.fullmatch(str(value.get("candidateImage"))) is None \
            or IMAGE.fullmatch(str(value.get("databaseImage"))) is None \
            or SHA.fullmatch(str(value.get("backupSha256"))) is None \
            or not isinstance(value.get("expectedSchema"), int) \
            or isinstance(value.get("expectedSchema"), bool) \
            or value["expectedSchema"] < 1 \
            or value.get("expectedApplications") not in (5, 6):
        raise OwnerUatPlanError("verified read-only review state is required")
    return value


def _inventory(value: object) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise OwnerUatPlanError("bounded Open EPM service inventory is required")
    result = []
    seen = set()
    allowed = {"openepm-ui-review", "openepm-macos-pilot"}
    for item in value:
        required = {"project", "service", "container", "image", "state",
                    "status", "ports"}
        if not isinstance(item, dict) or set(item) != required \
                or item.get("project") not in allowed \
                or not all(isinstance(item.get(key), str) for key in required) \
                or not item["service"] or not item["container"] \
                or (item["project"], item["service"]) in seen:
            raise OwnerUatPlanError("Open EPM service inventory differs")
        seen.add((item["project"], item["service"]))
        result.append(dict(item))
    if ("openepm-ui-review", "web") not in seen \
            or ("openepm-ui-review", "db") not in seen:
        raise OwnerUatPlanError("read-only review services are incomplete")
    for service in ("db", "platform", "workspace", "router", "worker"):
        if ("openepm-macos-pilot", service) not in seen:
            raise OwnerUatPlanError("protected source service inventory is incomplete")
    return sorted(result, key=lambda item: (item["project"], item["service"]))


def build(review_state: object, service_inventory: object, *,
          workspace_id: str, application_id: str) -> dict:
    review = _review(review_state)
    inventory = _inventory(service_inventory)
    if workspace_id != "ws-pilot" or application_id != "pilot-fpna":
        raise OwnerUatPlanError("owner UAT application binding differs")
    body = {
        "format": PLAN_FORMAT,
        "effectIncluded": False,
        "ownerActionTimeAuthorizationRequired": True,
        "review": {
            "project": review["project"],
            "applicationImage": review["candidateImage"],
            "databaseImage": review["databaseImage"],
            "schema": review["expectedSchema"],
            "applicationCount": review["expectedApplications"],
            "backupName": review["backupName"],
            "backupSha256": review["backupSha256"],
            "databaseReadOnly": True,
        },
        "uat": {
            "workspaceId": workspace_id,
            "applicationId": application_id,
            "ownerIdentityCount": 1,
            "isolatedWritableVolumeRequired": True,
            "protectedSourceMutationAllowed": False,
            "readOnlyReviewMayBeMadeWritable": False,
            "endpointGeneration": list(REQUIRED_ENDPOINTS),
            "workerGenerationMustMatch": True,
            "rollbackMustPassBeforePublicWriteGate": True,
            "publicWriteGateInitiallyClosed": True,
        },
        "activation": {
            "mechanism": "qualified-blue-green-controller-v3",
            "prepare": [
                "capture-fresh-protected-backup",
                "restore-distinct-green-volume",
                "migrate-and-verify-exact-schema",
                "start-all-green-services-on-private-ports",
                "verify-web-and-three-mcp-endpoints-bind-green",
                "verify-worker-binds-green",
                "exercise-stop-and-blue-rollback",
            ],
            "authorizedSwitch": [
                "close-public-admission",
                "quiesce-blue-and-review",
                "select-green-endpoint-generation",
                "open-green-producer-and-public-write-gates",
                "verify-owner-authenticated-read-and-write",
            ],
        },
        "observedServiceInventorySha256": digest(inventory),
        "observedServices": inventory,
        "acceptanceMatrix": "docs/local-mac-owner-functional-uat.md",
    }
    return {**body, "planSha256": digest(body)}


def verify(value: object) -> dict:
    if not isinstance(value, dict) or value.get("format") != PLAN_FORMAT:
        raise OwnerUatPlanError("owner UAT plan differs")
    claimed = value.get("planSha256")
    body = {key: item for key, item in value.items() if key != "planSha256"}
    if SHA.fullmatch(str(claimed)) is None or digest(body) != claimed \
            or value.get("effectIncluded") is not False \
            or value.get("ownerActionTimeAuthorizationRequired") is not True:
        raise OwnerUatPlanError("owner UAT plan digest or boundary differs")
    return value


def capture_service_inventory() -> list[dict]:
    completed = subprocess.run(
        ["docker", "ps", "--format", "{{json .}}"], cwd=ROOT,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, check=False)
    if completed.returncode:
        raise OwnerUatPlanError((completed.stderr or completed.stdout).strip()
                                or "Docker inventory is unavailable")
    selected = []
    for line in completed.stdout.splitlines():
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as error:
            raise OwnerUatPlanError("Docker inventory is invalid") from error
        labels = {}
        for pair in raw.get("Labels", "").split(","):
            if "=" in pair:
                key, value = pair.split("=", 1); labels[key] = value
        project = labels.get("com.docker.compose.project")
        if project not in ("openepm-ui-review", "openepm-macos-pilot"):
            continue
        selected.append({
            "project": project,
            "service": labels.get("com.docker.compose.service", ""),
            "container": raw.get("Names", ""),
            "image": raw.get("Image", ""),
            "state": raw.get("State", ""),
            "status": raw.get("Status", ""),
            "ports": raw.get("Ports", ""),
        })
    return _inventory(selected)


def capture_live(state_root: Path) -> tuple[dict, list[dict]]:
    if not state_root.is_absolute():
        raise OwnerUatPlanError("review state root must be absolute")
    state = review_controller.status(argparse.Namespace(state_root=state_root))
    return state, capture_service_inventory()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-state", type=Path)
    parser.add_argument("--service-inventory", type=Path)
    parser.add_argument("--capture-live", action="store_true")
    parser.add_argument("--state-root", type=Path, default=
                        ROOT / "deploy/macos-pilot/.runtime/ui-review")
    parser.add_argument("--workspace-id", default="ws-pilot")
    parser.add_argument("--application-id", default="pilot-fpna")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.exists():
        parser.error("output must be a new absolute path")
    try:
        if args.capture_live:
            if args.review_state is not None or args.service_inventory is not None:
                raise OwnerUatPlanError(
                    "live capture cannot be combined with supplied observations")
            review, inventory = capture_live(args.state_root.resolve())
        else:
            if args.review_state is None or args.service_inventory is None:
                raise OwnerUatPlanError(
                    "review state and service inventory are required")
            review = json.loads(args.review_state.read_text(encoding="utf-8"))
            inventory = json.loads(
                args.service_inventory.read_text(encoding="utf-8"))
        value = build(review, inventory, workspace_id=args.workspace_id,
                      application_id=args.application_id)
        verify(value)
        args.output.write_bytes(canonical(value) + b"\n")
        args.output.chmod(0o600)
    except (OSError, UnicodeError, json.JSONDecodeError,
            OwnerUatPlanError) as error:
        parser.error(str(error))
    print(json.dumps({"effectIncluded": False,
                      "ownerActionTimeAuthorizationRequired": True,
                      "planSha256": value["planSha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

