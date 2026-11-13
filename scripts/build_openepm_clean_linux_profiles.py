#!/usr/bin/env python3
"""Generate clean-Linux runtime profiles from an exact qualification plan."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import urllib.parse


class ProfileError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def exact_json(value: object) -> bool:
    if isinstance(value, float):
        return False
    if isinstance(value, dict):
        return all(type(key) is str and exact_json(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return all(exact_json(item) for item in value)
    return value is None or type(value) in (str, int, bool)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError(f"invalid qualification plan: {error}") from error
    if not isinstance(value, dict):
        raise ProfileError("qualification plan must be an object")
    return value


ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION_SOURCE = (ROOT / "deploy/release/qualification/"
                        "python_publication_program.py")


def qualification_source_digest() -> str:
    return __import__("hashlib").sha256(QUALIFICATION_SOURCE.read_bytes()).hexdigest()


CONTRACT_FIELDS = {"mcpEndpoint", "workspaceId", "applicationId", "programId",
    "environmentId", "environmentVersion", "delegationId",
    "executionIssuer", "executionSubjectId",
    "requestPrefix", "expectedResult", "resultFunction",
    "resultArguments", "resultPath",
    "timeoutSeconds"}


def publication_contract(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != CONTRACT_FIELDS:
        raise ProfileError("Python publication contract is incomplete")
    try:
        endpoint = urllib.parse.urlsplit(value["mcpEndpoint"])
        port = endpoint.port
    except (TypeError, ValueError) as error:
        raise ProfileError("Python publication MCP endpoint is invalid") from error
    identifier = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
    if (endpoint.scheme != "https" or not endpoint.hostname
            or endpoint.username is not None or endpoint.password is not None
            or endpoint.query or endpoint.fragment or port == 0
            or not endpoint.path.startswith("/")
            or any(not isinstance(value.get(field), str)
                   or identifier.fullmatch(value[field]) is None
                   for field in ("workspaceId", "applicationId", "programId",
                                 "environmentId", "delegationId", "resultFunction"))
            or type(value.get("environmentVersion")) is not int
            or value["environmentVersion"] < 1
            or any(not isinstance(value.get(field), str) or not value[field]
                   or len(value[field]) > 300
                   or any(ord(character) < 32 or ord(character) == 127
                          for character in value[field])
                   for field in ("executionIssuer", "executionSubjectId"))
            or not isinstance(value.get("requestPrefix"), str)
            or re.fullmatch(r"[A-Za-z0-9._-]{8,96}", value["requestPrefix"]) is None
            or not isinstance(value.get("expectedResult"), str)
            or not value["expectedResult"]
            or len(value["expectedResult"].encode("utf-8")) > 4096
            or any(character in value["expectedResult"] for character in "\r\n\x00")
            or not isinstance(value.get("resultArguments"), dict)
            or not exact_json(value["resultArguments"])
            or len(canonical(value["resultArguments"])) > 65536
            or not isinstance(value.get("resultPath"), list)
            or not value["resultPath"]
            or any(not isinstance(item, str) or not item or len(item) > 200
                   for item in value["resultPath"])
            or type(value.get("timeoutSeconds")) is not int
            or not 10 <= value["timeoutSeconds"] <= 300):
        raise ProfileError("Python publication contract is invalid")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def build(plan: dict, publication: dict) -> dict[str, dict]:
    if plan.get("format") != "openepm-clean-linux-qualification-plan-v2" \
            or plan.get("status") != "execution-required" \
            or plan.get("qualificationClaimed") is not False:
        raise ProfileError("qualification plan is not execution-required")
    images = plan.get("nativeImageDigests")
    if not isinstance(images, dict) \
            or any(not isinstance(images.get(name), str)
                   or not re.fullmatch(r"sha256:[a-f0-9]{64}", images[name])
                   for name in ("builder",)):
        raise ProfileError("qualification plan builder images are invalid")
    publication = publication_contract(publication)
    return {
        "headless-runsc-profile.json": {
            "format": "openepm-headless-runsc-profile-v1",
            "image": images["builder"],
        },
        "python-build-publication-probe.json": {
            "format": "openepm-python-build-publication-probe-v3",
            "builderImage": images["builder"],
            "expectedSourceDigest": qualification_source_digest(),
            **publication,
        },
    }


def write(output: Path, profiles: dict[str, dict]) -> None:
    if output.exists() or output.is_symlink():
        raise ProfileError("output directory already exists")
    output.mkdir(mode=0o755)
    try:
        for name in sorted(profiles):
            path = output / name
            path.write_bytes(canonical(profiles[name]) + b"\n")
            path.chmod(0o444)
    except Exception:
        shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--publication-contract", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        profiles = build(load(arguments.plan.resolve()),
                         load(arguments.publication_contract.resolve()))
        write(arguments.output_directory.resolve(), profiles)
    except ProfileError as error:
        parser.error(str(error))
    print(json.dumps({"format": "openepm-clean-linux-profiles-v2",
        "files": sorted(profiles)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
