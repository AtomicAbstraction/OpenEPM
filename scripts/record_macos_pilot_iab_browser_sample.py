#!/usr/bin/env python3
"""Append one bounded observation made through Codex's in-app browser.

This utility never receives or stores a browser credential, cookie, email, or
raw identity.  The protected load contract supplies the expected subject hash
and session binding; the caller supplies only rendered-page observations.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import time

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.macos_pilot_load import MacPilotLoadContract, PilotLoadError


MAX_FEED_BYTES = 4 * 1024 * 1024


def _bounded_text(value: str, name: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 256
            or any(ord(character) < 32 for character in value)):
        raise PilotLoadError(f"{name} is invalid")
    return value


def append_sample(config_path: Path, *, sequence: int,
                  observed_web_origin: str, identity_subject_sha256: str,
                  navigation_seconds: float, applications_seconds: float,
                  application_count: int, page_title: str,
                  marker_observed: str, presentation_bundle_loaded: bool,
                  console_error_count: int, observed_at: float | None = None) -> dict:
    contract = MacPilotLoadContract.load(config_path.resolve())
    browser = contract.raw["browser"]
    if "sampleFeed" not in browser:
        raise PilotLoadError("configuration does not use the Codex IAB feed")
    if (type(sequence) is not int or sequence <= 0
            or type(application_count) is not int or application_count < 0
            or type(console_error_count) is not int or console_error_count < 0
            or type(presentation_bundle_loaded) is not bool
            or any(type(value) not in (int, float) or value < 0 or value > 300
                   for value in (navigation_seconds, applications_seconds))):
        raise PilotLoadError("browser sample values are invalid")
    if (observed_web_origin.rstrip("/") != browser["webOrigin"].rstrip("/")
            or identity_subject_sha256 != browser["identitySubjectSha256"]):
        raise PilotLoadError("browser observation binding is invalid")
    timestamp = time.time() if observed_at is None else observed_at
    if type(timestamp) not in (int, float) or timestamp <= 0:
        raise PilotLoadError("browser observation time is invalid")
    record = {"format": "openepm-codex-iab-browser-sample-v1",
        "sessionId": browser["sessionId"], "sequence": sequence,
        "observedAt": timestamp,
        "webOrigin": browser["webOrigin"],
        "identitySubjectSha256": browser["identitySubjectSha256"],
        "navigationSeconds": navigation_seconds,
        "applicationsSeconds": applications_seconds,
        "applicationCount": application_count,
        "pageTitle": _bounded_text(page_title, "page title"),
        "markerObserved": _bounded_text(marker_observed, "page marker"),
        "presentationBundleLoaded": presentation_bundle_loaded,
        "consoleErrorCount": console_error_count}
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path = Path(browser["sampleFeed"])
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_size + len(encoded) > MAX_FEED_BYTES):
            raise PilotLoadError("Codex IAB sample feed is unsafe or full")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        lines = os.pread(descriptor, MAX_FEED_BYTES + 1, 0).decode(
            "utf-8").splitlines()
        if lines:
            try:
                previous = json.loads(lines[-1])
            except json.JSONDecodeError as error:
                raise PilotLoadError("Codex IAB sample feed is malformed") from error
            if (type(previous) is not dict
                    or type(previous.get("sequence")) is not int
                    or sequence <= previous["sequence"]):
                raise PilotLoadError("Codex IAB sequence must increase")
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise PilotLoadError("Codex IAB sample write failed")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"status": "recorded", "sessionId": browser["sessionId"],
            "sequence": sequence, "credentialsStored": False,
            "rawIdentityStored": False}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--observed-web-origin", required=True)
    parser.add_argument("--identity-subject-sha256", required=True)
    parser.add_argument("--navigation-seconds", required=True, type=float)
    parser.add_argument("--applications-seconds", required=True, type=float)
    parser.add_argument("--application-count", required=True, type=int)
    parser.add_argument("--page-title", required=True)
    parser.add_argument("--marker-observed", required=True)
    parser.add_argument("--presentation-bundle-loaded", required=True,
                        choices=("true", "false"))
    parser.add_argument("--console-error-count", required=True, type=int)
    args = parser.parse_args()
    result = append_sample(args.config, sequence=args.sequence,
        observed_web_origin=args.observed_web_origin,
        identity_subject_sha256=args.identity_subject_sha256,
        navigation_seconds=args.navigation_seconds,
        applications_seconds=args.applications_seconds,
        application_count=args.application_count, page_title=args.page_title,
        marker_observed=args.marker_observed,
        presentation_bundle_loaded=args.presentation_bundle_loaded == "true",
        console_error_count=args.console_error_count)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
