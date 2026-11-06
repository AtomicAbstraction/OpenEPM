#!/usr/bin/env python3
"""Legacy storage primitives for Mac-pilot activation.

The former digest-only mutation API is retired and fails closed. The supported
state service is ``macos_pilot_secure_activation.SecureActivationService``.
"""
from __future__ import annotations

import hashlib
import json
import os
import fcntl
from contextlib import contextmanager
from pathlib import Path
import stat
import tempfile
from typing import Optional


COMMANDS = ("prepare", "activate-read-only", "rollback", "commit")
LEGACY_MUTATION_RETIRED = True
NEXT = {
    None: {"prepare": "prepared"},
    "prepared": {"activate-read-only": "activating-read-only",
                 "rollback": "rolling-back"},
    "activating-read-only": {},
    "read-only": {"rollback": "rolling-back", "commit": "committing"},
    "rolling-back": {},
    "committing": {},
    "rolled-back": {},
    "committed": {},
    "recovery-required": {},
}
COMPLETION = {
    "activating-read-only": ("activate-read-only", "read-only"),
    "rolling-back": ("rollback", "rolled-back"),
    "committing": ("commit", "committed"),
}


class ActivationStateError(ValueError):
    pass


class ActivationStore:
    """Owner-only, append-only storage; journal replay remains authoritative."""

    def __init__(self, root: Path):
        if not root.is_absolute():
            raise ActivationStateError("activation state directory must be absolute")
        self.root = root
        self.journal = root / "journal"

    def initialize(self) -> None:
        if self.root.exists() and self.root.is_symlink():
            raise ActivationStateError("activation state directory cannot be a symlink")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.journal.mkdir(mode=0o700, exist_ok=True)
        self._secure(self.root, directory=True)
        self._secure(self.journal, directory=True)

    @staticmethod
    def _secure(path: Path, *, directory: bool = False) -> None:
        info = path.lstat()
        expected = 0o700 if directory else 0o600
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != expected \
                or (directory and not stat.S_ISDIR(info.st_mode)) \
                or (not directory and not stat.S_ISREG(info.st_mode)):
            raise ActivationStateError(f"unsafe activation path ownership/mode: {path}")

    def load(self) -> list[dict]:
        self.initialize()
        records = []
        paths = sorted(self.journal.iterdir())
        for ordinal, path in enumerate(paths, 1):
            if path.name != f"{ordinal:012d}.json" or path.is_symlink():
                raise ActivationStateError("activation journal has a gap or unexpected file")
            self._secure(path)
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise ActivationStateError("activation journal contains invalid JSON") from error
            records.append(value)
        return records

    def append(self, event: dict) -> None:
        raise ActivationStateError(
            "raw activation append is retired; use SecureActivationService")

    def _append_locked(self, event: dict) -> None:
        """Append while the caller holds ``_lock``; used by secure service."""
        records = self.load()
        ordinal = len(records) + 1
        body = {key: value for key, value in event.items() if key != "recordSha256"}
        previous = records[-1]["recordSha256"] if records else "0" * 64
        if event.get("ordinal") != ordinal \
                or event.get("format") != "openepm-macos-pilot-activation-event-v1" \
                or event.get("previousSha256") != previous \
                or event.get("recordSha256") != digest(body):
            raise ActivationStateError("event ordinal does not append to durable journal")
        target = self.journal / f"{ordinal:012d}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(target, flags, 0o600)
        try:
            payload = json.dumps(event, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            os.write(descriptor, payload); os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._secure(target)
        self._fsync(self.journal)
        self._atomic("activation-state.json", event)

    def publish_active_slot(self, plan: dict, event: dict) -> dict:
        raise ActivationStateError(
            "legacy pointer publication is retired; use SecureActivationService")
        plan_sha256 = validate_plan(plan)
        if event.get("state") != "committed" \
                or event.get("planSha256") != plan_sha256 \
                or event.get("pointOfNoReturnCrossed") is not True:
            raise ActivationStateError("only a certified commit can publish active slot")
        pointer = {
            "format": "openepm-macos-pilot-active-slot-v1",
            "generation": event["ordinal"], "slot": "green",
            "project": plan["green"]["project"],
            "applicationImage": plan["green"]["applicationImage"],
            "databaseImage": plan["green"]["databaseImage"],
            "sandboxNetwork": plan["sandboxNetwork"],
            "planSha256": plan_sha256,
            "activationEventSha256": event["recordSha256"],
            "committedEventSha256": event["recordSha256"],
        }
        pointer["pointerSha256"] = digest(pointer)
        with self._lock():
            records = self.load()
            last = verify_journal(records, plan_sha256)
            if last != event:
                raise ActivationStateError("commit event is not the journal's exact last event")
            self._require_stored_plan(plan)
            active = self.root / "active-slot.json"
            if active.exists():
                self._secure(active)
                previous = json.loads(active.read_text(encoding="utf-8"))
                self._atomic("active-slot.previous.json", previous)
            self._atomic("active-slot.json", pointer)
        return pointer

    def publish_initial_blue_slot(self, plan: dict, event: dict) -> dict:
        """Create the initial source pointer; never replace an existing pointer."""
        raise ActivationStateError(
            "legacy pointer publication is retired; use SecureActivationService")
        plan_sha256 = validate_plan(plan)
        if event.get("state") != "prepared" \
                or event.get("planSha256") != plan_sha256 \
                or event.get("writesAdmitted") is not False:
            raise ActivationStateError("only a certified prepare can publish initial blue slot")
        pointer = {
            "format": "openepm-macos-pilot-active-slot-v1",
            "generation": event["ordinal"], "slot": "blue",
            "project": plan["blue"]["project"],
            "applicationImage": plan["blue"]["applicationImage"],
            "databaseImage": plan["blue"]["databaseImage"],
            "sandboxNetwork": plan["sandboxNetwork"],
            "planSha256": plan_sha256,
            "activationEventSha256": event["recordSha256"],
        }
        pointer["pointerSha256"] = digest(pointer)
        with self._lock():
            records = self.load()
            last = verify_journal(records, plan_sha256)
            if last != event:
                raise ActivationStateError("prepare event is not the journal's exact last event")
            if (self.root / "active-slot.json").exists():
                raise ActivationStateError("initial active-slot pointer already exists")
            plan_path = self.root / "activation-plan.json"
            if plan_path.exists():
                self._require_stored_plan(plan)
            else:
                self._atomic("activation-plan.json", plan)
            self._atomic("active-slot.json", pointer)
        return pointer

    def _require_stored_plan(self, plan: dict) -> None:
        path = self.root / "activation-plan.json"
        if not path.exists():
            raise ActivationStateError("protected activation plan is missing")
        self._secure(path)
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ActivationStateError("protected activation plan is invalid") from error
        if stored != plan:
            raise ActivationStateError("protected activation plan differs")

    @contextmanager
    def _lock(self):
        self.initialize()
        path = self.root / "activation.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            self._secure(path)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _atomic(self, name: str, value: dict) -> None:
        self.initialize()
        descriptor, temporary_name = tempfile.mkstemp(prefix="." + name + ".",
                                                       dir=self.root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, indent=2, sort_keys=True)
                handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
            temporary.chmod(0o600)
            os.replace(temporary, self.root / name)
            self._fsync(self.root)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _fsync(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_plan(plan: dict) -> str:
    if not isinstance(plan, dict) \
            or plan.get("format") != "openepm-macos-pilot-activation-plan-v1":
        raise ActivationStateError("sealed activation plan is required")
    claimed = plan.get("planSha256")
    body = {key: value for key, value in plan.items() if key != "planSha256"}
    if not isinstance(claimed, str) or claimed != digest(body):
        raise ActivationStateError("activation plan digest mismatch")
    constraints = plan.get("constraints")
    required = {
        "publicIngressStoppedUntilCommit": True,
        "writesDeniedUntilCommit": True,
        "bluePreservedUntilCommit": True,
        "rollbackPermittedAfterCommit": False,
        "commitIsPointOfNoReturn": True,
        "dockerExecutionIncluded": False,
        "sharedPilotMutationIncluded": False,
    }
    if not isinstance(constraints, dict) \
            or any(constraints.get(key) is not value for key, value in required.items()) \
            or plan.get("commands") != list(COMMANDS):
        raise ActivationStateError("activation safety constraints are incomplete")
    blue, green = plan.get("blue"), plan.get("green")
    if not isinstance(blue, dict) or not isinstance(green, dict) \
            or blue.get("slot") != "blue" or green.get("slot") != "green" \
            or blue.get("project") == green.get("project") \
            or blue.get("databaseVolume") == green.get("databaseVolume"):
        raise ActivationStateError("activation slot identities are invalid")
    return claimed


def verify_journal(records: list[dict], plan_sha256: str) -> Optional[dict]:
    previous = "0" * 64
    state = None
    seen: dict[str, str] = {}
    for ordinal, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ActivationStateError("activation journal record is not an object")
        claimed = record.get("recordSha256")
        body = {key: value for key, value in record.items() if key != "recordSha256"}
        if record.get("ordinal") != ordinal \
                or record.get("previousSha256") != previous \
                or record.get("planSha256") != plan_sha256 \
                or not isinstance(claimed, str) or claimed != digest(body):
            raise ActivationStateError("activation journal chain is invalid")
        key, request = record.get("requestKey"), record.get("requestSha256")
        if not isinstance(key, str) or not key or not isinstance(request, str):
            raise ActivationStateError("activation request identity is invalid")
        if key in seen and seen[key] != request:
            raise ActivationStateError("activation request key has conflicting content")
        seen[key] = request
        state, previous = record, claimed
    return state


def transition(plan: dict, records: list[dict], *, command: str,
               request_key: str, evidence_sha256: str) -> tuple[list[dict], dict, bool]:
    raise ActivationStateError(
        "legacy digest-only activation is retired; use SecureActivationService")
    plan_sha256 = validate_plan(plan)
    if command not in COMMANDS or not isinstance(request_key, str) or not request_key \
            or not isinstance(evidence_sha256, str) or len(evidence_sha256) != 64 \
            or any(character not in "0123456789abcdef" for character in evidence_sha256):
        raise ActivationStateError("command, request key, or evidence digest is invalid")
    last = verify_journal(records, plan_sha256)
    request = {"command": command, "evidenceSha256": evidence_sha256,
               "planSha256": plan_sha256}
    request_sha256 = digest(request)
    for record in records:
        if record["requestKey"] == request_key:
            if record["requestSha256"] != request_sha256:
                raise ActivationStateError("request key replay has different content")
            return records, record, True
    prior = last.get("state") if last else None
    target = NEXT.get(prior, {}).get(command)
    if target is None:
        if prior == "committed":
            raise ActivationStateError("commit is the point of no return; rollback is forbidden")
        raise ActivationStateError(f"{command} is invalid from state {prior!r}")
    body = {
        "format": "openepm-macos-pilot-activation-event-v1",
        "ordinal": len(records) + 1,
        "previousSha256": last["recordSha256"] if last else "0" * 64,
        "planSha256": plan_sha256,
        "requestKey": request_key,
        "requestSha256": request_sha256,
        "command": command,
        "priorState": prior,
        "state": target,
        "evidenceSha256": evidence_sha256,
        "activeSlot": "green" if target == "committed" else "blue",
        "eventKind": "intent" if target in COMPLETION else "completion",
        "writesAdmitted": False,
        "publicIngressPermitted": False,
        "rollbackPermitted": target in ("prepared", "read-only"),
        "pointOfNoReturnCrossed": target == "committed",
    }
    event = {**body, "recordSha256": digest(body)}
    return [*records, event], event, False


def complete(plan: dict, records: list[dict], *, command: str,
             request_key: str, receipt_sha256: str) -> tuple[list[dict], dict, bool]:
    """Certify an intent only after a separate executor receipt was validated."""
    raise ActivationStateError(
        "legacy digest-only completion is retired; use SecureActivationService")
    plan_sha256 = validate_plan(plan)
    last = verify_journal(records, plan_sha256)
    prior = last.get("state") if last else None
    expected = COMPLETION.get(prior)
    if expected is None or expected[0] != command:
        raise ActivationStateError(f"cannot complete {command} from state {prior!r}")
    if not isinstance(receipt_sha256, str) or len(receipt_sha256) != 64 \
            or any(character not in "0123456789abcdef" for character in receipt_sha256):
        raise ActivationStateError("executor receipt digest is invalid")
    request = {"command": command, "intentSha256": last["recordSha256"],
               "planSha256": plan_sha256, "receiptSha256": receipt_sha256}
    request_sha256 = digest(request)
    for record in records:
        if record["requestKey"] == request_key:
            if record["requestSha256"] != request_sha256:
                raise ActivationStateError("request key replay has different content")
            return records, record, True
    target = expected[1]
    body = {
        "format": "openepm-macos-pilot-activation-event-v1",
        "ordinal": len(records) + 1,
        "previousSha256": last["recordSha256"],
        "planSha256": plan_sha256,
        "requestKey": request_key,
        "requestSha256": request_sha256,
        "command": command,
        "priorState": prior,
        "state": target,
        "evidenceSha256": receipt_sha256,
        "eventKind": "completion",
        "intentSha256": last["recordSha256"],
        "activeSlot": "green" if target == "committed" else "blue",
        "writesAdmitted": target == "committed",
        "publicIngressPermitted": target == "committed",
        "rollbackPermitted": target == "read-only",
        "pointOfNoReturnCrossed": target == "committed",
    }
    event = {**body, "recordSha256": digest(body)}
    return [*records, event], event, False


def recovery_required(plan: dict, records: list[dict], *, request_key: str,
                      observation_sha256: str) -> tuple[list[dict], dict, bool]:
    """Fail closed after an intent whose external outcome is ambiguous."""
    raise ActivationStateError(
        "legacy recovery API is retired; use SecureActivationService")
    plan_sha256 = validate_plan(plan)
    last = verify_journal(records, plan_sha256)
    prior = last.get("state") if last else None
    if prior not in COMPLETION:
        raise ActivationStateError("recovery-required needs an incomplete mutation intent")
    return _terminal_event(plan_sha256, records, last, request_key=request_key,
                           request_sha256=digest({"intentSha256": last["recordSha256"],
                                                  "observationSha256": observation_sha256}),
                           evidence_sha256=observation_sha256,
                           state="recovery-required")


def _terminal_event(plan_sha256: str, records: list[dict], last: dict, *,
                    request_key: str, request_sha256: str,
                    evidence_sha256: str, state: str) -> tuple[list[dict], dict, bool]:
    if not isinstance(request_key, str) or not request_key \
            or not isinstance(evidence_sha256, str) or len(evidence_sha256) != 64 \
            or any(character not in "0123456789abcdef" for character in evidence_sha256):
        raise ActivationStateError("recovery request or observation digest is invalid")
    for record in records:
        if record["requestKey"] == request_key:
            if record["requestSha256"] != request_sha256:
                raise ActivationStateError("request key replay has different content")
            return records, record, True
    body = {
        "format": "openepm-macos-pilot-activation-event-v1",
        "ordinal": len(records) + 1, "previousSha256": last["recordSha256"],
        "planSha256": plan_sha256, "requestKey": request_key,
        "requestSha256": request_sha256, "command": "recovery-required",
        "priorState": last["state"], "state": state,
        "evidenceSha256": evidence_sha256, "eventKind": "recovery",
        "activeSlot": "unknown", "writesAdmitted": False,
        "publicIngressPermitted": False, "rollbackPermitted": False,
        "pointOfNoReturnCrossed": last["state"] == "committing",
    }
    event = {**body, "recordSha256": digest(body)}
    return [*records, event], event, False
