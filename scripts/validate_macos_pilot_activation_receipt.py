#!/usr/bin/env python3
"""Authenticate exact Mac-pilot executor receipts and commit authorization.

This module performs no runtime action. Verification keys are supplied by the
trusted fixed service's protected registry, never by receipt or user payload.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SHA = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
RECEIPT_KEYS = {
    "format", "activationId", "command", "intentEventSha256",
    "dryPlanSha256", "executionContractSha256", "executorKeyId",
    "runtimeBindings", "observations", "outcome", "receiptSha256",
    "signature"}
AUTHORIZATION_KEYS = {
    "format", "keyId", "decision", "activationId", "dryPlanSha256",
    "executionContractSha256", "readOnlyCompletionEventSha256",
    "commitIntentEventSha256", "journalGeneration", "candidateBindingSha256",
    "issuedAtUtc", "notBeforeUtc", "expiresAtUtc", "nonce",
    "authorizationSha256", "signature"}
OBSERVATIONS = {
    "prepare": ("quiescence", "drainedWork", "finalBackup", "sourceEquality",
                "candidatePrepared", "restoreMigration", "dataIdentity",
                "sandboxNetwork"),
    "activate-read-only": ("tunnelStopped", "candidateServices",
                "launcherNetwork", "health", "unsignedDenial",
                "authenticatedRead", "writeDenial", "sourcePreserved"),
    "rollback": ("candidateStopped", "sourceNetworkRestored", "sourceServices",
                "sourceData", "authenticatedRead", "unsignedDenial",
                "writesControlled", "candidateRetained"),
    "commit": ("candidateRevalidated", "greenPointerPrepared", "ownerAuthorized",
                "writeGateStillClosed", "tunnelStillStopped"),
    "finalize": ("committedDecisionCurrent", "greenPointerSelected",
                 "writeGateOpened", "tunnelResumed", "publicForwardVerified"),
    "certify-rollback": ("signedBlueGateReadBack",),
    "publish-active": ("signedGreenGateReadBack","producerFenceOpened"),
}
V3_FINALIZE_OBSERVATIONS=("committedDecisionCurrent","greenPointerSelected",
    "greenDatabaseAclReady","candidateServices","health","producerFenceClosed",
    "tunnelStillStopped")

def observations_for(contract:dict,command:str)->tuple[str,...]:
    if command=="finalize" and contract.get("format")== \
            "openepm-macos-pilot-activation-execution-contract-v3":
        return V3_FINALIZE_OBSERVATIONS
    if command=="certify-rollback" and contract.get("format")== \
            "openepm-macos-pilot-activation-execution-contract-v3":
        return ("signedBlueGateReadBack","producerFenceOpened")
    return OBSERVATIONS[command]
INTENT_STATES = {
    "prepare": "preparing", "activate-read-only": "activating-read-only",
    "rollback": "rolling-back", "commit": "committing",
    "finalize": "finalizing", "certify-rollback": "publishing-rollback",
    "publish-active":"publishing-active"}


class ReceiptValidationError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise ReceiptValidationError(f"{label} must be an SHA-256 digest")
    return value


def _utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise ReceiptValidationError(f"{label} must be an exact UTC second")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError as error:
        raise ReceiptValidationError(f"{label} is invalid") from error


class TrustRegistry:
    """Protected fixed-service trust; payloads cannot add keys or contracts."""

    def __init__(self, keys: dict[str, dict], approved_contracts: set[str]):
        if not isinstance(keys, dict) or not keys \
                or not isinstance(approved_contracts, set) or not approved_contracts \
                or any(not isinstance(item, str) or SHA.fullmatch(item) is None
                       for item in approved_contracts):
            raise ReceiptValidationError("trusted verifier registry is empty")
        self._keys: dict[str, dict] = {}
        self._approved_contracts = frozenset(approved_contracts)
        material_roles: dict[bytes, str] = {}
        for key_id, entry in keys.items():
            if not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None \
                    or not isinstance(entry, dict) \
                    or set(entry) != {"publicKey", "role", "version",
                                      "notBeforeUtc", "expiresAtUtc", "revoked"} \
                    or not isinstance(entry.get("publicKey"), Ed25519PublicKey) \
                    or entry.get("role") not in ("executor", "owner", "authority",
                                                  "evidence") \
                    or not isinstance(entry.get("version"), int) \
                    or isinstance(entry.get("version"), bool) or entry["version"] < 1 \
                    or not isinstance(entry.get("revoked"), bool) \
                    or _utc(entry.get("notBeforeUtc"), "key not-before") \
                        >= _utc(entry.get("expiresAtUtc"), "key expiry"):
                raise ReceiptValidationError("trusted verifier registry is invalid")
            material = entry["publicKey"].public_bytes(Encoding.Raw, PublicFormat.Raw)
            prior_role = material_roles.setdefault(material, entry["role"])
            if prior_role != entry["role"]:
                raise ReceiptValidationError(
                    "executor and owner verifier key material must be distinct")
            self._keys[key_id] = dict(entry)

    def require_contract(self, contract_sha256: str) -> None:
        if contract_sha256 not in self._approved_contracts:
            raise ReceiptValidationError("execution contract is not trusted")

    def verifier_public_key(self, key_id: str, *, role: str,
                            version: int) -> Ed25519PublicKey:
        entry=self._keys.get(key_id)
        if entry is None or entry["role"]!=role or entry["version"]!=version \
                or entry["revoked"] is True:
            raise ReceiptValidationError("verifier is not trusted")
        return entry["publicKey"]

    def verifier_public_key_at(self,key_id:str,*,role:str,version:int,
                               now_utc:str)->Ed25519PublicKey:
        entry=self._keys.get(key_id);now=_utc(now_utc,"verification time")
        if entry is None or entry["role"]!=role or entry["version"]!=version \
                or entry["revoked"] is True \
                or now<_utc(entry["notBeforeUtc"],"key not-before") \
                or now>=_utc(entry["expiresAtUtc"],"key expiry"):
            raise ReceiptValidationError("verifier is not currently trusted")
        return entry["publicKey"]

    def verify(self, key_id: str, payload: bytes, signature: object,
               label: str, *, role: str, version: int, now_utc: str) -> None:
        entry = self._keys.get(key_id)
        now = _utc(now_utc, "verification time")
        if entry is None or entry["role"] != role or entry["version"] != version \
                or entry["revoked"] is True \
                or now < _utc(entry["notBeforeUtc"], "key not-before") \
                or now >= _utc(entry["expiresAtUtc"], "key expiry"):
            raise ReceiptValidationError(f"{label} verifier is not trusted")
        if not isinstance(signature, dict) \
                or set(signature) != {"algorithm", "keyId", "valueBase64"} \
                or signature.get("algorithm") != "Ed25519" \
                or signature.get("keyId") != key_id \
                or not isinstance(signature.get("valueBase64"), str) \
                or len(signature["valueBase64"]) != 88:
            raise ReceiptValidationError(f"{label} signature envelope is invalid")
        try:
            raw = base64.b64decode(signature["valueBase64"], validate=True)
            if len(raw) != 64:
                raise ValueError("Ed25519 signature must be 64 bytes")
            entry["publicKey"].verify(raw, payload)
        except (InvalidSignature, ValueError, TypeError) as error:
            raise ReceiptValidationError(f"{label} signature is invalid") from error

def trust_registry_from_runtime_value(value:dict)->TrustRegistry:
    """Parse the one canonical manifest-protected runtime trust schema."""
    if not isinstance(value,dict) or set(value)!={"format","keys","approvedContracts"} \
            or value.get("format")!="openepm-macos-pilot-runtime-trust-v1" \
            or not isinstance(value.get("keys"),list) \
            or not isinstance(value.get("approvedContracts"),list):
        raise ReceiptValidationError("runtime trust registry differs")
    keys={}
    try:
        for item in value["keys"]:
            if not isinstance(item,dict) or set(item)!={"keyId","publicKeyBase64",
                    "role","version","notBeforeUtc","expiresAtUtc","revoked"} \
                    or item["keyId"] in keys:
                raise ValueError("runtime trust key shape")
            raw=base64.b64decode(item["publicKeyBase64"],validate=True)
            keys[item["keyId"]]={**{key:field for key,field in item.items()
                if key not in ("keyId","publicKeyBase64")},
                "publicKey":Ed25519PublicKey.from_public_bytes(raw)}
        return TrustRegistry(keys,set(value["approvedContracts"]))
    except Exception as error:
        if isinstance(error,ReceiptValidationError):raise
        raise ReceiptValidationError("runtime trust registry is invalid") from error


def _contract(contract: dict, registry: TrustRegistry) -> tuple[str, str, str]:
    required = {"format", "activationId", "dryPlanSha256", "preparedAtUtc",
        "source", "candidate", "finalBackup", "infrastructure",
        "expectedAssertions", "executorVerifier", "ownerAuthorizationVerifier",
        "evidenceVerifier", "constraints", "executionContractSha256"}
    if isinstance(contract,dict) and contract.get("format")== \
            "openepm-macos-pilot-activation-execution-contract-v3":
        required.add("authorityVerifier")
    if not isinstance(contract, dict) or set(contract) != required \
            or contract.get("format") not in (
                "openepm-macos-pilot-activation-execution-contract-v2",
                "openepm-macos-pilot-activation-execution-contract-v3"):
        raise ReceiptValidationError("sealed execution contract is required")
    contract_sha = _sha(contract.get("executionContractSha256"), "contract")
    body = {key: value for key, value in contract.items()
            if key != "executionContractSha256"}
    if digest(body) != contract_sha:
        raise ReceiptValidationError("execution contract digest differs")
    registry.require_contract(contract_sha)
    activation_id = contract.get("activationId")
    plan_sha = _sha(contract.get("dryPlanSha256"), "dry plan")
    infrastructure = contract.get("infrastructure")
    if not isinstance(activation_id, str) or not activation_id \
            or any(not isinstance(contract.get(field), dict)
                   or not contract[field] for field in
                   ("source", "candidate", "finalBackup", "infrastructure",
                    "expectedAssertions", "executorVerifier",
                    "ownerAuthorizationVerifier", "evidenceVerifier")+
                    (("authorityVerifier",) if contract.get("format").endswith("-v3") else ())) \
            or SHA.fullmatch(str(infrastructure.get(
                "routeAuthoritySha256"))) is None:
        raise ReceiptValidationError("activation identity is invalid")
    if contract.get("format").endswith("-v3"):
        authority=_verifier(contract,"authorityVerifier")
        executor=_verifier(contract,"executorVerifier")
        owner=_verifier(contract,"ownerAuthorizationVerifier")
        evidence=_verifier(contract,"evidenceVerifier")
        if len({authority,executor,owner,evidence})!=4:
            raise ReceiptValidationError("activation verifier identities must be distinct")
        for field,role in (("authorityVerifier","authority"),
                           ("executorVerifier","executor"),
                           ("ownerAuthorizationVerifier","owner"),
                           ("evidenceVerifier","evidence")):
            key_id,version=_verifier(contract,field)
            key=registry.verifier_public_key(key_id,role=role,version=version)
            if field=="evidenceVerifier" and contract[field].get(
                    "publicKeySha256") is not None \
                    and contract[field]["publicKeySha256"]!=hashlib.sha256(
                        key.public_bytes(Encoding.Raw,PublicFormat.Raw)).hexdigest():
                raise ReceiptValidationError("evidence verifier material differs")
    return activation_id, plan_sha, contract_sha


def _verifier(contract: dict, field: str) -> tuple[str, int]:
    value = contract.get(field)
    expected={"algorithm", "keyId", "version"} \
        | ({"publicKeySha256"} if field=="evidenceVerifier" and isinstance(
            value,dict) and "publicKeySha256" in value else set())
    if not isinstance(value, dict) or set(value) != expected \
            or value.get("algorithm") != "Ed25519" \
            or not isinstance(value.get("keyId"), str) \
            or KEY_ID.fullmatch(value["keyId"]) is None \
            or not isinstance(value.get("version"), int) \
            or isinstance(value.get("version"), bool) or value["version"] < 1:
        raise ReceiptValidationError(f"{field} identity is invalid")
    return value["keyId"], value["version"]


def _event(value: object, *, activation_id: str, plan_sha: str,
           contract_sha: str, command: str, state: str,
           allow_contract_absent: bool = False) -> dict:
    if not isinstance(value, dict):
        raise ReceiptValidationError("journal event is invalid")
    claimed = _sha(value.get("recordSha256"), "journal event")
    body = {key: item for key, item in value.items() if key != "recordSha256"}
    contract_value = value.get("executionContractSha256")
    expected_kind = "intent" if state in INTENT_STATES.values() else "completion"
    if digest(body) != claimed \
            or value.get("format") != "openepm-macos-pilot-activation-event-v1" \
            or value.get("activationId") != activation_id \
            or value.get("planSha256") != plan_sha \
            or value.get("command") != command or value.get("state") != state \
            or value.get("eventKind") != expected_kind \
            or not isinstance(value.get("ordinal"), int) \
            or isinstance(value.get("ordinal"), bool) or value["ordinal"] < 1 \
            or (contract_value != contract_sha
                and not (allow_contract_absent and contract_value is None)):
        raise ReceiptValidationError("journal event binding is invalid")
    return value


def _journal(records: object, *, activation_id: str, plan_sha: str,
             contract_sha: str) -> list[dict]:
    if not isinstance(records, list) or not records:
        raise ReceiptValidationError("authoritative journal is empty")
    previous = "0" * 64
    result = []
    for ordinal, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ReceiptValidationError("authoritative journal record is invalid")
        claimed = _sha(record.get("recordSha256"), "journal record")
        body = {key: item for key, item in record.items() if key != "recordSha256"}
        contract_value = record.get("executionContractSha256")
        pre_contract_intent = ordinal == 1 \
            and record.get("state") == "preparing" \
            and record.get("command") == "prepare" \
            and contract_value is None
        if record.get("ordinal") != ordinal \
                or record.get("previousSha256") != previous \
                or record.get("format") \
                    != "openepm-macos-pilot-activation-event-v1" \
                or record.get("activationId") != activation_id \
                or record.get("planSha256") != plan_sha \
                or (contract_value != contract_sha and not pre_contract_intent) \
                or digest(body) != claimed:
            raise ReceiptValidationError("authoritative journal chain is invalid")
        result.append(record); previous = claimed
    return result


def _runtime_bindings(contract: dict, command: str) -> dict:
    fields = {
        "prepare": ("source", "candidate", "finalBackup", "infrastructure"),
        "activate-read-only": ("candidate", "infrastructure", "expectedAssertions"),
        "rollback": ("source", "candidate", "infrastructure", "expectedAssertions"),
        "commit": ("candidate", "infrastructure", "expectedAssertions"),
        "finalize": ("candidate", "infrastructure", "expectedAssertions"),
        "certify-rollback": ("source", "infrastructure", "expectedAssertions"),
        "publish-active": ("candidate", "infrastructure", "expectedAssertions"),
    }[command]
    return {field: contract[field] for field in fields}


def _observations(value: object, command: str,contract:dict) -> dict:
    expected = set(observations_for(contract,command))
    if not isinstance(value, dict) or set(value) != expected:
        raise ReceiptValidationError("receipt observations are incomplete or unexpected")
    result = {}
    for name, check in value.items():
        if not isinstance(check, dict) \
                or set(check) != {"passed", "evidenceSha256"} \
                or check.get("passed") is not True:
            raise ReceiptValidationError(f"receipt observation did not pass: {name}")
        result[name] = {"passed": True,
                        "evidenceSha256": _sha(check.get("evidenceSha256"), name)}
    return result


def validate_owner_authorization(contract: dict, intent: dict,
        read_only_completion: dict, authorization: dict,
        registry: TrustRegistry, *, now_utc: str) -> str:
    activation_id, plan_sha, contract_sha = _contract(contract, registry)
    intent = _event(intent, activation_id=activation_id, plan_sha=plan_sha,
        contract_sha=contract_sha, command="commit", state="committing")
    read_only_completion = _event(read_only_completion,
        activation_id=activation_id, plan_sha=plan_sha,
        contract_sha=contract_sha, command="activate-read-only", state="read-only")
    if not isinstance(authorization, dict) or set(authorization) != AUTHORIZATION_KEYS:
        raise ReceiptValidationError("owner authorization shape is invalid")
    key_id, key_version = _verifier(contract, "ownerAuthorizationVerifier")
    if authorization.get("format") != "openepm-macos-pilot-owner-authorization-v1" \
            or authorization.get("keyId") != key_id \
            or authorization.get("decision") != "authorize-commit" \
            or authorization.get("activationId") != activation_id \
            or authorization.get("dryPlanSha256") != plan_sha \
            or authorization.get("executionContractSha256") != contract_sha \
            or authorization.get("readOnlyCompletionEventSha256") \
                != read_only_completion.get("recordSha256") \
            or authorization.get("commitIntentEventSha256") \
                != intent.get("recordSha256") \
            or authorization.get("candidateBindingSha256") \
                != digest(contract.get("candidate")) \
            or authorization.get("journalGeneration") != intent.get("ordinal") \
            or not isinstance(authorization.get("journalGeneration"), int) \
            or isinstance(authorization.get("journalGeneration"), bool) \
            or not isinstance(authorization.get("nonce"), str) \
            or not authorization["nonce"]:
        raise ReceiptValidationError("owner authorization binding is invalid")
    issued = _utc(authorization.get("issuedAtUtc"), "authorization issuance")
    not_before = _utc(authorization.get("notBeforeUtc"), "authorization not-before")
    expires = _utc(authorization.get("expiresAtUtc"), "authorization expiry")
    now = _utc(now_utc, "current time")
    if not (issued <= not_before <= now < expires) \
            or (expires - issued).total_seconds() > 900 \
            or read_only_completion["ordinal"] >= intent["ordinal"] \
            or not (16 <= len(authorization["nonce"]) <= 128):
        raise ReceiptValidationError("owner authorization has expired")
    claimed = _sha(authorization.get("authorizationSha256"), "authorization")
    body = {key: value for key, value in authorization.items()
            if key not in ("authorizationSha256", "signature")}
    if digest(body) != claimed:
        raise ReceiptValidationError("owner authorization digest differs")
    registry.verify(key_id, canonical({**body, "authorizationSha256": claimed}),
                    authorization.get("signature"), "owner authorization",
                    role="owner", version=key_version, now_utc=now_utc)
    return claimed


def validate_accepted_owner_authorization(contract: dict, intent: dict,
        read_only_completion: dict, authorization: dict, accepted: dict,
        registry: TrustRegistry) -> tuple[str, str]:
    """Validate protected pre-effect acceptance at its original decision time."""
    if not isinstance(accepted,dict) \
            or set(accepted)!={"format","intentEventSha256","acceptedAtUtc",
                              "ownerKeyId","ownerKeyVersion",
                              "ownerPublicKeyBase64","ownerPublicKeySha256",
                              "authorization","recordSha256"} \
            or accepted.get("format") \
                != "openepm-macos-pilot-accepted-owner-authorization-v1" \
            or accepted.get("intentEventSha256")!=intent.get("recordSha256") \
            or accepted.get("authorization")!=authorization:
        raise ReceiptValidationError("accepted owner authorization binding is invalid")
    claimed=_sha(accepted.get("recordSha256"),"accepted owner authorization")
    body={key:value for key,value in accepted.items() if key!="recordSha256"}
    if digest(body)!=claimed:
        raise ReceiptValidationError("accepted owner authorization digest differs")
    key_id,key_version=_verifier(contract,"ownerAuthorizationVerifier")
    if accepted.get("ownerKeyId")!=key_id \
            or accepted.get("ownerKeyVersion")!=key_version \
            or not isinstance(accepted.get("ownerPublicKeyBase64"),str) \
            or not isinstance(accepted.get("ownerPublicKeySha256"),str):
        raise ReceiptValidationError("accepted owner verifier binding is invalid")
    try:
        raw=base64.b64decode(accepted["ownerPublicKeyBase64"],validate=True)
        if len(raw)!=32 or hashlib.sha256(raw).hexdigest() \
                != accepted["ownerPublicKeySha256"]:
            raise ValueError("owner key digest differs")
        public_key=Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError,TypeError) as error:
        raise ReceiptValidationError("accepted owner public key is invalid") from error
    historical_keys={name:dict(item) for name,item in registry._keys.items()
        if item.get("role")!="owner"}
    historical_keys[key_id]={"publicKey":public_key,"role":"owner",
        "version":key_version,"notBeforeUtc":"1970-01-01T00:00:00Z",
        "expiresAtUtc":"9999-12-31T23:59:59Z","revoked":False}
    historical=TrustRegistry(historical_keys,
        {contract["executionContractSha256"]})
    authorization_sha=validate_owner_authorization(contract,intent,
        read_only_completion,authorization,historical,
        now_utc=accepted.get("acceptedAtUtc"))
    return authorization_sha,claimed


def validate_executor_receipt(contract: dict, intent: dict, receipt: dict,
        registry: TrustRegistry, *, journal_records: list[dict],
        owner_authorization: dict | None = None,
        read_only_completion: dict | None = None,
        recovery_event: dict | None = None,
        accepted_owner_authorization: dict | None = None,
        now_utc: str = "1970-01-01T00:00:00Z") -> str:
    activation_id, plan_sha, contract_sha = _contract(contract, registry)
    journal = _journal(journal_records, activation_id=activation_id,
                       plan_sha=plan_sha, contract_sha=contract_sha)
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS:
        raise ReceiptValidationError("executor receipt shape is invalid")
    command = receipt.get("command")
    if command not in OBSERVATIONS:
        raise ReceiptValidationError("executor receipt command is invalid")
    intent = _event(intent, activation_id=activation_id, plan_sha=plan_sha,
        contract_sha=contract_sha, command=command, state=INTENT_STATES[command],
        allow_contract_absent=command == "prepare")
    normal_head = recovery_event is None and journal[-1] == intent
    recovery_head = recovery_event is not None \
        and receipt.get("command") == "finalize" \
        and journal[-1] == recovery_event \
        and recovery_event.get("format") \
            == "openepm-macos-pilot-activation-event-v1" \
        and recovery_event.get("state") == "recovery-required" \
        and recovery_event.get("eventKind") == "recovery" \
        and recovery_event.get("command") == "recovery-required" \
        and recovery_event.get("intentSha256") == intent.get("recordSha256") \
        and recovery_event.get("pointOfNoReturnCrossed") is True \
        and recovery_event.get("outcomeAmbiguous") is True \
        and recovery_event.get("rollbackPermitted") is False \
        and any(record == intent for record in journal[:-1])
    if not (normal_head or recovery_head) \
            or receipt.get("format") != "openepm-macos-pilot-executor-receipt-v1" \
            or receipt.get("activationId") != activation_id \
            or receipt.get("intentEventSha256") != intent.get("recordSha256") \
            or receipt.get("dryPlanSha256") != plan_sha \
            or receipt.get("executionContractSha256") != contract_sha \
            or receipt.get("outcome") != "passed" \
            or receipt.get("runtimeBindings") != _runtime_bindings(contract, command):
        raise ReceiptValidationError("executor receipt binding is invalid")
    key_id, key_version = _verifier(contract, "executorVerifier")
    if receipt.get("executorKeyId") != key_id:
        raise ReceiptValidationError("executor receipt key identity differs")
    observations = _observations(receipt.get("observations"), command,contract)
    if command == "commit":
        if owner_authorization is None or read_only_completion is None:
            raise ReceiptValidationError("commit requires separate owner authorization")
        if not any(record == read_only_completion for record in journal[:-1]):
            raise ReceiptValidationError(
                "read-only completion is not in authoritative journal")
        if accepted_owner_authorization is None:
            authorization_sha = validate_owner_authorization(
                contract, intent, read_only_completion, owner_authorization,
                registry, now_utc=now_utc)
        else:
            authorization_sha,_=validate_accepted_owner_authorization(
                contract,intent,read_only_completion,owner_authorization,
                accepted_owner_authorization,registry)
        if observations["ownerAuthorized"]["evidenceSha256"] != authorization_sha:
            raise ReceiptValidationError("commit receipt does not bind owner authorization")
    elif owner_authorization is not None or read_only_completion is not None \
            or accepted_owner_authorization is not None:
        raise ReceiptValidationError("owner authorization is valid only for commit")
    claimed = _sha(receipt.get("receiptSha256"), "executor receipt")
    body = {key: value for key, value in receipt.items()
            if key not in ("receiptSha256", "signature")}
    if digest(body) != claimed:
        raise ReceiptValidationError("executor receipt digest differs")
    registry.verify(key_id, canonical({**body, "receiptSha256": claimed}),
                    receipt.get("signature"), "executor receipt",
                    role="executor", version=key_version, now_utc=now_utc)
    return claimed
