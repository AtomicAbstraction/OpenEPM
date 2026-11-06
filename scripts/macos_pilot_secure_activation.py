#!/usr/bin/env python3
"""Authenticated, replay-safe Mac-pilot activation state service.

This is a pure state boundary. It performs no Docker, launchd, Cloudflare or
EPM operation. External effects are admitted only after a durable intent and
certified only by the exact receipt validator.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
from typing import Optional
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

if __package__:
    from .validate_macos_pilot_activation_receipt import (
        TrustRegistry, ReceiptValidationError, validate_executor_receipt,
        validate_owner_authorization)
    from .macos_pilot_activation import ActivationStore, ActivationStateError
else:
    from validate_macos_pilot_activation_receipt import (
        TrustRegistry, ReceiptValidationError, validate_executor_receipt,
        validate_owner_authorization)
    from macos_pilot_activation import ActivationStore, ActivationStateError


SHA = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMAND_STATE = {
    "prepare": (None, "preparing", "prepared"),
    "activate-read-only": ("prepared", "activating-read-only", "read-only"),
    "rollback-prepared": ("prepared", "rolling-back", "rolled-back"),
    "rollback-read-only": ("read-only", "rolling-back", "rolled-back"),
    "commit": ("read-only", "committing", "committed"),
    "finalize": ("committed", "finalizing", "active"),
    "finalize-v3": ("committed", "finalizing", "finalized"),
    "publish-active": ("finalized", "publishing-active", "active"),
    "certify-rollback": ("rolled-back", "publishing-rollback", "rolled-back"),
}
RECEIPT_COMMAND = {
    "prepare": "prepare", "activate-read-only": "activate-read-only",
    "rollback-prepared": "rollback", "rollback-read-only": "rollback",
    "commit": "commit", "finalize": "finalize",
    "finalize-v3":"finalize","publish-active":"publish-active",
    "certify-rollback": "certify-rollback"}
TERMINAL = {"rolled-back", "active", "recovery-required"}


class SecureActivationError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise SecureActivationError(f"{label} must be an SHA-256 digest")
    return value


def validate_plan(plan: dict) -> str:
    if not isinstance(plan, dict) \
            or plan.get("format") != "openepm-macos-pilot-activation-plan-v1":
        raise SecureActivationError("sealed dry activation plan is required")
    claimed = _sha(plan.get("planSha256"), "dry plan")
    body = {key: item for key, item in plan.items() if key != "planSha256"}
    constraints = plan.get("constraints")
    if digest(body) != claimed \
            or not isinstance(constraints, dict) \
            or constraints.get("dockerExecutionIncluded") is not False \
            or constraints.get("sharedPilotMutationIncluded") is not False \
            or constraints.get("publicIngressStoppedUntilCommit") is not True \
            or constraints.get("writesDeniedUntilCommit") is not True \
            or constraints.get("commitIsPointOfNoReturn") is not True:
        raise SecureActivationError("dry activation plan is invalid")
    return claimed


def validate_contract(plan: dict, contract: dict, trust: TrustRegistry) -> str:
    plan_sha = validate_plan(plan)
    if not isinstance(contract, dict) \
            or contract.get("format") not in (
                "openepm-macos-pilot-activation-execution-contract-v2",
                "openepm-macos-pilot-activation-execution-contract-v3") \
            or contract.get("dryPlanSha256") != plan_sha:
        raise SecureActivationError("sealed execution contract is required")
    claimed = _sha(contract.get("executionContractSha256"), "execution contract")
    body = {key: item for key, item in contract.items()
            if key != "executionContractSha256"}
    if digest(body) != claimed:
        raise SecureActivationError("execution contract digest differs")
    try:
        trust.require_contract(claimed)
    except ReceiptValidationError as error:
        raise SecureActivationError(str(error)) from error
    if contract.get("activationId") in (None, ""):
        raise SecureActivationError("execution contract activation identity is invalid")
    if contract.get("format").endswith("-v3"):
        verifier=contract.get("authorityVerifier")
        if not isinstance(verifier,dict) or set(verifier)!={"algorithm","keyId","version"} \
                or verifier.get("algorithm")!="Ed25519":
            raise SecureActivationError("activation authority verifier is invalid")
        try:trust.verifier_public_key(verifier["keyId"],role="authority",
                                      version=verifier["version"])
        except Exception as error:raise SecureActivationError(
            "activation authority verifier is not trusted") from error
        roles=(("executorVerifier","executor"),
               ("ownerAuthorizationVerifier","owner"),
               ("authorityVerifier","authority"),
               ("evidenceVerifier","evidence"))
        identities=[]
        for field,role in roles:
            selected=contract.get(field)
            expected={"algorithm","keyId","version"} \
                | ({"publicKeySha256"} if field=="evidenceVerifier" else set())
            if not isinstance(selected,dict) \
                    or set(selected)!=expected \
                    or selected.get("algorithm")!="Ed25519":
                raise SecureActivationError("activation verifier identity is invalid")
            try:key=trust.verifier_public_key(selected["keyId"],role=role,
                                              version=selected["version"])
            except Exception as error:raise SecureActivationError(
                "activation verifier is not trusted") from error
            if field=="evidenceVerifier" and selected.get("publicKeySha256") \
                    != hashlib.sha256(key.public_bytes(
                        Encoding.Raw,PublicFormat.Raw)).hexdigest():
                raise SecureActivationError("evidence verifier material differs")
            identities.append((selected["keyId"],selected["version"]))
        if len(set(identities))!=4:
            raise SecureActivationError("activation verifier identities are not distinct")
    source, candidate = contract.get("source"), contract.get("candidate")
    source_keys = {"project","applicationImage","databaseImage","databaseVolume",
        "databaseVolumeId","schema","applicationCount","services","networks","ports",
        "dataDumpFingerprintSha256","businessDataDumpFingerprintSha256",
        "runningStateEvidenceSha256","quiescenceEvidenceSha256"}
    candidate_keys = {"project","applicationImage","databaseImage","databaseVolume",
        "databaseVolumeId","schema","applicationCount","services","networks",
        "publicPortsExposed","businessDataDumpFingerprintSha256",
        "candidateEvidenceSha256"}
    if contract.get("format").endswith("-v3"):
        candidate_keys.add("operationsImage")
    def exact_binding(value: object, keys: set[str], label: str) -> dict:
        if not isinstance(value, dict) or set(value) != keys \
                or not isinstance(value.get("project"), str) or not value["project"] \
                or IMAGE.fullmatch(str(value.get("applicationImage"))) is None \
                or IMAGE.fullmatch(str(value.get("databaseImage"))) is None \
                or not isinstance(value.get("databaseVolume"), str) \
                or not value["databaseVolume"] \
                or SHA.fullmatch(str(value.get("databaseVolumeId"))) is None \
                or not isinstance(value.get("schema"), dict) or not value["schema"] \
                or not isinstance(value.get("applicationCount"), int) \
                or isinstance(value.get("applicationCount"), bool) \
                or value["applicationCount"] not in (5,6) \
                or not isinstance(value.get("services"), dict) or not value["services"] \
                or not isinstance(value.get("networks"), dict) or not value["networks"] \
                or SHA.fullmatch(str(value.get(
                    "businessDataDumpFingerprintSha256"))) is None:
            raise SecureActivationError(f"execution contract {label} binding is incomplete")
        return value
    source=exact_binding(source,source_keys,"source")
    candidate=exact_binding(candidate,candidate_keys,"candidate")
    infrastructure=contract.get("infrastructure")
    if not isinstance(source.get("ports"),dict) or not source["ports"] \
            or SHA.fullmatch(str(source.get("dataDumpFingerprintSha256"))) is None \
            or SHA.fullmatch(str(source.get("runningStateEvidenceSha256"))) is None \
            or SHA.fullmatch(str(source.get("quiescenceEvidenceSha256"))) is None \
            or candidate.get("publicPortsExposed") is not False \
            or (contract.get("format").endswith("-v3") and
                (IMAGE.fullmatch(str(candidate.get("operationsImage"))) is None
                 or candidate["operationsImage"]!=candidate["applicationImage"])) \
            or SHA.fullmatch(str(candidate.get("candidateEvidenceSha256"))) is None \
            or source["applicationCount"] != candidate["applicationCount"] \
            or not isinstance(infrastructure,dict) \
            or SHA.fullmatch(str(infrastructure.get(
                "routeAuthoritySha256"))) is None \
            or source["businessDataDumpFingerprintSha256"] \
                != candidate["businessDataDumpFingerprintSha256"]:
        raise SecureActivationError("execution contract slot equality is invalid")
    return claimed


def _request_key(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise SecureActivationError("activation request key is invalid")
    return value


def _event(body: dict) -> dict:
    return {**body, "recordSha256": digest(body)}


def _sealed_pointer(contract: dict, slot: str, event: dict,
                    *, writes_admitted: bool,
                    public_ingress_permitted: bool) -> dict:
    if slot not in ("blue","green"):
        raise SecureActivationError("active-slot identity is invalid")
    binding=contract["source"] if slot=="blue" else contract["candidate"]
    value={"format":"openepm-macos-pilot-active-slot-v3",
        "activationId":contract["activationId"],
        "generation":event["ordinal"],"slot":slot,
        "authorityState":event["state"],
        "authorityPredecessorSha256":event["previousSha256"],
        "project":binding["project"],
        "applicationImage":binding["applicationImage"],
        "databaseImage":binding["databaseImage"],
        "databaseVolume":binding["databaseVolume"],
        "databaseVolumeId":binding["databaseVolumeId"],
        "schema":binding["schema"],"services":binding["services"],
        "networks":binding["networks"],
        "businessDataDumpFingerprintSha256":
            binding["businessDataDumpFingerprintSha256"],
        "bindingSha256":digest(binding),
        "executionContractSha256":contract["executionContractSha256"],
        "activationEventSha256":event["recordSha256"],
        "writesAdmitted":writes_admitted,
        "publicIngressPermitted":public_ingress_permitted}
    value["pointerSha256"]=digest(value)
    return value


def _base(records: list[dict], plan_sha: str, activation_id: str,
          contract_sha: Optional[str], *, request_key: str,
          request_sha: str, command: str, state: str,
          event_kind: str, evidence_sha: str) -> dict:
    previous = records[-1]["recordSha256"] if records else "0" * 64
    return {
        "format": "openepm-macos-pilot-activation-event-v1",
        "ordinal": len(records) + 1, "previousSha256": previous,
        "activationId": activation_id, "planSha256": plan_sha,
        "executionContractSha256": contract_sha,
        "requestKey": request_key, "requestSha256": request_sha,
        "command": command, "state": state, "eventKind": event_kind,
        "evidenceSha256": evidence_sha,
        "writesAdmitted": state == "active",
        "publicIngressPermitted": state == "active",
        "pointOfNoReturnCrossed": state in ("committed", "finalizing","finalized",
                                             "publishing-active","active"),
    }


def verify_journal(records: list[dict], plan_sha: str, activation_id: str,
                   expected_contract_sha: Optional[str] = None) -> Optional[dict]:
    if not isinstance(records, list):
        raise SecureActivationError("activation journal is invalid")
    previous = "0" * 64
    state = None
    contract_sha = None
    requests: dict[str, str] = {}
    records_by_sha: dict[str, dict] = {}
    last = None
    for ordinal, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise SecureActivationError("activation journal record is invalid")
        claimed = _sha(record.get("recordSha256"), "activation event")
        body = {key: item for key, item in record.items() if key != "recordSha256"}
        command, kind, next_state = (record.get("command"), record.get("eventKind"),
                                     record.get("state"))
        record_contract = record.get("executionContractSha256")
        if ordinal == 1:
            legal = command == "prepare" and kind == "intent" \
                and next_state == "preparing" and state is None \
                and record_contract is None
        elif kind == "completion":
            if state == "preparing":
                legal = command == "prepare" and next_state == "prepared" \
                    and isinstance(record_contract, str) \
                    and SHA.fullmatch(record_contract) is not None
                if legal: contract_sha = record_contract
            elif state in ("activating-read-only", "rolling-back", "committing",
                           "finalizing","publishing-rollback","publishing-active"):
                legal = ((state, command, next_state) in {
                    ("activating-read-only", "activate-read-only", "read-only"),
                    ("rolling-back", "rollback", "rolled-back"),
                    ("committing", "commit", "committed"),
                    ("finalizing", "finalize", "active"),
                    ("finalizing", "finalize", "finalized"),
                    ("publishing-active", "publish-active", "active"),
                    ("publishing-rollback", "certify-rollback", "rolled-back")}) \
                    and record_contract == contract_sha
            elif state == "recovery-required":
                origin = records_by_sha.get(last.get("intentSha256")) \
                    if isinstance(last, dict) else None
                legal = command == "finalize" and next_state == "active" \
                    and record_contract == contract_sha \
                    and isinstance(origin, dict) \
                    and origin.get("state") == "finalizing" \
                    and origin.get("command") == "finalize" \
                    and last.get("pointOfNoReturnCrossed") is True \
                    and last.get("outcomeAmbiguous") is True \
                    and last.get("rollbackPermitted") is False \
                    and record.get("recoveryEventSha256") == last.get("recordSha256") \
                    and record.get("intentSha256") == origin.get("recordSha256")
            else:
                legal = False
        elif kind == "intent" and contract_sha is not None:
            legal = ((state, command, next_state) in {
                ("prepared", "activate-read-only", "activating-read-only"),
                ("prepared", "rollback", "rolling-back"),
                ("read-only", "rollback", "rolling-back"),
                ("read-only", "commit", "committing"),
                ("committed", "finalize", "finalizing"),
                ("finalized", "publish-active", "publishing-active"),
                ("rolled-back", "certify-rollback", "publishing-rollback")}) \
                and record_contract == contract_sha
        elif kind == "recovery":
            legal = state == "finalizing" \
                and command == "recovery-required" \
                and next_state == "recovery-required" \
                and record_contract == contract_sha
        else:
            legal = False
        key, request_sha = record.get("requestKey"), record.get("requestSha256")
        if record.get("ordinal") != ordinal \
                or record.get("previousSha256") != previous \
                or record.get("activationId") != activation_id \
                or record.get("planSha256") != plan_sha \
                or digest(body) != claimed or not legal \
                or not isinstance(key, str) or not key \
                or not isinstance(request_sha, str) or SHA.fullmatch(request_sha) is None \
                or (key in requests and requests[key] != request_sha):
            raise SecureActivationError("activation journal chain or transition is invalid")
        requests[key] = request_sha
        records_by_sha[claimed] = record
        previous, state, last = claimed, next_state, record
    if expected_contract_sha is not None and contract_sha != expected_contract_sha:
        raise SecureActivationError("journal execution contract differs")
    return last


def begin_prepare(plan: dict, records: list[dict], *, activation_id: str,
                  request_key: str, evidence_sha256: str) -> tuple[list[dict], dict, bool]:
    plan_sha = validate_plan(plan); _request_key(request_key)
    _sha(evidence_sha256, "prepare evidence")
    if not isinstance(activation_id, str) or not activation_id or len(activation_id) > 128:
        raise SecureActivationError("activation identity is invalid")
    verify_journal(records, plan_sha, activation_id)
    request = {"command":"prepare", "activationId":activation_id,
               "planSha256":plan_sha, "evidenceSha256":evidence_sha256}
    request_sha = digest(request)
    for record in records:
        if record["requestKey"] == request_key:
            if record["requestSha256"] != request_sha:
                raise SecureActivationError("request key replay has different content")
            return records, record, True
    if records:
        raise SecureActivationError("prepare is valid only for an empty journal")
    body = _base(records, plan_sha, activation_id, None,
        request_key=request_key, request_sha=request_sha, command="prepare",
        state="preparing", event_kind="intent", evidence_sha=evidence_sha256)
    event = _event(body); return [event], event, False


def begin(plan: dict, contract: dict, trust: TrustRegistry, records: list[dict], *,
          command: str, request_key: str,
          evidence_sha256: str) -> tuple[list[dict], dict, bool]:
    if command not in ("activate-read-only", "rollback", "commit", "finalize",
                       "certify-rollback","publish-active"):
        raise SecureActivationError("activation command is invalid")
    plan_sha = validate_plan(plan); contract_sha = validate_contract(plan, contract, trust)
    activation_id = contract["activationId"]; _request_key(request_key)
    _sha(evidence_sha256, "intent evidence")
    last = verify_journal(records, plan_sha, activation_id, contract_sha)
    prior = last.get("state") if last else None
    variant = ("rollback-" + prior if command == "rollback" else
        "finalize-v3" if command=="finalize" and contract.get("format").endswith("-v3")
        else command)
    specification = COMMAND_STATE.get(variant)
    request = {"command":command,"activationId":activation_id,
        "planSha256":plan_sha,"executionContractSha256":contract_sha,
        "evidenceSha256":evidence_sha256}
    request_sha = digest(request)
    for record in records:
        if record["requestKey"] == request_key:
            if record["requestSha256"] != request_sha:
                raise SecureActivationError("request key replay has different content")
            return records, record, True
    if specification is None or specification[0] != prior:
        if prior in ("committed", "finalizing", "active"):
            raise SecureActivationError("commit is the point of no return")
        raise SecureActivationError(f"{command} is invalid from state {prior!r}")
    receipt_command, intent_state = RECEIPT_COMMAND[variant], specification[1]
    body = _base(records, plan_sha, activation_id, contract_sha,
        request_key=request_key, request_sha=request_sha, command=receipt_command,
        state=intent_state, event_kind="intent", evidence_sha=evidence_sha256)
    event = _event(body); return [*records,event],event,False


def complete(plan: dict, contract: dict, trust: TrustRegistry,
             records: list[dict], *, request_key: str, receipt: dict,
             now_utc: str, owner_authorization: dict | None = None,
             read_only_completion: dict | None = None,
             accepted_owner_authorization: dict | None = None
             ) -> tuple[list[dict], dict, bool]:
    plan_sha = validate_plan(plan); contract_sha = validate_contract(plan, contract, trust)
    activation_id = contract["activationId"]; _request_key(request_key)
    last = verify_journal(records, plan_sha, activation_id)
    command = receipt.get("command") if isinstance(receipt, dict) else None
    receipt_sha = receipt.get("receiptSha256") if isinstance(receipt, dict) else None
    authorization_sha = (owner_authorization or {}).get("authorizationSha256")
    receipt_envelope_sha = digest(receipt) if isinstance(receipt, dict) else None
    authorization_envelope_sha = digest(owner_authorization) \
        if isinstance(owner_authorization, dict) else None
    read_only_envelope_sha = digest(read_only_completion) \
        if isinstance(read_only_completion, dict) else None
    accepted_authorization_envelope_sha=digest(accepted_owner_authorization) \
        if isinstance(accepted_owner_authorization,dict) else None
    request = {"command":command,"activationId":activation_id,
        "planSha256":plan_sha,"executionContractSha256":contract_sha,
        "receiptSha256":receipt_sha,"receiptEnvelopeSha256":receipt_envelope_sha,
        "ownerAuthorizationSha256":authorization_sha,
        "ownerAuthorizationEnvelopeSha256":authorization_envelope_sha,
        "readOnlyCompletionEnvelopeSha256":read_only_envelope_sha,
        "acceptedOwnerAuthorizationEnvelopeSha256":
            accepted_authorization_envelope_sha}
    request_sha = digest(request)
    for record in records:
        if record["requestKey"] == request_key:
            if record["requestSha256"] != request_sha:
                raise SecureActivationError("request key replay has different content")
            return records,record,True
    if last is None or last.get("eventKind") != "intent":
        raise SecureActivationError("completion requires current mutation intent")
    try:
        certified = validate_executor_receipt(contract, last, receipt, trust,
            journal_records=records, owner_authorization=owner_authorization,
            read_only_completion=read_only_completion,
            accepted_owner_authorization=accepted_owner_authorization,
            now_utc=now_utc)
    except ReceiptValidationError as error:
        raise SecureActivationError(str(error)) from error
    targets = {"preparing":"prepared","activating-read-only":"read-only",
               "rolling-back":"rolled-back","committing":"committed",
               "finalizing":("finalized" if contract.get("format").endswith("-v3") else "active"),
               "publishing-rollback":"rolled-back","publishing-active":"active"}
    target = targets.get(last["state"])
    if target is None or command != last["command"]:
        raise SecureActivationError("receipt does not complete current intent")
    body = _base(records, plan_sha, activation_id, contract_sha,
        request_key=request_key, request_sha=request_sha, command=command,
        state=target, event_kind="completion", evidence_sha=certified)
    body["intentSha256"] = last["recordSha256"]
    body["receiptSha256"] = certified
    body["receiptEnvelopeSha256"] = receipt_envelope_sha
    body["ownerAuthorizationSha256"] = authorization_sha
    body["ownerAuthorizationEnvelopeSha256"] = authorization_envelope_sha
    body["readOnlyCompletionEnvelopeSha256"] = read_only_envelope_sha
    body["acceptedOwnerAuthorizationEnvelopeSha256"] = \
        accepted_authorization_envelope_sha
    event = _event(body); return [*records,event],event,False


def recovery_required(plan: dict, records: list[dict], *, activation_id: str,
        request_key: str, observation_sha256: str,
        contract_sha256: str | None = None) -> tuple[list[dict], dict, bool]:
    plan_sha = validate_plan(plan); _request_key(request_key)
    observation = _sha(observation_sha256, "recovery observation")
    last = verify_journal(records, plan_sha, activation_id, contract_sha256)
    for record in records:
        if record["requestKey"] == request_key:
            replay_request = {"command":"recovery-required",
                "intentSha256":record.get("intentSha256"),
                "observationSha256":observation}
            if record["requestSha256"] != digest(replay_request):
                raise SecureActivationError("request key replay has different content")
            return records,record,True
    if last is None or last.get("eventKind") != "intent" \
            or last.get("state") != "finalizing" \
            or last.get("command") != "finalize":
        raise SecureActivationError("recovery is reserved for current finalization intent")
    request = {"command":"recovery-required",
        "intentSha256":last["recordSha256"],"observationSha256":observation}
    request_sha = digest(request)
    body = _base(records, plan_sha, activation_id,
        last.get("executionContractSha256"), request_key=request_key,
        request_sha=request_sha, command="recovery-required",
        state="recovery-required", event_kind="recovery", evidence_sha=observation)
    body["intentSha256"] = last["recordSha256"]
    body["pointOfNoReturnCrossed"] = True
    body["outcomeAmbiguous"] = True
    body["rollbackPermitted"] = False
    event=_event(body); return [*records,event],event,False


def reconcile_finalize(plan: dict, contract: dict, trust: TrustRegistry,
        records: list[dict], *, request_key: str, receipt: dict,
        now_utc: str) -> tuple[list[dict], dict, bool]:
    """Certify a lost finalization result forward-only after PONR recovery."""
    plan_sha=validate_plan(plan); contract_sha=validate_contract(plan,contract,trust)
    activation_id=contract["activationId"]; _request_key(request_key)
    last=verify_journal(records,plan_sha,activation_id,contract_sha)
    receipt_sha=receipt.get("receiptSha256") if isinstance(receipt,dict) else None
    receipt_envelope_sha=digest(receipt) if isinstance(receipt,dict) else None
    for record in records:
        if record["requestKey"] == request_key:
            replay_request={"command":"reconcile-finalize","activationId":activation_id,
                "planSha256":plan_sha,"executionContractSha256":contract_sha,
                "recoveryEventSha256":record.get("recoveryEventSha256"),
                "receiptSha256":receipt_sha,
                "receiptEnvelopeSha256":receipt_envelope_sha}
            if record["requestSha256"] != digest(replay_request):
                raise SecureActivationError("request key replay has different content")
            return records,record,True
    if last is None or last.get("state") != "recovery-required" \
            or last.get("pointOfNoReturnCrossed") is not True \
            or last.get("outcomeAmbiguous") is not True \
            or last.get("rollbackPermitted") is not False:
        raise SecureActivationError(
            "finalize reconciliation requires forward-only recovery head")
    intent=next((record for record in records
                 if record.get("recordSha256")==last.get("intentSha256")),None)
    if intent is None or intent.get("state") != "finalizing" \
            or intent.get("command") != "finalize":
        raise SecureActivationError(
            "finalize reconciliation requires exact finalizing intent")
    request={"command":"reconcile-finalize","activationId":activation_id,
        "planSha256":plan_sha,"executionContractSha256":contract_sha,
        "recoveryEventSha256":last["recordSha256"],
        "receiptSha256":receipt_sha,"receiptEnvelopeSha256":receipt_envelope_sha}
    request_sha=digest(request)
    try:
        certified=validate_executor_receipt(contract,intent,receipt,trust,
            journal_records=records,recovery_event=last,now_utc=now_utc)
    except ReceiptValidationError as error:
        raise SecureActivationError(str(error)) from error
    body=_base(records,plan_sha,activation_id,contract_sha,
        request_key=request_key,request_sha=request_sha,command="finalize",
        state="active",event_kind="completion",evidence_sha=certified)
    body["intentSha256"]=intent["recordSha256"]
    body["recoveryEventSha256"]=last["recordSha256"]
    body["receiptSha256"]=certified
    body["receiptEnvelopeSha256"]=receipt_envelope_sha
    body["ownerAuthorizationSha256"]=None
    body["ownerAuthorizationEnvelopeSha256"]=None
    body["readOnlyCompletionEnvelopeSha256"]=None
    event=_event(body)
    return [*records,event],event,False


class SecureActivationService:
    """Only supported mutation-state API; trust and journal are service-owned."""

    def __init__(self, root: Path, trust: TrustRegistry):
        self._store = ActivationStore(root)
        self._trust = trust
        self._store.initialize()

    def _read(self, filename: str, label: str) -> dict:
        path = self._store.root / filename
        if not path.exists():
            raise SecureActivationError(f"protected {label} is missing")
        try:
            self._store._secure(path)
            value = json.loads(path.read_text(encoding="utf-8"))
        except (ActivationStateError, OSError, UnicodeError,
                json.JSONDecodeError) as error:
            raise SecureActivationError(f"protected {label} is invalid") from error
        if not isinstance(value, dict):
            raise SecureActivationError(f"protected {label} is invalid")
        return value

    def _plan(self) -> dict:
        plan = self._read("activation-plan.json", "activation plan")
        validate_plan(plan); return plan

    def _contract(self) -> dict:
        contract = self._read("activation-execution-contract.json",
                              "execution contract")
        validate_contract(self._plan(), contract, self._trust); return contract

    def _owner_authorization_locked(self, intent_sha256: str) -> dict | None:
        path=self._store.root / "commit-owner-authorization.json"
        if not path.exists(): return None
        record=self._read("commit-owner-authorization.json","owner authorization")
        if not isinstance(record,dict) \
                or set(record)!={"format","intentEventSha256","acceptedAtUtc",
                                 "ownerKeyId","ownerKeyVersion",
                                 "ownerPublicKeyBase64","ownerPublicKeySha256",
                                 "authorization","recordSha256"} \
                or record.get("format") \
                    != "openepm-macos-pilot-accepted-owner-authorization-v1" \
                or record.get("intentEventSha256")!=intent_sha256 \
                or record.get("recordSha256")!=digest({
                    key:value for key,value in record.items()
                    if key!="recordSha256"}):
            raise SecureActivationError("protected owner authorization is invalid")
        return record

    def owner_authorization(self, intent_sha256: str) -> dict | None:
        """Return exact pre-effect owner authorization accepted for commit."""
        _sha(intent_sha256,"commit intent")
        with self._store._lock():
            return self._owner_authorization_locked(intent_sha256)

    def validate_rollback_gate_attestation(self, attestation: dict, *,
            intent: dict, rollback_completion: dict, now_utc: str) -> str:
        """Verify the exact signed blue-open gate read back by fixed core."""
        contract=self._contract(); verifier=contract.get("authorityVerifier",
                                                          contract["executorVerifier"])
        required={"format","activationId","executionContractSha256","slot",
            "state","authorityState","rollbackCompletionSha256",
            "publicationIntentSha256","keyId","keyVersion",
            "attestationSha256","signature"}
        if contract.get("format","").endswith("-v3"):
            required|={"blueDatabaseOpenSha256","greenDatabaseClosedSha256",
                "blueProducerOpenSha256","blueServiceHealthSha256"}
        if not isinstance(attestation,dict) or set(attestation)!=required \
                or attestation.get("format") \
                    != "openepm-macos-pilot-rollback-gate-attestation-v1" \
                or attestation.get("activationId")!=contract["activationId"] \
                or attestation.get("executionContractSha256") \
                    != contract["executionContractSha256"] \
                or (attestation.get("slot"),attestation.get("state"),
                    attestation.get("authorityState")) \
                    != ("blue","open","rolled-back") \
                or attestation.get("rollbackCompletionSha256") \
                    != rollback_completion.get("recordSha256") \
                or attestation.get("publicationIntentSha256") \
                    != intent.get("recordSha256") \
                or attestation.get("keyId")!=verifier["keyId"] \
                or attestation.get("keyVersion")!=verifier["version"]:
            raise SecureActivationError("rollback gate attestation differs")
        if contract.get("format","").endswith("-v3") and any(
                SHA.fullmatch(str(attestation.get(field))) is None for field in (
                    "blueDatabaseOpenSha256","greenDatabaseClosedSha256",
                    "blueProducerOpenSha256","blueServiceHealthSha256")):
            raise SecureActivationError("rollback gate attestation differs")
        signed={key:value for key,value in attestation.items()
                if key!="signature"}
        claimed=attestation.get("attestationSha256")
        if claimed!=digest({key:value for key,value in signed.items()
                            if key!="attestationSha256"}):
            raise SecureActivationError("rollback gate attestation digest differs")
        try:
            self._trust.verify(verifier["keyId"],canonical(signed),
                attestation.get("signature"),"rollback gate",role=("authority" if
                    contract.get("format").endswith("-v3") else "executor"),
                version=verifier["version"],now_utc=now_utc)
        except ReceiptValidationError as error:
            raise SecureActivationError(str(error)) from error
        return digest(attestation)

    def validate_active_gate_attestation(self, attestation: dict, *,
            intent: dict, finalized_completion: dict, now_utc: str) -> str:
        """Verify the exact signed green-open gate read back by fixed core."""
        contract=self._contract();verifier=contract.get("authorityVerifier",
                                                         contract["executorVerifier"])
        required={"format","activationId","executionContractSha256","slot",
            "state","authorityState","finalizedCompletionSha256",
            "publicationIntentSha256","keyId","keyVersion",
            "blueDatabaseClosedSha256","greenDatabaseOpenSha256",
            "greenProducerOpenSha256","greenServiceHealthSha256",
            "attestationSha256","signature"}
        if not isinstance(attestation,dict) or set(attestation)!=required \
                or attestation.get("format") \
                    !="openepm-macos-pilot-active-gate-attestation-v1" \
                or attestation.get("activationId")!=contract["activationId"] \
                or attestation.get("executionContractSha256") \
                    !=contract["executionContractSha256"] \
                or (attestation.get("slot"),attestation.get("state"),
                    attestation.get("authorityState"))!=("green","open","active") \
                or attestation.get("finalizedCompletionSha256") \
                    !=finalized_completion.get("recordSha256") \
                or attestation.get("publicationIntentSha256") \
                    !=intent.get("recordSha256") \
                or attestation.get("keyId")!=verifier["keyId"] \
                or attestation.get("keyVersion")!=verifier["version"] \
                or any(SHA.fullmatch(str(attestation.get(field))) is None for field in (
                    "blueDatabaseClosedSha256","greenDatabaseOpenSha256",
                    "greenProducerOpenSha256","greenServiceHealthSha256")):
            raise SecureActivationError("active gate attestation differs")
        signed={key:value for key,value in attestation.items() if key!="signature"}
        if attestation.get("attestationSha256")!=digest({key:value for key,value
                in signed.items() if key!="attestationSha256"}):
            raise SecureActivationError("active gate attestation digest differs")
        try:
            self._trust.verify(verifier["keyId"],canonical(signed),
                attestation.get("signature"),"active gate",role=("authority" if
                    contract.get("format").endswith("-v3") else "executor"),
                version=verifier["version"],now_utc=now_utc)
        except ReceiptValidationError as error:raise SecureActivationError(str(error)) from error
        return digest(attestation)

    def accept_owner_authorization(self, *, intent: dict,
            read_only_completion: dict, authorization: dict,
            now_utc: str) -> dict:
        """Validate once and durably bind owner consent before any host effect."""
        with self._store._lock():
            plan=self._plan(); contract=self._contract(); records=self._store.load()
            last=verify_journal(records,plan["planSha256"],contract["activationId"],
                                contract["executionContractSha256"])
            if last != intent or intent.get("state")!="committing":
                raise SecureActivationError("owner authorization requires current commit intent")
            existing=self._owner_authorization_locked(intent["recordSha256"])
            if existing is not None:
                if existing["authorization"]!=authorization:
                    raise SecureActivationError("owner authorization already differs")
                return existing
            try:
                validate_owner_authorization(contract,intent,read_only_completion,
                    authorization,self._trust,now_utc=now_utc)
            except ReceiptValidationError as error:
                raise SecureActivationError(str(error)) from error
            verifier=contract["ownerAuthorizationVerifier"]
            try:
                public_key=self._trust.verifier_public_key(verifier["keyId"],
                    role="owner",version=verifier["version"])
            except ReceiptValidationError as error:
                raise SecureActivationError(str(error)) from error
            raw=public_key.public_bytes(Encoding.Raw,PublicFormat.Raw)
            body={"format":"openepm-macos-pilot-accepted-owner-authorization-v1",
                "intentEventSha256":intent["recordSha256"],
                "acceptedAtUtc":now_utc,"ownerKeyId":verifier["keyId"],
                "ownerKeyVersion":verifier["version"],
                "ownerPublicKeyBase64":base64.b64encode(raw).decode("ascii"),
                "ownerPublicKeySha256":hashlib.sha256(raw).hexdigest(),
                "authorization":authorization}
            record={**body,"recordSha256":digest(body)}
            self._store._atomic("commit-owner-authorization.json",record)
            return record

    def begin_prepare(self, plan: dict, *, activation_id: str,
                      request_key: str, evidence_sha256: str) -> dict:
        with self._store._lock():
            existing = self._store.load()
            if not existing:
                self._store._atomic("activation-plan.json", plan)
                self._store._atomic("activation-identity.json", {
                    "format":"openepm-macos-pilot-activation-identity-v1",
                    "activationId":activation_id,"planSha256":validate_plan(plan)})
            elif self._plan() != plan:
                raise SecureActivationError("protected activation plan differs")
            records,event,replay = begin_prepare(plan, existing,
                activation_id=activation_id, request_key=request_key,
                evidence_sha256=evidence_sha256)
            if not replay: self._store._append_locked(event)
            return event

    def complete_prepare(self, contract: dict, *, request_key: str,
                         receipt: dict, now_utc: str) -> dict:
        with self._store._lock():
            plan=self._plan(); records=self._store.load()
            validate_contract(plan,contract,self._trust)
            identity=self._read("activation-identity.json","activation identity")
            if identity.get("activationId") != contract.get("activationId"):
                raise SecureActivationError("execution contract activation differs")
            path=self._store.root / "activation-execution-contract.json"
            if path.exists() and self._contract() != contract:
                raise SecureActivationError("protected execution contract differs")
            _,event,replay=complete(plan,contract,self._trust,records,
                request_key=request_key,receipt=receipt,now_utc=now_utc)
            if not replay:
                if not path.exists(): self._store._atomic(path.name,contract)
                self._store._append_locked(event)
            return event

    def begin(self, *, command: str, request_key: str,
              evidence_sha256: str) -> dict:
        with self._store._lock():
            plan=self._plan(); contract=self._contract(); records=self._store.load()
            _,event,replay=begin(plan,contract,self._trust,records,command=command,
                request_key=request_key,evidence_sha256=evidence_sha256)
            if not replay:self._store._append_locked(event)
            return event

    def complete(self, *, request_key: str, receipt: dict, now_utc: str,
                 owner_authorization: dict | None = None,
                 read_only_completion: dict | None = None,
                 accepted_owner_authorization: dict | None = None) -> dict:
        with self._store._lock():
            plan=self._plan(); contract=self._contract(); records=self._store.load()
            _,event,replay=complete(plan,contract,self._trust,records,
                request_key=request_key,receipt=receipt,now_utc=now_utc,
                owner_authorization=owner_authorization,
                read_only_completion=read_only_completion,
                accepted_owner_authorization=accepted_owner_authorization)
            if not replay:
                self._store._append_locked(event)
                if event.get("command")=="activate-read-only" \
                        and event.get("state")=="read-only":
                    self._store._atomic("staged-green-slot.json",_sealed_pointer(
                        contract,"green",event,writes_admitted=False,
                        public_ingress_permitted=False))
            return event

    def recovery_required(self, *, request_key: str,
                          observation_sha256: str) -> dict:
        with self._store._lock():
            plan=self._plan(); records=self._store.load()
            if not records or records[-1].get("state") not in (
                    "finalizing","recovery-required"):
                raise SecureActivationError(
                    "recovery is reserved for current finalization intent")
            identity=self._read("activation-identity.json","activation identity")
            contract_sha=next((record.get("executionContractSha256") for record in records
                if record.get("executionContractSha256") is not None),None)
            _,event,replay=recovery_required(plan,records,
                activation_id=identity["activationId"],request_key=request_key,
                observation_sha256=observation_sha256,
                contract_sha256=contract_sha)
            if not replay: self._store._append_locked(event)
            return event

    def reconcile_finalize(self, *, request_key: str, receipt: dict,
                           now_utc: str) -> dict:
        with self._store._lock():
            plan=self._plan(); contract=self._contract(); records=self._store.load()
            _,event,replay=reconcile_finalize(plan,contract,self._trust,records,
                request_key=request_key,receipt=receipt,now_utc=now_utc)
            if not replay: self._store._append_locked(event)
            return event

    def require_staged_green_pointer(self) -> dict:
        """Return exact finalizing green route authority or fail closed."""
        with self._store._lock():
            plan=self._plan(); contract=self._contract(); records=self._store.load()
            last=verify_journal(records,plan["planSha256"],contract["activationId"],
                                contract["executionContractSha256"])
            finalizing=next((record for record in reversed(records)
                             if record.get("state")=="finalizing"),None)
            if finalizing is None or last is None \
                    or last.get("state") not in ("finalizing","recovery-required"):
                raise SecureActivationError("staged green pointer has no finalizing authority")
            current=self._read("active-slot.json","active slot")
            expected=_sealed_pointer(contract,"green",finalizing,
                writes_admitted=False,public_ingress_permitted=True)
            if current != expected:
                raise SecureActivationError("staged green pointer differs")
            return current

    def staged_green_pointer_for_commit(self, commit_intent: dict) -> dict:
        """Return the exact read-only pointer authorized by a current commit intent.

        This is the executor-side half of the cross-identity handoff.  The
        returned pointer is still untrusted by the privileged authority until
        it is included in executor-signed IPC evidence.
        """
        with self._store._lock():
            plan=self._plan();contract=self._contract();records=self._store.load()
            last=verify_journal(records,plan["planSha256"],contract["activationId"],
                                contract["executionContractSha256"])
            if last != commit_intent or last.get("command")!="commit" \
                    or last.get("state")!="committing" or len(records)<2:
                raise SecureActivationError(
                    "staged green pointer requires the current commit intent")
            read_only=records[-2]
            if read_only.get("eventKind")!="completion" \
                    or read_only.get("command")!="activate-read-only" \
                    or read_only.get("state")!="read-only" \
                    or last.get("previousSha256")!=read_only.get("recordSha256"):
                raise SecureActivationError(
                    "staged green pointer requires the preceding read-only completion")
            pointer=self._read("staged-green-slot.json","staged green slot")
            expected=_sealed_pointer(contract,"green",read_only,
                writes_admitted=False,public_ingress_permitted=False)
            if pointer!=expected:
                raise SecureActivationError("staged green pointer differs")
            return pointer

    def authority_pointer_for_intent(self, intent: dict) -> tuple[str,dict]:
        """Derive the exact root-visible pointer needed by a later phase."""
        with self._store._lock():
            plan=self._plan();contract=self._contract();records=self._store.load()
            last=verify_journal(records,plan["planSha256"],contract["activationId"],
                                contract["executionContractSha256"])
            if last!=intent:
                raise SecureActivationError("authority pointer requires current intent")
            if intent.get("command")=="finalize" and intent.get("state")=="finalizing" \
                    and len(records)>=2:
                event=records[-2];purpose="finalize-committed"
                if event.get("eventKind")!="completion" \
                        or event.get("command")!="commit" \
                        or event.get("state")!="committed" \
                        or intent.get("previousSha256")!=event.get("recordSha256"):
                    raise SecureActivationError("committed pointer lineage differs")
            elif intent.get("command")=="publish-active" \
                    and intent.get("state")=="publishing-active":
                event=intent;purpose="publish-active"
            elif intent.get("command")=="certify-rollback" \
                    and intent.get("state")=="publishing-rollback" \
                    and len(records)>=3:
                completion=records[-2];event=records[-3]
                purpose="certify-rollback-preopen"
                if completion.get("eventKind")!="completion" \
                        or completion.get("command")!="rollback" \
                        or completion.get("state")!="rolled-back" \
                        or intent.get("previousSha256")!=completion.get("recordSha256") \
                        or event.get("eventKind")!="intent" \
                        or event.get("command")!="rollback" \
                        or event.get("state")!="rolling-back" \
                        or completion.get("previousSha256")!=event.get("recordSha256"):
                    raise SecureActivationError("rollback pointer lineage differs")
            else:
                raise SecureActivationError("authority pointer phase differs")
            pointer=_sealed_pointer(contract,
                "blue" if purpose=="certify-rollback-preopen" else "green",event,
                writes_admitted=False,public_ingress_permitted=False)
            if purpose=="publish-active" and self._read(
                    "active-slot.json","active slot")!=pointer:
                raise SecureActivationError("publishing authority pointer differs")
            return purpose,pointer

    def public_pointer_for_completion(self, completion:dict) -> tuple[str,dict]:
        with self._store._lock():
            plan=self._plan();contract=self._contract();records=self._store.load()
            last=verify_journal(records,plan["planSha256"],contract["activationId"],
                                contract["executionContractSha256"])
            if last!=completion or completion.get("eventKind")!="completion":
                raise SecureActivationError("public pointer requires current completion")
            if (completion.get("command"),completion.get("state"))==(
                    "publish-active","active"):
                purpose="certify-active";slot="green"
            elif (completion.get("command"),completion.get("state"))==(
                    "certify-rollback","rolled-back"):
                purpose="certify-rollback";slot="blue"
            else:raise SecureActivationError("public pointer completion differs")
            expected=_sealed_pointer(contract,slot,completion,
                writes_admitted=True,public_ingress_permitted=True)
            if self._read("active-slot.json","active slot")!=expected:
                raise SecureActivationError("public pointer differs")
            return purpose,expected

    def publish_pointer(self) -> dict:
        with self._store._lock():
            plan=self._plan(); contract=self._contract(); records=self._store.load()
            last=verify_journal(records,plan["planSha256"],contract["activationId"],
                                contract["executionContractSha256"])
            allowed={"prepared","rolling-back","rolled-back","committed",
                     "finalizing","finalized","publishing-active","active"}
            if last is None or last["state"] not in allowed:
                raise SecureActivationError(
                    "pointer requires exact routable activation authority")
            state=last["state"]
            slot="green" if state in ("committed","finalizing","finalized",
                                      "publishing-active","active") else "blue"
            writes=state in ("rolled-back","active")
            public=(state in ("rolled-back","active") if contract.get("format").endswith("-v3")
                    else state in ("rolling-back","rolled-back","finalizing","active"))
            pointer=_sealed_pointer(contract,slot,last,writes_admitted=writes,
                                    public_ingress_permitted=public)
            active=self._store.root / "active-slot.json"
            if not active.exists() and state != "prepared":
                raise SecureActivationError(
                    "slot transition requires prior source authority")
            if active.exists():
                current=self._read("active-slot.json","active slot")
                if current.get("pointerSha256") != digest({k:v for k,v in current.items()
                                                           if k!="pointerSha256"}):
                    raise SecureActivationError("existing active-slot pointer is invalid")
                if current["pointerSha256"] == pointer["pointerSha256"]:
                    return current
                predecessor={"rolling-back":"prepared","rolled-back":"rolling-back",
                    "committed":"prepared","finalizing":"committed",
                    "finalized":"finalizing","publishing-active":"finalized",
                    "active":("publishing-active" if contract.get("format").endswith("-v3")
                              else "finalizing")}.get(state)
                prior=next((record for record in reversed(records[:-1])
                            if record.get("state")==predecessor),None)
                if prior is None:
                    raise SecureActivationError("slot transition predecessor is absent")
                prior_slot="green" if predecessor in ("committed","finalizing",
                    "finalized","publishing-active") \
                    else "blue"
                prior_writes=predecessor in ("rolled-back","active")
                prior_public=(predecessor in ("rolled-back","active")
                    if contract.get("format").endswith("-v3") else predecessor in
                    ("rolling-back","rolled-back","finalizing","active"))
                expected=_sealed_pointer(contract,prior_slot,prior,
                    writes_admitted=prior_writes,
                    public_ingress_permitted=prior_public)
                if current != expected:
                    raise SecureActivationError(
                        "existing active-slot pointer is not exact predecessor authority")
                if state in ("committed","rolling-back"):
                    self._store._atomic("active-slot.previous.json",current)
            self._store._atomic("active-slot.json",pointer)
            return pointer
