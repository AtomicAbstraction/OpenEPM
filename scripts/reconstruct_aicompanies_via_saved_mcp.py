"""Install the complete pinned AIcompanies rule-family set through saved MCP OAuth.

The native Codex bridge owns credentials and transport.  This bounded client
only submits current application-language programs; it never creates batches,
partitions, or worker jobs.
"""
from __future__ import annotations

import argparse
import asyncio
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from scripts.aicompanies_rule_reconstruction import reconstruct_rule_packets
from scripts.programmable_source_authoring import _program, state_pins
from scripts.provision_programmable_uat_sample_contents import _exact_replay

REQUIRED_PACKET_FORMATS = frozenset((
    "openepm-aicompanies-native-rules-v1",
    "openepm-aicompanies-scalar-supplement-v1",
    "openepm-aicompanies-apportionment-v1",
))

SIGNED_EFFECT_TOOLS = frozenset((
    "execute_v2_expression_rule_program",
    "execute_v2_metadata_program",
    "execute_v2_python_program_build",
    "execute_v2_python_program_registry",
    "execute_v2_python_program_workflow",
))


class AdmittedMCPCall:
    """Bind every effect to one server-issued operation identity.

    The semantic key remains a client-side reconciliation label.  The signed
    operation ID is the only idempotency identity sent to fixed core and is
    cached for the exact replay performed during this process.  A restarted
    client first rereads current application state, so already committed units
    are reconciled before another admission can be requested.
    """

    def __init__(self, invoke, identity_prefix: str):
        if not callable(invoke) or not isinstance(identity_prefix, str):
            raise ValueError("AICOMPANIES_MCP_CALL_CONFIGURATION_INVALID")
        self.invoke = invoke
        self.identity_prefix = identity_prefix
        self.sequence = 0
        self.admissions: dict[tuple[str, str], tuple[str, str]] = {}

    async def _invoke(self, tool: str, arguments: dict) -> dict:
        self.sequence += 1
        identity = f"{self.identity_prefix}.{self.sequence:05d}"
        return await asyncio.to_thread(
            self.invoke, identity, tool, arguments)

    async def __call__(self, tool: str, arguments: dict) -> dict:
        if tool not in SIGNED_EFFECT_TOOLS:
            return await self._invoke(tool, arguments)
        if (not isinstance(arguments, dict)
                or not isinstance(arguments.get("workspace_id"), str)
                or not isinstance(arguments.get("application_id"), str)
                or not isinstance(arguments.get("program"), dict)
                or not isinstance(arguments.get("idempotency_key"), str)):
            raise ValueError("AICOMPANIES_SIGNED_EFFECT_ARGUMENT_INVALID")
        semantic_key = arguments["idempotency_key"]
        intent = {key: value for key, value in arguments.items()
                  if key != "idempotency_key"}
        digest = sha256(json.dumps(intent, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        cache_key = (tool, semantic_key)
        prior = self.admissions.get(cache_key)
        if prior is None:
            admission = await self._invoke("issue_v2_operation_admission", {
                "workspace_id": arguments["workspace_id"],
                "application_id": arguments["application_id"],
                "program": arguments["program"],
                "ttl_seconds": 86_400,
            })
            operation_id = admission.get("operationId")
            if not isinstance(operation_id, str) or not operation_id.startswith("oa1_"):
                raise RuntimeError("AICOMPANIES_OPERATION_ADMISSION_INVALID")
            self.admissions[cache_key] = (digest, operation_id)
        else:
            prior_digest, operation_id = prior
            if prior_digest != digest:
                raise RuntimeError("AICOMPANIES_OPERATION_INTENT_CHANGED")
        return await self._invoke(tool, {
            **arguments, "idempotency_key": operation_id})


def load_packet(root: Path) -> dict:
    packet = json.loads((root / "coverage.json").read_text())
    for definition in packet["definitions"] + packet.get("inactiveDefinitions", []):
        definition["source"] = (root / definition.pop("sourceFile")).read_text()
    return packet


def current_business_program_ids(packets) -> set[str]:
    values = set()
    for packet in packets:
        for item in (packet.get("definitions", [])
                     + packet.get("inactiveDefinitions", [])):
            identity = item.get("definitionId")
            if not isinstance(identity, str):
                raise ValueError("AICOMPANIES_RULE_DEFINITION_INVALID")
            values.add("source-rule-" + identity)
    return values


def current_business_rule_ids(packets) -> tuple[set[str], set[str]]:
    active = {item["definitionId"] for packet in packets
              for item in packet.get("definitions", [])}
    inactive = {item["definitionId"] for packet in packets
                for item in packet.get("inactiveDefinitions", [])}
    if (not active or active & inactive
            or any(not isinstance(item, str) for item in active | inactive)):
        raise ValueError("AICOMPANIES_CURRENT_RULE_INVENTORY_INVALID")
    return active, inactive


def legacy_rule_replacement(rule_id: str, active_rule_ids: set[str]) -> str | None:
    """Map only the exact reviewed AIcompanies legacy identity families."""
    candidates = []
    if re.fullmatch(r"aic\.apportion\.policy\.[1-9][0-9]*", rule_id):
        candidates.append("aic.apportion.policy")
    if re.fullmatch(r"aic\.rule\.balance-change\.[1-9][0-9]*", rule_id):
        candidates.append("aic.rule.balance-change")
    if re.fullmatch(r"aic\.supp\.seed\.[1-9][0-9]*", rule_id):
        candidates.append("aic.supp.seed")
    if rule_id == "aic.supp.view.1":
        candidates.append("aic.supp.view")
    if re.fullmatch(r"aic\.rule\.[A-Za-z0-9_-]+\.1", rule_id):
        candidates.append(rule_id[:-2])
    matched = sorted(set(candidates) & active_rule_ids)
    if len(matched) > 1:
        raise ValueError("AICOMPANIES_LEGACY_RULE_MAPPING_AMBIGUOUS")
    return matched[0] if matched else None


async def retire_obsolete_compiled_rules(call, scope, *, key_prefix: str,
                                          active_rule_ids: set[str],
                                          inactive_rule_ids: set[str]) -> dict:
    """Physically retire reviewed unresolved rules against exact replacements."""
    current = active_rule_ids | inactive_rule_ids
    if (not active_rule_ids or active_rule_ids & inactive_rule_ids
            or any(not item.startswith("aic.") for item in current)):
        raise ValueError("AICOMPANIES_CURRENT_RULE_INVENTORY_INVALID")
    rows, after, revisions = [], None, None
    for _ in range(10_001):
        arguments = {"limit": 100}
        if after is not None:
            arguments.update(afterRuleId=after,
                expectedMetadataRevision=revisions[0],
                expectedPolicyRevision=revisions[1])
        page = (await call("read_v2_program", {**scope,
            "program": _program("application.rule.list", arguments)}))["result"]
        page_revisions = (page["metadataRevision"], page["policyRevision"])
        if revisions is not None and page_revisions != revisions:
            raise RuntimeError("AICOMPANIES_RULE_CATALOG_CHANGED")
        revisions = page_revisions
        rows.extend(page["rows"])
        after = page["nextAfterRuleId"]
        if after is None:
            break
    else:
        raise RuntimeError("AICOMPANIES_RULE_CATALOG_PAGE_LIMIT")
    by_id = {item["ruleId"]: item for item in rows}
    if len(by_id) != len(rows):
        raise RuntimeError("AICOMPANIES_RULE_CATALOG_DUPLICATE")
    for rule_id in active_rule_ids:
        replacement = by_id.get(rule_id)
        if (replacement is None or replacement.get("status") != "Active"
                or replacement.get("executable") is not True):
            raise ValueError("AICOMPANIES_CURRENT_REPLACEMENT_NOT_ACTIVE")
    for rule_id in inactive_rule_ids:
        retained = by_id.get(rule_id)
        if (retained is None or retained.get("status") != "Inactive"
                or retained.get("executable") is not False):
            raise ValueError("AICOMPANIES_CURRENT_INACTIVE_RULE_INVALID")
    managed_prefixes = ("aic.apportion.", "aic.rule.", "aic.supp.")
    obsolete = []
    for row in rows:
        rule_id = row["ruleId"]
        if rule_id in current or not rule_id.startswith(managed_prefixes):
            continue
        replacement_id = legacy_rule_replacement(rule_id, active_rule_ids)
        if replacement_id is None:
            raise ValueError("AICOMPANIES_LEGACY_RULE_MAPPING_REQUIRED:" + rule_id)
        if (row.get("status") != "Unavailable"
                or row.get("executable") is not False
                or not isinstance(row.get("stateToken"), str)
                or not isinstance(row.get("programDigest"), str)):
            raise ValueError("AICOMPANIES_LEGACY_RULE_NOT_RETIRABLE:" + rule_id)
        obsolete.append((row, by_id[replacement_id]))
    retired = []
    for legacy, replacement in sorted(obsolete,
                                      key=lambda item:item[0]["ruleId"]):
        pins = await state_pins(call, scope)
        arguments = {
            "ruleId": legacy["ruleId"],
            "expectedStateToken": legacy["stateToken"],
            "expectedProgramDigest": legacy["programDigest"],
            "replacementRuleId": replacement["ruleId"],
            "expectedReplacementStateToken": replacement["stateToken"],
            "expectedReplacementProgramDigest": replacement["programDigest"],
            "reason": "superseded_by_current_rule",
            "expectedMetadataRevision": pins["expectedMetadataRevision"],
            "expectedPolicyRevision": pins["expectedPolicyRevision"],
        }
        identity = key_prefix + ".retire-rule." + sha256(
            legacy["ruleId"].encode()).hexdigest()[:24]
        retired.append((await _exact_replay(call,
            "execute_v2_expression_rule_program", {**scope,
                "program": _program("application.rule.retire", arguments),
                "idempotency_key": identity}, identity))["result"])
    return {"before": len(rows), "managedBefore": sum(
        item["ruleId"].startswith(managed_prefixes) for item in rows),
        "retired": len(retired), "retainedCurrentRuleIds": sorted(current),
        "replacementBindings": [{"legacyRuleId": item["ruleId"],
            "replacementRuleId": replacement["ruleId"]}
            for item, replacement in sorted(obsolete,
                key=lambda value:value[0]["ruleId"])]}


def validate_complete_packet_set(packets) -> None:
    formats = [packet.get("format") for packet in packets]
    if (len(formats) != len(REQUIRED_PACKET_FORMATS)
            or set(formats) != REQUIRED_PACKET_FORMATS):
        raise ValueError("AICOMPANIES_COMPLETE_PACKET_SET_REQUIRED")


async def retire_obsolete_business_programs(call, scope, *, key_prefix: str,
                                             current_program_ids: set[str]
                                             ) -> dict:
    """Delete only superseded AIcompanies rule programs, retaining list sources."""
    if not current_program_ids or any(not item.startswith("source-rule-aic.")
                                      for item in current_program_ids):
        raise ValueError("AICOMPANIES_CURRENT_PROGRAM_INVENTORY_INVALID")
    programs = []
    after = None
    for _ in range(10_001):
        arguments = {"limit": 100}
        if after is not None:
            arguments["afterProgramId"] = after
        page = (await call("read_v2_program", {**scope,
            "program": _program("python.program.list", arguments)}))["result"]
        programs.extend(page["programs"])
        after = page["nextAfterProgramId"]
        if after is None:
            break
    else:
        raise RuntimeError("AICOMPANIES_PROGRAM_CATALOG_PAGE_LIMIT")
    legacy_prefixes = ("aic.apportion.", "aic.rule.", "aic.supp.",
                       "aicompanies-allocation-", "aicompanies-source-")
    managed_prefixes = legacy_prefixes + ("source-rule-aic.",)
    managed = [item for item in programs
               if item["programId"].startswith(managed_prefixes)]
    obsolete = [item for item in managed
                if item["programId"] not in current_program_ids]
    retained = [item for item in programs if item not in obsolete]
    deleted = []
    for item in obsolete:
        program_id = item["programId"]
        identity = key_prefix + ".retire." + sha256(
            program_id.encode()).hexdigest()[:24]
        token = item["stateToken"]
        if item["status"] == "Active":
            deactivated = (await _exact_replay(call,
                "execute_v2_python_program_registry", {**scope,
                    "program": _program("python.program.deactivate", {
                        "programId": program_id,
                        "expectedStateToken": token,
                        **await state_pins(call, scope)}),
                    "idempotency_key": identity + ".deactivate"},
                identity + ".deactivate"))["result"]
            token = deactivated["stateToken"]
        deleted.append((await _exact_replay(call,
            "execute_v2_python_program_registry", {**scope,
                "program": _program("python.program.delete", {
                    "programId": program_id,
                    "expectedStateToken": token,
                    **await state_pins(call, scope)}),
                "idempotency_key": identity + ".delete"},
            identity + ".delete"))["result"])
    return {"before": len(programs), "managedBefore": len(managed),
            "retained": len(retained),
            "deleted": len(deleted),
            "retainedCurrentBusinessProgramIds":
                sorted(current_program_ids)}


async def retire_member_list_wrappers(call, scope, *, key_prefix: str,
                                      expected_count: int = 38,
                                      adopt: bool = True) -> dict:
    """Adopt exact native AIcompanies lists and retire their Python wrappers."""
    programs, after = [], None
    for _ in range(10_001):
        arguments = {"limit": 100}
        if after is not None:
            arguments["afterProgramId"] = after
        page = (await call("read_v2_program", {**scope,
            "program": _program("python.program.list", arguments)}))["result"]
        programs.extend(page["programs"])
        after = page["nextAfterProgramId"]
        if after is None:
            break
    else:
        raise RuntimeError("AICOMPANIES_PROGRAM_CATALOG_PAGE_LIMIT")
    wrapper_by_id = {}
    for item in programs:
        declared = item.get("declaredOutput")
        if not (isinstance(declared, dict)
                and declared.get("kind") == "MemberList"):
            continue
        list_id = declared.get("definitionId")
        if (not isinstance(list_id, str) or not list_id.startswith("aic.members.")
                or item["programId"] != list_id):
            raise ValueError("AICOMPANIES_MEMBER_LIST_WRAPPER_IDENTITY_INVALID")
        if list_id in wrapper_by_id:
            raise ValueError("AICOMPANIES_MEMBER_LIST_WRAPPER_IDENTITY_INVALID")
        wrapper_by_id[list_id] = item
    lists, after, collection_token = [], None, None
    for _ in range(10_001):
        arguments = {"limit": 100}
        if after is not None:
            arguments["afterListId"] = after
            arguments["expectedCollectionToken"] = collection_token
        page = (await call("read_v2_program", {**scope,
            "program": _program("metadata.member_list.list", arguments)}))["result"]
        collection_token = page["collectionToken"]
        lists.extend(item for item in page["memberLists"]
                     if item["listId"].startswith("aic.members."))
        after = page["nextAfterListId"]
        if after is None:
            break
    else:
        raise RuntimeError("AICOMPANIES_MEMBER_LIST_CATALOG_PAGE_LIMIT")
    wrappers = []
    for listed in lists:
        list_id = listed["listId"]
        opened = (await call("read_v2_program", {**scope,
            "program": _program("metadata.member_list.read", {
                "listId": list_id})}))["result"]
        source = opened.get("source")
        item = wrapper_by_id.get(list_id)
        status = opened.get("status")
        active = status == "Active"
        if (status not in {"Active", "Inactive"}
                or opened.get("defined") is not True
                or opened.get("sourceCurrent") is not True
                or opened.get("executable") is not active
                or opened.get("dimensionId") !=
                    opened.get("definition", {}).get("dimensionId")
                or not isinstance(opened.get("canonicalDigest"), str)
                or not isinstance(opened.get("stateToken"), str)
                or opened.get("definition", {}).get("parameters") != []):
            raise ValueError("AICOMPANIES_MEMBER_LIST_WRAPPER_NOT_RETIRABLE")
        if source is None:
            if item is not None:
                raise ValueError("AICOMPANIES_MEMBER_LIST_WRAPPER_NOT_RETIRABLE")
        elif (item is None
                or item.get("status") != status
                or opened.get("dimensionId") !=
                    item["declaredOutput"].get("dimensionId")
                or source.get("programId") != item["programId"]
                or source.get("programSourceToken") != item["sourceToken"]
                or source.get("sourceDigest") != item["sourceDigest"]
                or source.get("active") is not active):
            raise ValueError("AICOMPANIES_MEMBER_LIST_WRAPPER_NOT_RETIRABLE")
        expected_members = None
        if active:
            before = (await call("read_v2_program", {**scope,
                "program": _program("metadata.member_list.evaluate", {
                    "listId": list_id, "parameters": {},
                    "expectedMetadataRevision": opened["currentMetadataRevision"]})
                }))["result"]
            expected_members = before["memberIds"]
        wrappers.append((item, opened, expected_members))
    source_ids = {opened["listId"] for item, opened, _ in wrappers
                  if item is not None}
    if (len(wrappers) != expected_count
            or source_ids != set(wrapper_by_id)):
        raise ValueError(
            "AICOMPANIES_MEMBER_LIST_OWNERSHIP_RECONCILIATION_REQUIRED")
    if not adopt:
        return {"before": len(wrappers), "ready": True,
                "sourceOwned": len(source_ids),
                "alreadyAdopted": len(wrappers) - len(source_ids),
                "evaluated": sum(value[2] is not None for value in wrappers),
                "inactiveReady": sum(value[2] is None for value in wrappers)}
    adopted = []
    for item, opened, expected_members in sorted(wrappers,
                                                  key=lambda value:value[1]["listId"]):
        identity = key_prefix + ".adopt-list." + sha256(
            opened["listId"].encode()).hexdigest()[:24]
        result = {"stateToken": opened["stateToken"]}
        if item is not None:
            pins = await state_pins(call, scope)
            arguments = {"listId": opened["listId"],
                "expectedStateToken": opened["stateToken"],
                "expectedCanonicalDigest": opened["canonicalDigest"],
                "sourceProgramId": item["programId"],
                "expectedSourceStateToken": item["stateToken"],
                "expectedSourceToken": item["sourceToken"],
                "expectedSourceDigest": item["sourceDigest"],
                "reason": "native_object_replaces_python_wrapper",
                "expectedMetadataRevision": pins["expectedMetadataRevision"],
                "expectedPolicyRevision": pins["expectedPolicyRevision"]}
            result = (await _exact_replay(call,"execute_v2_metadata_program",
                {**scope,"program":_program(
                    "metadata.member_list.adopt_configuration",arguments),
                 "idempotency_key":identity},identity))["result"]
        if expected_members is None:
            pins = await state_pins(call, scope)
            activation_arguments = {"listId": opened["listId"],
                "expectedStateToken": result["stateToken"],
                "expectedMetadataRevision": pins["expectedMetadataRevision"],
                "expectedPolicyRevision": pins["expectedPolicyRevision"]}
            result = (await _exact_replay(call,"execute_v2_metadata_program",
                {**scope,"program":_program(
                    "metadata.member_list.activate", activation_arguments),
                 "idempotency_key":identity + ".activate"},
                identity + ".activate"))["result"]
        pins = await state_pins(call, scope)
        after = (await call("read_v2_program", {**scope,
            "program": _program("metadata.member_list.evaluate", {
                "listId": opened["listId"], "parameters": {},
                "expectedMetadataRevision": pins["expectedMetadataRevision"]})
            }))["result"]
        if (after.get("canonicalDigest") != opened["canonicalDigest"]
                or expected_members is not None
                and after["memberIds"] != expected_members):
            raise RuntimeError("AICOMPANIES_MEMBER_LIST_ADOPTION_CHANGED_OUTPUT")
        adopted.append({"listId": opened["listId"],
            "memberCount": len(after["memberIds"]),
            "memberIdsDigest": sha256(json.dumps(after["memberIds"],
                ensure_ascii=True,separators=(",", ":")).encode()).hexdigest(),
            "canonicalDigest": opened["canonicalDigest"],
            "sourceAdopted": item is not None,
            "activatedAfterAdoption": expected_members is None,
            "stateToken": result["stateToken"]})
    return {"before": len(wrappers),"adopted":len(adopted),
            "lists":adopted}


async def main_async(args) -> dict:
    sys.path.insert(0, str(args.bridge_runtime))
    from session_local import invoke
    call = AdmittedMCPCall(invoke, args.identity_prefix)

    scope = {"workspace_id": args.workspace_id,
             "application_id": args.application_id}
    packets = [load_packet(path) for path in args.packet]
    validate_complete_packet_set(packets)
    current_program_ids = current_business_program_ids(packets)
    active_rule_ids, inactive_rule_ids = current_business_rule_ids(packets)
    if args.retire_obsolete:
        # Retirement must be possible before reconstruction changes any current
        # rule, relation or environment.  Populated migrations can expose an
        # unresolved native-list/source association that requires a software
        # migration, never a partially completed business cutover.
        await retire_member_list_wrappers(
            call, scope, key_prefix=args.identity_prefix, adopt=False)
    current = (await call("read_v2_program", {**scope,
        "program": _program("python.environment.read", {
            "environmentId": args.environment_id})}))["result"]
    profiles = (await call("read_v2_program", {**scope,
        "program": _program("python.environment.profile.list", {})}))["result"]
    profile = next((item for item in profiles["profiles"]
                    if item["profileId"] == args.profile_id), None)
    if profile is None:
        raise RuntimeError("APPROVED_PROFILE_NOT_AVAILABLE")
    if (not current.get("defined")
            or current["environment"]["image_digest"] != profile["imageDigest"]):
        pins = await state_pins(call, scope)
        register = {"environmentId": args.environment_id,
                    "profileId": args.profile_id, **pins}
        if current.get("defined"):
            register["expectedStateToken"] = current["environment"]["state_token"]
        await call("execute_v2_python_program_registry", {**scope,
            "program": _program("python.environment.register", register),
            "idempotency_key": args.identity_prefix + ".environment"})

    os.environ["EPM_SAMPLE_PYTHON_PROFILE_ID"] = args.profile_id
    result = await reconstruct_rule_packets(
        call, scope, packets, key_prefix=args.identity_prefix)
    retirement = None
    if args.retire_obsolete:
        rules = await retire_obsolete_compiled_rules(
            call, scope, key_prefix=args.identity_prefix,
            active_rule_ids=active_rule_ids,
            inactive_rule_ids=inactive_rule_ids)
        lists = await retire_member_list_wrappers(
            call, scope, key_prefix=args.identity_prefix)
        programs = await retire_obsolete_business_programs(
            call, scope, key_prefix=args.identity_prefix,
            current_program_ids=current_program_ids)
        retirement = {"compiledRules": rules, "memberListWrappers": lists,
            "sourcePrograms": programs}
    final_environment = (await call("read_v2_program", {**scope,
        "program": _program("python.environment.read", {
            "environmentId": args.environment_id})}))["result"]["environment"]
    return {"environmentImageDigest": final_environment["image_digest"],
            "environmentStatus": final_environment["status"], **result,
            **({"retirement": retirement} if retirement is not None else {})}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge-runtime", type=Path, required=True)
    parser.add_argument("--packet", type=Path, action="append", required=True,
                        help="Repeat once for each complete rule-family packet")
    parser.add_argument("--workspace-id", default="ws-pilot")
    parser.add_argument("--application-id", default="AIcompanies")
    parser.add_argument("--environment-id", default="service-switch-only")
    parser.add_argument("--profile-id", default="service-switch-only:v4")
    parser.add_argument("--identity-prefix", required=True)
    parser.add_argument("--retire-obsolete", action="store_true")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(main_async(args)), sort_keys=True,
                     default=str))


if __name__ == "__main__":
    main()
