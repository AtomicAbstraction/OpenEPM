"""Comparison of old and proposed access gates on one application incarnation."""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json

from .application_authorization_actions import (
    ACTION_SCOPE_KINDS,
    APPLICATION_ENTRY,
    action_allows_operation,
)
from .metadata_read_contract import read_contract, read_example
from .postgres_access import _PERMISSION_RANK, _ROLE_RANK, _RULE_COLUMNS
from .postgres_numeric_catalog import obj

REVIEW = "security.workspace.authorization-migration.review"
ACTIVATE = "security.workspace.authorization-migration.activate"
FUNCTIONS = (REVIEW, ACTIVATE)
MODES = ("legacy", "group_assignments")
DISPOSITION_LIMIT = 300
INVALID = "AUTHORIZATION_MIGRATION_ARGUMENTS_INVALID"


def digest(value):
    return sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def catalog():
    text = {"type": "string", "minLength": 1}
    hashed = {**text, "pattern": "^[0-9a-f]{64}$"}
    ident = {**text, "maxLength": 200}
    text_list = {"type": "array", "items": text}
    mode = {"enum": list(MODES)}
    optional_digest = {"anyOf": [hashed, {"type": "null"}]}
    args = {"applicationId": ident, "targetMode": mode}
    example = {"applicationId": "example-application", "targetMode": "group_assignments"}
    legacy_receipts = obj({"scope":{"const":"application_operations"},
                           "includesDecisionReceipts":{"type":"boolean"}})
    receipt_visibility = {"oneOf":[obj({"scope":{"const":"unavailable"}}),legacy_receipts,
        obj({"scope":{"const":"matching_issuer_and_subject_policy_operations"},
             "currentlyAuthorizedFunctions":text_list})]}
    result = {
        "workspaceId": ident,
        "applicationId": ident,
        "incarnation": text,
        "sourceMode": mode,
        "targetMode": mode,
        "revision": {"type": "integer", "minimum": 0},
        "blockers": text_list,
        "reviewDigest": optional_digest,
        "requiredDispositions": {"type": "array", "items": hashed, "uniqueItems": True},
        "origins": {"type": "array", "items": {"type": "object",
                    "properties":{"legacyReceiptVisibility":legacy_receipts}}},
        "people": {"type": "array", "items": {"type": "object","properties":{
            "receiptVisibilityChange":obj({"source":receipt_visibility,"target":receipt_visibility})}}},
        "programSets": {"type": "object", "additionalProperties": text_list},
        "policyDisposition": text,
        "changed": {"type": "boolean"},
    }
    specs = {}
    for name in FUNCTIONS:
        write = name == ACTIVATE
        actual = obj(
            {
                **args,
                "reviewDigest": hashed,
                "acceptedDispositions": {
                    "type": "array",
                    "maxItems": DISPOSITION_LIMIT,
                    "uniqueItems": True,
                    "items": hashed,
                },
            }
            if write
            else args
        )
        wire = {
            **example,
            **({"reviewDigest": "0" * 64, "acceptedDispositions": []} if write else {}),
        }
        specs[name] = {
            "mode": "atomic_security_write" if write else "read",
            "permission": "workspace_admin",
            "idempotencyRequired": write,
            **({"idempotencyScope": "workspace security-operation namespace, bound to the exact application incarnation, actor and reviewed program"} if write else {}),
            "previewRequired": write,
            "workClass": "short",
            "arguments": list(actual["properties"]),
            "result": "Application-scoped reviewed authorization comparison"
            if not write
            else "Retained authorization transition receipt",
            **read_contract(
                name,
                actual,
                obj(
                    {**result, "outstandingWorkFamilies": text_list,
                     "planningWriteChange": obj({"effect": {"const": "planning_writes_closed_until_scoped_duties_are_linked"},
                                                 "dispositionId": hashed}),
                     **({"postAuthorityDigest": hashed} if write else {})},
                    [*result, "postAuthorityDigest" if write else "outstandingWorkFamilies"],
                ),
                owner="ApplicationAuthorizationMigration",
                examples=[
                    read_example(
                        name,
                        wire,
                        name="Review one application authorization transition",
                        binding="Use the selected workspace and application, then copy the exact current review and approved difference IDs.",
                    )
                ],
                semantic_rules=[
                    "The required dispositions name individually reviewed changes in program, admission and scoped authority.",
                    "With an active named planning policy and no linked grants, the forward review explicitly identifies the interruption in planning writes. Include its disposition only after review. A transition with unproved existing duty equivalence is blocked.",
                    "Settle a pending replacement in the current application before changing authorization mode. Activate it, or explicitly deactivate the current policy to retain the replacement as Saved, then request a new review.",
                    "Each affected person's disposition includes operation receipt visibility. Legacy readers can inspect ordinary receipts across actors, and administrators can also inspect decision receipts. A group policy manager can inspect their own issuer-qualified policy receipts for operations they still hold.",
                    "Unresolved or oversized evidence prevents switching. Existing receipts record history only.",
                    "Reverse transition requires a matching prior activation, no intervening authority changes and no expansion.",
                ],
            ),
        }
    return specs


def compile_program(p):
    if (
        not isinstance(p, dict)
        or set(p) != {"languageVersion", "function", "arguments"}
        or type(p["languageVersion"]) is not int
        or p["languageVersion"] != 2
        or p["function"] not in FUNCTIONS
        or not isinstance(p["arguments"], dict)
    ):
        raise ValueError(INVALID)
    a = p["arguments"]
    write = p["function"] == ACTIVATE
    if set(a) != (
        {"applicationId", "targetMode", "reviewDigest", "acceptedDispositions"}
        if write
        else {"applicationId", "targetMode"}
    ):
        raise ValueError(INVALID)
    application = a["applicationId"]
    if (
        not isinstance(application, str)
        or not 1 <= len(application) <= 200
        or application != application.strip()
        or any(ord(c) < 32 for c in application)
        or a["targetMode"] not in MODES
    ):
        raise ValueError(INVALID)
    if write:

        def valid_hash(s):
            return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)

        ids = a["acceptedDispositions"]
        if (
            not valid_hash(a["reviewDigest"])
            or not isinstance(ids, list)
            or len(ids) > DISPOSITION_LIMIT
            or not all(valid_hash(s) for s in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError(INVALID)
    return a


def _legacy_permissions(origins):
    role = max((_ROLE_RANK[o["role"]] for o in origins if "role" in o), default=0)
    ws = any(o["kind"].startswith("workspace_") for o in origins)
    return {
        perm
        for perm, level in _PERMISSION_RANK.items()
        if role >= level
        and (perm != "workspace_admin" or ws)
        and (
            perm not in _RULE_COLUMNS
            or role == 3
            or any(any(o.get(key) for key in _RULE_COLUMNS[perm]) for o in origins)
        )
    }


def _legacy_tags(origins):
    result = {}
    for field in ("readTags", "writeTags"):
        combined = defaultdict(set)
        for origin in origins:
            for axis, tags in origin.get(field, {}).items():
                combined[axis].update(tags)
        result[field] = {axis: sorted(tags) for axis, tags in sorted(combined.items())}
    return result


_LEGACY_DUTIES = {
    APPLICATION_ENTRY: {"read"}, "access.review": {"admin"},
    "access.manage": {"workspace_admin"}, "roles.manage": {"workspace_admin"},
    "facts.read": {"read"}, "facts.write": {"write"}, "metadata.browse": {"read"},
    "facts.import": {"write"}, "facts.export": {"read"},
    "planning.policy.draft": {"admin"}, "planning.policy.activate": {"admin"},
    "metadata.structure.create": {"admin"}, "metadata.structure.edit": {"admin"}, "metadata.classify": {"admin"},
    "views.read": {"read"}, "views.run": {"read"}, "views.save": {"write"}, "views.delete": {"write"},
    "rules.inspect": {"read"},
    # The new designer may also inspect eligible environments and the result
    # of their own automatic validation. Legacy environment discovery is admin-only.
    "rules.design": {"rule_design", "rule_validate", "admin"},
    "rules.test": {"rule_design", "read", "write"},
    "rules.publish": {"rule_publish", "write"},
    "rules.run": {"rule_run", "read", "write"},
}


def _resource_change(resource, *, permitted, possible, legacy_tags, old_policy, blockers):
    action = resource["action"]
    delegated = action.startswith("delegate.")
    required = {"admin"} if delegated else _LEGACY_DUTIES.get(action)
    if required is None:
        blockers.add("NEW_ACTION_SEMANTICS_REQUIRE_MIGRATION_REVIEW")
        return "action_semantics_unproven"
    if not required <= permitted:
        if (required - permitted) & possible:
            blockers.add("LEGACY_SIGNED_GROUP_AUTHORITY_UNPROVEN")
            return "legacy_permission_depends_on_other_signed_groups"
        return "gained_delegation" if delegated else "gained_scoped_action"
    if delegated:
        return "changed_delegation"
    if action.startswith("views.") and old_policy:
        blockers.add("SAVED_OBJECT_EQUIVALENCE_UNPROVEN")
        return "object_scope_unproven"
    if action == "metadata.classify" and old_policy:
        # An old administrator could update a classification but could read a tag
        # directory only after resolving a visible dimension. A new classifier
        # can discover its catalogue before the dimension has tags.
        blockers.add("CLASSIFICATION_CATALOGUE_VISIBILITY_UNPROVEN")
        return "classification_catalogue_visibility_unproven"
    if not old_policy or action not in ("facts.read", "facts.write", "metadata.browse"):
        return "restricted_to_reviewed_target_scope"
    # Legacy coordinates and single metadata references resolve the union of
    # the subject's direct grants and signed, current group grants. A target
    # binding proves only its own group was in this session. With a compatible
    # every-protected policy, any/all tag matches inside this guaranteed source
    # map are contained. All target facts.read witnesses are checked separately.
    source = legacy_tags["writeTags" if action == "facts.write" else "readTags"]
    selector = resource["selector"]
    if resource["scopeKind"] == "dimension_tags" and selector and all(
        tags and set(tags) <= set(source.get(axis, ())) for axis, tags in selector.items()
    ):
        return "restricted_to_complete_assignment_within_legacy_tags"
    blockers.add("DIMENSIONAL_EQUIVALENCE_UNPROVEN")
    return "dimensional_scope_unproven"


def compare(issuer, origins, functions, *, reverse, old_policy, blockers, changing_model=True):
    """Classify admission, public permission gates and scoped authority separately.

    These program sets express security gates. Definition existence, input
    validation and business constraints are not predicted for imaginary calls.
    """
    from .postgres_operation_receipts import READ as read_receipt
    from .postgres_planning_workflow_policy import SAVE, ACTIVATE as publish_policy, DEACTIVATE

    compare_receipts = changing_model and read_receipt in functions
    people = defaultdict(list)
    inventory = []
    for origin in origins:
        if origin["issuer"] != issuer:
            blockers.add("OTHER_AUTHORITY_ISSUER")
            continue
        members = origin["members"]
        record = {k: v for k, v in origin.items() if k not in ("issuer", "members")}
        reference = digest(
            [origin["kind"], origin["subjectId"], origin["groupId"], origin.get("assignmentId")]
        )
        record["originId"] = reference
        record["activeMembers"] = [m["subjectId"] for m in members if m["status"] == "Active"]
        if compare_receipts and origin.get("role") in _ROLE_RANK:
            # An active group with no current members still carries a grant
            # for its next member. Its origin disposition names this scope.
            record["legacyReceiptVisibility"] = {"scope":"application_operations",
                "includesDecisionReceipts":origin["role"]=="Administrator"}
            if reverse and origin["directoryStatus"] == "Active":
                blockers.add("REVERSAL_EXPANDS_OPERATION_RECEIPT_VISIBILITY")
        inventory.append(record)
        if len(members) > 100 or len(origins) > 200:
            blockers.add("INVENTORY_BOUND_EXCEEDED")
        if not origin["identityResolved"] or any(not m["resolved"] for m in members):
            blockers.add("UNRESOLVED_DIRECTORY_ORIGIN")
        if origin["kind"] == "assignment" and any(
            p["action"] not in origin["actions"]
            or p["scopeKind"] not in ACTION_SCOPE_KINDS.get(p["action"], ())
            for p in origin["privileges"]
        ):
            blockers.add("UNRESOLVED_ASSIGNMENT_ACTION_OR_SCOPE")
        if origin["directoryStatus"] == "Active":
            subjects = (
                [origin["subjectId"]]
                if origin["subjectId"] is not None
                else record["activeMembers"]
            )
            for subject in subjects:
                people[subject].append(record)
    program_sets = {}

    def program_set(operations):
        names = sorted(operations)
        key = digest(names)
        program_sets[key] = names
        return key

    changes = []
    # A grant to an empty or currently inactive group can still change future
    # access. Its origin needs a disposition even when no person appears today.
    required = []
    for origin in inventory:
        origin["dispositionId"] = digest(["origin", origin])
        required.append(origin["dispositionId"])
    if len(people) > DISPOSITION_LIMIT:
        blockers.add("INVENTORY_BOUND_EXCEEDED")
    for subject, rows in sorted(people.items())[:DISPOSITION_LIMIT]:
        legacy = [r for r in rows if r["kind"] != "assignment"]
        assigned = [r for r in rows if r["kind"] == "assignment"]
        perms = _legacy_permissions(legacy)
        actions = {
            p["action"]
            for r in assigned
            for p in r["privileges"]
            if p["action"] in r["actions"]
            and p["scopeKind"] in ACTION_SCOPE_KINDS.get(p["action"], ())
        }
        entered = APPLICATION_ENTRY in actions
        authorized = actions if entered else set()
        if any(a.removeprefix("delegate.") not in _LEGACY_DUTIES for a in actions):
            blockers.add("NEW_ACTION_SEMANTICS_REQUIRE_MIGRATION_REVIEW")
        old_programs = {name for name, permission in functions.items() if permission in perms}
        new_programs = {name for name in functions if action_allows_operation(authorized, name)}
        # Config management requires workspace authority when staging the legacy model.
        if "workspace_admin" not in perms:
            old_programs.difference_update(
                (
                    "security.application.authorization.read",
                    "security.application.authorization.preview",
                    "security.application.authorization.apply",
                )
            )
        resources = [
            {
                "originId": r["originId"],
                "groupId": r["groupId"],
                "action": p["action"],
                "scopeId": p["scopeId"],
                "scopeKind": p["scopeKind"],
                "selector": p["selector"],
            }
            for r in assigned
            for p in r["privileges"]
            if p["action"] in authorized
        ]
        # Legacy resolution unions per-axis tags from all of the subject's
        # application grants. Record the source sets as well as the target
        # clauses so crossed grants and loss of complement combinations can
        # be reviewed explicitly without disclosing a single financial cell.
        old_tags = _legacy_tags(legacy)
        guaranteed = {}
        for group in {item["groupId"] for item in resources}:
            origins_in_every_matching_session = [r for r in legacy if r["groupId"] in (None, group)]
            guaranteed[group] = (_legacy_permissions(origins_in_every_matching_session),
                                 _legacy_tags(origins_in_every_matching_session))
        resource_changes = []
        for resource in resources:
            permitted, tags = guaranteed[resource["groupId"]]
            change = _resource_change(resource, permitted=permitted, possible=perms, legacy_tags=tags,
                                      old_policy=old_policy, blockers=blockers)
            resource_changes.append({**resource, "comparison": change})
        before, after = (new_programs, old_programs) if reverse else (old_programs, new_programs)
        lost, gained = before - after, after - before
        prior_entry, current_entry = (entered, bool(perms)) if reverse else (bool(perms), entered)
        row = {
            "subjectId": subject,
            "legacyOriginIds": sorted(r["originId"] for r in legacy),
            "assignmentOriginIds": sorted(r["originId"] for r in assigned),
            "sourceEntered": prior_entry,
            "targetEntered": current_entry,
            "lostPrograms": program_set(lost),
            "gainedPrograms": program_set(gained),
            "retainedPrograms": program_set(after & before),
            "legacyDimensionTags": old_tags,
            "assignmentScopes": resource_changes,
        }
        if compare_receipts and read_receipt in (before | after):
            unavailable = {"scope":"unavailable"}
            legacy_receipts = ({"scope":"application_operations","includesDecisionReceipts":"admin" in perms}
                               if read_receipt in old_programs else unavailable)
            group_receipts = ({"scope":"matching_issuer_and_subject_policy_operations",
                               "currentlyAuthorizedFunctions":sorted(function for function in (SAVE,publish_policy,DEACTIVATE)
                                   if action_allows_operation(authorized,function))}
                              if read_receipt in new_programs else unavailable)
            row["receiptVisibilityChange"] = {"source":group_receipts if reverse else legacy_receipts,
                                              "target":legacy_receipts if reverse else group_receipts}
        changed = bool(lost or gained or prior_entry != current_entry or legacy or assigned)
        row["dispositionId"] = digest(row) if changed else None
        if changed:
            required.append(row["dispositionId"])
        if reverse and (gained or (current_entry and not prior_entry) or resource_changes):
            blockers.add("REVERSAL_MAY_RESTORE_REMOVED_ACCESS")
        changes.append(row)
    if len(required) > DISPOSITION_LIMIT:
        blockers.add("INVENTORY_BOUND_EXCEEDED")
    return {
        "origins": inventory,
        "people": changes,
        "programSets": program_sets,
        "requiredDispositions": required,
    }
