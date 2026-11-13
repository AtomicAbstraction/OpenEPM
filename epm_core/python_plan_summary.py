"""Bounded static explanation of one already validated authored plan."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json


FORMAT = "openepm-python-plan-summary-v1"
MAX_DIAGNOSTICS = 100


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def require_no_static_errors(summary: object) -> None:
    """Reject a structurally invalid authored plan using its repair code."""
    if not isinstance(summary, dict) or not isinstance(
            summary.get("diagnostics"), list):
        raise ValueError("PYTHON_PLAN_SUMMARY_INVALID")
    errors = [item.get("code") for item in summary["diagnostics"]
              if isinstance(item, dict) and item.get("severity") == "error"]
    if errors:
        raise ValueError(errors[0])


def _walk(value: object):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _effective_operations(plan: dict):
    """Yield authored business statements, looking through definition saves."""
    for unit_index, unit in enumerate(plan["units"]):
        for operation_index, operation in enumerate(unit["operations"]):
            path = f"/units/{unit_index}/operations/{operation_index}"
            definition = operation.get("arguments", {}).get("definition")
            if (operation.get("function") == "application.rule.save"
                    and isinstance(definition, dict)
                    and definition.get("format") == "openepm-application-rule-v1"
                    and isinstance(definition.get("units"), list)):
                for nested_unit_index, nested_unit in enumerate(definition["units"]):
                    for nested_operation_index, nested in enumerate(
                            nested_unit.get("operations", ())):
                        nested_path = (path + "/arguments/definition/units/" +
                            str(nested_unit_index) + "/operations/" +
                            str(nested_operation_index))
                        yield nested, nested_path, path
            else:
                yield operation, path, path


def static_plan_summary(plan: dict, source_map: dict, *,
                        plan_digest: str, source_digest: str) -> dict:
    """Describe shape/cost signals without reading facts or resolving selectors."""
    locations = {entry["path"]: entry["span"]
                 for entry in source_map.get("entries", ())}
    functions: Counter[str] = Counter()
    selectors: Counter[str] = Counter()
    explicit_members = 0
    diagnostics = []
    diagnostic_count = 0
    def diagnose(value):
        nonlocal diagnostic_count
        diagnostic_count += 1
        if len(diagnostics) < MAX_DIAGNOSTICS:
            diagnostics.append(value)
    units = plan["units"]
    envelope_functions = Counter(operation["function"] for unit in units
        for operation in unit["operations"])
    effective = list(_effective_operations(plan))
    scalar_expressions = []
    singleton_writes = []
    for operation, path, source_path in effective:
        functions[operation["function"]] += 1
        operation_explicit = 0
        for node in _walk(operation["arguments"]):
            kind = node.get("kind")
            if isinstance(kind, str) and kind in {
                    "Members", "Children", "Descendants", "Leaves",
                    "Ancestors", "Siblings", "member", "member_list",
                    "attribute", "hierarchy", "inline_expression"}:
                selectors[kind] += 1
            member_ids = node.get("memberIds")
            if isinstance(member_ids, list):
                operation_explicit += len(member_ids)
        explicit_members += operation_explicit
        if operation["function"] == "facts.expression.calculate":
            arguments = operation["arguments"]
            if ("sourceMembers" in arguments
                    and not any(key in arguments for key in (
                        "selectedDomain", "sourceMemberSets", "sourceDomain"))):
                scalar_expressions.append((path, source_path))
        if operation["function"] in {"facts.numeric.batch", "facts.text.batch"}:
            mutations = operation["arguments"].get("mutations")
            if isinstance(mutations, list) and len(mutations) == 1:
                singleton_writes.append((path, source_path))
        if operation_explicit >= 16:
            diagnostic = {
                "severity": "warning",
                "code": "STATIC_REPEATED_EXPLICIT_MEMBERS",
                "message": ("This operation contains at least 16 explicit member "
                            "references; consider a hierarchy, attribute, or "
                            "current member-list selector."),
                "path": path,
            }
            if source_path in locations:
                diagnostic["span"] = locations[source_path]
            diagnose(diagnostic)
    for candidates, code, message in (
            (scalar_expressions, "STATIC_SCALAR_CALCULATION_FRAGMENTATION",
             "This rule expands at least 16 scalar calculations; express the business scope with hierarchy, attribute, member-list or sparse-relation primitives and let the server partition execution."),
            (singleton_writes, "STATIC_CLIENT_WORK_PARTITIONING",
             "This rule contains at least 16 one-cell write batches; clients submit business intent and the server owns calculation work partitioning.")):
        if len(candidates) >= 16:
            path, source_path = candidates[0]
            diagnostic = {"severity": "error", "code": code,
                          "message": message, "path": path,
                          "statementCount": len(candidates)}
            if source_path in locations:
                diagnostic["span"] = locations[source_path]
            diagnose(diagnostic)
    result = {
        "format": FORMAT,
        "planDigest": plan_digest,
        "sourceDigest": source_digest,
        "unitCount": len(units),
        "operationCount": len(effective),
        "envelopeOperationCount": sum(envelope_functions.values()),
        "functionCounts": dict(sorted(functions.items())),
        "envelopeFunctionCounts": dict(sorted(envelope_functions.items())),
        "selectionSummary": {
            "selectorCounts": dict(sorted(selectors.items())),
            "explicitMemberReferenceCount": explicit_members,
        },
        "diagnostics": diagnostics,
        "diagnosticsTruncated": diagnostic_count > len(diagnostics),
        "evaluation": "static_no_fact_scan",
    }
    return {**result, "summaryDigest": sha256(_canonical(result)).hexdigest()}
