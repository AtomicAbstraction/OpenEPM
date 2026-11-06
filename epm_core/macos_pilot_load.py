"""Fail-closed mixed-user load harness for the owner-operated Mac pilot.

The harness drives only authenticated public MCP tools.  It deliberately has no
database adapter or setup shortcut: applications, grants and workload programs
must already exist through normal product workflows.
"""
from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import statistics
import time
from typing import Any, Protocol
from urllib.parse import urlparse


class PilotLoadError(ValueError):
    pass


REQUIRED_ROLES = frozenset((
    "humanRead", "agentRead", "write", "calculation", "import",
    "forecast", "task", "retry", "cancel", "revocation", "isolation",
    "invariant",
))
STEADY_ROLES = REQUIRED_ROLES.difference({"revocation", "isolation",
                                          "invariant"})
AGENT_ROLES = ("agentRead", "write", "calculation", "import", "forecast",
               "task", "retry", "cancel")
HUMAN_ROLES = ("humanRead", "task")
ALLOWED_TOOLS = frozenset((
    "list_v2_functions", "read_v2_program",
    "execute_v2_generic_fact_program", "preview_v2_program",
    "submit_v2_program",
    "execute_v2_source_program", "execute_v2_forecast_occurrence_control", "list_v2_tasks",
    "set_v2_application_access",
))
ROLE_PROFILES = {
    "humanRead": ("read_v2_program", "facts.generic.value.read"),
    "agentRead": ("read_v2_program", "facts.generic.value.read"),
    "write": ("execute_v2_generic_fact_program", "facts.generic.value.set"),
    "retry": ("execute_v2_generic_fact_program", "facts.generic.value.set"),
    "calculation": ("submit_v2_program", "facts.planning."),
    "import": ("execute_v2_source_program", "facts.source."),
    "forecast": ("execute_v2_forecast_occurrence_control",
                 "facts.planning.forecast.occurrence."),
    "task": ("list_v2_tasks", None),
    "cancel": ("read_v2_program", "facts.cube.aggregate."),
    "invariant": ("read_v2_program", "facts.generic.value.read"),
}
FORBIDDEN_KEYS = re.compile(r"(?:^|_)(?:dsn|sql|password|database_url)(?:$|_)", re.I)


def _standard_action(tool: str, function: str | None, *,
                     expected: str | None = None,
                     capture: str | None = None,
                     receipt: bool = False,
                     denied: str | None = None) -> dict:
    """Build one fixed public-MCP action used by the adopted pilot profile."""
    arguments: dict[str, Any] = {"workspace_id": "{workspaceId}",
                                 "application_id": "{applicationId}"}
    if function is not None:
        program_arguments: dict[str, Any] = {"requestId": "{requestId}"}
        if function == "facts.generic.value.read":
            program_arguments = {"tableId": "{genericTableId}",
                                 "seriesKey": "{readerSeriesKey}"}
            expected = "{readerExpectation}" if expected is None else expected
        elif function == "facts.generic.value.set":
            write_value = "{writerExpectation}:{requestId}"
            program_arguments = {"tableId": "{genericTableId}",
                "seriesKey": write_value, "value": write_value,
                "expectedChangeId": "", "expectedDataRevision": (
                    0 if denied else "{currentDataRevision}")}
            expected = write_value if expected is None else expected
        arguments["program"] = {"languageVersion": 2, "function": function,
                                "arguments": program_arguments}
    expected = "ok" if expected is None else expected
    result_path = (["result", "value"] if function in {
        "facts.generic.value.read", "facts.generic.value.set"} else ["value"])
    return {"tool": tool, "arguments": arguments,
            "expectPath": None if denied else result_path,
            "expectTemplate": None if denied else expected,
            "captureAs": capture,
            "capturePath": [capture] if capture else None,
            "receiptPath": (["result", "changeId"] if receipt else None),
            "deniedContains": denied}


def build_standard_workload(source: dict[str, str], target_dimension: str,
                            target_members: list[str],
                            aggregate_dimensions: list[str]) -> dict:
    """Return the single reviewed workload contract for a real pilot model.

    Application-specific coordinates and layout are explicit inputs.  The
    request lifecycle, retry identity, captures and denial probes remain fixed
    here so an operator cannot accidentally assemble a fixture-only profile.
    The returned value is still validated by :class:`MacPilotLoadContract`.
    """
    if (not isinstance(source, dict) or not source
            or not all(isinstance(axis, str) and axis
                       and isinstance(member, str) and member
                       for axis, member in source.items())
            or not isinstance(target_dimension, str)
            or target_dimension not in source
            or not isinstance(target_members, list) or not target_members
            or len(target_members) != len(set(target_members))
            or any(not isinstance(member, str) or not member
                   for member in target_members)
            or source[target_dimension] in target_members
            or not isinstance(aggregate_dimensions, list)
            or not aggregate_dimensions
            or len(aggregate_dimensions) != len(set(aggregate_dimensions))
            or any(not isinstance(axis, str) or not axis
                   for axis in aggregate_dimensions)):
        _fail("standard workload model bindings are invalid")

    workload = {
        "humanRead": [_standard_action(
            "read_v2_program", "facts.generic.value.read")],
        "agentRead": [_standard_action(
            "read_v2_program", "facts.generic.value.read")],
        "write": [_standard_action("execute_v2_generic_fact_program",
                                   "facts.generic.value.set", receipt=True)],
        "calculation": [
            _standard_action("preview_v2_program",
                             "facts.planning.spread.equal",
                             expected="facts.planning.spread.equal",
                             capture="previewToken"),
            _standard_action("submit_v2_program",
                             "facts.planning.spread.equal",
                             expected="False", capture="jobId")],
        "import": [
            _standard_action("execute_v2_source_program",
                             "facts.source.begin", capture="batchId"),
            _standard_action("execute_v2_source_program",
                             "facts.source.append", capture="contentDigest"),
            _standard_action("execute_v2_source_program",
                             "facts.source.seal"),
            _standard_action("execute_v2_source_program",
                             "facts.source.preview", capture="previewToken"),
            _standard_action("execute_v2_source_program",
                             "facts.source.publish")],
        "forecast": [_standard_action(
            "execute_v2_forecast_occurrence_control",
            "facts.planning.forecast.occurrence.request",
            capture="occurrenceId")],
        "task": [_standard_action("list_v2_tasks", None,
                                  expected="$type:list")],
        "retry": [_standard_action("execute_v2_generic_fact_program",
                                   "facts.generic.value.set", receipt=True)],
        "cancel": [
            _standard_action("read_v2_program",
                             "facts.cube.aggregate.request",
                             capture="queryId"),
            _standard_action("read_v2_program",
                             "facts.cube.aggregate.cancel"),
            _standard_action("read_v2_program",
                             "facts.cube.aggregate.read",
                             expected="cancelled")],
        "revocation": [
            _standard_action("read_v2_program", "facts.generic.value.read"),
            _standard_action("set_v2_application_access",
                             "security.application.access.set",
                             expected="security.application.access.set"),
            _standard_action("read_v2_program", "facts.generic.value.read",
                             denied="APPLICATION_GRANT_REQUIRED"),
            _standard_action("set_v2_application_access",
                             "security.application.access.set",
                             expected="security.application.access.set"),
            _standard_action("read_v2_program", "facts.generic.value.read")],
        "isolation": [
            _standard_action("read_v2_program", "facts.generic.value.read",
                             denied="APPLICATION_GRANT_REQUIRED"),
            _standard_action("execute_v2_generic_fact_program",
                             "facts.generic.value.set",
                             denied="APPLICATION_GRANT_REQUIRED"),
            _standard_action("submit_v2_program",
                             "facts.planning.spread.equal",
                             denied="APPLICATION_GRANT_REQUIRED")],
        "invariant": [_standard_action(
            "read_v2_program", "facts.generic.value.read")],
    }
    for role in ("write", "retry"):
        workload[role][0]["arguments"]["idempotency_key"] = "{requestId}"

    spread = {"source": dict(source), "targetDimension": target_dimension,
              "targetMembers": list(target_members),
              "resultKey": "pilot.spread.{requestId}"}
    for action in workload["calculation"]:
        action["arguments"]["program"]["arguments"] = spread
    workload["calculation"][0].update(expectPath=["function"])
    workload["calculation"][1].update(expectPath=["duplicate"])
    workload["calculation"][1]["arguments"].update(
        preview_token="{previewToken}", idempotency_key="{requestId}",
        depends_on_job_ids=[])
    isolated_calculation = workload["isolation"][2]
    isolated_calculation["arguments"]["program"]["arguments"] = spread
    isolated_calculation["arguments"].update(
        preview_token="denied-preview-token", idempotency_key="{requestId}",
        depends_on_job_ids=[])

    workload["task"][0]["arguments"].update(after_sequence=0, limit=100)
    workload["task"][0].update(expectPath=["tasks"])
    for action, effect, role, suffix in (
            (workload["revocation"][1], "revoke", None, "revoke"),
            (workload["revocation"][3], "grant", "Editor", "restore")):
        action["arguments"]["program"]["arguments"] = {
            "subjectId": "{targetSubject}", "action": effect, "role": role}
        action["arguments"]["idempotency_key"] = "{requestId}:" + suffix
        action.update(expectPath=["function"])

    source_arguments = [
        {"idempotencyKey": "{requestId}", "mode": "merge",
         "scopeMembers": {}, "scopeAll": True,
         "expectedMetadataRevision": "{currentMetadataRevision}",
         "expectedDataRevision": "{currentDataRevision}"},
        {"batchId": "{batchId}", "chunkIndex": 0,
         "rows": ["{importRow}"]},
        {"batchId": "{batchId}", "expectedRows": 1,
         "expectedContentDigest": "{contentDigest}"},
        {"batchId": "{batchId}"},
        {"batchId": "{batchId}", "previewToken": "{previewToken}"},
    ]
    capture_paths = [["result", "batchId"], ["result", "contentDigest"],
                     None, ["result", "previewToken"], None]
    for action, arguments, capture_path in zip(
            workload["import"], source_arguments, capture_paths, strict=True):
        function = action["arguments"]["program"]["function"]
        action["arguments"]["program"]["arguments"] = arguments
        action.update(expectPath=["function"], expectTemplate=function,
                      capturePath=capture_path)

    forecast = workload["forecast"][0]
    forecast["arguments"]["program"]["arguments"] = {
        "definitionId": "{forecastDefinitionId}",
        "dueAt": "{forecastDueAt}",
        "actualClosedThrough": "{forecastActualClosedThrough}",
        "delegationId": "{forecastDelegationId}",
        "delegationVersion": "{forecastDelegationVersion}"}
    forecast.update(expectPath=["result", "status"], expectTemplate="ready",
                    captureAs="occurrenceId",
                    capturePath=["result", "occurrenceId"])

    request, cancel, read = workload["cancel"]
    request["arguments"]["program"]["arguments"] = {
        "query": {"source": "raw_numeric",
            "grain": {"inputDimensions": list(aggregate_dimensions),
                      "groupBy": list(aggregate_dimensions),
                      "reduceDimensions": []},
            "selectors": {}, "measures": [{"kind": "CountPresent"}],
            "missing": "exclude",
            "aggregation": "unique_coordinate_reduction"},
        "limits": {"maxGroups": 1000, "maxResultBytes": 1048576,
                   "pageSize": 100, "ttlSeconds": 900}}
    request.update(expectPath=["result", "status"], expectTemplate="ready",
                   capturePath=["result", "queryId"])
    cancel["arguments"]["program"]["arguments"] = {"queryId": "{queryId}"}
    cancel.update(expectPath=["result", "status"],
                  expectTemplate="$oneof:cancelled,cancel_requested")
    read["arguments"]["program"]["arguments"] = {"queryId": "{queryId}"}
    read.update(expectPath=["result", "status"], expectTemplate="cancelled")
    for action in workload["isolation"]:
        action["arguments"]["application_id"] = (
            "{isolationDeniedApplicationId}")
    return workload


def _fail(message: str) -> None:
    raise PilotLoadError(message)


def _strict(value: object, fields: set[str], name: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        _fail(f"{name} fields must be exactly {sorted(fields)}")
    return value


def _https(value: object, name: str) -> str:
    parsed = urlparse(str(value))
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname in {
            "localhost", "127.0.0.1", "::1"}:
        _fail(f"{name} must be a non-loopback HTTPS URL")
    return str(value).rstrip("/")


def _iso_date(value: object) -> bool:
    try:
        return isinstance(value, str) and date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _secret_file(value: object, name: str) -> str:
    path = Path(str(value))
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        _fail(f"{name} must be an absolute regular file")
    if path.stat().st_mode & 0o077:
        _fail(f"{name} must have mode 600 or stricter")
    return str(path)


def _reject_private_database_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if FORBIDDEN_KEYS.search(str(key)):
                _fail("private database or SQL configuration is forbidden")
            _reject_private_database_fields(item)
    elif isinstance(value, list):
        for item in value:
            _reject_private_database_fields(item)


def _program_function(action: dict) -> str | None:
    program = action["arguments"].get("program")
    return program.get("function") if isinstance(program, dict) else None


def _application_roles(application: dict) -> frozenset[str]:
    """Return the steady workload families admitted for one application.

    Older v2 profiles predate heterogeneous application routing and therefore
    retain the original all-families meaning.  New profiles can narrow the
    families explicitly without weakening whole-run coverage.
    """
    roles = application.get("workloadRoles")
    return (STEADY_ROLES if roles is None else frozenset(roles))


def _validate_action(action: object, name: str) -> dict:
    value = _strict(action, {"tool", "arguments", "expectPath", "expectTemplate",
        "captureAs", "capturePath", "receiptPath", "deniedContains"}, name)
    if value["tool"] not in ALLOWED_TOOLS or type(value["arguments"]) is not dict:
        _fail(f"{name} must use an approved public MCP tool")
    for path_name in ("expectPath", "capturePath", "receiptPath"):
        path = value[path_name]
        if path is not None and (type(path) is not list or not path or not all(
                isinstance(part, (str, int)) for part in path)):
            _fail(f"{name}.{path_name} must be a nonempty path or null")
    success = isinstance(value["expectTemplate"], str) and bool(value["expectPath"])
    denied = (isinstance(value["deniedContains"], str)
              and bool(value["deniedContains"]) and value["expectPath"] is None)
    if not (success ^ denied):
        _fail(f"{name} must define exactly one success or denial expectation")
    if ((value["captureAs"] is None) != (value["capturePath"] is None)
            or value["captureAs"] is not None and not re.fullmatch(
                r"[A-Za-z][A-Za-z0-9]{0,63}", str(value["captureAs"]))):
        _fail(f"{name} capture fields are inconsistent")
    return value


@dataclass(frozen=True, slots=True)
class MacPilotLoadContract:
    raw: dict

    @classmethod
    def load(cls, path: Path) -> "MacPilotLoadContract":
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            _fail("configuration must be an absolute regular file")
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise PilotLoadError("configuration is unreadable") from error
        contract = cls(raw)
        contract.validate()
        return contract

    def validate(self) -> None:
        _reject_private_database_fields(self.raw)
        raw = _strict(self.raw, {"format", "target", "browser", "load", "identities",
            "applications", "controls", "budgets", "workload", "evidence"},
            "configuration")
        if raw["format"] != "openepm-macos-pilot-load-v2":
            _fail("unsupported Mac pilot load format")
        target = _strict(raw["target"], {"mcpUrl", "oidcIssuer", "oidcAudience",
            "composeProject", "composeFile", "sampleServices"}, "target")
        _https(target["mcpUrl"], "target.mcpUrl")
        _https(target["oidcIssuer"], "target.oidcIssuer")
        if not isinstance(target["oidcAudience"], str) or not target["oidcAudience"]:
            _fail("target.oidcAudience is required")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", str(target["composeProject"])):
            _fail("target.composeProject is invalid")
        compose = Path(str(target["composeFile"]))
        if not compose.is_absolute() or not compose.is_file() or compose.is_symlink():
            _fail("target.composeFile must be an absolute regular file")
        services = target["sampleServices"]
        if (type(services) is not list or set(services) != {
                "db", "platform", "workspace", "router", "web", "worker"}):
            _fail("all six Mac pilot services must be sampled exactly once")

        browser = raw["browser"]
        credential_fields = {"webOrigin", "credentialFile", "credentialKind",
            "identitySubject", "expectedTitle", "expectedMarker",
            "sampleEverySeconds"}
        feed_fields = {"webOrigin", "sampleFeed", "sessionId",
            "identitySubjectSha256", "expectedTitle", "expectedMarker",
            "sampleEverySeconds", "maximumSampleAgeSeconds"}
        if type(browser) is not dict or set(browser) not in {
                frozenset(credential_fields), frozenset(feed_fields)}:
            _fail("browser fields do not match a supported qualification mode")
        _https(browser["webOrigin"], "browser.webOrigin")
        if (not isinstance(browser["expectedTitle"], str)
                or not browser["expectedTitle"]
                or not isinstance(browser["expectedMarker"], str)
                or not browser["expectedMarker"]
                or type(browser["sampleEverySeconds"]) is not int
                or not 5 <= browser["sampleEverySeconds"] <= 60):
            _fail("browser qualification profile is invalid")
        if set(browser) == credential_fields:
            _secret_file(browser["credentialFile"], "browser credential")
            if (browser["credentialKind"] != "oidc_bearer"
                    or not isinstance(browser["identitySubject"], str)
                    or not browser["identitySubject"]):
                _fail("browser qualification profile is invalid")
        else:
            _secret_file(browser["sampleFeed"], "Codex browser sample feed")
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}",
                                 str(browser["sessionId"]))
                    or not re.fullmatch(r"[0-9a-f]{64}",
                                        str(browser["identitySubjectSha256"]))
                    or type(browser["maximumSampleAgeSeconds"]) is not int
                    or not browser["sampleEverySeconds"] <= browser[
                        "maximumSampleAgeSeconds"] <= 180):
                _fail("Codex browser feed profile is invalid")

        load = _strict(raw["load"], {"durationSeconds", "warmupSeconds",
            "identityCount", "applicationCount", "aggressiveIdentityCount",
            "agentOperationsPerMinute", "humanOperationsPerMinute"}, "load")
        if (load["durationSeconds"] < 1800 or load["warmupSeconds"] < 60
                or load["identityCount"] != 10
                or load["applicationCount"] not in (5, 6)
                or load["aggressiveIdentityCount"] not in (3, 4)
                or not 1 <= load["agentOperationsPerMinute"] <= 60
                or not 1 <= load["humanOperationsPerMinute"] <= 12):
            _fail("load must model the adopted 30-minute 10-identity Mac pilot")
        identities = raw["identities"]
        if type(identities) is not list or len(identities) != 10:
            _fail("exactly ten identities are required")
        seen_subjects, seen_files, kinds = set(), set(), Counter()
        for index, item in enumerate(identities):
            identity = _strict(item, {"subject", "tokenFile", "kind"},
                               f"identities[{index}]")
            if not isinstance(identity["subject"], str) or not identity["subject"]:
                _fail("identity subject is required")
            token = _secret_file(identity["tokenFile"], "identity token")
            if identity["subject"] in seen_subjects or token in seen_files:
                _fail("identity subjects and token files must be distinct")
            if identity["kind"] not in ("agent", "human"):
                _fail("identity kind must be agent or human")
            seen_subjects.add(identity["subject"]); seen_files.add(token)
            kinds[identity["kind"]] += 1
        if kinds["agent"] != load["aggressiveIdentityCount"]:
            _fail("aggressive identity count does not match identity kinds")
        agent_subjects = {item["subject"] for item in identities
                          if item["kind"] == "agent"}
        browser_identity = next((item for item in identities
            if (item["subject"] == browser.get("identitySubject")
                or hashlib.sha256(item["subject"].encode("utf-8")).hexdigest()
                    == browser.get("identitySubjectSha256"))), None)
        if browser_identity is None or browser_identity["kind"] != "human":
            _fail("browser identity must be one configured human identity")

        applications = raw["applications"]
        if type(applications) is not list or len(applications) != load["applicationCount"]:
            _fail("application inventory does not match the configured count")
        scopes, tables, reader_keys, readers, writers = (set(), set(), set(),
                                                          set(), set())
        covered_roles: set[str] = set()
        for index, item in enumerate(applications):
            base_fields = {"workspaceId", "applicationId", "genericTableId",
                           "readerSeriesKey", "readerExpectation",
                           "writerExpectation"}
            if (type(item) is not dict or not base_fields.issubset(item)
                    or set(item) - base_fields - {"workloadRoles", "importRow",
                                                  "forecastProfile"}):
                _fail(f"applications[{index}] fields must be the exact v2 "
                      "base fields with optional workloadRoles/importRow/"
                      "forecastProfile")
            app = item
            if not all(isinstance(app[field], str) and app[field]
                       for field in base_fields):
                _fail("application scope and sentinel values are required")
            if not re.fullmatch(r"[0-9a-f]{32}", app["genericTableId"]):
                _fail("application genericTableId must be a lowercase 32-hex ID")
            if (app["readerSeriesKey"] != app["readerSeriesKey"].strip()
                    or len(app["readerSeriesKey"]) > 1000):
                _fail("application readerSeriesKey is invalid")
            roles = app.get("workloadRoles")
            if roles is not None and (
                    type(roles) is not list or not roles
                    or len(roles) != len(set(roles))
                    or not set(roles).issubset(STEADY_ROLES)):
                _fail("application workloadRoles must be unique supported "
                      "steady workload roles")
            effective_roles = _application_roles(app)
            if "import" in effective_roles:
                row = app.get("importRow")
                if (not isinstance(row, dict)
                        or set(row) != {"members", "value", "sourceRef"}
                        or not isinstance(row["members"], dict)
                        or not row["members"]
                        or not all(isinstance(axis, str) and axis
                                   and isinstance(member, str) and member
                                   for axis, member in row["members"].items())
                        or row["value"] != {"type": "AmountLiteral",
                                            "decimal": "1.00000000"}
                        or row["sourceRef"] != "pilot-load-import"):
                    _fail("import-capable applications require one explicit "
                          "prepared numeric source row")
            if "forecast" in effective_roles:
                profile = app.get("forecastProfile")
                if (not isinstance(profile, dict)
                        or set(profile) != {"definitionId",
                                            "actualClosedThrough",
                                            "delegations"}
                        or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", str(
                            profile["definitionId"]))
                        or not _iso_date(profile["actualClosedThrough"])
                        or not isinstance(profile["delegations"], dict)
                        or set(profile["delegations"]) != agent_subjects):
                    _fail("forecast-capable applications require a complete "
                          "agent delegation profile")
                for delegation in profile["delegations"].values():
                    if (not isinstance(delegation, dict)
                            or set(delegation) != {"delegationId", "version"}
                            or not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", str(
                                delegation["delegationId"]))
                            or type(delegation["version"]) is not int
                            or delegation["version"] < 1):
                        _fail("forecast-capable applications require a complete "
                              "agent delegation profile")
            if not effective_roles.intersection({
                    "humanRead", "agentRead", "write", "task"}):
                _fail("every application must admit a normal progress role")
            covered_roles.update(effective_roles)
            scope = (app["workspaceId"], app["applicationId"])
            if (scope in scopes or app["genericTableId"] in tables
                    or app["readerSeriesKey"] in reader_keys
                    or app["readerExpectation"] in readers
                    or app["writerExpectation"] in writers):
                _fail("application scopes, tables, keys and sentinel expectations "
                      "must be distinct")
            scopes.add(scope); readers.add(app["readerExpectation"])
            tables.add(app["genericTableId"])
            reader_keys.add(app["readerSeriesKey"])
            writers.add(app["writerExpectation"])
        if covered_roles != STEADY_ROLES:
            _fail("application workload routing must cover every steady role")

        controls = _strict(raw["controls"], {"controlSubject", "revocationSubject",
            "revocationAtSeconds", "isolationSubject",
            "isolationDeniedApplicationIndex", "isolationAtSeconds"}, "controls")
        if (controls["controlSubject"] not in seen_subjects
                or controls["revocationSubject"] not in seen_subjects
                or controls["controlSubject"] == controls["revocationSubject"]
                or controls["isolationSubject"] not in seen_subjects
                or not 0 <= controls["isolationDeniedApplicationIndex"] < len(applications)
                or not 0 < controls["revocationAtSeconds"] < load["durationSeconds"]
                or not 0 < controls["isolationAtSeconds"] < load["durationSeconds"]):
            _fail("revocation control subjects/timing are invalid")
        isolation_identity = next(item for item in identities
            if item["subject"] == controls["isolationSubject"])
        isolation_roles = (AGENT_ROLES if isolation_identity["kind"] == "agent"
                           else HUMAN_ROLES)
        for role in isolation_roles:
            if not any(index != controls["isolationDeniedApplicationIndex"]
                       and role in _application_roles(application)
                       for index, application in enumerate(applications)):
                _fail("isolation identity has no allowed application for " + role)
        budgets = _strict(raw["budgets"], {"maximumConnections",
            "maximumMemoryGiB", "maximumTemporaryDiskGiB", "maximumCpuPercent",
            "maximumHumanP99Seconds", "maximumBrowserP99Seconds",
            "maximumQueueWaitP99Seconds"}, "budgets")
        if any(type(value) not in (int, float) or value <= 0
               for value in budgets.values()):
            _fail("all pilot budgets must be positive")

        workload = raw["workload"]
        if type(workload) is not dict or set(workload) != REQUIRED_ROLES:
            _fail("workload must define every required pilot role")
        for role, actions in workload.items():
            if type(actions) is not list or not actions:
                _fail(f"workload.{role} must be a nonempty action sequence")
            for index, action in enumerate(actions):
                action = _validate_action(action, f"workload.{role}[{index}]")
                if role in ("revocation", "isolation", "calculation"):
                    continue
                tool, prefix = ROLE_PROFILES[role]
                function = _program_function(action)
                if action["tool"] != tool or (prefix is not None and
                        (not isinstance(function, str) or not function.startswith(prefix))):
                    _fail(f"workload.{role} does not use its fixed public profile")
        retry = workload["retry"]
        if len(retry) != 1 or retry[0]["receiptPath"] is None:
            _fail("retry must be one exact replay action with receipt evidence")
        encoded = {role: json.dumps(actions, sort_keys=True)
                   for role, actions in workload.items()}
        read_roles = ("humanRead", "agentRead", "invariant")
        for role in read_roles:
            for action in workload[role]:
                arguments = action["arguments"].get("program", {}).get(
                    "arguments")
                if arguments != {"tableId": "{genericTableId}",
                                  "seriesKey": "{readerSeriesKey}"}:
                    _fail(f"workload.{role} must read sentinel from the prepared "
                          "application")
                if action["expectPath"] != ["result", "value"]:
                    _fail(f"workload.{role} must inspect the public result envelope")
            if "{readerExpectation}" not in encoded[role]:
                _fail(f"workload.{role} must expect the application read sentinel")
        for role in ("write", "retry"):
            for action in workload[role]:
                arguments = action["arguments"].get("program", {}).get(
                    "arguments")
                expected_value = "{writerExpectation}:{requestId}"
                if arguments != {
                        "tableId": "{genericTableId}",
                        "seriesKey": expected_value,
                        "value": expected_value,
                        "expectedChangeId": "",
                        "expectedDataRevision": "{currentDataRevision}"}:
                    _fail(f"workload.{role} must use a unique prepared generic "
                          "write with a current data revision")
                if (action["arguments"].get("idempotency_key") != "{requestId}"
                        or action["expectPath"] != ["result", "value"]
                        or action["receiptPath"] != ["result", "changeId"]):
                    _fail(f"workload.{role} must bind request identity and the "
                          "stable generic change receipt")
        calculation = workload["calculation"]
        if ([action["tool"] for action in calculation] != [
                "preview_v2_program", "submit_v2_program"]
                or any(_program_function(action) !=
                       "facts.planning.spread.equal" for action in calculation)):
            _fail("workload.calculation must preview then submit one equal spread")
        preview_action, submit_action = calculation
        preview_program = preview_action["arguments"].get("program")
        submit_program = submit_action["arguments"].get("program")
        spread = (preview_program.get("arguments")
                  if isinstance(preview_program, dict) else None)
        if (preview_program != submit_program
                or not isinstance(spread, dict)
                or set(spread) != {"source", "targetDimension",
                                   "targetMembers", "resultKey"}
                or not isinstance(spread["source"], dict)
                or not spread["source"]
                or not all(isinstance(key, str) and key
                           and isinstance(value, str) and value
                           for key, value in spread["source"].items())
                or spread["targetDimension"] not in spread["source"]
                or not isinstance(spread["targetMembers"], list)
                or not spread["targetMembers"]
                or len(spread["targetMembers"]) != len(set(
                    spread["targetMembers"]))
                or any(not isinstance(member, str) or not member
                       for member in spread["targetMembers"])
                or spread["source"][spread["targetDimension"]]
                    in spread["targetMembers"]
                or spread["resultKey"] != "pilot.spread.{requestId}"):
            _fail("workload.calculation spread binding is invalid")
        if (preview_action["captureAs"] != "previewToken"
                or preview_action["capturePath"] != ["previewToken"]
                or preview_action["expectPath"] != ["function"]
                or preview_action["expectTemplate"] !=
                    "facts.planning.spread.equal"
                or submit_action["arguments"].get("preview_token") !=
                    "{previewToken}"
                or submit_action["arguments"].get("idempotency_key") !=
                    "{requestId}"
                or submit_action["arguments"].get("depends_on_job_ids") != []
                or submit_action["captureAs"] != "jobId"
                or submit_action["capturePath"] != ["jobId"]
                or submit_action["expectPath"] != ["duplicate"]
                or submit_action["expectTemplate"] != "False"):
            _fail("workload.calculation preview/submission bindings are incomplete")
        import_actions = workload["import"]
        import_functions = [_program_function(action)
                            for action in import_actions]
        if import_functions != [
                "facts.source.begin", "facts.source.append",
                "facts.source.seal", "facts.source.preview",
                "facts.source.publish"]:
            _fail("import must complete begin/append/seal/preview/publish")
        captures = [action["captureAs"] for action in import_actions]
        if captures != ["batchId", "contentDigest", None, "previewToken", None]:
            _fail("import lifecycle capture contract is incomplete")
        encoded_import = json.dumps(import_actions, sort_keys=True)
        if (encoded_import.count("{batchId}") < 4
                or "{contentDigest}" not in encoded_import
                or "{previewToken}" not in encoded_import):
            _fail("import lifecycle dependencies are not bound")
        expected_source_arguments = [
            {"idempotencyKey": "{requestId}", "mode": "merge",
             "scopeMembers": {}, "scopeAll": True,
             "expectedMetadataRevision": "{currentMetadataRevision}",
             "expectedDataRevision": "{currentDataRevision}"},
            {"batchId": "{batchId}", "chunkIndex": 0,
             "rows": ["{importRow}"]},
            {"batchId": "{batchId}", "expectedRows": 1,
             "expectedContentDigest": "{contentDigest}"},
            {"batchId": "{batchId}"},
            {"batchId": "{batchId}", "previewToken": "{previewToken}"},
        ]
        capture_paths = [["result", "batchId"],
                         ["result", "contentDigest"], None,
                         ["result", "previewToken"], None]
        for action, function, arguments, capture_path in zip(
                import_actions, import_functions, expected_source_arguments,
                capture_paths, strict=True):
            if (action["arguments"]["program"]["arguments"] != arguments
                    or action["expectPath"] != ["function"]
                    or action["expectTemplate"] != function
                    or action["capturePath"] != capture_path):
                _fail("import lifecycle must use exact public source programs")
        forecast = workload["forecast"]
        if len(forecast) != 1:
            _fail("forecast workload must request one durable occurrence")
        forecast_action = forecast[0]
        forecast_arguments = forecast_action["arguments"].get(
            "program", {}).get("arguments")
        if (forecast_arguments != {
                "definitionId": "{forecastDefinitionId}",
                "dueAt": "{forecastDueAt}",
                "actualClosedThrough": "{forecastActualClosedThrough}",
                "delegationId": "{forecastDelegationId}",
                "delegationVersion": "{forecastDelegationVersion}"}
                or forecast_action["expectPath"] != ["result", "status"]
                or forecast_action["expectTemplate"] != "ready"
                or forecast_action["captureAs"] != "occurrenceId"
                or forecast_action["capturePath"] != ["result",
                                                       "occurrenceId"]):
            _fail("forecast workload must use an authorized public occurrence")
        revocation_tools = [action["tool"] for action in workload["revocation"]]
        if (revocation_tools.count("set_v2_application_access") != 2
                or not any(action["deniedContains"] for action in workload["revocation"])
                or len(workload["revocation"]) < 5
                or "{targetSubject}" not in encoded["revocation"]):
            _fail("revocation must prove allowed, revoked denial, restoration and readback")
        access_actions = [action for action in workload["revocation"]
                          if action["tool"] == "set_v2_application_access"]
        expected_access = (("revoke", None, "{requestId}:revoke"),
                           ("grant", "Editor", "{requestId}:restore"))
        for action, (effect, role_name, request_key) in zip(
                access_actions, expected_access, strict=True):
            program = action["arguments"].get("program")
            if (program != {"languageVersion": 2,
                    "function": "security.application.access.set",
                    "arguments": {"subjectId": "{targetSubject}",
                        "action": effect, "role": role_name}}
                    or action["arguments"].get("idempotency_key") != request_key
                    or action["expectPath"] != ["function"]
                    or action["expectTemplate"] !=
                        "security.application.access.set"):
                _fail("revocation access changes must use exact public programs")
        isolation = workload["isolation"]
        isolation_profiles = {(action["tool"], _program_function(action))
                              for action in isolation}
        if (len(isolation) != 3
                or any(not action["deniedContains"] for action in isolation)
                or isolation_profiles != {
                    ("read_v2_program", "facts.generic.value.read"),
                    ("execute_v2_generic_fact_program", "facts.generic.value.set"),
                    ("submit_v2_program", "facts.planning.spread.equal")}
                or any("{isolationDeniedApplicationId}" not in json.dumps(action)
                       for action in isolation)):
            _fail("isolation must deny read, write and job submission in one application")
        isolation_generic = [action for action in isolation
            if _program_function(action) in {
                "facts.generic.value.read", "facts.generic.value.set"}]
        for action in isolation_generic:
            arguments = action["arguments"]["program"]["arguments"]
            function = _program_function(action)
            expected = ({"tableId": "{genericTableId}",
                         "seriesKey": "{readerSeriesKey}"}
                if function == "facts.generic.value.read" else {
                    "tableId": "{genericTableId}",
                    "seriesKey": "{writerExpectation}:{requestId}",
                    "value": "{writerExpectation}:{requestId}",
                    "expectedChangeId": "", "expectedDataRevision": 0})
            if arguments != expected:
                _fail("isolation generic actions must use valid prepared shapes")
        cancel_functions = [_program_function(action) for action in workload["cancel"]]
        if not {"facts.cube.aggregate.request", "facts.cube.aggregate.cancel",
                "facts.cube.aggregate.read"}.issubset(cancel_functions) \
                or not any(action["captureAs"] == "queryId"
                           for action in workload["cancel"]) \
                or encoded["cancel"].count("{queryId}") < 2:
            _fail("cancel must bind request, cancellation and terminal read")
        request_action, cancel_action, read_action = workload["cancel"]
        request_arguments = request_action["arguments"]["program"]["arguments"]
        query = request_arguments.get("query") if isinstance(
            request_arguments, dict) else None
        if (not isinstance(query, dict)
                or set(request_arguments) != {"query", "limits"}
                or set(query) != {"source", "grain", "selectors", "measures",
                                  "missing", "aggregation"}
                or query["source"] != "raw_numeric"
                or not isinstance(query["grain"], dict)
                or set(query["grain"]) != {"inputDimensions", "groupBy",
                                            "reduceDimensions"}
                or not isinstance(query["grain"]["inputDimensions"], list)
                or not query["grain"]["inputDimensions"]
                or not isinstance(query["grain"]["groupBy"], list)
                or not isinstance(query["grain"]["reduceDimensions"], list)
                or sorted(query["grain"]["groupBy"]
                          + query["grain"]["reduceDimensions"]) != sorted(
                              query["grain"]["inputDimensions"])
                or query["selectors"] != {}
                or query["measures"] != [{"kind": "CountPresent"}]
                or query["missing"] != "exclude"
                or query["aggregation"] != "unique_coordinate_reduction"
                or request_arguments["limits"] != {"maxGroups": 1000,
                    "maxResultBytes": 1048576, "pageSize": 100,
                    "ttlSeconds": 900}
                or request_action["captureAs"] != "queryId"
                or request_action["capturePath"] != ["result", "queryId"]
                or request_action["expectPath"] != ["result", "status"]
                or request_action["expectTemplate"] != "ready"):
            _fail("cancel request must use a bounded public aggregate query")
        for action, function in ((cancel_action,
                                  "facts.cube.aggregate.cancel"),
                                 (read_action, "facts.cube.aggregate.read")):
            expected_arguments = {"queryId": "{queryId}"}
            if action["arguments"]["program"]["arguments"] != expected_arguments:
                _fail("cancel lifecycle must bind the accepted query ID")
            expected_status = ("$oneof:cancelled,cancel_requested"
                               if function == "facts.cube.aggregate.cancel"
                               else "cancelled")
            if (action["expectPath"] != ["result", "status"]
                    or action["expectTemplate"] != expected_status):
                _fail("cancel lifecycle must prove accepted control and the "
                      "terminal cancelled state")
        task = workload["task"]
        if (len(task) != 1 or task[0]["tool"] != "list_v2_tasks"
                or task[0]["arguments"] != {
                    "workspace_id": "{workspaceId}",
                    "application_id": "{applicationId}",
                    "after_sequence": 0, "limit": 100}
                or task[0]["expectPath"] != ["tasks"]
                or task[0]["expectTemplate"] != "$type:list"):
            _fail("task workload must use the bounded public task list")

        evidence = _strict(raw["evidence"], {"output", "sampleEverySeconds"},
                           "evidence")
        output = Path(str(evidence["output"]))
        if not output.is_absolute() or output.suffix != ".json" or output.is_symlink():
            _fail("evidence output must be an absolute nonsymlink JSON path")
        if not 1 <= evidence["sampleEverySeconds"] <= 30:
            _fail("resource sample cadence must be 1-30 seconds")

    def redacted_plan(self) -> dict:
        raw = self.raw
        return {"format": raw["format"], "target": {
            "mcpUrl": raw["target"]["mcpUrl"],
            "oidcIssuer": raw["target"]["oidcIssuer"],
            "composeProject": raw["target"]["composeProject"],
            "sampleServices": raw["target"]["sampleServices"]},
            "load": raw["load"],
            "identityKinds": dict(Counter(item["kind"] for item in raw["identities"])),
            "browser": {"webOrigin": raw["browser"]["webOrigin"],
                "identityKind": "human",
                "probeKind": ("codex_iab_feed" if "sampleFeed" in raw["browser"]
                    else raw["browser"]["credentialKind"]),
                "sampleEverySeconds": raw["browser"]["sampleEverySeconds"],
                "tokenContentsRead": False},
            "applicationCount": len(raw["applications"]),
            "applicationWorkloadRoles": {
                f"application-{index + 1:02d}": sorted(
                    _application_roles(application))
                for index, application in enumerate(raw["applications"])},
            "workloadRoles": sorted(raw["workload"]),
            "tokenContentsRead": False, "qualificationClaimed": False}


class Gateway(Protocol):
    async def tools(self, session: Any) -> set[str]: ...
    async def open(self, subject: str, token_file: str): ...
    async def call(self, session: Any, tool: str, arguments: dict) -> dict: ...
    async def call_expect_denied(self, session: Any, tool: str, arguments: dict,
                                 contains: str) -> None: ...
    async def close(self, session: Any) -> None: ...


class Sampler(Protocol):
    async def sample(self) -> dict: ...
    async def close(self) -> None: ...


class BrowserProbe(Protocol):
    async def open(self) -> None: ...
    async def sample(self) -> dict: ...
    async def close(self) -> None: ...


def _expand(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        exact = re.fullmatch(r"\{([A-Za-z][A-Za-z0-9]{0,63})\}", value)
        if exact and exact.group(1) in context:
            return context[exact.group(1)]
        for key, item in context.items():
            value = value.replace("{" + key + "}", str(item))
        return value
    if isinstance(value, list):
        return [_expand(item, context) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item, context) for key, item in value.items()}
    return value


def _at(value: Any, path: list[str | int]) -> Any:
    for part in path:
        value = value[part]
    return value


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int(len(ordered) * fraction)))]


def _resource_summary(samples: list[dict]) -> dict:
    """Return bounded, decision-useful maxima without losing raw samples."""
    if not samples:
        return {"sampleCount": 0, "maximumConnections": None,
            "maximumMemoryGiB": None, "maximumTemporaryDiskGiB": None,
            "maximumCpuPercent": None, "maximumQueueDepths": {}}
    queue_families = sorted({family for sample in samples
        for family in sample["queueDepths"]})
    return {"sampleCount": len(samples),
        "maximumConnections": max(sample["connections"] for sample in samples),
        "maximumMemoryGiB": max(sample["memoryGiB"] for sample in samples),
        "maximumTemporaryDiskGiB": max(
            sample["temporaryDiskGiB"] for sample in samples),
        "maximumCpuPercent": max(sample["cpuPercent"] for sample in samples),
        "maximumQueueDepths": {family: max(
            int(sample["queueDepths"].get(family, 0)) for sample in samples)
            for family in queue_families}}


class MacPilotLoadEngine:
    def __init__(self, contract: MacPilotLoadContract, gateway: Gateway,
                 sampler: Sampler, browser: BrowserProbe, *,
                 clock=time.monotonic, sleep=asyncio.sleep):
        self.contract, self.gateway, self.sampler = contract, gateway, sampler
        self.browser = browser
        self.clock, self.sleep = clock, sleep
        self.errors: list[dict] = []
        self.latencies: dict[str, list[float]] = defaultdict(list)
        self.measured_latencies: dict[str, list[float]] = defaultdict(list)
        self.counts, self.subjects, self.applications = Counter(), Counter(), Counter()
        self.measured_counts = Counter()
        self.measured_subjects, self.measured_applications = Counter(), Counter()
        self.receipts: dict[tuple[str, str, str], str] = {}
        self.samples: list[dict] = []
        self.browser_samples: list[dict] = []
        self._locks = {item["subject"]: asyncio.Lock()
                       for item in contract.raw["identities"]}
        self._sessions: dict[str, Any] = {}
        self._stop = asyncio.Event()
        self._measure_start = self._measure_finish = 0.0
        self.revocation = {"executed": 0, "denials": 0, "restored": 0}
        self.isolation = {"executed": 0, "denials": 0}

    def _measured(self, started: float) -> bool:
        return self._measure_start <= started < self._measure_finish

    async def _action(self, session: Any, role: str, action: dict,
                      context: dict[str, Any]) -> dict:
        started = self.clock(); measured = self._measured(started)
        try:
            function = _program_function(action)
            if (function in {"facts.generic.value.set", "facts.source.begin"}
                    and not action["deniedContains"]
                    and "currentDataRevision" not in context):
                state = await self.gateway.call(session, "read_v2_program", {
                    "workspace_id": context["workspaceId"],
                    "application_id": context["applicationId"],
                    "program": {"languageVersion": 2,
                                "function": "application.capabilities.read",
                                "arguments": {}}})
                result = state.get("result") if isinstance(state, dict) else None
                revision = result.get("dataRevision") if isinstance(
                    result, dict) else None
                if type(revision) is not int or revision < 0:
                    raise RuntimeError("application data revision is invalid")
                context["currentDataRevision"] = revision
                metadata_revision = result.get("metadataRevision")
                if type(metadata_revision) is not int or metadata_revision < 0:
                    raise RuntimeError("source metadata revision is invalid")
                context["currentMetadataRevision"] = metadata_revision
            arguments = _expand(action["arguments"], context)
            if action["deniedContains"]:
                await self.gateway.call_expect_denied(session, action["tool"],
                    arguments, action["deniedContains"])
                result = {"denied": True}
                if role == "revocation":
                    self.revocation["denials"] += 1
                elif role == "isolation":
                    self.isolation["denials"] += 1
            else:
                result = await self.gateway.call(session, action["tool"], arguments)
                actual = _at(result, action["expectPath"])
                expected = _expand(action["expectTemplate"], context)
                if (role == "cancel"
                        and function == "facts.cube.aggregate.read"
                        and expected == "cancelled"
                        and actual in {"ready", "running", "cancel_requested"}):
                    deadline = self.clock() + 10
                    while actual != "cancelled" and self.clock() < deadline:
                        await self.sleep(.05)
                        result = await self.gateway.call(
                            session, action["tool"], arguments)
                        actual = _at(result, action["expectPath"])
                expected_type = ({"list": list, "dict": dict,
                                  "string": str}.get(expected.removeprefix(
                                      "$type:"))
                                 if isinstance(expected, str)
                                 and expected.startswith("$type:") else None)
                expected_values = (expected.removeprefix("$oneof:").split(",")
                    if isinstance(expected, str)
                    and expected.startswith("$oneof:") else None)
                if ((expected_type is not None and type(actual) is not expected_type)
                        or expected_values is not None
                        and str(actual) not in expected_values
                        or expected_type is None and expected_values is None
                        and str(actual) != str(expected)):
                    raise RuntimeError(f"{role} expectation mismatch")
                if action["captureAs"]:
                    context[action["captureAs"]] = str(_at(result, action["capturePath"]))
                if action["receiptPath"]:
                    receipt = str(_at(result, action["receiptPath"]))
                    key = (context["applicationId"], context["requestId"], role)
                    old = self.receipts.setdefault(key, receipt)
                    if old != receipt:
                        raise RuntimeError(f"{role} replay changed its receipt")
            self.counts[role] += 1
            self.subjects[context["subject"]] += 1
            scope_key = context["workspaceId"] + "\x1f" + context["applicationId"]
            self.applications[scope_key] += 1
            if measured:
                self.measured_counts[role] += 1
                self.measured_subjects[context["subject"]] += 1
                self.measured_applications[scope_key] += 1
            return result
        finally:
            elapsed = self.clock() - started
            self.latencies[role].append(elapsed)
            if measured:
                self.measured_latencies[role].append(elapsed)

    async def _role(self, subject: str, role: str, context: dict[str, Any]) -> None:
        actions = self.contract.raw["workload"][role]
        async with self._locks[subject]:
            for action in actions:
                await self._action(self._sessions[subject], role, action, context)
            if role == "retry":
                for action in actions:
                    await self._action(self._sessions[subject], role, action, context)

    async def _identity(self, index: int, finish: float) -> None:
        identity = self.contract.raw["identities"][index]
        roles = AGENT_ROLES if identity["kind"] == "agent" else HUMAN_ROLES
        all_applications = self.contract.raw["applications"]
        denied_index = (self.contract.raw["controls"][
            "isolationDeniedApplicationIndex"]
            if identity["subject"] == self.contract.raw["controls"][
                "isolationSubject"] else None)
        rate = self.contract.raw["load"]["agentOperationsPerMinute" if
            identity["kind"] == "agent" else "humanOperationsPerMinute"]
        cadence = 60 / rate; sequence = 0
        try:
            while self.clock() < finish and not self._stop.is_set():
                role = roles[sequence % len(roles)]
                applications = [app for app_index, app in enumerate(
                    all_applications) if app_index != denied_index
                    and role in _application_roles(app)]
                app = applications[(sequence // len(roles)) % len(applications)]
                context = {**app,
                    "subject": identity["subject"],
                    "requestId": f"pilot-{index:02d}-{sequence:08d}",
                    "targetSubject": self.contract.raw["controls"]["revocationSubject"]}
                if role == "forecast":
                    profile = app["forecastProfile"]
                    delegation = profile["delegations"][identity["subject"]]
                    context.update(
                        forecastDefinitionId=profile["definitionId"],
                        forecastActualClosedThrough=profile[
                            "actualClosedThrough"],
                        forecastDelegationId=delegation["delegationId"],
                        forecastDelegationVersion=delegation["version"],
                        forecastDueAt=datetime.now(timezone.utc).isoformat())
                await self._role(identity["subject"], role, context)
                sequence += 1
                await self.sleep(max(0, min(finish, self._measure_start -
                    self.contract.raw["load"]["warmupSeconds"] + sequence * cadence)
                    - self.clock()))
        except Exception as error:
            self.errors.append({"identity": f"identity-{index + 1:02d}",
                "error": repr(error)})
            self._stop.set()

    async def _control(self, start: float) -> None:
        raw = self.contract.raw
        await self.sleep(max(0, self._measure_start + raw["controls"][
            "revocationAtSeconds"] - self.clock()))
        controller = raw["controls"]["controlSubject"]
        target = raw["controls"]["revocationSubject"]
        app = raw["applications"][0]
        context = {**app,
            "subject": controller, "targetSubject": target,
            "requestId": "pilot-revocation-control"}
        try:
            async with self._locks[target]:
                for action in raw["workload"]["revocation"]:
                    subject = (target if action["tool"] !=
                               "set_v2_application_access" else controller)
                    context["subject"] = subject
                    await self._action(self._sessions[subject], "revocation", action, context)
                self.revocation["executed"] += 1
                self.revocation["restored"] += 1
        except Exception as error:
            self.errors.append({"revocation": repr(error)}); self._stop.set()

    async def _isolation_control(self) -> None:
        raw = self.contract.raw
        await self.sleep(max(0, self._measure_start + raw["controls"][
            "isolationAtSeconds"] - self.clock()))
        subject = raw["controls"]["isolationSubject"]
        app = raw["applications"][raw["controls"][
            "isolationDeniedApplicationIndex"]]
        context = {**app,
            "subject": subject, "targetSubject": subject,
            "isolationDeniedApplicationId": str(app["applicationId"]),
            "requestId": "pilot-cross-application-denial"}
        try:
            await self._role(subject, "isolation", context)
            self.isolation["executed"] += 1
        except Exception as error:
            self.errors.append({"isolation": repr(error)}); self._stop.set()

    async def _resources(self, finish: float) -> None:
        cadence = self.contract.raw["evidence"]["sampleEverySeconds"]
        budgets = self.contract.raw["budgets"]
        while self.clock() < finish and not self._stop.is_set():
            try:
                sample = await self.sampler.sample()
                required = {"connections", "memoryGiB", "temporaryDiskGiB",
                    "cpuPercent", "queueDepths", "queueWaitSamples",
                    "serviceCount"}
                if type(sample) is not dict or set(sample) != required \
                        or sample["serviceCount"] != 6:
                    raise RuntimeError("resource sample scope is incomplete")
                for field, budget in (("connections", budgets["maximumConnections"]),
                        ("memoryGiB", budgets["maximumMemoryGiB"]),
                        ("temporaryDiskGiB", budgets["maximumTemporaryDiskGiB"]),
                        ("cpuPercent", budgets["maximumCpuPercent"])):
                    if not isinstance(sample[field], (int, float)) or sample[field] > budget:
                        raise RuntimeError(f"resource budget exceeded: {field}")
                self.samples.append(sample)
            except Exception as error:
                self.errors.append({"resource": repr(error)}); self._stop.set()
            await self.sleep(max(0, min(cadence, finish - self.clock())))

    async def _browser(self, finish: float) -> None:
        cadence = self.contract.raw["browser"]["sampleEverySeconds"]
        await self.sleep(max(0, self._measure_start - self.clock()))
        while self.clock() < finish and not self._stop.is_set():
            started = self.clock()
            try:
                sample = await self.browser.sample()
                expected = {"navigationSeconds", "applicationsSeconds",
                    "applicationCount", "identityMatched", "pageTitle", "markerObserved",
                    "presentationBundleLoaded", "consoleErrorCount"}
                if (type(sample) is not dict or set(sample) != expected
                        or sample["applicationCount"] != len(
                            self.contract.raw["applications"])
                        or sample["identityMatched"] is not True
                        or sample["pageTitle"] != self.contract.raw["browser"][
                            "expectedTitle"]
                        or sample["markerObserved"] != self.contract.raw[
                            "browser"]["expectedMarker"]
                        or sample["presentationBundleLoaded"] is not True
                        or sample["consoleErrorCount"] != 0
                        or any(type(sample[field]) not in (int, float)
                            or sample[field] < 0 for field in (
                                "navigationSeconds", "applicationsSeconds"))):
                    raise RuntimeError("authenticated browser sample is invalid")
                self.browser_samples.append(sample)
            except Exception as error:
                self.errors.append({"browser": repr(error)}); self._stop.set()
            elapsed = self.clock() - started
            await self.sleep(max(0, min(cadence - elapsed,
                finish - self.clock())))

    async def run(self) -> dict:
        raw = self.contract.raw; started = self.clock()
        self._measure_start = started + raw["load"]["warmupSeconds"]
        self._measure_finish = self._measure_start + raw["load"]["durationSeconds"]
        try:
            await self.browser.open()
            for identity in raw["identities"]:
                self._sessions[identity["subject"]] = await self.gateway.open(
                    identity["subject"], identity["tokenFile"])
            async with asyncio.TaskGroup() as group:
                for index in range(len(raw["identities"])):
                    group.create_task(self._identity(index, self._measure_finish))
                group.create_task(self._control(started))
                group.create_task(self._isolation_control())
                group.create_task(self._resources(self._measure_finish))
                group.create_task(self._browser(self._measure_finish))
            controller = raw["controls"]["controlSubject"]
            for index, app in enumerate(raw["applications"]):
                context = {**app,
                    "subject": controller, "targetSubject": raw["controls"][
                        "revocationSubject"], "requestId": f"pilot-invariant-{index}"}
                await self._role(controller, "invariant", context)
        finally:
            await asyncio.gather(*(self.gateway.close(session)
                for session in self._sessions.values()), return_exceptions=True)
            await self.sampler.close()
            await self.browser.close()

        latency = {name: {"count": len(values),
            "p50Seconds": statistics.median(values),
            "p95Seconds": _percentile(values, .95),
            "p99Seconds": _percentile(values, .99)}
            for name, values in self.measured_latencies.items() if values}
        waits: dict[str, list[float]] = defaultdict(list)
        for sample in self.samples:
            for family, values in sample["queueWaitSamples"].items():
                waits[family].extend(float(value) for value in values)
        queue_wait = {family: {"count": len(values),
            "p50Seconds": statistics.median(values),
            "p95Seconds": _percentile(values, .95),
            "p99Seconds": _percentile(values, .99)}
            for family, values in waits.items() if values}
        browser_values = [max(sample["navigationSeconds"],
            sample["applicationsSeconds"]) for sample in self.browser_samples]
        browser_latency = ({"count": len(browser_values),
            "p50Seconds": statistics.median(browser_values),
            "p95Seconds": _percentile(browser_values, .95),
            "p99Seconds": _percentile(browser_values, .99)}
            if browser_values else None)
        measured_subjects = {subject for subject in self.measured_subjects
            if self.measured_subjects[subject] > 0}
        measured_apps = {app for app in self.measured_applications
            if self.measured_applications[app] > 0}
        checks = {
            "tenIdentitiesProgressed": len(measured_subjects) == 10,
            "allApplicationsProgressed": len(measured_apps) == len(raw["applications"]),
            "allRequiredRolesProgressed": all(self.measured_counts[role] > 0
                for role in REQUIRED_ROLES - {"revocation", "invariant"}),
            "revocationDeniedAndRestored": self.revocation == {
                "executed": 1, "denials": 1, "restored": 1},
            "crossApplicationReadWriteJobDenied": self.isolation == {
                "executed": 1, "denials": 3},
            "idempotentRetryReceiptsStable": self.measured_counts["retry"] >= 2,
            "invariantsReadForEveryApplication": self.counts["invariant"] ==
                len(raw["applications"]),
            "humanP99WithinBudget": "humanRead" in latency and latency[
                "humanRead"]["p99Seconds"] <= raw["budgets"]["maximumHumanP99Seconds"],
            "browserSamplesComplete": bool(self.browser_samples),
            "browserP99WithinBudget": browser_latency is not None and
                browser_latency["p99Seconds"] <= raw["budgets"][
                    "maximumBrowserP99Seconds"],
            "queueWaitWithinBudget": bool(queue_wait) and all(item["p99Seconds"] <=
                raw["budgets"]["maximumQueueWaitP99Seconds"]
                for item in queue_wait.values()),
            "resourceSamplesComplete": bool(self.samples),
            "noErrors": not self.errors,
        }
        identity_labels = {item["subject"]: f"identity-{index + 1:02d}"
            for index, item in enumerate(raw["identities"])}
        application_labels = {
            item["workspaceId"] + "\x1f" + item["applicationId"]:
                f"application-{index + 1:02d}"
            for index, item in enumerate(raw["applications"])}
        attribution = {
            "identities": {identity_labels[item["subject"]]: {
                "kind": item["kind"],
                "successfulMeasuredActions": self.measured_subjects[
                    item["subject"]]}
                for item in raw["identities"]},
            "applications": {application_labels[key]:
                self.measured_applications[key]
                for key in application_labels},
            "roles": dict(self.measured_counts),
            "rawSubjectsIncluded": False,
            "tokenPathsIncluded": False,
        }
        return {"format": "openepm-macos-pilot-load-evidence-v2",
            "status": "passed" if all(checks.values()) else "failed",
            "qualificationClaimed": False, "checks": checks,
            "counts": dict(self.counts), "measuredCounts": dict(self.measured_counts),
            "latency": latency, "queueWait": queue_wait,
            "browserLatency": browser_latency,
            "browserSamples": self.browser_samples,
            "resourceSamples": self.samples,
            "resourceSummary": _resource_summary(self.samples),
            "attribution": attribution, "errors": self.errors,
            "measurement": {"identityCount": 10,
                "aggressiveIdentityCount": raw["load"]["aggressiveIdentityCount"],
                "applicationCount": len(raw["applications"]),
                "configuredWarmupSeconds": raw["load"]["warmupSeconds"],
                "configuredDurationSeconds": raw["load"]["durationSeconds"]},
            "throughputPerSecond": {role: count / raw["load"]["durationSeconds"]
                for role, count in self.measured_counts.items()},
            "configurationDigest": hashlib.sha256(json.dumps(
                raw, sort_keys=True).encode()).hexdigest(),
            "limit": "Harness evidence only; LP14/LP16 require the explicit real Mac pilot run."}
