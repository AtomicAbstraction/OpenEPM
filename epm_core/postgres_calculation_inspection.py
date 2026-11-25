"""Authorized W09 calculation status and bounded affected-work explanation."""
from __future__ import annotations

import re

from psycopg.rows import dict_row

from .calculation_dependency_contract import (COVERAGE, DEPENDENCY_KINDS,
    FANOUTS, PRESENCE, REASONS)
from .calculation_work_contract import compile_calculation_work_plan
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_calculation_impact import impact_processing_barrier
from .postgres_calculation_work import load_calculation_scope_states
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


STATUS = "calculation.status.read"
EXPLAIN = "calculation.impact.explain"
RECALCULATE = "calculation.recalculate.request"
FUNCTIONS = frozenset({STATUS, EXPLAIN})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MODES = ("affected", "force_populated", "force_domain")
_STATUS_PAGE_LIMIT = 500
_STATUS_CURSOR_LIMIT = 600
_EXPLAIN_DEPENDENCY_LIMIT = 500
_SERVER_TASK_LIMIT = 10_000


def catalog() -> dict[str, dict[str, object]]:
    common = {"mode": "read", "permission": "read",
              "previewRequired": False, "idempotencyRequired": False,
              "workClass": "bounded_read"}
    return {
        STATUS: {**common, **inspection_program_contract(STATUS), "arguments": {
            "definitionId": "exact definition identity",
            "definitionStateToken": "exact current definition state token",
            "limit": "1-500 status rows",
            "after": "optional binding/stage/partition continuation"},
            "result": "authorized currentness, reasons, presence, coverage, generations and impact barrier"},
        EXPLAIN: {**common, **inspection_program_contract(EXPLAIN), "arguments": {
            "bindingDigest": "exact authorized instance binding digest",
            "mode": "affected, force_populated or force_domain"},
            "result": "read-only business impact, declared dependencies, estimates, currentness and cost warnings"},
        RECALCULATE: {**inspection_program_contract(RECALCULATE),
            "mode": "durable_write", "permission": "rule_run",
            "previewRequired": False, "idempotencyRequired": True,
            "workClass": "long", "arguments": {
                "bindingDigest": "exact published instance binding digest",
                "mode": "affected, force_populated or force_domain",
                "expectedDefinitionDigest": "exact immutable definition digest",
                "expectedImpactEpoch": "nonnegative processed impact epoch pin"},
            "result": "durable logical recalculation request identity and status"},
    }


def inspection_program_contract(function: str) -> dict:
    from .metadata_read_contract import obj, read_contract, read_example

    identifier = {"type": "string", "pattern": "^" + _ID.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}
    digest = {"type": "string", "pattern": "^" + _DIGEST.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}
    nullable_digest = {**digest, "type": ["string", "null"]}
    epoch = {"type": "integer", "minimum": 0}
    boolean = {"type": "boolean"}
    count = {"type": "integer", "minimum": 0}
    barrier = obj({"impactEpoch": epoch, "processedImpactEpoch": epoch, "pending": boolean})
    coverage = {"enum": sorted(COVERAGE)}
    policy_version = {"type": "integer", "minimum": 1}
    example_digest = "a" * 64

    if function == STATUS:
        state = {"definitionId": identifier, "definitionStateToken": digest}
        cursor = {"type": "string", "maxLength": _STATUS_CURSOR_LIMIT}
        arguments = obj({**state, "limit": {"type": "integer", "minimum": 1, "maximum": _STATUS_PAGE_LIMIT},
                         "after": cursor}, list(state))
        fields = {
            "bindingDigest": digest, "stage": identifier, "partitionKey": identifier,
            "definitionDigest": digest, "requiredEpoch": epoch, "publishedEpoch": epoch,
            "coverage": coverage, "coverageComplete": boolean, "presence": {"enum": sorted(PRESENCE)},
            "currentResultStateToken": nullable_digest, "currentPartitionCertificateDigest": nullable_digest,
            "currentManifestDigest": nullable_digest, "partitionPolicyVersion": policy_version,
            "reasons": {"type": "array", "items": {"enum": sorted(REASONS)}, "uniqueItems": True},
            "activity": {"const": "idle"}, "impactBarrier": barrier,
            "freshness": {"enum": ["never_calculated", "invalid_definition", "impacted", "current",
                                  "impact_coverage_pending"]},
            "requiredAction": {"enum": ["rebuild_definition", "resolve_dependency", "calculate", "none",
                                       "process_impact"]},
            "resultCurrentness": obj({"matchesAtRead": boolean, "reason": {
                "type": ["string", "null"], "pattern": r"^[A-Za-z][A-Za-z0-9_]{0,127}(?![\s\S])"}}),
        }
        row = obj({**fields, "dependencyTokenDigest": nullable_digest}, list(fields))
        result = obj({"format": {"const": "openepm-calculation-status-v1"}, **state,
            "rows": {"type": "array", "items": row, "maxItems": _STATUS_PAGE_LIMIT},
            "nextAfter": {**cursor, "type": ["string", "null"]}, "impactBarrier": barrier})
        example = read_example(function, {"definitionId": "example-calculation", "definitionStateToken": example_digest,
            "limit": 20}, name="Inspect the current bound calculation scopes",
            binding="Read the authorized calculated-member definition and copy its exact definition ID and state token. Continue using nextAfter with the same definition.")
        semantics = [
            "An empty page only describes the supplied definition token and keyset. A changed definition requires a fresh status read.",
            "A durable result token and present value do not imply freshness. Check impactBarrier, freshness, resultCurrentness and requiredAction.",
        ]
        recovery = (
            "If CALCULATION_CURRENTNESS_READ_CUT_CHANGED is returned, or the definition changed, "
            "read the current definition and restart status from the first page. For impact_coverage_pending, "
            "wait for impact processing and read status again. Treat nextAfter as an opaque keyset.")
    elif function == EXPLAIN:
        arguments = obj({"bindingDigest": digest, "mode": {"enum": list(_MODES)}}, ["bindingDigest"])
        member_scope = {"type": "array", "maxItems": 32, "items": obj({
            "dimensionId": identifier, "memberIds": {"type": "array", "items": identifier, "minItems": 1,
                                                     "maxItems": 500, "uniqueItems": True}})}
        dependency = obj({"kind": {"enum": sorted(DEPENDENCY_KINDS)}, "objectType": identifier,
            "objectId": identifier, "scope": member_scope, "absenceWatch": boolean, "fanout": {"enum": sorted(FANOUTS)}})
        unresolved = obj({"dependencyOrdinal": count, "reason": {"const": "INSTANCE_BINDING_NOT_DERIVABLE_FROM_TEMPLATE"}})
        result = obj({"format": {"const": "openepm-calculation-impact-explain-v1"},
            "estimateKind": {"const": "authorized_current_state"},
            "definition": obj({"definitionId": identifier, "stateToken": digest, "definitionDigest": digest,
                               "compilerVersion": identifier}),
            "binding": obj({"bindingDigest": digest, "stage": identifier, "parameters": {"type": "object"},
                            "partitionPolicyVersion": policy_version}),
            "coverage": coverage, "dependencies": {"type": "array", "items": dependency,
                "maxItems": _EXPLAIN_DEPENDENCY_LIMIT}, "dependenciesTruncated": boolean,
            "dependencyGraph": obj({"unresolvedBindings": {"type": "array", "items": unresolved,
                "maxItems": _EXPLAIN_DEPENDENCY_LIMIT}, "complete": boolean}),
            "affectedUnitCount": count, "impactBarrier": barrier,
            "cost": obj({"outputUpperBound": count, "eligibleBackendProfiles": {"const": []},
                "backendSelection": {"const": "server_owned"}, "warnings": {"enum": [[], ["DEPENDENCY_BINDINGS_UNRESOLVED"]]}}),
        })
        example = read_example(function, {"bindingDigest": example_digest, "mode": "affected"},
            name="Explain affected work for one current calculation binding",
            binding="Get the exact authorized bindingDigest from calculation.status.read. Review affected estimates and unresolved dependencies before any separate recalculation.")
        semantics = [
            "This read estimates work for the given binding. It neither submits work nor authorizes recalculation.",
            "Unresolved bindings and truncated dependencies limit the explanation. The fixed owner chooses the execution backend.",
        ]
        recovery = (
            "After CALCULATION_BINDING_UNAVAILABLE, CALCULATION_TEMPLATE_UNAVAILABLE or "
            "CALCULATION_CURRENTNESS_READ_CUT_CHANGED, read current calculation status under the same "
            "application authority, then use a binding returned by that status.")
    elif function == RECALCULATE:
        pins = {"bindingDigest": digest, "expectedDefinitionDigest": digest, "expectedImpactEpoch": epoch}
        arguments = obj({**pins, "mode": {"enum": list(_MODES)}}, list(pins))
        result = obj({
            "format": {"const": "openepm-calculation-recalculate-v1"},
            "requestId": {"type": "string", "pattern": r"^[0-9a-f]{32}(?![\s\S])"},
            "status": {"enum": ["planned", "no_change", "running", "published", "failed", "cancelled"]},
            "duplicate": boolean, "compatible": boolean, "taskCount": count,
            "bindingDigest": digest, "affectedUnitCount": count,
            "impactBarrier": obj({"impactEpoch": epoch, "processedImpactEpoch": epoch, "pending": {"const": False}}),
        })
        example = read_example(function, {"bindingDigest": example_digest, "mode": "affected",
            "expectedDefinitionDigest": "b" * 64, "expectedImpactEpoch": 1},
            name="Request work for the current inspected calculation binding",
            binding="Use calculation.impact.explain for the exact binding and mode. Review its estimate and copy binding.bindingDigest, definition.definitionDigest and the processed impact epoch when pending is false. Obtain an admission for that exact program.")
        semantics = [
            "A successful result identifies a durable work request. Its status may advance, while impactBarrier records the accepted epoch.",
            "An exact signed retry checks current authority and reads the original request before considering any new plan.",
        ]
        recovery = (
            "For a missing acknowledgement, use execute_v2_expression_rule_program with the original admission and "
            "unchanged program. Expired recovery only reads accepted work. For IMPACT_COVERAGE_PENDING, wait for processing. "
            "For CALCULATION_IMPACT_EPOCH_STALE, read a fresh impact explanation and review a new intent.")
    else:
        raise ValueError("CALCULATION_INSPECTION_FUNCTION_INVALID")
    contract = read_contract(function, arguments, result, owner="PostgresCalculationInspection",
                             examples=[example], semantic_rules=semantics)
    contract["programContract"]["recovery"] = recovery
    return contract


def _program(raw: object) -> tuple[str, dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or type(raw.get("languageVersion")) is not int
            or raw["languageVersion"] != 2
            or not isinstance(raw.get("function"), str)
            or raw.get("function") not in FUNCTIONS
            or not isinstance(raw.get("arguments"), dict)):
        raise ValueError("CALCULATION_INSPECTION_PROGRAM_INVALID")
    function, arguments = raw["function"], raw["arguments"]
    if function == STATUS:
        if (set(arguments) - {"definitionId", "definitionStateToken", "limit", "after"}
                or not isinstance(arguments.get("definitionId"), str)
                or _ID.fullmatch(arguments["definitionId"]) is None
                or not isinstance(arguments.get("definitionStateToken"), str)
                or _DIGEST.fullmatch(arguments["definitionStateToken"]) is None
                or type(arguments.get("limit", 100)) is not int
                or not 1 <= arguments.get("limit", 100) <= _STATUS_PAGE_LIMIT
                or ("after" in arguments
                    and (not isinstance(arguments["after"], str)
                         or len(arguments["after"]) > _STATUS_CURSOR_LIMIT))):
            raise ValueError("CALCULATION_STATUS_ARGUMENTS_INVALID")
    elif (set(arguments) - {"bindingDigest", "mode"}
          or not isinstance(arguments.get("bindingDigest"), str)
          or _DIGEST.fullmatch(arguments["bindingDigest"]) is None
          or arguments.get("mode", "affected") not in _MODES):
        raise ValueError("CALCULATION_EXPLAIN_ARGUMENTS_INVALID")
    return function, arguments


def _recalculate_arguments(raw: object) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or type(raw.get("languageVersion")) is not int
            or raw["languageVersion"] != 2
            or raw.get("function") != RECALCULATE
            or not isinstance(raw.get("arguments"), dict)):
        raise ValueError("CALCULATION_RECALCULATE_PROGRAM_INVALID")
    arguments = raw["arguments"]
    if (set(arguments) - {"bindingDigest", "mode",
                          "expectedDefinitionDigest", "expectedImpactEpoch"}
            or not isinstance(arguments.get("bindingDigest"), str)
            or _DIGEST.fullmatch(arguments["bindingDigest"]) is None
            or not isinstance(arguments.get("expectedDefinitionDigest"), str)
            or _DIGEST.fullmatch(arguments["expectedDefinitionDigest"]) is None
            or arguments.get("mode", "affected") not in _MODES
            or type(arguments.get("expectedImpactEpoch")) is not int
            or arguments["expectedImpactEpoch"] < 0):
        raise ValueError("CALCULATION_RECALCULATE_ARGUMENTS_INVALID")
    return arguments


def _key(row: dict) -> str:
    return "\x1f".join((row["bindingDigest"], row["stage"],
                         row["partitionKey"]))


def _recalculation_result(binding_digest, barrier, request):
    return {**request, "format": "openepm-calculation-recalculate-v1",
            "bindingDigest": binding_digest, "affectedUnitCount": request["taskCount"],
            "impactBarrier": barrier}


def _result_verdict(row: dict, arguments: dict, status: dict | None) -> dict:
    """Project only an exact requested scope's authoritative currentness."""
    reason = None
    if status is None:
        reason = 'result_head_unavailable'
    elif status.get('truncated'):
        reason = 'result_read_limit'
    else:
        manifest = status.get('manifestCurrentnessStatus')
        if not isinstance(manifest, dict) or manifest.get('certificateValid') is not True:
            reason = 'result_manifest_unavailable'
        elif any(manifest.get(key) != value for key, value in (
                ('bindingDigest', row['bindingDigest']), ('stage', row['stage']),
                ('definitionDigest', row['definitionDigest']),
                ('definitionId', arguments['definitionId']),
                ('definitionStateToken', arguments['definitionStateToken']),
                ('resultStateToken', row['currentResultStateToken']))):
            reason = 'result_binding_mismatch'
        else:
            partitions = [part for part in manifest.get('partitions', [])
                if part.get('partitionKey') == row['partitionKey']]
            if len(partitions) != 1:
                reason = 'result_partition_unavailable'
            elif any(partitions[0].get(key) != row.get(key) for key in (
                    'currentResultStateToken', 'requiredEpoch', 'publishedEpoch',
                    'definitionDigest', 'presence', 'dependencyTokenDigest')):
                reason = 'result_partition_mismatch'
            elif partitions[0].get('matchesAtRead') is not True:
                reason = 'result_partition_not_current'
            elif status.get('matchesAtRead') is not True:
                producer = status.get('producerStatus') or {}
                candidate = producer.get('reason')
                # Do not expose arbitrary diagnostic text or nested profiles.
                reason = (candidate if isinstance(candidate, str)
                    and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}', candidate)
                    else 'result_not_current')
    return {'matchesAtRead': reason is None, 'reason': reason}


class PostgresCalculationInspection:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("Verified identity is required")
        self.dsn, self.identity = dsn, identity

    def execute(self, scope: ApplicationScope, raw: object) -> dict[str, object]:
        from .postgres_calculation_status import _currentness_read

        function, arguments = _program(raw)
        with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "read", function=function)
            with _currentness_read(db, scope, pin_application_cut=True):
                result = (self._status(db, scope, arguments)
                          if function == STATUS else
                          self._explain(db, scope, arguments))
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=function)
            return result

    def _status(self, db, scope: ApplicationScope,
                arguments: dict) -> dict[str, object]:
        limit = arguments.get("limit", 100)
        rows = load_calculation_scope_states(db, scope,
            definition=(arguments["definitionId"], arguments["definitionStateToken"]),
            after=arguments.get("after"), limit=limit + 1)
        page = rows[:limit]
        from .postgres_calculation_dependencies import read_scope_freshness
        from .postgres_calculation_status import (_currentness_read,
            manifest_currentness_status, published_result_status)
        barrier = impact_processing_barrier(db, scope)
        heads = {}
        # Share the authoritative evaluator's budget and read-cut fence across
        # the page. Keep full evidence internal; only its verdict is public.
        with _currentness_read(db, scope) as read:
            for row in page:
                row.update(read_scope_freshness(db, scope,
                    binding_digest=row['bindingDigest'], stage=row['stage'],
                    partition_key=row['partitionKey'],
                    expected_definition_digest=row['definitionDigest'],
                    impact_barrier=barrier))
                token = row['currentResultStateToken']
                status = None
                if token is not None:
                    if token not in heads:
                        head = db.execute("""SELECT result_key
                            FROM epm.calculation_result_state
                            WHERE workspace_id=%s AND application_id=%s
                              AND state_token=%s""", (scope.workspace_id,
                            scope.application_id, token)).fetchone()
                        current = (published_result_status(db, scope,
                            head['result_key'], token) if head else None)
                        if (current is not None and current.get('evidenceReference')
                                and current.get('manifestCurrentnessStatus') is None):
                            # A prior root may already have visited this head as
                            # a dependency. The shared memo returns compact
                            # evidence; authenticate its exact scope separately.
                            current = {**current, 'manifestCurrentnessStatus':
                                manifest_currentness_status(db, scope, token,
                                    _budget=read.budget, impact_barrier=barrier)}
                        heads[token] = current
                    status = heads[token]
                verdict = _result_verdict(row, arguments, status)
                row['resultCurrentness'] = verdict
                if row['freshness'] == 'current' and not verdict['matchesAtRead']:
                    row.update(freshness='impacted', requiredAction='resolve_dependency')
                row.pop("currentGenerationId", None)
                row.pop("currentFragmentGenerationId", None)
        return {"format": "openepm-calculation-status-v1",
                "definitionId": arguments["definitionId"],
                "definitionStateToken": arguments["definitionStateToken"],
                "rows": page,
                "nextAfter": _key(page[-1]) if len(rows) > limit else None,
                "impactBarrier": barrier}

    def _explain(self, db, scope: ApplicationScope,
                 arguments: dict) -> dict[str, object]:
        binding = db.execute("""SELECT binding_digest,template_digest,
            definition_id,definition_state_token,stage,parameters,
            partition_policy_version FROM epm.calculation_instance_binding
            WHERE workspace_id=%s AND application_id=%s
              AND binding_digest=%s""", (scope.workspace_id,
            scope.application_id, arguments["bindingDigest"])).fetchone()
        if binding is None:
            raise ValueError("CALCULATION_BINDING_UNAVAILABLE")
        template = db.execute("""SELECT definition_digest,compiler_version,
            coverage,template FROM epm.calculation_dependency_template
            WHERE workspace_id=%s AND application_id=%s
              AND template_digest=%s""", (scope.workspace_id,
            scope.application_id, binding["template_digest"])).fetchone()
        if template is None:
            raise ValueError("CALCULATION_TEMPLATE_UNAVAILABLE")
        states = load_calculation_scope_states(db, scope, binding_digest=binding["binding_digest"])
        barrier = impact_processing_barrier(db, scope)
        plan = compile_calculation_work_plan(
            mode=arguments.get("mode", "affected"), states=states,
            impact_barrier_pending=barrier["pending"],
            max_tasks=_SERVER_TASK_LIMIT)
        dependencies = template["template"].get("dependencies", [])
        unresolved = [{"dependencyOrdinal": ordinal,
                       "reason": "INSTANCE_BINDING_NOT_DERIVABLE_FROM_TEMPLATE"}
                      for ordinal, _dependency in enumerate(dependencies[:_EXPLAIN_DEPENDENCY_LIMIT])]
        return {"format": "openepm-calculation-impact-explain-v1",
                "estimateKind": "authorized_current_state",
                "definition": {"definitionId": binding["definition_id"],
                    "stateToken": binding["definition_state_token"],
                    "definitionDigest": template["definition_digest"],
                    "compilerVersion": template["compiler_version"]},
                "binding": {"bindingDigest": binding["binding_digest"],
                    "stage": binding["stage"],
                    "parameters": binding["parameters"],
                    "partitionPolicyVersion":
                        binding["partition_policy_version"]},
                "coverage": template["coverage"],
                "dependencies": dependencies[:_EXPLAIN_DEPENDENCY_LIMIT],
                "dependenciesTruncated": len(dependencies) > _EXPLAIN_DEPENDENCY_LIMIT,
                "dependencyGraph": {"unresolvedBindings": unresolved,
                    "complete": not dependencies},
                "affectedUnitCount": plan.task_count,
                "impactBarrier": barrier,
                "cost": {"outputUpperBound": len(states),
                    "eligibleBackendProfiles": [],
                    "backendSelection": "server_owned",
                    "warnings": (["DEPENDENCY_BINDINGS_UNRESOLVED"]
                                 if dependencies else [])}}

    def recalculate(self, scope: ApplicationScope, raw: object, *,
                    idempotency_key: str, admission_secret: bytes | None = None,
                    replay_only: bool = False) -> dict[str, object]:
        """Persist a pinned work request; workers retain all execution fences."""
        from .operation_admission_contract import (authenticate_operation_admission,
            is_signed_operation_id, validate_operation_admission)
        from .postgres_calculation_work import (
            lock_and_read_calculation_work_request, persist_calculation_work_request)
        from .postgres_jobs import _canonical_digest

        arguments = _recalculate_arguments(raw)
        signed = is_signed_operation_id(idempotency_key)
        if replay_only and not signed:
            raise ValueError("OPERATION_ADMISSION_EXPIRED")
        if signed:
            authenticate = authenticate_operation_admission if replay_only else validate_operation_admission
            authenticate(admission_secret, scope, self.identity, operation_id=idempotency_key,
                         function=RECALCULATE, intent_digest=_canonical_digest(raw))
        with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "read", function=RECALCULATE)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "write", function=RECALCULATE)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "rule_run", function=RECALCULATE)
            if signed:
                prior = lock_and_read_calculation_work_request(db, scope, issuer=self.identity.issuer,
                    subject_id=self.identity.subject_id, idempotency_key=idempotency_key)
                if prior is not None:
                    # The verified original program pins the barrier accepted with this key.
                    epoch = arguments["expectedImpactEpoch"]
                    return _recalculation_result(arguments["bindingDigest"],
                        {"impactEpoch": epoch, "processedImpactEpoch": epoch, "pending": False},
                        {"requestId": prior["request_id"], "status": prior["status"], "duplicate": True,
                         "compatible": False, "taskCount": prior["task_count"]})
                if replay_only:
                    raise ValueError("OPERATION_ADMISSION_EXPIRED")
            binding = db.execute("""SELECT template.definition_digest FROM
                epm.calculation_instance_binding AS binding JOIN
                epm.calculation_dependency_template AS template ON
                  template.workspace_id=binding.workspace_id AND
                  template.application_id=binding.application_id AND
                  template.template_digest=binding.template_digest
                WHERE binding.workspace_id=%s AND binding.application_id=%s
                  AND binding.binding_digest=%s""", (
                scope.workspace_id, scope.application_id,
                arguments["bindingDigest"])).fetchone()
            if binding is None:
                raise ValueError("CALCULATION_BINDING_UNAVAILABLE")
            if binding["definition_digest"] != arguments["expectedDefinitionDigest"]:
                raise ValueError("DEFINITION_REVALIDATION_REQUIRED")
            barrier = impact_processing_barrier(db, scope)
            if barrier["pending"]:
                raise ValueError("IMPACT_COVERAGE_PENDING")
            if barrier["processedImpactEpoch"] != arguments["expectedImpactEpoch"]:
                raise ValueError("CALCULATION_IMPACT_EPOCH_STALE")
            states = load_calculation_scope_states(db, scope, binding_digest=arguments["bindingDigest"])
            plan = compile_calculation_work_plan(
                mode=arguments.get("mode", "affected"), states=states,
                impact_barrier_pending=False, max_tasks=_SERVER_TASK_LIMIT)
            result = persist_calculation_work_request(
                db, scope, plan=plan, issuer=self.identity.issuer,
                subject_id=self.identity.subject_id,
                idempotency_key=idempotency_key)
            return _recalculation_result(arguments["bindingDigest"], barrier, result)
