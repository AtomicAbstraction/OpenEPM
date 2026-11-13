"""Authorized W09 calculation status and bounded affected-work explanation."""
from __future__ import annotations

import re

from psycopg.rows import dict_row

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
_SERVER_TASK_LIMIT = 10_000


def catalog() -> dict[str, dict[str, object]]:
    common = {"mode": "read", "permission": "read",
              "previewRequired": False, "idempotencyRequired": False,
              "workClass": "bounded_read"}
    return {
        STATUS: {**common, "arguments": {
            "definitionId": "exact definition identity",
            "definitionStateToken": "exact current definition state token",
            "limit": "1-500 status rows",
            "after": "optional binding/stage/partition continuation"},
            "result": "authorized currentness, reasons, presence, coverage, generations and impact barrier"},
        EXPLAIN: {**common, "arguments": {
            "bindingDigest": "exact authorized instance binding digest",
            "mode": "affected, force_populated or force_domain"},
            "result": "read-only business impact, declared dependencies, estimates, currentness and cost warnings"},
        RECALCULATE: {"mode": "durable_write", "permission": "rule_run",
            "previewRequired": False, "idempotencyRequired": True,
            "workClass": "long", "arguments": {
                "bindingDigest": "exact published instance binding digest",
                "mode": "affected, force_populated or force_domain",
                "expectedDefinitionDigest": "exact immutable definition digest",
                "expectedImpactEpoch": "nonnegative processed impact epoch pin"},
            "result": "durable logical recalculation request identity and status"},
    }


def _program(raw: object) -> tuple[str, dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
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
                or not 1 <= arguments.get("limit", 100) <= 500
                or ("after" in arguments
                    and (not isinstance(arguments["after"], str)
                         or len(arguments["after"]) > 600))):
            raise ValueError("CALCULATION_STATUS_ARGUMENTS_INVALID")
    elif (set(arguments) - {"bindingDigest", "mode"}
          or not isinstance(arguments.get("bindingDigest"), str)
          or _DIGEST.fullmatch(arguments["bindingDigest"]) is None
          or arguments.get("mode", "affected") not in {
              "affected", "force_populated", "force_domain"}):
        raise ValueError("CALCULATION_EXPLAIN_ARGUMENTS_INVALID")
    return function, arguments


def _recalculate_arguments(raw: object) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
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
            or arguments.get("mode", "affected") not in {
                "affected", "force_populated", "force_domain"}
            or type(arguments.get("expectedImpactEpoch")) is not int
            or arguments["expectedImpactEpoch"] < 0):
        raise ValueError("CALCULATION_RECALCULATE_ARGUMENTS_INVALID")
    return arguments


def _key(row: dict) -> str:
    return "\x1f".join((row["bindingDigest"], row["stage"],
                         row["partitionKey"]))


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
        function, arguments = _program(raw)
        with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "read", function=function)
            result = (self._status(db, scope, arguments)
                      if function == STATUS else
                      self._explain(db, scope, arguments))
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "read", function=function)
            return result

    @staticmethod
    def _states(db, scope: ApplicationScope, definition_id: str,
                definition_state_token: str) -> list[dict[str, object]]:
        allowed = {row["binding_digest"] for row in db.execute("""SELECT
            binding_digest FROM epm.calculation_instance_binding
            WHERE workspace_id=%s AND application_id=%s
              AND definition_id=%s AND definition_state_token=%s""", (
            scope.workspace_id, scope.application_id, definition_id,
            definition_state_token)).fetchall()}
        return [row for row in load_calculation_scope_states(db, scope)
                if row["bindingDigest"] in allowed]

    def _status(self, db, scope: ApplicationScope,
                arguments: dict) -> dict[str, object]:
        rows = self._states(db, scope, arguments["definitionId"],
                            arguments["definitionStateToken"])
        after = arguments.get("after")
        if after is not None:
            rows = [row for row in rows if _key(row) > after]
        limit = arguments.get("limit", 100)
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
        states = [row for row in load_calculation_scope_states(db, scope)
                  if row["bindingDigest"] == binding["binding_digest"]]
        barrier = impact_processing_barrier(db, scope)
        plan = compile_calculation_work_plan(
            mode=arguments.get("mode", "affected"), states=states,
            impact_barrier_pending=barrier["pending"],
            max_tasks=_SERVER_TASK_LIMIT)
        dependencies = template["template"].get("dependencies", [])
        unresolved = [{"dependencyOrdinal": ordinal,
                       "reason": "INSTANCE_BINDING_NOT_DERIVABLE_FROM_TEMPLATE"}
                      for ordinal, _dependency in enumerate(dependencies[:500])]
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
                "dependencies": dependencies[:500],
                "dependenciesTruncated": len(dependencies) > 500,
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
                    idempotency_key: str) -> dict[str, object]:
        """Persist a pinned work request; workers retain all execution fences."""
        arguments = _recalculate_arguments(raw)
        from .postgres_calculation_work import (
            load_calculation_scope_states, persist_calculation_work_request)
        from .calculation_work_contract import compile_calculation_work_plan
        with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "read", function=RECALCULATE)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "write", function=RECALCULATE)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "rule_run", function=RECALCULATE)
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
            if (barrier["pending"] or barrier["processedImpactEpoch"] !=
                    arguments["expectedImpactEpoch"]):
                raise ValueError("IMPACT_COVERAGE_PENDING")
            states = [row for row in load_calculation_scope_states(db, scope)
                if row["bindingDigest"] == arguments["bindingDigest"]]
            plan = compile_calculation_work_plan(
                mode=arguments.get("mode", "affected"), states=states,
                impact_barrier_pending=False, max_tasks=_SERVER_TASK_LIMIT)
            result = persist_calculation_work_request(
                db, scope, plan=plan, issuer=self.identity.issuer,
                subject_id=self.identity.subject_id,
                idempotency_key=idempotency_key)
            return {**result, "format": "openepm-calculation-recalculate-v1",
                    "bindingDigest": arguments["bindingDigest"],
                    "affectedUnitCount": plan.task_count,
                    "impactBarrier": barrier}
