"""The current SDK source and its typed rule owner must agree in this application."""

from .postgres_access import AccessDenied


RULE_OWNER = """ AND d.declared_output->>'kind'='ApplicationRule'
    AND EXISTS (SELECT 1 FROM epm.expression_rule_definition r
        WHERE (r.workspace_id,r.application_id,r.source_program_id,r.source_token,r.source_digest)
            =(d.workspace_id,d.application_id,d.program_id,d.source_token,d.source_digest)
          AND r.definition_kind='ApplicationRule' AND r.ownership_state='Source' AND r.status=d.status
          AND r.rule_id=d.declared_output->>'definitionId')"""


def require_design_target(db, scope, definition, current):
    declared = definition.get("declaredOutput")
    if not declared or declared["kind"] != "ApplicationRule":
        raise AccessDenied("RULE_SOURCE_DESIGN_TARGET_UNAVAILABLE")
    owner = db.execute(
        """SELECT definition_kind,status,ownership_state,source_program_id,source_token,source_digest
        FROM epm.expression_rule_definition WHERE workspace_id=%s AND application_id=%s AND rule_id=%s FOR UPDATE""",
        (scope.workspace_id, scope.application_id, declared["definitionId"]),
    ).fetchone()
    if current is None and owner is None:
        return
    if (
        current is not None
        and current["status"] == "Inactive"
        and current["declared_output"] == declared
        and owner is not None
        and owner["definition_kind"] == "ApplicationRule"
        and owner["status"] == "Inactive"
        and owner["ownership_state"] == "Source"
        and owner["source_program_id"] == current["program_id"]
        and owner["source_token"] == current["source_token"]
        and owner["source_digest"] == current["source_digest"]
    ):
        return
    raise AccessDenied("RULE_SOURCE_DESIGN_TARGET_UNAVAILABLE")


def require_impact_source(db, scope, source, *, published=False):
    if not source:
        raise AccessDenied("RULE_IMPACT_SOURCE_UNAVAILABLE")
    row = db.execute(
        """SELECT d.declared_output->>'definitionId' AS rule_id FROM epm.python_program_definition d
        WHERE d.workspace_id=%s AND d.application_id=%s AND d.program_id=%s AND d.source_token=%s
          AND d.status=%s"""
        + RULE_OWNER,
        (scope.workspace_id, scope.application_id, *source, "Active" if published else "Inactive"),
    ).fetchone()
    if row is None:
        raise AccessDenied("RULE_IMPACT_SOURCE_UNAVAILABLE")
    return row["rule_id"]


def require_build_source(db, scope, identity, source, build_id, purpose):
    if purpose == "ImpactTest":
        return require_impact_source(db, scope, source)
    if purpose == "Validation":
        return require_automatic_rule_validation(db, scope, identity, source, build_id)
    raise AccessDenied("RULE_SOURCE_VALIDATION_UNAVAILABLE")


def require_automatic_rule_validation(db, scope, identity, source, build_id):
    if not source:
        raise AccessDenied("RULE_SOURCE_VALIDATION_UNAVAILABLE")
    row = db.execute(
        """SELECT d.declared_output->>'definitionId' AS rule_id
        FROM epm.python_program_definition d JOIN epm.operation_receipt receipt
          ON (receipt.workspace_id,receipt.application_id,receipt.operation_id)
            =(d.workspace_id,d.application_id,d.updated_operation_id)
        WHERE d.workspace_id=%s AND d.application_id=%s AND d.program_id=%s AND d.source_token=%s
          AND d.status='Inactive' AND d.updated_issuer=%s AND d.updated_subject_id=%s
          AND receipt.result->'validation'->>'buildId'=%s"""
        + RULE_OWNER,
        (scope.workspace_id, scope.application_id, *source, identity.issuer, identity.subject_id, build_id),
    ).fetchone()
    if row is None:
        raise AccessDenied("RULE_SOURCE_VALIDATION_UNAVAILABLE")
    return row["rule_id"]


NUMERIC_RULE_OPERATIONS = frozenset(("facts.numeric.sequence", "facts.numeric.batch"))


def require_numeric_rule_declaration(rule_id, function, arguments, *, impact=False):
    """Admit only the checked typed owner and its bounded numerical statement family."""
    unavailable = "RULE_SOURCE_VALIDATION_OPERATION_UNAVAILABLE"
    if function != "application.rule.save" or arguments.get("ruleId") != rule_id:
        raise AccessDenied(unavailable)
    definition = arguments.get("definition")
    units = definition.get("units") if isinstance(definition, dict) else None
    if not isinstance(units, list) or not units:
        raise AccessDenied(unavailable)
    if impact:
        parameters = definition.get("parameters", [])
        if not isinstance(parameters, list) or any(
                not isinstance(p, dict) or p.get("type") not in ("Amount", "Ratio") for p in parameters):
            raise AccessDenied("RULE_IMPACT_PARAMETER_UNAVAILABLE")
    for unit in units:
        operations = unit.get("operations") if isinstance(unit, dict) else None
        if not isinstance(operations, list) or not operations:
            raise AccessDenied(unavailable)
        if any(
            not isinstance(op, dict) or op.get("function") not in NUMERIC_RULE_OPERATIONS for op in operations
        ):
            raise AccessDenied(unavailable)


def designer_validation_statuses(db, scope, sources, identity, authority_digest):
    """Expose only progress of the caller's exact automatic validation, under current authority."""
    from psycopg.types.json import Jsonb

    if not sources:
        return {}
    rows = db.execute(
        """SELECT d.program_id,d.source_token,b.build_id,b.status,
          (b.expected_metadata_revision=s.metadata_revision AND b.expected_policy_revision=s.policy_revision
           AND b.expected_schema_epoch=s.schema_epoch AND (b.status<>'sealed' OR COALESCE(
               a.sealed_at>clock_timestamp()-interval '24 hours',false))) AS current
        FROM jsonb_to_recordset(%s::jsonb) supplied(program_id text,source_token text)
        JOIN epm.python_program_definition d USING(program_id,source_token)
        JOIN epm.application_state s USING(workspace_id,application_id)
        JOIN epm.operation_receipt receipt ON (receipt.workspace_id,receipt.application_id,receipt.operation_id)
            =(d.workspace_id,d.application_id,d.updated_operation_id)
        JOIN epm.python_program_build b ON (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
            =(d.workspace_id,d.application_id,d.program_id,d.source_token)
            AND b.build_id=receipt.result->'validation'->>'buildId' AND b.purpose='Validation'
        LEFT JOIN epm.python_plan_artifact a ON (a.workspace_id,a.application_id,a.build_id)
            =(b.workspace_id,b.application_id,b.build_id)
        WHERE d.workspace_id=%s AND d.application_id=%s AND d.status='Inactive'
          AND (b.issuer,b.subject_id)=(d.updated_issuer,d.updated_subject_id)
          AND (b.issuer,b.subject_id,b.authorization_scope_digest)=(%s,%s,%s)"""
        + RULE_OWNER,
        (
            Jsonb([{"program_id": p, "source_token": t} for p, t in sources]),
            scope.workspace_id,
            scope.application_id,
            identity.issuer,
            identity.subject_id,
            authority_digest,
        ),
    ).fetchall()
    return {
        (r["program_id"], r["source_token"]): {
            "buildId": r["build_id"],
            "taskId": "p:" + r["build_id"],
            "purpose": "Validation",
            "status": r["status"],
            "current": r["current"],
            "ownedByCaller": True,
        }
        for r in rows
    }


def _normalized_rule_operation(program):
    from .postgres_numeric_sequence import compile_program
    if program['function'] == 'facts.numeric.sequence':
        return compile_program(program)
    if program['function'] == 'facts.numeric.batch':
        from .postgres_language_v2 import compile_numeric_program
        return {'function': program['function'], 'statements': [
            {'series_key': m.coordinate.series_key, 'members': dict(m.coordinate.members), 'op': m.kind.value}
            for m in compile_numeric_program(program)]}
    raise AccessDenied('RULE_RUN_TARGET_UNAVAILABLE')


def authorize_rule_points(db, identity, scope, program, *, check_planning=False):
    """Use the underlying numeric compiler and current dimensional decision for each target."""
    from .postgres_numeric_sequence import enforce_sequence_dimensional_security
    normalized = _normalized_rule_operation(program)
    enforce_sequence_dimensional_security(db, identity, scope, normalized)
    if check_planning:
        from .postgres_numeric_sequence import enforce_sequence_target_policy
        enforce_sequence_target_policy(db, scope, normalized, "Assigned", identity=identity)


def _sample_points(row):
    from .postgres_application_rules import bind_definition
    from .python_plan_runner import SealedPlanRunner
    definition = row['program']['arguments']
    require_numeric_rule_declaration(row['rule_id'], 'application.rule.save',
        {'ruleId':row['rule_id'], 'definition':definition}, impact=True)
    bound, _ = bind_definition(definition, None, samples=True)
    for unit in bound['units']:
        operation = _normalized_rule_operation(SealedPlanRunner._atomic_operation(unit))
        for statement in operation['statements']:
            yield tuple(sorted(statement['members'].items()))


def runnable_rules(db, identity, scope, rows):
    """Prove each rule independently using its exact current SDK owner and every compiled target."""
    from .dimensional_security_policy import AccessKind
    from .postgres_definition_lifecycle import current_state, resolution_context
    from .postgres_dimensional_security import PostgresDimensionalSecurityResolver as Resolver
    from .postgres_jobs import _canonical_digest

    rows = [r for r in rows if r and r['status']=='Active' and r['definition_kind']=='ApplicationRule'
            and r['ownership_state']=='Source' and isinstance(r['program'],dict)
            and isinstance(r['program'].get('arguments'),dict) and r['program_digest']==_canonical_digest(r['program'])]
    if not rows:
        return []
    owners = db.execute("""SELECT d.program_id,d.source_token,d.source_digest,d.declared_output->>'definitionId' AS id
        FROM epm.python_program_definition d WHERE d.workspace_id=%s AND d.application_id=%s
        AND d.status='Active' AND d.program_id=ANY(%s)""" + RULE_OWNER,
        (scope.workspace_id,scope.application_id,[r['source_program_id'] for r in rows])).fetchall()
    sources = {(r['program_id'],r['source_token'],r['source_digest'],r['id']) for r in owners}
    context = resolution_context(db,scope,rows)
    rows = [r for r in rows if (r['source_program_id'],r['source_token'],r['source_digest'],r['rule_id']) in sources
            and current_state(r,context)['executable']]
    if not rows:
        return []
    active = Resolver.active_policy_in_transaction(db,identity,scope)
    if active is None:
        return []
    policy, _, _, revision = active
    denied = set()
    users = {}

    def check_points():
        points = tuple(dict(point) for point in users)
        for kind in (AccessKind.READ, AccessKind.WRITE):
            try:
                decisions = Resolver.resolve_many_in_transaction(db,identity,scope,kind=kind,
                    policy=policy,coordinates=points,deny_unavailable_points=True)
            except AccessDenied:
                denied.update(row['rule_id'] for row in rows)
                users.clear()
                return
            for rule_ids,outcome in zip(users.values(),decisions,strict=True):
                if outcome.security_revision!=revision:
                    raise AccessDenied('RULE_RUN_TARGET_UNAVAILABLE')
                if not outcome.decision.allowed:
                    denied.update(rule_ids)
        users.clear()

    for row in rows:
        rule_id = row['rule_id']
        if rule_id in denied:
            continue
        try:
            for point in _sample_points(row):
                users.setdefault(point,set()).add(rule_id)
                if len(users)==1000:
                    check_points()
                    if rule_id in denied:
                        break
        except ValueError:
            denied.add(rule_id)
    if users:
        check_points()
    return [r for r in rows if r['rule_id'] not in denied]


def require_runnable_rule(db, identity, scope, row):
    try:
        allowed = runnable_rules(db,identity,scope,[row])
    except ValueError as exc:
        raise AccessDenied('RULE_RUN_TARGET_UNAVAILABLE') from exc
    if not allowed:
        raise AccessDenied('RULE_RUN_TARGET_UNAVAILABLE')
