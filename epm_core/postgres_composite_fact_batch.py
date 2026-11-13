"""One fixed-core transaction for numeric, text, and supporting detail."""
from __future__ import annotations

from dataclasses import dataclass, replace
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import (
    PostgresJobQueue, _canonical_digest, _decode_detail_program,
    _decode_numeric_program, _decode_text_program, _detail_program,
    _numeric_program, _require_python_job_authority, _text_program,
)
from .postgres_numeric_store import PostgresNumericFactStore


FUNCTION = 'facts.composite.batch'
COMPILER_V1 = 'fixed-composite-fact-batch-v1'
COMPILER = 'fixed-composite-fact-batch-v2'
SUPPORTED = frozenset({'facts.numeric.batch', 'facts.text.batch',
                       'facts.line-detail.replace'})
PLAN_DIGEST_V1 = _canonical_digest({
    'function': FUNCTION, 'version': 1, 'publishers': sorted(SUPPORTED),
    'atomic': 'one_transaction_one_receipt_one_revision',
    'overlap': 'rejected',
})
PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'version': 2, 'publishers': sorted(SUPPORTED),
    'atomic': 'one_transaction_one_receipt_one_revision',
    'sameFamilyPriorResult': 'shared_revision_and_prior_ordinal',
    'crossTypeCollision': 'rejected',
})
_PRIOR = '@composite-prior-result'
_JOB_ID = re.compile(r'[A-Za-z0-9._:-]{1,200}')


@dataclass(frozen=True, slots=True)
class CompositePlan:
    operations: tuple[dict, ...]
    version: int = 2

    @property
    def normalized_program(self) -> dict:
        return {'version': self.version, 'function': FUNCTION,
                'operations': list(self.operations),
                'transaction': 'one_application_transaction'}


def _with_prior_markers(operation: dict, prior: dict) -> dict:
    """Add a private CAS marker only for an omitted later same-family pin."""
    family = operation.get('function')
    if family in ('facts.numeric.batch', 'facts.text.batch'):
        if (set(operation) != {'languageVersion', 'function', 'arguments'}
                or type(operation.get('arguments')) is not dict
                or set(operation['arguments']) != {'mutations'}
                or type(operation['arguments']['mutations']) is not list):
            return operation
        rows = []
        for source in operation['arguments']['mutations']:
            if type(source) is not dict or type(source.get('coordinate')) is not dict:
                rows.append(source)
                continue
            row = dict(source)
            from .persistence_contract import Coordinate
            coordinate = Coordinate.from_mapping(row['coordinate'])
            previous = prior.get(coordinate)
            if previous is None:
                if 'expectedChangeId' not in row:
                    raise ValueError('COMPOSITE_FIRST_TOUCH_CHANGE_ID_REQUIRED')
                if row['expectedChangeId'] == _PRIOR:
                    raise ValueError('COMPOSITE_RESERVED_CHANGE_ID')
            elif previous != family:
                raise ValueError('COMPOSITE_CROSS_TYPE_COLLISION')
            elif 'expectedChangeId' in row:
                raise ValueError('COMPOSITE_LATER_TOUCH_CHANGE_ID_FORBIDDEN')
            else:
                row['expectedChangeId'] = _PRIOR
            rows.append(row)
        return {**operation, 'arguments': {'mutations': rows}}
    if family == 'facts.line-detail.replace' and type(operation.get('arguments')) is dict:
        args = dict(operation['arguments'])
        from .persistence_contract import Coordinate
        coordinate = Coordinate.from_mapping(args.get('coordinate'))
        previous = prior.get(coordinate)
        pins = ('expectedCellChangeId', 'expectedDetailChangeId')
        present = tuple(key in args for key in pins)
        if previous is None:
            if present != (True, True):
                raise ValueError('COMPOSITE_FIRST_TOUCH_CHANGE_ID_REQUIRED')
            if any(args[key] == _PRIOR for key in pins):
                raise ValueError('COMPOSITE_RESERVED_CHANGE_ID')
        elif previous != family:
            raise ValueError('COMPOSITE_CROSS_TYPE_COLLISION')
        else:
            # Detail history intentionally has one coordinate event per
            # revision.  Replacing it twice would erase the intermediate
            # lineage rather than represent an ordered durable action.
            raise ValueError('COMPOSITE_DETAIL_REPEAT_UNSUPPORTED')
        return {**operation, 'arguments': args}
    return operation


def _compile_external(operation: dict, prior: dict) -> tuple[dict, tuple]:
    operation = _with_prior_markers(operation, prior)
    family = operation.get('function')
    if family == 'facts.numeric.batch':
        from .postgres_language_v2 import compile_numeric_program
        values = compile_numeric_program(operation)
        return _numeric_program(values), tuple(x.coordinate for x in values)
    if family == 'facts.text.batch':
        from .postgres_language_v2 import compile_text_program
        values = compile_text_program(operation)
        return _text_program(values), tuple(x.coordinate for x in values)
    if family == 'facts.line-detail.replace':
        from .postgres_line_detail_job import compile_program as compile_detail
        values = compile_detail(operation)
        return _detail_program(*values), (values[0],)
    raise ValueError('COMPOSITE_PUBLISHER_UNSUPPORTED')


def compile_program(raw: object) -> CompositePlan:
    if (type(raw) is not dict
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or raw.get('languageVersion') != 2
            or raw.get('function') != FUNCTION
            or type(raw.get('arguments')) is not dict
            or set(raw['arguments']) != {'operations'}
            or type(raw['arguments']['operations']) is not list
            or not 3 <= len(raw['arguments']['operations']) <= 100):
        raise ValueError('V2_COMPOSITE_BATCH_INVALID')
    normalized = []
    coordinate_families = {}
    families = set()
    mutation_count = 0
    for operation in raw['arguments']['operations']:
        if type(operation) is not dict:
            raise ValueError('COMPOSITE_PUBLISHER_UNSUPPORTED')
        canonical, points = _compile_external(operation, coordinate_families)
        family = canonical['function']
        families.add(family)
        for coordinate in points:
            previous = coordinate_families.get(coordinate)
            if previous is not None and previous != family:
                raise ValueError('COMPOSITE_CROSS_TYPE_COLLISION')
            coordinate_families[coordinate] = family
            mutation_count += 1
            if mutation_count > 500:
                raise ValueError('COMPOSITE_BATCH_LIMIT')
        normalized.append(canonical)
    if families != SUPPORTED:
        raise ValueError('COMPOSITE_REQUIRED_FAMILIES_MISSING')
    return CompositePlan(tuple(normalized), 2)


def _external_program(operation: dict) -> dict:
    family = operation.get('function')
    if family == 'facts.numeric.batch':
        rows = []
        for item in _decode_numeric_program(operation):
            row = {'coordinate': dict(item.coordinate.members),
                   'op': item.kind.value}
            if item.expected_change_id != _PRIOR:
                row['expectedChangeId'] = item.expected_change_id
            if item.amount is not None:
                row['value'] = {'type': 'AmountLiteral',
                                'decimal': format(item.amount, 'f')}
            rows.append(row)
        return {'languageVersion': 2, 'function': family,
                'arguments': {'mutations': rows}}
    if family == 'facts.text.batch':
        rows = []
        for item in _decode_text_program(operation):
            row = {'coordinate': dict(item.coordinate.members),
                   'op': item.kind.value}
            if item.expected_change_id != _PRIOR:
                row['expectedChangeId'] = item.expected_change_id
            if item.value is not None:
                row['value'] = {'type': 'TextLiteral', 'text': item.value}
            rows.append(row)
        return {'languageVersion': 2, 'function': family,
                'arguments': {'mutations': rows}}
    if family == 'facts.line-detail.replace':
        coordinate, items, cell_change, detail_change = (
            _decode_detail_program(operation))
        arguments = {
            'coordinate': dict(coordinate.members),
            'items': [{'description': item.description,
                       'amount': format(item.amount, 'f')} for item in items],
        }
        if (cell_change, detail_change) != (_PRIOR, _PRIOR):
            arguments.update({'expectedCellChangeId': cell_change,
                              'expectedDetailChangeId': detail_change})
        return {'languageVersion': 2, 'function': family,
                'arguments': arguments}
    raise ValueError('COMPOSITE_PUBLISHER_UNSUPPORTED')


def decode_program(raw: object) -> CompositePlan:
    if (type(raw) is not dict
            or set(raw) != {'version', 'function', 'operations', 'transaction'}
            or raw.get('version') not in (1, 2) or raw.get('function') != FUNCTION
            or raw.get('transaction') != 'one_application_transaction'
            or type(raw.get('operations')) is not list):
        raise ValueError('UNSUPPORTED_COMPOSITE_JOB_PROGRAM')
    external = [_external_program(operation) for operation in raw['operations']]
    current = compile_program({'languageVersion': 2, 'function': FUNCTION,
                               'arguments': {'operations': external}})
    plan = (current if raw['version'] == 2
            else CompositePlan(current.operations, 1))
    if plan.normalized_program != raw:
        raise ValueError('NONCANONICAL_COMPOSITE_JOB_PROGRAM')
    return plan


def compiler_for(program: dict) -> tuple[str, str]:
    version = program.get('version') if isinstance(program, dict) else None
    if version == 1:
        return COMPILER_V1, PLAN_DIGEST_V1
    if version == 2:
        return COMPILER, PLAN_DIGEST
    raise ValueError('UNSUPPORTED_COMPOSITE_JOB_PROGRAM')


def _first_touch_operations(program: dict) -> list[dict]:
    """Return ordinary V2 operations sufficient to validate initial state."""
    from .persistence_contract import Coordinate

    seen = set()
    result = []
    for operation in program['arguments']['operations']:
        family = operation['function']
        if family in ('facts.numeric.batch', 'facts.text.batch'):
            rows = []
            for row in operation['arguments']['mutations']:
                coordinate = Coordinate.from_mapping(row['coordinate'])
                if coordinate not in seen:
                    rows.append(row)
                    seen.add(coordinate)
            if rows:
                result.append({**operation,
                    'arguments': {'mutations': rows}})
        else:
            coordinate = Coordinate.from_mapping(
                operation['arguments']['coordinate'])
            if coordinate not in seen:
                result.append(operation)
                seen.add(coordinate)
    return result


def preview(language, scope: ApplicationScope, program: dict) -> dict:
    plan = compile_program(program)
    vectors = [language.preview(scope, operation)['revisionVector']
               for operation in _first_touch_operations(program)]
    if any(vector != vectors[0] for vector in vectors[1:]):
        raise ValueError('COMPOSITE_PREVIEW_REVISION_CHANGED')
    token, digest = language._sign_preview(
        scope, FUNCTION, plan.normalized_program, vectors[0])
    return {'languageVersion': 2, 'function': FUNCTION,
            'programDigest': digest, 'revisionVector': vectors[0],
            'operationCount': len(plan.operations), 'previewToken': token,
            'compilerVersion': COMPILER, 'planDigest': PLAN_DIGEST}


def submit(language, scope: ApplicationScope, program: dict, *,
           preview_token: str, idempotency_key: str,
           depends_on_job_ids: tuple[str, ...] = (),
           execution_authority: dict | None = None) -> dict:
    plan = compile_program(program)
    payload = language._unpack_preview(scope, FUNCTION, preview_token)
    if payload.get('programDigest') != _canonical_digest(plan.normalized_program):
        raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    revisions = payload['revisions']
    return PostgresJobQueue(language.dsn, identity=language.identity).submit(
        scope, idempotency_key=idempotency_key, function_name=FUNCTION,
        normalized_program=plan.normalized_program, compiler_version=COMPILER,
        plan_digest=PLAN_DIGEST,
        expected_metadata_revision=revisions['metadata_revision'],
        expected_data_revision=revisions['data_revision'],
        expected_policy_revision=revisions['policy_revision'],
        depends_on_job_ids=depends_on_job_ids,
        execution_authority=execution_authority)


def _composite_replay(db, scope, job, receipt):
    if receipt is None:
        return None
    if (job is None or job['status'] != 'published'
            or job['receipt_revision'] != receipt['committed_revision']
            or job['result'] != receipt['result']
            or job['subject_id'] != receipt['actor_id']):
        raise ValueError('COMPOSITE_RECEIPT_CONFLICT')
    PostgresNumericFactStore._require_replay_impact(
        db,scope,job['job_id'],receipt)
    return receipt['result']


def _composite_impact(decoded, prepared, *, operation_id, revision):
    """Collapse ordered composite effects to one semantic target effect."""
    from .calculation_impact_contract import (
        compile_calculation_impact, fact_effect)
    numeric_final={};text_final={}
    for family,values in decoded:
        if family == 'facts.numeric.batch':
            numeric_final.update((item.coordinate.series_key,item.kind.value)
                                 for item in values)
        elif family == 'facts.text.batch':
            text_final.update((item.coordinate.series_key,item.kind.value)
                              for item in values)
    effects=[]
    for row in prepared['numeric']:
        final=numeric_final[row['series_key']]
        effects.append(fact_effect(domain='numeric_fact',change='replace',
            object_id=row['series_key'],members=row['members'],
            old_present=row['before_present'],new_present=final!='clear'))
    for row in prepared['text']:
        final=text_final[row['series_key']]
        effects.append(fact_effect(domain='text_fact',change='replace',
            object_id=row['series_key'],members=row['members'],
            old_present=row['prior_present'],new_present=final=='set'))
    for coordinate,before in prepared['detail']:
        effects.append({'domain':'line_detail','change':'replace',
            'objectType':'line_detail','objectId':coordinate.series_key,
            'scope':[{'dimensionId':axis,'memberId':member}
                     for axis,member in coordinate.members],
            'reason':'data_changed',
            'oldPresence':'present' if before[3] else 'absent',
            'newPresence':'present'})
    return compile_calculation_impact({
        'format':'openepm-calculation-impact-v1',
        'sourceKind':'source_replace','sourceId':operation_id,
        'causalRevision':revision,'effects':effects})


def _prepare_composite(db, scope, plan, workflow_role,*,fact_state=None):
    """Prepare all caller-visible inputs without taking the mutation row.

    Later same-family touches depend only on an earlier operation in this
    atomic unit.  Their private marker is resolved during publication; every
    first touch is pinned here and rechecked under the final fence.
    """
    from .postgres_line_detail import PostgresLineDetailStore
    from .postgres_numeric_batch import prepare as prepare_numeric
    from .postgres_text_batch import prepare as prepare_text
    from .postgres_planning_write_guard import enforce_active_planning_policy

    decoded, writes = [], []
    numeric_first, text_first, detail_first = [], [], []
    for operation in plan.operations:
        family = operation['function']
        if family == 'facts.numeric.batch':
            values = _decode_numeric_program(operation)
            names = {'set': 'Set', 'add': 'Add', 'clear': 'Clear'}
            writes.extend((item.coordinate,names[item.kind.value])
                          for item in values)
            numeric_first.extend(item for item in values
                                 if item.expected_change_id != _PRIOR)
        elif family == 'facts.text.batch':
            values = _decode_text_program(operation)
            names = {'set': 'Set', 'clear': 'Clear'}
            writes.extend((item.coordinate,names[item.kind.value])
                          for item in values)
            text_first.extend(item for item in values
                              if item.expected_change_id != _PRIOR)
        else:
            values = _decode_detail_program(operation)
            writes.append((values[0],'ReplaceDetail'))
            current = (PostgresLineDetailStore._current_inputs(
                db,scope,values[0],False) if fact_state is None else
                fact_state.detail_inputs(db,scope,values[0]))
            PostgresLineDetailStore._validate_inputs(
                current,values[2],values[3])
            detail_first.append((values[0],current))
        decoded.append((family,values))
    prepared = {
        'numeric': prepare_numeric(db,scope,tuple(numeric_first),fact_state=fact_state),
        'text': prepare_text(db,scope,tuple(text_first),fact_state=fact_state),
        'detail': detail_first,
    }
    policy = enforce_active_planning_policy(
        db,scope,writes=tuple(writes),workflow_role=workflow_role,
        ordered_actions=plan.version >= 2)
    return decoded,prepared,policy


def ordered_operations(decoded,revision):
    """Resolve the same-family prior-result marker and shared event ordinals.

    Both publication and private evaluation consume this iterator. No input
    lookup or database write happens here; the existing family preparation
    kernels remain authoritative for types, CAS, arithmetic and constraints.
    """
    last_change={}
    ordinal=0
    for family,values in decoded:
        if family in ('facts.numeric.batch','facts.text.batch'):
            resolved=tuple(replace(item,
                expected_change_id=last_change[item.coordinate])
                if item.expected_change_id==_PRIOR else item for item in values)
            yield family,resolved,ordinal
            for index,item in enumerate(resolved,ordinal+1):
                last_change[item.coordinate]=f'{revision}:{index}'
            ordinal+=len(resolved)
        else:
            yield family,values,ordinal
            last_change[values[0]]=f'{revision}:{ordinal+1}'
            ordinal+=1


def _recheck_composite(db, scope, prepared):
    from .postgres_line_detail import PostgresLineDetailStore
    from .postgres_numeric_batch import recheck_prepared_inputs as numeric_recheck
    from .postgres_text_batch import recheck_prepared_inputs as text_recheck

    numeric_recheck(db,scope,prepared['numeric'])
    text_recheck(db,scope,prepared['text'])
    for coordinate,before in prepared['detail']:
        current = PostgresLineDetailStore._current_inputs(
            db,scope,coordinate,False)
        if not PostgresLineDetailStore._same_inputs(before,current):
            raise ValueError('STALE_DETAIL_CHANGE_ID')


class PostgresCompositeFactPublisher:
    """Publish all supported effects in one short, fenced transaction."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 fault_after_family: str | None = None):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if fault_after_family is not None and fault_after_family not in SUPPORTED:
            raise ValueError('COMPOSITE_FAULT_FAMILY_INVALID')
        self.dsn, self.identity = dsn, identity
        self.fault_after_family = fault_after_family

    def publish(self, claim: dict) -> dict:
        if (type(claim) is not dict
                or type(claim.get('workspace_id')) is not str
                or type(claim.get('application_id')) is not str
                or type(claim.get('job_id')) is not str
                or _JOB_ID.fullmatch(claim['job_id']) is None
                or type(claim.get('claimant')) is not str
                or type(claim.get('claim_generation')) is not int
                or (claim.get('function_name') is not None
                    and claim['function_name'] != FUNCTION)):
            raise ValueError('Invalid worker claim')
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT a.status AS application_status,
                    s.processing_mode,s.metadata_revision,s.data_revision,
                    s.policy_revision,s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=FUNCTION)
                job = db.execute('''SELECT * FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                    (scope.workspace_id, scope.application_id,
                                    claim['job_id'])).fetchone()
                receipt = db.execute('''SELECT committed_revision,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'])).fetchone()
                replay = _composite_replay(db,scope,job,receipt)
                if replay is not None:
                    return replay
                if (job is None or job['issuer'] != self.identity.issuer
                        or job['subject_id'] != self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                lease = db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()
                if (job['status'] != 'running'
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant']
                        or not lease['unexpired']):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db, scope, job)
                authority = compiler_for(job['normalized_program'])
                if (job['function_name'] != FUNCTION
                        or (job['compiler_version'], job['plan_digest']) != authority
                        or job['program_digest'] != _canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_COMPOSITE_JOB_PROGRAM')
                if ((state['metadata_revision'], state['data_revision'],
                     state['policy_revision']) !=
                        (job['expected_metadata_revision'],
                         job['expected_data_revision'],
                         job['expected_policy_revision'])):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                plan = decode_program(job['normalized_program'])
                decoded,prepared,policy = _prepare_composite(
                    db,scope,plan,access.role)

                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                final_state = db.execute('''SELECT
                    a.status AS application_status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision,
                    s.commit_revision FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',(scope.workspace_id,
                    scope.application_id)).fetchone()
                final_job = db.execute('''SELECT * FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    FOR UPDATE''',(scope.workspace_id,scope.application_id,
                    claim['job_id'])).fetchone()
                final_receipt = db.execute('''SELECT committed_revision,
                    actor_id,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',(scope.workspace_id,
                    scope.application_id,claim['job_id'])).fetchone()
                replay = _composite_replay(db,scope,final_job,final_receipt)
                if replay is not None:
                    return replay
                final_live = (final_job is not None and db.execute(
                    '''SELECT %s::timestamptz > clock_timestamp()
                    AS unexpired''',(final_job['lease_until'],)).fetchone()[
                        'unexpired'])
                immutable = ('issuer','subject_id','function_name',
                    'normalized_program','program_digest','compiler_version',
                    'plan_digest','expected_metadata_revision',
                    'expected_data_revision','expected_policy_revision',
                    'idempotency_key','python_workflow_id',
                    'execution_delegation_id','execution_delegation_state_token',
                    'execution_schedule_id','execution_schedule_state_token')
                if (final_state is None or final_job is None
                        or any(final_job[key] != job[key] for key in immutable)
                        or final_job['status'] != 'running'
                        or final_job['claim_generation'] !=
                            claim['claim_generation']
                        or final_job['claimant'] != claim['claimant']
                        or not final_live):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db,scope,final_job)
                final_access = PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=FUNCTION)
                if (final_state['application_status'] != 'Active'
                        or final_state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (final_state['metadata_revision'] !=
                        final_job['expected_metadata_revision']
                        or final_state['policy_revision'] !=
                        final_job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                _recheck_composite(db,scope,prepared)
                from .postgres_planning_write_guard import (
                    enforce_active_planning_policy)
                writes=[]
                for family,values in decoded:
                    if family == 'facts.numeric.batch':
                        names={'set':'Set','add':'Add','clear':'Clear'}
                        writes.extend((item.coordinate,names[item.kind.value])
                                      for item in values)
                    elif family == 'facts.text.batch':
                        names={'set':'Set','clear':'Clear'}
                        writes.extend((item.coordinate,names[item.kind.value])
                                      for item in values)
                    else:
                        writes.append((values[0],'ReplaceDetail'))
                policy = enforce_active_planning_policy(db,scope,
                    writes=tuple(writes),workflow_role=final_access.role,
                    ordered_actions=plan.version >= 2)
                state,job=final_state,final_job
                revision = state['commit_revision'] + 1
                ordinal = 0
                counts = {
                    'numeric': sum(len(values) for family, values in decoded
                                   if family == 'facts.numeric.batch'),
                    'text': sum(len(values) for family, values in decoded
                                if family == 'facts.text.batch'),
                    'detail': sum(1 for family, _ in decoded
                                  if family == 'facts.line-detail.replace'),
                }
                digest = job['program_digest']
                impact=_composite_impact(decoded,prepared,
                    operation_id=claim['job_id'],revision=revision)
                result = {'changedCount': sum(counts.values()),
                          'familyCounts': counts,
                          'committedRevision': revision, 'atomic': True,
                          'planningPolicy': policy,
                          'impactDigest':impact.digest}
                # Fact events have a scoped FK to their operation receipt.
                # Insert the single final receipt before effects; the enclosing
                # transaction still makes it invisible unless every family and
                # the terminal job publication succeeds.
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id, claim['job_id'],
                     digest, job['subject_id'], revision, Jsonb(result)))
                for family, values, ordinal in ordered_operations(decoded,revision):
                    if family == 'facts.numeric.batch':
                        from .postgres_numeric_batch import apply
                        apply(db, scope, values, revision=revision,
                              operation_id=claim['job_id'],
                              command_digest=digest, actor_id=job['subject_id'],
                              payload_digest=digest, write_control=False,
                              ordinal_offset=ordinal)
                    elif family == 'facts.text.batch':
                        from .postgres_text_batch import apply
                        apply(db, scope, values, revision=revision,
                              operation_id=claim['job_id'],
                              command_digest=digest, actor_id=job['subject_id'],
                              payload_digest=digest, write_control=False,
                              ordinal_offset=ordinal)
                    else:
                        from .postgres_line_detail import PostgresLineDetailStore
                        coordinate, items, cell_change, detail_change = values
                        PostgresLineDetailStore(
                            self.dsn, identity=self.identity).apply(
                                scope, coordinate, items,
                                operation_id=claim['job_id'],
                                command_digest=digest,
                                actor_id=job['subject_id'],
                                expected_metadata_revision=(
                                    job['expected_metadata_revision']),
                                expected_data_revision=state['data_revision'],
                                expected_cell_change_id=cell_change,
                                expected_detail_change_id=detail_change,
                                _connection=db, _shared_revision=revision,
                                _write_control=False, _ordinal=ordinal + 1,
                                _policy_evidence=policy)
                    if self.fault_after_family == family:
                        raise RuntimeError('COMPOSITE_INJECTED_FAILURE')
                db.execute('''UPDATE epm.application_state SET
                    data_revision=data_revision+1,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision, scope.workspace_id, scope.application_id))
                from .postgres_calculation_impact import (
                    record_calculation_impact)
                record_calculation_impact(db,scope,
                    operation_id=claim['job_id'],impact=impact)
                changed = db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s
                    AND claimant=%s AND lease_until>clock_timestamp()''',
                    (revision, Jsonb(result), scope.workspace_id,
                     scope.application_id, claim['job_id'],
                     claim['claim_generation'],claim['claimant'])).rowcount
                if changed != 1:
                    raise ValueError('STALE_WORKER_FENCE')
                return result
