"""Canonical sealed contract for bounded CurrencyConvert member-set plans.

The public request contains one hierarchy selector.  Trusted preview code resolves
that selector and seals these rows; workers never resolve ``active`` hierarchy
state or infer a rate after admission.
"""
from __future__ import annotations

import json
import re
from decimal import Decimal
from hashlib import sha256

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


COMPILER = 'typed-numeric-expression-v23'
PLAN_DIGEST = sha256(b'openepm:currency-member-set:v23:sealed-exact-rational').hexdigest()
MAX_ROWS = 100
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_RESULT_BYTES = 32 * 1024 * 1024
_ID = re.compile(r'[^\x00]{1,200}\Z')
_CHANGE = re.compile(r'[^\x00]{1,200}\Z')
_HEX = re.compile(r'[0-9a-f]{64}\Z')


def _id(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or value != value.strip():
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_ID_INVALID')
    return value


def normalize_request(value: object) -> dict:
    """Normalize the caller-authored selector without enumerating source cells."""
    if not isinstance(value, dict) or set(value) != {
            'grain', 'fixedMembers', 'selection', 'sourceUnitBinding',
            'toCurrencyMemberId', 'outputUnitCurrencyMemberId', 'rateKind',
            'resultKey'}:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_REQUEST_INVALID')
    grain = value['grain']
    if (not isinstance(grain, dict) or set(grain) != {'mode', 'dimensions'}
            or grain.get('mode') != 'full_coordinate'
            or not isinstance(grain.get('dimensions'), list)
            or not 1 <= len(grain['dimensions']) <= 128):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_GRAIN_INVALID')
    dimensions = sorted(_id(item) for item in grain['dimensions'])
    if len(set(dimensions)) != len(dimensions):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_GRAIN_INVALID')
    fixed = value['fixedMembers']
    if (not isinstance(fixed, dict) or len(fixed) != len(dimensions) - 1
            or any(_id(axis) not in dimensions or not _id(member)
                   for axis, member in fixed.items())):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_GRAIN_INVALID')
    selection = value['selection']
    if (not isinstance(selection, dict) or set(selection) != {
            'dimensionId', 'kind', 'rootMemberId', 'hierarchyVersion',
            'includeSelf'} or selection.get('kind') not in (
                'Descendants', 'Children', 'Leaves')
            or type(selection.get('hierarchyVersion')) is not int
            or selection['hierarchyVersion'] < 1
            or type(selection.get('includeSelf')) is not bool):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_SELECTION_INVALID')
    axis = _id(selection['dimensionId'])
    if axis not in dimensions or axis in fixed:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_GRAIN_INVALID')
    target = _id(value['toCurrencyMemberId'])
    output = _id(value['outputUnitCurrencyMemberId'])
    if (value['sourceUnitBinding']!='EntityDefaultCurrency'
            or output != target or value['rateKind'] not in ('balance', 'flow')):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_UNIT_INVALID')
    result_key = value['resultKey']
    if not isinstance(result_key, str) or not re.fullmatch(
            r'[A-Za-z0-9._-]{8,128}', result_key):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_REQUEST_INVALID')
    return {'grain': {'mode': 'full_coordinate', 'dimensions': dimensions},
        'fixedMembers': dict(sorted((_id(k), _id(v)) for k, v in fixed.items())),
        'selection': {'dimensionId': axis, 'kind': selection['kind'],
            'rootMemberId': _id(selection['rootMemberId']),
            'hierarchyVersion': selection['hierarchyVersion'],
            'includeSelf': selection['includeSelf']},
        'sourceUnitBinding':'EntityDefaultCurrency',
        'toCurrencyMemberId': target,
        'outputUnitCurrencyMemberId': output, 'rateKind': value['rateKind'],
        'resultKey': result_key}


def seal(request: object, *, metadata_revision: int, data_revision: int,
         layout_digest: str, resolved_rows: object) -> dict:
    """Seal server-resolved unique coordinates and their exact rate lineage."""
    request = normalize_request(request)
    if (type(metadata_revision) is not int or metadata_revision < 0
            or type(data_revision) is not int or data_revision < 0
            or not isinstance(layout_digest, str) or not _HEX.fullmatch(layout_digest)
            or not isinstance(resolved_rows, list)
            or not 1 <= len(resolved_rows) <= MAX_ROWS):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_SEAL_INVALID')
    axis = request['selection']['dimensionId']
    expected_axes = set(request['grain']['dimensions'])
    sealed = []
    seen_coordinates = set()
    seen_members = set()
    for row in resolved_rows:
        if not isinstance(row, dict) or set(row) != {
                'members', 'seriesKey', 'sourceChangeId',
                'fromCurrencyMemberId', 'rate'}:
            raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_ROW_INVALID')
        members = row['members']
        if (not isinstance(members, dict) or set(members) != expected_axes
                or any(_id(k) not in expected_axes or not _id(v)
                       for k, v in members.items())
                or any(members.get(k) != v
                       for k, v in request['fixedMembers'].items())):
            raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_GRAIN_INVALID')
        selected = members[axis]
        canonical = json.dumps(dict(sorted(members.items())),
                               sort_keys=True, separators=(',', ':'))
        if canonical in seen_coordinates or selected in seen_members:
            raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_DUPLICATE')
        seen_coordinates.add(canonical); seen_members.add(selected)
        if not isinstance(row['seriesKey'], str) or not _HEX.fullmatch(row['seriesKey']):
            raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_ROW_INVALID')
        change = row['sourceChangeId']
        source_currency=_id(row['fromCurrencyMemberId'])
        if source_currency==request['toCurrencyMemberId']:
            raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_UNIT_INVALID')
        rate = row['rate']
        if (not isinstance(change, str) or not _CHANGE.fullmatch(change)
                or not isinstance(rate, dict) or set(rate) != {
                    'strategy', 'exactFactor', 'sourceChangeIds', 'sources'}
                or not isinstance(rate['strategy'], str)
                or not 1 <= len(rate['strategy']) <= 100
                or not isinstance(rate['exactFactor'], dict)
                or set(rate['exactFactor']) != {'numerator', 'denominator'}
                or any(not isinstance(rate['exactFactor'][part], str)
                       or not rate['exactFactor'][part].isdigit()
                       or int(rate['exactFactor'][part]) <= 0
                       for part in ('numerator', 'denominator'))
                or not isinstance(rate['sourceChangeIds'], list)
                or not 1 <= len(rate['sourceChangeIds']) <= 2
                or len(set(rate['sourceChangeIds'])) != len(rate['sourceChangeIds'])
                or any(not isinstance(item, str) or not _CHANGE.fullmatch(item)
                       for item in rate['sourceChangeIds'])
                or not isinstance(rate['sources'], list)
                or len(rate['sources']) != len(rate['sourceChangeIds'])):
            raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_RATE_INVALID')
        sealed.append({'members': dict(sorted(members.items())),
            'seriesKey': row['seriesKey'], 'selectedMemberId': selected,
            'sourceChangeId': change,
            'fromCurrencyMemberId':source_currency,'rate': rate})
    sealed.sort(key=lambda item: item['seriesKey'])
    document = {'version': 1, 'compiler': COMPILER, 'request': request,
        'pins': {'metadataRevision': metadata_revision,
            'dataRevision': data_revision,
            'layoutDigest': layout_digest,
            'hierarchyVersions': {axis: request['selection']['hierarchyVersion']}},
        'resolvedRows': sealed, 'limits': {'maxRows': MAX_ROWS,
            'maxPlanBytes': MAX_PLAN_BYTES, 'maxResultBytes': MAX_RESULT_BYTES},
        'outputGrain': 'same_full_coordinate_typed_currency_unit',
        'rounding': 'half-even-final-8', 'statutorySemantics': 'none'}
    raw = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
    if len(raw) > MAX_PLAN_BYTES:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_PLAN_LIMIT')
    document['planDigest'] = sha256(raw).hexdigest()
    if len(json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
           ) > MAX_PLAN_BYTES:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_PLAN_LIMIT')
    return document


def admission_program(sealed: object, *, expected_publication_revision: int = 0) -> dict:
    """Validate and wrap the exact preview output for durable job admission."""
    if (not isinstance(sealed, dict)
            or type(expected_publication_revision) is not int
            or expected_publication_revision < 0):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_SEALED_INVALID')
    document = dict(sealed)
    digest = document.pop('planDigest', None)
    if (not isinstance(digest, str) or not _HEX.fullmatch(digest)
            or document.get('compiler') != COMPILER
            or document.get('version') != 1
            or document.get('outputGrain') !=
                'same_full_coordinate_typed_currency_unit'
            or document.get('rounding') != 'half-even-final-8'
            or document.get('statutorySemantics') != 'none'):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_SEALED_INVALID')
    raw = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
    if sha256(raw).hexdigest() != digest:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_DIGEST_MISMATCH')
    rows = document.get('resolvedRows')
    limits = document.get('limits')
    if (not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROWS
            or limits != {'maxRows': MAX_ROWS,
                'maxPlanBytes': MAX_PLAN_BYTES,
                'maxResultBytes': MAX_RESULT_BYTES}):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_SEALED_INVALID')
    normalized = {'version': 2,
        'function': 'facts.expression.calculate',
        'operation': 'CurrencyConvertMemberSet',
        'compiler': COMPILER, 'sealedPlan': sealed,
        'resultKey': document['request']['resultKey'],
        'expectedPublicationRevision': expected_publication_revision,
        'inputGrain': 'server_resolved_one_axis_member_set',
        'outputGrain': 'same_full_coordinate_typed_currency_unit',
        'rounding': 'half-even-final-8'}
    if len(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()
           ) > MAX_PLAN_BYTES:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_PLAN_LIMIT')
    return normalized


def preview_contract(sealed: object, *, expected_publication_revision: int = 0) -> dict:
    """Return the exact plan to resubmit; the signed token carries only its digest."""
    normalized = admission_program(sealed,
        expected_publication_revision=expected_publication_revision)
    raw = json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()
    return {'sealedProgram': normalized,
        'programDigest': sha256(raw).hexdigest(),
        'estimatedRows': len(sealed['resolvedRows']),
        'compiler': COMPILER}


def validate_admission(sealed_program: object, preview_digest: object) -> dict:
    """Require byte-canonical preview output, never a reconstructed selector."""
    if (not isinstance(sealed_program, dict)
            or not isinstance(preview_digest, str)
            or not _HEX.fullmatch(preview_digest)):
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_ADMISSION_INVALID')
    canonical = admission_program(sealed_program.get('sealedPlan'),
        expected_publication_revision=sealed_program.get(
            'expectedPublicationRevision'))
    if canonical != sealed_program:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_NONCANONICAL')
    raw = json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()
    if sha256(raw).hexdigest() != preview_digest:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_DIGEST_MISMATCH')
    return canonical


def _layout_digest(schema_epoch: int, dimensions: list[str]) -> str:
    raw = json.dumps({'schemaEpoch': schema_epoch,
        'dimensions': dimensions}, sort_keys=True, separators=(',', ':')).encode()
    return sha256(raw).hexdigest()


def resolve_and_seal(db, scope: ApplicationScope, identity: VerifiedIdentity,
                     raw_request: object, state: dict) -> dict:
    """Trusted preview resolution under one revision-locked transaction."""
    request = normalize_request(raw_request)
    from .postgres_cube_select import PostgresCubeSelect
    from .postgres_currency_amount_preview import evaluate_in_transaction
    from .postgres_currency_rates import FUNCTION as RATE_FUNCTION, PostgresCurrencyRates
    intent = {'grain': request['grain'], 'selectors': {
        request['selection']['dimensionId']: {
            key: request['selection'][key] for key in (
                'kind', 'rootMemberId', 'hierarchyVersion', 'includeSelf')}},
        'limit': MAX_ROWS, 'includeMissing': False}
    sets, versions = PostgresCubeSelect._resolve(
        db, scope, intent, state['metadata_revision'])
    axis = request['selection']['dimensionId']
    if versions != {axis: request['selection']['hierarchyVersion']}:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_HIERARCHY_STALE')
    selected = sets[axis]
    if not selected or len(selected) > MAX_ROWS:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_ROW_LIMIT')
    predicate = (' AND '.join("c.members->>%s=%s"
        for _ in request['fixedMembers']) or 'TRUE')
    params = [item for pair in request['fixedMembers'].items() for item in pair]
    rows = db.execute(f'''SELECT c.coordinate_id,c.series_key,c.members,
        n.amount,n.change_id FROM epm.coordinate c
        JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
        AND c.members->>%s=ANY(%s::text[]) AND {predicate}
        ORDER BY c.series_key LIMIT %s''', (scope.workspace_id,
        scope.application_id, axis, selected, *params, MAX_ROWS + 1)).fetchall()
    if len(rows) != len(selected) or len(rows) > MAX_ROWS:
        raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_SOURCE_GRAIN_INVALID')
    resolver = PostgresCurrencyRates('in-transaction', identity=identity)
    entity_axes=db.execute('''SELECT dimension_id FROM epm.dimension WHERE
        workspace_id=%s AND application_id=%s AND status='Active'
        AND model_role='Entity' ''',(scope.workspace_id,
        scope.application_id)).fetchall()
    if len(entity_axes)!=1:
        raise ValueError('EXPRESSION_ENTITY_UNIT_BINDING_UNAVAILABLE')
    entity_axis=entity_axes[0]['dimension_id']
    resolved = []
    for row in rows:
        entity=db.execute('''SELECT entity_default_currency_member_id currency
            FROM epm.member WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND member_id=%s AND status='Active' ''',(
            scope.workspace_id,scope.application_id,entity_axis,
            row['members'][entity_axis])).fetchone()
        if entity is None or not entity['currency']:
            raise ValueError('EXPRESSION_ENTITY_UNIT_BINDING_UNAVAILABLE')
        source_currency=entity['currency']
        rate_program = {'languageVersion': 2, 'function': RATE_FUNCTION,
            'arguments': {'coordinate': row['members'],
                'fromCurrencyMemberId': source_currency,
                'toCurrencyMemberId': request['toCurrencyMemberId'],
                'rateKind': request['rateKind']}}
        rate = resolver.resolve_in_transaction(
            db, scope, rate_program, lock_state=False)
        expected = {'strategy': rate['strategy'],
            'exactFactor': rate['exactFactor'],
            'sourceChangeIds': [item['changeId'] for item in rate['sources']]}
        inspected = evaluate_in_transaction(db, scope, identity, {
            'coordinate': Coordinate.from_mapping(row['members']),
            'sourceAmount': row['amount'], 'sourceChangeId': row['change_id'],
            'fromCurrencyMemberId': source_currency,
            'toCurrencyMemberId': request['toCurrencyMemberId'],
            'rateKind': request['rateKind'], 'expectedRate': expected,
            'expectedDataRevision': state['data_revision'],
            'rounding': 'half-even-final-8'}, permission='write',
            function='facts.expression.calculate', lock_state=False)
        resolved.append({'members': row['members'],
            'seriesKey': row['series_key'],
            'sourceChangeId': row['change_id'],
            'fromCurrencyMemberId':source_currency,
            'rate': {**expected,
                'sources': [{**item,
                    'sourceUnitCurrencyMemberId':source_currency}
                    for item in inspected['lineage']['rate']['sources']]}})
    return seal(request, metadata_revision=state['metadata_revision'],
        data_revision=state['data_revision'],
        layout_digest=_layout_digest(state['schema_epoch'],
            request['grain']['dimensions']), resolved_rows=resolved)


class PostgresCurrencyMemberSetPublisher:
    """Atomic relational publication of an admitted v23 sealed plan."""
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        self.dsn, self.identity = dsn, identity

    def publish(self, claim: dict) -> dict:
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        # Resolve the bounded hierarchy selection, source cells and exact rate
        # lineage without holding the application mutation row.  This work may
        # perform up to MAX_ROWS rate resolutions and is deliberately private:
        # it cannot publish any effect.  The final transaction below accepts it
        # only when the exact data snapshot and every authority/control pin are
        # still current.
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                prepared_state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision,
                    s.commit_revision,s.schema_epoch FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',(
                    scope.workspace_id,scope.application_id)).fetchone()
                if (prepared_state is None or prepared_state['status']!='Active'
                        or prepared_state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                prepared_job=db.execute('''SELECT * FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',(
                    scope.workspace_id,scope.application_id,
                    claim['job_id'])).fetchone()
                if (prepared_job is None
                        or prepared_job['issuer']!=self.identity.issuer
                        or prepared_job['subject_id']!=self.identity.subject_id
                        or prepared_job['status']!='running'
                        or prepared_job['claim_generation']!=claim['claim_generation']
                        or prepared_job['claimant']!=claim['claimant']
                        or not db.execute(
                            'SELECT %s::timestamptz>clock_timestamp() valid',
                            (prepared_job['lease_until'],)).fetchone()['valid']):
                    raise ValueError('STALE_WORKER_FENCE')
                if (prepared_job['compiler_version']!=COMPILER
                        or prepared_job['plan_digest']!=PLAN_DIGEST):
                    raise ValueError('UNSUPPORTED_EXPRESSION_JOB_PROGRAM')
                prepared_program=validate_admission(
                    prepared_job['normalized_program'],
                    prepared_job['program_digest'])
                prepared_sealed=prepared_program['sealedPlan']
                prepared_pins=prepared_sealed['pins']
                prepared_request=prepared_sealed['request']
                if ((prepared_state['metadata_revision'],
                     prepared_state['policy_revision']) !=
                        (prepared_job['expected_metadata_revision'],
                         prepared_job['expected_policy_revision'])
                        or prepared_pins['metadataRevision'] !=
                            prepared_state['metadata_revision']
                        or prepared_pins['layoutDigest'] != _layout_digest(
                            prepared_state['schema_epoch'],
                            prepared_request['grain']['dimensions'])):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                current=resolve_and_seal(db,scope,self.identity,
                    prepared_request,prepared_state)
                if current['resolvedRows']!=prepared_sealed['resolvedRows']:
                    raise ValueError('STALE_CURRENCY_MEMBER_SET_INPUT')

        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision,
                    s.commit_revision,s.schema_epoch FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',(scope.workspace_id,
                    scope.application_id)).fetchone()
                if state is None or state['status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',
                    function='facts.expression.calculate')
                job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
                    AND application_id=%s AND job_id=%s FOR UPDATE''',(
                    scope.workspace_id,scope.application_id,
                    claim['job_id'])).fetchone()
                if (job is None or job['issuer']!=self.identity.issuer
                        or job['subject_id']!=self.identity.subject_id
                        or job['status']!='running'
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']
                        or not db.execute('SELECT %s::timestamptz>clock_timestamp() valid',
                            (job['lease_until'],)).fetchone()['valid']):
                    raise ValueError('STALE_WORKER_FENCE')
                if job['compiler_version']!=COMPILER or job['plan_digest']!=PLAN_DIGEST:
                    raise ValueError('UNSUPPORTED_EXPRESSION_JOB_PROGRAM')
                program=validate_admission(job['normalized_program'],job['program_digest'])
                sealed=program['sealedPlan']; pins=sealed['pins']; request=sealed['request']
                if ((state['metadata_revision'],state['policy_revision']) !=
                        (job['expected_metadata_revision'],
                         job['expected_policy_revision'])
                        or pins['metadataRevision']!=state['metadata_revision']
                        or pins['layoutDigest']!=_layout_digest(state['schema_epoch'],
                            request['grain']['dimensions'])):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                # Any raw source/rate change after private preparation changes
                # data_revision and rejects the sealed result.  Calculated
                # publications only advance commit_revision, so independent
                # member-set results prepared from the same exact data snapshot
                # can still publish sequentially through this short fence.
                if state['data_revision']!=prepared_state['data_revision']:
                    raise ValueError('STALE_CURRENCY_MEMBER_SET_INPUT')
                pointer=db.execute('''SELECT published_revision FROM
                    epm.calculation_publication WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',(
                    scope.workspace_id,scope.application_id,
                    request['resultKey'])).fetchone()
                if (pointer['published_revision'] if pointer else 0)!=program[
                        'expectedPublicationRevision']:
                    raise ValueError('STALE_PUBLICATION_POINTER')
                from .postgres_planning_write_guard import enforce_active_planning_policy
                policy=enforce_active_planning_policy(db,scope,writes=tuple(
                    (Coordinate.from_mapping(row['members']),'Set')
                    for row in sealed['resolvedRows']),workflow_role=access.role)
                revision=state['commit_revision']+1
                db.execute('''INSERT INTO epm.calculation_generation(
                    workspace_id,application_id,generation_id,job_id,result_key,
                    source_commit_revision,source_metadata_revision,
                    source_policy_revision,function_name,row_count,published_revision)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(
                    scope.workspace_id,scope.application_id,claim['job_id'],
                    claim['job_id'],request['resultKey'],state['commit_revision'],
                    state['metadata_revision'],state['policy_revision'],
                    'facts.expression.calculate',len(sealed['resolvedRows']),revision))
                currency=db.execute('''SELECT dimension_id FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s AND status='Active'
                    AND model_role='Currency' ''',(scope.workspace_id,
                    scope.application_id)).fetchall()
                if len(currency)!=1: raise ValueError('EXPRESSION_CURRENCY_ROLE_AMBIGUOUS')
                inserted=db.execute('''INSERT INTO epm.calculation_unit_result(
                    workspace_id,application_id,generation_id,coordinate_id,
                    output_unit_currency_dimension_id,output_unit_currency_member_id,
                    source_amount,source_change_id,amount,rate_strategy,
                    rate_numerator,rate_denominator,rate_sources)
                    SELECT %s,%s,%s,c.coordinate_id,%s,%s,n.amount,n.change_id,
                    epm.round_half_even(n.amount*(x.numerator::numeric)/
                      (x.denominator::numeric),8),x.strategy,x.numerator::numeric,
                    x.denominator::numeric,x.sources FROM jsonb_to_recordset(%s::jsonb)
                    x(series_key text,source_change_id text,strategy text,
                      numerator text,denominator text,sources jsonb)
                    JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s
                     AND c.series_key=x.series_key
                    JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
                    WHERE n.present AND n.change_id=x.source_change_id''',(
                    scope.workspace_id,scope.application_id,claim['job_id'],
                    currency[0]['dimension_id'],request['outputUnitCurrencyMemberId'],
                    Jsonb([{'series_key':r['seriesKey'],
                        'source_change_id':r['sourceChangeId'],
                        'strategy':r['rate']['strategy'],
                        'numerator':r['rate']['exactFactor']['numerator'],
                        'denominator':r['rate']['exactFactor']['denominator'],
                        'sources':r['rate']['sources']}
                        for r in sealed['resolvedRows']]),scope.workspace_id,
                    scope.application_id)).rowcount
                if inserted!=len(sealed['resolvedRows']):
                    raise ValueError('CALCULATION_SOURCE_CHANGED')
                db.execute('''INSERT INTO epm.calculation_publication(
                    workspace_id,application_id,result_key,generation_id,published_revision)
                    VALUES(%s,%s,%s,%s,%s) ON CONFLICT(workspace_id,application_id,result_key)
                    DO UPDATE SET generation_id=excluded.generation_id,
                    published_revision=excluded.published_revision,
                    updated_at=transaction_timestamp()''',(scope.workspace_id,
                    scope.application_id,request['resultKey'],claim['job_id'],revision))
                result={'generationId':claim['job_id'],'resultKey':request['resultKey'],
                    'rowCount':inserted,'sourceCommitRevision':state['commit_revision'],
                    'committedRevision':revision,'engine':'postgres_exact_sql',
                    'outputUnit':{'type':'Currency','dimensionId':currency[0]['dimension_id'],
                        'memberId':request['outputUnitCurrencyMemberId']},
                    'selection':request['selection'],'planningPolicy':policy,
                    'consolidationTranslation':False}
                db.execute('''UPDATE epm.application_state SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',(revision,
                    scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,
                    application_id,operation_id,command_digest,actor_id,
                    committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
                    scope.workspace_id,scope.application_id,claim['job_id'],
                    job['program_digest'],job['subject_id'],revision,Jsonb(result)))
                changed=db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,lease_until=NULL,
                    updated_at=transaction_timestamp() WHERE workspace_id=%s
                    AND application_id=%s AND job_id=%s AND status='running'
                    AND claim_generation=%s AND claimant=%s
                    AND lease_until>clock_timestamp()''',(revision,Jsonb(result),
                    scope.workspace_id,scope.application_id,claim['job_id'],
                    claim['claim_generation'],claim['claimant'])).rowcount
                if changed!=1: raise ValueError('STALE_WORKER_FENCE')
                return result

