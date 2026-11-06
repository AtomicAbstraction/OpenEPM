"""Exact planning-member comparison for one typed-Currency generation.

Typed Currency is an output unit and is deliberately not part of cube grain.
The caller therefore pins both the immutable calculated generation and one
Currency unit while the fixed core validates the complete non-Currency grain.
"""
from __future__ import annotations

from decimal import Decimal
import re

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_capability_contract import producer_capability_status
from .postgres_calculation_status import input_revision_status, published_input_status
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_version_compare import PostgresVersionCompare, _identifier


FUNCTION = 'planning.version.unit-calculation.compare'
_RESULT_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_MISSING = {'kind': 'missing', 'present': False, 'amount': None,
            'sourceAmount': None, 'sourceChangeId': None,
            'rateLineage': None}


def _generation_status(db, scope: ApplicationScope, generation: dict) -> dict:
    """Return the same conservative revision/dependency status as reads."""
    revision = input_revision_status(generation)
    result = {'inputRevisionStatus': revision}
    result['producerCapabilities'] = producer_capability_status(
        generation['function_name'], generation['normalized_program'],
        generation['enabled_capabilities'],
        generation['capability_revision'])
    if generation['function_name'] == 'facts.expression.calculate':
        dependency = published_input_status(
            db, scope, generation['normalized_program'])
        if dependency is not None:
            result['publishedInputStatus'] = dependency
            revision['matchesAtRead'] &= dependency['matchesAtRead']
    return result


def _context_status(publication: dict, status: dict) -> dict:
    """Normalize conservative staleness into stable machine reasons."""
    reasons = []
    if not publication['matchesAtRead']:
        reasons.append('PUBLICATION_POINTER_CHANGED')
    revision = status['inputRevisionStatus']
    for name in ('metadata', 'data', 'policy'):
        if revision['expected'][name] != revision['observed'][name]:
            reasons.append(f'{name.upper()}_REVISION_CHANGED')
    dependency = status.get('publishedInputStatus')
    if dependency is not None and not dependency['matchesAtRead']:
        reasons.append('PUBLISHED_INPUT_CHANGED')
    return {'matchesAtRead': not reasons, 'reasons': reasons}


def _publication_status(db, scope: ApplicationScope, result_key: str,
                        generation_id: str, published_revision: int) -> dict:
    current = db.execute('''SELECT generation_id,published_revision
        FROM epm.calculation_publication
        WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',
        (scope.workspace_id, scope.application_id, result_key)).fetchone()
    return {
        'matchesAtRead': bool(current
            and current['generation_id'] == generation_id
            and current['published_revision'] == published_revision),
        'expectedGenerationId': generation_id,
        'expectedPublishedRevision': published_revision,
        'observedGenerationId': (
            current['generation_id'] if current is not None else None),
        'observedPublishedRevision': (
            current['published_revision'] if current is not None else None),
    }


def _validate_currency_unit(db, scope: ApplicationScope, dimension: str,
                            member: str) -> None:
    row = db.execute('''SELECT m.status AS member_status,
            d.status AS dimension_status,d.model_role
        FROM epm.dimension d JOIN epm.member m
          ON m.workspace_id=d.workspace_id
         AND m.application_id=d.application_id
         AND m.dimension_id=d.dimension_id
        WHERE d.workspace_id=%s AND d.application_id=%s
          AND d.dimension_id=%s AND m.member_id=%s''',
        (scope.workspace_id, scope.application_id,
         dimension, member)).fetchone()
    if (row is None or row['dimension_status'] != 'Active'
            or row['member_status'] != 'Active'
            or row['model_role'] != 'Currency'):
        raise ValueError('CALCULATED_UNIT_CURRENCY_UNAVAILABLE')


def _load_generation(db, scope: ApplicationScope, result_key: str,
                     generation_id: str | None = None,
                     published_revision: int | None = None) -> dict:
    if generation_id is None:
        pointer = db.execute('''SELECT generation_id,published_revision
            FROM epm.calculation_publication
            WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',
            (scope.workspace_id, scope.application_id, result_key)).fetchone()
        if pointer is None:
            raise ValueError('PUBLICATION_UNAVAILABLE')
        generation_id = pointer['generation_id']
        published_revision = pointer['published_revision']
    generation = db.execute('''SELECT g.generation_id,g.result_key,
            g.published_revision,g.function_name,g.source_commit_revision,
            g.source_metadata_revision,g.source_policy_revision,
            j.status AS job_status,j.normalized_program,j.expected_metadata_revision,
            j.expected_data_revision,j.expected_policy_revision,
            s.metadata_revision AS current_metadata_revision,
            s.data_revision AS current_data_revision,
            s.policy_revision AS current_policy_revision,
            s.commit_revision AS observed_commit_revision,
            s.enabled_capabilities,s.capability_revision
        FROM epm.calculation_generation g
        JOIN epm.job j ON j.workspace_id=g.workspace_id
          AND j.application_id=g.application_id AND j.job_id=g.job_id
        JOIN epm.application_state s ON s.workspace_id=g.workspace_id
          AND s.application_id=g.application_id
        WHERE g.workspace_id=%s AND g.application_id=%s
          AND g.generation_id=%s AND g.result_key=%s''',
        (scope.workspace_id, scope.application_id,
         generation_id, result_key)).fetchone()
    if (generation is None or generation['job_status'] != 'published'
            or generation['published_revision'] != published_revision):
        raise ValueError('CALCULATION_GENERATION_UNAVAILABLE')
    return generation


def _cell(row: dict) -> dict:
    if row['amount'] is None:
        return dict(_MISSING)
    return {'kind': 'numeric', 'present': True,
            'amount': format(row['amount'], '.8f'),
            'sourceAmount': format(row['source_amount'], '.8f'),
            'sourceChangeId': row['source_change_id'],
            'rateLineage': {
                'strategy': row['rate_strategy'],
                'exactFactor': {
                    'numerator': str(row['rate_numerator']),
                    'denominator': str(row['rate_denominator'])},
                'sources': row['rate_sources']}}


class PostgresCalculatedUnitVersionCompare:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program.get('languageVersion')) is not int
                or program.get('languageVersion') != 2
                or program.get('function') != FUNCTION
                or not isinstance(program.get('arguments'), dict)):
            raise ValueError('CALCULATED_UNIT_VERSION_ARGUMENTS_INVALID')
        args = program['arguments']
        required = {'resultKey', 'currencyDimensionId', 'currencyMemberId',
                    'dimensionId', 'baseMemberId', 'targetMemberId',
                    'coordinates'}
        if (not required <= set(args)
                or set(args) - (required | {'expectedPublishedRevision'})):
            raise ValueError('CALCULATED_UNIT_VERSION_ARGUMENTS_INVALID')
        result_key = args['resultKey']
        if not isinstance(result_key, str) or not _RESULT_KEY.fullmatch(result_key):
            raise ValueError('RESULT_KEY_INVALID')
        currency_dimension = _identifier(
            args['currencyDimensionId'], 'Currency dimension ID')
        currency_member = _identifier(
            args['currencyMemberId'], 'Currency member ID')
        dimension = _identifier(args['dimensionId'], 'Dimension ID')
        base = _identifier(args['baseMemberId'], 'Base member ID')
        target = _identifier(args['targetMemberId'], 'Target member ID')
        if base == target:
            raise ValueError('VERSION_COMPARE_DISTINCT_MEMBERS_REQUIRED')
        coordinates = args['coordinates']
        if not isinstance(coordinates, list) or not 1 <= len(coordinates) <= 500:
            raise ValueError('CALCULATED_UNIT_VERSION_BOUNDS_INVALID')
        others, seen = [], set()
        for item in coordinates:
            if (not isinstance(item, dict) or len(item) > 31
                    or dimension in item or currency_dimension in item):
                raise ValueError('CALCULATED_UNIT_VERSION_COORDINATE_INVALID')
            other = {_identifier(axis, 'Dimension ID'):
                     _identifier(member, 'Member ID')
                     for axis, member in item.items()}
            key = tuple(sorted(other.items()))
            if key in seen:
                raise ValueError('VERSION_COMPARE_DUPLICATE_COORDINATE')
            seen.add(key)
            others.append(other)
        expected = args.get('expectedPublishedRevision')
        if expected is not None and (type(expected) is not int or expected < 1):
            raise ValueError('PUBLISHED_REVISION_INVALID')

        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                _validate_currency_unit(
                    db, scope, currency_dimension, currency_member)
                PostgresVersionCompare._validate_metadata(
                    db, scope, dimension, base, target, others)
                generation = _load_generation(db, scope, result_key)
                if (expected is not None
                        and generation['published_revision'] != expected):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                unit_exists = db.execute('''SELECT 1
                    FROM epm.calculation_unit_result
                    WHERE workspace_id=%s AND application_id=%s
                      AND generation_id=%s
                      AND output_unit_currency_dimension_id=%s
                      AND output_unit_currency_member_id=%s LIMIT 1''',
                    (scope.workspace_id, scope.application_id,
                     generation['generation_id'], currency_dimension,
                     currency_member)).fetchone()
                if unit_exists is None:
                    raise ValueError('CALCULATED_UNIT_RESULT_UNAVAILABLE')
                requested = []
                for ordinal, other in enumerate(others):
                    for variant, member in (('base', base), ('target', target)):
                        members = {**other, dimension: member}
                        requested.append({'ordinal': ordinal,
                            'variant': variant,
                            'series_key': Coordinate.from_mapping(
                                members).series_key,
                            'members': members})
                rows = db.execute('''WITH requested AS (
                    SELECT * FROM jsonb_to_recordset(%s::jsonb)
                    AS r(ordinal integer,variant text,series_key text,
                         members jsonb))
                    SELECT r.ordinal,r.variant,r.members,
                        c.members AS stored_members,x.amount,x.source_amount,
                        x.source_change_id,
                        x.rate_strategy,x.rate_numerator,x.rate_denominator,
                        x.rate_sources
                    FROM requested r
                    LEFT JOIN epm.coordinate c ON c.workspace_id=%s
                      AND c.application_id=%s AND c.series_key=r.series_key
                    LEFT JOIN epm.calculation_unit_result x
                      ON x.workspace_id=c.workspace_id
                     AND x.application_id=c.application_id
                     AND x.coordinate_id=c.coordinate_id
                     AND x.generation_id=%s
                     AND x.output_unit_currency_dimension_id=%s
                     AND x.output_unit_currency_member_id=%s
                    ORDER BY r.ordinal,r.variant''',
                    (Jsonb(requested), scope.workspace_id,
                     scope.application_id, generation['generation_id'],
                     currency_dimension, currency_member)).fetchall()
                after = db.execute('''SELECT metadata_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (after is None or after['metadata_revision'] !=
                        state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                publication = _publication_status(
                    db, scope, result_key, generation['generation_id'],
                    generation['published_revision'])
                status = _generation_status(db, scope, generation)
                context = _context_status(publication, status)
        states = {}
        for row in rows:
            if (row['stored_members'] is not None
                    and row['stored_members'] != row['members']):
                raise ValueError('COORDINATE_HASH_COLLISION')
            states[(row['ordinal'], row['variant'])] = _cell(row)
        result_rows = []
        for ordinal, other in enumerate(others):
            base_cell = states[(ordinal, 'base')]
            target_cell = states[(ordinal, 'target')]
            delta = (format(Decimal(target_cell['amount']) -
                            Decimal(base_cell['amount']), '.8f')
                     if base_cell['present'] and target_cell['present']
                     else None)
            result_rows.append({'otherMembers': other, 'base': base_cell,
                'target': target_cell, 'delta': delta,
                'equal': (base_cell['kind'] == target_cell['kind'] and
                          base_cell['amount'] == target_cell['amount'])})
        return {'layer': 'calculated_typed_unit', 'resultKey': result_key,
            'dimensionId': dimension, 'baseMemberId': base,
            'targetMemberId': target,
            'outputUnit': {'type': 'Currency',
                'dimensionId': currency_dimension, 'memberId': currency_member},
            'generationId': generation['generation_id'],
            'publishedRevision': generation['published_revision'],
            'sourceCommitRevision': generation['source_commit_revision'],
            'sourceMetadataRevision': generation['source_metadata_revision'],
            'sourcePolicyRevision': generation['source_policy_revision'],
            'metadataRevision': state['metadata_revision'],
            'publicationStatus': publication, **status,
            'contextStatus': context, 'rows': result_rows}
