"""Durable staged numeric/text/supporting-detail loads and scenario copy.

The fixed server validates typed chunks, pins revisions and commits receipt,
events and current facts together. Staging alone never changes business facts.
Server-side file transfer and unbounded streaming remain future work. Detail rows retain
items and totals atomically through the same publication path.
"""
from __future__ import annotations

import base64
import binascii
import csv
from decimal import Decimal, localcontext
import hmac
from io import StringIO
import json
import re
import time
import uuid
from hashlib import sha256

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import (configure_lock_wait,
                                                  configure_statement_timeout)
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import (ApplicationScope, Coordinate, LineItem,
                                   NumericCell, TextCell)
from .postgres_access import (AccessDecision, AccessDenied, AccessGroupsChanged,
                              PostgresAccessChecker, VerifiedIdentity)
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security import CUBE_READ_AUTHORIZATION_STALE
from .postgres_dimensional_security_enforcement import (
    authorize_coordinates, coordinate_read_allowed)
from . import postgres_group_source_import as group_import
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_transfer_artifacts import (PostgresTransferArtifacts,
                                            _validated_diagnostics)
from .source_import_diagnostics import (
    SourceDiagnosticIdentity, compile_source_import_diagnostics)


_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_BATCH = re.compile(r'[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_EMPTY_DIGEST = sha256(b'').hexdigest()
_PLANNING_POLICY_CHUNK = 10_000
_REVIEW_SAMPLE_LIMIT = 20
_REVIEW_SAMPLE_BYTES = 262144
PREVIEW = 'facts.source.preview'
CANCEL = 'facts.source.cancel'
PUBLISH = 'facts.source.publish'
DIAGNOSTICS_COMPILE = 'facts.source.diagnostics.compile'


def source_publication_receipt_schema() -> dict:
    from .postgres_numeric_catalog import obj

    batch = {'type': 'string', 'pattern': r'^[0-9a-f]{32}(?![\s\S])'}
    digest = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
    count = {'type': 'integer', 'minimum': 0}
    base = {'batchId': batch, 'mode': {'enum': ['merge', 'replace']}, 'setCount': count,
            'clearCount': count, 'changedCount': count, 'committedRevision': count,
            'contentDigest': digest}
    return obj({**base, 'impactDigest': digest, 'diagnosticArtifactId': batch,
                'diagnosticsDigest': digest, 'planningPolicy': {'type': 'object'}}, list(base))


def _diagnostic_summary_schema() -> dict:
    from .postgres_numeric_catalog import obj

    count = {'type': 'integer', 'minimum': 0}
    flag = {'type': 'boolean'}
    return obj({'artifactId': {'type': 'string', 'pattern': r'^[0-9a-f]{32}(?![\s\S])'},
        'diagnosticsDigest': {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'},
        'diagnosticCount': count, 'errorCount': count, 'warningCount': count, 'accepted': flag,
        'warningsAllowed': flag, 'admissionAllowed': flag})


def source_lifecycle_program_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    batch = {'type': 'string', 'pattern': r'^[0-9a-f]{32}(?![\s\S])'}
    flag = {'type': 'boolean'}
    example = {'batchId': 'a' * 32}
    if function == CANCEL:
        arguments = obj({'batchId': batch})
        result = obj({'batchId': batch, 'status': {'enum': ['cancelled', 'failed', 'published']},
                      'committedEffectsRemain': flag})
        name = 'Cancel an uncommitted source batch'
        binding = 'Use the exact batch ID returned when staging began. The batch owner or a current application administrator may cancel.'
        rules = ['Staging and ready batches become cancelled. A published batch retains its effects and receipt.',
                 'Cancellation of an import execution uses its distinct request ID and facts.transfer.import.cancel.']
        recovery = 'Repeat the cancellation for the same batch to confirm its current terminal status.'
    elif function == PUBLISH:
        arguments = obj({'batchId': batch,
                         'previewToken': {'type': 'string', 'minLength': 1, 'maxLength': 4096}})
        result = source_publication_receipt_schema()
        example['previewToken'] = 'example-confirmed-source-preview'
        name = 'Publish the exact reviewed source batch'
        binding = 'Use the batch ID and unchanged token from the current authorized facts.source.preview.'
        rules = ['Publication validates the ready batch, exact token, current grants and pinned scope.',
                 'Publication writes the facts and receipt atomically. Reconciliation of an owned published batch returns its original result.',
                 'Use facts.transfer.import.request for a queued import with a separate execution identity.']
        recovery = ('Use application.operation.receipt.read with the original batch ID after an uncertain publication. '
                    'Review a fresh preview before starting a changed intent.')
    elif function == DIAGNOSTICS_COMPILE:
        arguments = obj({'batchId': batch, 'rows': {'type': 'array', 'maxItems': 100000,
            'description': 'Raw JSON rows, including invalid rows for the compiler to diagnose.'},
            'allowWarnings': flag})
        result = _diagnostic_summary_schema()
        example.update(rows=[{'members': {'Account': 'Revenue'}, 'sourceRef': 'example-row',
                              'value': {'type': 'AmountLiteral', 'decimal': '1.00'}}], allowWarnings=False)
        name = 'Compile diagnostics for a manifest-backed source'
        binding = 'Use an owned manifest-backed batch and its raw rows. Resolve every active fact axis for a valid full-grain input.'
        rules = ['The named batch requires current application WRITE and an immutable manifest.',
                 'The server compiles invalid raw rows into fixed diagnostics. Compilation retains an artifact and does not stage or publish facts.',
                 'admissionAllowed describes the diagnostic decision only. A ready preview and current authorization govern publication.']
        recovery = ('Use facts.transfer.import.diagnostics.read with the retained artifactId. '
                    'For a changed source, review the input and start a new batch with its own manifest.')
    else:
        raise ValueError('SOURCE_LIFECYCLE_FUNCTION_INVALID')
    contract = read_contract(function, arguments, result, owner='PostgresSourceBatch',
        examples=[read_example(function, example, name=name, binding=binding)], semantic_rules=rules)
    contract['programContract']['recovery'] = recovery
    return contract


def preview_program_contract() -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    identifier = {'type': 'string', 'minLength': 1}
    batch = {'type': 'string', 'pattern': r'^[0-9a-f]{32}(?![\s\S])'}
    digest = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
    revision = {'type': 'integer', 'minimum': 0}
    flag = {'type': 'boolean'}
    mode = {'enum': ['merge', 'replace']}
    members = {'type': 'object', 'propertyNames': identifier, 'additionalProperties': identifier}
    decimal = {'type': 'string', 'description': 'An exact decimal string.'}
    items = {'type': 'array', 'maxItems': 500,
             'items': obj({'description': {'type': 'string'}, 'amount': decimal})}
    present = {kind: obj({'present': {'const': True}, **fields}) for kind, fields in (
        ('numeric', {'amount': decimal}), ('text', {'text': {'type': 'string'}}),
        ('detail', {'amount': decimal, 'items': items}))}
    missing = obj({'present': {'const': False}})
    state = {kind: {'oneOf': [missing, value]} for kind, value in present.items()}
    companion = {'type': 'array', 'minItems': 1, 'maxItems': 1, 'items': {'oneOf': [
        obj({'valueKind': {'const': 'numeric'}, 'before': state['numeric'], 'after': present['numeric']}),
        obj({'valueKind': {'const': 'detail'}, 'before': present['detail'], 'after': missing}),
    ]}}
    review_example_shapes = []
    example_required = ['members', 'valueKind', 'action', 'sourceRef', 'before', 'after']
    for kind, value in present.items():
        fields = {'members': {**members, 'minProperties': 1}, 'valueKind': {'const': kind}}
        if kind != 'text':
            fields['companionChanges'] = companion
        review_example_shapes.append(obj({**fields, 'action': {'const': 'set'},
            'sourceRef': identifier, 'before': state[kind], 'after': value}, example_required))
        if kind != 'detail':
            review_example_shapes.append(obj({**fields, 'action': {'const': 'clear'},
                'sourceRef': {'type': 'null'}, 'before': value, 'after': missing}, example_required))
    periods = obj({'yearDimension': identifier, 'periodDimension': identifier,
        'periods': {'type': 'array', 'minItems': 1, 'maxItems': 36, 'uniqueItems': True,
                    'items': obj({'year_id': identifier, 'period_id': identifier})}})
    review = obj({'format': {'const': 'openepm-source-change-review-v1'},
        'mode': mode, 'scopeMembers': members, 'scopeAll': flag,
        'periodSelection': {'oneOf': [periods, {'type': 'null'}]},
        'metadataRevision': revision, 'dataRevision': revision, 'commitRevision': revision,
        'sampleLimitPerAction': {'const': _REVIEW_SAMPLE_LIMIT},
        'sampleByteLimit': {'const': _REVIEW_SAMPLE_BYTES}, 'setsComplete': flag,
        'clearsComplete': flag, 'readRestricted': flag,
        'examples': {'type': 'array', 'maxItems': 2 * _REVIEW_SAMPLE_LIMIT,
                     'items': {'oneOf': review_example_shapes}}})
    result = obj({'batchId': batch, 'mode': mode, 'setCount': revision, 'clearCount': revision,
        'review': review, 'contentDigest': digest, 'previewToken': {'type': 'string', 'minLength': 1},
        'diagnostics': _diagnostic_summary_schema()},
        ['batchId', 'mode', 'setCount', 'clearCount', 'review', 'contentDigest', 'previewToken'])
    contract = read_contract(PREVIEW, obj({'batchId': batch, 'allowWarnings': flag}, ['batchId']), result,
        owner='PostgresSourceBatch', examples=[read_example(PREVIEW, {'batchId': 'a' * 32},
            name='Preview the exact staged source change',
            binding='Use the batch ID from the acknowledged seal. Review the returned counts and samples before requesting publication.')],
        semantic_rules=[
            'Current WRITE and exact preparation revisions are required. Preview examples also require coordinate READ.',
            'The set and clear counts cover the full intent. The completeness flags describe bounded and read-authorized examples.',
            'Missing, zero, empty text and ordered supporting detail retain their distinct wire shapes.',
            'A manifest-backed preview can include diagnostic evidence. Explicit allowWarnings is required to accept warnings.',
            'The token binds the exact ready batch, observed revisions and identity. Publication rechecks current authority and freshness.',
            'For a prepared slice copy, the current READ grant must still cover every retained source coordinate.',
        ])
    contract['programContract']['recovery'] = ('If a preview becomes stale, inspect the current batch and application revisions. '
        'Review a current preview before starting a new publication intent. Check the original request if publication was already sent.')
    return contract


def csv_input_rejections() -> dict:
    """Fixed append refusals raised before any staging connection or write.

    This does not classify arbitrary validation errors or a prior uncertain
    dispatch. A corrected chunk is a new admitted intent on the same native
    batch/chunk owner; an accepted prefix is never resubmitted or replaced.
    """
    return {
        'format': 'openepm-csv-input-rejections-v1',
        'phase': 'before_chunk_write',
        'httpStatus': 400,
        'firstDispatchOnly': True,
        'priorUncertainty': 'retain_original',
        'changedInput': 'new_admission',
        'codes': [
            'SOURCE_CSV_BYTES_INVALID', 'SOURCE_CSV_HEADER_INVALID',
            'SOURCE_CSV_ROW_INVALID', 'SOURCE_CSV_LITERAL_INVALID',
            'SOURCE_CSV_INVALID', 'SOURCE_ROW_INVALID',
            'SOURCE_DETAIL_ROW_INVALID', 'SOURCE_DUPLICATE_COORDINATE',
            'SOURCE_CHUNK_BYTES_LIMIT', 'SOURCE_AMOUNT_INVALID',
        ],
    }


def _omitted_source_targets(scope, batch, table, kinds):
    """One omitted-target predicate for preview counts and change inspection."""
    if table not in ('numeric_cell_current', 'text_cell_current'):
        raise ValueError('SOURCE_REVIEW_DOMAIN_INVALID')
    predicate, params = _scope_predicate(
        batch['scope_members'], batch['period_selection'])
    return f''' FROM epm.{table} n JOIN epm.coordinate c
        ON c.workspace_id=n.workspace_id AND c.application_id=n.application_id
        AND c.coordinate_id=n.coordinate_id
        WHERE n.workspace_id=%s AND n.application_id=%s AND n.present
        {predicate}
        AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
            WHERE r.workspace_id=n.workspace_id AND r.application_id=n.application_id
            AND r.batch_id=%s AND r.series_key=c.series_key
            AND r.value_kind=ANY(%s::text[]))''', (
                scope.workspace_id, scope.application_id, *params,
                batch['batch_id'], kinds)


class SourceBatchPrepublicationRejection(ValueError):
    """A fixed source-batch validation rejection before any publication."""


def _scope_members(value: object, *, scope_all: bool) -> dict[str, str]:
    if (not isinstance(scope_all, bool) or not isinstance(value, dict)
            or len(value) > 32 or scope_all != (len(value) == 0)
            or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                   or not isinstance(member, str) or not 1 <= len(member) <= 200
                   for axis, member in value.items())):
        raise ValueError('SOURCE_SCOPE_INVALID')
    return dict(sorted(value.items()))


def _scope_predicate(members: dict[str, str],
                     period_selection: dict | None = None) -> tuple[str, list]:
    predicates = []
    params = []
    for axis, member in members.items():
        predicates.append('''AND EXISTS (SELECT 1 FROM epm.coordinate_member cm
            WHERE cm.workspace_id=c.workspace_id
            AND cm.application_id=c.application_id
            AND cm.coordinate_id=c.coordinate_id
            AND cm.dimension_id=%s AND cm.member_id=%s)''')
        params.extend((axis, member))
    if period_selection is not None:
        predicates.append('''AND EXISTS (
            SELECT 1 FROM jsonb_to_recordset(%s::jsonb)
            AS selected(year_id text,period_id text)
            WHERE c.members->>%s=selected.year_id
              AND c.members->>%s=selected.period_id)''')
        params.extend((Jsonb(period_selection['periods']),
                       period_selection['yearDimension'],
                       period_selection['periodDimension']))
    return '\n'.join(predicates), params


def enforce_source_batch_policy(db, scope: ApplicationScope, batch,
                                workflow_role: str, *, identity=None) -> dict | None:
    """Guard final ordinary-import, copy and forecast publication targets.

    The action query mirrors source publication: staged numeric, text and
    detail values are Sets, while every currently-present value omitted from
    a replacement scope is a Clear. Source manifests and reads are not inputs
    to the editability decision.
    """
    predicate, params = _scope_predicate(
        batch['scope_members'], batch['period_selection'])
    rows = db.execute(f'''WITH actions AS (
        SELECT r.members,'Set'::text AS action
        FROM epm.source_batch_row r
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.batch_id=%s
        UNION
        SELECT c.members,'Clear'::text AS action
        FROM epm.numeric_cell_current n JOIN epm.coordinate c
          ON c.workspace_id=n.workspace_id
         AND c.application_id=n.application_id
         AND c.coordinate_id=n.coordinate_id
        WHERE n.workspace_id=%s AND n.application_id=%s AND n.present
          AND %s::text='replace' {predicate}
          AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
              WHERE r.workspace_id=n.workspace_id
                AND r.application_id=n.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind IN ('numeric','detail'))
        UNION
        SELECT c.members,'Clear'::text AS action
        FROM epm.text_cell_current t JOIN epm.coordinate c
          ON c.workspace_id=t.workspace_id
         AND c.application_id=t.application_id
         AND c.coordinate_id=t.coordinate_id
        WHERE t.workspace_id=%s AND t.application_id=%s AND t.present
          AND %s::text='replace' {predicate}
          AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
              WHERE r.workspace_id=t.workspace_id
                AND r.application_id=t.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind='text')
        UNION
        SELECT c.members,'Clear'::text AS action
        FROM epm.line_detail_current d JOIN epm.coordinate c
          ON c.workspace_id=d.workspace_id
         AND c.application_id=d.application_id
         AND c.coordinate_id=d.coordinate_id
        WHERE d.workspace_id=%s AND d.application_id=%s
          AND %s::text='replace' AND %s::boolean {predicate}
          AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
              WHERE r.workspace_id=d.workspace_id
                AND r.application_id=d.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind='detail'))
        SELECT members,action FROM actions
        ORDER BY members::text COLLATE "C",action''',
        (scope.workspace_id, scope.application_id, batch['batch_id'],
         scope.workspace_id, scope.application_id, batch['mode'], *params,
         batch['batch_id'], scope.workspace_id, scope.application_id,
         batch['mode'], *params, batch['batch_id'],
         scope.workspace_id, scope.application_id, batch['mode'],
         batch['period_selection'] is not None, *params,
         batch['batch_id'])).fetchall()
    if not rows:
        return None
    writes = tuple((Coordinate.from_mapping(row['members']), row['action'])
                   for row in rows)
    from .postgres_planning_write_guard import enforce_active_planning_policy
    chunks = []
    for offset in range(0, len(writes), _PLANNING_POLICY_CHUNK):
        chunks.append(enforce_active_planning_policy(
            db, scope,
            writes=writes[offset:offset + _PLANNING_POLICY_CHUNK],
            workflow_role=workflow_role, identity=identity))
    if len(chunks) == 1:
        return chunks[0]
    identity_keys = ('configured', 'allowed', 'reasonCode', 'policyId',
                     'policyStateToken', 'policyDigest')
    identity = {key: chunks[0][key] for key in identity_keys}
    if any(any(chunk[key] != identity[key] for key in identity_keys)
           for chunk in chunks[1:]):
        raise ValueError('SOURCE_BATCH_POLICY_CHANGED_DURING_GUARD')
    decision_payload = {
        'chunkDigests': [chunk['decisionDigest'] for chunk in chunks],
        'writeCount': len(writes),
    }
    return {**identity, 'writeCount': len(writes),
            'decisionDigest': _canonical_digest(decision_payload),
            'matchedRuleIds': sorted({rule for chunk in chunks
                                      for rule in chunk['matchedRuleIds']}),
            'chunkCount': len(chunks)}


def enforce_source_batch_dimensional_security(
        db, identity: VerifiedIdentity, scope: ApplicationScope, batch, *,
        expected_access: AccessDecision | None = None) -> None:
    """Authorize every explicit Set and implicit replacement Clear target.

    Source imports may contain 100,000 explicit rows and replacement scopes
    can add omitted current cells.  The fixed core derives that complete
    target set from trusted staged/current state; callers cannot omit a Clear
    target from authorization by leaving it out of the uploaded file.

    This first complete boundary intentionally reuses the same authoritative
    coordinate evaluator as point writes.  A later set-based implementation
    may replace its execution strategy only after exact parity is qualified.
    """
    predicate, params = _scope_predicate(
        batch['scope_members'], batch['period_selection'])
    rows = db.execute(f'''WITH targets AS (
        SELECT r.members
        FROM epm.source_batch_row r
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.batch_id=%s
        UNION
        SELECT c.members
        FROM epm.numeric_cell_current n JOIN epm.coordinate c
          ON c.workspace_id=n.workspace_id
         AND c.application_id=n.application_id
         AND c.coordinate_id=n.coordinate_id
        WHERE n.workspace_id=%s AND n.application_id=%s AND n.present
          AND %s::text='replace' {predicate}
          AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
              WHERE r.workspace_id=n.workspace_id
                AND r.application_id=n.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind IN ('numeric','detail'))
        UNION
        SELECT c.members
        FROM epm.text_cell_current t JOIN epm.coordinate c
          ON c.workspace_id=t.workspace_id
         AND c.application_id=t.application_id
         AND c.coordinate_id=t.coordinate_id
        WHERE t.workspace_id=%s AND t.application_id=%s AND t.present
          AND %s::text='replace' {predicate}
          AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
              WHERE r.workspace_id=t.workspace_id
                AND r.application_id=t.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind='text')
        UNION
        SELECT c.members
        FROM epm.line_detail_current d JOIN epm.coordinate c
          ON c.workspace_id=d.workspace_id
         AND c.application_id=d.application_id
         AND c.coordinate_id=d.coordinate_id
        WHERE d.workspace_id=%s AND d.application_id=%s
          AND %s::text='replace' AND %s::boolean {predicate}
          AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
              WHERE r.workspace_id=d.workspace_id
                AND r.application_id=d.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind='detail'))
        SELECT members FROM targets
        ORDER BY members::text COLLATE "C"''',
        (scope.workspace_id, scope.application_id, batch['batch_id'],
         scope.workspace_id, scope.application_id, batch['mode'], *params,
         batch['batch_id'], scope.workspace_id, scope.application_id,
         batch['mode'], *params, batch['batch_id'],
         scope.workspace_id, scope.application_id, batch['mode'],
         batch['period_selection'] is not None, *params,
         batch['batch_id'])).fetchall()
    authorize_coordinates(
        db, identity, scope,
        (Coordinate.from_mapping(row['members']) for row in rows),
        kind=AccessKind.WRITE, expected_access=expected_access)


def require_current_copy_groups(db, identity, groups):
    if (groups is not None
            and PostgresAccessChecker.current_groups_in_transaction(db, identity) != groups):
        raise AccessDenied('DIMENSIONAL_SCOPE_DENIED')


def authorize_staged_copy_sources(db, identity, scope, batch, origin, *,
                                  expected_access: AccessDecision, include_targets=False):
    """Check exact retained coordinates under the opening application decision."""
    dimension = origin.get('scenarioDimension') if isinstance(origin, dict) else None
    member = origin.get('sourceMember') if isinstance(origin, dict) else None
    if not isinstance(dimension, str) or not dimension or not isinstance(member, str) or not member:
        raise ValueError('SCENARIO_COPY_ORIGIN_INVALID')
    after = 0
    seen = 0
    while True:
        rows = db.execute('''SELECT row_ordinal,members FROM epm.source_batch_row
            WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
            AND row_ordinal>%s ORDER BY row_ordinal LIMIT 1000''',
            (scope.workspace_id, scope.application_id, batch['batch_id'], after)).fetchall()
        if not rows:
            break
        authorize_coordinates(db, identity, scope,
            (Coordinate.from_mapping({**row['members'], dimension: member}) for row in rows),
            kind=AccessKind.READ, expected_access=expected_access)
        if include_targets:
            authorize_coordinates(db, identity, scope,
                (Coordinate.from_mapping(row['members']) for row in rows),
                kind=AccessKind.READ, expected_access=expected_access)
        seen += len(rows)
        if seen > 100000:
            raise ValueError('SCENARIO_COPY_ROW_LIMIT')
        after = rows[-1]['row_ordinal']
    if seen != batch['row_count']:
        raise ValueError('SCENARIO_COPY_STATUS_INCONSISTENT')
    return expected_access.groups


class PostgresSourceBatch:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes, publication_authorizer=None,
                 publication_finalizer=None):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if not isinstance(preview_secret, bytes) or len(preview_secret) < 32:
            raise ValueError('A server-owned preview secret of 32+ bytes is required')
        if (publication_authorizer is not None
                and not callable(publication_authorizer)):
            raise ValueError('SOURCE_PUBLICATION_AUTHORIZER_INVALID')
        if (publication_finalizer is not None
                and not callable(publication_finalizer)):
            raise ValueError('SOURCE_PUBLICATION_FINALIZER_INVALID')
        self.dsn = dsn
        self.identity = identity
        self.preview_secret = preview_secret
        self.publication_authorizer = publication_authorizer
        self.publication_finalizer = publication_finalizer

    def _authorize_publication(self, db, scope):
        if (self.publication_authorizer is not None
                and self.publication_authorizer(db, scope) is not True):
            raise ValueError('SOURCE_PUBLICATION_AUTHORIZATION_DENIED')

    def _finalize_publication(self, db, scope):
        if (self.publication_finalizer is not None
                and self.publication_finalizer(db, scope) is not True):
            raise ValueError('SOURCE_PUBLICATION_FINAL_FENCE_FAILED')

    def _authorize_copied_sources(self, db, scope, batch, *, expected_access: AccessDecision):
        row = db.execute('''SELECT normalized_program,source_row_count
            FROM epm.planning_copy_origin
            WHERE workspace_id=%s AND application_id=%s AND batch_id=%s''',
            (scope.workspace_id, scope.application_id, batch['batch_id'])).fetchone()
        if row is None:
            return None
        if row['source_row_count'] != batch['row_count']:
            raise ValueError('SCENARIO_COPY_STATUS_INCONSISTENT')
        origin = row['normalized_program']
        return authorize_staged_copy_sources(db, self.identity, scope, batch,
            origin.get('copyProgram', origin), expected_access=expected_access)

    def append_csv(self, scope: ApplicationScope, batch_id: str, *,
                   chunk_index: int, csv_text: str,
                   replay_only: bool = False) -> dict | None:
        """Parse one bounded stable-ID CSV chunk into ordinary staged rows.

        The header has axis.<dimensionId> columns plus literalType, value and
        sourceRef. The value of a detail literal is a JSON item array. No
        server filesystem path or caller-selected SQL is accepted.
        """
        if not isinstance(csv_text, str) or '\x00' in csv_text:
            raise ValueError('SOURCE_CSV_BYTES_INVALID')
        try:
            byte_count = len(csv_text.encode('utf-8'))
        except UnicodeError as error:
            raise ValueError('SOURCE_CSV_BYTES_INVALID') from error
        if byte_count > 8_000_000:
            raise ValueError('SOURCE_CSV_BYTES_INVALID')
        try:
            reader = csv.reader(StringIO(csv_text, newline=''), strict=True)
            header = next(reader)
            axis_columns = [name for name in header
                            if name.startswith('axis.')]
            if (len(header) != len(set(header))
                    or set(header) !=
                    set(axis_columns) | {'literalType', 'value', 'sourceRef'}
                    or any(not 1 <= len(name[5:]) <= 200
                           for name in axis_columns)):
                raise ValueError('SOURCE_CSV_HEADER_INVALID')
            rows = []
            for record in reader:
                if len(record) != len(header) or len(rows) >= 500:
                    raise ValueError('SOURCE_CSV_ROW_INVALID')
                cells = dict(zip(header, record, strict=True))
                members = {name[5:]: cells[name] for name in axis_columns}
                base = {'members': members,
                        'sourceRef': cells['sourceRef']}
                kind = cells['literalType']
                if kind == 'AmountLiteral':
                    rows.append({**base, 'amount': cells['value']})
                elif kind == 'TextLiteral':
                    rows.append({**base, 'text': cells['value']})
                elif kind == 'LineDetailLiteral':
                    items = json.loads(cells['value'])
                    if (not isinstance(items, list)
                            or any(not isinstance(item, dict)
                                   or set(item) != {'description', 'decimal'}
                                   for item in items)):
                        raise ValueError('SOURCE_CSV_ROW_INVALID')
                    rows.append({**base, 'detail': [
                        {'description': item['description'],
                         'amount': item['decimal']} for item in items]})
                else:
                    raise ValueError('SOURCE_CSV_LITERAL_INVALID')
            if not rows:
                raise ValueError('SOURCE_CSV_ROW_INVALID')
        except (csv.Error, StopIteration, UnicodeError, json.JSONDecodeError,
                RecursionError, TypeError) as error:
            raise ValueError('SOURCE_CSV_INVALID') from error
        return self.append(scope, batch_id, chunk_index=chunk_index,
                           rows=rows,replay_only=replay_only,csv_source=True)

    def begin(self, scope: ApplicationScope, *, idempotency_key: str,
              mode: str, scope_members: dict[str, str], scope_all: bool,
              expected_metadata_revision: int,
              expected_data_revision: int) -> dict:
        return self._begin(scope, idempotency_key=idempotency_key, mode=mode,
            scope_members=scope_members, scope_all=scope_all,
            expected_metadata_revision=expected_metadata_revision,
            expected_data_revision=expected_data_revision, replay_only=False)

    def replay_begin(self, scope: ApplicationScope, *, idempotency_key: str,
                     mode: str, scope_members: dict[str, str], scope_all: bool,
                     expected_metadata_revision: int,
                     expected_data_revision: int) -> dict | None:
        return self._begin(scope, idempotency_key=idempotency_key, mode=mode,
            scope_members=scope_members, scope_all=scope_all,
            expected_metadata_revision=expected_metadata_revision,
            expected_data_revision=expected_data_revision, replay_only=True)

    def _begin(self, scope: ApplicationScope, *, idempotency_key: str,
               mode: str, scope_members: dict[str, str], scope_all: bool,
               expected_metadata_revision: int,
               expected_data_revision: int, replay_only: bool) -> dict | None:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)
                or mode not in ('merge', 'replace')
                or any(type(value) is not int or value < 0 for value in (
                    expected_metadata_revision, expected_data_revision))):
            raise ValueError('SOURCE_BATCH_ADMISSION_INVALID')
        members = _scope_members(scope_members, scope_all=scope_all)
        request_digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'mode': mode, 'members': members, 'scopeAll': scope_all,
            'revisions': [expected_metadata_revision, expected_data_revision],
        })
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                if replay_only:
                    db.execute('SET TRANSACTION READ ONLY')
                    configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = group_import.source_access(db,self.identity,scope,'facts.source.begin')
                grouped = access.authorization_model == 'group_assignments'
                if grouped and (mode != 'merge' or members or not scope_all):
                    raise ValueError(group_import.UNSUPPORTED)
                state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.commit_revision,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s'''
                    + ('' if replay_only else ' FOR UPDATE OF s'),
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                previous = db.execute('''SELECT * FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s
                    AND idempotency_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if previous:
                    group_import.authorize_existing(db,self.identity,scope,access,previous)
                    if previous['request_digest'] != request_digest:
                        raise ValueError('SOURCE_IDEMPOTENCY_CONFLICT')
                    return {'batchId': previous['batch_id'],
                            'status': previous['status'],
                            'rowCount': previous['row_count'],
                            'contentDigest': previous['content_digest'],
                            'duplicate': True}
                if replay_only:
                    return None
                group_import.require_supported_policy(db,scope,self.identity,access)
                if (state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision'] != expected_metadata_revision
                        or state['data_revision'] != expected_data_revision):
                    raise ValueError('STALE_SOURCE_BATCH_REVISION')
                self._check_scope_members(db, scope, members)
                batch_id = uuid.uuid4().hex
                db.execute('''INSERT INTO epm.source_batch
                    (workspace_id,application_id,batch_id,issuer,subject_id,
                     idempotency_key,request_digest,mode,scope_members,
                     scope_all,expected_metadata_revision,
                     expected_data_revision,expected_commit_revision,
                     status,content_digest,group_numeric_import)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                            'staging',%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     batch_id, self.identity.issuer, self.identity.subject_id,
                     idempotency_key, request_digest, mode, Jsonb(members),
                     scope_all, expected_metadata_revision,
                     expected_data_revision, state['commit_revision'],
                     _EMPTY_DIGEST,grouped))
                return {'batchId': batch_id, 'status': 'staging',
                        'rowCount': 0, 'contentDigest': _EMPTY_DIGEST,
                        'duplicate': False}

    def append_typed(self, scope: ApplicationScope, batch_id: str, *,
                     chunk_index: int, rows: list[dict],
                     replay_only: bool = False) -> dict | None:
        """Normalize the typed stage and its exact recovery through one owner."""
        if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
            raise ValueError('V2_SOURCE_ROWS_INVALID')
        normalized = []
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {'members', 'value', 'sourceRef'}
                    or not isinstance(row['value'], dict)):
                raise ValueError('V2_SOURCE_ROW_INVALID')
            literal = row['value']
            base = {'members': row['members'], 'sourceRef': row['sourceRef']}
            kind = literal.get('type')
            if kind == 'AmountLiteral' and set(literal) == {'type', 'decimal'}:
                normalized.append({**base, 'amount': literal['decimal']})
            elif kind == 'TextLiteral' and set(literal) == {'type', 'text'}:
                normalized.append({**base, 'text': literal['text']})
            elif (kind == 'LineDetailLiteral' and set(literal) == {'type', 'items'}
                    and isinstance(literal['items'], list)):
                items = []
                for item in literal['items']:
                    if not isinstance(item, dict) or set(item) != {'description', 'decimal'}:
                        raise ValueError('V2_SOURCE_ROW_INVALID')
                    items.append({'description': item['description'], 'amount': item['decimal']})
                normalized.append({**base, 'detail': items})
            else:
                raise ValueError('V2_SOURCE_ROW_INVALID')
        return self.append(scope, batch_id, chunk_index=chunk_index,
                           rows=normalized, replay_only=replay_only)

    def append(self, scope: ApplicationScope, batch_id: str, *,
               chunk_index: int, rows: list[dict],
               replay_only: bool = False, csv_source: bool = False) -> dict | None:
        self._batch_id(batch_id)
        if (type(chunk_index) is not int or not 0 <= chunk_index < 1000
                or not isinstance(rows, list) or not 1 <= len(rows) <= 500):
            raise ValueError('SOURCE_CHUNK_BOUNDS_INVALID')
        prepared = []
        digest_rows = []
        for row in rows:
            if (not isinstance(row, dict)
                    or set(row) not in ({'members', 'amount', 'sourceRef'},
                                        {'members', 'text', 'sourceRef'},
                                        {'members', 'detail', 'sourceRef'})
                    or not isinstance(row['sourceRef'], str)
                    or not 1 <= len(row['sourceRef']) <= 200):
                raise ValueError('SOURCE_ROW_INVALID')
            coordinate = Coordinate.from_mapping(row['members'])
            base = {'series_key': coordinate.series_key,
                    'members': dict(coordinate.members),
                    'source_ref': row['sourceRef']}
            if 'amount' in row:
                try:
                    cell = NumericCell.from_wire(present=True,
                                                 amount=row['amount'])
                except ValueError as error:
                    raise ValueError('SOURCE_AMOUNT_INVALID') from error
                amount = cell.wire_amount()
                prepared.append({**base, 'value_kind': 'numeric',
                                 'amount': amount, 'text_value': None,
                                 'detail_items': None})
                digest_rows.append({**base, 'amount': amount})
            elif 'text' in row:
                cell = TextCell(True, row['text'], '')
                prepared.append({**base, 'value_kind': 'text',
                                 'amount': None, 'text_value': cell.value,
                                 'detail_items': None})
                digest_rows.append({**base, 'text': cell.value})
            else:
                raw_items = row['detail']
                if not isinstance(raw_items,list) or len(raw_items)>500:
                    raise ValueError('SOURCE_DETAIL_ROW_INVALID')
                try:
                    items=tuple(LineItem(item['description'],
                        Decimal(item['amount'])) for item in raw_items
                        if isinstance(item,dict) and
                        set(item)=={'description','amount'} and
                        isinstance(item['amount'],str))
                    if len(items)!=len(raw_items):
                        raise ValueError('SOURCE_DETAIL_ROW_INVALID')
                    with localcontext() as precision:
                        precision.prec=80
                        total=sum((item.amount for item in items),Decimal(0))
                    NumericCell(True,total,'')
                except (ArithmeticError,KeyError,TypeError,ValueError) as error:
                    raise ValueError('SOURCE_DETAIL_ROW_INVALID') from error
                encoded=[{'description':item.description,
                    'amount':format(item.amount,'f')} for item in items]
                amount=format(total,'f')
                prepared.append({**base,'value_kind':'detail',
                    'amount':amount,'text_value':None,
                    'detail_items':encoded})
                digest_rows.append({**base,'amount':amount,'detail':encoded})
        if len({row['series_key'] for row in prepared}) != len(prepared):
            raise ValueError('SOURCE_DUPLICATE_COORDINATE')
        try:
            chunk_bytes = len(json.dumps(digest_rows, ensure_ascii=False,
                separators=(',', ':'), allow_nan=False).encode('utf-8'))
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValueError('SOURCE_ROW_INVALID') from error
        if chunk_bytes > 8_000_000:
            raise ValueError('SOURCE_CHUNK_BYTES_LIMIT')
        digest = _canonical_digest(digest_rows)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                if replay_only:
                    db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db, scope)
                function = 'facts.source.csv.append' if csv_source else 'facts.source.append'
                access = group_import.source_access(db,self.identity,scope,function)
                batch = self._owned_batch(db, scope, batch_id, lock=not replay_only)
                group_import.check_model(access,batch)
                if batch['group_numeric_import']:
                    group_import.authorize_rows(db,self.identity,scope,access,prepared)
                if chunk_index < batch['chunk_count']:
                    group_import.authorize_existing(db,self.identity,scope,access,batch)
                    previous = db.execute('''SELECT chunk_digest
                        FROM epm.source_batch_chunk WHERE workspace_id=%s
                        AND application_id=%s AND batch_id=%s
                        AND chunk_index=%s''',
                        (scope.workspace_id, scope.application_id,
                         batch_id, chunk_index)).fetchone()
                    if previous and previous['chunk_digest'] == digest:
                        return {'batchId': batch_id, 'chunkIndex': chunk_index,
                                'rowCount': batch['row_count'],
                                'contentDigest': batch['content_digest'],
                                'duplicate': True}
                    raise ValueError('SOURCE_CHUNK_IDEMPOTENCY_CONFLICT')
                if replay_only:
                    return None
                if chunk_index != batch['chunk_count']:
                    raise ValueError('SOURCE_CHUNK_OUT_OF_ORDER')
                if batch['status'] != 'staging':
                    raise ValueError('SOURCE_BATCH_NOT_STAGING')
                if batch['row_count'] + len(prepared) > 100000:
                    raise ValueError('SOURCE_BATCH_ROW_LIMIT')
                if batch['group_numeric_import']:
                    group_import.require_plannable_rows(db,self.identity,scope,access,prepared)
                self._validate_rows(db, scope, batch, prepared)
                staged = [{**row,
                           'row_ordinal': batch['row_count'] + ordinal}
                          for ordinal, row in enumerate(prepared, 1)]
                db.execute('''INSERT INTO epm.source_batch_row
                    (workspace_id,application_id,batch_id,row_ordinal,
                     series_key,members,amount,value_kind,text_value,
                     detail_items,source_ref)
                    SELECT %s,%s,%s,input.row_ordinal,input.series_key,
                           input.members,input.amount::numeric,input.value_kind,
                           input.text_value,input.detail_items,input.source_ref
                    FROM jsonb_to_recordset(%s::jsonb) AS input
                    (row_ordinal bigint,series_key text,members jsonb,
                     amount text,value_kind text,text_value text,
                     detail_items jsonb,source_ref text)''',
                    (scope.workspace_id, scope.application_id,batch_id,
                     Jsonb(staged)))
                db.execute('''INSERT INTO epm.source_batch_chunk
                    (workspace_id,application_id,batch_id,chunk_index,
                     row_count,chunk_digest) VALUES (%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,batch_id,
                     chunk_index,len(prepared),digest))
                content_digest = sha256((batch['content_digest'] + digest)
                                        .encode('ascii')).hexdigest()
                db.execute('''UPDATE epm.source_batch SET
                    chunk_count=chunk_count+1,row_count=row_count+%s,
                    content_digest=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s''',
                    (len(prepared),content_digest,scope.workspace_id,
                     scope.application_id,batch_id))
                return {'batchId': batch_id, 'chunkIndex': chunk_index,
                        'rowCount': batch['row_count'] + len(prepared),
                        'contentDigest': content_digest,
                        'duplicate': False}

    def seal(self, scope: ApplicationScope, batch_id: str, *,
             expected_rows: int, expected_content_digest: str,
             replay_only: bool = False) -> dict | None:
        self._batch_id(batch_id)
        if (type(expected_rows) is not int or expected_rows < 0
                or not isinstance(expected_content_digest, str)
                or not _DIGEST.fullmatch(expected_content_digest)):
            raise ValueError('SOURCE_SEAL_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                if replay_only:
                    db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db, scope)
                access = group_import.source_access(db,self.identity,scope,'facts.source.seal')
                batch = self._owned_batch(db, scope, batch_id, lock=not replay_only)
                group_import.authorize_existing(db,self.identity,scope,access,batch)
                if (batch['row_count'] != expected_rows
                        or batch['content_digest'] != expected_content_digest):
                    raise ValueError('SOURCE_BATCH_CONTENT_MISMATCH')
                if batch['status'] == 'staging':
                    if replay_only:
                        return None
                    db.execute('''UPDATE epm.source_batch SET status='ready',
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND batch_id=%s''',
                        (scope.workspace_id,scope.application_id,batch_id))
                elif batch['status'] != 'ready':
                    raise ValueError('SOURCE_BATCH_NOT_SEALABLE')
                return {'batchId': batch_id, 'status': 'ready',
                        'rowCount': batch['row_count'],
                        'contentDigest': batch['content_digest']}

    def diagnose(self, scope: ApplicationScope, batch_id: str, *,
                 rows: list[object], allow_warnings: bool = False) -> dict:
        """Compile and retain diagnostics for a manifest-backed source.

        This accepts the raw transfer row shape, before typed staging rejects
        an invalid value.  The immutable artifact is therefore available even
        when no invalid row can safely be inserted into source_batch_row.
        """
        self._batch_id(batch_id)
        if (not isinstance(rows, list) or len(rows) > 100000
                or not isinstance(allow_warnings, bool)):
            raise ValueError('SOURCE_DIAGNOSTIC_REQUEST_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                batch = self._owned_batch(db, scope, batch_id)
                artifact, expiry = self._compile_diagnostics(
                    db, scope, batch, rows)
        saved = PostgresTransferArtifacts(
            self.dsn, identity=self.identity).save_import(
                scope, batch_id,
                idempotency_key='source-diagnostics-' + batch_id,
                artifact=artifact, expires_at=expiry)
        return self._diagnostic_result(
            saved, allow_warnings=allow_warnings, enforce=False)

    def preview(self, scope: ApplicationScope, batch_id: str, *,
                allow_warnings: bool = False) -> dict:
        self._batch_id(batch_id)
        if not isinstance(allow_warnings, bool):
            raise ValueError('SOURCE_DIAGNOSTIC_POLICY_INVALID')
        compiled = None
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                opening_access = group_import.source_access(db,self.identity,scope,PREVIEW)
                batch = self._owned_batch(db, scope, batch_id)
                group_import.check_model(opening_access,batch)
                if batch['group_numeric_import'] and allow_warnings:
                    raise ValueError(group_import.UNSUPPORTED)
                group_import.require_supported_policy(db,scope,self.identity,opening_access)
                if batch['status'] != 'ready':
                    raise ValueError('SOURCE_BATCH_NOT_READY')
                state = self._state(db, scope)
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                self._check_preparation_revisions(batch, state)
                copy_groups = self._authorize_copied_sources(
                    db, scope, batch, expected_access=opening_access)
                copy_access = opening_access if copy_groups is not None else None
                if copy_groups is not None:
                    # A copy stages live application facts at the admitted
                    # data revision, including the source of a replacement.
                    self._check_revisions(batch, state)
                if batch['group_numeric_import']:
                    group_import.authorize_existing(db,self.identity,scope,opening_access,batch,check_planning=True)
                self._validate_staged(db, scope, batch)
                if not batch['group_numeric_import']:
                    enforce_source_batch_dimensional_security(
                        db, self.identity, scope, batch, expected_access=copy_access)
                self._check_conflicts(db, scope, batch)
                self._check_locks(db, scope, batch)
                clears = self._clear_count(db, scope, batch)
                if batch['row_count'] + clears > 100000:
                    raise ValueError('SOURCE_PUBLICATION_ROW_LIMIT')
                if batch['expected_data_revision'] != state['data_revision']:
                    self._checked_replace_scope_digest(db, scope, batch, state)
                review = self._change_review(db, scope, batch, state, clears,
                                             expected_access=opening_access)
                if batch['manifest_digest'] is not None:
                    existing = self._diagnostic_artifact(db, scope, batch)
                    if existing is None:
                        rows = self._staged_diagnostic_rows(
                            db, scope, batch_id)
                        artifact, expiry = self._compile_diagnostics(
                            db, scope, batch, rows)
                        compiled = (artifact, expiry)
                    else:
                        diagnostic = self._diagnostic_result(
                            existing, allow_warnings=allow_warnings)
                        self._check_diagnostic_content(batch, existing)
                self._check_preview_cut(db, scope, state, opening_access, copy_groups)
        if compiled is not None:
            artifact, expiry = compiled
            saved = PostgresTransferArtifacts(
                self.dsn, identity=self.identity).save_import(
                    scope, batch_id,
                    idempotency_key='source-diagnostics-' + batch_id,
                    artifact=artifact, expires_at=expiry)
            diagnostic = self._diagnostic_result(
                saved, allow_warnings=allow_warnings)
            self._check_diagnostic_content(batch, saved)
            # Diagnostic retention uses a separate transaction. Recheck the
            # reviewed state again before returning examples or a signed token.
            with connect_postgres(self.dsn, row_factory=dict_row) as db:
                with db.transaction():
                    configure_statement_timeout(db, 5000)
                    PostgresNumericFactStore._set_scope(db, scope)
                    self._check_preview_cut(db, scope, state, opening_access, copy_groups)
        payload = {'scope': [scope.workspace_id, scope.application_id],
                   'identity': [self.identity.issuer,self.identity.subject_id],
                   'batchId': batch_id,
                   'contentDigest': batch['content_digest'],
                   'revisions': [batch['expected_metadata_revision'],
                                 batch['expected_data_revision']],
                   'securityRevision': state['security_revision'],
                   'expiresAt': int(time.time()) + 300}
        if batch['manifest_digest'] is not None:
            payload['diagnosticArtifactId'] = diagnostic['artifactId']
            payload['diagnosticsDigest'] = diagnostic['diagnosticsDigest']
        if batch['period_selection'] is not None:
            payload['scopeDigest'] = self._scope_digest(batch)
        raw = json.dumps(payload, sort_keys=True,separators=(',', ':'),
                         ensure_ascii=False).encode('utf-8')
        signature = hmac.new(self.preview_secret,raw,sha256).digest()
        result = {'batchId': batch_id, 'mode': batch['mode'],
                'setCount': batch['row_count'], 'clearCount': clears,
                'review': review,
                'contentDigest': batch['content_digest'],
                'previewToken': base64.urlsafe_b64encode(
                    raw + signature).decode('ascii')}
        if batch['manifest_digest'] is not None:
            result['diagnostics'] = diagnostic
        return result

    def _check_preview_cut(self, db, scope, state, opening_access, copy_groups):
        """Bind the examples and token to one business state and current authority."""
        require_current_copy_groups(db, self.identity, copy_groups)
        try:
            current = group_import.source_access(db,self.identity,scope,PREVIEW,expected_groups=opening_access.groups)
        except AccessGroupsChanged:
            raise ValueError('SOURCE_PREVIEW_AUTHORIZATION_STALE') from None
        if current != opening_access:
            raise ValueError('SOURCE_PREVIEW_AUTHORIZATION_STALE')
        latest = self._state(db, scope)
        if any(latest[key] != state[key] for key in (
                'metadata_revision', 'data_revision', 'commit_revision', 'security_revision',
                'processing_mode', 'application_status')):
            raise ValueError('STALE_SOURCE_BATCH_REVISION')

    def _change_review(self, db, scope, batch, state, clear_count, *,
                       expected_access: AccessDecision | None = None):
        """Bounded, read-authorized examples of this already validated intent.

        Examples explain the exact typed operation; they do not grant publish
        authority or replace the signed preview, current fences or full counts.
        Unreadable coordinates and their values are never returned.
        """
        rows = db.execute('''WITH staged AS MATERIALIZED (
            SELECT * FROM epm.source_batch_row WHERE workspace_id=%s
            AND application_id=%s AND batch_id=%s ORDER BY row_ordinal LIMIT %s)
            SELECT r.members,r.value_kind,r.amount,r.text_value,r.detail_items,
              r.source_ref,n.present AS numeric_present,n.amount AS numeric_before,
              t.present AS text_present,t.text_value AS text_before,
              d.items AS detail_before,d.total AS detail_total_before
            FROM staged r LEFT JOIN epm.coordinate c
              ON c.workspace_id=r.workspace_id AND c.application_id=r.application_id
              AND c.series_key=r.series_key
            LEFT JOIN epm.numeric_cell_current n ON n.workspace_id=c.workspace_id
              AND n.application_id=c.application_id AND n.coordinate_id=c.coordinate_id
            LEFT JOIN epm.text_cell_current t ON t.workspace_id=c.workspace_id
              AND t.application_id=c.application_id AND t.coordinate_id=c.coordinate_id
            LEFT JOIN epm.line_detail_current d ON d.workspace_id=c.workspace_id
              AND d.application_id=c.application_id AND d.coordinate_id=c.coordinate_id
            ORDER BY r.row_ordinal''', (scope.workspace_id, scope.application_id,
                batch['batch_id'], _REVIEW_SAMPLE_LIMIT)).fetchall()
        examples, restricted = [], False
        for row in rows:
            if not coordinate_read_allowed(db, self.identity, scope,
                                           Coordinate.from_mapping(row['members']),
                                           expected_access=expected_access):
                restricted = True
                continue
            kind = row['value_kind']
            before = {'present': bool(row[f'{kind}_present'])} if kind != 'detail' else {
                'present': row['detail_before'] is not None}
            after = {'present': True}
            if kind == 'numeric':
                if before['present']:
                    before['amount'] = format(row['numeric_before'], 'f')
                after['amount'] = format(row['amount'], 'f')
            elif kind == 'text':
                if before['present']:
                    before['text'] = row['text_before']
                after['text'] = row['text_value']
            else:
                if before['present']:
                    before.update(items=row['detail_before'],
                                  amount=format(row['detail_total_before'], 'f'))
                after.update(items=row['detail_items'], amount=format(row['amount'], 'f'))
            example = {'action': 'set', 'members': row['members'],
                'valueKind': kind, 'sourceRef': row['source_ref'],
                'before': before, 'after': after}
            if kind == 'detail':
                numeric_before = {'present': bool(row['numeric_present'])}
                if numeric_before['present']:
                    numeric_before['amount'] = format(row['numeric_before'], 'f')
                example['companionChanges'] = [{'valueKind': 'numeric',
                    'before': numeric_before,
                    'after': {'present': True, 'amount': format(row['amount'], 'f')}}]
            elif kind == 'numeric' and row['detail_before'] is not None:
                # Only an already permitted replacement can reach this branch;
                # the review does not relax _check_conflicts.
                example['companionChanges'] = [{'valueKind': 'detail',
                    'before': {'present': True, 'items': row['detail_before'],
                               'amount': format(row['detail_total_before'], 'f')},
                    'after': {'present': False}}]
            examples.append(example)
        clear_examples = []
        if batch['mode'] == 'replace':
            for table, kinds, kind, column in (
                    ('numeric_cell_current', ['numeric', 'detail'], 'numeric', 'amount'),
                    ('text_cell_current', ['text'], 'text', 'text_value')):
                fragment, params = _omitted_source_targets(scope, batch, table, kinds)
                # A numeric omission also removes any supporting detail. Use
                # exact coordinate-correlated lookups without changing the
                # shared omitted-target predicate or its fact counts.
                detail = (''' ,(SELECT d.items FROM epm.line_detail_current d
                    WHERE d.workspace_id=n.workspace_id AND d.application_id=n.application_id
                    AND d.coordinate_id=n.coordinate_id) AS detail_items,
                    (SELECT d.total FROM epm.line_detail_current d
                    WHERE d.workspace_id=n.workspace_id AND d.application_id=n.application_id
                    AND d.coordinate_id=n.coordinate_id) AS detail_total'''
                    if kind == 'numeric' else '')
                omitted = db.execute(f'SELECT c.members,n.{column} AS value' + detail + fragment +
                    ' ORDER BY c.series_key COLLATE "C" LIMIT %s',
                    (*params, _REVIEW_SAMPLE_LIMIT)).fetchall()
                for row in omitted:
                    if not coordinate_read_allowed(db, self.identity, scope,
                                                   Coordinate.from_mapping(row['members']),
                                                   expected_access=expected_access):
                        restricted = True
                        continue
                    before = {'present': True, ('amount' if kind == 'numeric' else 'text'):
                              format(row['value'], 'f') if kind == 'numeric' else row['value']}
                    example = {'action': 'clear', 'members': row['members'],
                        'valueKind': kind, 'sourceRef': None,
                        'before': before, 'after': {'present': False}}
                    if kind == 'numeric' and row['detail_items'] is not None:
                        example['companionChanges'] = [{'valueKind': 'detail',
                            'before': {'present': True, 'items': row['detail_items'],
                                       'amount': format(row['detail_total'], 'f')},
                            'after': {'present': False}}]
                    clear_examples.append(example)
        clear_examples.sort(key=lambda item: (sorted(item['members'].items()), item['valueKind']))
        clear_examples = clear_examples[:_REVIEW_SAMPLE_LIMIT]
        bounded = []
        used = 2
        for example in examples + clear_examples:
            size = len(json.dumps(example, ensure_ascii=False, separators=(',', ':')).encode()) + 1
            if used + size > _REVIEW_SAMPLE_BYTES:
                continue
            bounded.append(example)
            used += size
        return {'format': 'openepm-source-change-review-v1',
            'mode': batch['mode'], 'scopeMembers': batch['scope_members'],
            'scopeAll': batch['scope_all'], 'periodSelection': batch['period_selection'],
            'metadataRevision': state['metadata_revision'],
            'dataRevision': state['data_revision'], 'commitRevision': state['commit_revision'],
            'sampleLimitPerAction': _REVIEW_SAMPLE_LIMIT,
            'sampleByteLimit': _REVIEW_SAMPLE_BYTES,
            'setsComplete': sum(item['action'] == 'set' for item in bounded) == batch['row_count'],
            'clearsComplete': sum(item['action'] == 'clear' for item in bounded) == clear_count,
            'readRestricted': restricted, 'examples': bounded}

    @staticmethod
    def _require_exact_group_preview(batch, token):
        if not hmac.compare_digest(group_import.preview_digest(token),batch['publication_preview_digest']):
            raise ValueError('SOURCE_PREVIEW_STALE_OR_MISMATCHED')

    @staticmethod
    def _published_result(db, scope, batch):
        digest = (batch['result'] or {}).get('impactDigest')
        if digest is not None:
            from .postgres_calculation_impact import require_recorded_impact
            require_recorded_impact(db, scope, operation_id=batch['batch_id'],
                                   expected_digest=digest)
        return batch['result']

    def replay_publication(self, scope: ApplicationScope, batch_id: str, *, preview_token: str | None = None) -> dict | None:
        """Reconcile the owned batch receipt; never consume or renew a preview."""
        self._batch_id(batch_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = group_import.source_access(db,self.identity,scope,PUBLISH)
                self._authorize_publication(db, scope)
                batch = self._owned_batch(db, scope, batch_id)
                group_import.authorize_existing(db,self.identity,scope,access,batch)
                if batch['group_numeric_import'] and batch['status']=='published':
                    self._require_exact_group_preview(batch,preview_token)
                return (self._published_result(db, scope, batch)
                        if batch['status'] == 'published' else None)

    def publish(self, scope: ApplicationScope, batch_id: str, *,
                preview_token: str) -> dict:
        self._batch_id(batch_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                opening_access = group_import.source_access(db,self.identity,scope,PUBLISH)
                state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.commit_revision,s.security_revision,
                    s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    ''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                self._authorize_publication(db, scope)
                batch = self._owned_batch(db, scope, batch_id, lock=True)
                group_import.check_model(opening_access,batch)
                if batch['status'] == 'published':
                    if batch['group_numeric_import']:
                        self._require_exact_group_preview(batch,preview_token)
                        group_import.authorize_existing(db,self.identity,scope,opening_access,batch)
                    return self._published_result(db, scope, batch)
                diagnostic = (self._diagnostic_artifact(db, scope, batch)
                              if batch['manifest_digest'] is not None else None)
                self._verify_token(
                    preview_token, scope, batch, diagnostic,
                    security_revision=state['security_revision'])
                if batch['manifest_digest'] is not None:
                    self._diagnostic_result(diagnostic, allow_warnings=True)
                    self._check_diagnostic_content(batch, diagnostic)
                if batch['status'] != 'ready':
                    raise ValueError('SOURCE_BATCH_NOT_READY')
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                self._check_preparation_revisions(batch, state)
                copy_groups = self._authorize_copied_sources(
                    db, scope, batch, expected_access=opening_access)
                copy_access = opening_access if copy_groups is not None else None
                if copy_groups is not None:
                    self._check_revisions(batch, state)
                if batch['group_numeric_import']:
                    group_import.authorize_existing(db,self.identity,scope,opening_access,batch)
                self._validate_staged(db, scope, batch)
                if not batch['group_numeric_import']:
                    enforce_source_batch_dimensional_security(
                        db, self.identity, scope, batch, expected_access=copy_access)
                self._check_locks(db, scope, batch)
                clears = self._clear_count(db, scope, batch)
                total = batch['row_count'] + clears
                if total > 100000:
                    raise ValueError('SOURCE_PUBLICATION_ROW_LIMIT')
                self._check_conflicts(db, scope, batch)
                details_to_clear = self._detail_clear_count(
                    db, scope, batch)
                # A merge names every target.  Lock a bounded deterministic
                # shard set and retain an exact current-value digest while the
                # application publication row remains free.  Disjoint merges
                # can perform validation together; overlapping merges share a
                # shard and cannot both prepare from the same target state.
                # Replace fences the full scope because implicit clears can
                # target coordinates absent from the staged batch.
                target_digest = None
                if batch['mode'] == 'merge':
                    before_target_lock = self._merge_target_digest(
                        db, scope, batch)
                    self._lock_merge_target_shards(db, scope, batch)
                    target_digest = self._merge_target_digest(
                        db, scope, batch)
                    if target_digest != before_target_lock:
                        raise ValueError('STALE_SOURCE_BATCH_REVISION')
                elif batch['expected_commit_revision'] is not None:
                    target_digest = self._checked_replace_scope_digest(
                        db, scope, batch, state)

                state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.commit_revision,s.security_revision,
                    s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                # A preview is an authorization-sensitive approval, not only
                # a content digest.  Reverify its security revision under the
                # short publication fence so any intervening assignment or
                # active-policy change requires a fresh preview.
                self._verify_token(
                    preview_token, scope, batch, diagnostic,
                    security_revision=state['security_revision'])
                if copy_groups is not None:
                    # An unchanged destination cannot prove that the staged
                    # copy still reflects its source. Keep the admitted data
                    # revision pinned until this transaction commits.
                    self._check_revisions(batch, state)
                else:
                    self._check_publication_revisions(
                        db, scope, batch, state, target_digest)
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                # Preparation can outlive a grant, public worker fence,
                # planning lock or target-family change.  Repeat all mutable
                # publication controls under the short application fence.
                access = group_import.source_access(db,self.identity,scope,PUBLISH)
                if copy_access is not None and access != copy_access:
                    raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
                self._authorize_publication(db, scope)
                require_current_copy_groups(db, self.identity, copy_groups)
                if batch['group_numeric_import']:
                    group_import.authorize_existing(db,self.identity,scope,access,batch)
                else:
                    enforce_source_batch_dimensional_security(
                        db, self.identity, scope, batch, expected_access=copy_access)
                self._check_locks(db, scope, batch)
                self._check_conflicts(db, scope, batch)
                policy_evidence = enforce_source_batch_policy(
                    db, scope, batch, access.role, identity=self.identity)
                self._ensure_coordinates(db, scope, batch_id)
                revision = state['commit_revision'] + 1
                source_kinds=db.execute('''SELECT value_kind,count(*) n
                    FROM epm.source_batch_row WHERE workspace_id=%s
                    AND application_id=%s AND batch_id=%s
                    GROUP BY value_kind''',(scope.workspace_id,
                    scope.application_id,batch_id)).fetchall()
                domain_counts={row['value_kind']:row['n']
                               for row in source_kinds}
                impact_domains=[]
                if (domain_counts.get('numeric',0)
                        or domain_counts.get('detail',0) or clears):
                    impact_domains.append('numeric_fact')
                if domain_counts.get('text',0) or clears:
                    impact_domains.append('text_fact')
                if domain_counts.get('detail',0) or details_to_clear:
                    impact_domains.append('line_detail')
                from .calculation_impact_contract import (
                    compile_calculation_impact)
                impact=compile_calculation_impact({
                    'format':'openepm-calculation-impact-v1',
                    'sourceKind':'source_replace','sourceId':batch_id,
                    'causalRevision':revision,
                    'effects':[{'domain':domain,'change':'replace',
                        'objectType':'source_batch','objectId':batch_id,
                        'scope':[{'dimensionId':axis,'memberId':member}
                                 for axis,member in
                                 sorted(batch['scope_members'].items())],
                        'reason':'data_changed','oldPresence':'unknown',
                        'newPresence':'unknown'} for domain in impact_domains]})
                result = {'batchId': batch_id,'mode': batch['mode'],
                          'setCount': batch['row_count'],
                          'clearCount': clears,'changedCount': total,
                          'committedRevision': revision,
                          'contentDigest': batch['content_digest'],
                          'impactDigest':impact.digest}
                if diagnostic is not None:
                    result['diagnosticArtifactId'] = diagnostic['artifactId']
                    result['diagnosticsDigest'] = \
                        diagnostic['artifact']['diagnosticsDigest']
                if policy_evidence is not None:
                    result['planningPolicy'] = policy_evidence
                db.execute('''UPDATE epm.application_state SET
                    data_revision=data_revision+1,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,batch_id,
                     batch['content_digest'],self.identity.subject_id,
                     revision,Jsonb(result)))
                numeric_events = self._write_events(
                    db, scope, batch, revision,
                    empty_application=state['data_revision']==0)
                text_events = self._write_text_events(
                    db, scope, batch, revision,
                    empty_application=state['data_revision']==0)
                if numeric_events + text_events != total:
                    raise ValueError('SOURCE_PUBLICATION_COUNT_CHANGED')
                self._project_numeric_events(
                    db,scope,batch_id,numeric_events)
                db.execute('''INSERT INTO epm.text_cell_projection
                    (workspace_id,application_id,coordinate_id,present,
                     text_value,change_id,last_revision,projection_generation)
                    SELECT workspace_id,application_id,coordinate_id,present,
                           resulting_value,change_id,committed_revision,(SELECT epm.active_projection_generation())
                    FROM epm.text_fact_event
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s
                    ON CONFLICT (workspace_id,application_id,projection_generation,coordinate_id)
                    DO UPDATE SET present=EXCLUDED.present,
                    text_value=EXCLUDED.text_value,
                    change_id=EXCLUDED.change_id,
                    last_revision=EXCLUDED.last_revision''',
                    (scope.workspace_id,scope.application_id,batch_id))
                detail_events = self._write_detail_events(
                    db, scope, batch, revision,
                    empty_application=state['data_revision']==0)
                expected_details = db.execute('''SELECT count(*) AS total
                    FROM epm.source_batch_row WHERE workspace_id=%s
                    AND application_id=%s AND batch_id=%s
                    AND value_kind='detail' ''',
                    (scope.workspace_id,scope.application_id,
                     batch_id)).fetchone()['total']
                if detail_events != expected_details + details_to_clear:
                    raise ValueError('SOURCE_DETAIL_PUBLICATION_COUNT_CHANGED')
                self._finalize_seed_lineage(db, scope, batch, revision)
                from .postgres_calculation_impact import (
                    record_calculation_impact)
                record_calculation_impact(db,scope,operation_id=batch_id,
                                          impact=impact)
                db.execute('''UPDATE epm.source_batch SET
                    status='published',receipt_revision=%s,result=%s,publication_preview_digest=%s,
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s''',
                    (revision,Jsonb(result), group_import.preview_digest(preview_token) if batch['group_numeric_import'] else None,
                     scope.workspace_id,scope.application_id,batch_id))
                # This is intentionally the last effect-boundary statement.
                # A stale external worker claim raises here and rolls the
                # source events, projections, receipt, lineage and batch back.
                require_current_copy_groups(db, self.identity, copy_groups)
                self._finalize_publication(db, scope)
                return result

    @staticmethod
    def _finalize_seed_lineage(db, scope, batch, revision):
        """Bind prepared Seed source versions to this atomic publication."""
        seeded = db.execute('''SELECT count(*) AS total
            FROM epm.planning_seed_lineage WHERE workspace_id=%s
            AND application_id=%s AND batch_id=%s''',
            (scope.workspace_id,scope.application_id,
             batch['batch_id'])).fetchone()['total']
        origin = db.execute('''SELECT normalized_program FROM
            epm.planning_copy_origin WHERE workspace_id=%s
            AND application_id=%s AND batch_id=%s''',
            (scope.workspace_id,scope.application_id,
             batch['batch_id'])).fetchone()
        policy = (origin['normalized_program'].get('reusablePolicy')
                  if origin and isinstance(origin['normalized_program'],dict)
                  else None)
        if not seeded and policy is None:
            return
        updated = db.execute('''SELECT epm.finalize_planning_seed_lineage(
            %s,%s,%s,%s) AS total''',(scope.workspace_id,
            scope.application_id,batch['batch_id'],revision)).fetchone()['total']
        if updated != seeded:
            raise ValueError('SCENARIO_COPY_TARGET_LINEAGE_CHANGED')
        if policy is None or batch['mode'] != 'replace':
            return
        inserted = db.execute('''WITH existing AS (
              SELECT COALESCE(max(action_ordinal),0) AS offset
              FROM epm.planning_seed_lineage WHERE workspace_id=%s
               AND application_id=%s AND batch_id=%s), clears AS (
              SELECT c.series_key,c.coordinate_id,
                CASE WHEN d.change_id IS NOT NULL THEN 'Detail'
                     ELSE 'Numeric' END AS family,
                n.change_id,CASE WHEN d.change_id IS NOT NULL THEN d.change_id END
                  AS detail_change_id
              FROM epm.numeric_fact_event n JOIN epm.coordinate c
                ON c.workspace_id=n.workspace_id AND c.application_id=n.application_id
               AND c.coordinate_id=n.coordinate_id
              LEFT JOIN epm.line_detail_event d ON d.workspace_id=n.workspace_id
               AND d.application_id=n.application_id AND d.coordinate_id=n.coordinate_id
               AND d.operation_id=n.operation_id AND NOT d.present
              WHERE n.workspace_id=%s AND n.application_id=%s
               AND n.operation_id=%s AND n.kind='clear'
              UNION ALL
              SELECT c.series_key,c.coordinate_id,'Text',t.change_id,NULL
              FROM epm.text_fact_event t JOIN epm.coordinate c
                ON c.workspace_id=t.workspace_id AND c.application_id=t.application_id
               AND c.coordinate_id=t.coordinate_id
              WHERE t.workspace_id=%s AND t.application_id=%s
               AND t.operation_id=%s AND t.kind='clear'), numbered AS (
              SELECT *,row_number() OVER (ORDER BY series_key,family) AS ordinal
              FROM clears)
            INSERT INTO epm.planning_seed_lineage
             (workspace_id,application_id,batch_id,action_ordinal,action,
              value_family,target_series_key,target_coordinate_id,target_change_id,
              target_detail_change_id,target_committed_revision,policy_id,
              policy_state_token,policy_digest,content_digest)
            SELECT %s,%s,%s,e.offset+n.ordinal,'ReplaceClear',n.family,
              n.series_key,n.coordinate_id,n.change_id,n.detail_change_id,%s,
              %s,%s,%s,%s FROM numbered n CROSS JOIN existing e''',
            (scope.workspace_id,scope.application_id,batch['batch_id'],
             scope.workspace_id,scope.application_id,batch['batch_id'],
             scope.workspace_id,scope.application_id,batch['batch_id'],
             scope.workspace_id,scope.application_id,batch['batch_id'],revision,
             policy['policyId'],policy['stateToken'],policy['policyDigest'],
             batch['content_digest'])).rowcount
        if inserted + seeded > 100000:
            raise ValueError('SOURCE_PUBLICATION_ROW_LIMIT')

    def published_result(self, scope: ApplicationScope,
                         batch_id: str) -> dict:
        """Return a caller-owned settled receipt for idempotent orchestration."""
        self._batch_id(batch_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                self._authorize_publication(db, scope)
                batch = self._owned_batch(db, scope, batch_id)
                if (batch['status'] != 'published'
                        or not isinstance(batch['result'], dict)):
                    raise ValueError('SOURCE_BATCH_NOT_PUBLISHED')
                return batch['result']

    @classmethod
    def request_cancel_as_task_controller(
            cls, dsn: str, *, identity: VerifiedIdentity,
            scope: ApplicationScope, batch_id: str) -> dict:
        """Cancel uncommitted staging through current owner/admin authority."""
        if (not isinstance(dsn, str) or not dsn
                or not isinstance(identity, VerifiedIdentity)):
            raise ValueError('SOURCE_BATCH_UNAVAILABLE')
        self = object.__new__(cls)
        self.dsn, self.identity = dsn, identity
        self._batch_id(batch_id)
        if not isinstance(scope, ApplicationScope):
            raise ValueError('SOURCE_BATCH_UNAVAILABLE')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                PostgresNumericFactStore._set_scope(db, scope)
                access = group_import.source_access(db,self.identity,scope,CANCEL)
                batch = db.execute('''SELECT issuer,subject_id,status,group_numeric_import
                    FROM epm.source_batch WHERE workspace_id=%s
                    AND application_id=%s AND batch_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     batch_id)).fetchone()
                if batch is None:
                    raise ValueError('SOURCE_BATCH_UNAVAILABLE')
                owner = (batch['issuer'], batch['subject_id']) == (
                    self.identity.issuer, self.identity.subject_id)
                group_import.check_model(access,batch)
                if not owner and batch['group_numeric_import']:
                    raise ValueError('SOURCE_BATCH_UNAVAILABLE')
                if not owner:
                    try:
                        PostgresAccessChecker.check_in_transaction(
                            db, self.identity, scope, 'admin')
                    except AccessDenied as error:
                        raise ValueError('SOURCE_BATCH_UNAVAILABLE') from error
                if batch['status'] in ('staging', 'ready'):
                    changed = db.execute('''UPDATE epm.source_batch
                        SET status='cancelled',updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND batch_id=%s AND status IN('staging','ready')''',
                        (scope.workspace_id, scope.application_id,
                         batch_id)).rowcount
                    if changed != 1:
                        raise ValueError('SOURCE_BATCH_STATE_STALE')
                    status = 'cancelled'
                else:
                    status = batch['status']
                return {'batchId': batch_id, 'status': status,
                        'committedEffectsRemain': status == 'published'}

    def cancel(self, scope: ApplicationScope, batch_id: str) -> dict:
        """Cancel this owned staged business input through its typed lifecycle."""
        return self.request_cancel_as_task_controller(
            self.dsn, identity=self.identity, scope=scope, batch_id=batch_id)

    @staticmethod
    def _batch_id(batch_id: str) -> None:
        if not isinstance(batch_id, str) or not _BATCH.fullmatch(batch_id):
            raise ValueError('SOURCE_BATCH_ID_INVALID')

    def _owned_batch(self, db, scope, batch_id, *, lock=False):
        row = db.execute(f'''SELECT * FROM epm.source_batch
            WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
            {'FOR UPDATE' if lock else ''}''',
            (scope.workspace_id,scope.application_id,batch_id)).fetchone()
        if (row is None or row['issuer'] != self.identity.issuer
                or row['subject_id'] != self.identity.subject_id):
            raise ValueError('SOURCE_BATCH_UNAVAILABLE')
        return row

    @staticmethod
    def _staged_diagnostic_rows(db, scope, batch_id):
        rows = db.execute('''SELECT members,value_kind,amount,text_value,
            detail_items,source_ref FROM epm.source_batch_row
            WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
            ORDER BY row_ordinal''',
            (scope.workspace_id, scope.application_id, batch_id)).fetchall()
        output = []
        for row in rows:
            if row['value_kind'] == 'numeric':
                value = {'type': 'AmountLiteral',
                         'decimal': format(row['amount'], 'f')}
            elif row['value_kind'] == 'text':
                value = {'type': 'TextLiteral', 'text': row['text_value']}
            elif row['value_kind'] == 'detail':
                value = {'type': 'LineDetailLiteral', 'items': [
                    {'description': item['description'],
                     'decimal': item['amount']}
                    for item in row['detail_items']]}
            else:
                value = {'type': row['value_kind']}
            output.append({'members': row['members'], 'value': value,
                           'sourceRef': row['source_ref']})
        return output

    @staticmethod
    def _compile_diagnostics(db, scope, batch, rows):
        if (batch['manifest_digest'] is None
                or batch['manifest_content_digest'] is None
                or batch['manifest_schema_digest'] is None
                or batch['manifest_created_at'] is None):
            raise ValueError('SOURCE_UPLOAD_MANIFEST_REQUIRED')
        dimensions = [row['dimension_id'] for row in db.execute('''
            SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            AND model_role IS DISTINCT FROM 'Currency'
            ORDER BY dimension_id''',
            (scope.workspace_id, scope.application_id)).fetchall()]
        member_rows = db.execute('''SELECT dimension_id,member_id
            FROM epm.member WHERE workspace_id=%s AND application_id=%s
            AND status='Active' AND dimension_id=ANY(%s::text[])
            ORDER BY dimension_id,member_id''',
            (scope.workspace_id, scope.application_id, dimensions)).fetchall()
        members = {dimension: {} for dimension in dimensions}
        for row in member_rows:
            members[row['dimension_id']][row['member_id']] = [row['member_id']]
        identity = SourceDiagnosticIdentity(
            batch['manifest_digest'], batch['manifest_content_digest'],
            batch['manifest_schema_digest'])
        artifact = compile_source_import_diagnostics(
            identity=identity, rows=rows, required_dimensions=dimensions,
            dimension_candidates={value: [value] for value in dimensions},
            member_candidates=members, mode=batch['mode'],
            scope_members=batch['scope_members'], scope_all=batch['scope_all'])
        expiry = int(batch['manifest_created_at'].timestamp()) + 30 * 86400
        return artifact, expiry

    @staticmethod
    def _diagnostic_artifact(db, scope, batch):
        row = db.execute('''SELECT *,
            (retention_status='expired' OR expires_at_epoch<=
             extract(epoch FROM transaction_timestamp())::bigint) AS expired
            FROM epm.source_import_diagnostic_artifact
            WHERE workspace_id=%s AND application_id=%s AND batch_id=%s''',
            (scope.workspace_id, scope.application_id,
             batch['batch_id'])).fetchone()
        if row is None:
            return None
        PostgresTransferArtifacts._verify_import_row(scope, row)
        artifact, _ = _validated_diagnostics(row['artifact'])
        if artifact['sourceIdentity'] != {
                'manifestDigest': batch['manifest_digest'],
                'contentDigest': batch['manifest_content_digest'],
                'schemaDigest': batch['manifest_schema_digest']}:
            raise ValueError('SOURCE_DIAGNOSTIC_IDENTITY_DRIFT')
        return {'artifactId': row['artifact_id'], 'artifact': artifact,
                'expiresAt': row['expires_at_epoch'],
                'expired': row['expired'], 'duplicate': True,
                'retention': {'status': row['retention_status']}}

    @staticmethod
    def _diagnostic_result(saved, *, allow_warnings, enforce=True):
        if saved is None:
            raise ValueError('SOURCE_DIAGNOSTIC_ARTIFACT_REQUIRED')
        artifact = saved['artifact']
        if saved.get('expired') or saved['retention']['status'] == 'expired':
            raise ValueError('SOURCE_DIAGNOSTIC_ARTIFACT_EXPIRED')
        if enforce and (not artifact['accepted'] or artifact['errorCount']):
            raise ValueError('SOURCE_IMPORT_DIAGNOSTICS_REJECTED')
        if enforce and artifact['warningCount'] and not allow_warnings:
            raise ValueError('SOURCE_IMPORT_WARNINGS_REQUIRE_POLICY')
        return {'artifactId': saved['artifactId'],
                'diagnosticsDigest': artifact['diagnosticsDigest'],
                'diagnosticCount': artifact['diagnosticCount'],
                'errorCount': artifact['errorCount'],
                'warningCount': artifact['warningCount'],
                'accepted': artifact['accepted'],
                'warningsAllowed': allow_warnings,
                'admissionAllowed': (artifact['accepted'] and
                                     (allow_warnings or
                                      artifact['warningCount'] == 0))}

    @staticmethod
    def _check_diagnostic_content(batch, diagnostic):
        if (batch['manifest_content_digest'] != batch['content_digest']
                or diagnostic['artifact']['sourceIdentity']['contentDigest'] !=
                   batch['content_digest']):
            raise ValueError('SOURCE_MANIFEST_CONTENT_DRIFT')

    @staticmethod
    def _state(db, scope):
        state = db.execute('''SELECT s.metadata_revision,s.data_revision,
            s.commit_revision,s.security_revision,s.processing_mode,
            a.status AS application_status
            FROM epm.application_state s JOIN epm.application a
            USING (workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s''',
            (scope.workspace_id,scope.application_id)).fetchone()
        if state is None:
            raise ValueError('APPLICATION_UNAVAILABLE')
        return state

    @staticmethod
    def _check_revisions(batch, state):
        if (batch['expected_metadata_revision'] != state['metadata_revision']
                or batch['expected_data_revision'] != state['data_revision']):
            raise ValueError('STALE_SOURCE_BATCH_REVISION')

    @staticmethod
    def _check_preparation_revisions(batch, state):
        if batch['expected_metadata_revision'] != state['metadata_revision']:
            raise ValueError('STALE_SOURCE_BATCH_REVISION')
        if batch['expected_data_revision'] == state['data_revision']:
            return
        # A new replace batch retains the immutable commit boundary captured
        # when its caller-supplied data revision was admitted. Preview and
        # publication check its complete effect scope against that boundary.
        # Historical batches without that pin keep the exact revision check.
        if (batch['mode'] != 'replace'
                or batch['expected_commit_revision'] is None):
            raise ValueError('STALE_SOURCE_BATCH_REVISION')

    def _checked_replace_scope_digest(self, db, scope, batch, state):
        expected = batch['expected_commit_revision']
        digest = self._replace_scope_digest(db, scope, batch, expected)
        if (state['commit_revision'] != expected
                and self._replace_scope_digest(
                    db, scope, batch, state['commit_revision']) != digest):
            raise ValueError('STALE_SOURCE_BATCH_REVISION')
        return digest

    @staticmethod
    def _check_publication_revisions(db, scope, batch, state,
                                     prepared_target_digest):
        if batch['expected_metadata_revision'] != state['metadata_revision']:
            raise ValueError('STALE_SOURCE_BATCH_REVISION')
        if batch['expected_data_revision'] == state['data_revision']:
            return
        if prepared_target_digest is None:
            raise ValueError('STALE_SOURCE_BATCH_REVISION')
        if batch['mode'] == 'merge':
            current = PostgresSourceBatch._merge_target_digest(
                db, scope, batch)
        elif (batch['mode'] == 'replace'
              and batch['expected_commit_revision'] is not None):
            current = PostgresSourceBatch._replace_scope_digest(
                db, scope, batch, state['commit_revision'])
        else:
            raise ValueError('STALE_SOURCE_BATCH_REVISION')
        if current != prepared_target_digest:
            raise ValueError('STALE_SOURCE_BATCH_REVISION')

    @staticmethod
    def _lock_merge_target_shards(db, scope, batch):
        """Serialize overlapping merge targets with at most 64 locks.

        Advisory locks are collision-safe: unrelated targets may occasionally
        wait on the same shard, but an overlapping series can never escape the
        same shard.  The bound avoids exhausting PostgreSQL's shared lock table
        for a permitted 100,000-row source batch.
        """
        db.execute('''WITH shards AS (
            SELECT DISTINCT (hashtextextended(series_key,0) & 63)::integer shard
            FROM epm.source_batch_row
            WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
        ) SELECT pg_advisory_xact_lock(hashtextextended(
            %s || ':' || shard::text,0)) FROM shards ORDER BY shard''',
            (scope.workspace_id, scope.application_id, batch['batch_id'],
             'epm.pov.source:' + scope.workspace_id + ':' +
             scope.application_id))

    @staticmethod
    def _merge_target_digest(db, scope, batch):
        """Hash exact current target state for disjoint merge revalidation."""
        # Fence the already bounded batch target before joining the three
        # current projections.  Without this boundary PostgreSQL may expand
        # the RLS-scoped joins before applying the batch predicate, turning a
        # 500-row public CSV publication into a statement-timeout plan.
        return db.execute('''WITH staged AS MATERIALIZED (
            SELECT series_key,members FROM epm.source_batch_row
            WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
        ) SELECT encode(sha256(convert_to(COALESCE(
            string_agg(jsonb_build_array(
                r.series_key,r.members,c.members,
                n.present,n.amount::text,n.change_id,n.last_revision,
                t.present,t.text_value,t.change_id,t.last_revision,
                d.items,d.total::text,d.change_id,d.last_revision
            )::text,E'\\n' ORDER BY r.series_key),''),'UTF8')),'hex') digest
            FROM staged r
            LEFT JOIN epm.coordinate c ON c.workspace_id=%s
             AND c.application_id=%s AND c.series_key=r.series_key
            LEFT JOIN epm.numeric_cell_current n ON n.workspace_id=%s
             AND n.application_id=%s
             AND n.coordinate_id=c.coordinate_id
            LEFT JOIN epm.text_cell_current t ON t.workspace_id=%s
             AND t.application_id=%s
             AND t.coordinate_id=c.coordinate_id
            LEFT JOIN epm.line_detail_current d ON d.workspace_id=%s
             AND d.application_id=%s AND d.coordinate_id=c.coordinate_id''',
            (scope.workspace_id,scope.application_id,batch['batch_id'],
             scope.workspace_id,scope.application_id,
             scope.workspace_id,scope.application_id,
             scope.workspace_id,scope.application_id,
             scope.workspace_id,scope.application_id)).fetchone()['digest']

    @staticmethod
    def _replace_scope_digest(db, scope, batch, commit_revision):
        """Digest the complete replacement scope at an immutable boundary."""
        if (type(commit_revision) is not int or commit_revision < 0):
            raise ValueError('STALE_SOURCE_BATCH_REVISION')
        predicate, params = _scope_predicate(
            batch['scope_members'], batch['period_selection'])
        return db.execute(f'''WITH points AS (
            SELECT c.coordinate_id,c.series_key FROM epm.coordinate c
            WHERE c.workspace_id=%s AND c.application_id=%s {predicate}
        ), numeric_history AS (
            SELECT DISTINCT ON (e.coordinate_id) p.series_key,e.present,
              e.resulting_amount,e.change_id,e.committed_revision,e.line_ordinal
            FROM points p JOIN epm.numeric_fact_event e
              ON e.workspace_id=%s AND e.application_id=%s
             AND e.coordinate_id=p.coordinate_id
            WHERE e.committed_revision<=%s
            ORDER BY e.coordinate_id,e.committed_revision DESC,
                     e.line_ordinal DESC
        ), text_history AS (
            SELECT DISTINCT ON (e.coordinate_id) p.series_key,e.present,
              e.resulting_value,e.change_id,e.committed_revision,e.line_ordinal
            FROM points p JOIN epm.text_fact_event e
              ON e.workspace_id=%s AND e.application_id=%s
             AND e.coordinate_id=p.coordinate_id
            WHERE e.committed_revision<=%s
            ORDER BY e.coordinate_id,e.committed_revision DESC,
                     e.line_ordinal DESC
        ), detail_history AS (
            SELECT DISTINCT ON (e.coordinate_id) p.series_key,e.present,
              e.items,e.total,e.change_id,e.committed_revision,e.event_id
            FROM points p JOIN epm.line_detail_event e
              ON e.workspace_id=%s AND e.application_id=%s
             AND e.coordinate_id=p.coordinate_id
            WHERE e.committed_revision<=%s
            ORDER BY e.coordinate_id,e.committed_revision DESC,e.event_id DESC
        ), states AS (
            SELECT series_key,'numeric'::text family,
              jsonb_build_array(present,resulting_amount::text,change_id,
                                committed_revision,line_ordinal) state
            FROM numeric_history
            UNION ALL
            SELECT series_key,'text',
              jsonb_build_array(present,resulting_value,change_id,
                                committed_revision,line_ordinal)
            FROM text_history
            UNION ALL
            SELECT series_key,'detail',
              jsonb_build_array(present,items,total::text,change_id,
                                committed_revision,event_id)
            FROM detail_history
        ) SELECT encode(sha256(convert_to(COALESCE(string_agg(
            jsonb_build_array(series_key,family,state)::text,E'\\n'
            ORDER BY series_key,family),''),'UTF8')),'hex') digest FROM states''',
            (scope.workspace_id, scope.application_id, *params,
             scope.workspace_id, scope.application_id, commit_revision,
             scope.workspace_id, scope.application_id, commit_revision,
             scope.workspace_id, scope.application_id,
             commit_revision)).fetchone()['digest']

    @staticmethod
    def _check_scope_members(db, scope, members):
        if not members:
            return
        found = db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AS active
            FROM jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text)
            LEFT JOIN epm.member m ON m.workspace_id=%s
            AND m.application_id=%s
            AND m.dimension_id=input.dimension_id
            AND m.member_id=input.member_id AND m.status='Active'
            JOIN epm.dimension d ON d.workspace_id=%s
            AND d.application_id=%s AND d.dimension_id=input.dimension_id
            AND d.status='Active'
            AND d.model_role IS DISTINCT FROM 'Currency' ''',
            (Jsonb([{'dimension_id': axis,'member_id': member}
                    for axis, member in members.items()]),
             scope.workspace_id,scope.application_id,
             scope.workspace_id,scope.application_id)).fetchall()
        if len(found) != len(members) or any(not row['active'] for row in found):
            raise ValueError('SOURCE_SCOPE_MEMBER_UNAVAILABLE')

    def _validate_rows(self, db, scope, batch, rows):
        axes = {row['dimension_id'] for row in db.execute('''SELECT dimension_id
            FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
            AND status='Active'
            AND model_role IS DISTINCT FROM 'Currency' ''',
            (scope.workspace_id,scope.application_id)).fetchall()}
        scope_members = batch['scope_members']
        for row in rows:
            if set(row['members']) != axes:
                raise ValueError('SOURCE_COORDINATE_DIMENSIONS_MISMATCH')
            if any(row['members'].get(axis) != member
                   for axis, member in scope_members.items()):
                raise ValueError('SOURCE_ROW_OUTSIDE_SCOPE')
        pairs = {(axis, member)
                 for row in rows for axis, member in row['members'].items()}
        found = db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AS active
            FROM jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text)
            LEFT JOIN epm.member m ON m.workspace_id=%s
            AND m.application_id=%s
            AND m.dimension_id=input.dimension_id
            AND m.member_id=input.member_id AND m.status='Active' ''',
            (Jsonb([{'dimension_id': axis,'member_id': member}
                    for axis, member in pairs]),
             scope.workspace_id,scope.application_id)).fetchall()
        if any(not row['active'] for row in found):
            raise ValueError('SOURCE_COORDINATE_MEMBER_UNAVAILABLE')

    @staticmethod
    def _validate_staged(db, scope, batch):
        PostgresSourceBatch._check_scope_members(db,scope,batch['scope_members'])
        selection = batch['period_selection']
        if selection is not None:
            if (batch['mode'] != 'replace'
                    or not isinstance(selection, dict)
                    or set(selection) != {'yearDimension',
                                          'periodDimension', 'periods'}
                    or not isinstance(selection['yearDimension'], str)
                    or not isinstance(selection['periodDimension'], str)
                    or selection['yearDimension'] ==
                       selection['periodDimension']
                    or not isinstance(selection['periods'], list)
                    or not 1 <= len(selection['periods']) <= 36
                    or any(not isinstance(pair, dict)
                           or set(pair) != {'year_id', 'period_id'}
                           or not isinstance(pair['year_id'], str)
                           or not isinstance(pair['period_id'], str)
                           for pair in selection['periods'])
                    or len({(pair['year_id'], pair['period_id'])
                            for pair in selection['periods']}) !=
                       len(selection['periods'])):
                raise ValueError('SOURCE_PERIOD_SELECTION_INVALID')
            outside = db.execute('''SELECT 1 FROM epm.source_batch_row r
                WHERE r.workspace_id=%s AND r.application_id=%s
                AND r.batch_id=%s AND NOT EXISTS (
                    SELECT 1 FROM jsonb_to_recordset(%s::jsonb)
                    AS selected(year_id text,period_id text)
                    WHERE r.members->>%s=selected.year_id
                      AND r.members->>%s=selected.period_id)
                LIMIT 1''',
                (scope.workspace_id,scope.application_id,batch['batch_id'],
                 Jsonb(selection['periods']),selection['yearDimension'],
                 selection['periodDimension'])).fetchone()
            if outside:
                raise ValueError('SOURCE_ROW_OUTSIDE_PERIOD_SELECTION')
        actual=db.execute('''SELECT count(*) AS total FROM
            epm.source_batch_row WHERE workspace_id=%s
            AND application_id=%s AND batch_id=%s''',
            (scope.workspace_id,scope.application_id,
             batch['batch_id'])).fetchone()['total']
        if actual!=batch['row_count']:
            raise ValueError('SOURCE_BATCH_ROW_COUNT_MISMATCH')
        axes = db.execute('''SELECT count(*) AS total FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            AND model_role IS DISTINCT FROM 'Currency' ''',
            (scope.workspace_id,scope.application_id)).fetchone()['total']
        invalid = db.execute('''SELECT 1 FROM epm.source_batch_row r
            LEFT JOIN LATERAL (
                SELECT count(*) AS total FROM jsonb_each_text(r.members) item
                JOIN epm.member m ON m.workspace_id=r.workspace_id
                AND m.application_id=r.application_id
                AND m.dimension_id=item.key AND m.member_id=item.value
                AND m.status='Active'
            ) valid ON true
            WHERE r.workspace_id=%s AND r.application_id=%s
            AND r.batch_id=%s AND
            (valid.total<>%s OR EXISTS (
                SELECT 1 FROM jsonb_object_keys(r.members) AS k(axis)
                WHERE NOT EXISTS (SELECT 1 FROM epm.dimension d
                    WHERE d.workspace_id=r.workspace_id
                    AND d.application_id=r.application_id
                    AND d.dimension_id=k.axis AND d.status='Active'
                    AND d.model_role IS DISTINCT FROM 'Currency')))
            LIMIT 1''',
            (scope.workspace_id,scope.application_id,batch['batch_id'],
             axes)).fetchone()
        if invalid:
            raise ValueError('SOURCE_STAGED_METADATA_INVALID')
        detail = db.execute('''SELECT count(*) AS row_count,
            COALESCE(sum(jsonb_array_length(detail_items)),0) AS item_count
            FROM epm.source_batch_row WHERE workspace_id=%s
            AND application_id=%s AND batch_id=%s
            AND value_kind='detail' ''',
            (scope.workspace_id,scope.application_id,
             batch['batch_id'])).fetchone()
        if detail['row_count']:
            if detail['item_count'] > 100000:
                raise ValueError('SOURCE_DETAIL_STAGING_INVALID')

    @staticmethod
    def _clear_count(db, scope, batch):
        if batch['mode'] != 'replace':
            return 0
        total = 0
        for table, kinds in (('numeric_cell_current', ['numeric','detail']),
                             ('text_cell_current', ['text'])):
            fragment, params = _omitted_source_targets(scope, batch, table, kinds)
            total += db.execute('SELECT count(*) AS total' + fragment,
                                params).fetchone()['total']
        return total

    @staticmethod
    def _detail_clear_count(db, scope, batch):
        if batch['mode'] != 'replace':
            return 0
        predicate, params = _scope_predicate(
            batch['scope_members'], batch['period_selection'])
        return db.execute(f'''SELECT count(*) AS total
            FROM epm.line_detail_current d JOIN epm.coordinate c
            ON c.workspace_id=d.workspace_id
            AND c.application_id=d.application_id
            AND c.coordinate_id=d.coordinate_id
            WHERE d.workspace_id=%s AND d.application_id=%s
            {predicate}
            AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
                WHERE r.workspace_id=d.workspace_id
                AND r.application_id=d.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind='detail')''',
            (scope.workspace_id,scope.application_id,*params,
             batch['batch_id'])).fetchone()['total']

    @staticmethod
    def _check_conflicts(db, scope, batch):
        staged = db.execute('''SELECT 1 FROM epm.source_batch_row r
            JOIN epm.coordinate c ON c.workspace_id=r.workspace_id
            AND c.application_id=r.application_id
            AND c.series_key=r.series_key
            LEFT JOIN epm.text_cell_current t ON
            t.workspace_id=c.workspace_id
            AND t.application_id=c.application_id
            AND t.coordinate_id=c.coordinate_id
            LEFT JOIN epm.numeric_cell_current n ON
            n.workspace_id=c.workspace_id
            AND n.application_id=c.application_id
            AND n.coordinate_id=c.coordinate_id
            LEFT JOIN epm.line_detail_current d ON
            d.workspace_id=c.workspace_id
            AND d.application_id=c.application_id
            AND d.coordinate_id=c.coordinate_id
            WHERE r.workspace_id=%s AND r.application_id=%s
            AND r.batch_id=%s AND
            (c.members<>r.members
             OR (d.coordinate_id IS NOT NULL AND
                 (r.value_kind<>'detail' OR %s::text<>'replace')
                 AND NOT %s::boolean)
             OR (%s='merge' AND
                 ((r.value_kind IN ('numeric','detail')
                   AND COALESCE(t.present,false))
                  OR (r.value_kind='text' AND COALESCE(n.present,false)))))
            LIMIT 1''',
            (scope.workspace_id,scope.application_id,
             batch['batch_id'],batch['mode'],
             batch['period_selection'] is not None,
             batch['mode'])).fetchone()
        if staged:
            raise ValueError('SOURCE_TARGET_CONFLICT')
    @staticmethod
    def _check_locks(db, scope, batch):
        staged=db.execute('''SELECT 1 FROM epm.source_batch_row r
            JOIN epm.cube_write_scope_lock l
            ON l.workspace_id=r.workspace_id
            AND l.application_id=r.application_id
            AND l.status='Locked'
            AND (l.scope_all OR r.members @> l.scope_members)
            WHERE r.workspace_id=%s AND r.application_id=%s
            AND r.batch_id=%s LIMIT 1''',
            (scope.workspace_id,scope.application_id,
             batch['batch_id'])).fetchone()
        if staged:
            raise SourceBatchPrepublicationRejection('PLANNING_SLICE_LOCKED')
        if batch['mode']=='replace':
            predicate,params=_scope_predicate(
                batch['scope_members'], batch['period_selection'])
            for table, kinds in (('numeric_cell_current',
                                  ['numeric','detail']),
                                 ('text_cell_current',['text'])):
                clearing=db.execute(f'''SELECT 1 FROM
                    epm.{table} n JOIN epm.coordinate c
                    ON c.workspace_id=n.workspace_id
                    AND c.application_id=n.application_id
                    AND c.coordinate_id=n.coordinate_id
                    JOIN epm.cube_write_scope_lock l
                    ON l.workspace_id=n.workspace_id
                    AND l.application_id=n.application_id
                    AND l.status='Locked'
                    AND (l.scope_all OR c.members @> l.scope_members)
                    WHERE n.workspace_id=%s AND n.application_id=%s
                    AND n.present {predicate}
                    AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
                        WHERE r.workspace_id=n.workspace_id
                        AND r.application_id=n.application_id
                        AND r.batch_id=%s AND r.series_key=c.series_key
                        AND r.value_kind=ANY(%s::text[]))
                    LIMIT 1''',
                    (scope.workspace_id,scope.application_id,
                     *params,batch['batch_id'],kinds)).fetchone()
                if clearing:
                    raise SourceBatchPrepublicationRejection(
                        'PLANNING_SLICE_LOCKED')

    @staticmethod
    def _ensure_coordinates(db, scope, batch_id):
        # This is fixed-core work inside the source publication transaction.
        # Bound each statement so a large import cannot turn coordinate and
        # projection maintenance into one timeout-prone SQL statement.  The
        # client still submits one source batch and cannot choose these chunks.
        last_series_key=None
        while True:
            progress=db.execute('''WITH selected AS MATERIALIZED (
                    SELECT r.workspace_id,r.application_id,r.series_key,r.members
                    FROM epm.source_batch_row r
                    WHERE r.workspace_id=%s AND r.application_id=%s
                      AND r.batch_id=%s
                      AND (%s::text IS NULL OR r.series_key>%s::text)
                    ORDER BY r.series_key COLLATE "C" LIMIT 1000
                ), inserted AS (
                    INSERT INTO epm.coordinate
                        (workspace_id,application_id,series_key,members)
                    SELECT workspace_id,application_id,series_key,members
                    FROM selected ON CONFLICT DO NOTHING RETURNING 1
                )
                SELECT max(series_key COLLATE "C") last_series_key,
                       (SELECT count(*) FROM inserted) inserted_count
                FROM selected''',
                (scope.workspace_id,scope.application_id,batch_id,
                 last_series_key,last_series_key)).fetchone()
            last_series_key=progress['last_series_key']
            if last_series_key is None:
                break

        last_series_key=None
        while True:
            progress=db.execute('''WITH selected AS MATERIALIZED (
                    SELECT r.workspace_id,r.application_id,r.series_key,r.members
                    FROM epm.source_batch_row r
                    WHERE r.workspace_id=%s AND r.application_id=%s
                      AND r.batch_id=%s
                      AND (%s::text IS NULL OR r.series_key>%s::text)
                    ORDER BY r.series_key COLLATE "C" LIMIT 200
                ), inserted AS (
                    INSERT INTO epm.coordinate_member_projection
                        (workspace_id,application_id,coordinate_id,
                         dimension_id,member_id,projection_generation)
                    SELECT c.workspace_id,c.application_id,c.coordinate_id,
                        item.key,item.value,
                        (SELECT epm.active_projection_generation())
                    FROM selected r
                    JOIN epm.coordinate c ON c.workspace_id=r.workspace_id
                     AND c.application_id=r.application_id
                     AND c.series_key=r.series_key
                    CROSS JOIN LATERAL jsonb_each_text(r.members) item
                    ON CONFLICT DO NOTHING RETURNING 1
                )
                SELECT max(series_key COLLATE "C") last_series_key,
                       (SELECT count(*) FROM inserted) inserted_count
                FROM selected''',
                (scope.workspace_id,scope.application_id,batch_id,
                 last_series_key,last_series_key)).fetchone()
            last_series_key=progress['last_series_key']
            if last_series_key is None:
                break

    @staticmethod
    def _write_events(db, scope, batch, revision, *, empty_application=False):
        predicate,params = _scope_predicate(
            batch['scope_members'], batch['period_selection'])
        db.execute('''CREATE TEMP TABLE epm_source_numeric_actions(
            ordinal integer PRIMARY KEY,coordinate_id bigint NOT NULL,
            desired numeric,before_amount numeric NOT NULL,
            kind text NOT NULL) ON COMMIT DROP''')
        if batch['mode']=='merge':
            if empty_application:
                db.execute('''INSERT INTO epm_source_numeric_actions
                    (ordinal,coordinate_id,desired,before_amount,kind)
                    WITH source_rows AS MATERIALIZED (
                        SELECT r.workspace_id,r.application_id,r.series_key,
                               r.amount
                        FROM epm.source_batch_row r
                        WHERE r.workspace_id=%s AND r.application_id=%s
                          AND r.batch_id=%s
                          AND r.value_kind IN ('numeric','detail')
                    )
                    SELECT row_number() OVER (
                               ORDER BY r.series_key COLLATE "C")::integer,
                           (SELECT c.coordinate_id FROM epm.coordinate c
                            WHERE c.workspace_id=r.workspace_id
                              AND c.application_id=r.application_id
                              AND c.series_key=r.series_key),
                           r.amount,0::numeric,'set'
                    FROM source_rows r''',
                    (scope.workspace_id,scope.application_id,
                     batch['batch_id']))
            else:
                db.execute('''INSERT INTO epm_source_numeric_actions
                (ordinal,coordinate_id,desired,before_amount,kind)
                SELECT row_number() OVER (
                           ORDER BY r.series_key COLLATE "C")::integer,
                       c.coordinate_id,r.amount,
                       COALESCE(n.amount,0::numeric),'set'
                FROM epm.source_batch_row r
                JOIN epm.coordinate c ON c.workspace_id=r.workspace_id
                 AND c.application_id=r.application_id
                 AND c.series_key=r.series_key
                LEFT JOIN epm.numeric_cell_current n
                  ON n.workspace_id=c.workspace_id
                 AND n.application_id=c.application_id
                 AND n.coordinate_id=c.coordinate_id
                WHERE r.workspace_id=%s AND r.application_id=%s
                  AND r.batch_id=%s
                  AND r.value_kind IN ('numeric','detail')''',
                    (scope.workspace_id,scope.application_id,
                     batch['batch_id']))
        else:
            db.execute(f'''INSERT INTO epm_source_numeric_actions
            (ordinal,coordinate_id,desired,before_amount,kind)
            SELECT row_number() OVER (ORDER BY series_key)::integer,
                   coordinate_id,desired,before_amount,kind
            FROM (
            SELECT c.coordinate_id,c.series_key,r.amount AS desired,
                COALESCE(n.amount,0::numeric) AS before_amount,
                'set'::text AS kind
            FROM epm.source_batch_row r JOIN epm.coordinate c
            ON c.workspace_id=r.workspace_id
            AND c.application_id=r.application_id
            AND c.series_key=r.series_key
            LEFT JOIN epm.numeric_cell_current n
            ON n.workspace_id=c.workspace_id
            AND n.application_id=c.application_id
            AND n.coordinate_id=c.coordinate_id
            WHERE r.workspace_id=%s AND r.application_id=%s
            AND r.batch_id=%s AND r.value_kind IN ('numeric','detail')
            UNION ALL
            SELECT c.coordinate_id,c.series_key,NULL::numeric,
                n.amount,'clear'::text
            FROM epm.numeric_cell_current n JOIN epm.coordinate c
            ON c.workspace_id=n.workspace_id
            AND c.application_id=n.application_id
            AND c.coordinate_id=n.coordinate_id
            WHERE n.workspace_id=%s AND n.application_id=%s
            AND n.present AND %s::text='replace'
            {predicate}
            AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
                WHERE r.workspace_id=n.workspace_id
                AND r.application_id=n.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind IN ('numeric','detail'))
            ) actions''', (
                scope.workspace_id,scope.application_id,batch['batch_id'],
                scope.workspace_id,scope.application_id,batch['mode'],
                *params,batch['batch_id']))
        count=db.execute('''SELECT count(*) n
            FROM epm_source_numeric_actions''').fetchone()['n']
        inserted=0
        for start in range(1,count+1,500):
            inserted += db.execute('''INSERT INTO epm.numeric_fact_event
                (workspace_id,application_id,coordinate_id,operation_id,
                 line_ordinal,kind,delta,present,resulting_amount,
                 change_id,committed_revision)
                SELECT %s,%s,coordinate_id,%s,ordinal,kind,
                    COALESCE(desired,0::numeric)-before_amount,
                    kind='set',desired,%s::text || ':' || ordinal::text,%s
                FROM epm_source_numeric_actions
                WHERE ordinal BETWEEN %s AND %s ORDER BY ordinal''',
                (scope.workspace_id,scope.application_id,batch['batch_id'],
                 revision,revision,start,min(start+499,count))).rowcount
        return inserted

    @staticmethod
    def _project_numeric_events(db,scope,batch_id,event_count):
        for start in range(1,event_count+1,500):
            db.execute('''INSERT INTO epm.numeric_cell_projection
                (workspace_id,application_id,coordinate_id,present,
                 amount,change_id,last_revision,projection_generation)
                SELECT workspace_id,application_id,coordinate_id,present,
                       resulting_amount,change_id,committed_revision,
                       (SELECT epm.active_projection_generation())
                FROM epm.numeric_fact_event
                WHERE workspace_id=%s AND application_id=%s
                  AND operation_id=%s AND line_ordinal BETWEEN %s AND %s
                ORDER BY line_ordinal
                ON CONFLICT (workspace_id,application_id,
                             projection_generation,coordinate_id)
                DO UPDATE SET present=EXCLUDED.present,
                    amount=EXCLUDED.amount,
                    change_id=EXCLUDED.change_id,
                    last_revision=EXCLUDED.last_revision''',
                (scope.workspace_id,scope.application_id,batch_id,
                 start,min(start+499,event_count)))

    @staticmethod
    def _write_detail_events(db, scope, batch, revision, *,
                             empty_application=False):
        if batch['mode']=='merge' and empty_application:
            inserted = db.execute('''WITH source_rows AS MATERIALIZED (
                SELECT r.workspace_id,r.application_id,r.series_key,
                       r.batch_id,r.detail_items,r.amount
                FROM epm.source_batch_row r
                WHERE r.workspace_id=%s AND r.application_id=%s
                  AND r.batch_id=%s AND r.value_kind='detail'
            ), mapped AS MATERIALIZED (
                SELECT r.*,(SELECT c.coordinate_id FROM epm.coordinate c
                    WHERE c.workspace_id=r.workspace_id
                      AND c.application_id=r.application_id
                      AND c.series_key=r.series_key) coordinate_id
                FROM source_rows r
            ) INSERT INTO epm.line_detail_event
                (workspace_id,application_id,coordinate_id,operation_id,
                 prior_items,prior_total,items,total,change_id,
                 committed_revision)
                SELECT r.workspace_id,r.application_id,r.coordinate_id,
                    r.batch_id,NULL::jsonb,NULL::numeric,r.detail_items,
                    r.amount,e.change_id,%s
                FROM mapped r JOIN epm.numeric_fact_event e
                  ON e.workspace_id=r.workspace_id
                  AND e.application_id=r.application_id
                  AND e.coordinate_id=r.coordinate_id
                  AND e.operation_id=r.batch_id AND e.kind='set' ''',
                (scope.workspace_id,scope.application_id,
                 batch['batch_id'],revision)).rowcount
        else:
            inserted = db.execute('''INSERT INTO epm.line_detail_event
            (workspace_id,application_id,coordinate_id,operation_id,
             prior_items,prior_total,items,total,change_id,
             committed_revision)
            SELECT r.workspace_id,r.application_id,c.coordinate_id,
                r.batch_id,d.items,d.total,r.detail_items,r.amount,
                e.change_id,%s
            FROM epm.source_batch_row r JOIN epm.coordinate c
              ON c.workspace_id=r.workspace_id
              AND c.application_id=r.application_id
              AND c.series_key=r.series_key
            JOIN epm.numeric_fact_event e
              ON e.workspace_id=r.workspace_id
              AND e.application_id=r.application_id
              AND e.coordinate_id=c.coordinate_id
              AND e.operation_id=r.batch_id AND e.kind='set'
            LEFT JOIN epm.line_detail_current d
              ON d.workspace_id=r.workspace_id
              AND d.application_id=r.application_id
              AND d.coordinate_id=c.coordinate_id
            WHERE r.workspace_id=%s AND r.application_id=%s
              AND r.batch_id=%s AND r.value_kind='detail' ''',
                (revision,scope.workspace_id,scope.application_id,
                 batch['batch_id'])).rowcount
        cleared = 0
        if batch['mode'] == 'replace':
            predicate, params = _scope_predicate(
                batch['scope_members'], batch['period_selection'])
            cleared = db.execute(f'''INSERT INTO epm.line_detail_event
                (workspace_id,application_id,coordinate_id,operation_id,
                 prior_items,prior_total,items,total,change_id,
                 committed_revision,present)
                SELECT d.workspace_id,d.application_id,d.coordinate_id,
                    %s,d.items,d.total,'[]'::jsonb,0,e.change_id,
                    %s,false
                FROM epm.line_detail_current d JOIN epm.coordinate c
                ON c.workspace_id=d.workspace_id
                AND c.application_id=d.application_id
                AND c.coordinate_id=d.coordinate_id
                JOIN epm.numeric_fact_event e
                ON e.workspace_id=d.workspace_id
                AND e.application_id=d.application_id
                AND e.coordinate_id=d.coordinate_id
                AND e.operation_id=%s
                WHERE d.workspace_id=%s AND d.application_id=%s
                {predicate}
                AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
                    WHERE r.workspace_id=d.workspace_id
                    AND r.application_id=d.application_id
                    AND r.batch_id=%s AND r.series_key=c.series_key
                    AND r.value_kind='detail')''',
                (batch['batch_id'],revision,batch['batch_id'],
                 scope.workspace_id,scope.application_id,*params,
                 batch['batch_id'])).rowcount
        db.execute('''INSERT INTO epm.line_detail_projection
            (workspace_id,application_id,coordinate_id,items,total,
             change_id,last_revision,projection_generation)
            SELECT workspace_id,application_id,coordinate_id,items,total,
                change_id,committed_revision,(SELECT epm.active_projection_generation())
            FROM epm.line_detail_event WHERE workspace_id=%s
              AND application_id=%s AND operation_id=%s AND present
            ON CONFLICT (workspace_id,application_id,projection_generation,coordinate_id)
            DO UPDATE SET items=EXCLUDED.items,total=EXCLUDED.total,
                change_id=EXCLUDED.change_id,
                last_revision=EXCLUDED.last_revision''',
            (scope.workspace_id,scope.application_id,batch['batch_id']))
        if cleared:
            db.execute('''DELETE FROM epm.line_detail_projection d
                USING epm.line_detail_event e
                WHERE d.projection_generation=(SELECT epm.active_projection_generation()) AND e.workspace_id=d.workspace_id
                AND e.application_id=d.application_id
                AND e.coordinate_id=d.coordinate_id
                AND e.operation_id=%s AND NOT e.present
                AND d.workspace_id=%s AND d.application_id=%s''',
                (batch['batch_id'],scope.workspace_id,
                 scope.application_id))
        return inserted + cleared

    @staticmethod
    def _write_text_events(db, scope, batch, revision, *,
                           empty_application=False):
        if batch['mode']=='merge' and empty_application:
            return db.execute('''WITH source_rows AS MATERIALIZED (
                SELECT r.workspace_id,r.application_id,r.series_key,
                       r.text_value,r.batch_id
                FROM epm.source_batch_row r
                WHERE r.workspace_id=%s AND r.application_id=%s
                  AND r.batch_id=%s AND r.value_kind='text'
            ), ordered AS (
                SELECT (SELECT c.coordinate_id FROM epm.coordinate c
                        WHERE c.workspace_id=r.workspace_id
                          AND c.application_id=r.application_id
                          AND c.series_key=r.series_key) coordinate_id,
                       r.text_value,r.batch_id,
                       row_number() OVER (
                           ORDER BY r.series_key COLLATE "C")::integer ordinal
                FROM source_rows r
            ) INSERT INTO epm.text_fact_event
                (workspace_id,application_id,coordinate_id,operation_id,
                 line_ordinal,kind,prior_present,prior_value,present,
                 resulting_value,change_id,committed_revision)
                SELECT %s,%s,coordinate_id,batch_id,ordinal,'set',false,NULL,
                       true,text_value,%s::text || ':' || ordinal::text,%s
                FROM ordered''',
                (scope.workspace_id,scope.application_id,batch['batch_id'],
                 scope.workspace_id,scope.application_id,revision,
                 revision)).rowcount
        predicate,params = _scope_predicate(
            batch['scope_members'], batch['period_selection'])
        query = f'''WITH actions AS (
            SELECT c.coordinate_id,c.series_key,r.text_value AS desired,
                COALESCE(t.present,false) AS before_present,
                t.text_value AS before_value,'set'::text AS kind
            FROM epm.source_batch_row r JOIN epm.coordinate c
            ON c.workspace_id=r.workspace_id
            AND c.application_id=r.application_id
            AND c.series_key=r.series_key
            LEFT JOIN epm.text_cell_current t
            ON t.workspace_id=c.workspace_id
            AND t.application_id=c.application_id
            AND t.coordinate_id=c.coordinate_id
            WHERE r.workspace_id=%s AND r.application_id=%s
            AND r.batch_id=%s AND r.value_kind='text'
            UNION ALL
            SELECT c.coordinate_id,c.series_key,NULL::text,true,
                t.text_value,'clear'::text
            FROM epm.text_cell_current t JOIN epm.coordinate c
            ON c.workspace_id=t.workspace_id
            AND c.application_id=t.application_id
            AND c.coordinate_id=t.coordinate_id
            WHERE t.workspace_id=%s AND t.application_id=%s
            AND t.present AND %s::text='replace'
            {predicate}
            AND NOT EXISTS (SELECT 1 FROM epm.source_batch_row r
                WHERE r.workspace_id=t.workspace_id
                AND r.application_id=t.application_id
                AND r.batch_id=%s AND r.series_key=c.series_key
                AND r.value_kind='text')
        ), ordered AS (
            SELECT coordinate_id,desired,before_present,before_value,kind,
                row_number() OVER (ORDER BY series_key)::integer AS ordinal
            FROM actions
        ) INSERT INTO epm.text_fact_event
            (workspace_id,application_id,coordinate_id,operation_id,
             line_ordinal,kind,prior_present,prior_value,present,
             resulting_value,change_id,committed_revision)
            SELECT %s,%s,coordinate_id,%s,ordinal,kind,
                before_present,before_value,kind='set',desired,
                %s::text || ':' || ordinal::text,%s
            FROM ordered'''
        return db.execute(query, (
            scope.workspace_id,scope.application_id,batch['batch_id'],
            scope.workspace_id,scope.application_id,batch['mode'],
            *params,batch['batch_id'],scope.workspace_id,
            scope.application_id,batch['batch_id'],revision,
            revision)).rowcount

    def _verify_token(self, token, scope, batch, diagnostic=None, *,
                      security_revision):
        if not isinstance(token, str) or len(token) > 4096:
            raise ValueError('SOURCE_PREVIEW_INVALID')
        try:
            packed = base64.b64decode(token,altchars=b'-_',validate=True)
            raw,signature = packed[:-32],packed[-32:]
            if not hmac.compare_digest(
                    hmac.new(self.preview_secret,raw,sha256).digest(),
                    signature):
                raise ValueError('signature')
            payload = json.loads(raw)
        except (ValueError,TypeError,binascii.Error) as error:
            raise ValueError('SOURCE_PREVIEW_INVALID') from error
        expected_fields = {'scope','identity','batchId',
                           'contentDigest','revisions','securityRevision',
                           'expiresAt'}
        if batch['period_selection'] is not None:
            expected_fields.add('scopeDigest')
        if batch['manifest_digest'] is not None:
            expected_fields.update(
                ('diagnosticArtifactId', 'diagnosticsDigest'))
        if (not isinstance(payload,dict)
                or set(payload) != expected_fields
                or payload['scope'] != [scope.workspace_id,scope.application_id]
                or payload['identity'] != [self.identity.issuer,
                                           self.identity.subject_id]
                or payload['batchId'] != batch['batch_id']
                or payload['contentDigest'] != batch['content_digest']
                or payload['revisions'] != [
                    batch['expected_metadata_revision'],
                    batch['expected_data_revision']]
                or type(security_revision) is not int
                or security_revision < 0
                or payload['securityRevision'] != security_revision
                or (batch['manifest_digest'] is not None and
                    (diagnostic is None
                     or payload['diagnosticArtifactId'] !=
                        diagnostic['artifactId']
                     or payload['diagnosticsDigest'] !=
                        diagnostic['artifact']['diagnosticsDigest']))
                or (batch['period_selection'] is not None and
                    payload['scopeDigest'] != self._scope_digest(batch))
                or type(payload['expiresAt']) is not int
                or payload['expiresAt'] < time.time()):
            raise ValueError('SOURCE_PREVIEW_STALE_OR_MISMATCHED')

    @staticmethod
    def _scope_digest(batch):
        return _canonical_digest({
            'mode': batch['mode'],
            'scopeMembers': batch['scope_members'],
            'periodSelection': batch['period_selection']})
