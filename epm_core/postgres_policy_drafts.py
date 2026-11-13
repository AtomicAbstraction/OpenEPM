"""Current, effective-dated consolidation policy definitions.

One stable policy id identifies one current definition. Replacing a definition
rotates its opaque state token; prior product definitions are not retained.
"""
from __future__ import annotations

from datetime import date
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .current_object_contract import new_state_token, require_state_token
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


CREATE_FUNCTION = 'consolidation.policy.draft.save'
READ_FUNCTION = 'consolidation.policy.draft.effective.read'
ELECTIONS_FUNCTION = 'consolidation.policy.draft.elections.validate'
_ID = re.compile(r'[A-Za-z0-9._-]{1,100}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def _date(value: object) -> date:
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
        raise ValueError('POLICY_ISO_DATE_REQUIRED')
    try:
        result = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError('POLICY_ISO_DATE_REQUIRED') from error
    if result.isoformat() != value:
        raise ValueError('POLICY_ISO_DATE_REQUIRED')
    return result


def _program(program: object, function: str) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != function
            or not isinstance(program['arguments'], dict)):
        raise ValueError('V2_POLICY_FUNCTION_INVALID')
    args = program['arguments']
    if function == CREATE_FUNCTION:
        expected = {'policyId', 'family', 'effectiveFrom',
                    'effectiveBefore', 'requiredElections', 'sourceRefs',
                    'expectedStateToken', 'expectedPolicyRevision'}
    elif function == READ_FUNCTION:
        expected = {'policyId', 'effectiveOn'}
    elif function == ELECTIONS_FUNCTION:
        expected = {'policyId', 'effectiveOn', 'selections',
                    'expectedPolicyRevision'}
    else:
        raise ValueError('V2_POLICY_FUNCTION_INVALID')
    if set(args) != expected or not isinstance(args['policyId'], str) or not _ID.fullmatch(args['policyId']):
        raise ValueError('V2_POLICY_ARGUMENTS_INVALID')
    if function == READ_FUNCTION:
        return {'policyId': args['policyId'], 'effectiveOn': _date(args['effectiveOn'])}
    if function == ELECTIONS_FUNCTION:
        selections = args['selections']
        if (not isinstance(selections, dict) or len(selections) > 30
                or any(not isinstance(name, str) or not _ID.fullmatch(name)
                       or not isinstance(choice, str) or not _ID.fullmatch(choice)
                       for name, choice in selections.items())
                or type(args['expectedPolicyRevision']) is not int
                or args['expectedPolicyRevision'] < 0):
            raise ValueError('POLICY_ELECTION_SELECTIONS_INVALID')
        return {'policyId': args['policyId'],
                'effectiveOn': _date(args['effectiveOn']),
                'selections': dict(sorted(selections.items())),
                'expectedPolicyRevision': args['expectedPolicyRevision']}
    if (args['family'] not in ('IFRS', 'US_GAAP', 'CUSTOM')
            or type(args['expectedPolicyRevision']) is not int
            or args['expectedPolicyRevision'] < 0):
        raise ValueError('V2_POLICY_ARGUMENTS_INVALID')
    expected_state_token = args['expectedStateToken']
    if expected_state_token is not None:
        require_state_token(expected_state_token,
                            error='V2_POLICY_ARGUMENTS_INVALID')
    start, end = _date(args['effectiveFrom']), _date(args['effectiveBefore'])
    if start >= end:
        raise ValueError('POLICY_EFFECTIVE_RANGE_INVALID')
    elections = args['requiredElections']
    if not isinstance(elections, list) or len(elections) > 30:
        raise ValueError('POLICY_ELECTIONS_INVALID')
    names = set()
    for item in elections:
        if (not isinstance(item, dict) or set(item) != {'name', 'choices'}
                or not isinstance(item['name'], str)
                or not _ID.fullmatch(item['name'])
                or item['name'] in names
                or not isinstance(item['choices'], list)
                or not 2 <= len(item['choices']) <= 20
                or any(not isinstance(choice, str) or not _ID.fullmatch(choice)
                       for choice in item['choices'])
                or len(item['choices']) != len(set(item['choices']))):
            raise ValueError('POLICY_ELECTIONS_INVALID')
        names.add(item['name'])
    refs = args['sourceRefs']
    if (not isinstance(refs, list) or len(refs) > 30
            or any(not isinstance(ref, str) or not 1 <= len(ref) <= 500
                   for ref in refs)):
        raise ValueError('POLICY_SOURCE_REFS_INVALID')
    return {**args, 'effectiveFrom': start, 'effectiveBefore': end}


def validate_elections_in_transaction(db, scope: ApplicationScope,
                                      query: dict, state: dict) -> dict:
    """Resolve one draft and its complete choices under the caller's lock."""
    keys = (scope.workspace_id, scope.application_id)
    if state['policy_revision'] != query['expectedPolicyRevision']:
        raise ValueError('STALE_POLICY_REVISION')
    draft = db.execute('''SELECT state_token,definition_digest,family,effective_from,
        effective_before,required_elections,source_refs FROM epm.policy_pack_draft
        WHERE workspace_id=%s AND application_id=%s
        AND policy_id=%s AND effective_from<=%s
        AND effective_before>%s''',
        (*keys, query['policyId'], query['effectiveOn'],
         query['effectiveOn'])).fetchone()
    if draft is None:
        raise ValueError('POLICY_DRAFT_UNAVAILABLE')
    choices = {item['name']: set(item['choices'])
               for item in draft['required_elections']}
    selected = query['selections']
    if set(selected) != set(choices):
        raise ValueError('POLICY_ELECTION_NAMES_MISMATCH')
    if any(choice not in choices[name]
           for name, choice in selected.items()):
        raise ValueError('POLICY_ELECTION_CHOICE_INVALID')
    draft_digest = draft['definition_digest']
    selection_digest = _canonical_digest({
        'draftDigest': draft_digest,
        'effectiveOn': query['effectiveOn'].isoformat(),
        'selections': selected})
    return {'policyId': query['policyId'],
        'stateToken': draft['state_token'], 'family': draft['family'],
        'effectiveOn': query['effectiveOn'].isoformat(),
        'effectiveFrom': draft['effective_from'].isoformat(),
        'effectiveBefore': draft['effective_before'].isoformat(),
        'selections': selected,
        'draftDigest': draft_digest,
        'selectionDigest': selection_digest,
        'policyRevision': state['policy_revision'],
        'commitRevision': state['commit_revision'],
        'status': 'DraftUnreviewed',
        'accountingExecutionSupported': False}


class PostgresPolicyDrafts:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def read_effective(self, scope: ApplicationScope, program: object) -> dict:
        query = _program(program, READ_FUNCTION)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=READ_FUNCTION)
                row = db.execute('''SELECT state_token,definition_digest,family,effective_from,
                    effective_before,required_elections,source_refs FROM epm.policy_pack_draft
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s AND effective_from<=%s
                    AND effective_before>%s''',
                    (scope.workspace_id, scope.application_id,
                     query['policyId'], query['effectiveOn'],
                     query['effectiveOn'])).fetchone()
                return {'policyId': query['policyId'],
                        'effectiveOn': query['effectiveOn'].isoformat(),
                        'defined': row is not None, 'status': 'Draft' if row else None,
                        'stateToken': row['state_token'] if row else None,
                        'definitionDigest': row['definition_digest'] if row else None,
                        'family': row['family'] if row else None,
                        'effectiveFrom': row['effective_from'].isoformat() if row else None,
                        'effectiveBefore': row['effective_before'].isoformat() if row else None,
                        'requiredElections': row['required_elections'] if row else None,
                        'sourceRefs': row['source_refs'] if row else None,
                        'policyRevision': state['policy_revision'],
                        'commitRevision': state['commit_revision']}

    def validate_elections(self, scope: ApplicationScope,
                           program: object) -> dict:
        query = _program(program, ELECTIONS_FUNCTION)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=ELECTIONS_FUNCTION)
                return validate_elections_in_transaction(
                    db, scope, query, state)

    def create(self, scope: ApplicationScope, program: object, *,
               idempotency_key: str) -> dict:
        query = _program(program, CREATE_FUNCTION)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('POLICY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=CREATE_FUNCTION)
                previous = db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key)).fetchone()
                if previous:
                    if (previous['command_digest'] != digest
                            or previous['actor_id'] != self.identity.subject_id):
                        raise ValueError('POLICY_IDEMPOTENCY_CONFLICT')
                    return previous['result']
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['policy_revision'] != query['expectedPolicyRevision']:
                    raise ValueError('STALE_POLICY_REVISION')
                current = db.execute('''SELECT state_token FROM epm.policy_pack_draft
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     query['policyId'])).fetchone()
                observed = current['state_token'] if current else None
                if observed != query['expectedStateToken']:
                    raise ValueError('STALE_POLICY_STATE_TOKEN')
                revision = state['commit_revision'] + 1
                policy_revision = state['policy_revision'] + 1
                state_token = new_state_token()
                definition_digest = _canonical_digest({
                    'policyId': query['policyId'], 'family': query['family'],
                    'effectiveFrom': query['effectiveFrom'].isoformat(),
                    'effectiveBefore': query['effectiveBefore'].isoformat(),
                    'requiredElections': query['requiredElections'],
                    'sourceRefs': query['sourceRefs']})
                result = {'operationId': idempotency_key,
                          'policyId': query['policyId'],
                          'stateToken': state_token,
                          'definitionDigest': definition_digest,
                          'status': 'Draft',
                          'effectiveFrom': query['effectiveFrom'].isoformat(),
                          'effectiveBefore': query['effectiveBefore'].isoformat(),
                          'policyRevision': policy_revision}
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision, revision, scope.workspace_id,
                     scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                    command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id, idempotency_key,
                     digest, self.identity.subject_id, revision, Jsonb(result)))
                db.execute('''INSERT INTO epm.policy_pack_draft
                    (workspace_id,application_id,policy_id,state_token,
                    definition_digest,family,
                    effective_from,effective_before,required_elections,
                    source_refs,created_operation_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,policy_id)
                    DO UPDATE SET state_token=EXCLUDED.state_token,
                    definition_digest=EXCLUDED.definition_digest,
                    family=EXCLUDED.family,
                    effective_from=EXCLUDED.effective_from,
                    effective_before=EXCLUDED.effective_before,
                    required_elections=EXCLUDED.required_elections,
                    source_refs=EXCLUDED.source_refs,
                    created_operation_id=EXCLUDED.created_operation_id,
                    created_at=transaction_timestamp()''',
                    (scope.workspace_id, scope.application_id, query['policyId'],
                     state_token, definition_digest, query['family'], query['effectiveFrom'],
                     query['effectiveBefore'], Jsonb(query['requiredElections']),
                     Jsonb(query['sourceRefs']), idempotency_key))
                return result
