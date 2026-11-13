"""Current, parent-scoped basic IC balance-offset state.

The raw facts are never rewritten. One current state per parent/source pair
holds the separately labelled, unreviewed elimination effect.
"""
from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .current_object_contract import new_state_token, require_state_token
from .dimensional_security_policy import AccessKind
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_ic_elimination_preview import (
    PostgresIntercompanyEliminationPreview,
    FUNCTION as PREVIEW_FUNCTION)
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import enforce_active_planning_policy


POST_FUNCTION = 'consolidation.ic.elimination.publish'
READ_FUNCTION = 'consolidation.ic.elimination.read'
WITHDRAW_FUNCTION = 'consolidation.ic.elimination.withdraw'
_ID = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_AMOUNT = re.compile(r'-?(?:0|[1-9][0-9]*)\.[0-9]{8}\Z')
_CHANGE = re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_PAIR = re.compile(r'[0-9a-f]{64}\Z')
_STATE_TOKEN = re.compile(r'[0-9a-f]{64}\Z')


def _pair_key(parent: str, left: Coordinate,
              right: Coordinate) -> str:
    keys = sorted((left.series_key, right.series_key))
    return sha256((parent + '\0' + keys[0] + '\0' + keys[1]).encode()).hexdigest()


def _publication_candidate(db, scope: ApplicationScope, args: dict, *,
                           left: Coordinate, right: Coordinate, pair_key: str,
                           identity: VerifiedIdentity,
                           workflow_role: str, final: bool) -> dict:
    """Resolve exact sources, policy and pair pointer around a short fence.

    The initial call proves the caller's complete preview revision vector is
    current without locking the application row.  The final call permits only
    unrelated data/commit progress: metadata and policy remain exact, both raw
    source change IDs must still match, and the pair-specific pointer must be
    identical to the initial snapshot.
    """
    state = db.execute('''SELECT s.metadata_revision,s.data_revision,
        s.policy_revision,s.commit_revision,s.processing_mode,
        a.status AS application_status
        FROM epm.application_state s JOIN epm.application a
        USING (workspace_id,application_id)
        WHERE s.workspace_id=%s AND s.application_id=%s'''+
        (' FOR UPDATE OF s' if final else ''),
        (scope.workspace_id, scope.application_id)).fetchone()
    if (state is None or state['application_status'] != 'Active'
            or state['processing_mode'] != 'Active'):
        raise ValueError('APPLICATION_NOT_WRITABLE')
    revision_pairs = (
        ('expectedMetadataRevision','metadata_revision'),
        ('expectedPolicyRevision','policy_revision'),
    ) if final else (
        ('expectedMetadataRevision','metadata_revision'),
        ('expectedDataRevision','data_revision'),
        ('expectedPolicyRevision','policy_revision'),
        ('expectedCommitRevision','commit_revision'),
    )
    if any(args[expected] != state[observed]
           for expected, observed in revision_pairs):
        raise ValueError('IC_ELIMINATION_PREVIEW_STALE')
    authorize_coordinates(db, identity, scope, (left, right),
                          kind=AccessKind.READ)
    authorize_coordinates(db, identity, scope, (left, right),
                          kind=AccessKind.WRITE)
    source_rows = []
    for coordinate, expected_change in (
            (left,args['expectedLeftChangeId']),
            (right,args['expectedRightChangeId'])):
        row = db.execute('''SELECT c.coordinate_id,c.members,n.change_id
            FROM epm.coordinate c JOIN epm.numeric_cell_current n ON
              n.workspace_id=c.workspace_id
              AND n.application_id=c.application_id
              AND n.coordinate_id=c.coordinate_id AND n.present
            WHERE c.workspace_id=%s AND c.application_id=%s
              AND c.series_key=%s''',
            (scope.workspace_id, scope.application_id,
             coordinate.series_key)).fetchone()
        if (row is None or row['members'] != dict(coordinate.members)
                or row['change_id'] != expected_change):
            raise ValueError('IC_ELIMINATION_SOURCE_STALE')
        source_rows.append(row)
    policy_evidence = enforce_active_planning_policy(
        db, scope, writes=tuple((point, 'Add') for point in (left, right)),
        workflow_role=workflow_role, ordered_actions=True)
    pointer = db.execute('''SELECT state_token,status
        FROM epm.ic_elimination_state
        WHERE workspace_id=%s AND application_id=%s
          AND parent_entity_member_id=%s AND pair_key=%s'''+
        (' FOR UPDATE' if final else ''),
        (scope.workspace_id, scope.application_id,
         args['parentEntityId'], pair_key)).fetchone()
    return {'state': state, 'sourceRows': source_rows,
            'planningPolicy': policy_evidence,
            'pointer': (None if pointer is None else
                        (pointer['state_token'],pointer['status']))}


def _withdrawal_candidate(db, scope: ApplicationScope, args: dict, *,
                          identity: VerifiedIdentity,
                          workflow_role: str, lock_pointer: bool) -> dict:
    """Resolve the exact current IC pointer and its governed targets.

    The first call is deliberately read-only and runs before the application
    publication fence. The second call locks the pointer and repeats every
    mutable check inside that short fence. The opaque current-state token and
    current lines make the returned identity safe to compare across the two
    transactions.
    """
    current = db.execute('''SELECT state_token,status
        FROM epm.ic_elimination_state
        WHERE workspace_id=%s AND application_id=%s
          AND parent_entity_member_id=%s AND pair_key=%s'''+
        (' FOR UPDATE' if lock_pointer else ''),
        (scope.workspace_id, scope.application_id,
         args['parentEntityId'],args['pairKey'])).fetchone()
    if (current is None
            or current['status']!='PublishedUnreviewed'
            or current['state_token'] != args['resultStateToken']):
        raise ValueError('IC_ELIMINATION_STATE_NOT_CURRENT')
    targets = db.execute('''SELECT c.members
        FROM epm.ic_elimination_current_line l JOIN epm.coordinate c
          ON c.workspace_id=l.workspace_id
          AND c.application_id=l.application_id
          AND c.coordinate_id=l.coordinate_id
        WHERE l.workspace_id=%s AND l.application_id=%s
        AND l.parent_entity_member_id=%s AND l.pair_key=%s
        ORDER BY l.line_ordinal''',
        (scope.workspace_id, scope.application_id,
         args['parentEntityId'],args['pairKey'])).fetchall()
    if len(targets) != 2:
        raise ValueError('IC_ELIMINATION_CURRENT_LINES_INVALID')
    target_members = tuple(row['members'] for row in targets)
    authorize_coordinates(
        db, identity, scope,
        tuple(Coordinate.from_mapping(members)
              for members in target_members),
        kind=AccessKind.WRITE)
    policy_evidence = enforce_active_planning_policy(
        db, scope,
        writes=tuple((Coordinate.from_mapping(members), 'Clear')
                     for members in target_members),
        workflow_role=workflow_role, ordered_actions=True)
    return {
        'parentEntityId': args['parentEntityId'],
        'pairKey': args['pairKey'],
        'targetMembers': target_members,
        'planningPolicy': policy_evidence,
    }


class PostgresIntercompanyElimination:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def _compile_post(program: object) -> tuple[dict, dict]:
        preview_keys = {'leftMembers', 'rightMembers', 'parentEntityId',
                        'leftRelationshipId', 'rightRelationshipId',
                        'scenarioId', 'yearId', 'periodId', 'decisions'}
        expected_keys = {'expectedMetadataRevision',
                         'expectedDataRevision', 'expectedPolicyRevision',
                         'expectedCommitRevision', 'expectedLeftChangeId',
                         'expectedRightChangeId',
                         'expectedMatchedMagnitude',
                         'expectedSignedResidual'}
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != POST_FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) != preview_keys | expected_keys):
            raise ValueError('IC_ELIMINATION_PUBLISH_PROGRAM_INVALID')
        args = program['arguments']
        for key in ('expectedMetadataRevision','expectedDataRevision',
                    'expectedPolicyRevision','expectedCommitRevision'):
            if type(args[key]) is not int or args[key] < 0:
                raise ValueError('IC_ELIMINATION_EXPECTED_REVISION_INVALID')
        for key in ('expectedLeftChangeId','expectedRightChangeId'):
            if not isinstance(args[key], str) or not _CHANGE.fullmatch(args[key]):
                raise ValueError('IC_ELIMINATION_SOURCE_CHANGE_ID_INVALID')
        for key in ('expectedMatchedMagnitude','expectedSignedResidual'):
            if not isinstance(args[key], str) or not _AMOUNT.fullmatch(args[key]):
                raise ValueError('IC_ELIMINATION_EXPECTED_AMOUNT_INVALID')
        if Decimal(args['expectedMatchedMagnitude']) <= 0:
            raise ValueError('IC_ELIMINATION_ZERO_MATCH')
        preview_program = {'languageVersion': 2,
                           'function': PREVIEW_FUNCTION,
                           'arguments': {key: args[key] for key in preview_keys}}
        return args, preview_program

    @staticmethod
    def _prior(db, scope: ApplicationScope, operation_id: str,
               digest: str, subject_id: str) -> dict | None:
        prior = db.execute('''SELECT command_digest,actor_id,result
            FROM epm.operation_receipt WHERE workspace_id=%s
            AND application_id=%s AND operation_id=%s''',
            (scope.workspace_id, scope.application_id,
             operation_id)).fetchone()
        if prior is None:
            return None
        result_state_token = prior['result'].get('resultStateToken')
        if (prior['command_digest'] != digest
                or prior['actor_id'] != subject_id
                or not isinstance(result_state_token, str)
                or not _STATE_TOKEN.fullmatch(result_state_token)):
            raise ValueError('IC_ELIMINATION_IDEMPOTENCY_CONFLICT')
        PostgresNumericFactStore._require_replay_impact(
            db,scope,operation_id,prior)
        return prior['result']

    @staticmethod
    def _withdraw_prior(db, scope: ApplicationScope, operation_id: str,
                        digest: str, subject_id: str) -> dict | None:
        prior = db.execute('''SELECT command_digest,actor_id,result
            FROM epm.operation_receipt WHERE workspace_id=%s
            AND application_id=%s AND operation_id=%s''',
            (scope.workspace_id, scope.application_id,
             operation_id)).fetchone()
        if prior is None:
            return None
        if (prior['command_digest'] != digest
                or prior['actor_id'] != subject_id
                or prior['result'].get('withdrawalId') != operation_id):
            raise ValueError('IC_ELIMINATION_IDEMPOTENCY_CONFLICT')
        PostgresNumericFactStore._require_replay_impact(
            db,scope,operation_id,prior)
        return prior['result']

    def publish(self, scope: ApplicationScope, program: object, *,
                idempotency_key: str) -> dict:
        args, preview_program = self._compile_post(program)
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(idempotency_key, str)
                or not _ID.fullmatch(idempotency_key)):
            raise ValueError('IC_ELIMINATION_TARGET_OR_KEY_INVALID')
        digest = _canonical_digest({'scope': [scope.workspace_id,
                                             scope.application_id],
                                    'identity': [self.identity.issuer,
                                                 self.identity.subject_id],
                                    'program': program})
        # A replay must work even when the original source has since changed.
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=POST_FUNCTION)
                prior = self._prior(db, scope, idempotency_key, digest,
                                    self.identity.subject_id)
                if prior is not None:
                    return prior
        candidate = PostgresIntercompanyEliminationPreview(
            self.dsn, identity=self.identity).preview(scope, preview_program)
        if not candidate['candidateAvailable']:
            raise ValueError('IC_ELIMINATION_CANDIDATE_UNAVAILABLE')
        pair = candidate['sourcePair']
        if (args['expectedMetadataRevision'] != candidate['metadataRevision']
                or args['expectedDataRevision'] != candidate['dataRevision']
                or args['expectedPolicyRevision'] != candidate['policyRevision']
                or args['expectedCommitRevision'] != candidate['commitRevision']
                or args['expectedLeftChangeId'] != pair['left']['changeId']
                or args['expectedRightChangeId'] != pair['right']['changeId']
                or args['expectedMatchedMagnitude'] !=
                    candidate['matchedMagnitude']
                or args['expectedSignedResidual'] !=
                    candidate['signedResidual']):
            raise ValueError('IC_ELIMINATION_PREVIEW_STALE')
        left = Coordinate.from_mapping(pair['left']['members'])
        right = Coordinate.from_mapping(pair['right']['members'])
        key = _pair_key(candidate['parentEntityId'], left, right)
        signed = [Decimal(row['signedCandidateOffset'])
                  for row in candidate['candidateLines']]
        if (len(signed) != 2 or signed[0] == 0 or signed[1] == 0
                or signed[0] + signed[1] != 0):
            raise ValueError('IC_ELIMINATION_NOT_BALANCED')
        # Resolve the complete admitted candidate without holding the
        # application publication row.  Independent pairs can prepare in
        # parallel; the final transaction repeats every mutable check.
        with connect_postgres(self.dsn, row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before, 10000)
                PostgresNumericFactStore._set_scope(before, scope)
                PostgresAccessChecker.lock_workspace(
                    before, scope.workspace_id)
                initial_access = PostgresAccessChecker.check_in_transaction(
                    before, self.identity, scope, 'admin')
                # This transaction creates no effect and deliberately avoids
                # a shared application-state row lock.  Two preparers must not
                # deadlock later while upgrading to the final exclusive row
                # fence.  Publication repeats the locked capability check.
                PostgresAccessChecker.require_capability_in_transaction(
                    before, scope, POST_FUNCTION, lock_state=False)
                prior = self._prior(before, scope, idempotency_key, digest,
                                    self.identity.subject_id)
                if prior is not None:
                    return prior
                initial = _publication_candidate(
                    before, scope, args, left=left, right=right,
                    pair_key=key, identity=self.identity,
                    workflow_role=initial_access.role,
                    final=False)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                # Take the exclusive publication row before the capability
                # check takes its shared lock.  This fixed order prevents two
                # publishers from deadlocking while upgrading FOR SHARE.
                db.execute('''SELECT 1 FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s
                    FOR UPDATE''', (scope.workspace_id,
                                   scope.application_id)).fetchone()
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=POST_FUNCTION)
                prior = self._prior(db, scope, idempotency_key, digest,
                                    self.identity.subject_id)
                if prior is not None:
                    return prior
                final = _publication_candidate(
                    db, scope, args, left=left, right=right, pair_key=key,
                    identity=self.identity, workflow_role=access.role,
                    final=True)
                if final['pointer'] != initial['pointer']:
                    raise ValueError('IC_ELIMINATION_POINTER_STALE')
                state = final['state']
                source_rows = final['sourceRows']
                policy_evidence = final['planningPolicy']
                revision = state['commit_revision'] + 1
                state_token = new_state_token()
                result = {'resultStateToken':state_token,
                          'parentEntityId': candidate['parentEntityId'],
                          'pairKey': key,
                          'status': 'PublishedUnreviewed',
                          'matchedMagnitude': candidate['matchedMagnitude'],
                          'signedResidual': candidate['signedResidual'],
                          'sourceDataRevision': args['expectedDataRevision'],
                          'dataRevision': state['data_revision'] + 1,
                          'lineCount': 2,
                          'accountingPolicyStatus': 'Unreviewed',
                          'planningPolicy': policy_evidence}
                from .postgres_calculation_impact import (
                    coordinate_numeric_impact)
                impact=coordinate_numeric_impact(source_kind='elimination',
                    operation_id=idempotency_key,causal_revision=revision,
                    member_sets=[row['members'] for row in source_rows],
                    change='add',old_present=True,new_present=True)
                result['impactDigest']=impact.digest
                db.execute('''DELETE FROM epm.ic_elimination_current_line
                    WHERE workspace_id=%s AND application_id=%s
                      AND parent_entity_member_id=%s AND pair_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     candidate['parentEntityId'],key))
                db.cursor().executemany('''INSERT INTO
                    epm.ic_elimination_current_line
                    (workspace_id,application_id,parent_entity_member_id,
                     pair_key,line_ordinal,
                     coordinate_id,signed_amount,source_change_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''', [
                    (scope.workspace_id,scope.application_id,
                     candidate['parentEntityId'],key,ordinal,
                     source_rows[ordinal-1]['coordinate_id'],amount,
                     source_rows[ordinal-1]['change_id'])
                    for ordinal,amount in enumerate(signed,1)])
                db.execute('''INSERT INTO epm.ic_elimination_state
                    (workspace_id,application_id,parent_entity_member_id,
                     pair_key,state_token,status,left_relationship_id,
                     right_relationship_id,left_coordinate_id,
                     right_coordinate_id,left_source_change_id,
                     right_source_change_id,matched_magnitude,signed_residual,
                     source_metadata_revision,source_data_revision,
                     source_policy_revision,committed_revision,issuer,subject_id)
                    VALUES (%s,%s,%s,%s,%s,'PublishedUnreviewed',%s,%s,%s,%s,
                            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,
                        parent_entity_member_id,pair_key)
                    DO UPDATE SET state_token=EXCLUDED.state_token,
                        status=EXCLUDED.status,
                        left_relationship_id=EXCLUDED.left_relationship_id,
                        right_relationship_id=EXCLUDED.right_relationship_id,
                        left_coordinate_id=EXCLUDED.left_coordinate_id,
                        right_coordinate_id=EXCLUDED.right_coordinate_id,
                        left_source_change_id=EXCLUDED.left_source_change_id,
                        right_source_change_id=EXCLUDED.right_source_change_id,
                        matched_magnitude=EXCLUDED.matched_magnitude,
                        signed_residual=EXCLUDED.signed_residual,
                        source_metadata_revision=EXCLUDED.source_metadata_revision,
                        source_data_revision=EXCLUDED.source_data_revision,
                        source_policy_revision=EXCLUDED.source_policy_revision,
                        committed_revision=EXCLUDED.committed_revision,
                        issuer=EXCLUDED.issuer,subject_id=EXCLUDED.subject_id,
                        updated_at=transaction_timestamp()''',
                    (scope.workspace_id,scope.application_id,
                     candidate['parentEntityId'],key,state_token,
                     args['leftRelationshipId'],args['rightRelationshipId'],
                     source_rows[0]['coordinate_id'],
                     source_rows[1]['coordinate_id'],
                     args['expectedLeftChangeId'],args['expectedRightChangeId'],
                     Decimal(candidate['matchedMagnitude']),
                     Decimal(candidate['signedResidual']),
                     args['expectedMetadataRevision'],
                     args['expectedDataRevision'],
                     args['expectedPolicyRevision'],revision,
                     self.identity.issuer,self.identity.subject_id))
                db.execute('''UPDATE epm.application_state SET
                    data_revision=data_revision+1,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,idempotency_key,
                     digest,self.identity.subject_id,revision,Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=idempotency_key,impact=impact)
                return result

    def withdraw(self, scope: ApplicationScope, program: object, *,
                 idempotency_key: str) -> dict:
        """Replace the current offset with one withdrawn current state."""
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != WITHDRAW_FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) != {
                    'parentEntityId','pairKey','resultStateToken',
                    'expectedDataRevision','expectedCommitRevision'}
                or not isinstance(program['arguments']['parentEntityId'],str)
                or not 1 <= len(program['arguments']['parentEntityId']) <= 200
                or not isinstance(program['arguments']['pairKey'],str)
                or not _PAIR.fullmatch(program['arguments']['pairKey'])
                or any(type(program['arguments'][key]) is not int
                       or program['arguments'][key] < 0
                       for key in ('expectedDataRevision',
                                   'expectedCommitRevision'))
                or not isinstance(idempotency_key,str)
                or not _ID.fullmatch(idempotency_key)):
            raise ValueError('IC_ELIMINATION_WITHDRAW_PROGRAM_INVALID')
        args = program['arguments']
        require_state_token(args['resultStateToken'],
                            error='IC_ELIMINATION_WITHDRAW_PROGRAM_INVALID')
        digest = _canonical_digest({
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'program':program})
        # Resolve and govern the exact current state before taking the
        # application publication lock. This lets unrelated IC withdrawals
        # prepare concurrently. The final transaction repeats authority,
        # lifecycle, pointer and planning-policy checks before any effect.
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before, 10000)
                PostgresNumericFactStore._set_scope(before,scope)
                PostgresAccessChecker.lock_workspace(
                    before,scope.workspace_id)
                initial_access = PostgresAccessChecker.check_in_transaction(
                    before,self.identity,scope,'admin',
                    function=WITHDRAW_FUNCTION)
                prior = self._withdraw_prior(
                    before, scope, idempotency_key, digest,
                    self.identity.subject_id)
                if prior is not None:
                    return prior
                initial_state = before.execute('''SELECT s.data_revision,
                    s.commit_revision,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (initial_state is None
                        or initial_state['application_status'] != 'Active'
                        or initial_state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (initial_state['data_revision'] !=
                        args['expectedDataRevision']
                        or initial_state['commit_revision'] !=
                            args['expectedCommitRevision']):
                    raise ValueError(
                        'IC_ELIMINATION_WITHDRAW_PREVIEW_STALE')
                candidate = _withdrawal_candidate(
                    before, scope, args,
                    identity=self.identity,
                    workflow_role=initial_access.role,
                    lock_pointer=False)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                access = PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin', function=WITHDRAW_FUNCTION)

                prior = self._withdraw_prior(
                    db, scope, idempotency_key, digest,
                    self.identity.subject_id)
                if prior is not None:
                    return prior
                state = db.execute('''SELECT s.data_revision,
                    s.commit_revision,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                prior = self._withdraw_prior(
                    db, scope, idempotency_key, digest,
                    self.identity.subject_id)
                if prior is not None:
                    return prior
                final_candidate = _withdrawal_candidate(
                    db, scope, args, identity=self.identity,
                    workflow_role=access.role,
                    lock_pointer=True)
                identity_keys = ('parentEntityId','pairKey','targetMembers')
                if ({key: final_candidate[key] for key in identity_keys}
                        != {key: candidate[key] for key in identity_keys}):
                    raise ValueError(
                        'IC_ELIMINATION_WITHDRAW_CANDIDATE_STALE')
                policy_evidence = final_candidate['planningPolicy']
                revision = state['commit_revision'] + 1
                state_token = new_state_token()
                deleted = db.execute('''DELETE FROM
                    epm.ic_elimination_current_line
                    WHERE workspace_id=%s AND application_id=%s
                    AND parent_entity_member_id=%s AND pair_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     final_candidate['parentEntityId'],
                     final_candidate['pairKey'])).rowcount
                if deleted != 2:
                    raise ValueError('IC_ELIMINATION_CURRENT_LINES_INVALID')
                updated=db.execute('''UPDATE epm.ic_elimination_state SET
                    state_token=%s,status='WithdrawnUnreviewed',
                    committed_revision=%s,issuer=%s,subject_id=%s,
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                      AND parent_entity_member_id=%s AND pair_key=%s
                      AND state_token=%s AND status='PublishedUnreviewed' ''',
                    (state_token,revision,self.identity.issuer,
                     self.identity.subject_id,scope.workspace_id,
                     scope.application_id,
                     final_candidate['parentEntityId'],
                     final_candidate['pairKey'],
                     args['resultStateToken'])).rowcount
                if updated!=1:
                    raise ValueError('IC_ELIMINATION_STATE_NOT_CURRENT')
                result = {'withdrawalId':idempotency_key,
                          'resultStateToken':state_token,
                          'parentEntityId':final_candidate['parentEntityId'],
                          'pairKey':final_candidate['pairKey'],
                          'status':'WithdrawnUnreviewed',
                          'dataRevision':state['data_revision'] + 1,
                          'accountingPolicyStatus':'Unreviewed',
                          'rawFactsChanged':False,
                          'planningPolicy':policy_evidence}
                from .postgres_calculation_impact import (
                    coordinate_numeric_impact)
                impact=coordinate_numeric_impact(source_kind='elimination',
                    operation_id=idempotency_key,causal_revision=revision,
                    member_sets=list(final_candidate['targetMembers']),
                    change='clear',old_present=True,new_present=False)
                result['impactDigest']=impact.digest
                db.execute('''UPDATE epm.application_state SET
                    data_revision=data_revision+1,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,idempotency_key,
                     digest,self.identity.subject_id,revision,Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=idempotency_key,impact=impact)
                return result

    def read(self, scope: ApplicationScope, program: object) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != READ_FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) != {'parentEntityId','pairKey'}
                or not isinstance(
                    program['arguments']['parentEntityId'], str)
                or not 1 <= len(
                    program['arguments']['parentEntityId']) <= 200
                or not isinstance(program['arguments']['pairKey'], str)
                or not _PAIR.fullmatch(program['arguments']['pairKey'])):
            raise ValueError('IC_ELIMINATION_READ_PROGRAM_INVALID')
        args=program['arguments']
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read', function=READ_FUNCTION)
                state=db.execute('''SELECT metadata_revision,policy_revision,
                    data_revision,commit_revision FROM epm.application_state WHERE
                    workspace_id=%s AND application_id=%s FOR SHARE''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                current=db.execute('''SELECT s.*,
                    left_cell.change_id AS current_left_change_id,
                    right_cell.change_id AS current_right_change_id
                    FROM epm.ic_elimination_state s
                    LEFT JOIN epm.numeric_cell_current left_cell ON
                      left_cell.workspace_id=s.workspace_id
                      AND left_cell.application_id=s.application_id
                      AND left_cell.coordinate_id=s.left_coordinate_id
                      AND left_cell.present
                    LEFT JOIN epm.numeric_cell_current right_cell ON
                      right_cell.workspace_id=s.workspace_id
                      AND right_cell.application_id=s.application_id
                      AND right_cell.coordinate_id=s.right_coordinate_id
                      AND right_cell.present
                    WHERE s.workspace_id=%s AND s.application_id=%s
                      AND s.parent_entity_member_id=%s AND s.pair_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     args['parentEntityId'],args['pairKey'])).fetchone()
                if current is None:
                    raise ValueError('IC_ELIMINATION_STATE_UNAVAILABLE')
                lines=db.execute('''SELECT l.line_ordinal,l.signed_amount,
                    l.source_change_id,c.members
                    FROM epm.ic_elimination_current_line l JOIN epm.coordinate c
                      USING (workspace_id,application_id,coordinate_id)
                    WHERE l.workspace_id=%s AND l.application_id=%s
                    AND l.parent_entity_member_id=%s AND l.pair_key=%s
                    ORDER BY l.line_ordinal''',
                    (scope.workspace_id,scope.application_id,
                     args['parentEntityId'],args['pairKey'])).fetchall()
                if ((current['status']=='PublishedUnreviewed' and len(lines)!=2)
                        or (current['status']=='WithdrawnUnreviewed' and lines)):
                    raise ValueError('IC_ELIMINATION_CURRENT_STATE_INVALID')
                authorize_coordinates(
                    db, self.identity, scope,
                    tuple(Coordinate.from_mapping(row['members'])
                          for row in lines),
                    kind=AccessKind.READ)
        metadata_matches=(state['metadata_revision']==
                          current['source_metadata_revision'])
        policy_matches=(state['policy_revision']==
                        current['source_policy_revision'])
        raw_sources_match=(
            current['current_left_change_id']==current['left_source_change_id']
            and current['current_right_change_id']==
                current['right_source_change_id'])
        return {'resultStateToken':current['state_token'],
                'parentEntityId':current['parent_entity_member_id'],
                'pairKey':current['pair_key'],
                'status':current['status'],
                'ruleId':current['rule_id'],
                'matchedMagnitude':format(current['matched_magnitude'],'.8f'),
                'signedResidual':format(current['signed_residual'],'.8f'),
                'sourceDataRevision':current['source_data_revision'],
                'currentDataRevision':state['data_revision'],
                'currentCommitRevision':state['commit_revision'],
                'metadataStillMatches':metadata_matches,
                'policyStillMatches':policy_matches,
                'rawSourcesStillMatch':raw_sources_match,
                'sourceStillMatches':(metadata_matches and policy_matches
                                      and raw_sources_match),
                'lines':[{'lineOrdinal':row['line_ordinal'],
                          'sourceMembers':row['members'],
                          'signedAmount':format(row['signed_amount'],'.8f'),
                          'sourceChangeId':row['source_change_id']}
                         for row in lines],
                'accountingPolicyStatus':'Unreviewed',
                'rawFactsChanged':False}
