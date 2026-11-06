"""Transactional PostgreSQL mutation slice for generic EPM metadata.

Only fixed application-language handlers may call this store. It does not yet
replace the legacy metadata module or its full edit/delete/validation surface.
"""
from __future__ import annotations

from hashlib import sha256
import base64
import binascii
import hmac
import json
import re
from collections import deque

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .persistence_contract import ApplicationScope, MutationReceipt
from .postgres_numeric_store import PostgresNumericFactStore
from .security_string import parse_security_string


_MODEL_ROLES = {
    'Scenario', 'Year', 'Period', 'View', 'Entity', 'Value', 'Account',
    'ICP', 'Currency', 'DataType', 'Custom', 'Movement',
}

_AGGREGATION_OPERATORS = {
    'Add', 'Subtract', 'Ignore', 'NeverAggregate', 'Formula',
}
_MEMBERSHIP_SEMANTICS = {'unique_member', 'placement'}


def _name(value: str, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 200:
        raise ValueError(f'{label} must contain 1–200 characters')
    return value.strip()


def _description(value: str, label: str, maximum: int) -> str:
    if (not isinstance(value, str) or len(value) > maximum
            or '\x00' in value):
        raise ValueError(f'{label} must contain at most {maximum} characters')
    return value.strip()


def _security_tags(value: object, label: str) -> list[str]:
    """Return a canonical tag set without choosing authorization semantics."""
    if (not isinstance(value, list) or len(value) > 100
            or any(not isinstance(tag, str)
                   or tag != tag.strip()
                   or not 1 <= len(tag) <= 20
                   or ';' in tag for tag in value)
            or len(set(value)) != len(value)):
        raise ValueError(f'{label} must contain unique exact 1–20 character tags')
    return sorted(value)


def _security_tag(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError('SECURITY_TAG_ID_INVALID')
    try:
        return _security_tags([value], 'Security tag ID')[0]
    except ValueError as error:
        raise ValueError('SECURITY_TAG_ID_INVALID') from error


def _compiled_security_string(value: object,
                              known_tags: set[str]) -> tuple[list[str], list[str]]:
    if not isinstance(value, str):
        raise ValueError('SECURITY_STRING_INVALID')
    compiled = parse_security_string(value, known_tags=known_tags)
    return list(compiled.read_tags), list(compiled.write_tags)


class PostgresMetadataStore:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 cursor_secret: bytes | None = None):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL connection string is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity
        if (cursor_secret is not None and
                (not isinstance(cursor_secret, bytes)
                 or len(cursor_secret) < 32)):
            raise ValueError('A server-owned cursor secret of 32+ bytes is required')
        self.cursor_secret = cursor_secret

    def _begin_read(self, db, scope: ApplicationScope) -> int:
        # The security fence requires a fresh READ COMMITTED grant snapshot.
        # P11 will add a pinned metadata snapshot contract for multi-query reads.
        db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY')
        PostgresNumericFactStore._set_scope(db, scope)
        PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, 'read')
        row = db.execute('''SELECT metadata_revision FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if row is None:
            raise ValueError('APPLICATION_UNAVAILABLE')
        return row['metadata_revision']

    @staticmethod
    def _finish_read(db, scope: ApplicationScope, revision: int) -> None:
        row = db.execute('''SELECT metadata_revision FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if row is None or row['metadata_revision'] != revision:
            raise ValueError('METADATA_CHANGED_DURING_READ')

    def resolve_dimension(self, scope: ApplicationScope,
                          reference: str) -> dict:
        reference = _name(reference, 'Dimension reference')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            revision = self._begin_read(db, scope)
            result = self._resolve_dimension(db, scope, reference)
            self._finish_read(db, scope, revision)
            return result

    def resolve_member(self, scope: ApplicationScope,
                       dimension_reference: str,
                       member_reference: str) -> dict:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            revision = self._begin_read(db, scope)
            result = self._resolve_member(db, scope, dimension_reference,
                                          member_reference)
            self._finish_read(db, scope, revision)
            return result

    def list_dimensions(self, scope: ApplicationScope, *,
                        limit: int = 100, after_dimension_id: str | None = None,
                        expected_metadata_revision: int | None = None) -> dict:
        self._validate_page(limit, after_dimension_id,
                            expected_metadata_revision)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            revision = self._begin_read(db, scope)
            self._check_page_revision(revision, expected_metadata_revision)
            rows = db.execute('''SELECT dimension_id, name, model_role, status,
                short_description, detailed_description
                FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
                AND (%s::text IS NULL OR dimension_id>%s)
                ORDER BY dimension_id LIMIT %s''',
                (scope.workspace_id, scope.application_id,
                 after_dimension_id, after_dimension_id, limit + 1)).fetchall()
            self._finish_read(db, scope, revision)
            page = [dict(row) for row in rows[:limit]]
            return {'rows': page, 'metadataRevision': revision,
                    'hasMore': len(rows) > limit,
                    'nextAfterDimensionId': page[-1]['dimension_id']
                    if len(rows) > limit else None}

    def list_members(self, scope: ApplicationScope,
                     dimension_reference: str, *, limit: int = 100,
                     after_member_id: str | None = None,
                     expected_metadata_revision: int | None = None) -> dict:
        self._validate_page(limit, after_member_id,
                            expected_metadata_revision)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            revision = self._begin_read(db, scope)
            self._check_page_revision(revision, expected_metadata_revision)
            dimension = self._resolve_dimension(db, scope,
                                                dimension_reference)
            rows = db.execute('''SELECT dimension_id, member_id, name, status,
                short_description, detailed_description, numeric_value_kind,
                aggregation_operator, custom_values
                FROM epm.member WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s
                AND (%s::text IS NULL OR member_id>%s)
                ORDER BY member_id LIMIT %s''',
                (scope.workspace_id, scope.application_id,
                 dimension['dimension_id'], after_member_id, after_member_id,
                 limit + 1)).fetchall()
            self._finish_read(db, scope, revision)
            page = [dict(row) for row in rows[:limit]]
            return {'dimensionId': dimension['dimension_id'], 'rows': page,
                    'metadataRevision': revision,
                    'hasMore': len(rows) > limit,
                    'nextAfterMemberId': page[-1]['member_id']
                    if len(rows) > limit else None}

    def list_security_tags(self, scope: ApplicationScope,
                           dimension_reference: str, *, limit: int = 100,
                           status: str | None = None,
                           after_tag_id: str | None = None,
                           expected_metadata_revision: int | None = None
                           ) -> dict:
        self._validate_page(limit, after_tag_id, expected_metadata_revision)
        if status not in (None, 'Active', 'Inactive'):
            raise ValueError('SECURITY_TAG_STATUS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            revision = self._begin_read(db, scope)
            self._check_page_revision(revision, expected_metadata_revision)
            dimension = self._resolve_dimension(db, scope,
                                                dimension_reference)
            rows = db.execute('''SELECT dimension_id,tag_id,display_name,
                short_description,semantic_description,status
                FROM epm.security_tag
                WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=%s
                  AND (%s::text IS NULL OR status=%s)
                  AND (%s::text IS NULL OR tag_id>%s)
                ORDER BY tag_id LIMIT %s''',
                (scope.workspace_id,scope.application_id,
                 dimension['dimension_id'],status,status,
                 after_tag_id,after_tag_id,limit+1)).fetchall()
            self._finish_read(db,scope,revision)
            page=[dict(row) for row in rows[:limit]]
            return {'dimensionId':dimension['dimension_id'],'rows':page,
                    'metadataRevision':revision,'status':status,
                    'hasMore':len(rows)>limit,
                    'nextAfterTagId':page[-1]['tag_id']
                    if len(rows)>limit else None}

    def list_relationships(self, scope: ApplicationScope,
                           dimension_reference: str | None = None, *,
                           limit: int = 100, status: str | None = None,
                           cursor: str | None = None) -> dict:
        """Page current relationship records, not hierarchy-version membership."""
        if cursor is not None:
            if dimension_reference is not None or status is not None or limit != 100:
                raise ValueError('METADATA_RELATIONSHIP_CURSOR_ARGUMENTS_INVALID')
            request = self._unpack_relationship_cursor(cursor, scope)
        else:
            if dimension_reference is None:
                raise ValueError('METADATA_RELATIONSHIP_DIMENSION_REQUIRED')
            self._validate_page(limit, None, None)
            if status not in (None, 'Active', 'Inactive'):
                raise ValueError('METADATA_RELATIONSHIP_STATUS_INVALID')
            request = {'dimensionId': dimension_reference, 'status': status,
                       'limit': limit, 'afterRelationshipId': None,
                       'metadataRevision': None}
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            revision = self._begin_read(db, scope)
            self._check_page_revision(revision, request['metadataRevision'])
            dimension = self._resolve_dimension(db, scope,
                                                request['dimensionId'])
            if (request['metadataRevision'] is not None and
                    dimension['dimension_id'] != request['dimensionId']):
                raise ValueError('METADATA_RELATIONSHIP_CURSOR_INVALID')
            rows = db.execute('''SELECT relationship_id, dimension_id,
                name,short_description,parent_member_id, child_member_id,
                semantic_tag,detailed_description,semantic_description,
                status, custom_values,
                aggregation_operator_override
                FROM epm.relationship
                WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s
                AND (%s::text IS NULL OR status=%s)
                AND (%s::text IS NULL OR relationship_id>%s)
                ORDER BY relationship_id LIMIT %s''',
                (scope.workspace_id, scope.application_id,
                 dimension['dimension_id'], request['status'], request['status'],
                 request['afterRelationshipId'],
                 request['afterRelationshipId'], request['limit'] + 1)).fetchall()
            self._finish_read(db, scope, revision)
            page = [dict(row) for row in rows[:request['limit']]]
            has_more = len(rows) > request['limit']
            return {'dimensionId': dimension['dimension_id'], 'rows': page,
                    'metadataRevision': revision,
                    'status': request['status'], 'hasMore': has_more,
                    'nextAfterRelationshipId': page[-1]['relationship_id']
                    if has_more else None,
                    'nextCursor': self._pack_relationship_cursor(scope, {
                        'dimensionId': dimension['dimension_id'],
                        'status': request['status'], 'limit': request['limit'],
                        'afterRelationshipId': page[-1]['relationship_id'],
                        'metadataRevision': revision}) if has_more else None}

    def _pack_relationship_cursor(self, scope: ApplicationScope,
                                  payload: dict) -> str:
        if self.cursor_secret is None:
            raise ValueError('METADATA_RELATIONSHIP_CURSOR_UNAVAILABLE')
        value = {**payload,
                 '_scope': [scope.workspace_id, scope.application_id],
                 '_identity': [self.identity.issuer, self.identity.subject_id]}
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False).encode()
        return base64.urlsafe_b64encode(
            raw + hmac.new(self.cursor_secret, raw, sha256).digest()).decode()

    def _unpack_relationship_cursor(self, token: str,
                                    scope: ApplicationScope) -> dict:
        if (self.cursor_secret is None or not isinstance(token, str)
                or len(token) > 8192):
            raise ValueError('METADATA_RELATIONSHIP_CURSOR_INVALID')
        try:
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(signature, hmac.new(
                    self.cursor_secret, raw, sha256).digest()):
                raise ValueError('signature')
            value = json.loads(raw)
        except (ValueError, TypeError, binascii.Error, UnicodeDecodeError,
                json.JSONDecodeError) as error:
            raise ValueError('METADATA_RELATIONSHIP_CURSOR_INVALID') from error
        expected = {'dimensionId', 'status', 'limit', 'afterRelationshipId',
                    'metadataRevision', '_scope', '_identity'}
        if (not isinstance(value, dict) or set(value) != expected
                or value['_scope'] != [scope.workspace_id, scope.application_id]
                or value['_identity'] != [self.identity.issuer,
                                           self.identity.subject_id]
                or value['status'] not in (None, 'Active', 'Inactive')
                or type(value['limit']) is not int
                or not 1 <= value['limit'] <= 500
                or type(value['metadataRevision']) is not int
                or value['metadataRevision'] < 0):
            raise ValueError('METADATA_RELATIONSHIP_CURSOR_INVALID')
        try:
            value['dimensionId'] = _name(value['dimensionId'], 'Dimension ID')
            value['afterRelationshipId'] = _name(
                value['afterRelationshipId'], 'Relationship ID')
        except ValueError as error:
            raise ValueError('METADATA_RELATIONSHIP_CURSOR_INVALID') from error
        value.pop('_scope')
        value.pop('_identity')
        return value

    @staticmethod
    def _validate_page(limit: int, after_id: str | None,
                       expected_revision: int | None) -> None:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError('METADATA_PAGE_LIMIT_INVALID')
        if after_id is not None:
            _name(after_id, 'Metadata page anchor')
            if expected_revision is None:
                raise ValueError('METADATA_PAGE_REVISION_REQUIRED')
        if (expected_revision is not None and
                (type(expected_revision) is not int or
                 expected_revision < 0)):
            raise ValueError('METADATA_PAGE_REVISION_INVALID')

    @staticmethod
    def _check_page_revision(actual: int, expected: int | None) -> None:
        if expected is not None and actual != expected:
            raise ValueError('STALE_METADATA_REVISION')

    def list_children(self, scope: ApplicationScope, dimension_reference: str,
                      parent_reference: str, *, limit: int = 500) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError('Hierarchy child limit must be 1–500')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            revision = self._begin_read(db, scope)
            parent = self._resolve_member(db, scope, dimension_reference,
                                          parent_reference)
            result = [dict(row) for row in db.execute('''SELECT
                r.relationship_id, m.member_id, m.name
                FROM epm.relationship r JOIN epm.member m
                ON m.workspace_id=r.workspace_id
                AND m.application_id=r.application_id
                AND m.dimension_id=r.dimension_id
                AND m.member_id=r.child_member_id
                WHERE r.workspace_id=%s AND r.application_id=%s
                AND r.dimension_id=%s AND r.parent_member_id=%s
                AND r.status='Active' AND m.status='Active'
                ORDER BY lower(m.name), m.member_id LIMIT %s''',
                (scope.workspace_id, scope.application_id,
                 parent['dimension_id'], parent['member_id'], limit)).fetchall()]
            self._finish_read(db, scope, revision)
            return result

    def build_hierarchy(self, scope: ApplicationScope, *, dimension_id: str,
                        operation_id: str, command_digest: str, actor_id: str,
                        expected_metadata_revision: int,
                        membership_semantics: str | None = None) -> dict:
        dimension_id = _name(dimension_id, 'Dimension ID')
        if (membership_semantics is not None and
                membership_semantics not in _MEMBERSHIP_SEMANTICS):
            raise ValueError('HIERARCHY_MEMBERSHIP_SEMANTICS_INVALID')
        if (not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 200
                or not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)
                or isinstance(expected_metadata_revision, bool)
                or not isinstance(expected_metadata_revision, int)
                or expected_metadata_revision < 0):
            raise ValueError('Valid operation, actor, digest and revision are required')
        if actor_id != self.identity.subject_id:
            raise ValueError('Actor ID must match verified identity')
        payload_digest = sha256(json.dumps({
            'kind': 'hierarchy.build', 'workspaceId': scope.workspace_id,
            'applicationId': scope.application_id, 'dimensionId': dimension_id,
            'actorId': actor_id,
            'expectedMetadataRevision': expected_metadata_revision,
            'requestedMembershipSemantics': membership_semantics,
        }, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                keys = (scope.workspace_id, scope.application_id)
                state = db.execute('''SELECT a.status, s.processing_mode,
                    s.metadata_revision, s.security_revision,
                    s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id, application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin')
                previous = db.execute('''SELECT command_digest,
                    committed_revision, result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''', (*keys, operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['result'].get('payloadDigest') != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return {'version': previous['result']['version'],
                            'closureCount': previous['result']['closureCount'],
                            'membershipSemantics': previous['result'].get(
                                'membershipSemantics', 'unique_member'),
                            'committedRevision': previous['committed_revision']}
                if state['status'] != 'Active' or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != expected_metadata_revision:
                    raise ValueError('STALE_METADATA_REVISION')
                if membership_semantics is None:
                    prior_semantics = db.execute('''SELECT
                        v.membership_semantics FROM epm.hierarchy_active a
                        JOIN epm.hierarchy_version v USING
                        (workspace_id,application_id,dimension_id,version)
                        WHERE a.workspace_id=%s AND a.application_id=%s
                        AND a.dimension_id=%s''',
                        (*keys, dimension_id)).fetchone()
                    effective_membership_semantics = (
                        prior_semantics['membership_semantics']
                        if prior_semantics else 'unique_member')
                else:
                    effective_membership_semantics = membership_semantics
                dimension = db.execute('''SELECT 1 FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND status='Active' ''',
                    (*keys, dimension_id)).fetchone()
                if dimension is None:
                    raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                members = [row['member_id'] for row in db.execute('''SELECT member_id
                    FROM epm.member WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND status='Active'
                    ORDER BY member_id''', (*keys, dimension_id)).fetchall()]
                if len(members) > 5000:
                    raise ValueError('HIERARCHY_MEMBER_LIMIT')
                edges = db.execute('''SELECT parent_member_id, child_member_id
                    FROM epm.relationship WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND status='Active' ''', (*keys, dimension_id)).fetchall()
                if len(edges) > 10000:
                    raise ValueError('HIERARCHY_EDGE_LIMIT')
                children = {member: [] for member in members}
                indegree = {member: 0 for member in members}
                for edge in edges:
                    parent, child = edge['parent_member_id'], edge['child_member_id']
                    if parent not in children or child not in children:
                        raise ValueError('HIERARCHY_INACTIVE_MEMBER')
                    children[parent].append(child)
                    indegree[child] += 1
                ready = deque(member for member in members if indegree[member] == 0)
                seen = 0
                while ready:
                    parent = ready.popleft()
                    seen += 1
                    for child in children[parent]:
                        indegree[child] -= 1
                        if indegree[child] == 0:
                            ready.append(child)
                if seen != len(members):
                    raise ValueError('HIERARCHY_CYCLE')
                closure = {}
                visits = 0
                for ancestor in members:
                    stack = [(ancestor, 0)]
                    while stack:
                        descendant, depth = stack.pop()
                        visits += 1
                        if visits > 100000:
                            raise ValueError('HIERARCHY_PATH_LIMIT')
                        key = (ancestor, descendant)
                        old = closure.get(key)
                        closure[key] = (min(old[0], depth), old[1] + 1) if old else (depth, 1)
                        stack.extend((child, depth + 1)
                                     for child in children[descendant])
                version = db.execute('''SELECT COALESCE(MAX(version),0)+1
                    AS next_version FROM epm.hierarchy_version
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s''',
                    (*keys, dimension_id)).fetchone()['next_version']
                revision = state['commit_revision'] + 1
                db.execute('''UPDATE epm.application_state
                    SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision, *keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, operation_id, command_digest, actor_id, revision,
                     Jsonb({'kind': 'hierarchy.build', 'version': version,
                            'closureCount': len(closure),
                            'membershipSemantics':
                                effective_membership_semantics,
                            'payloadDigest': payload_digest})))
                db.execute('''INSERT INTO epm.hierarchy_version
                    (workspace_id,application_id,dimension_id,version,
                     metadata_revision,operation_id,membership_semantics)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, dimension_id, version,
                     expected_metadata_revision, operation_id,
                     effective_membership_semantics))
                with db.cursor() as cursor:
                    cursor.executemany('''INSERT INTO epm.hierarchy_closure
                        (workspace_id,application_id,dimension_id,version,
                         ancestor_member_id,descendant_member_id,
                         min_depth,path_count)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
                        [(*keys, dimension_id, version, ancestor, descendant,
                          depth, count)
                         for (ancestor, descendant), (depth, count)
                         in closure.items()])
                db.execute('''INSERT INTO epm.hierarchy_active
                    (workspace_id,application_id,dimension_id,version)
                    VALUES (%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,dimension_id)
                    DO UPDATE SET version=EXCLUDED.version,
                    activated_at=transaction_timestamp()''',
                    (*keys, dimension_id, version))
                return {'version': version, 'closureCount': len(closure),
                        'membershipSemantics': effective_membership_semantics,
                        'committedRevision': revision}

    def descendants(self, scope: ApplicationScope, *, dimension_id: str,
                    ancestor_member_id: str, version: int | None = None,
                    limit: int = 500) -> dict:
        dimension_id = _name(dimension_id, 'Dimension ID')
        ancestor_member_id = _name(ancestor_member_id, 'Ancestor member ID')
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError('Descendant limit must be 1–500')
        if version is not None and (isinstance(version, bool) or
                                    not isinstance(version, int) or version <= 0):
            raise ValueError('Hierarchy version must be positive')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            read_revision = self._begin_read(db, scope)
            keys = (scope.workspace_id, scope.application_id, dimension_id)
            current_requested = version is None
            if version is None:
                active = db.execute('''SELECT version FROM epm.hierarchy_active
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s''', keys).fetchone()
                if active is None:
                    raise ValueError('HIERARCHY_NOT_BUILT')
                version = active['version']
            build = db.execute('''SELECT metadata_revision
                FROM epm.hierarchy_version WHERE workspace_id=%s
                AND application_id=%s AND dimension_id=%s AND version=%s''',
                (*keys, version)).fetchone()
            if build is None:
                raise ValueError('HIERARCHY_VERSION_UNAVAILABLE')
            if current_requested:
                state = db.execute('''SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None or state['metadata_revision'] != build['metadata_revision']:
                    raise ValueError('HIERARCHY_STALE')
            rows = db.execute('''SELECT descendant_member_id, min_depth,
                path_count FROM epm.hierarchy_closure
                WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND version=%s AND ancestor_member_id=%s
                ORDER BY min_depth, descendant_member_id LIMIT %s''',
                (*keys, version, ancestor_member_id, limit)).fetchall()
            self._finish_read(db, scope, read_revision)
            return {'version': version,
                    'metadataRevision': build['metadata_revision'],
                    'members': [dict(row) for row in rows]}

    @staticmethod
    def _resolve_dimension(db, scope: ApplicationScope, reference: str) -> dict:
        reference = _name(reference, 'Dimension reference')
        rows = db.execute('''SELECT dimension_id, name, model_role, status,
            short_description, detailed_description
            FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
            AND status='Active'
            AND (dimension_id=%s OR lower(name)=lower(%s))''',
            (scope.workspace_id, scope.application_id,
             reference, reference)).fetchall()
        if len(rows) != 1:
            raise ValueError('UNKNOWN_OR_AMBIGUOUS_DIMENSION')
        return dict(rows[0])

    @classmethod
    def _resolve_member(cls, db, scope: ApplicationScope,
                        dimension_reference: str,
                        member_reference: str) -> dict:
        dimension = cls._resolve_dimension(db, scope, dimension_reference)
        reference = _name(member_reference, 'Member reference')
        rows = db.execute('''SELECT dimension_id, member_id, name, status,
            short_description, detailed_description, numeric_value_kind
            FROM epm.member WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND status='Active'
            AND (member_id=%s OR lower(name)=lower(%s))''',
            (scope.workspace_id, scope.application_id,
             dimension['dimension_id'], reference, reference)).fetchall()
        if len(rows) != 1:
            raise ValueError('UNKNOWN_OR_AMBIGUOUS_MEMBER')
        return dict(rows[0])

    def create_dimension(self, scope: ApplicationScope, *, dimension_id: str,
                         name: str, operation_id: str, command_digest: str,
                         actor_id: str, expected_metadata_revision: int,
                         model_role: str | None = None,
                         short_description: str = '',
                         detailed_description: str = '') -> MutationReceipt:
        dimension_id = _name(dimension_id, 'Dimension ID')
        name = _name(name, 'Dimension name')
        if model_role is not None and model_role not in _MODEL_ROLES:
            raise ValueError('Unknown dimension model role')
        return self._create(scope, 'dimension',
                            {'dimensionId': dimension_id, 'name': name,
                             'modelRole': model_role,
                             'shortDescription': _description(
                                 short_description, 'Short description', 500),
                             'detailedDescription': _description(
                                 detailed_description, 'Detailed description',
                                 10000)}, operation_id,
                            command_digest, actor_id,
                            expected_metadata_revision)

    def create_member(self, scope: ApplicationScope, *, dimension_id: str,
                      member_id: str, name: str, operation_id: str,
                      command_digest: str, actor_id: str,
                      expected_metadata_revision: int,
                      short_description: str = '',
                      detailed_description: str = '') -> MutationReceipt:
        return self._create(scope, 'member',
                            {'dimensionId': _name(dimension_id, 'Dimension ID'),
                             'memberId': _name(member_id, 'Member ID'),
                             'name': _name(name, 'Member name'),
                             'shortDescription': _description(
                                 short_description, 'Short description', 500),
                             'detailedDescription': _description(
                                 detailed_description, 'Detailed description',
                                 10000)},
                            operation_id, command_digest, actor_id,
                            expected_metadata_revision)

    def rename_dimension(self, scope: ApplicationScope, *, dimension_id: str,
                         name: str, operation_id: str, command_digest: str,
                         actor_id: str,
                         expected_metadata_revision: int) -> MutationReceipt:
        return self._create(scope, 'dimension.rename',
                            {'dimensionId': _name(dimension_id, 'Dimension ID'),
                             'name': _name(name, 'Dimension name')},
                            operation_id, command_digest, actor_id,
                            expected_metadata_revision)

    def rename_member(self, scope: ApplicationScope, *, dimension_id: str,
                      member_id: str, name: str, operation_id: str,
                      command_digest: str, actor_id: str,
                      expected_metadata_revision: int) -> MutationReceipt:
        return self._create(scope, 'member.rename',
                            {'dimensionId': _name(dimension_id, 'Dimension ID'),
                             'memberId': _name(member_id, 'Member ID'),
                             'name': _name(name, 'Member name')},
                            operation_id, command_digest, actor_id,
                            expected_metadata_revision)

    def describe_dimension(self, scope: ApplicationScope, *,
                           dimension_id: str, short_description: str,
                           detailed_description: str, operation_id: str,
                           command_digest: str, actor_id: str,
                           expected_metadata_revision: int) -> MutationReceipt:
        return self._create(scope, 'dimension.describe', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'shortDescription': _description(
                short_description, 'Short description', 500),
            'detailedDescription': _description(
                detailed_description, 'Detailed description', 10000)},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def describe_member(self, scope: ApplicationScope, *,
                        dimension_id: str, member_id: str,
                        short_description: str,
                        detailed_description: str, operation_id: str,
                        command_digest: str, actor_id: str,
                        expected_metadata_revision: int) -> MutationReceipt:
        return self._create(scope, 'member.describe', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'memberId': _name(member_id, 'Member ID'),
            'shortDescription': _description(
                short_description, 'Short description', 500),
            'detailedDescription': _description(
                detailed_description, 'Detailed description', 10000)},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def rename_relationship(self, scope: ApplicationScope, *,
                            relationship_id: str, name: str,
                            operation_id: str, command_digest: str,
                            actor_id: str,
                            expected_metadata_revision: int
                            ) -> MutationReceipt:
        return self._create(scope, 'relationship.rename', {
            'relationshipId': _name(relationship_id, 'Relationship ID'),
            'name': _name(name, 'Relationship name')},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def describe_relationship(self, scope: ApplicationScope, *,
                              relationship_id: str,
                              short_description: str,
                              detailed_description: str,
                              operation_id: str, command_digest: str,
                              actor_id: str,
                              expected_metadata_revision: int
                              ) -> MutationReceipt:
        return self._create(scope, 'relationship.describe', {
            'relationshipId': _name(relationship_id, 'Relationship ID'),
            'shortDescription': _description(
                short_description, 'Short description', 500),
            'detailedDescription': _description(
                detailed_description, 'Detailed description', 10000)},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def set_member_status(self, scope: ApplicationScope, *,
                          dimension_id: str, member_id: str, status: str,
                          operation_id: str, command_digest: str,
                          actor_id: str,
                          expected_metadata_revision: int) -> MutationReceipt:
        if status not in ('Active', 'Inactive'):
            raise ValueError('MEMBER_STATUS_INVALID')
        return self._create(scope, 'member.status.set', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'memberId': _name(member_id, 'Member ID'),
            'status': status}, operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def set_member_security_tags(self, scope: ApplicationScope, *,
                                 dimension_id: str, member_id: str,
                                 read_tags: object, write_tags: object,
                                 operation_id: str, command_digest: str,
                                 actor_id: str,
                                 expected_metadata_revision: int
                                 ) -> MutationReceipt:
        return self._create(scope, 'member.security-tags.set', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'memberId': _name(member_id, 'Member ID'),
            'readTags': _security_tags(read_tags, 'Read tags'),
            'writeTags': _security_tags(write_tags, 'Write tags')},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def set_member_security_string(self, scope: ApplicationScope, *,
                                   dimension_id: str, member_id: str,
                                   security_string: object,
                                   operation_id: str, command_digest: str,
                                   actor_id: str,
                                   expected_metadata_revision: int
                                   ) -> MutationReceipt:
        if not isinstance(security_string, str):
            raise ValueError('SECURITY_STRING_INVALID')
        return self._create(scope, 'member.security-string.set', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'memberId': _name(member_id, 'Member ID'),
            'securityString': security_string},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def set_dimension_security_string(self, scope: ApplicationScope, *,
                                      dimension_id: str,
                                      security_string: object,
                                      operation_id: str,
                                      command_digest: str,
                                      actor_id: str,
                                      expected_metadata_revision: int
                                      ) -> MutationReceipt:
        if not isinstance(security_string, str):
            raise ValueError('SECURITY_STRING_INVALID')
        return self._create(scope, 'dimension.security-string.set', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'securityString': security_string},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def set_relationship_security_string(self, scope: ApplicationScope, *,
                                         relationship_id: str,
                                         security_string: object,
                                         operation_id: str,
                                         command_digest: str,
                                         actor_id: str,
                                         expected_metadata_revision: int
                                         ) -> MutationReceipt:
        if not isinstance(security_string, str):
            raise ValueError('SECURITY_STRING_INVALID')
        return self._create(scope, 'relationship.security-string.set', {
            'relationshipId': _name(relationship_id, 'Relationship ID'),
            'securityString': security_string},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def create_security_tag(self, scope: ApplicationScope, *,
                            dimension_id: str, tag_id: str,
                            display_name: str, short_description: str,
                            semantic_description: str,
                            operation_id: str, command_digest: str,
                            actor_id: str,
                            expected_metadata_revision: int
                            ) -> MutationReceipt:
        return self._create(scope,'security-tag',{
            'dimensionId':_name(dimension_id,'Dimension ID'),
            'tagId':_security_tag(tag_id),
            'displayName':_name(display_name,'Security tag display name'),
            'shortDescription':_description(
                short_description,'Short description',500),
            'semanticDescription':_description(
                semantic_description,'Semantic description',10000)},
            operation_id,command_digest,actor_id,expected_metadata_revision)

    def update_security_tag(self, scope: ApplicationScope, *,
                            dimension_id: str, tag_id: str,
                            display_name: str, short_description: str,
                            semantic_description: str,
                            operation_id: str, command_digest: str,
                            actor_id: str,
                            expected_metadata_revision: int
                            ) -> MutationReceipt:
        return self._create(scope,'security-tag.update',{
            'dimensionId':_name(dimension_id,'Dimension ID'),
            'tagId':_security_tag(tag_id),
            'displayName':_name(display_name,'Security tag display name'),
            'shortDescription':_description(
                short_description,'Short description',500),
            'semanticDescription':_description(
                semantic_description,'Semantic description',10000)},
            operation_id,command_digest,actor_id,expected_metadata_revision)

    def set_security_tag_status(self, scope: ApplicationScope, *,
                                dimension_id: str, tag_id: str, status: str,
                                operation_id: str, command_digest: str,
                                actor_id: str,
                                expected_metadata_revision: int
                                ) -> MutationReceipt:
        if status not in ('Active','Inactive'):
            raise ValueError('SECURITY_TAG_STATUS_INVALID')
        return self._create(scope,'security-tag.status.set',{
            'dimensionId':_name(dimension_id,'Dimension ID'),
            'tagId':_security_tag(tag_id),'status':status},
            operation_id,command_digest,actor_id,expected_metadata_revision)

    def set_dimension_status(self, scope: ApplicationScope, *,
                             dimension_id: str, status: str,
                             operation_id: str, command_digest: str,
                             actor_id: str,
                             expected_metadata_revision: int
                             ) -> MutationReceipt:
        if status not in ('Active', 'Inactive'):
            raise ValueError('DIMENSION_STATUS_INVALID')
        return self._create(scope, 'dimension.status.set', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'status': status}, operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def delete_dimension(self, scope: ApplicationScope, *,
                         dimension_id: str, operation_id: str,
                         command_digest: str, actor_id: str,
                         expected_metadata_revision: int
                         ) -> MutationReceipt:
        return self._create(scope, 'dimension.delete', {
            'dimensionId': _name(dimension_id, 'Dimension ID')},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def set_member_numeric_kind(self, scope: ApplicationScope, *,
                                dimension_id: str, member_id: str,
                                numeric_value_kind: str | None,
                                operation_id: str, command_digest: str,
                                actor_id: str,
                                expected_metadata_revision: int
                                ) -> MutationReceipt:
        if numeric_value_kind not in (None, 'amount', 'ratio'):
            raise ValueError('MEMBER_NUMERIC_KIND_INVALID')
        return self._create(scope, 'member.numeric-kind.set', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'memberId': _name(member_id, 'Member ID'),
            'numericValueKind': numeric_value_kind}, operation_id,
            command_digest, actor_id, expected_metadata_revision)

    def set_member_aggregation_operator(self, scope: ApplicationScope, *,
                                        dimension_id: str, member_id: str,
                                        aggregation_operator: str,
                                        operation_id: str,
                                        command_digest: str, actor_id: str,
                                        expected_metadata_revision: int
                                        ) -> MutationReceipt:
        if aggregation_operator not in _AGGREGATION_OPERATORS:
            raise ValueError('MEMBER_AGGREGATION_OPERATOR_INVALID')
        return self._create(scope, 'member.aggregation-operator.set', {
            'dimensionId': _name(dimension_id, 'Dimension ID'),
            'memberId': _name(member_id, 'Member ID'),
            'aggregationOperator': aggregation_operator}, operation_id,
            command_digest, actor_id, expected_metadata_revision)

    def link_members(self, scope: ApplicationScope, *, dimension_id: str,
                     relationship_id: str, parent_member_id: str,
                     child_member_id: str, name: str | None = None,
                     short_description: str = '',
                     detailed_description: str = '', operation_id: str,
                     command_digest: str, actor_id: str,
                     expected_metadata_revision: int) -> MutationReceipt:
        parent = _name(parent_member_id, 'Parent member ID')
        child = _name(child_member_id, 'Child member ID')
        if parent == child:
            raise ValueError('A member cannot be its own parent')
        stable_id = _name(relationship_id, 'Relationship ID')
        return self._create(scope, 'relationship',
                            {'dimensionId': _name(dimension_id, 'Dimension ID'),
                             'relationshipId': stable_id,
                             'name': _name(name if name is not None else
                                           stable_id, 'Relationship name'),
                             'shortDescription': _description(
                                 short_description, 'Short description', 500),
                             'detailedDescription': _description(
                                 detailed_description,
                                 'Detailed description', 10000),
                             'parentMemberId': parent,
                             'childMemberId': child},
                            operation_id, command_digest, actor_id,
                            expected_metadata_revision)

    def set_relationship_status(self, scope: ApplicationScope, *,
                                relationship_id: str, status: str,
                                operation_id: str, command_digest: str,
                                actor_id: str,
                                expected_metadata_revision: int) -> MutationReceipt:
        if status not in ('Active', 'Inactive'):
            raise ValueError('RELATIONSHIP_STATUS_INVALID')
        return self._create(scope, 'relationship.status.set', {
            'relationshipId': _name(relationship_id, 'Relationship ID'),
            'status': status}, operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def set_relationship_aggregation_operator(
            self, scope: ApplicationScope, *, relationship_id: str,
            aggregation_operator_override: str | None, operation_id: str,
            command_digest: str, actor_id: str,
            expected_metadata_revision: int) -> MutationReceipt:
        if (aggregation_operator_override is not None and
                aggregation_operator_override not in _AGGREGATION_OPERATORS):
            raise ValueError('RELATIONSHIP_AGGREGATION_OPERATOR_INVALID')
        return self._create(scope, 'relationship.aggregation-operator.set', {
            'relationshipId': _name(relationship_id, 'Relationship ID'),
            'aggregationOperatorOverride': aggregation_operator_override},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def _create(self, scope: ApplicationScope, kind: str, payload: dict,
                operation_id: str, command_digest: str, actor_id: str,
                expected_metadata_revision: int) -> MutationReceipt:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        if (not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 200
                or not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID, actor ID and SHA-256 digest are required')
        if actor_id != self.identity.subject_id:
            raise ValueError('Actor ID must match verified identity')
        if (isinstance(expected_metadata_revision, bool) or
                not isinstance(expected_metadata_revision, int) or
                expected_metadata_revision < 0):
            raise ValueError('Expected metadata revision is required')
        canonical = {'kind': kind, 'payload': payload,
                     'workspaceId': scope.workspace_id,
                     'applicationId': scope.application_id,
                     'actorId': actor_id,
                     'expectedMetadataRevision': expected_metadata_revision}
        payload_digest = sha256(json.dumps(
            canonical, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8')).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT a.status, s.processing_mode,
                    s.metadata_revision, s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id, application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin')
                previous = db.execute('''SELECT command_digest,
                    committed_revision, result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['result'].get('payloadDigest') != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return MutationReceipt(operation_id,
                                           previous['committed_revision'], 1)
                if state['status'] != 'Active' or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != expected_metadata_revision:
                    raise ValueError('STALE_METADATA_REVISION')
                keys = (scope.workspace_id, scope.application_id)
                if kind == 'dimension':
                    retired = db.execute('''SELECT 1 FROM
                        epm.operation_receipt WHERE workspace_id=%s
                        AND application_id=%s
                        AND result->>'kind'='dimension.delete'
                        AND result->>'dimensionId'=%s LIMIT 1''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if retired:
                        raise ValueError('DIMENSION_ID_RETIRED')
                    populated = db.execute('''SELECT 1 FROM epm.coordinate
                        WHERE workspace_id=%s AND application_id=%s
                        LIMIT 1''', keys).fetchone()
                    if populated and payload['modelRole'] != 'Currency':
                        raise ValueError('POPULATED_AXIS_REBUILD_REQUIRED')
                    if (payload['modelRole'] not in (None, 'Custom') and
                            db.execute('''SELECT 1 FROM epm.dimension
                                WHERE workspace_id=%s AND application_id=%s
                                AND model_role=%s AND status='Active'
                                LIMIT 1''',
                                (*keys, payload['modelRole'])).fetchone()):
                        raise ValueError('MODEL_ROLE_ALREADY_ACTIVE')
                    db.execute('''INSERT INTO epm.dimension
                        (workspace_id,application_id,dimension_id,name,
                         model_role,short_description,detailed_description)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                        (*keys, payload['dimensionId'], payload['name'],
                         payload['modelRole'], payload['shortDescription'],
                         payload['detailedDescription']))
                elif kind == 'member':
                    active = db.execute('''SELECT 1 FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND status='Active' ''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if not active:
                        raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                    db.execute('''INSERT INTO epm.member
                        (workspace_id,application_id,dimension_id,member_id,
                         name,short_description,detailed_description)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                        (*keys, payload['dimensionId'], payload['memberId'],
                         payload['name'], payload['shortDescription'],
                         payload['detailedDescription']))
                elif kind == 'dimension.status.set':
                    dimension = db.execute('''SELECT status,model_role
                        FROM epm.dimension WHERE workspace_id=%s
                        AND application_id=%s AND dimension_id=%s''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if dimension is None:
                        raise ValueError('DIMENSION_UNAVAILABLE')
                    if dimension['status'] == payload['status']:
                        raise ValueError('DIMENSION_STATUS_UNCHANGED')
                    if payload['status'] == 'Active':
                        if (dimension['model_role'] not in (None, 'Custom') and
                                db.execute('''SELECT 1 FROM epm.dimension
                                    WHERE workspace_id=%s
                                    AND application_id=%s
                                    AND dimension_id<>%s
                                    AND model_role=%s AND status='Active'
                                    LIMIT 1''',
                                    (*keys, payload['dimensionId'],
                                     dimension['model_role'])).fetchone()):
                            raise ValueError('MODEL_ROLE_ALREADY_ACTIVE')
                    else:
                        if db.execute('''SELECT 1 FROM epm.member
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND status='Active'
                            LIMIT 1''',
                            (*keys, payload['dimensionId'])).fetchone():
                            raise ValueError('DIMENSION_HAS_ACTIVE_MEMBERS')
                        if db.execute('''SELECT 1 FROM epm.coordinate_member
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s LIMIT 1''',
                            (*keys, payload['dimensionId'])).fetchone():
                            raise ValueError('DIMENSION_HAS_COORDINATES')
                        if db.execute('''SELECT 1 FROM epm.relationship
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND status='Active'
                            LIMIT 1''',
                            (*keys, payload['dimensionId'])).fetchone():
                            raise ValueError('DIMENSION_HAS_ACTIVE_RELATIONSHIPS')
                        if db.execute('''SELECT 1 FROM epm.semantic_column
                            WHERE workspace_id=%s AND application_id=%s
                            AND properties->>'referenceDimensionId'=%s
                            LIMIT 1''',
                            (*keys, payload['dimensionId'])).fetchone():
                            raise ValueError('DIMENSION_HAS_SEMANTIC_REFERENCES')
                        settings = db.execute('''SELECT currency_settings
                            FROM epm.application_state WHERE workspace_id=%s
                            AND application_id=%s''', keys).fetchone()[
                                'currency_settings']
                        if (settings is not None and
                                (dimension['model_role'] in {
                                    'Currency','Account','Entity','Value',
                                    'View','ICP'} or payload['dimensionId']
                                 in (settings.get('fromCurrencyDimensionId'),
                                     settings.get('toCurrencyDimensionId')))):
                            raise ValueError('DIMENSION_HAS_CURRENCY_SETTINGS')
                        if db.execute('''SELECT 1 FROM epm.cube_write_scope_lock
                            WHERE workspace_id=%s AND application_id=%s
                            AND status='Locked' AND scope_members ? %s
                            LIMIT 1''',
                            (*keys, payload['dimensionId'])).fetchone():
                            raise ValueError('DIMENSION_HAS_ACTIVE_LOCK')
                        if db.execute('''SELECT 1 FROM epm.source_batch
                            WHERE workspace_id=%s AND application_id=%s
                            AND status IN ('staging','ready')
                            AND scope_members ? %s LIMIT 1''',
                            (*keys, payload['dimensionId'])).fetchone():
                            raise ValueError('DIMENSION_HAS_PENDING_SOURCE')
                    db.execute('''UPDATE epm.dimension SET status=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s''',
                        (payload['status'], *keys, payload['dimensionId']))
                elif kind == 'dimension.delete':
                    target = db.execute('''SELECT status FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if target is None:
                        raise ValueError('DIMENSION_UNAVAILABLE')
                    if target['status'] != 'Inactive':
                        raise ValueError('DIMENSION_MUST_BE_INACTIVE')
                    dimension_id = payload['dimensionId']
                    dependencies = (
                        ('epm.member', 'dimension_id',
                         'DIMENSION_HAS_MEMBERS'),
                        ('epm.relationship', 'dimension_id',
                         'DIMENSION_HAS_RELATIONSHIPS'),
                        ('epm.semantic_column', 'dimension_id',
                         'DIMENSION_HAS_SEMANTIC_COLUMNS'),
                        ('epm.coordinate_member', 'dimension_id',
                         'DIMENSION_HAS_COORDINATES'),
                        ('epm.hierarchy_version', 'dimension_id',
                         'DIMENSION_HAS_HIERARCHY_HISTORY'),
                    )
                    for table, column, error in dependencies:
                        if db.execute(f'''SELECT 1 FROM {table}
                            WHERE workspace_id=%s AND application_id=%s
                            AND {column}=%s LIMIT 1''',
                            (*keys, dimension_id)).fetchone():
                            raise ValueError(error)
                    if db.execute('''SELECT 1 FROM epm.coordinate
                        WHERE workspace_id=%s AND application_id=%s
                        AND members ? %s LIMIT 1''',
                        (*keys, dimension_id)).fetchone():
                        raise ValueError('DIMENSION_HAS_COORDINATES')
                    if db.execute('''SELECT 1 FROM epm.semantic_column
                        WHERE workspace_id=%s AND application_id=%s
                        AND properties->>'referenceDimensionId'=%s
                        LIMIT 1''', (*keys, dimension_id)).fetchone():
                        raise ValueError('DIMENSION_HAS_SEMANTIC_REFERENCES')
                    if db.execute('''SELECT 1 FROM epm.cube_write_scope_lock
                        WHERE workspace_id=%s AND application_id=%s
                        AND scope_members ? %s LIMIT 1''',
                        (*keys, dimension_id)).fetchone():
                        raise ValueError('DIMENSION_HAS_LOCK_HISTORY')
                    if db.execute('''SELECT 1 FROM epm.source_batch
                        WHERE workspace_id=%s AND application_id=%s
                        AND scope_members ? %s LIMIT 1''',
                        (*keys, dimension_id)).fetchone():
                        raise ValueError('DIMENSION_HAS_SOURCE_HISTORY')
                    db.execute('''DELETE FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s''', (*keys, dimension_id))
                elif kind == 'dimension.rename':
                    existing = db.execute('''SELECT name FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND status='Active' ''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if existing is None:
                        raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                    if existing['name'] == payload['name']:
                        raise ValueError('METADATA_NAME_UNCHANGED')
                    collision = db.execute('''SELECT 1 FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id<>%s AND dimension_id=%s
                        LIMIT 1''',
                        (*keys, payload['dimensionId'],
                         payload['name'])).fetchone()
                    if collision:
                        raise ValueError('METADATA_REFERENCE_AMBIGUOUS')
                    db.execute('''UPDATE epm.dimension SET name=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s''',
                        (payload['name'], *keys, payload['dimensionId']))
                elif kind == 'member.rename':
                    existing = db.execute('''SELECT name FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s
                        AND status='Active' ''',
                        (*keys, payload['dimensionId'],
                         payload['memberId'])).fetchone()
                    if existing is None:
                        raise ValueError('ACTIVE_MEMBER_REQUIRED')
                    if existing['name'] == payload['name']:
                        raise ValueError('METADATA_NAME_UNCHANGED')
                    collision = db.execute('''SELECT 1 FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id<>%s
                        AND member_id=%s LIMIT 1''',
                        (*keys, payload['dimensionId'],
                         payload['memberId'], payload['name'])).fetchone()
                    if collision:
                        raise ValueError('METADATA_REFERENCE_AMBIGUOUS')
                    db.execute('''UPDATE epm.member SET name=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s''',
                        (payload['name'], *keys, payload['dimensionId'],
                         payload['memberId']))
                elif kind == 'dimension.describe':
                    existing = db.execute('''SELECT short_description,
                        detailed_description FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND status='Active' ''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if existing is None:
                        raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                    if (existing['short_description'] ==
                            payload['shortDescription'] and
                            existing['detailed_description'] ==
                            payload['detailedDescription']):
                        raise ValueError('METADATA_DESCRIPTION_UNCHANGED')
                    db.execute('''UPDATE epm.dimension SET
                        short_description=%s,detailed_description=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s''',
                        (payload['shortDescription'],
                         payload['detailedDescription'], *keys,
                         payload['dimensionId']))
                elif kind == 'member.describe':
                    existing = db.execute('''SELECT short_description,
                        detailed_description FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s
                        AND status='Active' ''',
                        (*keys, payload['dimensionId'],
                         payload['memberId'])).fetchone()
                    if existing is None:
                        raise ValueError('ACTIVE_MEMBER_REQUIRED')
                    if (existing['short_description'] ==
                            payload['shortDescription'] and
                            existing['detailed_description'] ==
                            payload['detailedDescription']):
                        raise ValueError('METADATA_DESCRIPTION_UNCHANGED')
                    db.execute('''UPDATE epm.member SET
                        short_description=%s,detailed_description=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s''',
                        (payload['shortDescription'],
                         payload['detailedDescription'], *keys,
                         payload['dimensionId'], payload['memberId']))
                elif kind == 'relationship.rename':
                    existing = db.execute('''SELECT name
                        FROM epm.relationship
                        WHERE workspace_id=%s AND application_id=%s
                        AND relationship_id=%s AND status='Active' ''',
                        (*keys, payload['relationshipId'])).fetchone()
                    if existing is None:
                        raise ValueError('ACTIVE_RELATIONSHIP_REQUIRED')
                    if existing['name'] == payload['name']:
                        raise ValueError('METADATA_NAME_UNCHANGED')
                    db.execute('''UPDATE epm.relationship SET name=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND relationship_id=%s''',
                        (payload['name'], *keys,
                         payload['relationshipId']))
                elif kind == 'relationship.describe':
                    existing = db.execute('''SELECT short_description,
                        detailed_description FROM epm.relationship
                        WHERE workspace_id=%s AND application_id=%s
                        AND relationship_id=%s AND status='Active' ''',
                        (*keys, payload['relationshipId'])).fetchone()
                    if existing is None:
                        raise ValueError('ACTIVE_RELATIONSHIP_REQUIRED')
                    if (existing['short_description'] ==
                            payload['shortDescription'] and
                            existing['detailed_description'] ==
                            payload['detailedDescription']):
                        raise ValueError('METADATA_DESCRIPTION_UNCHANGED')
                    db.execute('''UPDATE epm.relationship SET
                        short_description=%s,detailed_description=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND relationship_id=%s''',
                        (payload['shortDescription'],
                         payload['detailedDescription'], *keys,
                         payload['relationshipId']))
                elif kind == 'member.numeric-kind.set':
                    member = db.execute('''SELECT m.numeric_value_kind
                        FROM epm.member m JOIN epm.dimension d
                        USING (workspace_id,application_id,dimension_id)
                        WHERE m.workspace_id=%s AND m.application_id=%s
                        AND m.dimension_id=%s AND m.member_id=%s
                        AND m.status='Active' AND d.status='Active' ''',
                        (*keys, payload['dimensionId'],
                         payload['memberId'])).fetchone()
                    if member is None:
                        raise ValueError('ACTIVE_MEMBER_REQUIRED')
                    if member['numeric_value_kind'] == payload['numericValueKind']:
                        raise ValueError('MEMBER_NUMERIC_KIND_UNCHANGED')
                    db.execute('''UPDATE epm.member SET numeric_value_kind=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s''',
                        (payload['numericValueKind'], *keys,
                         payload['dimensionId'], payload['memberId']))
                elif kind == 'member.aggregation-operator.set':
                    member = db.execute('''SELECT m.aggregation_operator
                        FROM epm.member m JOIN epm.dimension d
                        USING (workspace_id,application_id,dimension_id)
                        WHERE m.workspace_id=%s AND m.application_id=%s
                        AND m.dimension_id=%s AND m.member_id=%s
                        AND m.status='Active' AND d.status='Active' ''',
                        (*keys, payload['dimensionId'],
                         payload['memberId'])).fetchone()
                    if member is None:
                        raise ValueError('ACTIVE_MEMBER_REQUIRED')
                    if (member['aggregation_operator'] ==
                            payload['aggregationOperator']):
                        raise ValueError('MEMBER_AGGREGATION_OPERATOR_UNCHANGED')
                    db.execute('''UPDATE epm.member SET aggregation_operator=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s''',
                        (payload['aggregationOperator'], *keys,
                         payload['dimensionId'], payload['memberId']))
                elif kind in ('member.security-tags.set',
                               'member.security-string.set'):
                    member = db.execute('''SELECT m.read_security_tags,
                        m.write_security_tags FROM epm.member m
                        JOIN epm.dimension d
                        USING (workspace_id,application_id,dimension_id)
                        WHERE m.workspace_id=%s AND m.application_id=%s
                        AND m.dimension_id=%s AND m.member_id=%s
                        AND m.status='Active' AND d.status='Active' ''',
                        (*keys, payload['dimensionId'],
                         payload['memberId'])).fetchone()
                    if member is None:
                        raise ValueError('ACTIVE_MEMBER_REQUIRED')
                    if kind == 'member.security-string.set':
                        tag_rows = db.execute('''SELECT
                                tag_id
                            FROM epm.security_tag
                            WHERE workspace_id=%s AND application_id=%s
                              AND dimension_id=%s AND status='Active'
                            ORDER BY tag_id''',
                            (*keys, payload['dimensionId'])).fetchall()
                        known_tags={row['tag_id'] for row in tag_rows}
                        read_tags, write_tags = _compiled_security_string(
                            payload['securityString'], known_tags)
                    else:
                        read_tags = payload['readTags']
                        write_tags = payload['writeTags']
                    if (member['read_security_tags'] == read_tags
                            and member['write_security_tags'] == write_tags):
                        raise ValueError('MEMBER_SECURITY_TAGS_UNCHANGED')
                    db.execute('''UPDATE epm.member SET
                        read_security_tags=%s,write_security_tags=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s''',
                        (read_tags, write_tags, *keys,
                         payload['dimensionId'], payload['memberId']))
                elif kind == 'dimension.security-string.set':
                    dimension = db.execute('''SELECT read_security_tags,
                            write_security_tags FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND status='Active' ''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if dimension is None:
                        raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                    tag_rows = db.execute('''SELECT tag_id
                        FROM epm.security_tag
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND status='Active'
                        ORDER BY tag_id''',
                        (*keys, payload['dimensionId'])).fetchall()
                    read_tags, write_tags = _compiled_security_string(
                        payload['securityString'],
                        {row['tag_id'] for row in tag_rows})
                    if (dimension['read_security_tags'] == read_tags
                            and dimension['write_security_tags'] == write_tags):
                        raise ValueError('DIMENSION_SECURITY_TAGS_UNCHANGED')
                    db.execute('''UPDATE epm.dimension SET
                        read_security_tags=%s,write_security_tags=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s''',
                        (read_tags, write_tags, *keys,
                         payload['dimensionId']))
                elif kind == 'relationship.security-string.set':
                    relationship = db.execute('''SELECT dimension_id,
                            read_security_tags,write_security_tags
                        FROM epm.relationship
                        WHERE workspace_id=%s AND application_id=%s
                          AND relationship_id=%s AND status='Active' ''',
                        (*keys, payload['relationshipId'])).fetchone()
                    if relationship is None:
                        raise ValueError('ACTIVE_RELATIONSHIP_REQUIRED')
                    tag_rows = db.execute('''SELECT tag_id
                        FROM epm.security_tag
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND status='Active'
                        ORDER BY tag_id''',
                        (*keys, relationship['dimension_id'])).fetchall()
                    read_tags, write_tags = _compiled_security_string(
                        payload['securityString'],
                        {row['tag_id'] for row in tag_rows})
                    if (relationship['read_security_tags'] == read_tags
                            and relationship['write_security_tags'] ==
                            write_tags):
                        raise ValueError('RELATIONSHIP_SECURITY_TAGS_UNCHANGED')
                    db.execute('''UPDATE epm.relationship SET
                        read_security_tags=%s,write_security_tags=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND relationship_id=%s''',
                        (read_tags, write_tags, *keys,
                         payload['relationshipId']))
                elif kind in ('security-tag','security-tag.update',
                               'security-tag.status.set'):
                    dimension=db.execute('''SELECT 1 FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND status='Active' ''',
                        (*keys,payload['dimensionId'])).fetchone()
                    if dimension is None:
                        raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                    existing=db.execute('''SELECT display_name,
                        short_description,semantic_description,status
                        FROM epm.security_tag
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND tag_id=%s''',
                        (*keys,payload['dimensionId'],
                         payload['tagId'])).fetchone()
                    if kind=='security-tag':
                        if existing is not None:
                            raise ValueError('SECURITY_TAG_ALREADY_EXISTS')
                        db.execute('''INSERT INTO epm.security_tag(
                            workspace_id,application_id,dimension_id,tag_id,
                            display_name,short_description,
                            semantic_description)
                            VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                            (*keys,payload['dimensionId'],payload['tagId'],
                             payload['displayName'],
                             payload['shortDescription'],
                             payload['semanticDescription']))
                    elif existing is None:
                        raise ValueError('SECURITY_TAG_UNAVAILABLE')
                    elif kind=='security-tag.update':
                        if (existing['display_name']==payload['displayName']
                                and existing['short_description']==
                                    payload['shortDescription']
                                and existing['semantic_description']==
                                    payload['semanticDescription']):
                            raise ValueError('SECURITY_TAG_UNCHANGED')
                        db.execute('''UPDATE epm.security_tag SET
                            display_name=%s,short_description=%s,
                            semantic_description=%s,
                            updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND dimension_id=%s AND tag_id=%s''',
                            (payload['displayName'],
                             payload['shortDescription'],
                             payload['semanticDescription'],*keys,
                             payload['dimensionId'],payload['tagId']))
                    else:
                        if existing['status']==payload['status']:
                            raise ValueError('SECURITY_TAG_STATUS_UNCHANGED')
                        db.execute('''UPDATE epm.security_tag SET status=%s
                            WHERE workspace_id=%s AND application_id=%s
                              AND dimension_id=%s AND tag_id=%s''',
                            (payload['status'],*keys,payload['dimensionId'],
                             payload['tagId']))
                elif kind == 'member.status.set':
                    member = db.execute('''SELECT status FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s''',
                        (*keys, payload['dimensionId'],
                         payload['memberId'])).fetchone()
                    if member is None:
                        raise ValueError('MEMBER_UNAVAILABLE')
                    if member['status'] == payload['status']:
                        raise ValueError('MEMBER_STATUS_UNCHANGED')
                    if payload['status'] == 'Active':
                        dimension = db.execute('''SELECT 1 FROM epm.dimension
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND status='Active' ''',
                            (*keys, payload['dimensionId'])).fetchone()
                        if dimension is None:
                            raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                        stale_reference = db.execute('''SELECT 1
                            FROM epm.semantic_column c
                            JOIN epm.member source_member
                              ON source_member.workspace_id=c.workspace_id
                             AND source_member.application_id=c.application_id
                             AND source_member.dimension_id=c.dimension_id
                            LEFT JOIN epm.member target_member
                              ON target_member.workspace_id=c.workspace_id
                             AND target_member.application_id=c.application_id
                             AND target_member.dimension_id=
                                 c.properties->>'referenceDimensionId'
                             AND target_member.member_id=
                                 source_member.custom_values->>(
                                     'Custom' || lpad(c.slot::text,2,'0'))
                             AND target_member.status='Active'
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.dimension_id=%s AND c.scope='Member'
                              AND c.properties->>'valueType'='MemberReference'
                              AND source_member.member_id=%s
                              AND source_member.custom_values ? (
                                  'Custom' || lpad(c.slot::text,2,'0'))
                              AND target_member.member_id IS NULL
                              AND (c.properties->>'referenceDimensionId'
                                      IS DISTINCT FROM %s
                                   OR source_member.custom_values->>(
                                      'Custom' || lpad(c.slot::text,2,'0'))
                                      IS DISTINCT FROM %s)
                            LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             payload['memberId'], payload['dimensionId'],
                             payload['memberId'])).fetchone()
                        if stale_reference:
                            raise ValueError('SEMANTIC_REFERENCE_MEMBER_UNAVAILABLE')
                    else:
                        # A status change cannot strand coordinates or live
                        # metadata/business references. Historical hierarchy
                        # closure remains immutable and becomes stale through
                        # the metadata revision below.
                        used = db.execute('''SELECT 1 FROM epm.coordinate_member
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND member_id=%s LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             payload['memberId'])).fetchone()
                        if used:
                            raise ValueError('MEMBER_HAS_COORDINATES')
                        if db.execute('''SELECT 1 FROM epm.cube_write_scope_lock
                            WHERE workspace_id=%s AND application_id=%s
                            AND status='Locked'
                            AND scope_members->>%s=%s LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             payload['memberId'])).fetchone():
                            raise ValueError('MEMBER_HAS_ACTIVE_LOCK')
                        edge = db.execute('''SELECT 1 FROM epm.relationship
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND status='Active'
                            AND (parent_member_id=%s OR child_member_id=%s)
                            LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             payload['memberId'],
                             payload['memberId'])).fetchone()
                        if edge:
                            raise ValueError('MEMBER_HAS_ACTIVE_RELATIONSHIPS')
                        calendar = db.execute('''SELECT 1 FROM
                            epm.calendar_period_current
                            WHERE workspace_id=%s AND application_id=%s
                            AND ((year_dimension_id=%s AND year_member_id=%s)
                              OR (period_dimension_id=%s AND period_member_id=%s))
                            LIMIT 1''',
                            (*keys, payload['dimensionId'], payload['memberId'],
                             payload['dimensionId'],
                             payload['memberId'])).fetchone()
                        if calendar:
                            raise ValueError('MEMBER_HAS_CALENDAR_PERIOD')
                        ownership = db.execute('''SELECT 1 FROM
                            epm.ownership_value_current
                            WHERE workspace_id=%s AND application_id=%s
                            AND present AND
                            ((scenario_dimension_id=%s AND scenario_member_id=%s)
                             OR (year_dimension_id=%s AND year_member_id=%s)
                             OR (period_dimension_id=%s AND period_member_id=%s))
                            LIMIT 1''',
                            (*keys, payload['dimensionId'], payload['memberId'],
                             payload['dimensionId'], payload['memberId'],
                             payload['dimensionId'],
                             payload['memberId'])).fetchone()
                        if ownership:
                            raise ValueError('MEMBER_HAS_OWNERSHIP_VALUE')
                        semantic_reference = db.execute('''SELECT 1
                            FROM epm.semantic_column c JOIN epm.member m
                              ON m.workspace_id=c.workspace_id
                             AND m.application_id=c.application_id
                             AND m.dimension_id=c.dimension_id
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.scope='Member'
                              AND c.properties->>'valueType'='MemberReference'
                              AND c.properties->>'referenceDimensionId'=%s
                              AND m.status='Active'
                              AND m.custom_values->>(
                                  'Custom' || lpad(c.slot::text,2,'0'))=%s
                            LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             payload['memberId'])).fetchone()
                        if semantic_reference:
                            raise ValueError('MEMBER_HAS_SEMANTIC_REFERENCES')
                        relationship_reference = db.execute('''SELECT 1
                            FROM epm.semantic_column c
                            JOIN epm.relationship r
                              ON r.workspace_id=c.workspace_id
                             AND r.application_id=c.application_id
                             AND r.dimension_id=c.dimension_id
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.scope='Relationship'
                              AND c.properties->>'valueType'='MemberReference'
                              AND c.properties->>'referenceDimensionId'=%s
                              AND r.status='Active'
                              AND r.custom_values->>(
                                  'Custom' || lpad(c.slot::text,2,'0'))=%s
                            LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             payload['memberId'])).fetchone()
                        if relationship_reference:
                            raise ValueError('MEMBER_HAS_SEMANTIC_REFERENCES')
                    db.execute('''UPDATE epm.member SET status=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s''',
                        (payload['status'], *keys, payload['dimensionId'],
                         payload['memberId']))
                elif kind == 'relationship':
                    active = db.execute('''SELECT member_id FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND status='Active'
                        AND member_id IN (%s,%s)''',
                        (*keys, payload['dimensionId'],
                         payload['parentMemberId'],
                         payload['childMemberId'])).fetchall()
                    if len(active) != 2:
                        raise ValueError('ACTIVE_MEMBERS_REQUIRED')
                    db.execute('''INSERT INTO epm.relationship
                        (workspace_id,application_id,relationship_id,
                         dimension_id,parent_member_id,child_member_id,name,
                         short_description,detailed_description)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (*keys, payload['relationshipId'],
                         payload['dimensionId'], payload['parentMemberId'],
                         payload['childMemberId'], payload['name'],
                         payload['shortDescription'],
                         payload['detailedDescription']))
                elif kind == 'relationship.status.set':
                    edge = db.execute('''SELECT status,dimension_id,
                        parent_member_id,child_member_id
                        FROM epm.relationship WHERE workspace_id=%s
                        AND application_id=%s AND relationship_id=%s''',
                        (*keys, payload['relationshipId'])).fetchone()
                    if edge is None:
                        raise ValueError('RELATIONSHIP_UNAVAILABLE')
                    if edge['status'] == payload['status']:
                        raise ValueError('RELATIONSHIP_STATUS_UNCHANGED')
                    if payload['status'] == 'Active':
                        dimension = db.execute('''SELECT 1 FROM epm.dimension
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND status='Active' ''',
                            (*keys, edge['dimension_id'])).fetchone()
                        members = db.execute('''SELECT count(*) AS n
                            FROM epm.member WHERE workspace_id=%s
                            AND application_id=%s AND dimension_id=%s
                            AND member_id IN (%s,%s) AND status='Active' ''',
                            (*keys, edge['dimension_id'],
                             edge['parent_member_id'],
                             edge['child_member_id'])).fetchone()['n']
                        if dimension is None or members != 2:
                            raise ValueError('ACTIVE_MEMBERS_REQUIRED')
                        stale_reference = db.execute('''SELECT 1
                            FROM epm.semantic_column c
                            JOIN epm.relationship r
                              ON r.workspace_id=c.workspace_id
                             AND r.application_id=c.application_id
                             AND r.dimension_id=c.dimension_id
                            LEFT JOIN epm.member m
                              ON m.workspace_id=r.workspace_id
                             AND m.application_id=r.application_id
                             AND m.dimension_id=
                                 c.properties->>'referenceDimensionId'
                             AND m.member_id=r.custom_values->>(
                                 'Custom' || lpad(c.slot::text,2,'0'))
                             AND m.status='Active'
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.dimension_id=%s
                              AND c.scope='Relationship'
                              AND c.properties->>'valueType'='MemberReference'
                              AND r.relationship_id=%s
                              AND r.custom_values ? (
                                  'Custom' || lpad(c.slot::text,2,'0'))
                              AND m.member_id IS NULL LIMIT 1''',
                            (*keys, edge['dimension_id'],
                             payload['relationshipId'])).fetchone()
                        if stale_reference:
                            raise ValueError('SEMANTIC_REFERENCE_MEMBER_UNAVAILABLE')
                    else:
                        ownership = db.execute('''SELECT 1 FROM
                            epm.ownership_value_current
                            WHERE workspace_id=%s AND application_id=%s
                            AND relationship_id=%s AND present LIMIT 1''',
                            (*keys, payload['relationshipId'])).fetchone()
                        if ownership:
                            raise ValueError('RELATIONSHIP_HAS_ACTIVE_OWNERSHIP')
                    db.execute('''UPDATE epm.relationship SET status=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND relationship_id=%s''',
                        (payload['status'], *keys,
                         payload['relationshipId']))
                elif kind == 'relationship.aggregation-operator.set':
                    edge = db.execute('''SELECT aggregation_operator_override
                        FROM epm.relationship WHERE workspace_id=%s
                        AND application_id=%s AND relationship_id=%s
                        AND status='Active' ''',
                        (*keys, payload['relationshipId'])).fetchone()
                    if edge is None:
                        raise ValueError('ACTIVE_RELATIONSHIP_REQUIRED')
                    if (edge['aggregation_operator_override'] ==
                            payload['aggregationOperatorOverride']):
                        raise ValueError(
                            'RELATIONSHIP_AGGREGATION_OPERATOR_UNCHANGED')
                    db.execute('''UPDATE epm.relationship SET
                        aggregation_operator_override=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND relationship_id=%s''',
                        (payload['aggregationOperatorOverride'], *keys,
                         payload['relationshipId']))
                else:
                    raise ValueError('UNSUPPORTED_METADATA_MUTATION')
                revision = state['commit_revision'] + 1
                db.execute('''UPDATE epm.application_state SET
                    metadata_revision=metadata_revision+1,
                    security_revision=security_revision+%s,
                    commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (1 if kind in ('member.security-tags.set',
                                   'member.security-string.set',
                                   'dimension.security-string.set',
                                   'relationship.security-string.set') else 0,
                     revision, *keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id, application_id, operation_id,
                     command_digest, actor_id, committed_revision, result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, operation_id, command_digest, actor_id, revision,
                     Jsonb({'kind': kind, 'changedCount': 1,
                            'payloadDigest': payload_digest,
                            **({'dimensionId': payload['dimensionId']}
                               if kind == 'dimension.delete' else {})})))
                return MutationReceipt(operation_id, revision, 1)
