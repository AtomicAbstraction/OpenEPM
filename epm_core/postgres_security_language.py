"""Typed V2 application grant programs backed by the fixed security writer."""
from __future__ import annotations

import re

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_grants import PostgresGrantStore
from .postgres_dimensional_security_policies import (
    PostgresDimensionalSecurityPolicyStore, policy_from_values)
from .postgres_jobs import _canonical_digest


FUNCTION = 'security.application.access.set'
LIST_FUNCTION = 'security.application.access.list'
SUBJECT_LIST_FUNCTION = 'security.application.subject.list'
AUDIT_LIST_FUNCTION = 'security.application.audit.list'
RECEIPT_READ_FUNCTION = 'security.application.receipt.read'
GROUP_FUNCTION = 'security.application.group-access.set'
GROUP_LIST_FUNCTION = 'security.application.group-access.list'
DIMENSION_FUNCTION = 'security.application.dimension-access.set'
DIMENSION_READ_FUNCTION = 'security.application.dimension-access.read'
GROUP_DIMENSION_FUNCTION = 'security.application.group-dimension-access.set'
GROUP_DIMENSION_READ_FUNCTION = 'security.application.group-dimension-access.read'
DIMENSION_TAGS_FUNCTION = 'security.application.dimension-tags.read'
MEMBER_TAGS_READ_FUNCTION = 'security.application.member-tags.read'
DIMENSION_METADATA_TAGS_READ_FUNCTION = (
    'security.application.dimension-metadata-tags.read')
RELATIONSHIP_TAGS_READ_FUNCTION = 'security.application.relationship-tags.read'
DIMENSION_POLICY_SAVE_FUNCTION = 'security.application.dimension-policy.save'
DIMENSION_POLICY_READ_FUNCTION = 'security.application.dimension-policy.read'
DIMENSION_POLICY_ACTIVATE_FUNCTION = 'security.application.dimension-policy.activate'
DIMENSION_POLICY_DEACTIVATE_FUNCTION = 'security.application.dimension-policy.deactivate'
WORKSPACE_FUNCTION = 'security.workspace.access.set'
WORKSPACE_GROUP_FUNCTION = 'security.workspace.group-access.set'
WORKSPACE_GROUP_LIST_FUNCTION = 'security.workspace.group-access.list'
RULE_FUNCTION = 'security.rule.access.set'
RULE_GROUP_FUNCTION = 'security.rule.group-access.set'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_POLICY_KEYS = {
    'acrossDimensions', 'withinDimension', 'untaggedMember',
    'untaggedDenyPrecedence', 'memberTagCardinality', 'hierarchyTags',
    'writeReadRelationship', 'mixedSelection',
    'administratorTreatment', 'factSideAuthority'}


def compile_access_program(program: object) -> tuple[str, str, str | None]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'subjectId', 'action', 'role'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    args = program['arguments']
    subject = args['subjectId']
    action = args['action']
    role = args['role']
    if (not isinstance(subject, str) or not 1 <= len(subject) <= 300
            or subject != subject.strip()
            or any(ord(char) < 32 for char in subject)
            or action not in ('grant', 'revoke')
            or (action == 'grant' and role not in
                ('Reader', 'Editor', 'Administrator'))
            or (action == 'revoke' and role is not None)):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return subject, action, role


def compile_access_list(program: object) -> tuple[str | None, int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != LIST_FUNCTION
            or not isinstance(program.get('arguments'), dict)
            or not set(program['arguments']) <= {'afterSubjectId', 'limit'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    after = program['arguments'].get('afterSubjectId')
    limit = program['arguments'].get('limit', 100)
    if ((after is not None and
         (not isinstance(after, str) or not 1 <= len(after) <= 300
          or after != after.strip() or any(ord(char) < 32 for char in after)))
            or isinstance(limit, bool) or not isinstance(limit, int)
            or not 1 <= limit <= 100):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return after, limit


def compile_subject_list(program: object) -> tuple[str | None, int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != SUBJECT_LIST_FUNCTION
            or not isinstance(program.get('arguments'), dict)
            or not set(program['arguments']) <= {
                'afterSelectionKey', 'limit'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    after = program['arguments'].get('afterSelectionKey')
    limit = program['arguments'].get('limit', 100)
    if ((after is not None and
         (not isinstance(after, str) or not 1 <= len(after) <= 300
          or after != after.strip() or any(ord(char) < 32 for char in after)))
            or isinstance(limit, bool) or not isinstance(limit, int)
            or not 1 <= limit <= 100):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return after, limit


def compile_audit_list(program: object) -> tuple[int | None, int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != AUDIT_LIST_FUNCTION
            or not isinstance(program['arguments'], dict)
            or not set(program['arguments']) <= {'beforeAuditId', 'limit'}):
        raise ValueError('V2_SECURITY_AUDIT_FUNCTION_INVALID')
    before = program['arguments'].get('beforeAuditId')
    limit = program['arguments'].get('limit', 100)
    if ((before is not None and
         (isinstance(before, bool) or not isinstance(before, int) or before < 1))
            or isinstance(limit, bool) or not isinstance(limit, int)
            or not 1 <= limit <= 100):
        raise ValueError('V2_SECURITY_AUDIT_ARGUMENTS_INVALID')
    return before, limit


def compile_receipt_read(program: object) -> str:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != RECEIPT_READ_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'operationId'}):
        raise ValueError('V2_SECURITY_RECEIPT_FUNCTION_INVALID')
    operation_id = program['arguments']['operationId']
    if (not isinstance(operation_id, str)
            or not 1 <= len(operation_id) <= 200
            or operation_id != operation_id.strip()
            or any(ord(char) < 32 for char in operation_id)):
        raise ValueError('V2_SECURITY_RECEIPT_ARGUMENTS_INVALID')
    return operation_id


def _group_id(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 300
            or value != value.strip() or '*' in value
            or any(ord(char) < 32 for char in value)):
        raise ValueError('V2_SECURITY_GROUP_ID_INVALID')
    return value


def compile_group_access_program(
        program: object) -> tuple[str, str, str | None]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != GROUP_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'groupId', 'action', 'role'}):
        raise ValueError('V2_SECURITY_GROUP_FUNCTION_INVALID')
    args = program['arguments']
    group_id = _group_id(args['groupId'])
    action, role = args['action'], args['role']
    if (action not in ('grant', 'revoke')
            or (action == 'grant' and role not in
                ('Reader', 'Editor', 'Administrator'))
            or (action == 'revoke' and role is not None)):
        raise ValueError('V2_SECURITY_GROUP_ARGUMENTS_INVALID')
    return group_id, action, role


def compile_group_access_list(program: object) -> tuple[str | None, int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != GROUP_LIST_FUNCTION
            or not isinstance(program['arguments'], dict)
            or not set(program['arguments']) <= {'afterGroupId', 'limit'}):
        raise ValueError('V2_SECURITY_GROUP_FUNCTION_INVALID')
    after = program['arguments'].get('afterGroupId')
    limit = program['arguments'].get('limit', 100)
    if ((after is not None and _group_id(after) != after)
            or isinstance(limit, bool) or not isinstance(limit, int)
            or not 1 <= limit <= 100):
        raise ValueError('V2_SECURITY_GROUP_ARGUMENTS_INVALID')
    return after, limit


def _tag_map(value: object, label: str) -> dict[str, list[str]]:
    if not isinstance(value, dict) or len(value) > 100:
        raise ValueError(f'{label}_INVALID')
    result: dict[str, list[str]] = {}
    for dimension_id, tags in value.items():
        if (not isinstance(dimension_id, str)
                or not 1 <= len(dimension_id) <= 200
                or dimension_id != dimension_id.strip()
                or not isinstance(tags, list) or not tags or len(tags) > 100
                or any(not isinstance(tag, str)
                       or tag != tag.strip()
                       or not 1 <= len(tag) <= 20
                       or ';' in tag for tag in tags)
                or len(tags) != len(set(tags))):
            raise ValueError(f'{label}_INVALID')
        result[dimension_id] = sorted(tags)
    return {key: result[key] for key in sorted(result)}


def compile_dimension_access_program(
        program: object) -> tuple[str, dict[str, list[str]],
                                  dict[str, list[str]], int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != DIMENSION_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'subjectId', 'readTags',
                                               'writeTags',
                                               'expectedSecurityRevision'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    args = program['arguments']
    subject = args['subjectId']
    revision = args['expectedSecurityRevision']
    if (not isinstance(subject, str) or not 1 <= len(subject) <= 300
            or subject != subject.strip()
            or any(ord(char) < 32 for char in subject)
            or isinstance(revision, bool) or not isinstance(revision, int)
            or revision < 0):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return (subject, _tag_map(args['readTags'], 'READ_TAGS'),
            _tag_map(args['writeTags'], 'WRITE_TAGS'), revision)


def compile_dimension_access_read(program: object) -> str:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != DIMENSION_READ_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'subjectId'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    subject = program['arguments']['subjectId']
    if (not isinstance(subject, str) or not 1 <= len(subject) <= 300
            or subject != subject.strip()
            or any(ord(char) < 32 for char in subject)):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return subject


def compile_group_dimension_access_program(
        program: object) -> tuple[str, dict[str, list[str]],
                                  dict[str, list[str]], int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != GROUP_DIMENSION_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'groupId', 'readTags',
                                               'writeTags',
                                               'expectedSecurityRevision'}):
        raise ValueError('V2_SECURITY_GROUP_FUNCTION_INVALID')
    args = program['arguments']
    revision = args['expectedSecurityRevision']
    if (isinstance(revision, bool) or not isinstance(revision, int)
            or revision < 0):
        raise ValueError('V2_SECURITY_GROUP_ARGUMENTS_INVALID')
    return (_group_id(args['groupId']),
            _tag_map(args['readTags'], 'READ_TAGS'),
            _tag_map(args['writeTags'], 'WRITE_TAGS'), revision)


def compile_group_dimension_access_read(program: object) -> str:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != GROUP_DIMENSION_READ_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'groupId'}):
        raise ValueError('V2_SECURITY_GROUP_FUNCTION_INVALID')
    return _group_id(program['arguments']['groupId'])


def compile_dimension_tags_read(program: object) -> None:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != DIMENSION_TAGS_FUNCTION
            or program['arguments'] != {}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')


def compile_member_tags_read(program: object) -> tuple[str, str]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != MEMBER_TAGS_READ_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'dimensionId', 'memberId'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    dimension_id = program['arguments']['dimensionId']
    member_id = program['arguments']['memberId']
    if any(not isinstance(value, str) or not 1 <= len(value) <= 200
           or value != value.strip() or any(ord(char) < 32 for char in value)
           for value in (dimension_id, member_id)):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return dimension_id, member_id


def compile_dimension_metadata_tags_read(program: object) -> str:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != DIMENSION_METADATA_TAGS_READ_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'dimensionId'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    dimension_id = program['arguments']['dimensionId']
    if (not isinstance(dimension_id, str)
            or not 1 <= len(dimension_id) <= 200
            or dimension_id != dimension_id.strip()
            or any(ord(char) < 32 for char in dimension_id)):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return dimension_id


def compile_relationship_tags_read(program: object) -> str:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != RELATIONSHIP_TAGS_READ_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'relationshipId'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    relationship_id = program['arguments']['relationshipId']
    if (not isinstance(relationship_id, str)
            or not 1 <= len(relationship_id) <= 200
            or relationship_id != relationship_id.strip()
            or any(ord(char) < 32 for char in relationship_id)):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return relationship_id


def compile_dimension_policy_save(program: object):
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != DIMENSION_POLICY_SAVE_FUNCTION
            or not isinstance(program['arguments'], dict)
            or not set(program['arguments']) <= {'expectedStateToken','policy'}
            or 'policy' not in program['arguments']
            or (program['arguments'].get('expectedStateToken') is not None
                and not isinstance(program['arguments']['expectedStateToken'],str))
            or not isinstance(program['arguments']['policy'], dict)
            or set(program['arguments']['policy']) != _POLICY_KEYS):
        raise ValueError('V2_DIMENSIONAL_SECURITY_POLICY_SAVE_INVALID')
    return (program['arguments'].get('expectedStateToken'),
            policy_from_values(program['arguments']['policy']))


def compile_dimension_policy_read(program: object) -> None:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != DIMENSION_POLICY_READ_FUNCTION
            or not isinstance(program['arguments'], dict)
            or program['arguments'] != {}):
        raise ValueError('V2_DIMENSIONAL_SECURITY_POLICY_READ_INVALID')


def compile_dimension_policy_activation(program: object) -> tuple[str, int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != DIMENSION_POLICY_ACTIVATE_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {
                'expectedStateToken', 'expectedSecurityRevision'}):
        raise ValueError('V2_DIMENSIONAL_SECURITY_POLICY_ACTIVATION_INVALID')
    token = program['arguments']['expectedStateToken']
    revision = program['arguments']['expectedSecurityRevision']
    if (not isinstance(token,str)
            or isinstance(revision, bool) or not isinstance(revision, int)
            or revision < 0):
        raise ValueError('V2_DIMENSIONAL_SECURITY_POLICY_ACTIVATION_INVALID')
    return token, revision


def compile_dimension_policy_deactivation(program: object) -> tuple[str,int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != DIMENSION_POLICY_DEACTIVATE_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'expectedStateToken','expectedSecurityRevision'}):
        raise ValueError('V2_DIMENSIONAL_SECURITY_POLICY_DEACTIVATION_INVALID')
    token=program['arguments']['expectedStateToken']
    revision=program['arguments']['expectedSecurityRevision']
    if (not isinstance(token,str) or isinstance(revision,bool)
            or not isinstance(revision,int) or revision<0):
        raise ValueError('V2_DIMENSIONAL_SECURITY_POLICY_DEACTIVATION_INVALID')
    return token,revision


def compile_workspace_access_program(program: object) -> tuple[str, str]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != WORKSPACE_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'subjectId', 'action', 'role'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    args = program['arguments']
    subject, action, role = (args['subjectId'], args['action'], args['role'])
    if (not isinstance(subject, str) or not 1 <= len(subject) <= 300
            or subject != subject.strip()
            or any(ord(char) < 32 for char in subject)
            or action not in ('grant', 'revoke')
            or (action == 'grant' and role != 'Administrator')
            or (action == 'revoke' and role is not None)):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return subject, action


def compile_workspace_group_access_program(
        program: object) -> tuple[str, str]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != WORKSPACE_GROUP_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'groupId', 'action', 'role'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    args = program['arguments']
    action, role = args['action'], args['role']
    if (action not in ('grant', 'revoke')
            or (action == 'grant' and role != 'Administrator')
            or (action == 'revoke' and role is not None)):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return _group_id(args['groupId']), action


def compile_workspace_group_access_list(
        program: object) -> tuple[str | None, int]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != WORKSPACE_GROUP_LIST_FUNCTION
            or not isinstance(program['arguments'], dict)
            or not set(program['arguments']).issubset(
                {'afterGroupId', 'limit'})):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    after = program['arguments'].get('afterGroupId')
    limit = program['arguments'].get('limit', 100)
    if ((after is not None and _group_id(after) != after)
            or isinstance(limit, bool) or not isinstance(limit, int)
            or not 1 <= limit <= 100):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    return after, limit


def compile_rule_access_program(program: object) -> tuple[str, str, dict | None]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != RULE_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) !=
                {'subjectId', 'action', 'permissions'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    args=program['arguments']
    subject,action,permissions=(args['subjectId'],args['action'],
                                args['permissions'])
    if (not isinstance(subject,str) or not 1<=len(subject)<=300
            or subject!=subject.strip()
            or any(ord(char)<32 for char in subject)
            or action not in ('set','revoke')):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    if action=='set':
        if (not isinstance(permissions,dict)
                or set(permissions)!={'design','publish','run'}
                or any(type(value) is not bool
                       for value in permissions.values())
                or not any(permissions.values())):
            raise ValueError('RULE_PERMISSIONS_INVALID')
    elif permissions is not None:
        raise ValueError('RULE_PERMISSIONS_INVALID')
    return subject,action,permissions


def compile_rule_group_access_program(
        program: object) -> tuple[str, str, dict | None]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != RULE_GROUP_FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) !=
                {'groupId', 'action', 'permissions'}):
        raise ValueError('V2_SECURITY_FUNCTION_INVALID')
    args = program['arguments']
    group_id, action, permissions = (
        _group_id(args['groupId']), args['action'], args['permissions'])
    if action not in ('set', 'revoke'):
        raise ValueError('V2_SECURITY_ARGUMENTS_INVALID')
    if action == 'set':
        if (not isinstance(permissions, dict)
                or set(permissions) != {'design', 'publish', 'run'}
                or any(type(value) is not bool
                       for value in permissions.values())
                or not any(permissions.values())):
            raise ValueError('RULE_PERMISSIONS_INVALID')
    elif permissions is not None:
        raise ValueError('RULE_PERMISSIONS_INVALID')
    return group_id, action, permissions


class PostgresSecurityLanguage:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL security DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        self.dsn, self.identity = dsn, identity

    def record_privileged_denial(self, scope: ApplicationScope,
                                 program: object, error_code: str) -> None:
        if (not isinstance(program, dict)
                or not isinstance(program.get('function'), str)):
            raise ValueError('PRIVILEGED_DENIAL_AUDIT_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program,
        })
        PostgresGrantStore(self.dsn).record_privileged_denial(
            scope, actor=self.identity, function=program['function'],
            error_code=error_code, request_digest=digest)

    @staticmethod
    def catalog() -> dict:
        return {'languageVersion': 2, 'functions': {FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'subjectId': 'verified-provider subject ID',
                          'action': 'grant or revoke',
                          'role': 'Reader, Editor, Administrator, or null on revoke'},
            'result': 'scoped grant effect, security receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short'}, LIST_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'afterSubjectId': 'optional subject keyset',
                          'limit': 'optional 1-100'},
            'result': 'bounded application grants with dimensional and rule access',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, SUBJECT_LIST_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {
                'afterSelectionKey': 'optional opaque subject continuation',
                'limit': 'optional 1-100'},
            'result': ('bounded current active directory subjects with '
                       'business display names and opaque selection keys'),
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, AUDIT_LIST_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'beforeAuditId': 'optional descending keyset cursor',
                          'limit': 'optional 1-100'},
            'result': ('bounded immutable application security events with '
                       'safe digests and optional receipt correlation'),
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, RECEIPT_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'operationId': 'exact security audit correlation'},
            'result': ('application-bound committed security receipt with '
                       'allowlisted identifiers, action, time and digests'),
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, DIMENSION_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {
                'subjectId': 'existing application-grant subject ID'},
            'result': 'current scoped role, read/write tag assignments and security revision',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, GROUP_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'groupId': 'stable verified Keycloak group ID',
                          'action': 'grant or revoke',
                          'role': 'Reader, Editor, Administrator, or null on revoke'},
            'result': 'scoped group grant effect, security receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application and group target in the key',
            'workClass': 'short'}, GROUP_LIST_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'afterGroupId': 'optional group keyset',
                          'limit': 'optional 1-100'},
            'result': 'bounded application group grants with dimensional and rule access',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, GROUP_DIMENSION_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'groupId': 'existing application group-grant ID',
                'readTags': 'dimension-ID map of exact read tags',
                'writeTags': 'dimension-ID map of exact write tags',
                'expectedSecurityRevision': 'nonnegative integer'},
            'result': 'scoped group tag assignments, security revision, receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application and group target in the key',
            'workClass': 'short'}, GROUP_DIMENSION_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'groupId': 'existing application group-grant ID'},
            'result': 'current scoped group role, read/write tag assignments and security revision',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, DIMENSION_TAGS_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {},
            'result': 'active dimensions in stable application order with distinct active-member read/write tags and revisions',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, MEMBER_TAGS_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'dimensionId': 'active stable dimension ID',
                          'memberId': 'stable member ID'},
            'result': 'current exact member read/write tags and metadata/security revisions',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, DIMENSION_METADATA_TAGS_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'dimensionId': 'active stable dimension ID'},
            'result': 'current exact dimension-row read/write tags and metadata/security revisions',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, RELATIONSHIP_TAGS_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'relationshipId': 'stable relationship ID'},
            'result': 'current exact relationship-row read/write tags and metadata/security revisions',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, DIMENSION_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'subjectId': 'existing application-grant subject ID',
                'readTags': 'dimension-ID map of exact read tags',
                'writeTags': 'dimension-ID map of exact write tags',
                'expectedSecurityRevision': 'nonnegative integer'},
            'result': 'inert scoped tag assignments, security revision, receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short'}, DIMENSION_POLICY_SAVE_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'expectedStateToken': 'current opaque token when replacing',
                'policy': 'all ten explicit dimensional-security choices'},
            'result': 'saved current policy and fresh state token; no authorization effect',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short'}, DIMENSION_POLICY_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {},
            'result': 'integrity-checked current policy or explicit absent state',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}, DIMENSION_POLICY_ACTIVATE_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'expectedStateToken': 'exact current saved policy token',
                'expectedSecurityRevision': 'current nonnegative revision'},
            'result': ('active supported current policy and fresh token with advanced security '
                       'revision; hierarchy-effective drafts are not activatable'),
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short'}, DIMENSION_POLICY_DEACTIVATE_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'expectedStateToken': 'exact current active policy token',
                'expectedSecurityRevision': 'current nonnegative revision'},
            'result': 'explicit policy deactivation and advanced security revision',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short'}, RULE_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'subjectId': 'verified-provider subject ID',
                          'action': 'set or revoke',
                          'permissions': 'explicit design/publish/run booleans, or null on revoke'},
            'result': 'scoped rule permissions, receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application/rule target in the key',
            'workClass': 'short'}, RULE_GROUP_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'groupId': 'stable verified Keycloak group ID',
                          'action': 'set or revoke',
                          'permissions': 'explicit design/publish/run booleans, or null on revoke'},
            'result': 'scoped group rule permissions, receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application/group target in the key',
            'workClass': 'short'}}}

    @staticmethod
    def workspace_catalog() -> dict:
        return {'languageVersion': 2, 'functions': {WORKSPACE_FUNCTION: {
            'mode': 'atomic_security_write',
            'permission': 'workspace_admin',
            'arguments': {'subjectId': 'verified-provider subject ID',
                          'action': 'grant or revoke',
                          'role': 'Administrator or null on revoke'},
            'result': 'workspace grant, security receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace shared with application and rule grant writes',
            'workClass': 'short'}, WORKSPACE_GROUP_FUNCTION: {
            'mode': 'atomic_security_write',
            'permission': 'workspace_admin',
            'arguments': {'groupId': 'stable verified Keycloak group ID',
                          'action': 'grant or revoke',
                          'role': 'Administrator or null on revoke'},
            'result': 'workspace group grant, security receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace shared with application and rule grant writes',
            'workClass': 'short'}, WORKSPACE_GROUP_LIST_FUNCTION: {
            'mode': 'read', 'permission': 'workspace_admin',
            'arguments': {'afterGroupId': 'optional group keyset',
                          'limit': '1 through 100, default 100'},
            'result': 'bounded workspace group-administrator grants',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}}}

    def execute(self, scope: ApplicationScope, program: object, *,
                idempotency_key: str) -> dict:
        if isinstance(program, dict) and program.get('function') == GROUP_FUNCTION:
            return self.execute_group_access(
                scope, program, idempotency_key=idempotency_key)
        if (isinstance(program, dict)
                and program.get('function') == GROUP_DIMENSION_FUNCTION):
            return self.execute_group_dimension_access(
                scope, program, idempotency_key=idempotency_key)
        if isinstance(program, dict) and program.get('function') == DIMENSION_FUNCTION:
            return self.execute_dimension_access(
                scope, program, idempotency_key=idempotency_key)
        if (isinstance(program, dict)
                and program.get('function') == DIMENSION_POLICY_SAVE_FUNCTION):
            return self.execute_dimension_policy_save(
                scope, program, idempotency_key=idempotency_key)
        if (isinstance(program, dict)
                and program.get('function') in {
                    DIMENSION_POLICY_ACTIVATE_FUNCTION,
                    DIMENSION_POLICY_DEACTIVATE_FUNCTION}):
            return self.execute_dimension_policy_activation(
                scope, program, idempotency_key=idempotency_key)
        subject, action, role = compile_access_program(program)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({'scope': [scope.workspace_id,
                                               scope.application_id],
                                    'actor': [self.identity.issuer,
                                              self.identity.subject_id],
                                    'program': program})
        result = PostgresGrantStore(self.dsn).apply_application_grant(
            scope, actor=self.identity,
            target=VerifiedIdentity(self.identity.issuer, subject),
            action=action, role=role, operation_id=idempotency_key,
            command_digest=digest)
        return {'languageVersion': 2, 'function': FUNCTION, 'result': result}

    def execute_group_access(self, scope: ApplicationScope,
                             program: object, *,
                             idempotency_key: str) -> dict:
        group_id, action, role = compile_group_access_program(program)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        result = PostgresGrantStore(self.dsn).apply_application_group_grant(
            scope, actor=self.identity, group_id=group_id,
            action=action, role=role, operation_id=idempotency_key,
            command_digest=digest)
        return {'languageVersion': 2, 'function': GROUP_FUNCTION,
                'result': result}

    def execute_dimension_access(self, scope: ApplicationScope,
                                 program: object, *,
                                 idempotency_key: str) -> dict:
        subject, read_tags, write_tags, revision = (
            compile_dimension_access_program(program))
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        result = PostgresGrantStore(self.dsn).set_dimension_access(
            scope, actor=self.identity,
            target=VerifiedIdentity(self.identity.issuer, subject),
            read_tags=read_tags, write_tags=write_tags,
            expected_security_revision=revision,
            operation_id=idempotency_key, command_digest=digest)
        return {'languageVersion': 2, 'function': DIMENSION_FUNCTION,
                'result': result}

    def execute_group_dimension_access(
            self, scope: ApplicationScope, program: object, *,
            idempotency_key: str) -> dict:
        group_id, read_tags, write_tags, revision = (
            compile_group_dimension_access_program(program))
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        result = PostgresGrantStore(self.dsn).set_group_dimension_access(
            scope, actor=self.identity, group_id=group_id,
            read_tags=read_tags, write_tags=write_tags,
            expected_security_revision=revision,
            operation_id=idempotency_key, command_digest=digest)
        return {'languageVersion': 2, 'function': GROUP_DIMENSION_FUNCTION,
                'result': result}

    def list_application_access(self, scope: ApplicationScope,
                                program: object) -> dict:
        after, limit = compile_access_list(program)
        result = PostgresGrantStore(self.dsn).list_application_grants(
            scope, actor=self.identity, after_subject_id=after, limit=limit)
        return {'languageVersion': 2, 'function': LIST_FUNCTION,
                'result': result}

    def list_application_audit(self, scope: ApplicationScope,
                               program: object) -> dict:
        before, limit = compile_audit_list(program)
        result = PostgresGrantStore(self.dsn).list_application_security_audit(
            scope, actor=self.identity, before_audit_id=before, limit=limit)
        return {'languageVersion': 2, 'function': AUDIT_LIST_FUNCTION,
                'result': result}

    def list_application_subjects(self, scope: ApplicationScope,
                                  program: object) -> dict:
        after, limit = compile_subject_list(program)
        result = PostgresGrantStore(self.dsn).list_application_subjects(
            scope, actor=self.identity, after_selection_key=after, limit=limit)
        return {'languageVersion': 2, 'function': SUBJECT_LIST_FUNCTION,
                'result': result}

    def read_application_receipt(self, scope: ApplicationScope,
                                 program: object) -> dict:
        operation_id = compile_receipt_read(program)
        result = PostgresGrantStore(self.dsn).read_application_security_receipt(
            scope, actor=self.identity, operation_id=operation_id)
        return {'languageVersion': 2, 'function': RECEIPT_READ_FUNCTION,
                'result': result}

    def list_application_group_access(self, scope: ApplicationScope,
                                      program: object) -> dict:
        after, limit = compile_group_access_list(program)
        result = PostgresGrantStore(self.dsn).list_application_group_grants(
            scope, actor=self.identity, after_group_id=after, limit=limit)
        return {'languageVersion': 2, 'function': GROUP_LIST_FUNCTION,
                'result': result}

    def read_dimension_access(self, scope: ApplicationScope,
                              program: object) -> dict:
        subject = compile_dimension_access_read(program)
        result = PostgresGrantStore(self.dsn).read_dimension_access(
            scope, actor=self.identity,
            target=VerifiedIdentity(self.identity.issuer, subject))
        return {'languageVersion': 2, 'function': DIMENSION_READ_FUNCTION,
                'result': result}

    def read_group_dimension_access(self, scope: ApplicationScope,
                                    program: object) -> dict:
        group_id = compile_group_dimension_access_read(program)
        result = PostgresGrantStore(self.dsn).read_group_dimension_access(
            scope, actor=self.identity, group_id=group_id)
        return {'languageVersion': 2,
                'function': GROUP_DIMENSION_READ_FUNCTION,
                'result': result}

    def read_dimension_tags(self, scope: ApplicationScope,
                            program: object) -> dict:
        compile_dimension_tags_read(program)
        result = PostgresGrantStore(self.dsn).read_dimension_tags(
            scope, actor=self.identity)
        return {'languageVersion': 2, 'function': DIMENSION_TAGS_FUNCTION,
                'result': result}

    def read_member_tags(self, scope: ApplicationScope,
                         program: object) -> dict:
        dimension_id, member_id = compile_member_tags_read(program)
        result = PostgresGrantStore(self.dsn).read_member_security_tags(
            scope, actor=self.identity, dimension_id=dimension_id,
            member_id=member_id)
        return {'languageVersion': 2, 'function': MEMBER_TAGS_READ_FUNCTION,
                'result': result}

    def read_dimension_metadata_tags(self, scope: ApplicationScope,
                                     program: object) -> dict:
        dimension_id = compile_dimension_metadata_tags_read(program)
        result = PostgresGrantStore(self.dsn).read_dimension_security_tags(
            scope, actor=self.identity, dimension_id=dimension_id)
        return {'languageVersion': 2,
                'function': DIMENSION_METADATA_TAGS_READ_FUNCTION,
                'result': result}

    def read_relationship_tags(self, scope: ApplicationScope,
                               program: object) -> dict:
        relationship_id = compile_relationship_tags_read(program)
        result = PostgresGrantStore(self.dsn).read_relationship_security_tags(
            scope, actor=self.identity, relationship_id=relationship_id)
        return {'languageVersion': 2,
                'function': RELATIONSHIP_TAGS_READ_FUNCTION,
                'result': result}

    def execute_dimension_policy_save(
            self, scope: ApplicationScope, program: object, *,
            idempotency_key: str) -> dict:
        expected_token, policy = compile_dimension_policy_save(program)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        result = PostgresDimensionalSecurityPolicyStore(self.dsn).save(
            scope, actor=self.identity, policy=policy,
            expected_state_token=expected_token,
            operation_id=idempotency_key, command_digest=digest)
        return {'languageVersion': 2,
                'function': DIMENSION_POLICY_SAVE_FUNCTION,
                'result': result}

    def execute_dimension_policy_activation(
            self, scope: ApplicationScope, program: object, *,
            idempotency_key: str) -> dict:
        function = program.get('function') if isinstance(program, dict) else None
        if function == DIMENSION_POLICY_ACTIVATE_FUNCTION:
            token, revision = compile_dimension_policy_activation(program)
            active=True
        elif function == DIMENSION_POLICY_DEACTIVATE_FUNCTION:
            token,revision=compile_dimension_policy_deactivation(program)
            active=False
        else:
            raise ValueError('V2_DIMENSIONAL_SECURITY_POLICY_ACTIVATION_INVALID')
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        store = PostgresDimensionalSecurityPolicyStore(self.dsn)
        result = store.set_active(
            scope, actor=self.identity, active=active,
            expected_state_token=token,
            expected_security_revision=revision,
            operation_id=idempotency_key, command_digest=digest)
        return {'languageVersion': 2, 'function': function, 'result': result}

    def read_dimension_policy(self, scope: ApplicationScope,
                              program: object) -> dict:
        function = program.get('function') if isinstance(program, dict) else None
        store = PostgresDimensionalSecurityPolicyStore(self.dsn)
        if function == DIMENSION_POLICY_READ_FUNCTION:
            compile_dimension_policy_read(program)
            result=store.read(scope,actor=self.identity)
        else:
            raise ValueError('V2_DIMENSIONAL_SECURITY_POLICY_READ_INVALID')
        return {'languageVersion': 2, 'function': function, 'result': result}

    def execute_workspace(self, workspace_id: str, program: object, *,
                          idempotency_key: str) -> dict:
        if (isinstance(program, dict)
                and program.get('function') == WORKSPACE_GROUP_FUNCTION):
            return self.execute_workspace_group(
                workspace_id, program, idempotency_key=idempotency_key)
        subject, action = compile_workspace_access_program(program)
        if (not isinstance(workspace_id, str) or not workspace_id
                or not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({'workspaceId': workspace_id,
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        result = PostgresGrantStore(self.dsn).apply_workspace_grant(
            workspace_id, actor=self.identity,
            target=VerifiedIdentity(self.identity.issuer, subject),
            action=action, operation_id=idempotency_key,
            command_digest=digest)
        return {'languageVersion': 2, 'function': WORKSPACE_FUNCTION,
                'result': result}

    def execute_workspace_group(self, workspace_id: str, program: object, *,
                                idempotency_key: str) -> dict:
        group_id, action = compile_workspace_group_access_program(program)
        if (not isinstance(workspace_id, str) or not workspace_id
                or not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({'workspaceId': workspace_id,
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        result = PostgresGrantStore(self.dsn).apply_workspace_group_grant(
            workspace_id, actor=self.identity, group_id=group_id,
            action=action, operation_id=idempotency_key,
            command_digest=digest)
        return {'languageVersion': 2, 'function': WORKSPACE_GROUP_FUNCTION,
                'result': result}

    def list_workspace_group_access(self, workspace_id: str,
                                    program: object) -> dict:
        after, limit = compile_workspace_group_access_list(program)
        result = PostgresGrantStore(self.dsn).list_workspace_group_grants(
            workspace_id, actor=self.identity,
            after_group_id=after, limit=limit)
        return {'languageVersion': 2,
                'function': WORKSPACE_GROUP_LIST_FUNCTION,
                'result': result}

    def execute_rule(self, scope: ApplicationScope, program: object, *,
                     idempotency_key: str) -> dict:
        if (isinstance(program, dict)
                and program.get('function') == RULE_GROUP_FUNCTION):
            return self.execute_rule_group(
                scope, program, idempotency_key=idempotency_key)
        subject,action,permissions=compile_rule_access_program(program)
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest=_canonical_digest({'scope':[scope.workspace_id,
                                           scope.application_id],
            'actor':[self.identity.issuer,self.identity.subject_id],
            'program':program})
        result=PostgresGrantStore(self.dsn).apply_rule_grant(
            scope,actor=self.identity,
            target=VerifiedIdentity(self.identity.issuer,subject),
            action=action,permissions=permissions,
            operation_id=idempotency_key,command_digest=digest)
        return {'languageVersion':2,'function':RULE_FUNCTION,'result':result}

    def execute_rule_group(self, scope: ApplicationScope, program: object, *,
                           idempotency_key: str) -> dict:
        group_id, action, permissions = compile_rule_group_access_program(program)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('SECURITY_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({'scope': [scope.workspace_id,
                                               scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        result = PostgresGrantStore(self.dsn).apply_rule_group_grant(
            scope, actor=self.identity, group_id=group_id,
            action=action, permissions=permissions,
            operation_id=idempotency_key, command_digest=digest)
        return {'languageVersion': 2, 'function': RULE_GROUP_FUNCTION,
                'result': result}
