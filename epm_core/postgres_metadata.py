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
import time
from collections import deque
from contextlib import contextmanager

import psycopg
from psycopg import sql
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import new_state_token,require_state_token
from .dimensional_security_policy import ResolvedMemberSecurity

from .postgres_access import AccessDecision, AccessDenied, PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_scope import (
    metadata_page_token, metadata_reference_read_sql, metadata_relationship_read_sql,
    metadata_visible_attributes_sql, reject_mixed_metadata_reads,
    require_metadata_page_token, resolve_effective_dimensional_scope,
)
from .persistence_contract import ApplicationScope, MutationReceipt
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


def _metadata_calculation_impact(db, application_scope, kind, payload, operation_id, revision):
    """Return impact only for metadata that can change calculation meaning."""
    from .calculation_impact_contract import compile_calculation_impact
    dimension=payload.get('dimensionId')
    scope=([{'dimensionId':dimension,'memberId':payload['memberId']}]
           if dimension is not None and payload.get('memberId') is not None
           else [])
    if kind in {'dimension','dimension.status.set','dimension.delete'}:
        domain,object_type,object_id,reason=(
            'dimension','dimension',dimension,'membership_changed')
    elif kind in {'member','member.status.set'}:
        domain,object_type,object_id,reason=(
            'member','member',f"{dimension}:{payload['memberId']}",
            'membership_changed')
    elif kind == 'member.rename':
        domain,object_type,object_id,reason = (
            'member','member-name',f"{dimension}:{payload['memberId']}",'membership_changed')
    elif kind in {'hierarchy.create', 'hierarchy.members.set', 'hierarchy.status.set'}:
        domain,object_type,object_id,reason = (
            'hierarchy','named-hierarchy',f"{dimension}:{payload['hierarchyId']}",'hierarchy_changed')
        scope = []
    elif kind == 'hierarchy.default.set':
        domain,object_type,object_id,reason = (
            'hierarchy','default-hierarchy',dimension,'hierarchy_changed')
        scope = []
    elif kind=='member.numeric-kind.set':
        domain,object_type,object_id,reason=(
            'member','member',f"{dimension}:{payload['memberId']}",
            'unit_policy_changed')
    elif kind=='member.aggregation-operator.set':
        domain,object_type,object_id,reason=(
            'member','member',f"{dimension}:{payload['memberId']}",
            'hierarchy_changed')
    elif kind in {'relationship','relationship.status.set',
                  'relationship.aggregation-operator.set'}:
        edge = db.execute("""SELECT dimension_id,hierarchy_id FROM epm.relationship
            WHERE workspace_id=%s AND application_id=%s AND relationship_id=%s""",
            (application_scope.workspace_id, application_scope.application_id,
             payload['relationshipId'])).fetchone()
        if edge is None:
            raise ValueError('RELATIONSHIP_UNAVAILABLE')
        domain,object_type,object_id,reason=(
            'hierarchy','named-hierarchy',f"{edge['dimension_id']}:{edge['hierarchy_id']}",
            'hierarchy_changed')
        scope = []
    else:
        return None
    change=('insert' if kind in {'dimension','member','relationship'} else
            'delete' if kind=='dimension.delete' else
            'activate' if payload.get('status')=='Active' else
            'deactivate' if payload.get('status')=='Inactive' else 'update')
    return compile_calculation_impact({
        'format':'openepm-calculation-impact-v1','sourceKind':'metadata',
        'sourceId':operation_id,'causalRevision':revision,
        'effects':[{'domain':domain,'change':change,
            'objectType':object_type,'objectId':object_id,'scope':scope,
            'reason':reason,'oldPresence':(
                'absent' if change=='insert' else 'present'),
            'newPresence':('absent' if change in {'delete','deactivate'}
                           else 'present')}]})
from .postgres_hierarchies import (resolve_hierarchy, graph_members, insert_relationship,
    apply_mutation as apply_hierarchy_mutation, compile_mutation as compile_hierarchy_mutation,
    read as read_named_hierarchy)
from .security_string import MAX_SECURITY_STRING_LENGTH, parse_security_string
from .multidimensional_roles import ACCEPTED_MODEL_ROLES, REQUIRED_PROGRAMMABLE_ROLES


_MODEL_ROLES = ACCEPTED_MODEL_ROLES

_AGGREGATION_OPERATORS = {
    'Add', 'Subtract', 'Ignore', 'NeverAggregate', 'Formula',
}
_MEMBERSHIP_SEMANTICS = {'unique_member', 'placement'}
HIERARCHY_BUILD = 'metadata.hierarchy.build'
HIERARCHY_BUILD_FIELDS = frozenset(('dimensionId', 'expectedMetadataRevision'))
HIERARCHY_BUILD_OPTIONAL_FIELDS = frozenset(('hierarchyId', 'membershipSemantics', 'expectedStateToken'))
_HIERARCHY_BUILD_PATH_LIMIT = 100000
_NUMERIC_VALUE_KINDS = ('amount', 'ratio', None)
_MEMBER_NUMERIC_KIND_SET = 'metadata.member.numeric-kind.set'
_SECURITY_STRING_TARGETS = {
    'metadata.member.security-string.set': ('dimensionId', 'memberId'),
    'metadata.dimension.security-string.set': ('dimensionId',),
    'metadata.relationship.security-string.set': ('relationshipId',),
}
VALUE_EDIT_FIELDS = {
    _MEMBER_NUMERIC_KIND_SET: frozenset((
        'dimensionId', 'memberId', 'numericValueKind', 'expectedMetadataRevision')),
    **{function: frozenset((*targets, 'securityString', 'expectedMetadataRevision'))
       for function, targets in _SECURITY_STRING_TARGETS.items()},
}
VALUE_EDIT_FUNCTIONS = frozenset(VALUE_EDIT_FIELDS)
_SHORT_DESCRIPTION_LIMIT = 500
_DETAILED_DESCRIPTION_LIMIT = 10000
_DIMENSION_TARGET = frozenset(('dimensionId', 'expectedMetadataRevision'))
_MEMBER_TARGET = _DIMENSION_TARGET | {'memberId'}
_RELATIONSHIP_TARGET = frozenset(('relationshipId', 'expectedMetadataRevision'))
_STATUS_VALUES = ('Active', 'Inactive')
_STATUS_TARGETS = {
    'metadata.dimension.status.set': _DIMENSION_TARGET,
    'metadata.member.status.set': _MEMBER_TARGET,
    'metadata.relationship.status.set': _RELATIONSHIP_TARGET,
}
_MEMBER_OPERATOR_SET = 'metadata.member.aggregation-operator.set'
_RELATIONSHIP_OPERATOR_SET = 'metadata.relationship.aggregation-operator.set'
MODEL_STATE_EDIT_FIELDS = {
    **{function: target | {'status'} for function, target in _STATUS_TARGETS.items()},
    _MEMBER_OPERATOR_SET: _MEMBER_TARGET | {'aggregationOperator'},
    _RELATIONSHIP_OPERATOR_SET: _RELATIONSHIP_TARGET | {'aggregationOperatorOverride'},
}
MODEL_STATE_EDIT_FUNCTIONS = frozenset(MODEL_STATE_EDIT_FIELDS)
_SECURITY_TAG_ID_LIMIT = 20
_SECURITY_TAG_SET_LIMIT = 100
_SECURITY_TAG_TARGET = _DIMENSION_TARGET | {'tagId'}
_SECURITY_TAG_TEXT = frozenset(('displayName', 'shortDescription', 'semanticDescription'))
_MEMBER_TAGS_SET = 'metadata.member.security-tags.set'
SECURITY_TAG_EDIT_FIELDS = {
    'metadata.security-tag.create': _SECURITY_TAG_TARGET | _SECURITY_TAG_TEXT,
    'metadata.security-tag.update': _SECURITY_TAG_TARGET | _SECURITY_TAG_TEXT,
    'metadata.security-tag.status.set': _SECURITY_TAG_TARGET | {'status'},
    _MEMBER_TAGS_SET: _MEMBER_TARGET | {'readTags', 'writeTags'},
}
SECURITY_TAG_EDIT_FUNCTIONS = frozenset(SECURITY_TAG_EDIT_FIELDS)
_DESCRIPTION_FIELDS = frozenset(('shortDescription', 'detailedDescription'))
_SCOPED_STRUCTURAL_EDITS = frozenset(('dimension.rename', 'dimension.describe', 'member.rename', 'member.describe'))
_GROUP_MUTATION_PROGRAMS = {
    **{kind: 'metadata.' + kind + '.create' for kind in ('dimension', 'member', 'security-tag')},
    **{kind: 'metadata.' + kind for kind in _SCOPED_STRUCTURAL_EDITS | {
        'security-tag.update', 'dimension.security-string.set', 'member.security-string.set', 'member.security-tags.set'}},
}
STRUCTURE_EDIT_FIELDS = {
    'metadata.dimension.create': _DIMENSION_TARGET | {'name', 'modelRole'},
    'metadata.member.create': _MEMBER_TARGET | {'name'},
    'metadata.dimension.rename': _DIMENSION_TARGET | {'name'},
    'metadata.member.rename': _MEMBER_TARGET | {'name'},
    'metadata.dimension.describe': _DIMENSION_TARGET | _DESCRIPTION_FIELDS,
    'metadata.member.describe': _MEMBER_TARGET | _DESCRIPTION_FIELDS,
    'metadata.relationship.create': _RELATIONSHIP_TARGET | {
        'dimensionId', 'parentMemberId', 'childMemberId'},
    'metadata.relationship.rename': _RELATIONSHIP_TARGET | {'name'},
    'metadata.relationship.describe': _RELATIONSHIP_TARGET | _DESCRIPTION_FIELDS,
}
STRUCTURE_EDIT_OPTIONAL_FIELDS = {
    'metadata.dimension.create': _DESCRIPTION_FIELDS,
    'metadata.member.create': _DESCRIPTION_FIELDS,
    'metadata.relationship.create': _DESCRIPTION_FIELDS | {'name', 'hierarchyId', 'status'},
}
STRUCTURE_EDIT_FUNCTIONS = frozenset(STRUCTURE_EDIT_FIELDS)


def structure_edit_program_contract(function: str) -> dict | None:
    """Expose exact dimension, member and relationship authoring requests."""
    from .metadata_read_contract import obj, read_example

    if function not in STRUCTURE_EDIT_FUNCTIONS:
        return None
    _, target, action = function.split('.')
    title = {'type': 'string', 'minLength': 1, 'pattern': r'\S',
             'description': 'The store trims whitespace, then requires 1–200 characters.'}
    def description(limit):
        return {'type': 'string', 'maxLength': limit,
                'not': {'pattern': r'\u0000'}, 'description': 'Empty text clears the description.'}
    properties = dict.fromkeys(('dimensionId', 'memberId', 'name', 'relationshipId',
                                'parentMemberId', 'childMemberId'), title)
    properties.update({
        'hierarchyId': {'anyOf': [title, {'type': 'null'}],
                        'description': 'Omit or pass null to resolve the default hierarchy.'},
        'status': {'enum': ['Active', 'Inactive'], 'default': 'Active'},
        'expectedMetadataRevision': {'type': 'integer', 'minimum': 0},
        'modelRole': {'enum': [*sorted(_MODEL_ROLES), None]},
        'shortDescription': description(_SHORT_DESCRIPTION_LIMIT),
        'detailedDescription': description(_DETAILED_DESCRIPTION_LIMIT),
    })
    if function == 'metadata.relationship.create':
        properties['name'] = {'anyOf': [title, {'type': 'null'}],
                              'description': 'Omit or pass null to use the relationship ID.'}
    required = STRUCTURE_EDIT_FIELDS[function]
    fields = {name: schema for name, schema in properties.items()
              if name in required | STRUCTURE_EDIT_OPTIONAL_FIELDS.get(function, frozenset())}
    samples = {'dimensionId': 'Location', 'memberId': 'central',
               'name': {'dimension': 'Location', 'member': 'Central', 'relationship': 'Central placement'}[target],
               'modelRole': 'Custom', 'expectedMetadataRevision': 1,
               'shortDescription': 'Operating location',
               'detailedDescription': 'Physical locations used to plan site capacity.'}
    if action == 'rename':
        samples['name'] = {'dimension': 'Operating location', 'member': 'Central site',
                           'relationship': 'Central operating placement'}[target]
    if action == 'describe' and target != 'relationship':
        samples['shortDescription'] = 'Site capacity scope' if target == 'dimension' else ''
        samples['detailedDescription'] = ('Locations used in the capacity plan.' if target == 'dimension'
                                         else 'Central site where staffed capacity is planned.')
    if target == 'relationship':
        samples.update({'relationshipId': 'operating-central', 'parentMemberId': 'operating',
                        'childMemberId': 'central', 'hierarchyId': 'operating-locations', 'status': 'Active',
                        'shortDescription': 'Placement in the operating hierarchy' if action == 'create' else '',
                        'detailedDescription': ('Central participates in the operating locations rollup.'
                                                if action == 'create' else 'Central rolls up under Operating.')})
    example = {name: samples[name] for name in fields}
    binding = ('Use stable IDs in the current application and copy metadataRevision from '
               'application.state.read. Review the exact change before requesting admission.')
    if action == 'create':
        binding += ' Choose a new stable ID.'
        if target == 'member':
            binding += ' Use an existing active dimension.'
    if function == 'metadata.dimension.create':
        detail = ('Custom adds an application-specific axis. The core enforces active role '
                  'cardinality and the populated-layout gate before adding a fact axis.')
    elif function == 'metadata.member.create':
        detail = 'A new member belongs to the selected active dimension. The core owns ID uniqueness.'
    elif function == 'metadata.relationship.create':
        binding += (' Use metadata.hierarchy.list and metadata.member.resolve to bind the hierarchy '
                    'and distinct parent and child members in the same dimension.')
        detail = ('An active link requires an active hierarchy and active endpoints. If the hierarchy ID '
                  'is omitted or null, the store uses the default, establishing it if absent. Read the '
                  'current placement with metadata.relationship.list. Use the governed placement preview '
                  'and apply workflow to move an existing link.')
    elif target == 'relationship':
        binding += ' Use the ID of an active relationship from metadata.relationship.list.'
        detail = ('Rename changes the display name and preserves the hierarchy and endpoints.'
                  if action == 'rename' else
                  'Both description fields are required. Empty text clears the field and leaves placement unchanged.')
    elif action == 'rename':
        detail = 'Rename changes the display name and preserves the stable ID and its references.'
    else:
        detail = 'Both description fields are required. Use an empty string to clear either field.'
    if target in ('dimension','member'):
        detail += (' Group-assigned creation requires an application-wide structure creation duty. New '
                   'records start unclassified. A separately assigned classifier controls their visibility.'
                   if action == 'create' else
                   ' In a group-assigned application one assignment must cover metadata browsing and '
                   'structural editing of both the dimension and the target, using their current read tags.')
    return _metadata_edit_contract(function, obj(fields, [name for name in fields if name in required]),
        examples=[read_example(function, example,
            name=f'{action.title()} a {target} in the current model', binding=binding)], detail=detail)


def _metadata_edit_contract(function, arguments, *, examples, detail):
    from .metadata_read_contract import metadata_mutation_receipt_schema, read_contract

    contract = read_contract(function, arguments, metadata_mutation_receipt_schema(), owner='PostgresMetadataStore',
        examples=examples, semantic_rules=[detail,
            'The fixed core checks current application authority, the metadata revision and the exact '
            'admitted operation. Use application.state.read for current revisions.'])
    contract['programContract']['recovery'] = (
        'If the write outcome is unknown, reconcile the original operation or replay the exact request '
        'with its original operation ID. After a definite stale refusal, read the current metadata '
        'revision and target, review the change and obtain new admission.')
    return contract


def model_state_edit_program_contract(function: str) -> dict | None:
    """Expose existing status and aggregation operations from their validation owner."""
    from .metadata_read_contract import obj, read_example

    if function not in MODEL_STATE_EDIT_FUNCTIONS:
        return None
    identifier = {'type': 'string', 'minLength': 1, 'pattern': r'\S',
                  'description': 'The store trims whitespace, then requires 1–200 characters.'}
    properties = dict.fromkeys(('dimensionId', 'memberId', 'relationshipId'), identifier)
    properties.update({
        'expectedMetadataRevision': {'type': 'integer', 'minimum': 0},
        'status': {'enum': list(_STATUS_VALUES)},
        'aggregationOperator': {'enum': sorted(_AGGREGATION_OPERATORS)},
        'aggregationOperatorOverride': {'enum': [*sorted(_AGGREGATION_OPERATORS), None]},
    })
    fields = {name: schema for name, schema in properties.items()
              if name in MODEL_STATE_EDIT_FIELDS[function]}
    bindings = {'dimensionId': 'Location', 'memberId': 'central',
                'relationshipId': 'operating-central', 'expectedMetadataRevision': 1}
    example = {name: bindings[name] for name in fields if name in bindings}
    target = function.split('.')[1]
    read = f'metadata.{target}.list'
    binding = (f'Use the stable ID returned by {read} and metadataRevision from '
               'application.state.read. Check current dependencies before requesting admission.')
    if function in _STATUS_TARGETS:
        field = 'status'
        actions = [('Inactive', f'Inactivate a {target}'), ('Active', f'Reactivate a {target}')]
        detail = {
            'dimension': ('The core protects required roles and refuses inactivation with active members, '
                          'coordinates or dependent definitions. Use metadata.dimension.list for both statuses.'),
            'member': ('Inactivation refuses coordinates and live references, including active placements. '
                       'Reactivation requires an active dimension. Use metadata.member.list for both statuses.'),
            'relationship': ('Reactivation requires active endpoints. Inactivation refuses present ownership '
                             'assignments. Read the same hierarchy to confirm the relationship status.'),
        }[target]
    elif function == _MEMBER_OPERATOR_SET:
        field = 'aggregationOperator'
        actions = [('Subtract', 'Set a member aggregation operator')]
        detail = ('The member and dimension must be active. This sets the member operator. '
                  'Read the canonical value with metadata.member.list.')
    else:
        field = 'aggregationOperatorOverride'
        actions = [('Ignore', 'Set a placement aggregation override'),
                   (None, 'Clear a placement aggregation override')]
        detail = ('The override belongs to this relationship. Null clears it and restores the inherited '
                  'operator for placement evaluation. Use metadata.relationship.list to read the stored override.')
    return _metadata_edit_contract(function, obj(fields), examples=[
        read_example(function, {**example, field: value}, name=name, binding=binding)
        for value, name in actions], detail=detail)


def security_tag_edit_program_contract(function: str) -> dict | None:
    """Publish the current typed tag catalogue and member assignment contracts."""
    from .metadata_read_contract import obj, read_example

    if function not in SECURITY_TAG_EDIT_FUNCTIONS:
        return None
    identifier = {'type': 'string', 'minLength': 1, 'pattern': r'\S',
                  'description': 'The store trims whitespace, then requires 1–200 characters.'}
    tag_id = {'type': 'string', 'minLength': 1, 'maxLength': _SECURITY_TAG_ID_LIMIT,
              'pattern': r'^[^\s;\u0000](?:[^;\u0000]*[^\s;\u0000])?(?![\s\S])'}
    tag_set = {'type': 'array', 'items': tag_id, 'maxItems': _SECURITY_TAG_SET_LIMIT,
               'uniqueItems': True}
    description = {'type': 'string', 'not': {'pattern': r'\u0000'}}
    fields = {'dimensionId': identifier, 'memberId': identifier, 'tagId': tag_id,
              'displayName': identifier,
              'shortDescription': {**description, 'maxLength': _SHORT_DESCRIPTION_LIMIT},
              'semanticDescription': {**description, 'maxLength': _DETAILED_DESCRIPTION_LIMIT},
              'status': {'enum': list(_STATUS_VALUES)}, 'readTags': tag_set, 'writeTags': tag_set,
              'expectedMetadataRevision': {'type': 'integer', 'minimum': 0}}
    arguments = obj({key: schema for key, schema in fields.items()
                     if key in SECURITY_TAG_EDIT_FIELDS[function]})
    example = {'dimensionId': 'custom-axis', 'expectedMetadataRevision': 1}
    binding = ('Use the stable ID from metadata.dimension.list and metadataRevision from application.state.read. '
               'Read existing tags with metadata.security-tag.list before requesting admission.')
    if function == _MEMBER_TAGS_SET:
        example['memberId'] = 'member-b'
        actions = [('Assign active member tags', {'readTags': ['RouteTag'], 'writeTags': ['RouteTag']}),
                   ('Clear both member tag sets', {'readTags': [], 'writeTags': []})]
        detail = ('Both arrays replace the member’s complete typed tag assignments. All supplied IDs must '
                  'be active tags in this dimension. Effective access depends on the current dimensional policy. '
                  'Read the assignments with security.application.member-tags.read.')
    elif function == 'metadata.security-tag.status.set':
        example['tagId'] = 'RouteTag'
        actions = [('Inactivate an unused tag', {'status': 'Inactive'}),
                   ('Reactivate a tag', {'status': 'Active'})]
        detail = ('Inactivation refuses tags assigned to a dimension, member, relationship, or direct or group grant. '
                  'The existing catalogue row retains its stable ID and descriptions.')
    else:
        example['tagId'] = 'RouteTag'
        if function.endswith('.create'):
            actions = [('Create a security tag', {'displayName': 'Route access',
                'shortDescription': 'Route scope', 'semanticDescription': 'Use for operating route access.'})]
            detail = 'Create chooses a new stable tag ID in the active dimension. The catalogue starts it Active.'
        else:
            actions = [('Update security-tag descriptions', {'displayName': 'Operating route access',
                'shortDescription': '', 'semanticDescription': 'Use for reviewed operating route access.'})]
            detail = 'Update changes the display name and descriptions while preserving the tag ID and status.'
    return _metadata_edit_contract(function, arguments, examples=[
        read_example(function, {**example, **change}, name=name, binding=binding)
        for name, change in actions], detail=detail)


def hierarchy_build_program_contract() -> dict:
    from .metadata_read_contract import obj, read_contract, read_example

    identifier = {'type': 'string', 'minLength': 1, 'pattern': r'\S',
                  'description': 'The store trims whitespace, then requires 1–200 characters.'}
    token = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
    fields = {'dimensionId': identifier, 'expectedMetadataRevision': {'type': 'integer', 'minimum': 0},
        'hierarchyId': {'anyOf': [identifier, {'type': 'null'}]},
        'expectedStateToken': {'anyOf': [token, {'type': 'null'}]},
        'membershipSemantics': {'enum': [*sorted(_MEMBERSHIP_SEMANTICS), None]}}
    result = obj({'operationId': {'type': 'string', 'minLength': 1, 'maxLength': 200},
        'hierarchyId': identifier, 'stateToken': token,
        'closureCount': {'type': 'integer', 'minimum': 0, 'maximum': _HIERARCHY_BUILD_PATH_LIMIT},
        'membershipSemantics': {'enum': sorted(_MEMBERSHIP_SEMANTICS)},
        'committedRevision': {'type': 'integer', 'minimum': 1, 'maximum': 2**63 - 1}})
    example = {'dimensionId': 'Location', 'hierarchyId': 'operating-locations', 'expectedMetadataRevision': 1}
    binding = ('Read the named hierarchy with metadata.hierarchy.read and copy its metadataRevision. '
               'Review its active members and relationships before admission.')
    contract = read_contract(HIERARCHY_BUILD, obj(fields, sorted(HIERARCHY_BUILD_FIELDS)), result,
        owner='PostgresMetadataStore.build_hierarchy', examples=[
            read_example(HIERARCHY_BUILD, example, name='Build an unpublished hierarchy',
                binding=binding + ' The first build has a null stateToken. Omit expectedStateToken.'),
            read_example(HIERARCHY_BUILD, {**example, 'expectedStateToken': '1' * 64},
                name='Rebuild a published hierarchy', binding=binding + ' Copy its current stateToken even when the closure is stale.')],
        semantic_rules=[
            'An omitted or null hierarchyId selects the default. The core establishes the default if absent.',
            'A first build accepts an omitted or null expectedStateToken. Every rebuild requires the current token.',
            'Omitted or null membershipSemantics retains the current setting or uses unique_member for a first build.',
            'Publication atomically rotates the closure token and advances the application commit revision. Read metadata.hierarchy.read for currentness.',
        ])
    contract['programContract']['recovery'] = (
        'Check application.operation.receipt.read with the original operation ID after an interrupted reply. '
        'A matching receipt confirms the historical build. Inspect the current hierarchy separately. '
        'If the receipt is missing, use the exact admitted packet under current effect access. '
        'If the core reports STALE_HIERARCHY_STATE_TOKEN or STALE_METADATA_REVISION, read the current '
        'hierarchy and review a new request. If HIERARCHY_BUILD_REPLAY_RETIRED is returned, use the original receipt.')
    return contract


def value_edit_program_contract(function: str) -> dict | None:
    """Describe the existing numeric-kind and security-string writes and receipts."""
    from .metadata_read_contract import obj, read_example

    if function not in VALUE_EDIT_FUNCTIONS:
        return None
    revision = {'type': 'integer', 'minimum': 0}
    identifier = {'type': 'string', 'minLength': 1,
        'description': 'Use a stable ID. The native store trims whitespace, then requires 1–200 characters.'}
    binding = ('Use stable IDs in the current application and the metadataRevision from '
               'application.state.read. Confirm the exact change before obtaining operation admission.')
    fields = {'expectedMetadataRevision': revision}
    example = {'expectedMetadataRevision': 1}
    if function == _MEMBER_NUMERIC_KIND_SET:
        fields.update({'dimensionId': identifier, 'memberId': identifier,
                       'numericValueKind': {'enum': list(_NUMERIC_VALUE_KINDS)}})
        example.update({'dimensionId': 'custom-axis', 'memberId': 'member-b'})
        examples = [read_example(function, {**example, 'numericValueKind': value},
            name=name, binding=binding) for value, name in (
                ('ratio', 'Mark a member as a ratio'),
                (None, 'Clear the member numeric-kind override'))]
        rule = 'Use metadata.member.resolve to read the current numeric kind.'
    else:
        targets = _SECURITY_STRING_TARGETS[function]
        fields.update(dict.fromkeys(targets, identifier))
        fields['securityString'] = {'type': 'string', 'maxLength': MAX_SECURITY_STRING_LENGTH,
            'description': 'Use read=tag1,tag2;write=tag3 with current tags, or an empty string to clear.'}
        example_ids = {'dimensionId': 'custom-axis', 'memberId': 'member-b',
                       'relationshipId': 'route-edge'}
        example.update({target: example_ids[target] for target in targets})
        object_name = function.split('.')[1]
        tag_binding = (binding + ' For a tagged value, use exact tags listed for the target dimension '
                       'by metadata.security-tag.list.')
        examples = [read_example(function, {**example, 'securityString': 'read=RouteTag;write=RouteTag'},
            name=f'Set the {object_name} security tags', binding=tag_binding)]
        if object_name == 'member':
            examples.append(read_example(function, {**example, 'securityString': ''},
                name='Clear the member security tags', binding=binding))
        rule = ('The fixed core validates the security string against current tags in the target dimension. '
                'Use the authorized tag read for this object type to obtain normalized tags.')
    return _metadata_edit_contract(function, obj(fields), examples=examples, detail=rule)


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
    if (not isinstance(value, list) or len(value) > _SECURITY_TAG_SET_LIMIT
            or any(not isinstance(tag, str)
                   or tag != tag.strip()
                   or not 1 <= len(tag) <= _SECURITY_TAG_ID_LIMIT
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

    def hierarchy_mutation(self, scope, function, arguments, **common):
        kind, payload = compile_hierarchy_mutation(function, arguments)
        return self._create(scope, kind, payload, **common)

    def read_hierarchy(self, scope, function, arguments):
        with self._read_snapshot(scope) as (db, revision, access):
            authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
            return read_named_hierarchy(db, scope, function, arguments, revision,
                authority=authority, identity=self.identity, cursor_secret=self.cursor_secret)

    @contextmanager
    def _read_snapshot(self, scope: ApplicationScope, *, action='metadata.browse'):
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            revision, access = self._begin_read(db, scope, action)
            try:
                yield db, revision, access
            except ValueError:
                # A reference-resolution error also reveals information.
                self._finish_read(db, scope, revision, access, action)
                raise
            self._finish_read(db, scope, revision, access, action)

    def _begin_read(self, db, scope: ApplicationScope, action='metadata.browse') -> tuple[int, AccessDecision]:
        # The security fence requires a fresh READ COMMITTED grant snapshot.
        db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY')
        PostgresNumericFactStore._set_scope(db, scope)
        access = PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, 'read', action=action)
        row = db.execute('''SELECT metadata_revision FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if row is None:
            raise ValueError('APPLICATION_UNAVAILABLE')
        return row['metadata_revision'], access

    def _finish_read(self, db, scope: ApplicationScope, revision: int,
                     access: AccessDecision, action='metadata.browse') -> None:
        row = db.execute('''SELECT metadata_revision FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if row is None or row['metadata_revision'] != revision:
            raise ValueError('METADATA_CHANGED_DURING_READ')
        # Directory membership can change outside the workspace grant fence.
        current_access = PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, 'read', action=action)
        if current_access != access:
            raise ValueError('METADATA_DIRECTORY_READ_AUTHORIZATION_STALE')

    def resolve_dimension(self, scope: ApplicationScope,
                          reference: str) -> dict:
        reference = _name(reference, 'Dimension reference')
        with self._read_snapshot(scope) as (db, _, access):
            authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
            return self._resolve_dimension(db, scope, reference, authority=authority)

    def resolve_member(self, scope: ApplicationScope,
                       dimension_reference: str,
                       member_reference: str) -> dict:
        with self._read_snapshot(scope) as (db, _, access):
            authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
            return self._resolve_member(db, scope, dimension_reference,
                                        member_reference, authority=authority)

    def list_dimensions(self, scope: ApplicationScope, *,
                        limit: int = 100, after_dimension_id: str | None = None,
                        expected_metadata_revision: int | None = None,
                        expected_page_token: str | None = None) -> dict:
        self._validate_page(limit, after_dimension_id,
                            expected_metadata_revision)
        with self._read_snapshot(scope) as (db, revision, access):
            self._check_page_revision(revision, expected_metadata_revision)
            authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
            return self._directory_page(db, scope, authority, revision,
                table='dimension', key='dimension_id', after=after_dimension_id,
                limit=limit, expected_page_token=expected_page_token,
                columns=sql.SQL('m.dimension_id,m.name,m.model_role,m.status,'
                                'm.short_description,m.detailed_description'))

    def list_members(self, scope: ApplicationScope,
                     dimension_reference: str, *, limit: int = 100,
                     after_member_id: str | None = None,
                     expected_metadata_revision: int | None = None,
                     expected_page_token: str | None = None) -> dict:
        self._validate_page(limit, after_member_id,
                            expected_metadata_revision)
        with self._read_snapshot(scope) as (db, revision, access):
            self._check_page_revision(revision, expected_metadata_revision)
            authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
            dimension = self._resolve_dimension(db, scope,
                                                dimension_reference, authority=authority)
            dimension_id = dimension['dimension_id']
            columns = sql.SQL('''m.dimension_id,m.member_id,m.name,m.status,
                m.short_description,m.detailed_description,m.numeric_value_kind,
                m.aggregation_operator,{} AS custom_values''').format(
                    metadata_visible_attributes_sql(authority, 'Member'))
            return {'dimensionId': dimension_id, **self._directory_page(
                db, scope, authority, revision, table='member', key='member_id',
                dimension=dimension_id, after=after_member_id, limit=limit,
                expected_page_token=expected_page_token, columns=columns)}

    def _directory_page(self, db, scope, authority, revision, *, table, key,
                        after, limit, expected_page_token, columns, dimension=None):
        context = [table, scope.workspace_id, scope.application_id,
                   self.identity.issuer, self.identity.subject_id, dimension,
                   limit, revision, authority.scope_digest]
        require_metadata_page_token(authority, self.cursor_secret, context, after, expected_page_token)
        configure_statement_timeout(db, 30_000)
        parameters = (scope.workspace_id, scope.application_id)
        population = sql.SQL('FROM {} m WHERE m.workspace_id=%s AND m.application_id=%s').format(
            sql.Identifier('epm', table))
        if dimension is not None:
            population += sql.SQL(' AND m.dimension_id=%s')
            parameters += (dimension,)
        visible = metadata_reference_read_sql(authority, 'm', dimension)
        if reject_mixed_metadata_reads(authority):
            denied = sql.SQL('SELECT EXISTS(SELECT 1 {} AND NOT {}) AS denied').format(
                population, visible)
            if db.execute(denied, parameters).fetchone()['denied']:
                raise AccessDenied('METADATA_DIRECTORY_SCOPE_UNAVAILABLE')
        # The inner query chooses only visible rows. Resolve projected attributes
        # for that bounded page, including its one continuation sentinel.
        identity_column = sql.Identifier('m', key)
        rows = db.execute(sql.SQL('''SELECT {columns} FROM (
            SELECT m.* {population} AND {visible}
                AND (%s::text IS NULL OR {identity}>%s)
            ORDER BY {identity} LIMIT %s) m ORDER BY {identity}''').format(
                columns=columns, population=population, visible=visible, identity=identity_column),
            (*parameters, after, after, limit + 1)).fetchall()
        page = [dict(row) for row in rows[:limit]]
        has_more = len(rows) > limit
        next_id = page[-1][key] if has_more else None
        anchor_key = 'nextAfterMemberId' if table == 'member' else 'nextAfterDimensionId'
        result = {'rows': page, 'metadataRevision': revision, 'hasMore': has_more,
                  anchor_key: next_id}
        if authority.policy is not None:
            result['nextPageToken'] = metadata_page_token(
                self.cursor_secret, context, next_id) if next_id else None
        return result

    def list_security_tags(self, scope: ApplicationScope,
                           dimension_reference: str, *, limit: int = 100,
                           status: str | None = None,
                           after_tag_id: str | None = None,
                           expected_metadata_revision: int | None = None
                           ) -> dict:
        self._validate_page(limit, after_tag_id, expected_metadata_revision)
        if status not in (None, 'Active', 'Inactive'):
            raise ValueError('SECURITY_TAG_STATUS_INVALID')
        with self._read_snapshot(scope, action='metadata.classify') as (db, revision, access):
            self._check_page_revision(revision, expected_metadata_revision)
            # A classifier can inspect a dimension's tag catalogue before its
            # first classification. This query exposes only that catalogue.
            authority = (None if access.authorization_model == 'group_assignments' else
                         resolve_effective_dimensional_scope(db, self.identity, scope, access=access))
            dimension = self._resolve_dimension(db, scope,
                                                dimension_reference, authority=authority)
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
            page=[dict(row) for row in rows[:limit]]
            return {'dimensionId':dimension['dimension_id'],'rows':page,
                    'metadataRevision':revision,'status':status,
                    'hasMore':len(rows)>limit,
                    'nextAfterTagId':page[-1]['tag_id']
                    if len(rows)>limit else None}

    def list_relationships(self, scope: ApplicationScope,
                           dimension_reference: str | None = None, *,
                           limit: int = 100, status: str | None = None,
                           cursor: str | None = None, hierarchy_id: str | None = None) -> dict:
        """Page current relationship records, not hierarchy-version membership."""
        if cursor is not None:
            if dimension_reference is not None or status is not None or limit != 100 or hierarchy_id is not None:
                raise ValueError('METADATA_RELATIONSHIP_CURSOR_ARGUMENTS_INVALID')
            request = self._unpack_relationship_cursor(cursor, scope)
        else:
            if dimension_reference is None:
                raise ValueError('METADATA_RELATIONSHIP_DIMENSION_REQUIRED')
            self._validate_page(limit, None, None)
            if status not in (None, 'Active', 'Inactive'):
                raise ValueError('METADATA_RELATIONSHIP_STATUS_INVALID')
            request = {'dimensionId': dimension_reference, 'hierarchyId': hierarchy_id, 'status': status,
                       'limit': limit, 'afterRelationshipId': None,
                       'metadataRevision': None}
        with self._read_snapshot(scope) as (db, revision, access):
            self._check_page_revision(revision, request['metadataRevision'])
            authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
            digest = authority.scope_digest if authority.policy is not None else None
            if cursor is not None and (request.get('scopeDigest') != digest
                    or ('expires' in request and request['expires'] <= time.time())):
                raise ValueError('METADATA_DIRECTORY_CURSOR_STALE')
            dimension = self._resolve_dimension(db, scope,
                                                request['dimensionId'], authority=authority)
            dimension_id = dimension['dimension_id']
            if (request['metadataRevision'] is not None and
                    dimension['dimension_id'] != request['dimensionId']):
                raise ValueError('METADATA_RELATIONSHIP_CURSOR_INVALID')
            if request.get('hierarchyId') is not None:
                selected_hierarchy = resolve_hierarchy(db, scope, dimension['dimension_id'],
                    request['hierarchyId'], active=False)['hierarchy_id']
            else:
                selected_hierarchy = db.execute('SELECT epm.default_hierarchy_id(%s,%s,%s) AS id',
                    (scope.workspace_id, scope.application_id, dimension['dimension_id'])).fetchone()['id']
            configure_statement_timeout(db, 30_000)
            population = sql.SQL('''FROM epm.relationship m
                WHERE m.workspace_id=%s AND m.application_id=%s
                  AND m.dimension_id=%s AND m.hierarchy_id=%s
                  AND (%s::text IS NULL OR m.status=%s)''')
            keys = (scope.workspace_id, scope.application_id, dimension_id, selected_hierarchy,
                    request['status'], request['status'])
            visible = metadata_relationship_read_sql(authority, 'm', dimension_id)
            if reject_mixed_metadata_reads(authority) and db.execute(
                sql.SQL('SELECT EXISTS(SELECT 1 {} AND NOT {}) AS denied').format(population, visible),
                keys).fetchone()['denied']:
                raise AccessDenied('METADATA_DIRECTORY_SCOPE_UNAVAILABLE')
            rows = db.execute(sql.SQL('''SELECT relationship_id,dimension_id,hierarchy_id,
                name,short_description,parent_member_id,child_member_id,semantic_tag,
                detailed_description,semantic_description,status,{attributes} AS custom_values,
                aggregation_operator_override FROM (
                SELECT m.* {population} AND {visible}
                    AND (%s::text IS NULL OR m.relationship_id>%s)
                    ORDER BY m.relationship_id LIMIT %s) m ORDER BY m.relationship_id''').format(
                        population=population, visible=visible,
                        attributes=metadata_visible_attributes_sql(authority, 'Relationship')),
                (*keys, request['afterRelationshipId'], request['afterRelationshipId'],
                 request['limit'] + 1)).fetchall()
            page = [dict(row) for row in rows[:request['limit']]]
            has_more = len(rows) > request['limit']
            return {'dimensionId': dimension['dimension_id'], 'hierarchyId': selected_hierarchy, 'rows': page,
                    'metadataRevision': revision,
                    'status': request['status'], 'hasMore': has_more,
                    'nextAfterRelationshipId': page[-1]['relationship_id']
                    if has_more else None,
                    'nextCursor': self._pack_relationship_cursor(scope, {
                        'dimensionId': dimension['dimension_id'], 'hierarchyId': selected_hierarchy,
                        'status': request['status'], 'limit': request['limit'],
                        'afterRelationshipId': page[-1]['relationship_id'],
                        'metadataRevision': revision,
                        **({'scopeDigest': digest, 'expires': int(time.time()) + 900}
                           if digest is not None else {})}) if has_more else None}

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
        guarded = expected | {'hierarchyId', 'scopeDigest', 'expires'}
        if (not isinstance(value, dict) or set(value) not in (expected, expected | {'hierarchyId'}, guarded)
                or value['_scope'] != [scope.workspace_id, scope.application_id]
                or value['_identity'] != [self.identity.issuer,
                                           self.identity.subject_id]
                or value['status'] not in (None, 'Active', 'Inactive')
                or type(value['limit']) is not int
                or not 1 <= value['limit'] <= 500
                or type(value['metadataRevision']) is not int
                or value['metadataRevision'] < 0
                or ('scopeDigest' in value and
                    (not isinstance(value['scopeDigest'], str) or type(value['expires']) is not int))):
            raise ValueError('METADATA_RELATIONSHIP_CURSOR_INVALID')
        try:
            value['dimensionId'] = _name(value['dimensionId'], 'Dimension ID')
            if value.get('hierarchyId') is not None:
                value['hierarchyId'] = _name(value['hierarchyId'], 'Hierarchy ID')
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
                      parent_reference: str, *, limit: int = 500,
                      hierarchy_id: str | None = None) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError('Hierarchy child limit must be 1–500')
        with self._read_snapshot(scope) as (db, _, _access):
            parent = self._resolve_member(db, scope, dimension_reference,
                                          parent_reference)
            hierarchy = resolve_hierarchy(db, scope, parent['dimension_id'], hierarchy_id)
            result = [dict(row) for row in db.execute('''SELECT
                r.relationship_id, m.member_id, m.name
                FROM epm.relationship r JOIN epm.member m
                ON m.workspace_id=r.workspace_id
                AND m.application_id=r.application_id
                AND m.dimension_id=r.dimension_id
                AND m.member_id=r.child_member_id
                WHERE r.workspace_id=%s AND r.application_id=%s
                AND r.dimension_id=%s AND r.parent_member_id=%s AND r.hierarchy_id=%s
                AND r.status='Active' AND m.status='Active'
                ORDER BY lower(m.name), m.member_id LIMIT %s''',
                (scope.workspace_id, scope.application_id,
                 parent['dimension_id'], parent['member_id'], hierarchy['hierarchy_id'], limit)).fetchall()]
            return result

    def build_hierarchy(self, scope: ApplicationScope, *, dimension_id: str,
                        operation_id: str, command_digest: str, actor_id: str,
                        expected_metadata_revision: int,
                        expected_state_token: str | None = None,
                        membership_semantics: str | None = None,
                        hierarchy_id: str | None = None) -> dict:
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
        if expected_state_token is not None:
            require_state_token(expected_state_token,
                error='HIERARCHY_STATE_TOKEN_INVALID')
        if actor_id != self.identity.subject_id:
            raise ValueError('Actor ID must match verified identity')
        payload_digest = sha256(json.dumps({
            'kind': 'hierarchy.build', 'workspaceId': scope.workspace_id,
            'applicationId': scope.application_id, 'dimensionId': dimension_id,
            'actorId': actor_id,
            'expectedMetadataRevision': expected_metadata_revision,
            'expectedStateToken': expected_state_token,
            'requestedMembershipSemantics': membership_semantics,
            **({'hierarchyId': hierarchy_id} if hierarchy_id is not None else {}),
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
                    PostgresNumericFactStore._require_replay_impact(
                        db,scope,operation_id,previous)
                    current = db.execute('''SELECT hierarchy_id,state_token,
                        membership_semantics FROM epm.hierarchy_state
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND operation_id=%s''',
                        (*keys,dimension_id,operation_id)).fetchone()
                    if current is None:
                        raise ValueError('HIERARCHY_BUILD_REPLAY_RETIRED')
                    return {'hierarchyId': previous['result'].get('hierarchyId', 'primary'),
                            'stateToken': current['state_token'],
                            'closureCount': previous['result']['closureCount'],
                            'membershipSemantics': current['membership_semantics'],
                            'committedRevision': previous['committed_revision']}
                if state['status'] != 'Active' or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != expected_metadata_revision:
                    raise ValueError('STALE_METADATA_REVISION')
                dimension = db.execute('''SELECT 1 FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND status='Active' ''',
                    (*keys, dimension_id)).fetchone()
                if dimension is None:
                    raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                hierarchy = resolve_hierarchy(db, scope, dimension_id, hierarchy_id, create_default=True)
                resolved_hierarchy_id = hierarchy['hierarchy_id']
                current_state = db.execute('''SELECT state_token,membership_semantics
                    FROM epm.hierarchy_state WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND hierarchy_id=%s FOR UPDATE''',
                    (*keys, dimension_id, resolved_hierarchy_id)).fetchone()
                if ((current_state is None) != (expected_state_token is None)
                        or current_state is not None
                        and current_state['state_token'] != expected_state_token):
                    raise ValueError('STALE_HIERARCHY_STATE_TOKEN')
                if membership_semantics is None:
                    effective_membership_semantics = (
                        current_state['membership_semantics']
                        if current_state else 'unique_member')
                else:
                    effective_membership_semantics = membership_semantics
                members = graph_members(db, scope, dimension_id, hierarchy)
                if len(members) > 5000:
                    raise ValueError('HIERARCHY_MEMBER_LIMIT')
                edges = db.execute('''SELECT parent_member_id, child_member_id
                    FROM epm.relationship WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND hierarchy_id=%s AND status='Active' ''',
                    (*keys, dimension_id, resolved_hierarchy_id)).fetchall()
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
                        if visits > _HIERARCHY_BUILD_PATH_LIMIT:
                            raise ValueError('HIERARCHY_PATH_LIMIT')
                        key = (ancestor, descendant)
                        old = closure.get(key)
                        closure[key] = (min(old[0], depth), old[1] + 1) if old else (depth, 1)
                        stack.extend((child, depth + 1)
                                     for child in children[descendant])
                state_token = new_state_token()
                revision = state['commit_revision'] + 1
                from .calculation_impact_contract import (
                    compile_calculation_impact)
                hierarchy_impact=compile_calculation_impact({
                    'format':'openepm-calculation-impact-v1',
                    'sourceKind':'hierarchy','sourceId':operation_id,
                    'causalRevision':revision,'effects':[{
                        'domain':'hierarchy','change':'publish',
                        'objectType':'named_hierarchy',
                        'objectId':f'{dimension_id}:{resolved_hierarchy_id}',
                        'scope':[],'reason':'hierarchy_changed',
                        'oldPresence':'unknown','newPresence':'present'}]})
                db.execute('''UPDATE epm.application_state
                    SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision, *keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, operation_id, command_digest, actor_id, revision,
                     Jsonb({'kind': 'hierarchy.build', 'function': HIERARCHY_BUILD,
                            'hierarchyId': resolved_hierarchy_id,
                            'stateToken': state_token,
                            'closureCount': len(closure),
                            'membershipSemantics':
                                effective_membership_semantics,
                            'payloadDigest': payload_digest,
                            'impactDigest': hierarchy_impact.digest})))
                db.execute('''DELETE FROM epm.hierarchy_closure WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s AND hierarchy_id=%s''',
                    (*keys, dimension_id, resolved_hierarchy_id))
                db.execute('''INSERT INTO epm.hierarchy_state(workspace_id,application_id,
                    dimension_id,hierarchy_id,state_token,metadata_revision,
                    membership_semantics,operation_id,built_at)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,transaction_timestamp())
                    ON CONFLICT(workspace_id,application_id,dimension_id,hierarchy_id)
                    DO UPDATE SET state_token=EXCLUDED.state_token,
                      metadata_revision=EXCLUDED.metadata_revision,
                      membership_semantics=EXCLUDED.membership_semantics,
                      operation_id=EXCLUDED.operation_id,built_at=EXCLUDED.built_at''',
                    (*keys,dimension_id,resolved_hierarchy_id,state_token,
                     expected_metadata_revision,effective_membership_semantics,operation_id))
                with db.cursor() as cursor:
                    cursor.executemany('''INSERT INTO epm.hierarchy_closure
                        (workspace_id,application_id,dimension_id,hierarchy_id,state_token,
                         ancestor_member_id,descendant_member_id,
                         min_depth,path_count)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        [(*keys, dimension_id,resolved_hierarchy_id,state_token, ancestor, descendant,
                          depth, count)
                         for (ancestor, descendant), (depth, count)
                         in closure.items()])
                from .postgres_calculation_impact import (
                    record_calculation_impact)
                record_calculation_impact(db,scope,
                    operation_id=operation_id,impact=hierarchy_impact)
                return {'hierarchyId': resolved_hierarchy_id, 'stateToken': state_token, 'closureCount': len(closure),
                        'membershipSemantics': effective_membership_semantics,
                        'committedRevision': revision}

    def descendants(self, scope: ApplicationScope, *, dimension_id: str,
                    ancestor_member_id: str, state_token: str | None = None,
                    limit: int = 500, hierarchy_id: str | None = None) -> dict:
        dimension_id = _name(dimension_id, 'Dimension ID')
        ancestor_member_id = _name(ancestor_member_id, 'Ancestor member ID')
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError('Descendant limit must be 1–500')
        if state_token is not None:
            require_state_token(state_token,error='HIERARCHY_STATE_TOKEN_INVALID')
        with self._read_snapshot(scope) as (db, read_revision, _):
            keys = (scope.workspace_id, scope.application_id, dimension_id)
            hierarchy = resolve_hierarchy(db, scope, dimension_id, hierarchy_id)
            build = db.execute('''SELECT state_token,metadata_revision
                FROM epm.hierarchy_state WHERE workspace_id=%s
                AND application_id=%s AND dimension_id=%s AND hierarchy_id=%s''',
                (*keys,hierarchy['hierarchy_id'])).fetchone()
            if build is None:
                raise ValueError('HIERARCHY_NOT_BUILT')
            if state_token is not None and state_token != build['state_token']:
                raise ValueError('STALE_HIERARCHY_STATE_TOKEN')
            if read_revision != build['metadata_revision']:
                raise ValueError('HIERARCHY_STALE')
            rows = db.execute('''SELECT descendant_member_id, min_depth,
                path_count FROM epm.hierarchy_closure
                WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND hierarchy_id=%s AND state_token=%s
                AND ancestor_member_id=%s
                ORDER BY min_depth, descendant_member_id LIMIT %s''',
                (*keys,hierarchy['hierarchy_id'],build['state_token'],ancestor_member_id,limit)).fetchall()
            return {'hierarchyId': hierarchy['hierarchy_id'], 'stateToken': build['state_token'],
                    'metadataRevision': build['metadata_revision'],
                    'members': [dict(row) for row in rows]}

    @staticmethod
    def _resolve_dimension(db, scope: ApplicationScope, reference: str, *, authority=None) -> dict:
        reference = _name(reference, 'Dimension reference')
        query = '''SELECT dimension_id, name, model_role, status,
            short_description, detailed_description
            FROM epm.dimension m WHERE workspace_id=%s AND application_id=%s
            AND status='Active'
            AND (dimension_id=%s OR lower(name)=lower(%s))'''
        if authority is not None:
            query = sql.SQL(query + ' AND {}').format(metadata_reference_read_sql(authority, 'm'))
        rows = db.execute(query,
            (scope.workspace_id, scope.application_id,
             reference, reference)).fetchall()
        rows = [row for row in rows if row['dimension_id'] == reference] or rows
        if len(rows) != 1:
            raise ValueError('UNKNOWN_OR_AMBIGUOUS_DIMENSION')
        return dict(rows[0])

    @classmethod
    def _resolve_member(cls, db, scope: ApplicationScope,
                        dimension_reference: str,
                        member_reference: str, *, authority=None) -> dict:
        dimension = cls._resolve_dimension(db, scope, dimension_reference, authority=authority)
        reference = _name(member_reference, 'Member reference')
        query = '''SELECT dimension_id, member_id, name, status,
            short_description, detailed_description, numeric_value_kind
            FROM epm.member m WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND status='Active'
            AND (member_id=%s OR lower(name)=lower(%s))'''
        if authority is not None:
            query = sql.SQL(query + ' AND {}').format(
                metadata_reference_read_sql(authority, 'm', dimension['dimension_id']))
        rows = db.execute(query,
            (scope.workspace_id, scope.application_id,
             dimension['dimension_id'], reference, reference)).fetchall()
        rows = [row for row in rows if row['member_id'] == reference] or rows
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
                                 short_description, 'Short description', _SHORT_DESCRIPTION_LIMIT),
                             'detailedDescription': _description(
                                 detailed_description, 'Detailed description',
                                 _DETAILED_DESCRIPTION_LIMIT)}, operation_id,
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
                                 short_description, 'Short description', _SHORT_DESCRIPTION_LIMIT),
                             'detailedDescription': _description(
                                 detailed_description, 'Detailed description',
                                 _DETAILED_DESCRIPTION_LIMIT)},
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
                short_description, 'Short description', _SHORT_DESCRIPTION_LIMIT),
            'detailedDescription': _description(
                detailed_description, 'Detailed description', _DETAILED_DESCRIPTION_LIMIT)},
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
                short_description, 'Short description', _SHORT_DESCRIPTION_LIMIT),
            'detailedDescription': _description(
                detailed_description, 'Detailed description', _DETAILED_DESCRIPTION_LIMIT)},
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
                short_description, 'Short description', _SHORT_DESCRIPTION_LIMIT),
            'detailedDescription': _description(
                detailed_description, 'Detailed description', _DETAILED_DESCRIPTION_LIMIT)},
            operation_id, command_digest, actor_id,
            expected_metadata_revision)

    def set_member_status(self, scope: ApplicationScope, *,
                          dimension_id: str, member_id: str, status: str,
                          operation_id: str, command_digest: str,
                          actor_id: str,
                          expected_metadata_revision: int) -> MutationReceipt:
        if status not in _STATUS_VALUES:
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
                short_description,'Short description',_SHORT_DESCRIPTION_LIMIT),
            'semanticDescription':_description(
                semantic_description,'Semantic description',_DETAILED_DESCRIPTION_LIMIT)},
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
                short_description,'Short description',_SHORT_DESCRIPTION_LIMIT),
            'semanticDescription':_description(
                semantic_description,'Semantic description',_DETAILED_DESCRIPTION_LIMIT)},
            operation_id,command_digest,actor_id,expected_metadata_revision)

    def set_security_tag_status(self, scope: ApplicationScope, *,
                                dimension_id: str, tag_id: str, status: str,
                                operation_id: str, command_digest: str,
                                actor_id: str,
                                expected_metadata_revision: int
                                ) -> MutationReceipt:
        if status not in _STATUS_VALUES:
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
        if status not in _STATUS_VALUES:
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
        if numeric_value_kind not in _NUMERIC_VALUE_KINDS:
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
                     hierarchy_id: str | None = None, status: str = 'Active',
                     short_description: str = '',
                     detailed_description: str = '', operation_id: str,
                     command_digest: str, actor_id: str,
                     expected_metadata_revision: int) -> MutationReceipt:
        parent = _name(parent_member_id, 'Parent member ID')
        child = _name(child_member_id, 'Child member ID')
        if parent == child:
            raise ValueError('A member cannot be its own parent')
        stable_id = _name(relationship_id, 'Relationship ID')
        if status not in ('Active', 'Inactive'):
            raise ValueError('RELATIONSHIP_STATUS_INVALID')
        if hierarchy_id is not None:
            hierarchy_id = _name(hierarchy_id, 'Hierarchy ID')
        return self._create(scope, 'relationship',
                            {'dimensionId': _name(dimension_id, 'Dimension ID'),
                             'relationshipId': stable_id,
                             'name': _name(name if name is not None else
                                           stable_id, 'Relationship name'),
                             'shortDescription': _description(
                                 short_description, 'Short description', _SHORT_DESCRIPTION_LIMIT),
                             'detailedDescription': _description(
                                 detailed_description,
                                 'Detailed description', _DETAILED_DESCRIPTION_LIMIT),
                             'parentMemberId': parent,
                             'childMemberId': child,
                             **({'hierarchyId': hierarchy_id} if hierarchy_id is not None else {}),
                             **({'status': status} if status != 'Active' else {})},
                            operation_id, command_digest, actor_id,
                            expected_metadata_revision)

    def set_relationship_status(self, scope: ApplicationScope, *,
                                relationship_id: str, status: str,
                                operation_id: str, command_digest: str,
                                actor_id: str,
                                expected_metadata_revision: int) -> MutationReceipt:
        if status not in _STATUS_VALUES:
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

    def _require_structural_target(self, db, scope, access, payload):
        keys = (scope.workspace_id, scope.application_id, payload['dimensionId'])
        targets = db.execute("""SELECT dimension_id AS id,read_security_tags AS tags
            FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND status='Active'""", keys).fetchall()
        if 'memberId' in payload:
            targets += db.execute("""SELECT member_id AS id,read_security_tags AS tags
                FROM epm.member WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND member_id=%s AND status='Active'""",
                (*keys, payload['memberId'])).fetchall()
        if len(targets) == (2 if 'memberId' in payload else 1):
            authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
            references = [ResolvedMemberSecurity(payload['dimensionId'], row['id'],
                          tuple(sorted(row['tags'])), ()) for row in targets]
            if authority.privileges.permits_structure_edit(references, authority.policy):
                return
        raise AccessDenied('METADATA_STRUCTURAL_TARGET_UNAVAILABLE')

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
                # Membership and grants are fenced before locking application state.
                PostgresAccessChecker.lock_directory_membership_for_assignment(db)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=_GROUP_MUTATION_PROGRAMS.get(kind))
                state = db.execute('''SELECT a.status, a.kind AS application_kind, s.processing_mode,
                    s.metadata_revision, s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id, application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if access.authorization_model == 'group_assignments' and kind in _SCOPED_STRUCTURAL_EDITS:
                    self._require_structural_target(db, scope, access, payload)
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
                    PostgresNumericFactStore._require_replay_impact(
                        db,scope,operation_id,previous)
                    return MutationReceipt(operation_id,
                                           previous['committed_revision'], 1)
                if state['status'] != 'Active' or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != expected_metadata_revision:
                    raise ValueError('STALE_METADATA_REVISION')
                keys = (scope.workspace_id, scope.application_id)
                if kind.startswith('hierarchy.'):
                    apply_hierarchy_mutation(db, scope, kind, payload)
                elif kind == 'dimension':
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
                        if (state['application_kind'] == 'multidimensional' and
                                dimension['model_role'] in REQUIRED_PROGRAMMABLE_ROLES):
                            raise ValueError('PROGRAMMABLE_REQUIRED_DIMENSION')
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
                        if db.execute('''SELECT 1 FROM epm.attribute_definition
                            WHERE workspace_id=%s AND application_id=%s
                            AND status='Active'
                            AND value_type='MemberReference'
                            AND validation_constraints->>'referenceDimensionId'=%s
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
                    target = db.execute('''SELECT status,model_role FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if target is None:
                        raise ValueError('DIMENSION_UNAVAILABLE')
                    if (state['application_kind'] == 'multidimensional' and
                            target['model_role'] in REQUIRED_PROGRAMMABLE_ROLES):
                        raise ValueError('PROGRAMMABLE_REQUIRED_DIMENSION')
                    if target['status'] != 'Inactive':
                        raise ValueError('DIMENSION_MUST_BE_INACTIVE')
                    dimension_id = payload['dimensionId']
                    dependencies = (
                        ('epm.member', 'dimension_id',
                         'DIMENSION_HAS_MEMBERS'),
                        ('epm.relationship', 'dimension_id',
                         'DIMENSION_HAS_RELATIONSHIPS'),
                        ('epm.coordinate_member', 'dimension_id',
                         'DIMENSION_HAS_COORDINATES'),
                        ('epm.hierarchy_state', 'dimension_id',
                         'DIMENSION_HAS_CURRENT_HIERARCHY'),
                        ('epm.hierarchy_definition', 'dimension_id',
                         'DIMENSION_HAS_HIERARCHIES'),
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
                    if db.execute('''SELECT 1 FROM epm.attribute_definition
                        WHERE workspace_id=%s AND application_id=%s
                        AND status='Active'
                        AND value_type='MemberReference'
                        AND validation_constraints->>'referenceDimensionId'=%s
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
                    try:
                        db.execute('''DELETE FROM epm.dimension
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s''', (*keys, dimension_id))
                    except psycopg.errors.CheckViolation as error:
                        if error.diag.constraint_name == 'dimension_owned_attribute_definitions':
                            raise ValueError('DIMENSION_HAS_ATTRIBUTE_DEFINITIONS') from error
                        raise
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
                    try:
                        db.execute('''UPDATE epm.member SET
                            read_security_tags=%s,write_security_tags=%s,
                            updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND dimension_id=%s AND member_id=%s''',
                            (read_tags, write_tags, *keys,
                             payload['dimensionId'], payload['memberId']))
                    except psycopg.errors.RaiseException as error:
                        if error.diag.message_primary != 'SECURITY_TAG_NOT_CATALOGUED':
                            raise
                        raise ValueError('SECURITY_TAG_NOT_CATALOGUED') from None
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
                        try:
                            db.execute('''UPDATE epm.security_tag SET status=%s
                                WHERE workspace_id=%s AND application_id=%s
                                  AND dimension_id=%s AND tag_id=%s''',
                                (payload['status'],*keys,payload['dimensionId'],
                                 payload['tagId']))
                        except psycopg.errors.RaiseException as error:
                            if error.diag.message_primary != 'SECURITY_TAG_IN_USE':
                                raise
                            raise ValueError('SECURITY_TAG_IN_USE') from None
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
                            FROM epm.attribute_definition c
                            JOIN epm.member source_member
                              ON source_member.workspace_id=c.workspace_id
                             AND source_member.application_id=c.application_id
                             AND source_member.dimension_id=c.dimension_id
                            LEFT JOIN epm.member target_member
                              ON target_member.workspace_id=c.workspace_id
                             AND target_member.application_id=c.application_id
                             AND target_member.dimension_id=
                                 c.validation_constraints->>'referenceDimensionId'
                             AND target_member.member_id=
                                 source_member.custom_values->>c.attribute_id
                             AND target_member.status='Active'
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.dimension_id=%s AND c.scope='Member'
                              AND c.status='Active'
                              AND c.value_type='MemberReference'
                              AND source_member.member_id=%s
                              AND source_member.custom_values ? c.attribute_id
                              AND target_member.member_id IS NULL
                              AND (c.validation_constraints->>'referenceDimensionId'
                                      IS DISTINCT FROM %s
                                   OR source_member.custom_values->>c.attribute_id
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
                            FROM epm.attribute_definition c JOIN epm.member m
                              ON m.workspace_id=c.workspace_id
                             AND m.application_id=c.application_id
                             AND m.dimension_id=c.dimension_id
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.scope='Member'
                              AND c.status='Active'
                              AND c.value_type='MemberReference'
                              AND c.validation_constraints->>'referenceDimensionId'=%s
                              AND m.status='Active'
                              AND m.custom_values->>c.attribute_id=%s
                            LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             payload['memberId'])).fetchone()
                        if semantic_reference:
                            raise ValueError('MEMBER_HAS_SEMANTIC_REFERENCES')
                        relationship_reference = db.execute('''SELECT 1
                            FROM epm.attribute_definition c
                            JOIN epm.relationship r
                              ON r.workspace_id=c.workspace_id
                             AND r.application_id=c.application_id
                             AND r.dimension_id=c.dimension_id
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.scope='Relationship'
                              AND c.status='Active'
                              AND c.value_type='MemberReference'
                              AND c.validation_constraints->>'referenceDimensionId'=%s
                              AND r.status='Active'
                              AND r.custom_values->>c.attribute_id=%s
                            LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             payload['memberId'])).fetchone()
                        if relationship_reference:
                            raise ValueError('MEMBER_HAS_SEMANTIC_REFERENCES')
                        saved_view_blockers=[]
                        from .postgres_selection_preview import (
                            selection_semantic_references_in_transaction)
                        for saved_view in db.execute('''SELECT grid_id,definition
                            FROM epm.saved_grid_definition
                            WHERE workspace_id=%s AND application_id=%s
                            ORDER BY grid_id''',keys).fetchall():
                            try:
                                references=selection_semantic_references_in_transaction(
                                    db,scope,saved_view['definition']['selection'])
                            except (TypeError,ValueError) as error:
                                raise ValueError(
                                    'SAVED_GRID_REFERENCE_INTEGRITY_INVALID') from error
                            if (payload['dimensionId'],'member',
                                    payload['memberId']) in references:
                                saved_view_blockers.append({
                                    'kind':'saved-view','id':saved_view['grid_id']})
                        if saved_view_blockers:
                            from .postgres_definition_lifecycle import (
                                DefinitionReferenceBlocked)
                            raise DefinitionReferenceBlocked(saved_view_blockers)
                    db.execute('''UPDATE epm.member SET status=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s''',
                        (payload['status'], *keys, payload['dimensionId'],
                         payload['memberId']))
                elif kind == 'relationship':
                    hierarchy = resolve_hierarchy(db, scope, payload['dimensionId'],
                        payload.get('hierarchyId'), create_default=True,
                        active=payload.get('status', 'Active') == 'Active')
                    active = db.execute('''SELECT member_id FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND (%s='Inactive' OR status='Active')
                        AND member_id IN (%s,%s)''',
                        (*keys, payload['dimensionId'], payload.get('status', 'Active'),
                         payload['parentMemberId'],
                         payload['childMemberId'])).fetchall()
                    if len(active) != 2:
                        raise ValueError('ACTIVE_MEMBERS_REQUIRED')
                    insert_relationship(db, scope, dimension_id=payload['dimensionId'],
                        hierarchy_id=hierarchy['hierarchy_id'], relationship_id=payload['relationshipId'],
                        parent_member_id=payload['parentMemberId'], child_member_id=payload['childMemberId'],
                        name=payload['name'], short_description=payload['shortDescription'],
                        detailed_description=payload['detailedDescription'], status=payload.get('status', 'Active'))
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
                            FROM epm.attribute_definition c
                            JOIN epm.relationship r
                              ON r.workspace_id=c.workspace_id
                             AND r.application_id=c.application_id
                             AND r.dimension_id=c.dimension_id
                            LEFT JOIN epm.member m
                              ON m.workspace_id=r.workspace_id
                             AND m.application_id=r.application_id
                             AND m.dimension_id=
                                 c.validation_constraints->>'referenceDimensionId'
                             AND m.member_id=r.custom_values->>c.attribute_id
                             AND m.status='Active'
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.dimension_id=%s
                              AND c.scope='Relationship'
                              AND c.status='Active'
                              AND c.value_type='MemberReference'
                              AND r.relationship_id=%s
                              AND r.custom_values ? c.attribute_id
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
                        AND application_id=%s AND relationship_id=%s ''',
                        (*keys, payload['relationshipId'])).fetchone()
                    if edge is None:
                        raise ValueError('RELATIONSHIP_UNAVAILABLE')
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
                impact=_metadata_calculation_impact(
                    db,scope,kind,payload,operation_id,revision)
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
                            **({'impactDigest':impact.digest}
                               if impact is not None else {}),
                            **({'dimensionId': payload['dimensionId']}
                               if kind == 'dimension.delete' else {})})))
                if impact is not None:
                    from .postgres_calculation_impact import (
                        record_calculation_impact)
                    record_calculation_impact(db,scope,
                        operation_id=operation_id,impact=impact)
                return MutationReceipt(operation_id, revision, 1)
