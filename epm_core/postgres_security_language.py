"""Typed V2 application grant programs backed by the fixed security writer."""
from __future__ import annotations

import re

from .application_authorization_actions import DIMENSION_METADATA_TAGS_READ_FUNCTION, MEMBER_TAGS_READ_FUNCTION
from . import application_authorization_config, postgres_authorization_objects, postgres_access_explanation, postgres_authorization_tags, postgres_effective_access
from . import application_authorization_migration as auth_migration
from . import postgres_resource_access
from . import postgres_workspace_access_review as workspace_review
from .persistence_contract import ApplicationScope
from .postgres_access import SECURITY_READ_AUTHORIZATION_STALE, VerifiedIdentity
from .postgres_grants import WORKSPACE_SECURITY_AUTHORIZATION_STALE, PostgresGrantStore
from .postgres_dimensional_security_policies import (
    POLICY_KEYS, PostgresDimensionalSecurityPolicyStore, policy_from_values,
    policy_effect_result_schema, policy_read_result_schema, policy_state_token_schema,
    policy_values_schema)
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
_REFERENCE_CONTROLS = r'\x00-\x1f'


def _trimmed_reference_schema(maximum: int, excluded: str) -> dict:
    # Match the compiler's strip() boundary in both Python and ECMAScript.
    whitespace = r'\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000'
    edge = f'[^{excluded}{whitespace}]'
    return {'type': 'string', 'minLength': 1, 'maxLength': maximum,
            'pattern': rf'^{edge}(?:[^{excluded}]*{edge})?(?![\s\S])'}


def _principal_schemas() -> tuple[dict, dict]:
    subject = {'type': 'string', 'minLength': 1, 'maxLength': 300,
               'pattern': r'^[^\x00-\x1f]+(?![\s\S])'}
    return subject, {**subject, 'pattern': r'^[^\x00-\x1f*]+(?![\s\S])'}


def application_access_read_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    subject, group = _principal_schemas()
    operation = {**subject, 'maxLength': 200}
    count = {'type': 'integer', 'minimum': 1, 'maximum': 2**63 - 1}
    timestamp = {'type': 'string', 'format': 'date-time'}
    nullable = {'type': ['string', 'null']}
    text = {'type': 'string'}
    rules = ['Each read requires current application Administrator authority in the selected application.']
    if function in (AUDIT_LIST_FUNCTION, RECEIPT_READ_FUNCTION):
        from .application_authorization_config import requester_benefit_schema
        review_fields={'requesterBenefit':requester_benefit_schema(),
                       'authorizationMode':{'enum':['group_assignments','legacy']}}
        rules=['Legacy applications require current administrator authority. Group-assigned applications require access.review.',
               'For reviewed group changes, the event summarizes recorded requester benefit and the receipt identifies the exact grants.']
    if function == RECEIPT_READ_FUNCTION:
        arguments = obj({'operationId': operation})
        digest = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
        result = obj({'workspaceId': text, 'applicationId': text, 'operationId': operation,
            'action': text, 'outcome': {'const': 'Committed'}, 'committedAt': timestamp,
            'commandDigest': digest, 'payloadDigest': digest, 'actorDigest': digest})
        result['properties'].update(review_fields)
        from .application_authorization_config import WORKFLOW_DUTY_CHANGES
        result['properties']['reviewedWorkflowDuties']=WORKFLOW_DUTY_CHANGES
        examples = [read_example(function, {'operationId': 'example-access-operation'},
            name='Inspect a committed security receipt',
            binding='Use a detailsKey from this application’s security audit page.')]
        rules.append('Receipts require a corresponding audit event in the same application and expose the committed digests.')
        recovery = ('Use the audit page in the currently authorized application to confirm the receipt reference. '
                    f'On {SECURITY_READ_AUTHORIZATION_STALE}, check current access and repeat the exact receipt read.')
    else:
        if function in (LIST_FUNCTION, GROUP_LIST_FUNCTION):
            tags = {'type': 'object', 'additionalProperties': {'type': 'array', 'items': text}}
            permissions = {'oneOf': [obj({name: {'type': 'boolean'}
                for name in ('design', 'publish', 'run')}), {'type': 'null'}]}
            fields = {'role': {'enum': ['Reader', 'Editor', 'Administrator']}, 'readTags': tags,
                      'writeTags': tags, 'rulePermissions': permissions, 'grantedAt': timestamp}
            if function == LIST_FUNCTION:
                cursor, following, cursor_shape = 'afterSubjectId', 'nextAfterSubjectId', subject
                entity = 'direct application grants'
                row = obj({'subjectId': subject, 'displayName': nullable, 'username': nullable, **fields})
            else:
                cursor, following, cursor_shape = 'afterGroupId', 'nextAfterGroupId', group
                entity = 'application group grants'
                row = obj({'groupId': group, 'displayName': nullable, 'groupName': nullable,
                           'directoryStatus': {'enum': ['Active', 'Inactive', None]}, **fields})
                rules.append('Current group names and directory status come from the verified issuer. '
                             'Null fields mean a stored grant has no current matching directory details.')
            records = 'grants'
            rules.append('Direct and group grants have separate listings. Each grant carries its own tags and rule permissions.')
        elif function == SUBJECT_LIST_FUNCTION:
            cursor, following, cursor_shape = 'afterSelectionKey', 'nextAfterSelectionKey', subject
            entity, records = 'directory subjects', 'subjects'
            row = obj({'selectionKey': subject, 'displayName': text, 'username': text})
            rules.append('Rows describe active subjects in the current provider directory. Selecting a subject does not establish a grant.')
        elif function == AUDIT_LIST_FUNCTION:
            cursor, following, cursor_shape = 'beforeAuditId', 'nextBeforeAuditId', count
            entity, records = 'application security events', 'events'
            row = obj({'auditId': count, 'occurredAt': timestamp, 'actorName': text, 'action': text,
                       'targetName': text, 'outcome': {'enum': ['Accepted', 'Rejected', 'Failed']},
                       'detailsKey': nullable})
            row['properties'].update(review_fields)
            rules.append('Audit pages descend by event ID. Only a nonnull detailsKey can refer to a security receipt.')
        else:
            raise ValueError('APPLICATION_ACCESS_READ_FUNCTION_INVALID')
        nullable_cursor = {'oneOf': [cursor_shape, {'type': 'null'}]}
        arguments = obj({cursor: nullable_cursor, 'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100}}, [])
        result = obj({records: {'type': 'array', 'maxItems': 100, 'items': row}, following: nullable_cursor})
        samples = {'limit': 25, cursor: 100 if function == AUDIT_LIST_FUNCTION else 'example-page-key'}
        examples = [read_example(function, {'limit': 25}, name=f'List {entity}',
            binding='Use the current authorized application and omit the cursor on the first page.'),
            read_example(function, samples, name=f'Continue the {entity} list',
                binding=f'Copy {following} from the prior page into {cursor}.')]
        rules.append(f'Use the returned {following} for continuation. Null ends the list. The core rechecks current authority for every page.')
        recovery = (f'On {SECURITY_READ_AUTHORIZATION_STALE} or a scope change, check current access '
                    'and start again from the first page.')
    contract = read_contract(function, arguments, result, owner='PostgresGrantStore',
        examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = recovery
    return contract


def dimensional_access_read_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    subject = _trimmed_reference_schema(300, _REFERENCE_CONTROLS)
    group = _trimmed_reference_schema(300, _REFERENCE_CONTROLS + '*')
    reference = _trimmed_reference_schema(200, _REFERENCE_CONTROLS)
    text = {'type': 'string'}
    revision = {'type': 'integer', 'minimum': 0}
    scope = {'workspaceId': text, 'applicationId': text, 'securityRevision': revision}
    tags = {'type': 'array', 'items': text}
    metadata = {**scope, 'metadataRevision': revision}
    if function in (MEMBER_TAGS_READ_FUNCTION, DIMENSION_METADATA_TAGS_READ_FUNCTION):
        rules = ['In a group-assigned application the core checks application entry and the '
                 'metadata.classify action before and after the read. The dimension and any '
                 'selected member must be active. Legacy applications require current Administrator authority.']
    else:
        rules = ['The core rechecks current application Administrator authority.']
    owner = 'PostgresGrantStore'
    recovery = 'Check the current authorized application and rediscover the reference before retrying.'
    if function in (DIMENSION_READ_FUNCTION, GROUP_DIMENSION_READ_FUNCTION):
        if function == DIMENSION_READ_FUNCTION:
            selector, identifier, example_id = 'subjectId', subject, 'example-subject'
            name = 'Inspect dimensional tags assigned to a direct grant'
            binding = 'Use the subjectId returned by security.application.access.list.'
        else:
            selector, identifier, example_id = 'groupId', group, 'example-group'
            name = 'Inspect dimensional tags assigned to a group grant'
            binding = 'Use the groupId returned by security.application.group-access.list.'
        tag_map = {'type': 'object', 'additionalProperties': tags}
        arguments = obj({selector: identifier})
        example = {selector: example_id}
        result = obj({**scope, selector: identifier, 'role': {'enum': ['Reader', 'Editor', 'Administrator']},
                      'readTags': tag_map, 'writeTags': tag_map})
        rules.append('The returned tag maps belong to this grant. Current policy and effective identity determine access.')
    elif function == DIMENSION_TAGS_FUNCTION:
        arguments, example = obj({}), {}
        dimension = obj({'order': {'type': 'integer', 'minimum': 1}, 'dimensionId': reference,
            'name': text, 'modelRole': {'type': ['string', 'null']}, 'readTags': tags, 'writeTags': tags})
        result = obj({**metadata, 'dimensions': {'type': 'array', 'items': dimension}})
        name = 'List the current application tag vocabulary'
        binding = 'Use the currently authorized application.'
        rules.append('The catalogue lists active dimensions and distinct tags on their active members in server order.')
    elif function == DIMENSION_POLICY_READ_FUNCTION:
        owner = 'PostgresDimensionalSecurityPolicyStore'
        arguments, example = obj({}), {}
        result = policy_read_result_schema()
        name = 'Check the current dimensional security policy'
        binding = 'Use the currently authorized application.'
        rules.extend(['Absent means there is no current policy definition. Saved carries a definition without an authorization effect, including after deactivation.',
                      'Active carries an authorization effect. The response includes current securityRevision and the state token when a definition exists.'])
        recovery = 'Read the policy again after a lifecycle change before using its state token.'
    else:
        dimension = {'dimensionId': reference}
        object_selectors = {
            MEMBER_TAGS_READ_FUNCTION: ({**dimension, 'memberId': reference},
                {'dimensionId': 'Entity', 'memberId': 'example-member'}, 'member',
                'Use stable dimension and member IDs from current metadata discovery.'),
            DIMENSION_METADATA_TAGS_READ_FUNCTION: (dimension, {'dimensionId': 'Entity'},
                'dimension row', 'Use the stable dimension ID from current metadata discovery.'),
            RELATIONSHIP_TAGS_READ_FUNCTION: ({'relationshipId': reference},
                {'relationshipId': 'example-relationship'}, 'relationship',
                'Use the stable relationship ID from current metadata discovery.'),
        }
        selectors, example, label, binding = object_selectors[function]
        arguments = obj(selectors)
        result = obj({**metadata, **dimension, **selectors, 'name': text,
            'status': {'enum': ['Active', 'Inactive']}, 'readTags': tags, 'writeTags': tags,
            'securityString': text})
        name = f'Inspect security tags on a {label}'
        rules.append('The returned tags and security string describe the stored metadata row at the reported revisions.')
    contract = read_contract(function, arguments, result, owner=owner,
        examples=[read_example(function, example, name=name, binding=binding)], semantic_rules=rules)
    contract['programContract']['recovery'] = (
        f'{recovery} On {SECURITY_READ_AUTHORIZATION_STALE}, check current access '
        'and repeat the inspection.')
    return contract


def application_grant_effect_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    if function not in (FUNCTION, GROUP_FUNCTION, RULE_FUNCTION, RULE_GROUP_FUNCTION):
        raise ValueError('APPLICATION_GRANT_EFFECT_FUNCTION_INVALID')
    group = function in (GROUP_FUNCTION, RULE_GROUP_FUNCTION)
    rule = function in (RULE_FUNCTION, RULE_GROUP_FUNCTION)
    field = 'groupId' if group else 'subjectId'
    identifier = _trimmed_reference_schema(300, _REFERENCE_CONTROLS + '*' if group else _REFERENCE_CONTROLS)
    name = 'group' if group else 'direct'
    example_id = {field: f'example-{name}'}
    rules = ['Obtain signed admission for the exact program in the selected application. '
             'The fixed transaction rechecks current Administrator authority before applying or replaying it.']
    if rule:
        action, payload, sample = 'set', 'permissions', {'design': False, 'publish': False, 'run': True}
        enabled = dict.fromkeys(('design', 'publish', 'run'), {'type': 'boolean'})
        value = {**obj(enabled), 'anyOf': [
            {'properties': {permission: {'const': True}}} for permission in enabled]}
        label = f'{name} rule permissions'
        binding = ('Use the groupId from security.application.group-access.list.' if group else
                   'Use the subjectId from security.application.access.list.')
        rules.extend(['Rule permissions are separate from the application role and require an existing application grant.',
                      'Set replaces all three flags. At least one must be true. Revoke uses null and clears the rule grant.'])
    else:
        action, payload, sample = 'grant', 'role', 'Reader'
        value = {'enum': ['Reader', 'Editor', 'Administrator']}
        label = f'{name} application access'
        binding = ('Use the stable group ID from the current verified provider directory.' if group else
                   'Use the selectionKey from security.application.subject.list as subjectId when granting access.')
        rules.extend(['Grant assigns the requested role to an active principal in the verified issuer. '
                      'Revoke uses a null role and removes the corresponding application and rule grants.',
                      'A direct grant and a group grant are separate. Resolve current effective access before stating that a person has lost access.'])
    nullable = {'type': 'null'}
    fields = {'action': {'enum': [action, 'revoke']}, payload: {'anyOf': [value, nullable]}}
    relationship = {'if': {'properties': {'action': {'const': action}}},
                    'then': {'properties': {payload: value}},
                    'else': {'properties': {payload: nullable}}}
    arguments = {**obj({field: identifier, **fields}), **relationship}
    result = {**obj({'workspaceId': {'type': 'string'}, 'applicationId': {'type': 'string'},
        'changed': {'type': 'boolean'}, **fields, **({field: identifier} if group else {})}), **relationship}
    revoke_source = ('security.application.group-access.list' if group else 'security.application.access.list')
    examples = [
        read_example(function, {**example_id, 'action': action, payload: sample},
            name=f'{action.title()} {label}', binding=binding),
        read_example(function, {**example_id, 'action': 'revoke', payload: None},
            name=f'Revoke {label}', binding=f'Use the exact existing {field} from {revoke_source} in the current application.'),
    ]
    contract = read_contract(function, arguments, result, owner='PostgresGrantStore',
        examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = (
        'Keep the signed operation ID and use security.application.receipt.read to reconcile uncertainty. '
        'Replay only the exact original permitted program. Read the current grant for the latest role or rule permissions.')
    return contract


def workspace_security_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    group_id = _trimmed_reference_schema(300, _REFERENCE_CONTROLS + '*')
    rules = ['Use the MCP listener bound to the intended workspace. The core checks current workspace administrator authority.']
    if function == WORKSPACE_GROUP_LIST_FUNCTION:
        cursor = {'oneOf': [group_id, {'type': 'null'}]}
        arguments = obj({'afterGroupId': cursor,
                         'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100}}, [])
        grant = obj({'groupId': {'type': 'string'}, 'role': {'const': 'Administrator'},
                     'grantedAt': {'type': 'string', 'format': 'date-time'}})
        result = obj({'grants': {'type': 'array', 'items': grant, 'maxItems': 100},
                      'nextAfterGroupId': {'type': ['string', 'null']}})
        examples = [read_example(function, {'limit': 25}, name='List workspace group grants',
                                 binding='Omit afterGroupId on the first page.'),
                    read_example(function, {'afterGroupId': 'example-existing-group', 'limit': 25},
                                 name='Continue the workspace group grants list',
                                 binding='Copy the exact nonnull nextAfterGroupId from the previous page.')]
        rules.append('Null nextAfterGroupId means the listing is complete.')
        recovery = (f'On {WORKSPACE_SECURITY_AUTHORIZATION_STALE}, check current authority '
                    'and restart from the first page.')
    elif function in (WORKSPACE_FUNCTION, WORKSPACE_GROUP_FUNCTION):
        group = function == WORKSPACE_GROUP_FUNCTION
        field = 'groupId' if group else 'subjectId'
        identifier = group_id if group else _trimmed_reference_schema(300, _REFERENCE_CONTROLS)
        fields = {'action': {'enum': ['grant', 'revoke']}, 'role': {'enum': ['Administrator', None]}}
        role_by_action = {'if': {'properties': {'action': {'const': 'grant'}}},
                          'then': {'properties': {'role': {'const': 'Administrator'}}},
                          'else': {'properties': {'role': {'type': 'null'}}}}
        arguments = {**obj({field: identifier, **fields}), **role_by_action}
        result = {**obj({'workspaceId': {'type': 'string'}, 'changed': {'type': 'boolean'},
                         **fields, **({field: identifier} if group else {})}), **role_by_action}
        sample = {field: 'example-existing-group' if group else 'example-existing-subject'}
        label = 'group' if group else 'user'
        examples = [
            read_example(function, {**sample, 'action': 'grant', 'role': 'Administrator'},
                         name=f'Grant workspace administration to a {label}',
                         binding=f'Use the active {field} from the current verified identity directory and supply a new workspace request key.'),
            read_example(function, {**sample, 'action': 'revoke', 'role': None},
                         name=f'Revoke workspace administration from a {label}',
                         binding=f'Use the exact {field} of the existing workspace grant and supply a new workspace request key.'),
        ]
        rules.extend(['Grant uses role Administrator. Revoke uses a null role.',
                      'The grant change, receipt and audit entry commit together. Keep the original request key for exact replay.'])
        recovery = (f'On {WORKSPACE_SECURITY_AUTHORIZATION_STALE}, this attempt was rolled back. '
                    'Check current authority before retrying the exact program and original key.')
    else:
        raise ValueError('WORKSPACE_SECURITY_FUNCTION_INVALID')
    contract = read_contract(function, arguments, result, owner='PostgresGrantStore',
                             examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = recovery
    return contract


def dimensional_access_effect_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    revision = {'type': 'integer', 'minimum': 0}
    rules = ['Obtain signed admission for the exact program in the selected application. '
             'The fixed transaction rechecks current Administrator authority before applying or replaying it.']
    recovery = ('Keep the signed operation ID and reconcile uncertainty using the current application security receipt. '
                'Replay only the exact original permitted program. On a stale state or revision, read the current scope and approve a new intent.')
    if function in (DIMENSION_FUNCTION, GROUP_DIMENSION_FUNCTION):
        group = function == GROUP_DIMENSION_FUNCTION
        field = 'groupId' if group else 'subjectId'
        identifier = _trimmed_reference_schema(300, _REFERENCE_CONTROLS + '*' if group else _REFERENCE_CONTROLS)
        target = 'group' if group else 'direct'
        tag_map = {'type': 'object', 'maxProperties': 100,
            'propertyNames': _trimmed_reference_schema(200, r'\x00'),
            'additionalProperties': {'type': 'array', 'minItems': 1, 'maxItems': 100,
                'uniqueItems': True, 'items': _trimmed_reference_schema(20, r'\x00;')}}
        arguments = obj({field: identifier, 'readTags': tag_map, 'writeTags': tag_map,
                         'expectedSecurityRevision': revision})
        result = obj({'workspaceId': {'type': 'string'}, 'applicationId': {'type': 'string'},
                      'changed': {'type': 'boolean'}, 'securityRevision': revision,
                      **({field: identifier} if group else {})})
        values = {field: f'example-{target}', 'expectedSecurityRevision': 0}
        binding = ('Use the exact grant ID and securityRevision from the corresponding dimensional grant read. '
                   'Use exact axis and tag IDs from security.application.dimension-tags.read.')
        examples = [
            read_example(function, {**values, 'readTags': {'Entity': ['NorthRead']},
                'writeTags': {'Entity': ['NorthWrite']}}, name=f'Replace the {target} grant tag assignments',
                binding=binding),
            read_example(function, {**values, 'readTags': {}, 'writeTags': {}},
                name=f'Clear the {target} grant tag assignments', binding=binding),
        ]
        owner = 'PostgresGrantStore'
        rules.extend(['Both tag maps replace the grant’s previous maps. An empty map clears that side. '
                      'The fixed store checks the current grant, exact tag membership and security revision.',
                      'A changed assignment advances securityRevision. The result states whether it changed. '
                      'Read the grant to get the current tag maps. Effective access depends on the active policy and identity.'])
    elif function in (DIMENSION_POLICY_SAVE_FUNCTION, DIMENSION_POLICY_ACTIVATE_FUNCTION,
                      DIMENSION_POLICY_DEACTIVATE_FUNCTION):
        token = policy_state_token_schema()
        active = function == DIMENSION_POLICY_ACTIVATE_FUNCTION
        result = policy_effect_result_schema(active=active)
        owner = 'PostgresDimensionalSecurityPolicyStore'
        binding = 'Read security.application.dimension-policy.read in the same authorized application.'
        sample = 'a' * 64
        if function == DIMENSION_POLICY_SAVE_FUNCTION:
            values = {
                'acrossDimensions': 'every_protected', 'withinDimension': 'any_tag',
                'untaggedMember': 'deny', 'untaggedDenyPrecedence': 'absolute',
                'memberTagCardinality': 'multiple', 'hierarchyTags': 'selected_member_only',
                'writeReadRelationship': 'require_read', 'mixedSelection': 'filter_reads_reject_writes',
                'administratorTreatment': 'require_assignment', 'factSideAuthority': 'derived_query_aid_only',
            }
            arguments = obj({'policy': policy_values_schema(),
                             'expectedStateToken': {'anyOf': [token, {'type': 'null'}]}}, ['policy'])
            examples = [
                read_example(function, {'policy': values}, name='Save a new dimensional policy',
                    binding=binding+' Use this form when its status is Absent. Review all ten choices.'),
                read_example(function, {'policy': values, 'expectedStateToken': sample},
                    name='Replace the exact current dimensional policy',
                    binding=binding+' Copy the current token and review the entire replacement definition.'),
            ]
            rules.append('Save makes the definition Saved without an authorization effect. Replacing an Active definition '
                         'deactivates it and advances securityRevision. Review this consequence before signing.')
        else:
            action = 'Activate' if active else 'Deactivate'
            arguments = obj({'expectedStateToken': token, 'expectedSecurityRevision': revision})
            examples = [read_example(function, {'expectedStateToken': sample, 'expectedSecurityRevision': 0},
                name=f'{action} the exact current dimensional policy',
                binding=binding+' Copy the current token and securityRevision.')]
            rules.append('The transition rotates the token and advances securityRevision. '
                         'Only a supported Saved definition can become Active. Deactivation returns it to Saved.')
    else:
        raise ValueError('DIMENSIONAL_ACCESS_EFFECT_FUNCTION_INVALID')
    contract = read_contract(function, arguments, result, owner=owner,
        examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = recovery
    return contract


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
                or '\x00' in dimension_id
                or not isinstance(tags, list) or not tags or len(tags) > 100
                or any(not isinstance(tag, str)
                       or tag != tag.strip()
                       or not 1 <= len(tag) <= 20
                       or ';' in tag or '\x00' in tag for tag in tags)
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
            or set(program['arguments']['policy']) != POLICY_KEYS):
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
        return {'languageVersion': 2, 'functions': {
            **application_authorization_config.catalog(),
            postgres_resource_access.FUNCTION: postgres_resource_access.catalog_entry(),
            postgres_access_explanation.FUNCTION: postgres_access_explanation.catalog_entry(),
            postgres_authorization_tags.FUNCTION: postgres_authorization_tags.catalog_entry(),
            postgres_authorization_objects.FUNCTION: postgres_authorization_objects.catalog_entry(),
            postgres_effective_access.FUNCTION: postgres_effective_access.catalog_entry(), FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'subjectId': 'verified-provider subject ID',
                          'action': 'grant or revoke',
                          'role': 'Reader, Editor, Administrator, or null on revoke'},
            'result': 'scoped grant effect, security receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short', **application_grant_effect_contract(FUNCTION)}, LIST_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'afterSubjectId': 'optional subject keyset',
                          'limit': 'optional 1-100'},
            'result': 'bounded application grants with dimensional and rule access',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **application_access_read_contract(LIST_FUNCTION)}, SUBJECT_LIST_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {
                'afterSelectionKey': 'optional opaque subject continuation',
                'limit': 'optional 1-100'},
            'result': ('bounded current active directory subjects with '
                       'business display names and opaque selection keys'),
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **application_access_read_contract(SUBJECT_LIST_FUNCTION)}, AUDIT_LIST_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'beforeAuditId': 'optional descending keyset cursor',
                          'limit': 'optional 1-100'},
            'result': ('bounded immutable application security events with '
                       'safe digests and optional receipt correlation'),
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **application_access_read_contract(AUDIT_LIST_FUNCTION)}, RECEIPT_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'operationId': 'exact security audit correlation'},
            'result': ('application-bound committed security receipt with '
                       'allowlisted identifiers, action, time and digests'),
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **application_access_read_contract(RECEIPT_READ_FUNCTION)}, DIMENSION_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {
                'subjectId': 'existing application-grant subject ID'},
            'result': 'current scoped role, read/write tag assignments and security revision',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **dimensional_access_read_contract(DIMENSION_READ_FUNCTION)}, GROUP_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'groupId': 'stable verified Keycloak group ID',
                          'action': 'grant or revoke',
                          'role': 'Reader, Editor, Administrator, or null on revoke'},
            'result': 'scoped group grant effect, security receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application and group target in the key',
            'workClass': 'short', **application_grant_effect_contract(GROUP_FUNCTION)}, GROUP_LIST_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'afterGroupId': 'optional group keyset',
                          'limit': 'optional 1-100'},
            'result': 'bounded application group grants with dimensional and rule access',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **application_access_read_contract(GROUP_LIST_FUNCTION)}, GROUP_DIMENSION_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'groupId': 'existing application group-grant ID',
                'readTags': 'dimension-ID map of exact read tags',
                'writeTags': 'dimension-ID map of exact write tags',
                'expectedSecurityRevision': 'nonnegative integer'},
            'result': 'group ID, changed flag and security revision, with a durable receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application and group target in the key',
            'workClass': 'short', **dimensional_access_effect_contract(GROUP_DIMENSION_FUNCTION)}, GROUP_DIMENSION_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'groupId': 'existing application group-grant ID'},
            'result': 'current scoped group role, read/write tag assignments and security revision',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **dimensional_access_read_contract(GROUP_DIMENSION_READ_FUNCTION)}, DIMENSION_TAGS_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {},
            'result': 'active dimensions in stable application order with distinct active-member read/write tags and revisions',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **dimensional_access_read_contract(DIMENSION_TAGS_FUNCTION)}, MEMBER_TAGS_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'dimensionId': 'active stable dimension ID',
                          'memberId': 'stable member ID'},
            'result': 'current exact member read/write tags and metadata/security revisions',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **dimensional_access_read_contract(MEMBER_TAGS_READ_FUNCTION)}, DIMENSION_METADATA_TAGS_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'dimensionId': 'active stable dimension ID'},
            'result': 'current exact dimension-row read/write tags and metadata/security revisions',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **dimensional_access_read_contract(DIMENSION_METADATA_TAGS_READ_FUNCTION)}, RELATIONSHIP_TAGS_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {'relationshipId': 'stable relationship ID'},
            'result': 'current exact relationship-row read/write tags and metadata/security revisions',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **dimensional_access_read_contract(RELATIONSHIP_TAGS_READ_FUNCTION)}, DIMENSION_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'subjectId': 'existing application-grant subject ID',
                'readTags': 'dimension-ID map of exact read tags',
                'writeTags': 'dimension-ID map of exact write tags',
                'expectedSecurityRevision': 'nonnegative integer'},
            'result': 'changed flag and security revision, with a durable receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short', **dimensional_access_effect_contract(DIMENSION_FUNCTION)}, DIMENSION_POLICY_SAVE_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'policy': 'all ten explicit dimensional-security choices'},
            'optionalArguments': {
                'expectedStateToken': 'current opaque token when replacing; omit or null for an absent policy'},
            'result': 'saved current policy and fresh state token; no authorization effect',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short', **dimensional_access_effect_contract(DIMENSION_POLICY_SAVE_FUNCTION)}, DIMENSION_POLICY_READ_FUNCTION: {
            'mode': 'read', 'permission': 'admin',
            'arguments': {},
            'result': 'integrity-checked current policy or explicit absent state',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **dimensional_access_read_contract(DIMENSION_POLICY_READ_FUNCTION)}, DIMENSION_POLICY_ACTIVATE_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'expectedStateToken': 'exact current saved policy token',
                'expectedSecurityRevision': 'current nonnegative revision'},
            'result': ('active supported current policy and fresh token with advanced security '
                       'revision; hierarchy-effective drafts are not activatable'),
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short', **dimensional_access_effect_contract(DIMENSION_POLICY_ACTIVATE_FUNCTION)}, DIMENSION_POLICY_DEACTIVATE_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {
                'expectedStateToken': 'exact current active policy token',
                'expectedSecurityRevision': 'current nonnegative revision'},
            'result': 'explicit policy deactivation and advanced security revision',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application target in the key',
            'workClass': 'short', **dimensional_access_effect_contract(DIMENSION_POLICY_DEACTIVATE_FUNCTION)}, RULE_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'subjectId': 'verified-provider subject ID',
                          'action': 'set or revoke',
                          'permissions': 'explicit design/publish/run booleans, or null on revoke'},
            'result': 'scoped rule permissions, receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application/rule target in the key',
            'workClass': 'short', **application_grant_effect_contract(RULE_FUNCTION)}, RULE_GROUP_FUNCTION: {
            'mode': 'atomic_security_write', 'permission': 'admin',
            'arguments': {'groupId': 'stable verified Keycloak group ID',
                          'action': 'set or revoke',
                          'permissions': 'explicit design/publish/run booleans, or null on revoke'},
            'result': 'scoped group rule permissions, receipt and audit',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace security-operation namespace; include the application/group target in the key',
            'workClass': 'short', **application_grant_effect_contract(RULE_GROUP_FUNCTION)}}}

    @staticmethod
    def workspace_catalog() -> dict:
        functions = {WORKSPACE_FUNCTION: {
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
            'workClass': 'short'}}
        for name, specification in functions.items():
            contract = workspace_security_contract(name)
            specification.update(contract, recovery=contract['programContract']['recovery'])
        functions.update(workspace_review.catalog())
        functions.update(auth_migration.catalog())
        return {'languageVersion': 2, 'functions': functions}

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
