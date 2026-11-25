"""Fixed action vocabulary for group-assigned applications.

Each listed operation has a known target and enforcement point. Operations
without a mapping are unavailable in this authorization model.
"""
from __future__ import annotations

APPLICATION_ENTRY = 'application.enter'
MEMBER_TAGS_READ_FUNCTION = 'security.application.member-tags.read'
DIMENSION_METADATA_TAGS_READ_FUNCTION = 'security.application.dimension-metadata-tags.read'

# These companions must cover the target through the same assignment.
SAME_ASSIGNMENT_PREREQUISITE = {'facts.write':'facts.read', 'metadata.structure.edit':'metadata.browse'}

# Per-coordinate and metadata predicates are applied by the dimensional
# resolver. Application-level inspection requires an application-wide grant.
ACTION_SCOPE_KINDS = {
    APPLICATION_ENTRY: ('entire_application',),
    'access.review': ('entire_application',),
    'access.manage': ('entire_application',),
    'roles.manage': ('entire_application',),
    'facts.read': ('entire_application', 'dimension_tags'),
    'facts.write': ('entire_application', 'dimension_tags'),
    'facts.export': ('entire_application',),
    'facts.import': ('entire_application',),
    'metadata.browse': ('entire_application', 'dimension_tags'),
    'metadata.structure.create': ('entire_application',),
    'metadata.structure.edit': ('entire_application', 'dimension_tags'),
    'metadata.classify': ('entire_application',),
    'rules.inspect': ('entire_application',),
    'rules.design': ('entire_application',),
    'rules.test': ('entire_application',),
    'rules.publish': ('entire_application',),
    'rules.run': ('entire_application',),
    'planning.policy.draft': ('entire_application',),
    'planning.policy.activate': ('entire_application',),
    'views.read': ('entire_application', 'exact_object'),
    'views.save': ('entire_application', 'exact_object'),
    'views.delete': ('entire_application',),
    'views.run': ('entire_application', 'exact_object'),
}
# An administrator can be delegated the ability to assign a business privilege
# without acquiring the privilege to read or change business data personally.
ACTION_SCOPE_KINDS.update({
    'delegate.' + action: kinds for action, kinds in ACTION_SCOPE_KINDS.items()
})

PROGRAM_ACTIONS = {
    'application.state.read': APPLICATION_ENTRY,
    'application.capabilities.read': APPLICATION_ENTRY,
    'security.identity.current.read': APPLICATION_ENTRY,
    'security.application.access.explain': 'access.review',
    'security.application.resource-access.list': 'access.review',
    'security.application.effective-access.list': 'access.review',
    'security.application.audit.list': 'access.review',
    'security.application.receipt.read': 'access.review',
    'security.application.authorization.tags.list': 'access.manage',
    'security.application.authorization.objects.list': 'access.manage',
    'facts.numeric.batch': 'facts.write',
    'cube.write.policy.save': 'planning.policy.draft',
    'cube.write.policy.activate': 'planning.policy.activate',
    'cube.write.policy.deactivate': 'planning.policy.activate',
    'facts.cube.scan': 'facts.read',
    'facts.cube.aggregate.request': 'facts.read',
    'facts.cube.aggregate.read': 'facts.read',
    'facts.cube.aggregate.cancel': 'facts.read',
    'metadata.dimension.list': 'metadata.browse',
    'metadata.dimension.resolve': 'metadata.browse',
    'metadata.member.list': 'metadata.browse',
    'metadata.member.resolve': 'metadata.browse',
    'metadata.dimension.create': 'metadata.structure.create',
    'metadata.member.create': 'metadata.structure.create',
    'metadata.security-tag.list': 'metadata.classify',
    'metadata.security-tag.create': 'metadata.classify',
    'metadata.security-tag.update': 'metadata.classify',
    MEMBER_TAGS_READ_FUNCTION: 'metadata.classify',
    DIMENSION_METADATA_TAGS_READ_FUNCTION: 'metadata.classify',
    'metadata.dimension.security-string.set': 'metadata.classify',
    'metadata.member.security-tags.set': 'metadata.classify',
    'metadata.member.security-string.set': 'metadata.classify',
    'metadata.relationship.list': 'metadata.browse',
    'metadata.hierarchy.list': 'metadata.browse',
    'metadata.hierarchy.read': 'metadata.browse',
    'metadata.hierarchy.members.list': 'metadata.browse',
    'grid.definition.list': 'views.read',
    'grid.definition.read': 'views.read',
    'grid.definition.save': 'views.save',
    'grid.definition.delete': 'views.delete',
    'python.program.read': 'rules.inspect',
    'python.program.list': 'rules.inspect',
    'python.program.save': 'rules.design',
    'python.environment.list': 'rules.design',
}

# Every clause must be satisfied. The actions in one clause are alternatives.
# Resource predicates are checked by the handler after this admission gate.
_CONFIGURATION_EDIT = (('access.manage', 'roles.manage'),)
_STRUCTURE_EDIT = (('metadata.browse',), ('metadata.structure.edit',))
_POLICY_MANAGEMENT = (('planning.policy.draft', 'planning.policy.activate'),)
GROUP_SOURCE_IMPORT_FUNCTIONS = frozenset({
    'facts.source.begin', 'facts.source.append', 'facts.source.csv.append', 'facts.source.seal',
    'facts.source.preview', 'facts.source.publish', 'facts.source.cancel', 'facts.source.staging.read',
})
GROUP_EXPORT_FUNCTIONS = frozenset({
    'facts.export.page', 'facts.transfer.export.request', 'facts.transfer.export.read',
    'facts.transfer.export.cancel', 'facts.transfer.export.manifest.read',
    'facts.transfer.export.manifest.list', 'facts.transfer.export.payload.page',
})
COMPOSITE_ACTIONS = {
    **dict.fromkeys(('cube.write.policy.read', 'cube.write.policy.list',
                     'application.operation.receipt.read'), _POLICY_MANAGEMENT),
    **dict.fromkeys(('application.rule.list', 'application.rule.read',
                     'application.rule.run', 'application.rule.run.read'),
                    (('rules.run',), ('facts.read',), ('facts.write',))),
    'python.program.test': (('rules.test',), ('facts.read',), ('facts.write',)),
    'python.program.activate': (('rules.test',), ('rules.publish',), ('facts.read',), ('facts.write',)),
    **dict.fromkeys(GROUP_SOURCE_IMPORT_FUNCTIONS, (('facts.import',), ('facts.read',), ('facts.write',))),
    **dict.fromkeys(GROUP_EXPORT_FUNCTIONS, (('facts.export',), ('facts.read',))),
    'metadata.dimension.rename': _STRUCTURE_EDIT,
    'metadata.dimension.describe': _STRUCTURE_EDIT,
    'metadata.member.rename': _STRUCTURE_EDIT,
    'metadata.member.describe': _STRUCTURE_EDIT,
    'facts.cube.resolved.read': (('views.run',), ('facts.read',)),
    'security.application.authorization.read': (('access.manage', 'access.review', 'roles.manage'),),
    'security.application.authorization.preview': _CONFIGURATION_EDIT,
    'security.application.authorization.apply': _CONFIGURATION_EDIT,
}


def admission_action_clauses(function):
    action = PROGRAM_ACTIONS.get(function)
    if action is not None:
        return ((action,),)
    return COMPOSITE_ACTIONS.get(function, ())


def action_allows_operation(actions, function):
    clauses = admission_action_clauses(function)
    return bool(clauses) and all(any(action in actions for action in clause) for clause in clauses)


def describe_assignment_admission(function):
    """Describe the same gate used by discovery and execution, without disclosing a grant."""
    clauses = admission_action_clauses(function)
    if not clauses:
        return {'status': 'unavailable_in_group_model'}
    return {'status': 'action_gate', 'requiresApplicationEntry': True,
            'allOf': [{'anyAction': list(clause)} for clause in clauses],
            'targetCheckedByHandler': True}


def current_group_entitlements(db, scope, issuer, groups):
    """Return actions with compatible scope and the roles supplying them."""
    rows = db.execute('''SELECT DISTINCT action,scope_kind,role_name
        FROM epm.application_authorization_privilege
        WHERE workspace_id=%s AND application_id=%s AND issuer=%s
          AND group_id=ANY(%s::text[])''',
        (scope.workspace_id, scope.application_id, issuer, list(groups))).fetchall()
    actions = set()
    roles = set()
    for row in rows:
        if row['scope_kind'] in ACTION_SCOPE_KINDS.get(row['action'], ()):
            actions.add(row['action'])
            roles.add(row['role_name'])
    return tuple(sorted(actions)), tuple(sorted(roles))
