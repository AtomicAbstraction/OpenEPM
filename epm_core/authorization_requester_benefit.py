"""Describe how a reviewed change affects the requester's own group grants."""
from collections import defaultdict

from .application_authorization_actions import ACTION_SCOPE_KINDS, APPLICATION_ENTRY, SAME_ASSIGNMENT_PREREQUISITE
from .application_authorization_config import covers


_MAX_GRANTS = 4096
_REASONS = ('new_application_entry', 'new_grant_path', 'potential_scope_expansion', 'additional_grant_path')


def _graph_grants(graph, groups, affected):
    for assignment_id in affected:
        assignment = graph['assignments'].get(assignment_id)
        if assignment is None or assignment['groupId'] not in groups:
            continue
        role = graph['roles'][assignment['roleId']]
        duties=role.get('workflowDuties',()) if any(
            p['action']=='facts.write' for p in assignment['privileges']) else ()
        for binding in assignment['privileges']:
            scope = graph['scopes'][binding['scopeId']]
            action = binding['action']
            if action in role['actions'] and scope['scopeKind'] in ACTION_SCOPE_KINDS.get(action, ()):
                yield {'groupId':assignment['groupId'], 'assignmentId':assignment_id, 'roleId':role['roleId'],
                       'action':action, 'scopeId':binding['scopeId'], 'scopeRevision':scope['revision'],
                       'scopeKind':scope['scopeKind'], 'selector':scope['selector'],
                       **({'workflowDuties':duties} if duties and action in ('facts.read','facts.write') else {})}


def _path(row):
    return (row['assignmentId'], row['groupId'], row['action'], row['scopeId'])


def compare_grants(previous, proposed, *, other_scopes=(), continuing_entry=False, other_scopes_complete=True):
    """Compare assigned authority. Executability still depends on normal target checks."""
    if max(len(previous), len(proposed)) > _MAX_GRANTS:
        raise ValueError('APPLICATION_AUTHORIZATION_IMPACT_LIMIT')
    previous_paths = {_path(row):row for row in previous}
    previous_by_action = defaultdict(list)
    previous_companions = defaultdict(list)
    for row in previous:
        previous_by_action[row['action']].append(row)
        if row['action'] in SAME_ASSIGNMENT_PREREQUISITE.values():
            previous_companions[(row['assignmentId'],row['groupId'],row['action'])].append(row)
    expanded = set()
    for row in proposed:
        if row['action'] in SAME_ASSIGNMENT_PREREQUISITE.values():
            key = (row['assignmentId'],row['groupId'],row['action'])
            if not any(covers(old,row) for old in previous_companions[key]):
                expanded.add(key)
    for scope in other_scopes:
        previous_by_action[scope['action']].append(scope)
    admitted = continuing_entry or any(row['action'] == APPLICATION_ENTRY for row in proposed)
    newly_admitted = admitted and not continuing_entry and not previous_by_action[APPLICATION_ENTRY]
    changes = []
    proposed_paths={_path(row):row for row in proposed}
    for path in sorted(previous_paths.keys() | proposed_paths.keys()):
        prior=previous_paths.get(path)
        current=proposed_paths.get(path)
        old_duties=(prior or {}).get('workflowDuties',[])
        new_duties=(current or {}).get('workflowDuties',[])
        # A changed duty can remove an Allow or a higher-priority Deny. An
        # exact business decision also depends on the active policy and cell.
        duty_change=(old_duties!=new_duties or bool(old_duties and new_duties and
            (prior['scopeKind'],prior['selector'])!=(current['scopeKind'],current['selector'])))
        if current is None and not duty_change:
            continue
        row=current or prior
        companion = SAME_ASSIGNMENT_PREREQUISITE.get(row['action'])
        prerequisite_grew = (row['assignmentId'],row['groupId'],companion) in expanded
        if newly_admitted:
            reason = 'new_application_entry'
        elif duty_change or (prior and prerequisite_grew):
            reason = 'potential_scope_expansion'
        elif prior and covers(prior, row):
            continue
        elif any(covers(other, row) for other in previous_by_action[row['action']]):
            # Equivalent coverage for this *action*, possibly through a different
            # assignment. Its companion read or target checks are independent.
            reason = 'additional_grant_path'
        elif previous_by_action[row['action']] or not other_scopes_complete:
            reason = 'potential_scope_expansion'
        else:
            reason = 'new_grant_path'
        evidence={k:v for k,v in row.items() if k!='workflowDuties'}
        if duty_change:
            evidence.update(previousWorkflowDuties=old_duties,reviewedWorkflowDuties=new_duties)
            if prior and current and (prior['scopeKind'],prior['selector'])!=(current['scopeKind'],current['selector']):
                evidence['previousDutyScope']={k:prior[k] for k in ('scopeKind','scopeRevision','selector')}
        changes.append({**evidence, 'reason':reason, **({'expandedPrerequisite':companion} if prerequisite_grew else {})})
        if len(changes)>_MAX_GRANTS:
            raise ValueError('APPLICATION_AUTHORIZATION_IMPACT_LIMIT')
    classifications = {row['reason'] for row in changes}
    return {'classification':next((r for r in _REASONS if r in classifications), 'none'),
            'applicationEntry':'admitted' if admitted else 'requires_entry',
            'grants':changes, 'grantsComplete':True}


def requester_benefit(db, params, subject, before, after, affected):
    # Only the verified requester is examined. Include newly proposed groups
    # and directory memberships absent from an older token. This projection
    # describes beneficiaries and is never used to authorize the caller.
    proposed_groups = {a['groupId'] for a in after['assignments'].values()}
    values = {**params, 'subject':subject, 'proposed':sorted(proposed_groups), 'affected':affected}
    groups = db.execute("""SELECT epm.current_identity_groups(%(issuer)s,%(subject)s,ARRAY(
        SELECT group_id FROM epm.application_authorization_assignment
          WHERE workspace_id=%(workspace)s AND application_id=%(app)s AND issuer=%(issuer)s
        UNION SELECT unnest(%(proposed)s::text[]))) AS groups""", values).fetchone()['groups']
    own_groups = set(groups)
    previous = list(_graph_grants(before, own_groups, affected))
    proposed = list(_graph_grants(after, own_groups, affected))
    values.update(own=groups,limit=_MAX_GRANTS+1,actions=sorted({r['action'] for r in proposed}))
    other = """FROM epm.application_authorization_privilege
        WHERE workspace_id=%(workspace)s AND application_id=%(app)s AND issuer=%(issuer)s
          AND group_id=ANY(%(own)s::text[]) AND NOT (assignment_id=ANY(%(affected)s::text[]))"""
    continuing_entry = db.execute("SELECT EXISTS (SELECT 1 " + other +
        " AND action='application.enter' AND scope_kind='entire_application') AS admitted", values).fetchone()['admitted']
    newly_entered = (not continuing_entry and any(r['action']==APPLICATION_ENTRY for r in proposed)
                     and not any(r['action']==APPLICATION_ENTRY for r in previous))
    if newly_entered:
        # The edit activates dormant grants, including those outside this batch.
        dormant = db.execute("""SELECT group_id AS "groupId",assignment_id AS "assignmentId",role_id AS "roleId",
            action,scope_id AS "scopeId",scope_revision AS "scopeRevision",scope_kind AS "scopeKind",selector,
            CASE WHEN action IN ('facts.write','facts.read') THEN workflow_duties ELSE ARRAY[]::text[] END AS "workflowDuties" """
            + other + " LIMIT %(limit)s", values).fetchall()
        return compare_grants(previous, [*dormant, *proposed])
    if not proposed:
        return compare_grants(previous, proposed, continuing_entry=continuing_entry)
    # Compare a new path only to distinct scopes for the same action. Thousands
    # of unrelated or equivalent grants must not prevent a small reviewed edit.
    peers = db.execute('SELECT DISTINCT action,scope_kind AS "scopeKind",selector ' + other +
        ' AND action=ANY(%(actions)s::text[]) LIMIT %(limit)s', values).fetchall()
    complete = len(peers) <= _MAX_GRANTS
    return compare_grants(previous, proposed, other_scopes=peers if complete else (),
                          continuing_entry=continuing_entry, other_scopes_complete=complete)
