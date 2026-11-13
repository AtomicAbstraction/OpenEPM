"""Resolve and revalidate bounded hierarchy-level planning selectors."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re

from .persistence_contract import ApplicationScope
from .planning_workflow_policy import (
    FORMAT_V2,MAX_MEMBERS_PER_SELECTOR,PlanningWorkflowPolicy,
    level_resolution_digest,
)


_AUTHOR_KEYS=frozenset(('dimensionId','rootMemberId','depth'))
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z')


def authored_policy_identity(definition: object)->tuple[str,str]:
    """Validate the unsealed envelope and identify exact authored intent."""
    expected={'format','workspaceId','applicationId','policyId',
              'effectiveFrom','effectiveTo','rules'}
    if (not isinstance(definition,dict) or set(definition)!=expected
            or definition.get('format')!=FORMAT_V2
            or any(not isinstance(definition.get(name),str)
                   or not _ID.fullmatch(definition[name])
                   for name in ('workspaceId','applicationId','policyId'))
            or not isinstance(definition.get('rules'),list)
            or not 1<=len(definition['rules'])<=500):
        raise ValueError('PLANNING_POLICY_DEFINITION_INVALID')
    try:
        encoded=json.dumps(definition,sort_keys=True,separators=(',',':'),
            ensure_ascii=False,allow_nan=False).encode()
    except (TypeError,ValueError) as error:
        raise ValueError('PLANNING_POLICY_DEFINITION_INVALID') from error
    if len(encoded)>4194304:
        raise ValueError('PLANNING_POLICY_SIZE_LIMIT')
    return definition['policyId'],sha256(encoded).hexdigest()


def resolve_level_selectors(db,scope: ApplicationScope,definition: object)->dict:
    if not isinstance(definition,dict) or definition.get('format')!=FORMAT_V2:
        return definition
    _,intent_digest=authored_policy_identity(definition)
    sealed=deepcopy(definition)
    sealed['authoredIntentDigest']=intent_digest
    for rule in sealed['rules']:
        if not isinstance(rule,dict) or 'levelSelector' not in rule:
            raise ValueError('PLANNING_POLICY_LEVEL_SELECTOR_INVALID')
        raw=rule['levelSelector']
        if raw is None:continue
        if (not isinstance(raw,dict) or set(raw)!=_AUTHOR_KEYS
                or type(raw.get('depth')) is not int
                or not 0<=raw['depth']<=1000):
            raise ValueError('PLANNING_POLICY_LEVEL_SELECTOR_INVALID')
        dimension,root=raw.get('dimensionId'),raw.get('rootMemberId')
        if not isinstance(dimension,str) or not isinstance(root,str):
            raise ValueError('PLANNING_POLICY_LEVEL_SELECTOR_INVALID')
        context=db.execute('''SELECT s.metadata_revision,s.schema_epoch,
              h.state_token,h.hierarchy_id,
              h.metadata_revision AS hierarchy_metadata_revision,
              d.status AS dimension_status,m.status AS root_status,
              (l.dimensions @> ARRAY[%s]::text[]) AS dimension_in_layout
            FROM epm.application_state s
            JOIN epm.coordinate_layout l ON l.workspace_id=s.workspace_id
             AND l.application_id=s.application_id AND l.schema_epoch=s.schema_epoch
            LEFT JOIN epm.dimension d ON d.workspace_id=s.workspace_id
             AND d.application_id=s.application_id AND d.dimension_id=%s
            LEFT JOIN epm.member m ON m.workspace_id=s.workspace_id
             AND m.application_id=s.application_id AND m.dimension_id=%s
             AND m.member_id=%s
            LEFT JOIN epm.hierarchy_state h ON h.workspace_id=s.workspace_id
             AND h.application_id=s.application_id AND h.dimension_id=%s AND h.hierarchy_id=epm.default_hierarchy_id(h.workspace_id,h.application_id,h.dimension_id)
            WHERE s.workspace_id=%s AND s.application_id=%s''',(
            dimension,dimension,dimension,root,dimension,
            scope.workspace_id,scope.application_id)).fetchone()
        if (context is None or context['dimension_status']!='Active'
                or context['root_status']!='Active'
                or not context['dimension_in_layout']):
            raise ValueError('PLANNING_POLICY_LEVEL_METADATA_INVALID')
        if (context['state_token'] is None
                or context['hierarchy_metadata_revision']!=context['metadata_revision']):
            raise ValueError('PLANNING_POLICY_HIERARCHY_STALE')
        rows=db.execute('''SELECT c.descendant_member_id,c.path_count,m.status
            FROM epm.hierarchy_closure c JOIN epm.member m
              ON m.workspace_id=c.workspace_id AND m.application_id=c.application_id
             AND m.dimension_id=c.dimension_id
             AND m.member_id=c.descendant_member_id
            WHERE c.workspace_id=%s AND c.application_id=%s
              AND c.dimension_id=%s AND c.hierarchy_id=%s
              AND c.state_token=%s
              AND c.ancestor_member_id=%s AND c.min_depth=%s
            ORDER BY c.descendant_member_id LIMIT %s''',(
            scope.workspace_id,scope.application_id,dimension,
            context['hierarchy_id'],context['state_token'],root,raw['depth'],
            MAX_MEMBERS_PER_SELECTOR+1)).fetchall()
        if not rows:raise ValueError('PLANNING_POLICY_LEVEL_EMPTY')
        if len(rows)>MAX_MEMBERS_PER_SELECTOR:
            raise ValueError('PLANNING_POLICY_LEVEL_MEMBER_LIMIT')
        if any(row['status']!='Active' for row in rows):
            raise ValueError('PLANNING_POLICY_LEVEL_MEMBER_INACTIVE')
        if any(row['path_count']!=1 for row in rows):
            raise ValueError('PLANNING_POLICY_LEVEL_PLACEMENT_AMBIGUOUS')
        members=sorted(row['descendant_member_id'] for row in rows)
        payload={**raw,'hierarchyStateToken':context['state_token'],
                 'metadataRevision':context['metadata_revision'],
                 'schemaEpoch':context['schema_epoch'],
                 'resolvedMemberIds':members}
        rule['levelSelector']={**payload,
            'resolutionDigest':level_resolution_digest(payload)}
    return sealed


def validate_level_selector_pins(db,scope: ApplicationScope,
                                 policy: PlanningWorkflowPolicy)->None:
    selectors={rule.level_selector for rule in policy.rules
               if rule.level_selector is not None}
    for selector in selectors:
        row=db.execute('''SELECT s.metadata_revision,s.schema_epoch,h.state_token,
              h.metadata_revision AS hierarchy_metadata_revision,
              (l.dimensions @> ARRAY[%s]::text[]) AS dimension_in_layout
            FROM epm.application_state s
            JOIN epm.coordinate_layout l ON l.workspace_id=s.workspace_id
             AND l.application_id=s.application_id AND l.schema_epoch=s.schema_epoch
            LEFT JOIN epm.hierarchy_state h ON h.workspace_id=s.workspace_id
             AND h.application_id=s.application_id AND h.dimension_id=%s AND h.hierarchy_id=epm.default_hierarchy_id(h.workspace_id,h.application_id,h.dimension_id)
            WHERE s.workspace_id=%s AND s.application_id=%s''',(
            selector.dimension_id,selector.dimension_id,
            scope.workspace_id,scope.application_id)).fetchone()
        if (row is None or not row['dimension_in_layout']
                or row['state_token']!=selector.hierarchy_state_token
                or row['metadata_revision']!=selector.metadata_revision
                or row['schema_epoch']!=selector.schema_epoch
                or row['hierarchy_metadata_revision']!=selector.metadata_revision):
            raise ValueError('PLANNING_POLICY_HIERARCHY_STALE')
