"""Bounded, sealed non-fact dependencies for generic expressions.

These dependencies are publication fences and audit evidence.  They never
select accounting policy or turn caller assertions into verified facts.
"""
from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
import re

from .postgres_ownership import PostgresOwnershipValues, _ACCOUNTS, _BOUNDS


_ID = re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_CHANGE = re.compile(r'[0-9a-f]{32}\Z')
_FORMAT = 'openepm-expression-context-v1'
_MAX = Decimal('99999999999999999999.99999999')


def _identifier(value: object, error: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(error)
    return value


def _change(value: object) -> str:
    if type(value) is not str or _CHANGE.fullmatch(value) is None:
        raise ValueError('EXPRESSION_CONTEXT_CHANGE_ID_INVALID')
    return value


def _amount(value: object, account: str) -> str:
    if type(value) is not str:
        raise ValueError('EXPRESSION_CONTEXT_AMOUNT_INVALID')
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise ValueError('EXPRESSION_CONTEXT_AMOUNT_INVALID') from error
    if (not number.is_finite() or number.as_tuple().exponent < -8
            or abs(number) > _MAX):
        raise ValueError('EXPRESSION_CONTEXT_AMOUNT_INVALID')
    lower, upper = _BOUNDS[account]
    if number < lower or (upper is not None and number > upper):
        raise ValueError('EXPRESSION_CONTEXT_AMOUNT_INVALID')
    if account in {'Active','Method','Consol1','Consol2','Consol3'} and (
            number != number.to_integral_value()):
        raise ValueError('EXPRESSION_CONTEXT_AMOUNT_INVALID')
    return format(number, '.8f')


def normalize_requests(value: object) -> tuple[dict, ...]:
    if type(value) is not list or not 1 <= len(value) <= 8:
        raise ValueError('EXPRESSION_CONTEXT_DEPENDENCIES_INVALID')
    result = []
    for item in value:
        if type(item) is not dict:
            raise ValueError('EXPRESSION_CONTEXT_DEPENDENCY_INVALID')
        kind = item.get('kind')
        if kind == 'OwnershipValue':
            required = {'kind','sourceId','relationshipId','scenarioId',
                'yearId','periodId','account','expectedPresent',
                'expectedAmount','expectedChangeId'}
            if set(item) != required or type(item['expectedPresent']) is not bool:
                raise ValueError('EXPRESSION_CONTEXT_OWNERSHIP_INVALID')
            account = item['account']
            if account not in _ACCOUNTS:
                raise ValueError('EXPRESSION_CONTEXT_OWNERSHIP_INVALID')
            present = item['expectedPresent']
            if (present and item['expectedAmount'] is None) or (
                    not present and item['expectedAmount'] is not None):
                raise ValueError('EXPRESSION_CONTEXT_OWNERSHIP_INVALID')
            result.append({'kind':kind,
                'sourceId':_identifier(item['sourceId'],
                    'EXPRESSION_CONTEXT_SOURCE_ID_INVALID'),
                'relationshipId':_identifier(item['relationshipId'],
                    'EXPRESSION_CONTEXT_OWNERSHIP_INVALID'),
                'scenarioId':_identifier(item['scenarioId'],
                    'EXPRESSION_CONTEXT_OWNERSHIP_INVALID'),
                'yearId':_identifier(item['yearId'],
                    'EXPRESSION_CONTEXT_OWNERSHIP_INVALID'),
                'periodId':_identifier(item['periodId'],
                    'EXPRESSION_CONTEXT_OWNERSHIP_INVALID'),
                'account':account,'expectedPresent':present,
                'expectedAmount':(_amount(item['expectedAmount'], account)
                    if present else None),
                'expectedChangeId':_change(item['expectedChangeId'])})
        elif kind == 'CalendarPeriod':
            required = {'kind','sourceId','yearId','periodId','effectiveOn',
                        'expectedChangeId'}
            if set(item) != required or type(item.get('effectiveOn')) is not str:
                raise ValueError('EXPRESSION_CONTEXT_CALENDAR_INVALID')
            try:
                effective = date.fromisoformat(item['effectiveOn'])
            except ValueError as error:
                raise ValueError('EXPRESSION_CONTEXT_CALENDAR_INVALID') from error
            result.append({'kind':kind,
                'sourceId':_identifier(item['sourceId'],
                    'EXPRESSION_CONTEXT_SOURCE_ID_INVALID'),
                'yearId':_identifier(item['yearId'],
                    'EXPRESSION_CONTEXT_CALENDAR_INVALID'),
                'periodId':_identifier(item['periodId'],
                    'EXPRESSION_CONTEXT_CALENDAR_INVALID'),
                'effectiveOn':effective.isoformat(),
                'expectedChangeId':_change(item['expectedChangeId'])})
        else:
            raise ValueError('EXPRESSION_CONTEXT_KIND_UNSUPPORTED')
    ids = [item['sourceId'] for item in result]
    if len(ids) != len(set(ids)):
        raise ValueError('EXPRESSION_CONTEXT_SOURCE_ID_DUPLICATE')
    return tuple(sorted(result, key=lambda item:item['sourceId']))


def normalize_assertions(value: object) -> tuple[dict, ...]:
    if type(value) is not list or not 1 <= len(value) <= 8:
        raise ValueError('EXPRESSION_CONTEXT_ASSERTIONS_INVALID')
    result=[]
    for item in value:
        if (type(item) is not dict or set(item) != {
                'assertionId','name','value','assurance'}
                or type(item.get('value')) is not bool
                or item.get('assurance') != 'CallerDeclaredUnverified'):
            raise ValueError('EXPRESSION_CONTEXT_ASSERTION_INVALID')
        result.append({'assertionId':_identifier(item['assertionId'],
                'EXPRESSION_CONTEXT_ASSERTION_INVALID'),
            'name':_identifier(item['name'],
                'EXPRESSION_CONTEXT_ASSERTION_INVALID'),
            'value':item['value'],'assurance':'CallerDeclaredUnverified'})
    ids=[item['assertionId'] for item in result]
    if len(ids)!=len(set(ids)):
        raise ValueError('EXPRESSION_CONTEXT_ASSERTION_DUPLICATE')
    return tuple(sorted(result,key=lambda item:item['assertionId']))


def normalize_sealed(value: object) -> tuple[dict, ...]:
    if type(value) is not list or not 1 <= len(value) <= 8:
        raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID')
    result=[]
    for item in value:
        if type(item) is not dict or item.get('format') != _FORMAT:
            raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID')
        if item.get('kind') == 'OwnershipValue':
            request_keys={'kind','sourceId','relationshipId','scenarioId','yearId',
                'periodId','account','expectedPresent','expectedAmount',
                'expectedChangeId'}
            extra={'format','lastRevision','relationship','roleDimensions'}
            if set(item)!=request_keys|extra:
                raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID')
            request={key:item[key] for key in request_keys}
            normalized=normalize_requests([request])[0]
            relationship=item['relationship'];roles=item['roleDimensions']
            if (type(item['lastRevision']) is not int or item['lastRevision']<1
                    or type(relationship) is not dict
                    or set(relationship)!={'dimensionId','parentMemberId','childMemberId'}
                    or type(roles) is not dict
                    or set(roles)!={'Entity','Scenario','Year','Period'}):
                raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID')
            for entry in (*relationship.values(),*roles.values()):
                _identifier(entry,'EXPRESSION_CONTEXT_SEALED_INVALID')
            result.append({**normalized,'format':_FORMAT,
                'lastRevision':item['lastRevision'],
                'relationship':dict(relationship),'roleDimensions':dict(roles)})
        elif item.get('kind') == 'CalendarPeriod':
            request_keys={'kind','sourceId','yearId','periodId','effectiveOn',
                          'expectedChangeId'}
            extra={'format','yearDimensionId','periodDimensionId','ordinal',
                   'startsOn','endsBefore','lastRevision'}
            if set(item)!=request_keys|extra:
                raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID')
            normalized=normalize_requests([{key:item[key]
                for key in request_keys}])[0]
            try:
                starts=date.fromisoformat(item['startsOn'])
                ends=date.fromisoformat(item['endsBefore'])
            except (TypeError,ValueError) as error:
                raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID') from error
            if (type(item['ordinal']) is not int or not 1<=item['ordinal']<=366
                    or not starts<ends or type(item['lastRevision']) is not int
                    or item['lastRevision']<1):
                raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID')
            _identifier(item['yearDimensionId'],'EXPRESSION_CONTEXT_SEALED_INVALID')
            _identifier(item['periodDimensionId'],'EXPRESSION_CONTEXT_SEALED_INVALID')
            result.append({**normalized,'format':_FORMAT,
                'yearDimensionId':item['yearDimensionId'],
                'periodDimensionId':item['periodDimensionId'],
                'ordinal':item['ordinal'],'startsOn':starts.isoformat(),
                'endsBefore':ends.isoformat(),'lastRevision':item['lastRevision']})
        else:
            raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID')
    ids=[item['sourceId'] for item in result]
    if len(ids)!=len(set(ids)) or ids!=sorted(ids):
        raise ValueError('EXPRESSION_CONTEXT_SEALED_INVALID')
    return tuple(result)


def requests_from_sealed(value: tuple[dict, ...]) -> tuple[dict, ...]:
    result=[]
    for item in value:
        keys=({'kind','sourceId','relationshipId','scenarioId','yearId',
               'periodId','account','expectedPresent','expectedAmount',
               'expectedChangeId'} if item['kind']=='OwnershipValue' else
              {'kind','sourceId','yearId','periodId','effectiveOn',
               'expectedChangeId'})
        result.append({key:item[key] for key in keys})
    return normalize_requests(result)


def resolve(db, scope, requests: tuple[dict, ...]) -> tuple[dict, ...]:
    keys=(scope.workspace_id,scope.application_id);sealed=[]
    for item in requests:
        if item['kind']=='OwnershipValue':
            query={key:item[key] for key in ('relationshipId','scenarioId',
                'yearId','periodId','account')}
            roles=PostgresOwnershipValues._active_context(db,scope,query)
            relationship=db.execute('''SELECT dimension_id,parent_member_id,
                child_member_id FROM epm.relationship WHERE workspace_id=%s
                AND application_id=%s AND relationship_id=%s AND status='Active'  AND EXISTS(SELECT 1 FROM epm.hierarchy_definition hierarchy
          WHERE hierarchy.workspace_id=relationship.workspace_id AND hierarchy.application_id=relationship.application_id
            AND hierarchy.dimension_id=relationship.dimension_id AND hierarchy.hierarchy_id=relationship.hierarchy_id
            AND hierarchy.status='Active') ''',
                (*keys,item['relationshipId'])).fetchone()
            row=db.execute('''SELECT present,amount,change_id,last_revision
                FROM epm.ownership_value_current WHERE workspace_id=%s
                AND application_id=%s AND relationship_id=%s
                AND scenario_member_id=%s AND year_member_id=%s
                AND period_member_id=%s AND account_name=%s''',(*keys,
                item['relationshipId'],item['scenarioId'],item['yearId'],
                item['periodId'],item['account'])).fetchone()
            actual_present=bool(row and row['present'])
            actual_amount=(format(row['amount'],'.8f') if actual_present else None)
            if (relationship is None or row is None
                    or actual_present!=item['expectedPresent']
                    or actual_amount!=item['expectedAmount']
                    or row['change_id']!=item['expectedChangeId']):
                raise ValueError('EXPRESSION_CONTEXT_OWNERSHIP_STALE')
            sealed.append({**item,'format':_FORMAT,
                'lastRevision':row['last_revision'],
                'relationship':{'dimensionId':relationship['dimension_id'],
                    'parentMemberId':relationship['parent_member_id'],
                    'childMemberId':relationship['child_member_id']},
                'roleDimensions':dict(sorted(roles.items()))})
        else:
            row=db.execute('''SELECT year_dimension_id,period_dimension_id,
                ordinal,starts_on,ends_before,change_id,last_revision
                FROM epm.calendar_period_current WHERE workspace_id=%s
                AND application_id=%s AND year_member_id=%s
                AND period_member_id=%s''',(*keys,item['yearId'],
                item['periodId'])).fetchone()
            effective=date.fromisoformat(item['effectiveOn'])
            if (row is None or not row['starts_on']<=effective<row['ends_before']
                    or row['change_id']!=item['expectedChangeId']):
                raise ValueError('EXPRESSION_CONTEXT_CALENDAR_STALE')
            sealed.append({**item,'format':_FORMAT,
                'yearDimensionId':row['year_dimension_id'],
                'periodDimensionId':row['period_dimension_id'],
                'ordinal':row['ordinal'],'startsOn':row['starts_on'].isoformat(),
                'endsBefore':row['ends_before'].isoformat(),
                'lastRevision':row['last_revision']})
    return normalize_sealed(sealed)


def status(db, scope, sealed: tuple[dict, ...], *, budget: list[int] | None=None) -> dict:
    remaining=budget if budget is not None else [1000]
    if len(sealed)>remaining[0]:
        return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
    remaining[0]-=len(sealed);dependencies=[]
    keys=(scope.workspace_id,scope.application_id)
    for item in sealed:
        matches=False;observed={}
        if item['kind']=='OwnershipValue':
            row=db.execute('''SELECT o.present,o.amount,o.change_id,o.last_revision,
                r.dimension_id,r.parent_member_id,r.child_member_id,r.status,
                EXISTS(SELECT 1 FROM epm.hierarchy_definition hierarchy
                  WHERE hierarchy.workspace_id=r.workspace_id AND hierarchy.application_id=r.application_id
                    AND hierarchy.dimension_id=r.dimension_id AND hierarchy.hierarchy_id=r.hierarchy_id
                    AND hierarchy.status='Active') AS hierarchy_available
                FROM epm.ownership_value_current o LEFT JOIN epm.relationship r
                ON r.workspace_id=o.workspace_id AND r.application_id=o.application_id
                AND r.relationship_id=o.relationship_id WHERE o.workspace_id=%s
                AND o.application_id=%s AND o.relationship_id=%s
                AND o.scenario_member_id=%s AND o.year_member_id=%s
                AND o.period_member_id=%s AND o.account_name=%s''',(*keys,
                item['relationshipId'],item['scenarioId'],item['yearId'],
                item['periodId'],item['account'])).fetchone()
            if row:
                observed={'present':row['present'],'amount':(
                    format(row['amount'],'.8f') if row['present'] else None),
                    'changeId':row['change_id'],'lastRevision':row['last_revision']}
                relation=item['relationship']
                matches=(row['status']=='Active' and row['hierarchy_available']
                    and row['present']==item['expectedPresent']
                    and observed['amount']==item['expectedAmount']
                    and row['change_id']==item['expectedChangeId']
                    and row['last_revision']==item['lastRevision']
                    and row['dimension_id']==relation['dimensionId']
                    and row['parent_member_id']==relation['parentMemberId']
                    and row['child_member_id']==relation['childMemberId'])
        else:
            row=db.execute('''SELECT year_dimension_id,period_dimension_id,
                ordinal,starts_on,ends_before,change_id,last_revision
                FROM epm.calendar_period_current WHERE workspace_id=%s
                AND application_id=%s AND year_member_id=%s
                AND period_member_id=%s''',(*keys,item['yearId'],
                item['periodId'])).fetchone()
            if row:
                effective=date.fromisoformat(item['effectiveOn'])
                observed={'startsOn':row['starts_on'].isoformat(),
                    'endsBefore':row['ends_before'].isoformat(),
                    'changeId':row['change_id'],'lastRevision':row['last_revision']}
                matches=(row['year_dimension_id']==item['yearDimensionId']
                    and row['period_dimension_id']==item['periodDimensionId']
                    and row['ordinal']==item['ordinal']
                    and observed['startsOn']==item['startsOn']
                    and observed['endsBefore']==item['endsBefore']
                    and row['starts_on']<=effective<row['ends_before']
                    and row['change_id']==item['expectedChangeId']
                    and row['last_revision']==item['lastRevision'])
        dependencies.append({'sourceId':item['sourceId'],'kind':item['kind'],
            'matchesAtRead':matches,'observed':observed})
    return {'matchesAtRead':all(item['matchesAtRead'] for item in dependencies),
        'truncated':False,'dependencies':dependencies}


def require_current(db, scope, sealed: tuple[dict, ...]) -> dict:
    result=status(db,scope,sealed)
    if not result['matchesAtRead']:
        raise ValueError('EXPRESSION_CONTEXT_DEPENDENCY_STALE')
    return result
