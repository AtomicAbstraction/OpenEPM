"""Explicit fiscal Year/Period ranges for the PostgreSQL EPM model.

Period names never imply dates or ordering. This metadata is an input to
planning schedules and consolidation policy-effective-date validation.
"""
from __future__ import annotations

from datetime import date
import re
import uuid

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


SET_FUNCTION='metadata.calendar.period.set'
READ_FUNCTION='metadata.calendar.period.read'
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def _program(program: object,function: str) -> dict:
    if (not isinstance(program,dict)
            or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion']!=2 or program['function']!=function
            or not isinstance(program['arguments'],dict)):
        raise ValueError('V2_CALENDAR_FUNCTION_INVALID')
    args=program['arguments']
    required={'yearId','periodId'}
    if function==SET_FUNCTION:
        required|={'ordinal','startsOn','endsBefore','expectedChangeId',
                   'expectedMetadataRevision'}
    if set(args)!=required or any(not isinstance(args[key],str)
                                 or not 1<=len(args[key])<=200
                                 for key in ('yearId','periodId')):
        raise ValueError('V2_CALENDAR_ARGUMENTS_INVALID')
    result={'yearId':args['yearId'],'periodId':args['periodId']}
    if function==SET_FUNCTION:
        if (type(args['ordinal']) is not int
                or not 1<=args['ordinal']<=366
                or type(args['expectedMetadataRevision']) is not int
                or args['expectedMetadataRevision']<0
                or not isinstance(args['expectedChangeId'],str)
                or len(args['expectedChangeId'])>200):
            raise ValueError('V2_CALENDAR_ARGUMENTS_INVALID')
        dates=[]
        for key in ('startsOn','endsBefore'):
            raw=args[key]
            if not isinstance(raw,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',raw):
                raise ValueError('CALENDAR_ISO_DATE_REQUIRED')
            try:
                parsed=date.fromisoformat(raw)
            except ValueError as error:
                raise ValueError('CALENDAR_ISO_DATE_REQUIRED') from error
            if parsed.isoformat()!=raw:
                raise ValueError('CALENDAR_ISO_DATE_REQUIRED')
            dates.append(parsed)
        if dates[0]>=dates[1]:
            raise ValueError('CALENDAR_PERIOD_RANGE_INVALID')
        result.update({'ordinal':args['ordinal'],'startsOn':dates[0],
                       'endsBefore':dates[1],
                       'expectedChangeId':args['expectedChangeId'],
                       'expectedMetadataRevision':
                           args['expectedMetadataRevision']})
    return result


class PostgresCalendarPeriods:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def _roles(db,scope: ApplicationScope,query: dict) -> dict:
        roles={}
        for row in db.execute('''SELECT dimension_id,model_role
            FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
            AND model_role IN ('Year','Period') AND status='Active' ''',
            (scope.workspace_id,scope.application_id)).fetchall():
            if row['model_role'] in roles:
                raise ValueError('CALENDAR_MODEL_ROLE_AMBIGUOUS')
            roles[row['model_role']]=row['dimension_id']
        if set(roles)!={'Year','Period'}:
            raise ValueError('CALENDAR_MODEL_ROLES_REQUIRED')
        for role,member_id in (('Year',query['yearId']),
                               ('Period',query['periodId'])):
            found=db.execute('''SELECT 1 FROM epm.member
                WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND member_id=%s AND status='Active' ''',
                (scope.workspace_id,scope.application_id,
                 roles[role],member_id)).fetchone()
            if not found:
                raise ValueError('CALENDAR_CONTEXT_MEMBER_UNAVAILABLE')
        return roles

    def read(self,scope: ApplicationScope,program: object) -> dict:
        query=_program(program,READ_FUNCTION)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                state=db.execute('''SELECT metadata_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                self._roles(db,scope,query)
                row=db.execute('''SELECT ordinal,starts_on,ends_before,
                    change_id,last_revision FROM epm.calendar_period_current
                    WHERE workspace_id=%s AND application_id=%s
                    AND year_member_id=%s AND period_member_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     query['yearId'],query['periodId'])).fetchone()
                return {'yearId':query['yearId'],
                        'periodId':query['periodId'],
                        'defined':row is not None,
                        'ordinal':row['ordinal'] if row else None,
                        'startsOn':row['starts_on'].isoformat() if row else None,
                        'endsBefore':row['ends_before'].isoformat()
                            if row else None,
                        'changeId':row['change_id'] if row else '',
                        'metadataRevision':state['metadata_revision'],
                        'commitRevision':state['commit_revision']}

    def set(self,scope: ApplicationScope,program: object,*,
            idempotency_key: str) -> dict:
        query=_program(program,SET_FUNCTION)
        if (not isinstance(idempotency_key,str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('CALENDAR_IDEMPOTENCY_KEY_INVALID')
        digest=_canonical_digest({
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'query':{**query,'startsOn':query['startsOn'].isoformat(),
                     'endsBefore':query['endsBefore'].isoformat()}})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                state=db.execute('''SELECT s.metadata_revision,
                    s.commit_revision,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin')
                previous=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key)).fetchone()
                if previous:
                    if (previous['command_digest']!=digest
                            or previous['actor_id']!=self.identity.subject_id):
                        raise ValueError('CALENDAR_IDEMPOTENCY_CONFLICT')
                    return previous['result']
                if (state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision']!=
                        query['expectedMetadataRevision']):
                    raise ValueError('STALE_CALENDAR_METADATA_REVISION')
                roles=self._roles(db,scope,query)
                current=db.execute('''SELECT change_id FROM
                    epm.calendar_period_current
                    WHERE workspace_id=%s AND application_id=%s
                    AND year_member_id=%s AND period_member_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     query['yearId'],query['periodId'])).fetchone()
                if (current['change_id'] if current else '')!=query[
                        'expectedChangeId']:
                    raise ValueError('STALE_CALENDAR_CHANGE_ID')
                overlap=db.execute('''SELECT 1 FROM epm.calendar_period_current
                    WHERE workspace_id=%s AND application_id=%s
                    AND (year_member_id,period_member_id)
                        IS DISTINCT FROM (%s,%s)
                    AND daterange(starts_on,ends_before,'[)') &&
                        daterange(%s,%s,'[)') LIMIT 1''',
                    (scope.workspace_id,scope.application_id,
                     query['yearId'],query['periodId'],
                     query['startsOn'],query['endsBefore'])).fetchone()
                if overlap:
                    raise ValueError('CALENDAR_PERIOD_OVERLAP')
                ordinal_conflict=db.execute('''SELECT 1 FROM
                    epm.calendar_period_current WHERE workspace_id=%s
                    AND application_id=%s AND year_member_id=%s
                    AND period_member_id<>%s AND ordinal=%s LIMIT 1''',
                    (scope.workspace_id,scope.application_id,
                     query['yearId'],query['periodId'],
                     query['ordinal'])).fetchone()
                if ordinal_conflict:
                    raise ValueError('CALENDAR_ORDINAL_CONFLICT')
                change_id=uuid.uuid4().hex
                revision=state['commit_revision']+1
                metadata_revision=state['metadata_revision']+1
                result={'operationId':idempotency_key,
                        'yearId':query['yearId'],
                        'periodId':query['periodId'],
                        'ordinal':query['ordinal'],
                        'startsOn':query['startsOn'].isoformat(),
                        'endsBefore':query['endsBefore'].isoformat(),
                        'changeId':change_id,
                        'metadataRevision':metadata_revision,
                        'committedRevision':revision}
                db.execute('''UPDATE epm.application_state SET
                    metadata_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (metadata_revision,revision,
                     scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key,digest,self.identity.subject_id,
                     revision,Jsonb(result)))
                common=(scope.workspace_id,scope.application_id,
                        roles['Year'],query['yearId'],
                        roles['Period'],query['periodId'],
                        query['ordinal'],query['startsOn'],
                        query['endsBefore'])
                db.execute('''INSERT INTO epm.calendar_period_event
                    (workspace_id,application_id,operation_id,
                     year_dimension_id,year_member_id,
                     period_dimension_id,period_member_id,ordinal,
                     starts_on,ends_before,previous_change_id,change_id,
                     committed_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*common[:2],idempotency_key,*common[2:],
                     query['expectedChangeId'],change_id,revision))
                db.execute('''INSERT INTO epm.calendar_period_current
                    (workspace_id,application_id,year_dimension_id,
                     year_member_id,period_dimension_id,period_member_id,
                     ordinal,starts_on,ends_before,change_id,last_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,
                        year_member_id,period_member_id) DO UPDATE SET
                    ordinal=EXCLUDED.ordinal,
                    starts_on=EXCLUDED.starts_on,
                    ends_before=EXCLUDED.ends_before,
                    change_id=EXCLUDED.change_id,
                    last_revision=EXCLUDED.last_revision''',
                    (*common,change_id,revision))
                return result
