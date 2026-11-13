"""Durable fixed-core execution of immutable published application rules."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied,PostgresAccessChecker,
                              VerifiedIdentity,durable_authority_fields)
from .postgres_application_rules import (RUN, RUN_CANCEL, RUN_READ,
    RUN_RECONCILE,
    STORED_FUNCTION,
    PostgresApplicationRules, SealedApplicationRule)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_jobs import PostgresJobQueue, _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_python_build_validator import PostgresPythonBuildOperationValidator
from .python_plan_runner import ChildOutcome, SealedPlanRunner
from .python_program_execution import (SealedPlan, UnitCheckpoint,
                                       WorkflowRecord, WorkflowStatus,
                                       verify_plan_identity)


_HEX32=re.compile(r'^[0-9a-f]{32}$')
_KEY=re.compile(r'^[A-Za-z0-9._-]{8,128}$')


def parse_program(program: object, function: str):
    field='ruleId' if function==RUN else 'workflowId'
    pattern=None if function==RUN else _HEX32
    if (type(program) is not dict
            or set(program)!={'languageVersion','function','arguments'}
            or program.get('languageVersion')!=2
            or program.get('function')!=function
            or type(program.get('arguments')) is not dict
            or (set(program['arguments']) not in ({field},{field,'bindings'},
                {field,'expectedStateToken','expectedProgramDigest'},
                {field,'bindings','expectedStateToken','expectedProgramDigest'})
                if function==RUN else set(program['arguments'])!={field})
            or type(program['arguments'][field]) is not str
            or (pattern is not None and
                pattern.fullmatch(program['arguments'][field]) is None)):
        raise ValueError('APPLICATION_RULE_WORKFLOW_PROGRAM_INVALID')
    if function==RUN:
        bindings=program['arguments'].get('bindings',{})
        if type(bindings) is not dict:
            raise ValueError('APPLICATION_RULE_WORKFLOW_PROGRAM_INVALID')
        args=program['arguments']
        if 'expectedStateToken' in args and (
                type(args['expectedStateToken']) is not str
                or re.fullmatch(r'[0-9a-f]{64}',args['expectedStateToken']) is None
                or type(args['expectedProgramDigest']) is not str
                or re.fullmatch(r'[0-9a-f]{64}',args['expectedProgramDigest']) is None):
            raise ValueError('APPLICATION_RULE_WORKFLOW_PROGRAM_INVALID')
        return {'ruleId':args[field],'bindings':bindings,
            **({key:args[key] for key in ('expectedStateToken','expectedProgramDigest')}
               if 'expectedStateToken' in args else {})}
    return program['arguments'][field]


def _result(record: WorkflowRecord, metadata: dict | None=None) -> dict:
    retained={} if metadata is None else {key:metadata[key] for key in
        ('bindings','bindingDigest','bindingRequestDigest','argumentsDigest',
         'memberListPins',
         )
        if key in metadata}
    return {**retained,'planDigest':record.plan_digest,'unitCount':record.unit_count,
        'checkpoints':[{'ordinal':item.ordinal,'jobId':item.job_id,
            'committed':item.committed,'receiptId':item.receipt_id}
            for item in record.checkpoints]}


def _admitted_tail_ordinal(checkpoints,children):
    """Recognize only the valid admission-before-checkpoint transaction gap."""
    checkpoint_ordinals=set(checkpoints)
    if checkpoint_ordinals!=set(range(1,len(checkpoints)+1)):
        raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
    uncheckpointed=set(children)-checkpoint_ordinals
    if not uncheckpointed:
        return None
    tail=len(checkpoints)+1
    if uncheckpointed!={tail}:
        raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
    return tail


def _record(row) -> WorkflowRecord:
    result=row['result']
    checkpoints=tuple(UnitCheckpoint(item['ordinal'],item['jobId'],
        item['committed'],item.get('receiptId'))
        for item in result.get('checkpoints',[]))
    return WorkflowRecord(ApplicationScope(row['workspace_id'],
        row['application_id']),row['workflow_id'],row['plan_digest'][:32],
        row['plan_digest'],result['unitCount'],WorkflowStatus(row['status']),
        checkpoints)


def _wire(record: WorkflowRecord, *, rule_id: str | None = None,
          state_token: str | None = None,binding_metadata: dict | None=None) -> dict:
    value={'workflowId':record.workflow_id,'planDigest':record.plan_digest,
        'status':record.status.value,'unitCount':record.unit_count,
        'committedUnits':record.committed_units,
        'remainingUnits':record.remaining_units,
        'checkpoints':[{'ordinal':item.ordinal,'jobId':item.job_id,
            'committed':item.committed,'receiptId':item.receipt_id}
            for item in record.checkpoints]}
    if rule_id is not None:value.update(ruleId=rule_id,stateToken=state_token)
    if binding_metadata is not None:
        value.update({key:binding_metadata[key] for key in
            ('bindings','bindingDigest','argumentsDigest','memberListPins')
            if key in binding_metadata})
    return value


def workflow_id(scope: ApplicationScope, identity: VerifiedIdentity,
                idempotency_key: str,*,schema_epoch: int,plan_digest: str) -> str:
    if (type(schema_epoch) is not int or schema_epoch<0
            or type(plan_digest) is not str or re.fullmatch(r"[0-9a-f]{64}",plan_digest) is None):
        raise ValueError("APPLICATION_RULE_WORKFLOW_IDENTITY_INVALID")
    raw=json.dumps({'domain':'openepm-application-rule-workflow-v2',
        'schemaEpoch':schema_epoch,'planDigest':plan_digest,
        'scope':[scope.workspace_id,scope.application_id],
        'identity':[identity.issuer,identity.subject_id],
        'idempotencyKey':idempotency_key},sort_keys=True,separators=(',',':'),
        ensure_ascii=True).encode('ascii')
    return sha256(raw).hexdigest()[:32]


def rule_workflow_request_digest(scope: ApplicationScope,
        identity: VerifiedIdentity, idempotency_key: str,
        sealed: SealedApplicationRule) -> str:
    descriptor={'scope':[scope.workspace_id,scope.application_id],
        'identity':[identity.issuer,identity.subject_id],
        'idempotencyKey':idempotency_key,'rulePin':dict(sealed.pin),
        'planDigest':sealed.plan.digest}
    raw=json.dumps(descriptor,sort_keys=True,separators=(',',':'),
        ensure_ascii=True,allow_nan=False).encode('ascii')
    return sha256(raw).hexdigest()


class _JobInspector:
    def __init__(self,queue):self.queue=queue
    def inspect(self,scope,job_id):
        value=self.queue.read(scope,job_id)
        receipt=(job_id if value['status']=='published' and
                 value.get('receipt_revision') is not None else None)
        return ChildOutcome(job_id,value['status'],receipt)
    def request_cancel(self,scope,job_id):
        self.queue.request_cancel(scope,job_id)


class PostgresApplicationRuleWorkflowStore:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity,worker_claim=None):
        if type(dsn) is not str or not dsn or not isinstance(identity,VerifiedIdentity):
            raise ValueError('APPLICATION_RULE_WORKFLOW_CONFIGURATION_INVALID')
        if worker_claim is not None and (type(worker_claim) is not dict or
                not {'workspace_id','application_id','workflow_id',
                     'claim_generation','claimant'}<=set(worker_claim)):
            raise ValueError('APPLICATION_RULE_WORKER_CLAIM_INVALID')
        self.dsn,self.identity,self.worker_claim=dsn,identity,worker_claim

    @staticmethod
    def _scope(db,scope):PostgresNumericFactStore._set_scope(db,scope)

    def _authorize(self,db,scope):
        PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write')
        return PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,'rule_run')

    def _authorization_scope_digest(self,db,scope,*,access=None):
        return resolve_effective_dimensional_scope(db,self.identity,scope,
            access=access,function=RUN).scope_digest

    def _assert_authorization_scope(self,db,scope,row,*,access=None):
        current=self._authorization_scope_digest(db,scope,access=access)
        if (row.get('authorization_scope_digest') is None
                or row['authorization_scope_digest']!=current):
            raise AccessDenied(
                'APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
        return current

    @staticmethod
    def child_idempotency_key(workflow,ordinal):
        return f'rule-{workflow.workflow_id}-{ordinal}'

    @staticmethod
    def _verify_current(db,scope,row) -> None:
        state=db.execute('''SELECT metadata_revision,policy_revision,schema_epoch
            FROM epm.application_state WHERE workspace_id=%s AND application_id=%s
            ''',(scope.workspace_id,scope.application_id)).fetchone()
        publication=db.execute('''SELECT * FROM epm.expression_rule_definition
            WHERE workspace_id=%s AND application_id=%s AND rule_id=%s''',(
            scope.workspace_id,scope.application_id,row['rule_id'])).fetchone()
        if (state is None or publication is None
                or publication['status']!='Active'
                or publication['state_token']!=row['rule_state_token']
                or publication['program_digest']!=row['program_digest']
                or publication.get('definition_kind')!='ApplicationRule'
                or not isinstance(publication.get('program'),dict)
                or publication['program'].get('function')!=STORED_FUNCTION
                or _canonical_digest(publication['program'])!=row['program_digest']):
            raise ValueError('APPLICATION_RULE_WORKFLOW_PUBLICATION_STALE')
        from .postgres_definition_lifecycle import assert_current_executable
        assert_current_executable(db,scope,publication)
        certificate_digest=row.get('owner_certificate_digest')
        if (type(certificate_digest) is not str
                or re.fullmatch(r'[0-9a-f]{64}',certificate_digest) is None
                or not isinstance(publication.get('current_certificate'),dict)
                or _canonical_digest(publication['current_certificate'])!=certificate_digest):
            raise ValueError('APPLICATION_RULE_WORKFLOW_OWNER_CERTIFICATE_STALE')
        if ((state['metadata_revision'],state['policy_revision'],state['schema_epoch'])
                !=(row['expected_metadata_revision'],row['expected_policy_revision'],
                   row['expected_schema_epoch'])):
            raise ValueError('APPLICATION_RULE_WORKFLOW_CONTEXT_STALE')

    def create_or_read_rule(self,workflow: WorkflowRecord,
            sealed: SealedApplicationRule,*,idempotency_key: str,
            request_digest: str) -> WorkflowRecord:
        if (workflow.plan_digest!=sealed.plan.digest
                or workflow.build_id!=sealed.plan.digest[:32]):
            raise ValueError('APPLICATION_RULE_WORKFLOW_PLAN_MISMATCH')
        pin=sealed.pin
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,10000);self._scope(db,workflow.scope)
                PostgresAccessChecker.lock_workspace(db,workflow.scope.workspace_id)
                access=self._authorize(db,workflow.scope)
                authorization_scope_digest=self._authorization_scope_digest(
                    db,workflow.scope,access=access)
                prior=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                      AND subject_id=%s AND idempotency_key=%s FOR UPDATE''',
                    (workflow.scope.workspace_id,workflow.scope.application_id,
                     self.identity.issuer,self.identity.subject_id,
                     idempotency_key)).fetchone()
                if prior is not None:
                    if (prior['request_digest']!=request_digest
                            or prior['plan_digest']!=workflow.plan_digest
                            or prior['rule_id']!=pin['ruleId']
                            or prior['rule_state_token']!=pin['stateToken']
                            or prior['program_digest']!=pin['programDigest']
                            or prior['owner_certificate_digest']!=pin['owner_certificate_digest']):
                        raise ValueError('APPLICATION_RULE_WORKFLOW_IDEMPOTENCY_CONFLICT')
                    if (prior['authorization_scope_digest'] is None
                            or prior['authorization_scope_digest']!=
                               authorization_scope_digest):
                        raise AccessDenied(
                            'APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
                    return _record(prior)
                current={'rule_id':pin['ruleId'],
                    'rule_state_token':pin['stateToken'],
                    'program_digest':pin['programDigest'],
                    'owner_certificate_digest':pin['owner_certificate_digest'],
                    'expected_metadata_revision':pin['metadataRevision'],
                    'expected_policy_revision':pin['policyRevision'],
                    'expected_schema_epoch':pin['schemaEpoch']}
                self._verify_current(db,workflow.scope,current)
                token_issued_at,authority_kind=durable_authority_fields(
                    self.identity)
                row=db.execute('''INSERT INTO epm.application_rule_workflow(
                    workspace_id,application_id,workflow_id,rule_id,rule_state_token,
                    program_digest,owner_certificate_digest,sealed_plan,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_policy_revision,expected_schema_epoch,issuer,
                    subject_id,idempotency_key,request_digest,status,result,
                    verified_groups,authorization_scope_digest,
                    token_issued_at,authority_kind)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                           %s,%s,%s,'accepted',%s,%s,%s,%s,%s) RETURNING *''',(
                    workflow.scope.workspace_id,workflow.scope.application_id,
                    workflow.workflow_id,pin['ruleId'],pin['stateToken'],
                    pin['programDigest'],pin['owner_certificate_digest'],
                    Jsonb(sealed.plan.canonical_plan),sealed.plan.digest,
                    sealed.plan.compiler_version,pin['metadataRevision'],
                    pin['policyRevision'],pin['schemaEpoch'],self.identity.issuer,
                    self.identity.subject_id,idempotency_key,request_digest,
                    Jsonb(_result(workflow,dict(sealed.pin))),
                    list(access.groups),
                    authorization_scope_digest,token_issued_at,
                    authority_kind)).fetchone()
                return _record(row)

    def read(self,scope,workflow_id):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db,5000);self._scope(db,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND issuer=%s AND subject_id=%s''',(scope.workspace_id,
                    scope.application_id,workflow_id,self.identity.issuer,
                    self.identity.subject_id)).fetchone()
                if row is None:raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                self._assert_authorization_scope(db,scope,row,access=access)
                return _record(row)

    def read_by_idempotency_key(self,scope,idempotency_key,*,expected_schema_epoch=None):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db,5000);self._scope(db,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                      AND subject_id=%s AND idempotency_key=%s''',(
                    scope.workspace_id,scope.application_id,self.identity.issuer,
                    self.identity.subject_id,idempotency_key)).fetchone()
                if row is None:return None
                if expected_schema_epoch is not None and row['expected_schema_epoch']!=expected_schema_epoch:
                    raise ValueError('APPLICATION_SCHEDULE_OCCURRENCE_STALE_CLAIM')
                self._assert_authorization_scope(db,scope,row,access=access)
                return (row['rule_id'],row['rule_state_token'],_record(row),
                        {**row['result'],'programDigest':row['program_digest']})

    def request_cancel_as_task_controller(self,scope,workflow_id,*,
            allow_application_admin=False):
        if (type(workflow_id) is not str or _HEX32.fullmatch(workflow_id) is None
                or type(allow_application_admin) is not bool):
            raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000);self._scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,
                    'rule_run',function=RUN)
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s
                      AND workflow_id=%s FOR UPDATE''',(scope.workspace_id,
                    scope.application_id,workflow_id)).fetchone()
                if row is None:
                    raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                owner=((row['issuer'],row['subject_id'])==
                       (self.identity.issuer,self.identity.subject_id))
                if not owner:
                    if not allow_application_admin:
                        raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                    try:
                        PostgresAccessChecker.check_in_transaction(
                            db,self.identity,scope,'admin')
                    except AccessDenied as error:
                        raise ValueError(
                            'APPLICATION_RULE_WORKFLOW_UNAVAILABLE') from error
                current=_record(row);updated=current.request_cancel()
                if updated==current:return current
                changed=db.execute('''UPDATE epm.application_rule_workflow
                    SET status=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                      AND workflow_id=%s AND status=%s''',(updated.status.value,
                    scope.workspace_id,scope.application_id,workflow_id,
                    current.status.value)).rowcount
                if changed!=1:
                    raise ValueError('APPLICATION_RULE_WORKFLOW_STALE_CONTROL_STATE')
                return updated

    def reconcile_needs_inspection(self,scope,workflow_id,*,idempotency_key):
        """Inspect durable children and make an uncertain workflow claimable.

        This never rebuilds a plan, submits a child or claims that an effect
        committed. The ordinary runner subsequently replays exact idempotent
        admission and reconciles receipts one checkpoint at a time.
        """
        if (type(workflow_id) is not str or _HEX32.fullmatch(workflow_id) is None
                or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None):
            raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,10000);self._scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s
                      AND workflow_id=%s FOR UPDATE''',(scope.workspace_id,
                    scope.application_id,workflow_id)).fetchone()
                if row is None:
                    raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                owner=((row['issuer'],row['subject_id'])==
                       (self.identity.issuer,self.identity.subject_id))
                try:
                    access=PostgresAccessChecker.check_in_transaction(db,self.identity,
                        scope,'rule_run',function=RUN_RECONCILE)
                    if not owner:
                        PostgresAccessChecker.check_in_transaction(
                            db,self.identity,scope,'admin',
                            function=RUN_RECONCILE)
                except AccessDenied as error:
                    raise ValueError(
                        'APPLICATION_RULE_WORKFLOW_UNAVAILABLE') from error
                self._assert_authorization_scope(db,scope,row,access=access)
                prior=row['result'].get('reconciliation')
                if (isinstance(prior,dict)
                        and prior.get('operationId')==idempotency_key):
                    if prior.get('actor')!=[self.identity.issuer,
                                            self.identity.subject_id]:
                        raise ValueError(
                            'APPLICATION_RULE_WORKFLOW_RECONCILE_IDEMPOTENCY_CONFLICT')
                    return {'workflowId':workflow_id,
                        'status':prior['resultStatus'],
                        'observedChildren':prior['observedChildren'],
                        'observedCount':prior['observedCount'],
                        'unitCount':prior['unitCount']}
                if (row['status']!='needs_inspection'
                        or row['claimant'] is not None
                        or row['lease_until'] is not None):
                    raise ValueError(
                        'APPLICATION_RULE_WORKFLOW_RECONCILE_NOT_AVAILABLE')
                self._verify_current(db,scope,row)
                canonical=row['sealed_plan']
                raw=json.dumps(canonical,sort_keys=True,separators=(',',':'),
                    ensure_ascii=True,allow_nan=False).encode('ascii')
                if sha256(raw).hexdigest()!=row['plan_digest']:
                    raise ValueError('APPLICATION_RULE_STORED_PLAN_INVALID')
                units=canonical.get('units') if type(canonical) is dict else None
                if (type(units) is not list or not units
                        or len(units)!=row['result'].get('unitCount')):
                    raise ValueError('APPLICATION_RULE_STORED_PLAN_INVALID')
                record=_record(row);expected=[]
                for ordinal,unit in enumerate(units,1):
                    operation=SealedPlanRunner._atomic_operation(unit)
                    expected.append((ordinal,operation['function'],
                        self.child_idempotency_key(record,ordinal)))
                jobs=db.execute('''SELECT job_id,idempotency_key,function_name,
                    status,receipt_revision FROM epm.job WHERE workspace_id=%s
                    AND application_id=%s AND issuer=%s AND subject_id=%s
                    AND idempotency_key=ANY(%s::text[])''',(scope.workspace_id,
                    scope.application_id,row['issuer'],row['subject_id'],
                    [item[2] for item in expected])).fetchall()
                by_key={job['idempotency_key']:job for job in jobs}
                children=db.execute('''SELECT unit_ordinal,job_id FROM
                    epm.application_rule_workflow_child WHERE workspace_id=%s
                    AND application_id=%s AND workflow_id=%s ORDER BY
                    unit_ordinal''',(scope.workspace_id,scope.application_id,
                    workflow_id)).fetchall()
                child_by_ordinal={item['unit_ordinal']:item['job_id']
                                  for item in children}
                observed=[];gap=False
                for ordinal,function,key in expected:
                    job=by_key.get(key)
                    if job is None:
                        gap=True;continue
                    if gap or job['function_name']!=function or (
                            ordinal in child_by_ordinal and
                            child_by_ordinal[ordinal]!=job['job_id']):
                        raise ValueError(
                            'APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
                    observed.append({'ordinal':ordinal,'jobId':job['job_id'],
                        'status':job['status'],
                        'receiptPresent':job['status']=='published' and
                            job['receipt_revision'] is not None})
                result=dict(row['result']);result.pop('errorCode',None)
                result['reconciliation']={'observedChildren':observed,
                    'observedCount':len(observed),'unitCount':len(units),
                    'previousWorkerFailures':row['worker_failures'],
                    'previousErrorCode':row['worker_error_code'],
                    'resultStatus':'running',
                    'operationId':idempotency_key,
                    'actor':[self.identity.issuer,self.identity.subject_id]}
                changed=db.execute('''UPDATE epm.application_rule_workflow SET
                    status='running',result=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                      AND workflow_id=%s AND status='needs_inspection'
                      AND claimant IS NULL AND lease_until IS NULL''',(Jsonb(result),
                    scope.workspace_id,scope.application_id,workflow_id)).rowcount
                if changed!=1:
                    raise ValueError(
                        'APPLICATION_RULE_WORKFLOW_STALE_CONTROL_STATE')
                return {'workflowId':workflow_id,'status':'running',
                    'observedChildren':observed,'observedCount':len(observed),
                    'unitCount':len(units)}

    def details(self,scope,workflow_id):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._scope(db,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                row=db.execute('''SELECT * FROM
                    epm.application_rule_workflow WHERE workspace_id=%s
                    AND application_id=%s AND workflow_id=%s AND issuer=%s
                    AND subject_id=%s''',(scope.workspace_id,scope.application_id,
                    workflow_id,self.identity.issuer,
                    self.identity.subject_id)).fetchone()
                if row is None:raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                self._assert_authorization_scope(db,scope,row,access=access)
                return row['rule_id'],row['rule_state_token'],row['result']

    def lineage(self,scope,workflow_id):
        """Return the sealed parent/child/receipt chain and current freshness.

        This is a read of authoritative workflow, job and publication state.
        It never rebuilds the plan and never treats a UI/task projection as a
        receipt.  Stale dependencies are reported instead of hiding historical
        lineage behind a current-context exception.
        """
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s
                      AND workflow_id=%s AND issuer=%s AND subject_id=%s''',(
                    scope.workspace_id,scope.application_id,workflow_id,
                    self.identity.issuer,self.identity.subject_id)).fetchone()
                if row is None:
                    raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                self._assert_authorization_scope(db,scope,row,access=access)
                state=db.execute('''SELECT metadata_revision,policy_revision,
                    schema_epoch FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',(
                    scope.workspace_id,scope.application_id)).fetchone()
                publication=db.execute('''SELECT state_token,status,
                    program_digest,program
                    FROM epm.expression_rule_definition
                    WHERE workspace_id=%s AND application_id=%s
                      AND rule_id=%s''',(scope.workspace_id,
                    scope.application_id,row['rule_id'])).fetchone()
                children=db.execute('''SELECT c.unit_ordinal,c.job_id,
                    j.function_name,j.status,j.program_digest,j.plan_digest,
                    j.receipt_revision,j.error_code
                    FROM epm.application_rule_workflow_child c
                    JOIN epm.job j ON j.workspace_id=c.workspace_id
                     AND j.application_id=c.application_id
                     AND j.job_id=c.job_id
                    WHERE c.workspace_id=%s AND c.application_id=%s
                      AND c.workflow_id=%s ORDER BY c.unit_ordinal''',(
                    scope.workspace_id,scope.application_id,
                    workflow_id)).fetchall()
                job_ids=[child['job_id'] for child in children]
                dependencies=(db.execute('''SELECT job_id,depends_on_job_id
                    FROM epm.job_dependency WHERE workspace_id=%s
                      AND application_id=%s AND job_id=ANY(%s::text[])
                    ORDER BY job_id,depends_on_job_id''',(scope.workspace_id,
                    scope.application_id,job_ids)).fetchall()
                    if job_ids else [])
        canonical=row['sealed_plan']
        raw=json.dumps(canonical,sort_keys=True,separators=(',',':'),
            ensure_ascii=True,allow_nan=False).encode('ascii')
        if sha256(raw).hexdigest()!=row['plan_digest']:
            raise ValueError('APPLICATION_RULE_STORED_PLAN_INVALID')
        units=canonical.get('units') if type(canonical) is dict else None
        if type(units) is not list or len(units)!=row['result'].get('unitCount'):
            raise ValueError('APPLICATION_RULE_STORED_PLAN_INVALID')
        by_ordinal={child['unit_ordinal']:child for child in children}
        dependency_map={job_id:[] for job_id in job_ids}
        for dependency in dependencies:
            dependency_map[dependency['job_id']].append(
                dependency['depends_on_job_id'])
        checkpoints={item['ordinal']:item
            for item in row['result'].get('checkpoints',[])}
        admitted_tail=_admitted_tail_ordinal(checkpoints,by_ordinal)
        chain=[];previous_job=None
        for ordinal,unit in enumerate(units,1):
            operation=SealedPlanRunner._atomic_operation(unit)
            child=by_ordinal.get(ordinal);checkpoint=checkpoints.get(ordinal)
            if child is not None and child['function_name']!=operation['function']:
                raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
            if (checkpoint is not None and child is None
                    or child is not None and checkpoint is None
                       and ordinal!=admitted_tail
                    or child is not None and checkpoint is not None and
                    checkpoint.get('jobId')!=child['job_id']):
                raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
            actual_dependencies=([] if child is None else
                                 dependency_map[child['job_id']])
            expected_dependencies=([] if previous_job is None else
                                   [previous_job])
            if child is not None and actual_dependencies!=expected_dependencies:
                raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
            committed=bool(checkpoint and checkpoint.get('committed'))
            receipt_id=(checkpoint.get('receiptId') if checkpoint else None)
            receipt_revision=(child['receipt_revision'] if child else None)
            if committed and (receipt_id!=child['job_id']
                              or receipt_revision is None):
                raise ValueError('APPLICATION_RULE_WORKFLOW_RECEIPT_CONFLICT')
            chain.append({'ordinal':ordinal,'unitName':unit['name'],
                'function':operation['function'],
                'jobId':None if child is None else child['job_id'],
                'jobStatus':'not_admitted' if child is None else child['status'],
                'programDigest':None if child is None else
                    child['program_digest'],
                'childPlanDigest':None if child is None else
                    child['plan_digest'],
                'dependsOnJobIds':actual_dependencies,
                'committed':committed,'receiptId':receipt_id,
                'receiptRevision':receipt_revision,
                'errorCode':None if child is None else child['error_code']})
            if child is not None:previous_job=child['job_id']
        reasons=[]
        publication_current=(publication is not None
            and publication['status']=='Active'
            and publication['state_token']==row['rule_state_token']
            and publication['program_digest']==row['program_digest']
            and publication['program'].get('function')==STORED_FUNCTION)
        if not publication_current:reasons.append('publication')
        expected=(row['expected_metadata_revision'],
                  row['expected_policy_revision'],row['expected_schema_epoch'])
        current=(None,None,None) if state is None else (
            state['metadata_revision'],state['policy_revision'],
            state['schema_epoch'])
        for name,expected_value,current_value in zip(
                ('metadata','policy','schema'),expected,current):
            if expected_value!=current_value:reasons.append(name)
        lineage_complete=(row['status']=='published' and len(chain)==len(units)
            and all(item['committed'] and item['jobStatus']=='published'
                    and item['receiptId'] and item['receiptRevision']
                    for item in chain))
        return {**_wire(_record(row),rule_id=row['rule_id'],
                        state_token=row['rule_state_token'],
                        binding_metadata=row['result']),
            'compilerVersion':row['compiler_version'],
            'sealedPlanDigest':row['plan_digest'],
            'publishedRule':{'ruleId':row['rule_id'],
                'stateToken':row['rule_state_token'],
                'programDigest':row['program_digest']},
            'freshness':{'current':not reasons,'staleReasons':reasons,
                'expectedMetadataRevision':expected[0],
                'currentMetadataRevision':current[0],
                'expectedPolicyRevision':expected[1],
                'currentPolicyRevision':current[1],
                'expectedSchemaEpoch':expected[2],
                'currentSchemaEpoch':current[2]},
            'lineageComplete':lineage_complete,'lineage':chain}

    def sealed_plan(self,scope,workflow_id):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND issuer=%s AND subject_id=%s''',(scope.workspace_id,
                    scope.application_id,workflow_id,self.identity.issuer,
                    self.identity.subject_id)).fetchone()
                if row is None:raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                access=self._authorize(db,scope)
                self._assert_authorization_scope(db,scope,row,access=access)
                self._verify_current(db,scope,row)
        return self._stored_plan(row)

    @staticmethod
    def _stored_plan(row):
        canonical=row['sealed_plan']
        try:
            raw=json.dumps(canonical,sort_keys=True,separators=(',',':'),
                ensure_ascii=True,allow_nan=False).encode('ascii')
        except (TypeError,ValueError,UnicodeEncodeError) as error:
            raise ValueError('APPLICATION_RULE_STORED_PLAN_INVALID') from error
        units=canonical.get('units') if type(canonical) is dict else None
        if (type(units) is not list or not units
                or len(units)!=row['result'].get('unitCount')):
            raise ValueError('APPLICATION_RULE_STORED_PLAN_INVALID')
        operations=sum(len(unit.get('operations',[])) for unit in units
                       if type(unit) is dict and type(unit.get('operations')) is list)
        plan=SealedPlan(canonical,raw,sha256(raw).hexdigest(),len(units),
            operations,row['compiler_version'])
        verify_plan_identity(plan,row['plan_digest'])
        return plan

    def authorize_publication(self,workflow):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._scope(db,workflow.scope)
                PostgresAccessChecker.lock_workspace(
                    db,workflow.scope.workspace_id)
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND issuer=%s AND subject_id=%s''',(workflow.scope.workspace_id,
                    workflow.scope.application_id,workflow.workflow_id,
                    self.identity.issuer,self.identity.subject_id)).fetchone()
                if row is None:raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                access=self._authorize(db,workflow.scope)
                self._assert_authorization_scope(
                    db,workflow.scope,row,access=access)
                self._verify_current(db,workflow.scope,row)
                if ((row['issuer'],row['subject_id'])!=(self.identity.issuer,self.identity.subject_id)
                        or _record(row)!=workflow):
                    raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
                plan=self._stored_plan(row)
                from .postgres_capability_contract import assert_source_plan_purpose
                assert_source_plan_purpose(plan.canonical_plan,allow_definition=False)
                units=SealedPlanRunner._units(plan)
                ordinal=len(workflow.checkpoints)+1
                if (workflow.status!=WorkflowStatus.RUNNING or ordinal>len(units)
                        or any(not checkpoint.committed for checkpoint in workflow.checkpoints)):
                    raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_ADMISSION_INVALID')
                operation=SealedPlanRunner._atomic_operation(units[ordinal-1])
                return {'application_rule_workflow_id':workflow.workflow_id,
                    'unit_ordinal':ordinal,'sealed_plan_digest':plan.digest,
                    'public_operation_digest':_canonical_digest(operation),
                    'owner_certificate_digest':row['owner_certificate_digest']}

    def compare_and_set(self,current,updated):
        if (current.scope!=updated.scope or current.workflow_id!=updated.workflow_id
                or current.build_id!=updated.build_id
                or current.plan_digest!=updated.plan_digest):
            raise ValueError('APPLICATION_RULE_WORKFLOW_RECORD_MISMATCH')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000);self._scope(db,current.scope)
                PostgresAccessChecker.lock_workspace(
                    db,current.scope.workspace_id)
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND issuer=%s AND subject_id=%s FOR UPDATE''',(
                    current.scope.workspace_id,current.scope.application_id,
                    current.workflow_id,self.identity.issuer,
                    self.identity.subject_id)).fetchone()
                if row is None or _record(row)!=current:return False
                access=self._authorize(db,current.scope)
                self._assert_authorization_scope(
                    db,current.scope,row,access=access)
                claim=self.worker_claim
                if claim is None:
                    if row['claimant'] is not None:return False
                    fence_sql='claimant IS NULL';fence_args=()
                else:
                    if ((row['workspace_id'],row['application_id'],
                         row['workflow_id'],row['claim_generation'],row['claimant'])
                            !=(claim['workspace_id'],claim['application_id'],
                               claim['workflow_id'],claim['claim_generation'],
                               claim['claimant'])):
                        return False
                    live=db.execute('''SELECT lease_until>clock_timestamp() AS live
                        FROM epm.application_rule_workflow WHERE workspace_id=%s
                        AND application_id=%s AND workflow_id=%s''',(
                        current.scope.workspace_id,current.scope.application_id,
                        current.workflow_id)).fetchone()['live']
                    if not live:return False
                    fence_sql=('claim_generation=%s AND claimant=%s '
                               'AND lease_until>clock_timestamp()')
                    fence_args=(claim['claim_generation'],claim['claimant'])
                if len(updated.checkpoints)>len(current.checkpoints):
                    child=updated.checkpoints[-1]
                    if (len(updated.checkpoints)!=len(current.checkpoints)+1
                            or child.ordinal!=len(updated.checkpoints)):
                        raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
                    linked=db.execute('''SELECT job_id FROM epm.application_rule_workflow_child
                        WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                          AND unit_ordinal=%s''',(current.scope.workspace_id,
                        current.scope.application_id,current.workflow_id,child.ordinal)).fetchone()
                    if linked is None or linked['job_id']!=child.job_id:
                        raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
                result=_result(updated,row['result'])
                parent_receipt=None
                if updated.status==WorkflowStatus.PUBLISHED:
                    if (not updated.checkpoints
                            or len(updated.checkpoints)!=updated.unit_count
                            or any(not item.committed or not item.receipt_id
                                   for item in updated.checkpoints)):
                        raise ValueError(
                            'APPLICATION_RULE_WORKFLOW_PARENT_RECEIPT_INVALID')
                    revision=db.execute('''SELECT commit_revision+1 AS revision
                        FROM epm.application_state WHERE workspace_id=%s
                          AND application_id=%s FOR UPDATE''',(
                        current.scope.workspace_id,
                        current.scope.application_id)).fetchone()['revision']
                    parent_receipt={
                        'status':'Published','function':RUN,
                        'workflowId':updated.workflow_id,
                        'ruleId':row['rule_id'],
                        'stateToken':row['rule_state_token'],
                        'argumentsDigest':result.get('argumentsDigest'),
                        'planDigest':updated.plan_digest,
                        'childReceipts':[item.receipt_id
                            for item in updated.checkpoints],
                        'committedRevision':revision}
                    if (type(parent_receipt['argumentsDigest']) is not str
                            or len(parent_receipt['argumentsDigest'])!=64):
                        raise ValueError(
                            'APPLICATION_RULE_WORKFLOW_PARENT_RECEIPT_INVALID')
                    result['parentReceipt']=parent_receipt
                changed=db.execute('''UPDATE epm.application_rule_workflow SET
                    status=%s,result=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND status=%s AND '''+fence_sql,(updated.status.value,
                    Jsonb(result),current.scope.workspace_id,
                    current.scope.application_id,current.workflow_id,
                    current.status.value,*fence_args)).rowcount
                if changed!=1:return False
                if parent_receipt is not None:
                    db.execute('''INSERT INTO epm.operation_receipt(
                        workspace_id,application_id,operation_id,
                        command_digest,actor_id,committed_revision,result)
                        VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
                        current.scope.workspace_id,
                        current.scope.application_id,current.workflow_id,
                        row['request_digest'],row['subject_id'],
                        parent_receipt['committedRevision'],
                        Jsonb(parent_receipt)))
                    db.execute('''UPDATE epm.application_state
                        SET commit_revision=%s WHERE workspace_id=%s
                          AND application_id=%s''',(
                        parent_receipt['committedRevision'],
                        current.scope.workspace_id,
                        current.scope.application_id))
                return True

    def replay_admitted_child(self,workflow,*,ordinal,operation):
        """Verify retained acceptance; never preview or execute its effects again."""
        from .postgres_job_origin import recover_rule_child
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._scope(db,workflow.scope)
                access=self._authorize(db,workflow.scope)
                row=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND issuer=%s AND subject_id=%s''',(workflow.scope.workspace_id,
                    workflow.scope.application_id,workflow.workflow_id,
                    self.identity.issuer,self.identity.subject_id)).fetchone()
                if row is None:
                    raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                self._assert_authorization_scope(db,workflow.scope,row,access=access)
                if (_record(row)!=workflow or workflow.status!=WorkflowStatus.RUNNING
                        or ordinal!=len(workflow.checkpoints)+1
                        or any(not item.committed for item in workflow.checkpoints)):
                    raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
                return recover_rule_child(db,workflow.scope,self.identity,
                    workflow.workflow_id,ordinal,operation)

    def recover_child(self,workflow,*,ordinal,operation):
        key=self.child_idempotency_key(workflow,ordinal)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._scope(db,workflow.scope)
                access=self._authorize(db,workflow.scope)
                workflow_row=db.execute('''SELECT * FROM
                    epm.application_rule_workflow WHERE workspace_id=%s
                      AND application_id=%s AND workflow_id=%s
                      AND issuer=%s AND subject_id=%s''',(
                    workflow.scope.workspace_id,workflow.scope.application_id,
                    workflow.workflow_id,self.identity.issuer,
                    self.identity.subject_id)).fetchone()
                if workflow_row is None:
                    raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
                self._assert_authorization_scope(
                    db,workflow.scope,workflow_row,access=access)
                row=db.execute('''SELECT job_id,function_name,normalized_program
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                      AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',(
                    workflow.scope.workspace_id,workflow.scope.application_id,
                    self.identity.issuer,self.identity.subject_id,key)).fetchone()
        if row is None:return None
        # The stored payload is compiler-normalized while the sealed rule keeps
        # the public operation. The runner verifies the retained exact admission
        # through replay_admitted_child before accepting this checkpoint.
        if row['function_name']!=operation['function']:
            raise ValueError('APPLICATION_RULE_WORKFLOW_CHILD_CONFLICT')
        return UnitCheckpoint(ordinal,row['job_id'],False)


class PostgresApplicationRuleRun:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity,language,
                 worker_claim=None):
        self.identity,self.language=identity,language
        self.rules=PostgresApplicationRules(dsn,identity=identity)
        self.store=PostgresApplicationRuleWorkflowStore(dsn,identity=identity,
            worker_claim=worker_claim)
        self.runner=SealedPlanRunner(language,self.store,
            _JobInspector(PostgresJobQueue(dsn,identity=identity)))

    def run(self,scope,rule_id,*,bindings=None,idempotency_key,
            expected_state_token=None,expected_program_digest=None):
        if type(idempotency_key) is not str or _KEY.fullmatch(idempotency_key) is None:
            raise ValueError('APPLICATION_RULE_RUN_IDEMPOTENCY_KEY_INVALID')
        prior=self.store.read_by_idempotency_key(scope,idempotency_key)
        if prior is not None:
            prior_rule,prior_state_token,record,metadata=prior
            if (prior_rule!=rule_id or metadata.get('bindingRequestDigest')!=
                    _canonical_digest(bindings or {}) or (
                    expected_state_token is not None and (
                    prior_state_token!=expected_state_token
                    or metadata.get('programDigest')!=expected_program_digest))):
                raise ValueError('APPLICATION_RULE_WORKFLOW_IDEMPOTENCY_CONFLICT')
            return _wire(record,rule_id=prior_rule,
                         state_token=prior_state_token,
                         binding_metadata=metadata)
        _,pin=self.rules._published_snapshot(scope,rule_id,
            expected_state_token=expected_state_token,
            expected_program_digest=expected_program_digest,
            require_source_pin=True)
        validator=PostgresPythonBuildOperationValidator(self.store.dsn,
            identity=self.identity,preview_secret=self.language.preview_secret,
            metadata_revision=pin['metadataRevision'],
            policy_revision=pin['policyRevision'],schema_epoch=pin['schemaEpoch'],
            language=self.language)
        sealed=self.rules.seal_published(scope,rule_id,registry=validator,
            bindings=bindings,
            compiler_version='application-rule-v1',
            expected_state_token=pin['stateToken'],
            expected_program_digest=pin['programDigest'])
        artifact=sealed.plan.digest[:32]
        proposed=WorkflowRecord(scope,workflow_id(scope,self.identity,
            idempotency_key,schema_epoch=sealed.pin['schemaEpoch'],
            plan_digest=sealed.plan.digest),artifact,sealed.plan.digest,sealed.plan.unit_count)
        digest=rule_workflow_request_digest(scope,self.identity,
            idempotency_key,sealed)
        current=self.store.create_or_read_rule(proposed,sealed,
            idempotency_key=idempotency_key,request_digest=digest)
        try:
            current=self.runner.advance(current,sealed.plan)
        except ValueError as error:
            if str(error)!='PYTHON_WORKFLOW_STALE_CONTROL_STATE':raise
            # A background worker may claim and advance a newly accepted
            # workflow between durable creation and this optional eager
            # advance.  That is healthy progress, not a client-visible
            # failure.  Return the authoritative durable state; the worker
            # owns every further checkpoint through its generation fence.
            current=self.store.read(scope,proposed.workflow_id)
        return _wire(current,
                     rule_id=sealed.pin['ruleId'],
                     state_token=sealed.pin['stateToken'],
                     binding_metadata=dict(sealed.pin))

    def advance_existing(self,scope,workflow_id_value):
        current=self.store.read(scope,workflow_id_value)
        plan=self.store.sealed_plan(scope,workflow_id_value)
        rule_id,state_token,metadata=self.store.details(scope,workflow_id_value)
        return _wire(self.runner.advance(current,plan),rule_id=rule_id,
                     state_token=state_token,
                     binding_metadata=metadata)

    def read(self,scope,workflow_id_value):
        return self.store.lineage(scope,workflow_id_value)

    def cancel(self,scope,workflow_id_value):
        if type(workflow_id_value) is not str or _HEX32.fullmatch(workflow_id_value) is None:
            raise ValueError('APPLICATION_RULE_WORKFLOW_UNAVAILABLE')
        current=self.store.read(scope,workflow_id_value)
        rule_id,state_token,metadata=self.store.details(scope,workflow_id_value)
        return _wire(self.runner.request_cancel(current),rule_id=rule_id,
                     state_token=state_token,
                     binding_metadata=metadata)

    def reconcile(self,scope,workflow_id_value,*,idempotency_key):
        return self.store.reconcile_needs_inspection(scope,workflow_id_value,
            idempotency_key=idempotency_key)
