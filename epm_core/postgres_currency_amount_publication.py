"""Durable generic Amount × pinned Currency-rate calculation publication."""
from __future__ import annotations

from copy import deepcopy
import re
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_currency_amount_preview import (
    _arguments, evaluate_in_transaction, FUNCTION as PREVIEW)
from .postgres_jobs import (PostgresJobQueue, _canonical_digest,
    _require_python_job_authority)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates

FUNCTION='currency.amount.translate.publish'
COMPILER='currency-amount-rate-publication-v1'
PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'version':1,
    'engine':'postgres_exact_rational','source':'immutable_raw_amount',
    'rate':'currency.rate.resolve_pinned','rounding':'half-even-final-8',
    'output':'one_named_calculation_generation'})
BATCH_COMPILER='currency-amount-rate-publication-v2'
BATCH_PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'version':2,
    'engine':'postgres_exact_rational','source':'immutable_raw_amounts',
    'rate':'currency.rate.resolve_per_row_pinned','rounding':'half-even-final-8',
    'bound':100,'output':'one_atomic_named_calculation_generation'})
UNIT_COMPILER='currency-amount-rate-publication-v3'
UNIT_PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'version':3,
    'engine':'postgres_exact_rational','source':'immutable_raw_amounts',
    'rate':'currency.rate.resolve_per_row_pinned','rounding':'half-even-final-8',
    'bound':100,'output':'one_atomic_typed_currency_unit_generation'})
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def compile_program(raw, *, expected_publication_revision):
    if (type(raw) is not dict or set(raw)!={'languageVersion','function','arguments'}
            or raw.get('languageVersion')!=2 or raw.get('function')!=FUNCTION
            or type(raw.get('arguments')) is not dict):
        raise ValueError('CURRENCY_AMOUNT_PUBLICATION_PROGRAM_INVALID')
    args=raw['arguments']
    if (type(args.get('resultKey')) is not str
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision<0):
        raise ValueError('CURRENCY_AMOUNT_PUBLICATION_ARGUMENTS_INVALID')
    base=set(args)-{'resultKey'}
    if base=={'rows'}:
        if type(args['rows']) is not list or not 1<=len(args['rows'])<=100:
            raise ValueError('CURRENCY_AMOUNT_PUBLICATION_ROW_BOUNDS')
        rows=[];identities=set()
        unit_mode=all(isinstance(value,dict) and
            'outputUnitCurrencyMemberId' in value for value in args['rows'])
        if any(isinstance(value,dict) and
                'outputUnitCurrencyMemberId' in value for value in args['rows']) != unit_mode:
            raise ValueError('CURRENCY_AMOUNT_PUBLICATION_UNIT_MODE_MIXED')
        for value in args['rows']:
            if isinstance(value,dict) and 'targetCoordinate' in value:
                raise ValueError(
                    'CURRENCY_AMOUNT_TARGET_COORDINATE_UNSUPPORTED')
            unit=value.get('outputUnitCurrencyMemberId') if unit_mode else None
            preview_value={k:v for k,v in value.items()
                if k!='outputUnitCurrencyMemberId'}
            if unit_mode and (type(unit) is not str or unit!=value.get(
                    'toCurrencyMemberId')):
                raise ValueError('CURRENCY_AMOUNT_OUTPUT_UNIT_INVALID')
            preview={'languageVersion':2,'function':PREVIEW,'arguments':preview_value}
            parsed=_arguments(preview)
            identity=(parsed['coordinate'].series_key,unit)
            if identity in identities:
                raise ValueError('CURRENCY_AMOUNT_PUBLICATION_DUPLICATE_OUTPUT'
                    if unit_mode else
                    'CURRENCY_AMOUNT_PUBLICATION_DUPLICATE_COORDINATE')
            if not unit_mode and any(key[0]==identity[0] for key in identities):
                raise ValueError('CURRENCY_AMOUNT_PUBLICATION_DUPLICATE_COORDINATE')
            identities.add(identity)
            rows.append({**preview_value,
                **({'outputUnitCurrencyMemberId':unit} if unit_mode else {}),
                'coordinate':dict(parsed['coordinate'].members),
                'sourceAmount':format(parsed['sourceAmount'],'.8f')})
        return {'version':3 if unit_mode else 2,'function':FUNCTION,
            'arguments':{'rows':rows,'resultKey':args['resultKey']},
            'expectedPublicationRevision':expected_publication_revision}
    if (base!={'coordinate','sourceAmount','sourceChangeId','fromCurrencyMemberId',
            'toCurrencyMemberId','rateKind','expectedRate','expectedDataRevision','rounding'}
            ):
        raise ValueError('CURRENCY_AMOUNT_PUBLICATION_ARGUMENTS_INVALID')
    preview={'languageVersion':2,'function':PREVIEW,
        'arguments':{k:v for k,v in args.items() if k!='resultKey'}}
    parsed=_arguments(preview)
    return {'version':1,'function':FUNCTION,
        'arguments':{**preview['arguments'],
            'coordinate':dict(parsed['coordinate'].members),
            'sourceAmount':format(parsed['sourceAmount'],'.8f'),
            'resultKey':args['resultKey']},
        'expectedPublicationRevision':expected_publication_revision}


def decode_program(value):
    if type(value) is not dict or set(value)!={'version','function','arguments','expectedPublicationRevision'}:
        raise ValueError('UNSUPPORTED_CURRENCY_AMOUNT_PUBLICATION_JOB')
    raw={'languageVersion':2,'function':FUNCTION,'arguments':value['arguments']}
    checked=compile_program(raw,expected_publication_revision=value['expectedPublicationRevision'])
    if checked!=value: raise ValueError('NONCANONICAL_CURRENCY_AMOUNT_PUBLICATION_JOB')
    return checked


def compiler_for(plan):
    if plan['version']==1:return COMPILER,PLAN_DIGEST
    if plan['version']==2:return BATCH_COMPILER,BATCH_PLAN_DIGEST
    if plan['version']==3:return UNIT_COMPILER,UNIT_PLAN_DIGEST
    raise ValueError('UNSUPPORTED_CURRENCY_AMOUNT_PUBLICATION_JOB')


def parsed_rows(plan):
    values=(plan['arguments']['rows'] if plan['version'] in (2,3) else
        [{k:v for k,v in plan['arguments'].items() if k!='resultKey'}])
    return [_arguments({'languageVersion':2,'function':PREVIEW,
        'arguments':{k:v for k,v in value.items()
            if k!='outputUnitCurrencyMemberId'}}) for value in values]


def _seal_candidate(plan,results):
    """Detach one exact private result from its completed read transaction."""
    sealed=deepcopy(results)
    return {'digest':_canonical_digest({'plan':plan,'results':sealed}),
        'results':sealed}


def enforce_currency_amount_dimensional_security(
        db, identity, scope, args_rows, results):
    """Authorize raw Amount/rate inputs separately from calculated outputs."""
    if (not args_rows or len(args_rows) != len(results)
            or any(not isinstance(result, dict)
                   or not isinstance(result.get('lineage'), dict)
                   for result in results)):
        raise ValueError('CURRENCY_AMOUNT_SECURITY_COORDINATES_INVALID')
    reads = {}
    writes = {}
    for args, result in zip(args_rows, results, strict=True):
        source = args.get('coordinate')
        if not isinstance(source, Coordinate):
            raise ValueError('CURRENCY_AMOUNT_SECURITY_COORDINATES_INVALID')
        reads[source.series_key] = source
        writes[source.series_key] = source
        rate = result['lineage'].get('rate')
        rate_sources = rate.get('sources') if isinstance(rate, dict) else None
        if not isinstance(rate_sources, list):
            raise ValueError('CURRENCY_AMOUNT_SECURITY_COORDINATES_INVALID')
        for item in rate_sources:
            members = item.get('coordinate') if isinstance(item, dict) else None
            if not isinstance(members, dict):
                raise ValueError('CURRENCY_AMOUNT_SECURITY_COORDINATES_INVALID')
            coordinate = Coordinate.from_mapping(members)
            reads[coordinate.series_key] = coordinate
    authorize_coordinates(
        db, identity, scope, reads.values(), kind=AccessKind.READ)
    authorize_coordinates(
        db, identity, scope, writes.values(), kind=AccessKind.WRITE)


def preview(language,scope,raw):
    plan=compile_program(raw,expected_publication_revision=0)
    args_rows=parsed_rows(plan)
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            results=[evaluate_in_transaction(db,scope,language.identity,args,
                permission='write',function=FUNCTION) for args in args_rows]
            enforce_currency_amount_dimensional_security(
                db, language.identity, scope, args_rows, results)
            state=db.execute('''SELECT metadata_revision,data_revision,policy_revision
                FROM epm.application_state WHERE workspace_id=%s AND application_id=%s
                FOR SHARE''',(scope.workspace_id,scope.application_id)).fetchone()
            pointer=db.execute('''SELECT published_revision FROM epm.calculation_publication
                WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',
                (scope.workspace_id,scope.application_id,plan['arguments']['resultKey'])).fetchone()
            expected=pointer['published_revision'] if pointer else 0
            plan=compile_program(raw,expected_publication_revision=expected)
            revisions={k:state[k] for k in ('metadata_revision','data_revision','policy_revision')}
    token,digest=language._sign_preview(scope,FUNCTION,plan,revisions,
        extra={'expectedPublicationRevision':expected})
    result=(results[0] if plan['version']==1 else {'rows':results,
        'rowCount':len(results),'consolidationTranslation':False})
    return {**result,'function':FUNCTION,'programDigest':digest,
        'expectedPublicationRevision':expected,'previewToken':token,
        'publicationSupported':True,'effects':'NamedCalculationGeneration'}


def submit(language,scope,raw,token,key,dependencies):
    payload=language._unpack_preview(scope,FUNCTION,token)
    if (set(payload)!={'scope','identity','function','programDigest','revisions',
            'expiresAt','expectedPublicationRevision'}):
        raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    plan=compile_program(raw,expected_publication_revision=payload['expectedPublicationRevision'])
    if payload['programDigest']!=_canonical_digest(plan):
        raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    r=payload['revisions']
    compiler,digest=compiler_for(plan)
    return PostgresJobQueue(language.dsn,identity=language.identity).submit(scope,
        idempotency_key=key,function_name=FUNCTION,normalized_program=plan,
        compiler_version=compiler,plan_digest=digest,
        expected_metadata_revision=r['metadata_revision'],
        expected_data_revision=r['data_revision'],expected_policy_revision=r['policy_revision'],
        resource_class='short',depends_on_job_ids=dependencies)


class PostgresCurrencyAmountPublisher:
    def __init__(self,dsn,*,identity): self.dsn,self.identity=dsn,identity
    def publish(self,claim):
        if (not isinstance(claim,dict)
                or not isinstance(claim.get('workspace_id'),str)
                or not isinstance(claim.get('application_id'),str)
                or not isinstance(claim.get('job_id'),str)
                or not re.fullmatch(r'[0-9a-f]{32}',claim['job_id'])
                or not isinstance(claim.get('claimant'),str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id']);keys=(scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
          with before.transaction():
            configure_statement_timeout(before,10000)
            PostgresNumericFactStore._set_scope(before,scope)
            access=PostgresAccessChecker.check_in_transaction(
                before,self.identity,scope,'write',function=FUNCTION)
            job=before.execute('''SELECT *,lease_until>clock_timestamp() unexpired
                FROM epm.job WHERE workspace_id=%s AND application_id=%s
                AND job_id=%s''',(*keys,claim['job_id'])).fetchone()
            if (job is None or job['issuer']!=self.identity.issuer
                    or job['subject_id']!=self.identity.subject_id):
                raise ValueError('CURRENCY_AMOUNT_JOB_UNAVAILABLE')
            receipt=before.execute('''SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                AND application_id=%s AND operation_id=%s''',
                (*keys,claim['job_id'])).fetchone()
            if receipt:
                if (receipt['command_digest']!=job['program_digest']
                        or receipt['actor_id']!=job['subject_id']):
                    raise ValueError('CURRENCY_AMOUNT_RECEIPT_CONFLICT')
                return receipt['result']
            if (job['status']!='running'
                    or job['claim_generation']!=claim['claim_generation']
                    or job['claimant']!=claim['claimant']
                    or not job['unexpired']):
                raise ValueError('STALE_WORKER_FENCE')
            _require_python_job_authority(before,scope,job)
            if job['function_name']!=FUNCTION:
                raise ValueError('UNSUPPORTED_CURRENCY_AMOUNT_PUBLICATION_JOB')
            plan=decode_program(job['normalized_program'])
            compiler,digest=compiler_for(plan)
            if (job['compiler_version']!=compiler
                    or job['plan_digest']!=digest
                    or job['program_digest']!=_canonical_digest(plan)):
                raise ValueError('UNSUPPORTED_CURRENCY_AMOUNT_PUBLICATION_JOB')
            args_rows=parsed_rows(plan)
            results=[evaluate_in_transaction(before,scope,self.identity,args,
                permission='write',function=FUNCTION) for args in args_rows]
            enforce_currency_amount_dimensional_security(
                before, self.identity, scope, args_rows, results)
            revisions={(result['lineage']['revisions']['metadataRevision'],
                result['lineage']['revisions']['dataRevision'],
                result['lineage']['revisions']['policyRevision'])
                for result in results}
            expected=(job['expected_metadata_revision'],
                job['expected_data_revision'],job['expected_policy_revision'])
            if revisions!={expected}:
                raise ValueError('STALE_JOB_INPUT_REVISION')
            state=before.execute('''SELECT a.status,s.processing_mode,
                s.metadata_revision,s.data_revision,s.policy_revision
                FROM epm.application_state s JOIN epm.application a
                USING(workspace_id,application_id) WHERE s.workspace_id=%s
                AND s.application_id=%s''',keys).fetchone()
            if (state is None or state['status']!='Active'
                    or state['processing_mode']!='Active'):
                raise ValueError('APPLICATION_NOT_WRITABLE')
            if (state['metadata_revision'],state['data_revision'],
                    state['policy_revision'])!=expected:
                raise ValueError('STALE_JOB_INPUT_REVISION')
            pointer=before.execute('''SELECT published_revision FROM
                epm.calculation_publication WHERE workspace_id=%s
                AND application_id=%s AND result_key=%s''',
                (*keys,plan['arguments']['resultKey'])).fetchone()
            if (pointer['published_revision'] if pointer else 0)!=plan['expectedPublicationRevision']:
                raise ValueError('STALE_PUBLICATION_POINTER')
            from .postgres_planning_write_guard import enforce_active_planning_policy
            policy_coordinates={args['coordinate'].series_key:args['coordinate']
                for args in args_rows}
            enforce_active_planning_policy(before,scope,
                writes=tuple((coordinate,'Set') for coordinate in
                    policy_coordinates.values()),workflow_role=access.role)
        initial_job=job;candidate=_seal_candidate(plan,results)
        results=candidate['results']
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,10000)
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            state=db.execute('''SELECT a.status,s.processing_mode,
                s.metadata_revision,s.data_revision,s.policy_revision,
                s.commit_revision FROM epm.application_state s
                JOIN epm.application a USING(workspace_id,application_id)
                WHERE s.workspace_id=%s AND s.application_id=%s
                FOR UPDATE OF s''',keys).fetchone()
            access=PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,'write',function=FUNCTION)
            job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
                AND application_id=%s AND job_id=%s FOR UPDATE''',
                (*keys,claim['job_id'])).fetchone()
            receipt=db.execute('''SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                AND application_id=%s AND operation_id=%s''',
                (*keys,claim['job_id'])).fetchone()
            if receipt:
                if (job is None
                        or receipt['command_digest']!=job['program_digest']
                        or receipt['actor_id']!=job['subject_id']):
                    raise ValueError('CURRENCY_AMOUNT_RECEIPT_CONFLICT')
                return receipt['result']
            immutable=('issuer','subject_id','function_name',
                'normalized_program','program_digest','compiler_version',
                'plan_digest','expected_metadata_revision',
                'expected_data_revision','expected_policy_revision')
            if (job is None or any(job[key]!=initial_job[key]
                    for key in immutable)):
                raise ValueError('STALE_WORKER_FENCE')
            unexpired=db.execute(
                'SELECT %s::timestamptz>clock_timestamp() ok',
                (job['lease_until'],)).fetchone()['ok']
            if (job['status']!='running'
                    or job['claim_generation']!=claim['claim_generation']
                    or job['claimant']!=claim['claimant'] or not unexpired):
                raise ValueError('STALE_WORKER_FENCE')
            _require_python_job_authority(db,scope,job)
            if (job['function_name']!=FUNCTION
                    or job['compiler_version']!=compiler
                    or job['plan_digest']!=digest
                    or job['program_digest']!=_canonical_digest(plan)):
                raise ValueError('UNSUPPORTED_CURRENCY_AMOUNT_PUBLICATION_JOB')
            if _canonical_digest({'plan':plan,'results':results})!=candidate['digest']:
                raise ValueError('CURRENCY_AMOUNT_CANDIDATE_CHANGED')
            enforce_currency_amount_dimensional_security(
                db, self.identity, scope, args_rows, results)
            if (state is None or state['status']!='Active'
                    or state['processing_mode']!='Active'):
                raise ValueError('APPLICATION_NOT_WRITABLE')
            if any(state[k]!=job['expected_'+k] for k in
                    ('metadata_revision','data_revision','policy_revision')):
                raise ValueError('STALE_JOB_INPUT_REVISION')
            pointer=db.execute('''SELECT published_revision FROM
                epm.calculation_publication WHERE workspace_id=%s
                AND application_id=%s AND result_key=%s''',
                (*keys,plan['arguments']['resultKey'])).fetchone()
            if (pointer['published_revision'] if pointer else 0)!=plan['expectedPublicationRevision']:
                raise ValueError('STALE_PUBLICATION_POINTER')
            policy=enforce_active_planning_policy(db,scope,
                writes=tuple((coordinate,'Set') for coordinate in
                    policy_coordinates.values()),workflow_role=access.role)
            revision=state['commit_revision']+1
            body=(results[0] if plan['version']==1 else {'rows':results,
                'rowCount':len(results),'consolidationTranslation':False})
            publication={**body,'generationId':claim['job_id'],'resultKey':plan['arguments']['resultKey'],
                'committedRevision':revision,'sourceCommitRevision':state['commit_revision'],
                'publicationSupported':True,'effects':'NamedCalculationGeneration',
                'planningPolicy':policy}
            db.execute('''INSERT INTO epm.calculation_generation(workspace_id,application_id,generation_id,job_id,
                result_key,source_commit_revision,source_metadata_revision,source_policy_revision,function_name,
                factor,row_count,published_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s)''',
                (*keys,claim['job_id'],claim['job_id'],plan['arguments']['resultKey'],state['commit_revision'],
                 state['metadata_revision'],state['policy_revision'],FUNCTION,len(results),revision))
            if plan['version']==3:
                currency_dimensions=db.execute('''SELECT dimension_id FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s AND status='Active'
                    AND model_role='Currency' ORDER BY dimension_id''',keys).fetchall()
                if len(currency_dimensions)!=1:
                    raise ValueError('CURRENCY_AMOUNT_CURRENCY_ROLE_AMBIGUOUS')
                currency_dimension=currency_dimensions[0]['dimension_id']
                db.cursor().executemany('''INSERT INTO epm.calculation_unit_result
                    (workspace_id,application_id,generation_id,coordinate_id,
                     output_unit_currency_dimension_id,output_unit_currency_member_id,
                     source_amount,source_change_id,amount,rate_strategy,
                     rate_numerator,rate_denominator,rate_sources)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',[
                    (*keys,claim['job_id'],result['lineage']['source']['coordinateId'],
                     currency_dimension,args['outputUnitCurrencyMemberId'],
                     result['sourceAmount'],args['sourceChangeId'],result['translatedAmount'],
                     args['expectedRate']['strategy'],
                     args['expectedRate']['exactFactor']['numerator'],
                     args['expectedRate']['exactFactor']['denominator'],
                     Jsonb(result['lineage']['rate']['sources']))
                    for args,result in zip(plan['arguments']['rows'],results)])
            else:
                db.cursor().executemany('''INSERT INTO epm.calculation_result(workspace_id,application_id,generation_id,coordinate_id,
                source_amount,source_change_id,amount) VALUES(%s,%s,%s,%s,%s,%s,%s)''',[
                (*keys,claim['job_id'],result['lineage']['source']['coordinateId'],
                 result['sourceAmount'],args['sourceChangeId'],result['translatedAmount'])
                for args,result in zip(args_rows,results)])
            db.execute('''INSERT INTO epm.calculation_publication(workspace_id,application_id,result_key,generation_id,published_revision)
                VALUES(%s,%s,%s,%s,%s) ON CONFLICT(workspace_id,application_id,result_key) DO UPDATE SET
                generation_id=EXCLUDED.generation_id,published_revision=EXCLUDED.published_revision,updated_at=transaction_timestamp()''',
                (*keys,plan['arguments']['resultKey'],claim['job_id'],revision))
            db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,
                committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',(*keys,claim['job_id'],job['program_digest'],job['subject_id'],revision,Jsonb(publication)))
            db.execute('''UPDATE epm.application_state SET commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',(revision,*keys))
            changed=db.execute('''UPDATE epm.job SET status='published',receipt_revision=%s,result=%s,claimant=NULL,lease_until=NULL,
                updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND job_id=%s AND status='running'
                AND claim_generation=%s AND claimant=%s AND lease_until>clock_timestamp()''',(revision,Jsonb(publication),*keys,
                claim['job_id'],claim['claim_generation'],claim['claimant'])).rowcount
            if changed!=1: raise ValueError('STALE_WORKER_FENCE')
            return publication
