"""Dimension-bound bounded multi-slice reusable planning rollup."""
from __future__ import annotations

from dataclasses import dataclass
import re
from .persistence_contract import ApplicationScope,Coordinate
from .postgres_jobs import _canonical_digest,_require_python_job_authority
from .postgres_planning_rollup import (RollupPlan,active_hierarchy_version,
    compile_rollup_program,validate_rollup_inputs,_source_sql,
    _current_policy_pointer_matches,
    enforce_rollup_target_policy)
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

COMPILER='planning-rollup-slice-set-policy-v3'
PLAN_DIGEST=_canonical_digest({'function':'facts.planning.rollup.sum',
 'loweringVersion':3,'engine':'postgres_exact_sql','sliceBinding':'dimension_bound',
 'outputs':'one_parent_per_declared_slice','maxOutputs':100,'maxSources':500,
 'publication':'one_generation_pointer_receipt','rounding':'exact_sum_8'})
_JOB=re.compile(r'[0-9a-f]{32}\Z')
_DIGEST=re.compile(r'[0-9a-f]{64}\Z')
_POLICY_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z')
_POLICY_KEYS={'policyId','version','policyDigest','metadataRevision',
  'policyRevision','authoredMetadataRevision','authoredPolicyRevision',
  'pointerVersion','stateRevision'}

def _valid_policy_pin(value):
    return (isinstance(value,dict) and set(value)==_POLICY_KEYS
      and isinstance(value['policyId'],str)
      and _POLICY_ID.fullmatch(value['policyId']) is not None
      and isinstance(value['policyDigest'],str)
      and _DIGEST.fullmatch(value['policyDigest']) is not None
      and type(value['version']) is int and value['version']>=1
      and all(type(value[key]) is int and value[key]>=0 for key in (
        'metadataRevision','policyRevision','authoredMetadataRevision',
        'authoredPolicyRevision','pointerVersion','stateRevision')))

@dataclass(frozen=True,slots=True)
class SliceRollupPlan:
    dimension:str; parent:str; fixed_members:tuple[tuple[str,str],...]
    slice_dimension:str; slice_members:tuple[str,...]; result_key:str
    hierarchy_version:int; expected_publication_revision:int
    placement_ids:tuple[str,...]; reusable_policy:dict
    @property
    def normalized_program(self):
        return {'version':3,'function':'facts.planning.rollup.sum',
          'dimension':self.dimension,'parent':self.parent,
          'fixedMembers':dict(self.fixed_members),
          'sliceSelection':{'dimensionId':self.slice_dimension,
                            'memberIds':list(self.slice_members)},
          'resultKey':self.result_key,'hierarchyVersion':self.hierarchy_version,
          'expectedPublicationRevision':self.expected_publication_revision,
          'placementIds':list(self.placement_ids),
          'reusablePolicy':self.reusable_policy,
          'inputGrain':'leaf_full_coordinate','outputGrain':'parent_slice_set',
          'rounding':'exact_sum_8'}
    def children(self):
        return tuple(RollupPlan(self.dimension,self.parent,
          tuple(sorted((*self.fixed_members,(self.slice_dimension,member)))),
          self.result_key,self.hierarchy_version,
          self.expected_publication_revision,self.placement_ids)
          for member in self.slice_members)
    def targets(self): return tuple(child.target for child in self.children())

def compile_slice_rollup(bound,execution,*,hierarchy_version,
                         expected_publication_revision,pointer):
    if (not isinstance(bound,dict)
      or bound.get('policyFormat')!='openepm-planning-operation-policy-v2'
      or bound.get('kind')!='Rollup'
      or not isinstance(execution,dict) or set(execution)!={'resultKey'}):
        raise ValueError('ROLLUP_SLICE_POLICY_INVALID')
    definition=bound['definition'];selection=definition['sliceSelection']
    key=execution['resultKey']
    policy={k:bound[k] for k in ('policyId','version','policyDigest',
      'metadataRevision','policyRevision')};policy.update(pointer)
    plan=SliceRollupPlan(definition['dimension'],definition['parent'],
      tuple(sorted(definition['fixedMembers'].items())),
      selection['dimensionId'],tuple(selection['memberIds']),key,
      hierarchy_version,expected_publication_revision,
      tuple(definition['placementIds']),policy)
    try:
        return decode_slice_rollup(plan.normalized_program)
    except (KeyError,TypeError,ValueError) as error:
        raise ValueError('ROLLUP_SLICE_POLICY_INVALID') from error

def decode_slice_rollup(program):
    required={'version','function','dimension','parent','fixedMembers',
      'sliceSelection','resultKey','hierarchyVersion','expectedPublicationRevision',
      'placementIds','reusablePolicy','inputGrain','outputGrain','rounding'}
    if (not isinstance(program,dict) or set(program)!=required
      or program.get('version')!=3 or program.get('function')!='facts.planning.rollup.sum'
      or program.get('inputGrain')!='leaf_full_coordinate'
      or program.get('outputGrain')!='parent_slice_set'
      or program.get('rounding')!='exact_sum_8'
      or not isinstance(program.get('fixedMembers'),dict)
      or len(program['fixedMembers'])>30
      or not isinstance(program.get('sliceSelection'),dict)
      or set(program['sliceSelection'])!={'dimensionId','memberIds'}
      or not isinstance(program['sliceSelection']['memberIds'],list)
      or not 1<=len(program['sliceSelection']['memberIds'])<=100
      or not isinstance(program.get('placementIds'),list)
      or len(program['placementIds'])>100
      or not _valid_policy_pin(program.get('reusablePolicy'))):
        raise ValueError('UNSUPPORTED_ROLLUP_SLICE_JOB_PROGRAM')
    selection=program['sliceSelection'];members=selection['memberIds']
    fixed=program['fixedMembers']
    if (not isinstance(program.get('dimension'),str)
      or not isinstance(program.get('parent'),str)
      or not isinstance(selection['dimensionId'],str)
      or program['dimension']==selection['dimensionId']
      or program['dimension'] in fixed or selection['dimensionId'] in fixed
      or any(not isinstance(axis,str) or not isinstance(member,str)
             for axis,member in fixed.items())
      or any(not isinstance(member,str) for member in members)
      or members!=sorted(members) or len(members)!=len(set(members))
      or any(not isinstance(item,str) for item in program['placementIds'])
      or program['placementIds']!=sorted(program['placementIds'])
      or len(program['placementIds'])!=len(set(program['placementIds']))):
        raise ValueError('UNSUPPORTED_ROLLUP_SLICE_JOB_PROGRAM')
    plan=SliceRollupPlan(program['dimension'],program['parent'],
      tuple(sorted(fixed.items())),selection['dimensionId'],tuple(members),
      program['resultKey'],program['hierarchyVersion'],
      program['expectedPublicationRevision'],tuple(program['placementIds']),
      dict(program['reusablePolicy']))
    # Reuse the admitted V2 Rollup validators for every effective full-grain
    # output. This covers scalar ID/result-key bounds and rejects bool revision
    # values without creating a second subtly different validation contract.
    try:
      for child in plan.children():
        compile_rollup_program({'languageVersion':2,
          'function':'facts.planning.rollup.sum','arguments':{
            'dimension':child.dimension,'parent':child.parent,
            'otherMembers':dict(child.other_members),
            'resultKey':child.result_key,
            **({'placementIds':list(child.placement_ids)}
               if child.placement_ids else {})}},
          hierarchy_version=child.hierarchy_version,
          expected_publication_revision=child.expected_publication_revision)
    except (TypeError,ValueError) as error:
      raise ValueError('UNSUPPORTED_ROLLUP_SLICE_JOB_PROGRAM') from error
    if plan.normalized_program!=program:
        raise ValueError('NONCANONICAL_ROLLUP_SLICE_JOB_PROGRAM')
    return plan

def validate_slice_rollup(db,scope:ApplicationScope,plan:SliceRollupPlan):
    dimensions=db.execute('''SELECT dimension_id,model_role FROM epm.dimension
      WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
      (scope.workspace_id,scope.application_id)).fetchall()
    roles={row['dimension_id']:row['model_role'] for row in dimensions}
    # Currency is a typed unit, not coordinate grain. It may not be selected,
    # fixed, or rolled up through this generic coordinate operation.
    expected=set(roles)-{axis for axis,role in roles.items() if role=='Currency'}
    supplied={plan.dimension,plan.slice_dimension,*dict(plan.fixed_members)}
    if supplied!=expected or roles.get(plan.dimension)=='Currency' or roles.get(
            plan.slice_dimension)=='Currency':
        raise ValueError('ROLLUP_SLICE_COORDINATE_GRAIN_MISMATCH')
    summaries=[];total=0
    for child in plan.children():
        summary=validate_rollup_inputs(db,scope,child)
        total+=summary['sourceCount'];summaries.append(summary)
    if len(summaries)>100 or total>500:
        raise ValueError('ROLLUP_SLICE_SET_LIMIT')
    return {'outputCount':len(summaries),'sourceCount':total,
      'amounts':[{'target':item['target'],'amount':format(item['amount'],'f'),
                  'sourceCount':item['sourceCount']} for item in summaries]}

def _slice_replay(job,receipt):
    if receipt is None:return None
    if (job is None or job['status']!='published'
      or job['receipt_revision']!=receipt['committed_revision']
      or job['result']!=receipt['result']
      or job['subject_id']!=receipt['actor_id']):
        raise ValueError('ROLLUP_SLICE_RECEIPT_CONFLICT')
    return receipt['result']


class PostgresSliceRollupPublisher:
    def __init__(self,dsn,*,identity): self.dsn,self.identity=dsn,identity
    def publish(self,claim):
        if (not isinstance(claim,dict)
                or not all(isinstance(claim.get(key),str) and claim[key]
                           for key in ('workspace_id','application_id','job_id',
                                       'claimant'))
                or not _JOB.fullmatch(claim['job_id'])
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,5000)
            PostgresNumericFactStore._set_scope(db,scope)
            state=db.execute('''SELECT s.*,a.status application_status FROM
              epm.application_state s JOIN epm.application a USING(workspace_id,
              application_id) WHERE s.workspace_id=%s AND s.application_id=%s
              ''',(scope.workspace_id,scope.application_id)).fetchone()
            if state is None: raise ValueError('APPLICATION_UNAVAILABLE')
            access=PostgresAccessChecker.check_in_transaction(
              db,self.identity,scope,'write')
            job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
              AND application_id=%s AND job_id=%s''',(
              scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
            receipt=db.execute('''SELECT committed_revision,actor_id,result
              FROM epm.operation_receipt WHERE workspace_id=%s
              AND application_id=%s AND operation_id=%s''',(
              scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
            replay=_slice_replay(job,receipt)
            if replay is not None:return replay
            valid=db.execute('SELECT %s::timestamptz>clock_timestamp() valid',
              (job['lease_until'],)).fetchone()['valid'] if job else False
            if (job is None or job['issuer']!=self.identity.issuer
              or job['subject_id']!=self.identity.subject_id
              or job['status']!='running' or job['claim_generation']!=claim['claim_generation']
              or job['claimant']!=claim['claimant'] or not valid
              or job['function_name']!='facts.planning.rollup.sum'
              or job['compiler_version']!=COMPILER or job['plan_digest']!=PLAN_DIGEST
              or job['program_digest']!=_canonical_digest(job['normalized_program'])):
                raise ValueError('UNSUPPORTED_ROLLUP_SLICE_JOB')
            _require_python_job_authority(db,scope,job)
            plan=decode_slice_rollup(job['normalized_program'])
            if (not _current_policy_pointer_matches(db,scope,plan.reusable_policy)
              or state['application_status']!='Active' or state['processing_mode']!='Active'
              or state['metadata_revision']!=job['expected_metadata_revision']
              or state['data_revision']!=job['expected_data_revision']
              or state['policy_revision']!=job['expected_policy_revision']):
                raise ValueError('STALE_ROLLUP_SLICE_JOB')
            pointer=db.execute('''SELECT published_revision FROM epm.calculation_publication
              WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',(
              scope.workspace_id,scope.application_id,plan.result_key)).fetchone()
            if (pointer['published_revision'] if pointer else 0)!=plan.expected_publication_revision:
                raise ValueError('STALE_PUBLICATION_POINTER')
            summary=validate_slice_rollup(db,scope,plan)
            policy_evidence=[]
            for ordinal,child in enumerate(plan.children(),1):
              policy_evidence.append({'target':dict(child.target.members),
                'evidence':enforce_rollup_target_policy(
                    db,scope,child,access.role)})
            db.execute('''CREATE TEMP TABLE slice_rollup_source_stage(
              output_ordinal integer NOT NULL,source_coordinate_id bigint NOT NULL,
              source_amount numeric(28,8) NOT NULL,source_change_id text NOT NULL,
              placement_relationship_id text,placement_parent_member_id text,
              placement_child_member_id text) ON COMMIT DROP''')
            db.execute('''CREATE TEMP TABLE slice_rollup_output_stage(
              output_ordinal integer PRIMARY KEY,target_series_key text NOT NULL,
              target_members jsonb NOT NULL,amount numeric(28,8) NOT NULL,
              source_count integer NOT NULL,source_change_id text NOT NULL)
              ON COMMIT DROP''')
            for ordinal,child in enumerate(plan.children(),1):
              placement_select=(',placement.relationship_id,'
                'placement.parent_member_id,placement.child_member_id'
                if child.placement_ids else ',NULL::text,NULL::text,NULL::text')
              staged=db.execute(f'''INSERT INTO pg_temp.slice_rollup_source_stage(
                output_ordinal,source_coordinate_id,source_amount,source_change_id,
                placement_relationship_id,placement_parent_member_id,
                placement_child_member_id) SELECT %s,c.coordinate_id,n.amount,
                n.change_id{placement_select} {_source_sql(child)}''',(
                ordinal,*child.source_params(scope))).rowcount
              if staged!=summary['amounts'][ordinal-1]['sourceCount']:
                raise ValueError('ROLLUP_SOURCE_COUNT_CHANGED')
              output=db.execute('''INSERT INTO pg_temp.slice_rollup_output_stage(
                output_ordinal,target_series_key,target_members,amount,
                source_count,source_change_id)
                SELECT %s,%s,%s::jsonb,sum(source_amount),count(*),
                  'rollup:'||encode(sha256(convert_to(string_agg(
                    source_coordinate_id::text||':'||source_change_id,E'\n'
                    ORDER BY source_coordinate_id),'UTF8')),'hex')
                FROM pg_temp.slice_rollup_source_stage WHERE output_ordinal=%s
                RETURNING amount,source_count''',(
                ordinal,child.target.series_key,Jsonb(dict(child.target.members)),
                ordinal)).fetchone()
              if (output is None or output['source_count']!=staged
                    or format(output['amount'],'f')!=
                       summary['amounts'][ordinal-1]['amount']):
                raise ValueError('ROLLUP_RESULT_COUNT_CHANGED')

            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            final_state=db.execute('''SELECT s.*,a.status application_status FROM
              epm.application_state s JOIN epm.application a USING(workspace_id,
              application_id) WHERE s.workspace_id=%s AND s.application_id=%s
              FOR UPDATE OF s''',(scope.workspace_id,scope.application_id)).fetchone()
            final_job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
              AND application_id=%s AND job_id=%s FOR UPDATE''',(
              scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
            final_receipt=db.execute('''SELECT committed_revision,actor_id,result
              FROM epm.operation_receipt WHERE workspace_id=%s
              AND application_id=%s AND operation_id=%s''',(
              scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
            replay=_slice_replay(final_job,final_receipt)
            if replay is not None:return replay
            final_valid=(final_job is not None and db.execute(
              'SELECT %s::timestamptz>clock_timestamp() valid',
              (final_job['lease_until'],)).fetchone()['valid'])
            immutable=('issuer','subject_id','function_name','normalized_program',
              'program_digest','compiler_version','plan_digest',
              'expected_metadata_revision','expected_data_revision',
              'expected_policy_revision')
            if (final_state is None or final_job is None
              or any(final_job[key]!=job[key] for key in immutable)
              or final_job['status']!='running'
              or final_job['claim_generation']!=claim['claim_generation']
              or final_job['claimant']!=claim['claimant'] or not final_valid):
                raise ValueError('STALE_WORKER_FENCE')
            _require_python_job_authority(db,scope,final_job)
            final_access=PostgresAccessChecker.check_in_transaction(
              db,self.identity,scope,'write')
            if (not _current_policy_pointer_matches(db,scope,plan.reusable_policy)
              or final_state['application_status']!='Active'
              or final_state['processing_mode']!='Active'
              or final_state['metadata_revision']!=job['expected_metadata_revision']
              or final_state['data_revision']!=job['expected_data_revision']
              or final_state['policy_revision']!=job['expected_policy_revision']):
                raise ValueError('STALE_ROLLUP_SLICE_JOB')
            final_pointer=db.execute('''SELECT published_revision FROM
              epm.calculation_publication WHERE workspace_id=%s
              AND application_id=%s AND result_key=%s''',(
              scope.workspace_id,scope.application_id,plan.result_key)).fetchone()
            if (final_pointer['published_revision'] if final_pointer else 0)!=(
                    plan.expected_publication_revision):
                raise ValueError('STALE_PUBLICATION_POINTER')
            policy_evidence=[]
            for child in plan.children():
              policy_evidence.append({'target':dict(child.target.members),
                'evidence':enforce_rollup_target_policy(
                    db,scope,child,final_access.role)})
            state=final_state;job=final_job
            revision=state['commit_revision']+1
            db.execute('''INSERT INTO epm.calculation_generation(workspace_id,
              application_id,generation_id,job_id,result_key,source_commit_revision,
              source_metadata_revision,source_policy_revision,function_name,factor,
              row_count,published_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,
              'facts.planning.rollup.sum',NULL,%s,%s)''',(scope.workspace_id,
              scope.application_id,claim['job_id'],claim['job_id'],plan.result_key,
              state['commit_revision'],state['metadata_revision'],state['policy_revision'],
              summary['outputCount'],revision))
            lineage_count=0
            for child in plan.children():
              target=child.target
              db.execute('''INSERT INTO epm.coordinate(workspace_id,application_id,
                series_key,members) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING''',(
                scope.workspace_id,scope.application_id,target.series_key,
                Jsonb(dict(target.members))))
              coordinate=db.execute('''SELECT coordinate_id,members FROM epm.coordinate
                WHERE workspace_id=%s AND application_id=%s AND series_key=%s''',(
                scope.workspace_id,scope.application_id,target.series_key)).fetchone()
              if coordinate['members']!=dict(target.members):
                raise ValueError('COORDINATE_HASH_COLLISION')
              db.execute('''INSERT INTO epm.coordinate_member_projection(workspace_id,
                application_id,coordinate_id,dimension_id,member_id,projection_generation)
                SELECT %s,%s,%s,x.key,x.value,(SELECT epm.active_projection_generation())
                FROM jsonb_each_text(%s::jsonb)x ON CONFLICT DO NOTHING''',(
                scope.workspace_id,scope.application_id,coordinate['coordinate_id'],
                Jsonb(dict(target.members))))
              inserted=db.execute('''INSERT INTO epm.calculation_result(workspace_id,
                application_id,generation_id,coordinate_id,source_amount,
                source_change_id,amount) SELECT %s,%s,%s,%s,amount,
                source_change_id,amount FROM pg_temp.slice_rollup_output_stage
                WHERE output_ordinal=%s''',(scope.workspace_id,
                scope.application_id,claim['job_id'],coordinate['coordinate_id'],
                ordinal)).rowcount
              if inserted!=1: raise ValueError('ROLLUP_RESULT_COUNT_CHANGED')
              pcols=(',placement_relationship_id,placement_parent_member_id,'
                     'placement_child_member_id' if child.placement_ids else '')
              pvals=(',source.placement_relationship_id,'
                     'source.placement_parent_member_id,'
                     'source.placement_child_member_id'
                     if child.placement_ids else '')
              lineage_count+=db.execute(f'''INSERT INTO epm.rollup_source_lineage(
                workspace_id,application_id,generation_id,coordinate_id,
                source_coordinate_id,source_amount,source_change_id,
                hierarchy_dimension_id,hierarchy_version{pcols}) SELECT %s,%s,%s,%s,
                source.source_coordinate_id,source.source_amount,
                source.source_change_id,%s,%s{pvals}
                FROM pg_temp.slice_rollup_source_stage source
                WHERE source.output_ordinal=%s''',(
                scope.workspace_id,scope.application_id,claim['job_id'],
                coordinate['coordinate_id'],child.dimension,child.hierarchy_version,
                ordinal)).rowcount
            if lineage_count!=summary['sourceCount']:
                raise ValueError('ROLLUP_SOURCE_COUNT_CHANGED')
            db.execute('''INSERT INTO epm.calculation_publication(workspace_id,
              application_id,result_key,generation_id,published_revision)
              VALUES(%s,%s,%s,%s,%s) ON CONFLICT(workspace_id,application_id,result_key)
              DO UPDATE SET generation_id=excluded.generation_id,
              published_revision=excluded.published_revision,updated_at=transaction_timestamp()''',(
              scope.workspace_id,scope.application_id,plan.result_key,claim['job_id'],revision))
            result={'generationId':claim['job_id'],'resultKey':plan.result_key,
              'function':'facts.planning.rollup.sum','rowCount':summary['outputCount'],
              'sourceCount':lineage_count,'outputs':summary['amounts'],
              'hierarchyVersion':plan.hierarchy_version,
              'sourceCommitRevision':state['commit_revision'],
              'committedRevision':revision,
              'engine':'postgres_exact_sql','reusablePolicy':plan.reusable_policy,
              'planningPolicy':policy_evidence}
            if plan.placement_ids:
              result['placementContext']={'dimensionId':plan.dimension,
                'parentMemberId':plan.parent,
                'relationshipIds':list(plan.placement_ids),
                'semantics':'explicit_direct_leaf_placements_per_slice'}
            db.execute('''UPDATE epm.application_state SET commit_revision=%s
              WHERE workspace_id=%s AND application_id=%s''',(revision,
              scope.workspace_id,scope.application_id))
            db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
              operation_id,command_digest,actor_id,committed_revision,result)
              VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,
              scope.application_id,claim['job_id'],job['program_digest'],
              job['subject_id'],revision,Jsonb(result)))
            changed=db.execute('''UPDATE epm.job SET status='published',receipt_revision=%s,
              result=%s,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
              WHERE workspace_id=%s AND application_id=%s AND job_id=%s
              AND status='running' AND claim_generation=%s AND claimant=%s
              AND lease_until>clock_timestamp()''',(revision,Jsonb(result),
              scope.workspace_id,scope.application_id,claim['job_id'],
              claim['claim_generation'],claim['claimant'])).rowcount
            if changed!=1: raise ValueError('STALE_WORKER_FENCE')
            return result
