"""Reader-safe Raw/Adjusted baseline versus pinned Calculated scenario variance."""
from __future__ import annotations

import base64, binascii, hmac, json, re, time
from decimal import Decimal, localcontext
from hashlib import sha256

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_cube_layer_report import PostgresCubeLayerReport
from .postgres_cube_query import PostgresCubeQuery, _filter_members
from .postgres_calculation_status import input_revision_status
from .postgres_capability_contract import producer_capability_status
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_version_compare import PostgresVersionCompare, _identifier


COMPARE='planning.version.cross-layer.compare'
SCAN='planning.version.cross-layer.scan'
FUNCTIONS=frozenset((COMPARE,SCAN))
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB=re.compile(r'[0-9a-f]{32}\Z')


def catalog():
    common={'mode':'read','permission':'read','requiredCapabilities':[],
      'previewRequired':False,'idempotencyRequired':False,'workClass':'short'}
    pins={'baselineLayer':'Raw or Adjusted','snapshotRevision':'committed baseline snapshot',
      'resultKey':'pinned untyped calculated result','generationId':'exact generation',
      'publishedRevision':'exact publication revision','scenarioDimensionId':'active non-Currency axis',
      'baselineMemberId':'baseline scenario member','targetMemberId':'distinct calculated scenario member'}
    return {COMPARE:{**common,'arguments':{**pins,
      'coordinates':'1-500 complete coordinates excluding scenario axis'},
      'result':'labelled baseline and calculated cells plus targetMinusBaseline when both present'},
      SCAN:{**common,'arguments':pins,'optionalArguments':{
      'members':'active filters excluding scenario axis','limit':'1-500','cursor':'sole continuation argument'},
      'result':'subject-bound generation/snapshot-pinned variance pages'}}


def _cell(raw_present,raw_amount,raw_change,adjustment,line_count,
          journal_revision,layer):
    raw_present=bool(raw_present); adjustment=adjustment or Decimal(0)
    present=(raw_present if layer=='Raw' else raw_present or bool(line_count))
    amount=None
    if present:
        with localcontext() as context:
            context.prec=64
            amount=(raw_amount if raw_present else Decimal(0)) + (
                adjustment if layer=='Adjusted' else Decimal(0))
        NumericCell(True,amount,'')
    return {'layer':layer,'present':present,
      'amount':format(amount,'.8f') if present else None,
      'rawPresent':raw_present,'rawChangeId':raw_change or '',
      'journalNet':format(adjustment,'.8f') if layer=='Adjusted' else None,
      'journalLineCount':(line_count or 0) if layer=='Adjusted' else None,
      'lastJournalRevision':journal_revision if layer=='Adjusted' else None}


def _wire(row,layer):
    if row['baseline_text_present']:
        raise ValueError('CROSS_LAYER_NUMERIC_TEXT_CONFLICT')
    baseline=_cell(row['baseline_present'],row['baseline_amount'],
        row['baseline_change_id'],row['adjustment_amount'],row['line_count'],
        row['last_journal_revision'],layer)
    target={'layer':'Calculated','present':row['calculated_amount'] is not None,
      'amount':format(row['calculated_amount'],'.8f') if
        row['calculated_amount'] is not None else None,
      'sourceAmount':format(row['source_amount'],'.8f') if
        row['source_amount'] is not None else None,
      'sourceChangeId':row['source_change_id'] or '',
      'sourceLookupLineage':row['source_lookup_lineage'] or []}
    delta=None
    if baseline['present'] and target['present']:
        with localcontext() as context:
            context.prec=64
            delta=row['calculated_amount']-Decimal(baseline['amount'])
        NumericCell(True,delta,'')
    return {'comparisonMembers':row['other_members'],'baseline':baseline,
      'target':target,'targetMinusBaseline':format(delta,'.8f') if delta is not None else None}


class PostgresCrossLayerVersion(PostgresCubeQuery):
    def __init__(self,dsn,*,identity:VerifiedIdentity,cursor_secret:bytes):
        super().__init__(dsn,identity=identity,cursor_secret=cursor_secret)

    def read(self,scope:ApplicationScope,program:dict)->dict:
        if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
                or program.get('languageVersion')!=2 or program.get('function') not in FUNCTIONS
                or not isinstance(program.get('arguments'),dict)):
            raise ValueError('CROSS_LAYER_PROGRAM_INVALID')
        function=program['function'];args=program['arguments']
        if function==SCAN and set(args)=={'cursor'}:
            request=self._unpack(args['cursor'],scope); continuation=True
        else:
            request=self._first(function,args);continuation=False
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute('SET TRANSACTION READ ONLY');configure_statement_timeout(db,5000)
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=function)
            state=db.execute('''SELECT metadata_revision,commit_revision FROM epm.application_state
              WHERE workspace_id=%s AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
            if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
            if continuation and state['metadata_revision']!=request['metadataRevision']:
                raise ValueError('STALE_METADATA_REVISION')
            if request['snapshotRevision']>state['commit_revision']:
                raise ValueError('SNAPSHOT_NOT_COMMITTED')
            active_axes=self._validate(db,scope,request,complete=function==COMPARE)
            generation=PostgresCubeLayerReport._generation(db,scope,request['resultKey'],
                request['generationId'],request['publishedRevision'])
            PostgresCubeLayerReport._require_untyped(generation)
            current=db.execute('''SELECT generation_id,published_revision FROM
              epm.calculation_publication WHERE workspace_id=%s AND application_id=%s
              AND result_key=%s''',(scope.workspace_id,scope.application_id,request['resultKey'])).fetchone()
            if not continuation and (current is None or current['generation_id']!=request['generationId']
                    or current['published_revision']!=request['publishedRevision']):
                raise ValueError('CROSS_LAYER_PUBLICATION_STALE')
            rows=(self._compare_rows(db,scope,request) if function==COMPARE else
                self._scan_rows(db,scope,request,request['limit']+1))
            expected_axes=active_axes-{request['scenarioDimensionId']}
            if any(set(row['comparisonMembers'])!=expected_axes for row in rows):
                raise ValueError('COORDINATE_DIMENSIONS_MISMATCH')
            deep=PostgresCubeLayerReport._deep_status(db,scope,generation)
            current=db.execute('''SELECT generation_id,published_revision FROM
              epm.calculation_publication WHERE workspace_id=%s AND application_id=%s
              AND result_key=%s''',(scope.workspace_id,scope.application_id,
              request['resultKey'])).fetchone()
            after_state=db.execute('''SELECT metadata_revision FROM epm.application_state
              WHERE workspace_id=%s AND application_id=%s''',(
              scope.workspace_id,scope.application_id)).fetchone()
            if after_state is None or after_state['metadata_revision']!=state['metadata_revision']:
                raise ValueError('STALE_METADATA_REVISION')
        page=rows if function==COMPARE else rows[:request['limit']]
        has_more=function==SCAN and len(rows)>request['limit']
        next_cursor=(self._pack({**request,'function':SCAN,
            'metadataRevision':state['metadata_revision'],
            'after':page[-1]['comparisonMembers'],'expiresAt':request['expiresAt'],
            '_scope':[scope.workspace_id,scope.application_id],
            '_identity':[self.identity.issuer,self.identity.subject_id]})
            if has_more else None)
        pointer_current=bool(current and current['generation_id']==request['generationId']
            and current['published_revision']==request['publishedRevision'])
        revision_status=input_revision_status(generation)
        revision_status['matchesAtRead'] &= deep['matchesAtRead']
        return {'function':function,'baselineLayer':request['baselineLayer'],
          'scenarioDimensionId':request['scenarioDimensionId'],
          'baselineMemberId':request['baselineMemberId'],'targetMemberId':request['targetMemberId'],
          'snapshotRevision':request['snapshotRevision'],'metadataRevision':state['metadata_revision'],
          'calculation':{'resultKey':request['resultKey'],'generationId':request['generationId'],
            'publishedRevision':request['publishedRevision'],'pointerCurrent':pointer_current,
            'inputRevisionStatus':revision_status,'deepSourceStatus':deep,
            'producerCapabilities':producer_capability_status(
              generation['function_name'],generation['normalized_program'],
              generation['enabled_capabilities'],generation['capability_revision'])},
          'rows':page,'hasMore':has_more,
          'nextCursor':next_cursor,'arithmetic':'calculated_target_minus_labelled_baseline_only'}

    def _first(self,function,args):
        base={'baselineLayer','snapshotRevision','resultKey','generationId','publishedRevision',
          'scenarioDimensionId','baselineMemberId','targetMemberId'}
        extra={'coordinates'} if function==COMPARE else set()
        optional=set() if function==COMPARE else {'members','limit'}
        if (set(args)-base-extra-optional or not base|extra<=set(args)
                or args['baselineLayer'] not in ('Raw','Adjusted')
                or type(args['snapshotRevision']) is not int or args['snapshotRevision']<0
                or not isinstance(args['resultKey'],str) or not _KEY.fullmatch(args['resultKey'])
                or not isinstance(args['generationId'],str) or not _JOB.fullmatch(args['generationId'])
                or type(args['publishedRevision']) is not int or args['publishedRevision']<1):
            raise ValueError('CROSS_LAYER_ARGUMENTS_INVALID')
        request=dict(args);request['scenarioDimensionId']=_identifier(args['scenarioDimensionId'],'Dimension ID')
        request['baselineMemberId']=_identifier(args['baselineMemberId'],'Member ID')
        request['targetMemberId']=_identifier(args['targetMemberId'],'Member ID')
        if request['baselineMemberId']==request['targetMemberId']:
            raise ValueError('VERSION_COMPARE_DISTINCT_MEMBERS_REQUIRED')
        if function==COMPARE:
            coords=args['coordinates']
            if not isinstance(coords,list) or not 1<=len(coords)<=500:raise ValueError('CROSS_LAYER_BOUNDS_INVALID')
            request['coordinates']=[dict(sorted((_identifier(axis,'Dimension ID'),
                _identifier(member,'Member ID')) for axis,member in item.items()))
                for item in coords if isinstance(item,dict)
                and request['scenarioDimensionId'] not in item]
            if len(request['coordinates'])!=len(coords) or len({json.dumps(x,sort_keys=True) for x in request['coordinates']})!=len(coords):
                raise ValueError('CROSS_LAYER_COORDINATE_INVALID')
        else:
            request['members']=_filter_members(args.get('members',{}));request['limit']=args.get('limit',100)
            if (request['scenarioDimensionId'] in request['members'] or type(request['limit']) is not int
                    or not 1<=request['limit']<=500):raise ValueError('CROSS_LAYER_BOUNDS_INVALID')
            request.update({'after':None,'metadataRevision':None,'expiresAt':int(time.time())+3600})
        return request

    @staticmethod
    def _validate(db,scope,request,*,complete):
        axes=db.execute('''SELECT dimension_id FROM epm.dimension WHERE workspace_id=%s
          AND application_id=%s AND status='Active' AND model_role IS DISTINCT FROM 'Currency' ''',
          (scope.workspace_id,scope.application_id)).fetchall()
        active_axes={x['dimension_id'] for x in axes}
        if complete:
            PostgresVersionCompare._validate_metadata(db,scope,request['scenarioDimensionId'],
              request['baselineMemberId'],request['targetMemberId'],request['coordinates'])
        else:
            PostgresCubeLayerReport._validate_filters(db,scope,request['members'])
            if request['scenarioDimensionId'] not in active_axes:
                raise ValueError('VERSION_COMPARE_DIMENSION_UNAVAILABLE')
            found=db.execute('''SELECT member_id FROM epm.member WHERE workspace_id=%s
              AND application_id=%s AND dimension_id=%s AND status='Active'
              AND member_id=ANY(%s::text[])''',(scope.workspace_id,scope.application_id,
              request['scenarioDimensionId'],[request['baselineMemberId'],
              request['targetMemberId']])).fetchall()
            if {x['member_id'] for x in found}!={request['baselineMemberId'],request['targetMemberId']}:
                raise ValueError('VERSION_COMPARE_MEMBER_UNAVAILABLE')
        return active_axes

    @staticmethod
    def _base_sql():
        return '''SELECT q.other_members,n.present AS baseline_present,
          n.resulting_amount AS baseline_amount,n.change_id AS baseline_change_id,
          t.present AS baseline_text_present,j.adjustment_amount,j.line_count,
          j.last_journal_revision,r.source_amount,r.source_change_id,
          r.amount AS calculated_amount,r.source_lookup_lineage
          FROM requested q
          LEFT JOIN epm.coordinate b ON b.workspace_id=%s AND b.application_id=%s
            AND b.members=q.other_members||jsonb_build_object(%s::text,%s::text)
          LEFT JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s
            AND c.members=q.other_members||jsonb_build_object(%s::text,%s::text)
          LEFT JOIN LATERAL(SELECT present,resulting_amount,change_id FROM epm.numeric_fact_event
            WHERE workspace_id=b.workspace_id AND application_id=b.application_id
              AND coordinate_id=b.coordinate_id AND committed_revision<=%s
            ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)n ON true
          LEFT JOIN LATERAL(SELECT present FROM epm.text_fact_event
            WHERE workspace_id=b.workspace_id AND application_id=b.application_id
              AND coordinate_id=b.coordinate_id AND committed_revision<=%s
            ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)t ON true
          LEFT JOIN LATERAL(SELECT COALESCE(sum(l.signed_amount),0) adjustment_amount,
            count(*) line_count,max(h.committed_revision) last_journal_revision
            FROM epm.manual_journal_line l JOIN epm.manual_journal h
            USING(workspace_id,application_id,journal_id) WHERE l.workspace_id=b.workspace_id
            AND l.application_id=b.application_id AND l.coordinate_id=b.coordinate_id
            AND h.committed_revision<=%s)j ON true
          LEFT JOIN epm.calculation_result r ON r.workspace_id=c.workspace_id
            AND r.application_id=c.application_id AND r.coordinate_id=c.coordinate_id
            AND r.generation_id=%s'''

    def _compare_rows(self,db,scope,r):
        rows=db.execute('''WITH requested AS (SELECT value other_members FROM
          jsonb_array_elements(%s::jsonb)) '''+self._base_sql()+''' ORDER BY q.other_members''',
          (Jsonb(r['coordinates']),scope.workspace_id,scope.application_id,r['scenarioDimensionId'],
           r['baselineMemberId'],scope.workspace_id,scope.application_id,r['scenarioDimensionId'],
           r['targetMemberId'],r['snapshotRevision'],r['snapshotRevision'],r['snapshotRevision'],
           r['generationId'])).fetchall()
        return [_wire(x,r['baselineLayer']) for x in rows]

    def _scan_rows(self,db,scope,r,limit):
        filters=''.join(' AND other_members->>%s=%s' for _ in r['members'])
        params=[item for pair in r['members'].items() for item in pair]
        after=None if r['after'] is None else Jsonb(r['after'])
        rows=db.execute(f'''WITH candidates AS (
          SELECT c.members-%s::text other_members FROM epm.coordinate c
          JOIN epm.numeric_fact_event n USING(workspace_id,application_id,coordinate_id)
          WHERE c.workspace_id=%s AND c.application_id=%s AND c.members->>%s=%s
            AND n.committed_revision<=%s
          UNION SELECT c.members-%s::text FROM epm.coordinate c
            JOIN epm.text_fact_event t USING(workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND c.members->>%s=%s
            AND t.committed_revision<=%s
          UNION SELECT c.members-%s::text FROM epm.coordinate c JOIN epm.manual_journal_line l
            USING(workspace_id,application_id,coordinate_id) JOIN epm.manual_journal h
            USING(workspace_id,application_id,journal_id) WHERE c.workspace_id=%s
            AND c.application_id=%s AND c.members->>%s=%s AND h.committed_revision<=%s
          UNION SELECT c.members-%s::text FROM epm.coordinate c JOIN epm.calculation_result x
            USING(workspace_id,application_id,coordinate_id) WHERE c.workspace_id=%s
            AND c.application_id=%s AND c.members->>%s=%s AND x.generation_id=%s),
          requested AS (SELECT DISTINCT other_members FROM candidates WHERE
            (%s::jsonb IS NULL OR other_members>%s::jsonb)
            {filters} ORDER BY other_members LIMIT %s) '''+self._base_sql()+''' ORDER BY q.other_members''',(
          r['scenarioDimensionId'],scope.workspace_id,scope.application_id,r['scenarioDimensionId'],
          r['baselineMemberId'],r['snapshotRevision'],r['scenarioDimensionId'],scope.workspace_id,
          scope.application_id,r['scenarioDimensionId'],r['baselineMemberId'],r['snapshotRevision'],
          r['scenarioDimensionId'],scope.workspace_id,
          scope.application_id,r['scenarioDimensionId'],r['baselineMemberId'],r['snapshotRevision'],
          r['scenarioDimensionId'],scope.workspace_id,scope.application_id,r['scenarioDimensionId'],
          r['targetMemberId'],r['generationId'],after,after,*params,limit,
          scope.workspace_id,scope.application_id,r['scenarioDimensionId'],r['baselineMemberId'],
          scope.workspace_id,scope.application_id,r['scenarioDimensionId'],r['targetMemberId'],
          r['snapshotRevision'],r['snapshotRevision'],r['snapshotRevision'],r['generationId'])).fetchall()
        return [_wire(x,r['baselineLayer']) for x in rows]

    def _pack(self,payload):
        raw=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        return base64.urlsafe_b64encode(raw+hmac.new(self.cursor_secret,raw,sha256).digest()).decode()

    def _unpack(self,token,scope):
        if not isinstance(token,str) or len(token)>32768:raise ValueError('CROSS_LAYER_CURSOR_INVALID')
        try:
            packed=base64.b64decode(token,altchars=b'-_',validate=True);raw,sig=packed[:-32],packed[-32:]
            if not hmac.compare_digest(sig,hmac.new(self.cursor_secret,raw,sha256).digest()):raise ValueError('sig')
            p=json.loads(raw)
        except (ValueError,TypeError,binascii.Error) as error:raise ValueError('CROSS_LAYER_CURSOR_INVALID') from error
        expected={'baselineLayer','snapshotRevision','resultKey','generationId','publishedRevision',
          'scenarioDimensionId','baselineMemberId','targetMemberId','members','limit','after',
          'metadataRevision','expiresAt','function','_scope','_identity'}
        if (not isinstance(p,dict) or set(p)!=expected or p['function']!=SCAN
                or p['_scope']!=[scope.workspace_id,scope.application_id]
                or p['_identity']!=[self.identity.issuer,self.identity.subject_id]
                or p['baselineLayer'] not in ('Raw','Adjusted')
                or type(p['snapshotRevision']) is not int or p['snapshotRevision']<0
                or not isinstance(p['resultKey'],str) or not _KEY.fullmatch(p['resultKey'])
                or not isinstance(p['generationId'],str) or not _JOB.fullmatch(p['generationId'])
                or type(p['publishedRevision']) is not int or p['publishedRevision']<1
                or type(p['metadataRevision']) is not int or p['metadataRevision']<0
                or type(p['limit']) is not int or not 1<=p['limit']<=500
                or not isinstance(p['after'],dict) or not isinstance(p['members'],dict)
                or type(p['expiresAt']) is not int or p['expiresAt']<time.time()):
            raise ValueError('CROSS_LAYER_CURSOR_INVALID')
        p.pop('_scope');p.pop('_identity')
        p['members']=_filter_members(p['members'])
        return p
