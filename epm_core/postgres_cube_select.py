"""Bounded, current-state-pinned member-set selection of source coordinates."""
import base64
import binascii
import hmac
import json
import time
from hashlib import sha256

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .persistence_contract import ApplicationScope
from .postgres_connection import connect_postgres
from .postgres_access import PostgresAccessChecker
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_cube_query import PostgresCubeQuery,_SERIES_KEY
from .postgres_processing_limits import configure_statement_timeout
from .postgres_dimensional_security_enforcement import filter_read_rows
from .current_object_contract import require_state_token

FUNCTION='facts.cube.select'
VERSION=1
MAX_INTENT_BYTES=16384
MAX_SELECTED_MEMBERS=10000
MAX_AXIS_MEMBERS=5000


def _id(value):
    if not isinstance(value,str) or not 1<=len(value)<=200 or value!=value.strip() or '\x00' in value:
        raise ValueError('CUBE_SELECTION_ID_INVALID')
    return value


def arguments(args):
    if (not isinstance(args,dict) or not {'grain','selectors'}<=set(args)
            or set(args)-{'grain','selectors','limit','snapshotRevision','includeMissing'}):
        raise ValueError('CUBE_SELECTION_ARGUMENTS_INVALID')
    grain=args['grain'];selectors=args['selectors']
    if (not isinstance(grain,dict) or set(grain)!={'mode','dimensions'} or grain['mode']!='full_coordinate'
            or not isinstance(grain['dimensions'],list) or not 1<=len(grain['dimensions'])<=128):
        raise ValueError('CUBE_SELECTION_GRAIN_INVALID')
    dimensions=sorted(_id(v) for v in grain['dimensions'])
    if len(set(dimensions))!=len(dimensions):raise ValueError('CUBE_SELECTION_GRAIN_INVALID')
    if not isinstance(selectors,dict) or not 1<=len(selectors)<=16:raise ValueError('CUBE_SELECTION_BOUNDS')
    normalized={};explicit=0
    for axis,selector in selectors.items():
        _id(axis)
        if axis not in dimensions or not isinstance(selector,dict):raise ValueError('CUBE_SELECTION_AXIS_INVALID')
        kind=selector.get('kind')
        if kind=='Members':
            if set(selector)!={'kind','memberIds'} or not isinstance(selector['memberIds'],list) or not 1<=len(selector['memberIds'])<=500:
                raise ValueError('CUBE_SELECTION_MEMBERS_INVALID')
            ids=sorted(_id(v) for v in selector['memberIds']);explicit+=len(ids)
            if len(set(ids))!=len(ids):raise ValueError('CUBE_SELECTION_MEMBERS_INVALID')
            normalized[axis]={'kind':kind,'memberIds':ids}
        elif kind in ('Descendants','Children','Leaves'):
            if (not {'kind','rootMemberId','includeSelf'} <= set(selector)
                or set(selector)-{'kind','rootMemberId','includeSelf','hierarchyId'}
                or type(selector['includeSelf']) is not bool):
                raise ValueError('CUBE_SELECTION_HIERARCHY_INVALID')
            normalized[axis]={'kind':kind,'rootMemberId':_id(selector['rootMemberId']),
                'includeSelf':selector['includeSelf'],
                **({'hierarchyId':_id(selector['hierarchyId'])} if 'hierarchyId' in selector else {})}
        else:raise ValueError('CUBE_SELECTION_KIND_INVALID')
    if explicit>500:raise ValueError('CUBE_SELECTION_BOUNDS')
    limit=args.get('limit',100);missing=args.get('includeMissing',False)
    if type(limit) is not int or not 1<=limit<=500 or type(missing) is not bool:raise ValueError('CUBE_SELECTION_BOUNDS')
    result={'grain':{'mode':'full_coordinate','dimensions':dimensions},'selectors':dict(sorted(normalized.items())),
        'limit':limit,'includeMissing':missing}
    if 'snapshotRevision' in args:
        if type(args['snapshotRevision']) is not int or args['snapshotRevision']<0:raise ValueError('SNAPSHOT_REVISION_INVALID')
        result['snapshotRevision']=args['snapshotRevision']
    if len(json.dumps(result,ensure_ascii=False).encode())>MAX_INTENT_BYTES:raise ValueError('CUBE_SELECTION_BOUNDS')
    return result


def program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2 or raw['function']!=FUNCTION
            or not isinstance(raw['arguments'],dict)):
        raise ValueError('CUBE_SELECTION_PROGRAM_INVALID')
    if set(raw['arguments'])=={'cursor'}:
        if not isinstance(raw['arguments']['cursor'],str):raise ValueError('CUBE_SELECTION_CURSOR_INVALID')
        return raw['arguments']
    return arguments(raw['arguments'])


class PostgresCubeSelect(PostgresCubeQuery):
    def _cursor(self,token,scope):
        if not isinstance(token,str) or len(token)>65536:raise ValueError('CUBE_SELECTION_CURSOR_INVALID')
        try:
            value=base64.b64decode(token,altchars=b'-_',validate=True);raw,signature=value[:-32],value[-32:]
            if not hmac.compare_digest(hmac.new(self.cursor_secret,raw,sha256).digest(),signature):raise ValueError('signature')
            payload=json.loads(raw)
            if (not isinstance(payload,dict) or set(payload)!={'version','function','scope','identity','intent','pins','after','expiresAt'}
                    or type(payload['version']) is not int or payload['version']!=VERSION or payload['function']!=FUNCTION
                    or payload['scope']!=[scope.workspace_id,scope.application_id]
                    or payload['identity']!=[self.identity.issuer,self.identity.subject_id]
                    or not isinstance(payload['after'],str) or not _SERIES_KEY.fullmatch(payload['after'])
                    or type(payload['expiresAt']) is not int or payload['expiresAt']<time.time()
                    or arguments(payload['intent'])!=payload['intent']):raise ValueError('shape')
            pins=payload['pins'];axes={a for a,s in payload['intent']['selectors'].items() if s['kind']!='Members'}
            if (not isinstance(pins,dict) or set(pins)!={'metadataRevision','snapshotRevision','hierarchyStateTokens'}
                    or any(type(pins[k]) is not int or pins[k]<0 for k in ('metadataRevision','snapshotRevision'))
                    or not isinstance(pins['hierarchyStateTokens'],dict) or set(pins['hierarchyStateTokens'])!=axes
                    or any(require_state_token(v,error='pins')!=v for v in pins['hierarchyStateTokens'].values())
                    or ('snapshotRevision' in payload['intent'] and payload['intent']['snapshotRevision']!=pins['snapshotRevision'])):
                raise ValueError('pins')
            return payload
        except (KeyError,TypeError,ValueError,binascii.Error) as error:
            raise ValueError('CUBE_SELECTION_CURSOR_INVALID') from error

    @staticmethod
    def _resolve(db,scope,intent,metadata_revision,hierarchy_pins=None):
        configure_statement_timeout(db,5000)
        active=sorted(r['dimension_id'] for r in db.execute('''SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            AND model_role IS DISTINCT FROM 'Currency' ORDER BY dimension_id''',
            (scope.workspace_id,scope.application_id)).fetchall())
        if active!=intent['grain']['dimensions']:raise ValueError('CUBE_SELECTION_GRAIN_MISMATCH')
        lookups=[];specs=[]
        for axis,s in intent['selectors'].items():
            ids=s['memberIds'] if s['kind']=='Members' else [s['rootMemberId']]
            lookups.extend({'dimension_id':axis,'member_id':m} for m in ids)
            specs.append({'dimension_id':axis,'kind':s['kind'],'member_ids':ids if s['kind']=='Members' else [],
                'root':s.get('rootMemberId'),'include_self':s.get('includeSelf',False),
                'hierarchy_id':s.get('hierarchyId'),
                'requested_state_token':(hierarchy_pins[axis] if hierarchy_pins is not None and axis in hierarchy_pins
                    else None)})
        invalid=db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb) i(dimension_id text,member_id text)
            LEFT JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s AND m.dimension_id=i.dimension_id
            AND m.member_id=i.member_id AND m.status='Active' WHERE m.member_id IS NULL LIMIT 1''',
            (Jsonb(lookups),scope.workspace_id,scope.application_id)).fetchone()
        if invalid:raise ValueError('CUBE_SELECTION_MEMBER_UNAVAILABLE')
        states=db.execute("""SELECT i.dimension_id,d.hierarchy_id,s.state_token,s.metadata_revision,
            EXISTS(SELECT 1 FROM epm.hierarchy_closure c WHERE c.workspace_id=s.workspace_id
              AND c.application_id=s.application_id AND c.dimension_id=s.dimension_id
              AND c.hierarchy_id=s.hierarchy_id AND c.state_token=s.state_token
              AND c.ancestor_member_id=i.root AND c.descendant_member_id=i.root) AS root_present
            FROM jsonb_to_recordset(%s::jsonb) i(dimension_id text,kind text,requested_state_token text,hierarchy_id text,root text)
            LEFT JOIN epm.hierarchy_definition d ON d.workspace_id=%s AND d.application_id=%s
              AND d.dimension_id=i.dimension_id AND d.status='Active'
              AND ((i.hierarchy_id IS NULL AND d.is_default) OR d.hierarchy_id=i.hierarchy_id)
            LEFT JOIN epm.hierarchy_state s ON s.workspace_id=d.workspace_id
              AND s.application_id=d.application_id AND s.dimension_id=d.dimension_id
              AND s.hierarchy_id=d.hierarchy_id
              AND (i.requested_state_token IS NULL OR s.state_token=i.requested_state_token)
            WHERE i.kind<>'Members' """,(Jsonb(specs),scope.workspace_id,scope.application_id)).fetchall()
        if any(r['state_token'] is None for r in states):raise ValueError('CUBE_SELECTION_HIERARCHY_UNAVAILABLE')
        if any(not r['root_present'] for r in states):raise ValueError('CUBE_SELECTION_HIERARCHY_MEMBER_UNAVAILABLE')
        if any(r['metadata_revision']!=metadata_revision for r in states):raise ValueError('CUBE_SELECTION_HIERARCHY_STALE')
        resolved={r['dimension_id']:r['state_token'] for r in states}
        resolved_hierarchy_ids={r['dimension_id']:r['hierarchy_id'] for r in states}
        for spec in specs:
            spec['state_token']=resolved.get(spec['dimension_id'])
            if spec['kind']!='Members':spec['hierarchy_id']=resolved_hierarchy_ids.get(spec['dimension_id'])
        configure_statement_timeout(db,5000)
        selected=db.execute('''WITH specs AS (
            SELECT * FROM jsonb_to_recordset(%s::jsonb)
            i(dimension_id text,kind text,member_ids text[],root text,include_self boolean,state_token text,hierarchy_id text)),
        choices AS (
            SELECT i.dimension_id,u.member_id FROM specs i CROSS JOIN LATERAL unnest(i.member_ids) u(member_id)
            WHERE i.kind='Members'
            UNION
            SELECT i.dimension_id,h.descendant_member_id FROM specs i JOIN epm.hierarchy_closure h
            ON h.workspace_id=%s AND h.application_id=%s AND h.dimension_id=i.dimension_id
            AND h.hierarchy_id=i.hierarchy_id AND h.state_token=i.state_token
            AND h.ancestor_member_id=i.root
            WHERE i.kind<>'Members' AND (h.min_depth>0 OR i.include_self)
            AND (i.kind<>'Children' OR h.min_depth=1 OR (i.include_self AND h.min_depth=0))
            AND (i.kind<>'Leaves' OR NOT EXISTS (SELECT 1 FROM epm.hierarchy_closure child
                WHERE child.workspace_id=h.workspace_id AND child.application_id=h.application_id
                AND child.dimension_id=h.dimension_id AND child.hierarchy_id=h.hierarchy_id
                AND child.state_token=h.state_token
                AND child.ancestor_member_id=h.descendant_member_id AND child.min_depth>0)))
        SELECT dimension_id,member_id FROM choices ORDER BY dimension_id,member_id LIMIT 10001''',
            (Jsonb(specs),scope.workspace_id,scope.application_id)).fetchall()
        sets={axis:[] for axis in intent['selectors']}
        if len(selected)>MAX_SELECTED_MEMBERS:raise ValueError('CUBE_SELECTION_EXPANSION_BUDGET')
        for row in selected:sets[row['dimension_id']].append(row['member_id'])
        if any(len(ids)>MAX_AXIS_MEMBERS for ids in sets.values()):raise ValueError('CUBE_SELECTION_EXPANSION_BUDGET')
        return sets,resolved

    def select(self,scope,raw):
        if not isinstance(scope,ApplicationScope):raise ValueError('CUBE_SELECTION_SCOPE_INVALID')
        args=program(raw);payload=self._cursor(args['cursor'],scope) if 'cursor' in args else None
        intent=payload['intent'] if payload else args
        after=payload['after'] if payload else ''
        snapshot=payload['pins']['snapshotRevision'] if payload else intent.get('snapshotRevision')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read')
                state=db.execute('''SELECT metadata_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
                if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
                metadata=state['metadata_revision']
                if payload and metadata!=payload['pins']['metadataRevision']:raise ValueError('STALE_METADATA_REVISION')
                snapshot=state['commit_revision'] if snapshot is None else snapshot
                if snapshot>state['commit_revision']:raise ValueError('SNAPSHOT_NOT_COMMITTED')
                sets,state_tokens=self._resolve(db,scope,intent,metadata,payload['pins']['hierarchyStateTokens'] if payload else None)
                configure_statement_timeout(db,5000)
                rows=self._page(db,scope,{},after,snapshot,state['commit_revision'],intent['includeMissing'],intent['limit']+1,member_sets=sets)
                source='postgres_current' if snapshot==state['commit_revision'] else 'postgres_event_history'
                configure_statement_timeout(db,5000)
                final=db.execute('''SELECT metadata_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
                if final is None:raise ValueError('APPLICATION_UNAVAILABLE')
                if final['metadata_revision']!=metadata:raise ValueError('STALE_METADATA_REVISION')
                if source=='postgres_current' and final['commit_revision']!=snapshot:
                    configure_statement_timeout(db,5000)
                    rows=self._page(db,scope,{},after,snapshot,final['commit_revision'],intent['includeMissing'],intent['limit']+1,member_sets=sets)
                    source='postgres_event_history'
                    final_metadata=db.execute('''SELECT metadata_revision FROM epm.application_state
                        WHERE workspace_id=%s AND application_id=%s''',
                        (scope.workspace_id,scope.application_id)).fetchone()
                    if final_metadata is None or final_metadata['metadata_revision']!=metadata:
                        raise ValueError('STALE_METADATA_REVISION')
                raw_page=rows[:intent['limit']]
                page=filter_read_rows(db,self.identity,scope,raw_page)
        more=len(rows)>intent['limit'];pins={'metadataRevision':metadata,'snapshotRevision':snapshot,'hierarchyStateTokens':state_tokens}
        cursor=self._pack({'version':VERSION,'function':FUNCTION,'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],'intent':intent,'pins':pins,
            'after':raw_page[-1]['seriesKey'],'expiresAt':payload['expiresAt'] if payload else int(time.time())+3600}) if more else None
        return {'rows':page,'hasMore':more,'nextCursor':cursor,'source':source,'grain':intent['grain'],**pins,
            'selectedMemberCounts':{axis:len(ids) for axis,ids in sets.items()},'aggregation':'none','profileVersion':VERSION}


def catalog():
    from .postgres_numeric_catalog import obj,program_schema
    id_schema={'type':'string','minLength':1,'maxLength':200}
    member=obj({'kind':{'const':'Members'},'memberIds':{'type':'array','minItems':1,'maxItems':500,'uniqueItems':True,'items':id_schema}})
    hierarchy=obj({'kind':{'enum':['Descendants','Children','Leaves']},'rootMemberId':id_schema,
        'includeSelf':{'type':'boolean'},'hierarchyId':id_schema}, ['kind','rootMemberId','includeSelf'])
    fields={'grain':obj({'mode':{'const':'full_coordinate'},'dimensions':{'type':'array','minItems':1,'maxItems':128,'uniqueItems':True,'items':id_schema}}),
        'selectors':{'type':'object','minProperties':1,'maxProperties':16,'propertyNames':id_schema,'additionalProperties':{'oneOf':[member,hierarchy]}},
        'limit':{'type':'integer','minimum':1,'maximum':500},'includeMissing':{'type':'boolean'},'snapshotRevision':{'type':'integer','minimum':0}}
    first=obj(fields,['grain','selectors']);cursor=obj({'cursor':{'type':'string','maxLength':65536}})
    schema=program_schema(FUNCTION,{'oneOf':[first,cursor]})
    sample={'languageVersion':2,'function':FUNCTION,'arguments':{'grain':{'mode':'full_coordinate','dimensions':['Metric']},
        'selectors':{'Metric':{'kind':'Leaves','rootMemberId':'Total','includeSelf':False}},'limit':100}}
    row=obj({'seriesKey':{'type':'string','pattern':'^[0-9a-f]{64}$'},
        'members':{'type':'object','minProperties':1,'additionalProperties':id_schema},
        'kind':{'enum':['numeric','text','missing']},'present':{'type':'boolean'},
        'amount':{'type':['string','null']},'text':{'type':['string','null']},
        'changeId':{'type':'string'},'numericChangeId':{'type':'string'},'textChangeId':{'type':'string'},
        'lastRevision':{'type':['integer','null'],'minimum':0}})
    row['allOf']=[{'if':{'properties':{'kind':{'const':kind}}},'then':{'properties':{
        'present':{'const':kind!='missing'},'amount':{'type':'string' if kind=='numeric' else 'null'},
        'text':{'type':'string' if kind=='text' else 'null'}}}} for kind in ('numeric','text','missing')]
    result_schema={'$schema':'https://json-schema.org/draft/2020-12/schema',**obj({
        'rows':{'type':'array','maxItems':500,'items':row},'hasMore':{'type':'boolean'},
        'nextCursor':{'type':['string','null']},'source':{'enum':['postgres_current','postgres_event_history']},
        'grain':fields['grain'],'metadataRevision':{'type':'integer','minimum':0},
        'snapshotRevision':{'type':'integer','minimum':0},
        'hierarchyStateTokens':{'type':'object','additionalProperties':{'type':'string','pattern':'^[0-9a-f]{64}$'}},
        'selectedMemberCounts':{'type':'object','additionalProperties':{'type':'integer','minimum':0,'maximum':5000}},
        'aggregation':{'const':'none'},'profileVersion':{'const':VERSION}})}
    return {FUNCTION:{'mode':'read','permission':'read','arguments':fields,
        'result':'unaggregated exact source rows, explicit full grain, metadata/snapshot/hierarchy pins, bounded page and signed continuation',
        'previewRequired':False,'idempotencyRequired':False,'workClass':'bounded_read',
        'programContract':{'version':VERSION,'programSchema':schema,'resultSchema':result_schema,'semanticRules':[
            'Selectors form AND across axes and set membership within an axis; no aggregation, Cartesian expansion or duplicate source cell for shared paths.',
            'grain dimensions must equal all active fact axes except Currency; stable canonical IDs only. Counts are strict integers, never booleans/decimal tokens.',
            'Members require active IDs. Hierarchy selector roots/versions are scoped to this application/axis and built at current metadata revision. Stale hierarchy versions fail; no implicit rebuild.',
            'Descendants excludes root unless includeSelf. Children means minimum depth1 plus root when includeSelf. Leaves have no proper descendants in the current hierarchy state; includeSelf matters when root is itself a leaf.',
            'The current hierarchy resolves once and its opaque state token is pinned in the cursor. Replacing that hierarchy state invalidates continuation; a metadata revision change also rejects continuation. Data-only changes reconstruct the original committed snapshot from events.',
            'Limits:16 selector axes,128 full-grain axes,500 explicit IDs total,16KB normalized intent,5000 resolved members/axis and10000 total,1–500 rows/page,5s SQL stages and shorter inherited limits. Cursor expires1h from first page and binds identity/scope/profile/intent/pins/page size.',
            'Continuation arguments are cursor only. Each page rechecks current read authority. includeMissing exposes numeric/text event tombstones, not a synthetic full metadata Cartesian product or calculated-only coordinates. Present zero and empty text remain distinct.',
            'This profile reads raw numeric/text source state, including numeric supporting-detail totals. Calculation generations, merged financial layers and accounting placement rollups are separate functions.'
        ],'examples':[{'id':'leaves-at-full-grain','program':sample,
            'prerequisites':'Fresh generic Metric axis with Total→A and Total→B, current metadata hierarchy built through metadata.hierarchy.build, and authorized numeric/text values at A/B.'}],
            'execution':{'tool':'read_v2_program','scope':'Bound application or router with workspace_id/application_id',
                'continuation':'Use unchanged nextCursor as sole arguments.cursor; no new selectors or limit.'}}}}
