"""Read-only exact own-entity source; never includes descendants or calculated Full.

Caller holds the application-state fence. IC context is explicit: own-parent
inputs use the parent itself, while a leaf uses its declared consolidation parent.
Manual headers require current metadata pending a broader retained-unit policy.
"""
from decimal import Decimal, localcontext
from psycopg.types.json import Jsonb

from .persistence_contract import NumericCell
from .postgres_acquisition_contribution import acquisition_contributions
from .postgres_ic_contribution import ic_contributions
from .postgres_jobs import _canonical_digest
from .postgres_consolidation_stages import ACQUISITION_LAYERS


def resolve_own_source(db,scope,members,fact,layer,currency,account_type,ic_parent):
    if layer not in ACQUISITION_LAYERS:
        raise ValueError('OWN_SOURCE_LAYER_UNSUPPORTED')
    keys=(scope.workspace_id,scope.application_id)
    dimensions=db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',keys).fetchall()
    roles={row['model_role']:row['dimension_id'] for row in dimensions if row['model_role']!='Custom'}
    axes={row['dimension_id'] for row in dimensions if row['model_role']!='Currency'}
    if set(members)!=axes or 'Currency' not in roles:
        raise ValueError('OWN_SOURCE_GRAIN_INVALID')
    if db.execute('''SELECT count(*) AS n FROM jsonb_each_text(%s::jsonb) p
        JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
        AND m.dimension_id=p.key AND m.member_id=p.value AND m.status='Active' ''',
        (Jsonb(members),*keys)).fetchone()['n']!=len(axes):
        raise ValueError('OWN_SOURCE_MEMBER_UNAVAILABLE')
    coordinate_id=fact['coordinate_id'] if fact else None
    ids=[coordinate_id] if coordinate_id is not None else []
    manual=[]
    if 'manual_journal' in layer:
        manual=db.execute('''SELECT l.journal_id,l.line_ordinal,l.signed_amount,h.committed_revision,h.metadata_revision
            FROM epm.manual_journal_line l JOIN epm.manual_journal h
            USING(workspace_id,application_id,journal_id)
            WHERE l.workspace_id=%s AND l.application_id=%s AND l.coordinate_id=ANY(%s::bigint[])
            ORDER BY h.committed_revision,l.journal_id,l.line_ordinal LIMIT 501''',(*keys,ids)).fetchall()
        if len(manual)>500: raise ValueError('OWN_SOURCE_JOURNAL_LINE_LIMIT')
    metadata=db.execute('SELECT metadata_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s',keys).fetchone()['metadata_revision']
    if any(line['metadata_revision']!=metadata for line in manual):
        raise ValueError('OWN_SOURCE_MANUAL_METADATA_STALE')
    journals=[{'journalId':line['journal_id'],'lineOrdinal':line['line_ordinal'],
        'signedAmount':format(line['signed_amount'],'.8f'),'committedRevision':line['committed_revision'],
        'metadataRevision':line['metadata_revision']} for line in manual]
    acquisition=acquisition_contributions(db,scope,ids,roles['Currency'],currency,account_type).get(coordinate_id,[])
    ic=None
    if 'ic_elimination' in layer:
        if 'ICP' not in roles: raise ValueError('OWN_SOURCE_ICP_ROLE_REQUIRED')
        parent=db.execute('''SELECT entity_default_currency_member_id FROM epm.member
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
            AND member_id=%s AND status='Active' ''',(*keys,roles['Entity'],ic_parent)).fetchone()
        if parent is None or parent['entity_default_currency_member_id']!=currency:
            raise ValueError('OWN_SOURCE_IC_PARENT_CURRENCY_INVALID')
        if ic_parent!=members[roles['Entity']]:
            placements=db.execute('''SELECT parent_member_id FROM epm.relationship
                WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
                AND child_member_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' ''',
                (*keys,roles['Entity'],members[roles['Entity']])).fetchall()
            if len(placements)!=1 or placements[0]['parent_member_id']!=ic_parent:
                raise ValueError('OWN_SOURCE_IC_PARENT_PLACEMENT_INVALID')
        ic=ic_contributions(db,scope,ids,ic_parent).get(coordinate_id)
    raw=fact['amount'] if fact and fact['numeric_present'] else None
    # A stored line, including an exact linked correction netting to zero, gives
    # presence. A wholly absent source is never invented as numeric zero.
    if raw is None and not manual and not acquisition and ic is None:
        raise ValueError('CURRENCY_TRANSLATION_SOURCE_MISSING')
    with localcontext() as context:
        context.prec=64
        amount=(raw if raw is not None else Decimal(0))+sum((line['signed_amount'] for line in manual),Decimal(0))
        amount+=sum((Decimal(line['signedAmount']) for line in acquisition),Decimal(0))
        amount+=ic['signedAmount'] if ic else Decimal(0)
    NumericCell(True,amount,'')
    lineage={'sourceLayer':layer,'rawAmount':format(raw,'.8f') if raw is not None else None,
        'rawSourceChangeId':fact['change_id'] if raw is not None else '',
        'journalLines':journals,'acquisitionLines':acquisition,
        'icElimination':({**ic,'signedAmount':format(ic['signedAmount'],'.8f'),
            'matchedMagnitude':format(ic['matchedMagnitude'],'.8f'),
            'signedResidual':format(ic['signedResidual'],'.8f')} if ic else None),
        'icParentEntityId':ic_parent,'members':members,'present':True,'amount':format(amount,'.8f')}
    return amount,_canonical_digest(lineage),lineage
