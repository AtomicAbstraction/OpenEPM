"""Bounded, read-only acquisition-journal contributions to current Full stages.

Posted entries retain their original authority. Withdrawal does not erase an
entry; current activation is separate provenance. An unreversed entry requires
unchanged operational source/ownership/calendar pins and aligned currency.
Exact linked corrections may net to present zero even after sources change.
"""
from decimal import Decimal, localcontext

from psycopg.types.json import Jsonb

from .persistence_contract import NumericCell
from .postgres_acquisition_journal import ACCOUNT_TYPES

from .postgres_consolidation_stages import (
    ACQUISITION_LAYERS, ACQUISITION_LOCAL_STAGES as ACQUISITION_STAGES)


def acquisition_contributions(db,scope,coordinate_ids,currency_dimension_id,currency_member_id,account_type):
    """Caller holds state SHARE/UPDATE; no coordinate/data write is performed."""
    keys=(scope.workspace_id,scope.application_id)
    selected=sorted(set(point for point in coordinate_ids if point is not None))
    if not selected: return {}
    rows=db.execute('''SELECT l.coordinate_id,l.journal_id,l.line_ordinal,l.line_role,l.signed_amount,
        h.committed_revision,h.currency_dimension_id,h.currency_member_id,h.reversal_of,
        original.journal_id AS original_id,original.activation_id,original.manifest,
        correction.journal_id AS correction_id,
        active.activation_id AS current_activation_id,active.status AS current_activation_status
        FROM epm.acquisition_journal_line l JOIN epm.acquisition_journal h
        USING(workspace_id,application_id,journal_id)
        JOIN epm.acquisition_journal original ON original.workspace_id=h.workspace_id
        AND original.application_id=h.application_id
        AND original.journal_id=coalesce(h.reversal_of,h.journal_id)
        LEFT JOIN epm.acquisition_journal correction ON correction.workspace_id=original.workspace_id
        AND correction.application_id=original.application_id AND correction.reversal_of=original.journal_id
        LEFT JOIN epm.policy_activation_current active ON active.workspace_id=original.workspace_id
        AND active.application_id=original.application_id
        AND active.variant_key=original.manifest->'governedPolicy'->>'variantKey'
        WHERE l.workspace_id=%s AND l.application_id=%s AND l.coordinate_id=ANY(%s::bigint[])
        AND h.status='Posted' AND original.status='Posted'
        ORDER BY l.coordinate_id,h.committed_revision,l.journal_id,l.line_ordinal LIMIT 501''',
        (*keys,selected)).fetchall()
    if len(rows)>500: raise ValueError('FULL_AGGREGATE_ACQUISITION_LINE_LIMIT')
    originals={row['original_id']:row for row in rows}
    pins=[]; contexts=[]
    for original in originals.values():
        if original['correction_id'] is not None: continue
        if account_type not in ACCOUNT_TYPES.get(original['line_role'],()):
            raise ValueError('FULL_AGGREGATE_ACQUISITION_ACCOUNT_POLICY_MISMATCH')
        if (original['currency_dimension_id']!=currency_dimension_id
                or original['currency_member_id']!=currency_member_id):
            raise ValueError('FULL_AGGREGATE_ACQUISITION_CURRENCY_MISMATCH')
        manifest=original['manifest']
        inputs=manifest.get('inputs')
        governed=manifest.get('governedPolicy')
        ownership=manifest.get('ownershipSource'); calendar=manifest.get('calendarSource')
        if (not isinstance(inputs,dict) or not inputs or len(inputs)>9
                or not isinstance(governed,dict) or governed.get('activationId')!=original['activation_id']
                or not isinstance(ownership,dict) or not isinstance(calendar,dict)
                or any(not isinstance(ownership.get(key),str) for key in (
                    'relationshipId','scenarioId','yearId','periodId','changeId'))
                or not isinstance(calendar.get('changeId'),str)):
            raise ValueError('FULL_AGGREGATE_ACQUISITION_LINEAGE_INVALID')
        for source in inputs.values():
            if (not isinstance(source,dict) or type(source.get('coordinateId')) is not int
                    or not isinstance(source.get('changeId'),str)):
                raise ValueError('FULL_AGGREGATE_ACQUISITION_LINEAGE_INVALID')
            pins.append({'original_id':original['original_id'],
                'coordinate_id':source['coordinateId'],'change_id':source['changeId']})
        contexts.append({'relationship_id':ownership['relationshipId'],
            'scenario_id':ownership['scenarioId'],'year_id':ownership['yearId'],
            'period_id':ownership['periodId'],'ownership_change_id':ownership['changeId'],
            'calendar_change_id':calendar['changeId']})
    if pins and db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb)
        AS input(original_id text,coordinate_id bigint,change_id text)
        LEFT JOIN epm.numeric_cell_current n ON n.workspace_id=%s AND n.application_id=%s
        AND n.coordinate_id=input.coordinate_id AND n.present
        WHERE n.change_id IS DISTINCT FROM input.change_id LIMIT 1''',
        (Jsonb(pins),*keys)).fetchone():
        raise ValueError('FULL_AGGREGATE_ACQUISITION_SOURCE_STALE')
    if contexts and db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb)
        AS input(relationship_id text,scenario_id text,year_id text,period_id text,
                 ownership_change_id text,calendar_change_id text)
        LEFT JOIN epm.ownership_value_current o ON o.workspace_id=%s AND o.application_id=%s
        AND o.relationship_id=input.relationship_id AND o.scenario_member_id=input.scenario_id
        AND o.year_member_id=input.year_id AND o.period_member_id=input.period_id
        AND o.account_name='POWN' AND o.present
        LEFT JOIN epm.calendar_period_current c ON c.workspace_id=%s AND c.application_id=%s
        AND c.year_member_id=input.year_id AND c.period_member_id=input.period_id
        WHERE o.change_id IS DISTINCT FROM input.ownership_change_id
        OR c.change_id IS DISTINCT FROM input.calendar_change_id LIMIT 1''',
        (Jsonb(contexts),*keys,*keys)).fetchone():
        raise ValueError('FULL_AGGREGATE_ACQUISITION_SOURCE_STALE')
    result={}
    for row in rows:
        governed=row['manifest'].get('governedPolicy',{})
        if not isinstance(governed,dict): governed={}
        binding=governed.get('policyBinding',{})
        if not isinstance(binding,dict): binding={}
        entry={'journalId':row['journal_id'],'lineOrdinal':row['line_ordinal'],
            'lineRole':row['line_role'],'targetAccountTypeAtRead':account_type,
            'signedAmount':format(row['signed_amount'],'.8f'),
            'committedRevision':row['committed_revision'],'originalJournalId':row['original_id'],
            'reversalOf':row['reversal_of'],'correctionId':row['correction_id'],
            'currencyDimensionId':row['currency_dimension_id'],'currencyMemberId':row['currency_member_id'],
            'activationId':row['activation_id'],'approvalDigest':governed.get('approvalDigest'),
            'policyId':binding.get('policyId'),
            'policyStateToken':binding.get('policyStateToken'),
            'draftDigest':governed.get('draftDigest'),'selectionDigest':governed.get('selectionDigest'),
            'candidateCoreVersion':binding.get('candidateCoreVersion'),
            'policyActivationCurrent':row['current_activation_status']=='Active'
                and row['current_activation_id']==row['activation_id'],
            'sourcePinsCurrent':True if row['correction_id'] is None else None,
            'basis':'CurrentOperationalPins' if row['correction_id'] is None else 'ExactHistoricalCorrection'}
        result.setdefault(row['coordinate_id'],[]).append(entry)
    # Reversed originals must contribute an exact zero per selected coordinate;
    # they never authorize adding an old-currency or stale-source residual.
    with localcontext() as precision:
        precision.prec=80
        for lines in result.values():
            corrected={line['originalJournalId'] for line in lines if line['correctionId'] is not None}
            for original_id in corrected:
                paired=[line for line in lines if line['originalJournalId']==original_id]
                if len(paired)!=2 or sum((Decimal(line['signedAmount']) for line in paired),Decimal(0))!=0:
                    raise ValueError('FULL_AGGREGATE_ACQUISITION_CORRECTION_INVALID')
            NumericCell(True,sum((Decimal(line['signedAmount']) for line in lines),Decimal(0)),'')
    return result
