"""Durable W06 business-impact recording and replay reconciliation."""
from __future__ import annotations

from psycopg.types.json import Jsonb

from .calculation_impact_contract import CalculationImpact
from .calculation_impact_contract import compile_calculation_impact, fact_effect


def calculation_publication_impact(*, operation_id: str,
        causal_revision: int, result_key: str, existed: bool,
        withdrawn: bool = False) -> CalculationImpact:
    """Describe one authoritative result-pointer replacement/withdrawal."""
    return compile_calculation_impact({
        'format':'openepm-calculation-impact-v1',
        'sourceKind':'calculation_publication','sourceId':operation_id,
        'causalRevision':causal_revision,'effects':[{
            'domain':'calculation_result',
            'change':('withdraw' if withdrawn else
                      'replace' if existed else 'publish'),
            'objectType':'calculation-result','objectId':result_key,
            'scope':[],'reason':'upstream_changed',
            'oldPresence':'present' if existed else 'absent',
            'newPresence':'absent' if withdrawn else 'present'}]})


def journal_impact(*, operation_id: str, causal_revision: int,
                   member_sets: list[dict[str, str]]) -> CalculationImpact:
    """Describe additive journal lines as exact numeric-layer changes."""
    return coordinate_numeric_impact(source_kind='journal',
        operation_id=operation_id,causal_revision=causal_revision,
        member_sets=member_sets,change='add',old_present=True,
        new_present=True)


def coordinate_numeric_impact(*, source_kind: str, operation_id: str,
        causal_revision: int, member_sets: list[dict[str, str]],
        change: str, old_present: bool, new_present: bool
        ) -> CalculationImpact:
    """Describe exact numeric-layer effects from governed derived writers."""
    return compile_calculation_impact({
        'format':'openepm-calculation-impact-v1','sourceKind':source_kind,
        'sourceId':operation_id,'causalRevision':causal_revision,
        'effects':[fact_effect(domain='numeric_fact',change=change,
            object_id=f'{operation_id}:{ordinal}',members=members,
            old_present=old_present,new_present=new_present)
            for ordinal,members in enumerate(member_sets,1)]})


def object_impact(*, source_kind: str, operation_id: str,
        causal_revision: int, domain: str, object_type: str,
        object_id: str, change: str, reason: str,
        old_presence: str = 'unknown', new_presence: str = 'present',
        scope: list[dict[str, str]] | None = None) -> CalculationImpact:
    """Describe one fixed semantic object/pointer change."""
    return compile_calculation_impact({
        'format':'openepm-calculation-impact-v1','sourceKind':source_kind,
        'sourceId':operation_id,'causalRevision':causal_revision,
        'effects':[{'domain':domain,'change':change,
            'objectType':object_type,'objectId':object_id,
            'scope':scope or [],'reason':reason,
            'oldPresence':old_presence,'newPresence':new_presence}]})


def record_calculation_impact(db, scope, *, operation_id: str,
                              impact: CalculationImpact) -> int:
    """Record one immutable impact event inside the writer transaction.

    The application-state row must already be held by the authoritative
    writer.  Re-entry is accepted only for the exact same operation and
    descriptor; it never allocates a second logical event.
    """
    existing = db.execute('''SELECT impact_epoch,impact_digest,descriptor
        FROM epm.calculation_impact_event WHERE workspace_id=%s
          AND application_id=%s AND operation_id=%s''',
        (scope.workspace_id, scope.application_id, operation_id)).fetchone()
    if existing is not None:
        if (existing['impact_digest'] != impact.digest
                or existing['descriptor'] != impact.normalized):
            raise ValueError('CALCULATION_IMPACT_REPLAY_MISMATCH')
        return existing['impact_epoch']
    receipt = db.execute('''SELECT committed_revision FROM epm.operation_receipt
        WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
        (scope.workspace_id, scope.application_id, operation_id)).fetchone()
    if receipt is None:
        raise ValueError('CALCULATION_IMPACT_RECEIPT_REQUIRED')
    if receipt['committed_revision'] != impact.normalized['causalRevision']:
        raise ValueError('CALCULATION_IMPACT_CAUSAL_REVISION_MISMATCH')
    state = db.execute('''UPDATE epm.application_state
        SET impact_epoch=impact_epoch+1 WHERE workspace_id=%s
          AND application_id=%s RETURNING impact_epoch''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None:
        raise ValueError('APPLICATION_UNAVAILABLE')
    epoch = state['impact_epoch']
    db.execute('''INSERT INTO epm.calculation_impact_event(
        workspace_id,application_id,impact_epoch,operation_id,impact_digest,
        source_kind,source_id,causal_revision,descriptor)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
        (scope.workspace_id, scope.application_id, epoch, operation_id,
         impact.digest, impact.normalized['sourceKind'],
         impact.normalized['sourceId'], impact.normalized['causalRevision'],
         Jsonb(impact.normalized)))
    db.execute('''INSERT INTO epm.calculation_impact_progress(
        workspace_id,application_id,impact_epoch,status)
        VALUES(%s,%s,%s,'pending')''',
        (scope.workspace_id, scope.application_id, epoch))
    return epoch


def require_recorded_impact(db, scope, *, operation_id: str,
                            expected_digest: str) -> int:
    """Prove a post-W06 replay has its one matching durable event."""
    row = db.execute('''SELECT impact_epoch,impact_digest
        FROM epm.calculation_impact_event WHERE workspace_id=%s
          AND application_id=%s AND operation_id=%s''',
        (scope.workspace_id, scope.application_id, operation_id)).fetchone()
    if row is None or row['impact_digest'] != expected_digest:
        raise ValueError('CALCULATION_IMPACT_REPLAY_MISMATCH')
    return row['impact_epoch']


def impact_processing_barrier(db, scope) -> dict[str, object]:
    """Return the application-wide conservative pending-impact barrier."""
    row = db.execute('''SELECT impact_epoch,processed_impact_epoch
        FROM epm.application_state WHERE workspace_id=%s
          AND application_id=%s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if row is None:
        raise ValueError('APPLICATION_UNAVAILABLE')
    return {
        'impactEpoch': row['impact_epoch'],
        'processedImpactEpoch': row['processed_impact_epoch'],
        'pending': row['impact_epoch'] > row['processed_impact_epoch'],
    }


_FACT_OBJECT_TYPES = {
    'numeric_fact': 'numeric-fact',
    'text_fact': 'text-fact',
}


def _observed_producer_matches(effect, dependency):
    """Match immutable observed producer closure, never today's result-key owner."""
    if (effect['domain'] != 'definition' or effect['objectType'] != 'application-rule'
            or dependency['object_type'] != 'calculation-result'
            or dependency['dependency_kind'] != 'upstream'):
        return False
    token = dependency.get('resolved_token')
    if not isinstance(token, dict):
        return False
    from .calculation_dependency_contract import digest
    if digest(token) != dependency.get('token_digest'):
        raise ValueError('CALCULATION_PRODUCER_EVIDENCE_INVALID')
    evidence = token.get('publishedDependencyEvidence')
    if evidence is None:
        # Old unclassified tokens are not producer proof; readers refuse them.
        return False
    from .postgres_job_origin import validate_dependency_evidence
    validate_dependency_evidence(evidence, dependency['object_id'])
    return any(item['originKind'] == 'application_rule'
        and item['producer']['definitionId'] == effect['objectId'] for item in evidence)


def _dependency_matches(effect: dict[str, object], dependency: dict) -> bool:
    """Match one fixed effect to one compiled reverse-index descriptor."""
    if _observed_producer_matches(effect, dependency):
        return True
    domain = effect['domain']
    object_type = dependency['object_type']
    kind = dependency['dependency_kind']
    if domain in _FACT_OBJECT_TYPES:
        if (object_type != _FACT_OBJECT_TYPES[domain]
                or kind not in {'raw', 'absence_range'}):
            return False
    elif domain == 'line_detail':
        if object_type not in {'line-detail', 'numeric-fact'}:
            return False
    elif domain == 'dimension':
        # Axis activation/deactivation changes the valid cube grain and every
        # selector compiled against it.  The fanout is intentionally broad.
        pass
    elif domain == 'member':
        dimensions = {item['dimensionId'] for item in effect['scope']}
        if effect['objectType'] == 'member-name':
            if object_type != 'member-name' or dependency['object_id'] not in dimensions:
                return False
        elif object_type in {'dimension-member', 'dimension-members'}:
            if dependency['object_id'] not in dimensions:
                return False
        elif object_type in {'member-name', 'member-attribute', 'named-hierarchy',
                             'default-hierarchy', 'member-list'}:
            return False
        elif kind not in {'raw','absence_range','selector','hierarchy'}:
            return False
    elif domain in {'definition', 'attribute', 'calendar', 'calculation_result', 'hierarchy'}:
        from .calculation_dependency_contract import semantic_dependency_identity_matches
        if not semantic_dependency_identity_matches(effect, dependency):
            return False
    else:
        normalized = object_type.replace('-', '_')
        if (normalized != domain
                and not normalized.startswith(domain + '_')):
            return False
        object_id = effect['objectId']
        dependency_id = dependency['object_id']
        if (dependency_id != object_id
                and not dependency_id.startswith(object_id + ':')):
            return False
    members = {item['dimensionId']: item['memberId']
               for item in effect['scope']}
    for selector in dependency['scope_matcher'].get('scope', []):
        observed = members.get(selector['dimensionId'])
        if observed is not None and observed not in selector['memberIds']:
            return False
    return True


def _source_reference_matches(db, scope, source_id: str,
                              dependencies: list[dict],
                              domains: set[str]
                              ) -> dict[tuple[str, str, str, str], None]:
    """Resolve a bounded source reference through its exact durable events."""
    tables = {
        'numeric_fact': 'numeric_fact_event',
        'text_fact': 'text_fact_event',
        'line_detail': 'line_detail_event',
    }
    coordinates: dict[str, list[dict[str, str]]] = {}
    for domain, table in tables.items():
        if domain not in domains:
            continue
        rows = db.execute(f'''SELECT DISTINCT c.members
            FROM epm.{table} e JOIN epm.coordinate c
              ON c.workspace_id=e.workspace_id
             AND c.application_id=e.application_id
             AND c.coordinate_id=e.coordinate_id
            WHERE e.workspace_id=%s AND e.application_id=%s
              AND e.operation_id=%s LIMIT 100001''',
            (scope.workspace_id,scope.application_id,source_id)).fetchall()
        if len(rows)>100000:
            raise ValueError('CALCULATION_IMPACT_SOURCE_REFERENCE_LIMIT')
        coordinates[domain]=[row['members'] for row in rows]
    indexes={}
    for domain,rows in coordinates.items():
        index={}
        for ordinal,members in enumerate(rows):
            for axis,member in members.items():
                index.setdefault((axis,member),set()).add(ordinal)
        indexes[domain]=(len(rows),index)
    matches={}
    for dependency in dependencies:
        object_type=dependency['object_type']
        candidate_domains=[]
        if object_type=='numeric-fact':
            candidate_domains=['numeric_fact','line_detail']
        elif object_type=='text-fact':
            candidate_domains=['text_fact']
        elif object_type=='line-detail':
            candidate_domains=['line_detail']
        for domain in candidate_domains:
            total,index=indexes.get(domain,(0,{}))
            if not total:
                continue
            selected=None
            for selector in dependency['scope_matcher'].get('scope',[]):
                axis=selector['dimensionId']
                allowed=set()
                for member in selector['memberIds']:
                    allowed.update(index.get((axis,member),()))
                selected=allowed if selected is None else selected & allowed
                if not selected:
                    break
            if selected is None or selected:
                matches[(dependency['binding_digest'],dependency['stage'],
                    dependency['output_partition'],'data_changed')]=None
                break
    return matches


def process_next_calculation_impact(db, scope, *, claim_id: str,
                                    fanout_limit: int = 10_000
                                    ) -> dict[str, object] | None:
    """Expand and apply the next contiguous event in one crash-safe tx.

    The caller owns the transaction.  A process crash or exception rolls back
    the claim, durable fanout, scope invalidation and watermark together.
    """
    if (not isinstance(claim_id, str) or not 1 <= len(claim_id) <= 200
            or type(fanout_limit) is not int or not 1 <= fanout_limit <= 100_000):
        raise ValueError('CALCULATION_IMPACT_CLAIM_INVALID')
    state = db.execute('''SELECT impact_epoch,processed_impact_epoch
        FROM epm.application_state WHERE workspace_id=%s
          AND application_id=%s FOR UPDATE''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None:
        raise ValueError('APPLICATION_UNAVAILABLE')
    if state['processed_impact_epoch'] == state['impact_epoch']:
        return None
    epoch = state['processed_impact_epoch'] + 1
    event = db.execute('''SELECT e.descriptor,p.status
        FROM epm.calculation_impact_event e
        JOIN epm.calculation_impact_progress p USING(
          workspace_id,application_id,impact_epoch)
        WHERE e.workspace_id=%s AND e.application_id=%s
          AND e.impact_epoch=%s FOR UPDATE OF p''',
        (scope.workspace_id, scope.application_id, epoch)).fetchone()
    if event is None:
        raise ValueError('CALCULATION_IMPACT_EPOCH_GAP')
    if event['status'] == 'applied':
        raise ValueError('CALCULATION_IMPACT_WATERMARK_INCONSISTENT')
    db.execute('''UPDATE epm.calculation_impact_progress SET
        status='processing',attempt_count=attempt_count+1,claim_id=%s,
        claimed_at=clock_timestamp(),applied_at=NULL,failure_code=NULL,
        updated_at=clock_timestamp() WHERE workspace_id=%s
        AND application_id=%s AND impact_epoch=%s''',
        (claim_id, scope.workspace_id, scope.application_id, epoch))
    dependencies = db.execute('''SELECT DISTINCT i.dependency_kind,
        i.object_type,i.object_id,i.scope_matcher,i.output_partition,
        b.binding_digest,b.stage,i.token_digest,
        (SELECT resolved->'token' FROM jsonb_array_elements(m.manifest->'resolvedDependencies') resolved
          WHERE (resolved->>'templateOrdinal')::integer=i.dependency_ordinal) resolved_token
        FROM epm.calculation_dependency_index i
        JOIN epm.calculation_execution_manifest m USING(
          workspace_id,application_id,manifest_digest)
        JOIN epm.calculation_instance_binding b USING(
          workspace_id,application_id,binding_digest)
        JOIN epm.calculation_scope_state s ON
          s.workspace_id=b.workspace_id AND s.application_id=b.application_id
          AND s.binding_digest=b.binding_digest AND s.stage=b.stage
          AND s.partition_key=i.output_partition
        WHERE i.workspace_id=%s AND i.application_id=%s
          AND m.read_commit_revision < %s
        ORDER BY b.binding_digest,b.stage,i.output_partition,
          i.dependency_kind,i.object_type,i.object_id
        LIMIT %s''',
        (scope.workspace_id, scope.application_id,
         event['descriptor']['causalRevision'],fanout_limit + 1)).fetchall()
    if len(dependencies) > fanout_limit:
        raise ValueError('CALCULATION_IMPACT_FANOUT_LIMIT')
    if event['descriptor']['sourceKind']=='source_replace':
        matches=_source_reference_matches(db,scope,
            event['descriptor']['sourceId'],dependencies,
            {effect['domain'] for effect in event['descriptor']['effects']})
    else:
        matches: dict[tuple[str, str, str, str], None] = {}
        for effect in event['descriptor']['effects']:
            for dependency in dependencies:
                if _dependency_matches(effect, dependency):
                    key = (dependency['binding_digest'], dependency['stage'],
                           dependency['output_partition'], effect['reason'])
                    matches[key] = None
    from .postgres_calculation_dependencies import mark_scope_required
    for binding, stage, partition, reason in sorted(matches):
        db.execute('''INSERT INTO epm.calculation_impact_fanout(
            workspace_id,application_id,impact_epoch,binding_digest,stage,
            partition_key,reason) VALUES(%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT DO NOTHING''',
            (scope.workspace_id, scope.application_id, epoch, binding, stage,
             partition, reason))
        mark_scope_required(db, scope, binding_digest=binding, stage=stage,
            partition_key=partition, required_epoch=epoch, reason=reason)
    db.execute('''UPDATE epm.calculation_impact_progress SET
        status='applied',applied_at=clock_timestamp(),updated_at=clock_timestamp()
        WHERE workspace_id=%s AND application_id=%s AND impact_epoch=%s
          AND status='processing' AND claim_id=%s''',
        (scope.workspace_id, scope.application_id, epoch, claim_id))
    advanced = db.execute('''UPDATE epm.application_state
        SET processed_impact_epoch=%s WHERE workspace_id=%s
          AND application_id=%s AND processed_impact_epoch=%s
        RETURNING processed_impact_epoch''',
        (epoch, scope.workspace_id, scope.application_id, epoch - 1)).fetchone()
    if advanced is None:
        raise ValueError('CALCULATION_IMPACT_WATERMARK_RACE')
    return {'impactEpoch': epoch, 'fanoutCount': len(matches),
            'status': 'applied'}


def drain_calculation_impacts(dsn: str, scope, *, claimant: str,
                              limit: int = 1000) -> dict[str, int]:
    """Apply a bounded contiguous prefix for one worker-owned application."""
    if (not isinstance(dsn,str) or not dsn or not isinstance(claimant,str)
            or not claimant or type(limit) is not int or not 1<=limit<=10_000):
        raise ValueError('CALCULATION_IMPACT_DRAIN_INVALID')
    from hashlib import sha256
    from psycopg.rows import dict_row
    from .postgres_connection import connect_postgres
    from .postgres_numeric_store import PostgresNumericFactStore
    claim='impact-'+sha256(claimant.encode('utf-8')).hexdigest()[:32]
    processed=fanout=0
    for _ in range(limit):
        try:
            with connect_postgres(dsn,row_factory=dict_row) as db:
                with db.transaction():
                    # Impact draining is opportunistic around worker claims;
                    # it must never wait behind an application writer long
                    # enough to block unrelated application progress.
                    db.execute("SET LOCAL lock_timeout='100ms'")
                    PostgresNumericFactStore._set_scope(db,scope)
                    result=process_next_calculation_impact(
                        db,scope,claim_id=claim)
        except Exception as error:
            # The drain is opportunistic and application-scoped.  A competing
            # transaction may legitimately hold application_state while this
            # worker is looking for unrelated runnable work.  Preserve the
            # pending event for a later drain; never turn lock contention into
            # a worker-family outage.  All non-lock failures remain fatal.
            from psycopg.errors import LockNotAvailable
            if isinstance(error, LockNotAvailable):
                return {'processedCount':processed,'fanoutCount':fanout}
            raise
        if result is None:
            return {'processedCount':processed,'fanoutCount':fanout}
        processed+=1;fanout+=result['fanoutCount']
    raise ValueError('CALCULATION_IMPACT_DRAIN_LIMIT')

