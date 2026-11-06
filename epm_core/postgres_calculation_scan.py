"""Paged, generation-pinned reads of published PostgreSQL calculations."""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
from hashlib import sha256

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_capability_contract import producer_capability_status
from .postgres_access import PostgresAccessChecker
from .postgres_cube_query import PostgresCubeQuery, _filter_members
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_dimensional_security_enforcement import filter_read_rows
from .postgres_calculation_visibility import (
    redact_calculation_lineage, redact_expression_lineage,
    redact_expression_result_metadata)
from .postgres_calculation_status import (
    input_revision_status, published_child_status, published_input_status,
    published_translation_status,
    published_calculation_translation_status,
    typed_expression_raw_driver_status,
    expression_context_dependency_status)


FUNCTION = 'facts.calculation.scan'
_RESULT_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_GENERATION_ID = re.compile(r'[0-9a-f]{32}\Z')
_SERIES_KEY = re.compile(r'[0-9a-f]{64}\Z')


def _decorate_expression_reduction_counts(program: dict,
                                           rows: list[dict]) -> None:
    """Expose CountPresent from the exact ordered lineage for every reduction."""
    if not (program.get('reduceMemberSet') or program.get('reduceMemberSets')):
        return
    for row in rows:
        row['countPresent']=len(row.get('sourceLookupLineage',[]))


class PostgresCalculationScan(PostgresCubeQuery):
    def scan_published(self, scope: ApplicationScope, *,
                       result_key: str | None = None,
                       members: dict[str, str] | None = None,
                       limit: int = 100,
                       cursor: str | None = None) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or type(limit) is not int or not 1 <= limit <= 500):
            raise ValueError('CALCULATION_SCAN_BOUNDS_INVALID')
        if cursor is not None:
            if result_key is not None or members is not None:
                raise ValueError('CALCULATION_CURSOR_IS_COMPLETE_REQUEST')
            payload = self._unpack_calculation(cursor, scope)
            result_key = payload['resultKey']
            members = _filter_members(payload['members'])
            generation_id = payload['generationId']
            metadata_revision = payload['metadataRevision']
            security_revision = payload['securityRevision']
            published_revision = payload['publishedRevision']
            after = payload['after']
            limit = payload['limit']
        else:
            if not isinstance(result_key, str) or not _RESULT_KEY.fullmatch(result_key):
                raise ValueError('RESULT_KEY_INVALID')
            members = _filter_members({} if members is None else members)
            generation_id = None
            metadata_revision = None
            security_revision = None
            published_revision = None
            after = ''
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,
                    security_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if (metadata_revision is not None and
                        metadata_revision != state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                if (security_revision is not None and
                        security_revision != state['security_revision']):
                    raise ValueError('STALE_SECURITY_REVISION')
                metadata_revision = state['metadata_revision']
                security_revision = state['security_revision']
                if generation_id is None:
                    publication = db.execute('''SELECT generation_id,
                        published_revision FROM epm.calculation_publication
                        WHERE workspace_id=%s AND application_id=%s
                        AND result_key=%s''',
                        (scope.workspace_id, scope.application_id,
                         result_key)).fetchone()
                    if publication is None:
                        raise ValueError('PUBLICATION_UNAVAILABLE')
                    generation_id = publication['generation_id']
                    published_revision = publication['published_revision']
                generation = db.execute('''SELECT g.function_name,
                    g.source_commit_revision,g.source_metadata_revision,
                    g.published_revision,j.normalized_program,
                    j.compiler_version,
                    j.result AS job_result,
                    j.expected_metadata_revision,
                    j.expected_data_revision,j.expected_policy_revision,
                    s.metadata_revision AS current_metadata_revision,
                    s.data_revision AS current_data_revision,
                    s.policy_revision AS current_policy_revision,
                    s.commit_revision AS observed_commit_revision,
                    s.enabled_capabilities,s.capability_revision
                    FROM epm.calculation_generation g
                    JOIN epm.job j ON j.workspace_id=g.workspace_id
                    AND j.application_id=g.application_id AND j.job_id=g.job_id
                    JOIN epm.application_state s
                    ON s.workspace_id=g.workspace_id
                    AND s.application_id=g.application_id
                    WHERE g.workspace_id=%s AND g.application_id=%s
                    AND g.generation_id=%s AND g.result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     generation_id, result_key)).fetchone()
                if generation is None or generation['published_revision'] != published_revision:
                    raise ValueError('CALCULATION_GENERATION_UNAVAILABLE')
                normalized=generation['normalized_program']
                typed_unit=(isinstance(normalized,dict) and (
                    (generation['function_name']==
                        'currency.amount.translate.publish'
                     and normalized.get('version')==3)
                    or generation['function_name']==
                        'consolidation.equity.contribution.publish'
                    or generation['function_name']==
                        'consolidation.proportional.contribution.publish'
                    or generation['function_name']==
                        'consolidation.full.typed.contribute'
                    or generation['function_name']==
                        'consolidation.method.total.publish'
                    or generation['function_name']==
                        'consolidation.inventory.unrealized_profit.request'
                    or (generation['function_name']==
                        'consolidation.nci.period.publish' and
                        generation.get('compiler_version') in (
                        'period-nci-attribution-v7-typed-unit',
                        'period-nci-attribution-v8-ic-adjusted-typed-unit'))
                    or (generation['function_name']=='facts.expression.calculate'
                        and ((isinstance(normalized.get('expression'),dict)
                          and normalized['expression'].get('op')=='CurrencyConvert')
                         or generation.get('compiler_version') in (
                            'typed-numeric-expression-v19',
                            'typed-numeric-expression-v22',
                            'typed-numeric-expression-v23',
                            'typed-numeric-expression-v29',
                            'typed-numeric-expression-v32')))))
                typed_ratio=(generation['function_name']==
                    'facts.expression.calculate' and
                    generation.get('compiler_version')==
                        'typed-numeric-expression-v24')
                if typed_unit and after=='':
                    after={'seriesKey':'','dimensionId':'','memberId':''}
                if typed_unit != isinstance(after,dict):
                    raise ValueError('CALCULATION_CURSOR_SHAPE_MISMATCH')
                dependency_status = (published_child_status(
                    db, scope, generation['normalized_program'])
                    if generation['function_name'] ==
                    'consolidation.full.aggregate' else None)
                translation_status = (published_translation_status(
                    db,scope,generation['normalized_program'])
                    if generation['function_name'] ==
                    'consolidation.full.translated.aggregate' else None)
                calculation_translation_status = (
                    published_calculation_translation_status(
                        db,scope,generation['normalized_program'])
                    if generation['function_name'] ==
                    'currency.calculation.translation.publish' else None)
                period_nci_status=None
                if generation['function_name'] in ('consolidation.nci.period.publish','consolidation.nci.period.withdraw'):
                    from .postgres_period_nci_publication import source_status
                    period_nci_status=source_status(db,scope,generation['normalized_program'])
                input_dependency_status = (published_input_status(
                    db, scope, generation['normalized_program'])
                    if generation['function_name'] ==
                    'facts.expression.calculate' else None)
                raw_driver_status = (typed_expression_raw_driver_status(
                    db,scope,generation_id,generation['normalized_program'])
                    if generation['function_name']=='facts.expression.calculate'
                    and generation.get('compiler_version') in (
                        'typed-numeric-expression-v29',
                        'typed-numeric-expression-v32') else None)
                context_dependency_status=(
                    expression_context_dependency_status(
                        db,scope,generation['normalized_program'])
                    if generation['function_name']==
                        'facts.expression.calculate' else None)
                allocation_ratio_status=None
                if (generation['function_name']==
                        'facts.planning.allocate.weighted'):
                    ratio_pin=generation['normalized_program'].get(
                        'publishedRatioBasis')
                    if ratio_pin is not None:
                        allocation_ratio_status=published_input_status(
                            db,scope,{'publishedInputs':[ratio_pin]})
                        if allocation_ratio_status is None:
                            allocation_ratio_status={'matchesAtRead':False,
                                'truncated':True,'dependencies':[]}
                if generation['function_name'] == 'consolidation.equity.contribution.publish':
                    from .postgres_equity_method_publication import context_status,source_status
                    equity_source_status=source_status(db,scope,generation['job_result'])
                    equity_context_status=context_status(db,scope,generation['normalized_program'],generation['job_result'])
                else:
                    equity_source_status=equity_context_status=None
                if generation['function_name'] == 'consolidation.proportional.contribution.publish':
                    from .postgres_proportional_publication import context_status,source_status
                    proportional_source_status=source_status(db,scope,generation['job_result'])
                    proportional_context_status=context_status(db,scope,generation['normalized_program'],generation['job_result'])
                else:
                    proportional_source_status=proportional_context_status=None
                if generation['function_name']=='consolidation.method.total.publish':
                    from .postgres_consolidation_method_total import source_status
                    method_total_source_status=source_status(db,scope,generation['job_result'])
                else:
                    method_total_source_status=None
                if generation['function_name']=='consolidation.inventory.unrealized_profit.request':
                    from .postgres_inventory_unrealized_publication import source_status
                    inventory_unrealized_status=source_status(db,scope,generation['job_result'])
                else:inventory_unrealized_status=None
                if members:
                    found = db.execute('''SELECT input.dimension_id,
                        input.member_id,m.member_id IS NOT NULL AS found
                        FROM jsonb_to_recordset(%s::jsonb)
                        AS input(dimension_id text,member_id text)
                        LEFT JOIN epm.member m ON m.workspace_id=%s
                        AND m.application_id=%s
                        AND m.dimension_id=input.dimension_id
                        AND m.member_id=input.member_id''',
                        (Jsonb([{'dimension_id': axis, 'member_id': member}
                                for axis, member in members.items()]),
                         scope.workspace_id, scope.application_id)).fetchall()
                    if any(not row['found'] for row in found):
                        raise ValueError('CUBE_FILTER_MEMBER_UNAVAILABLE')
                rows = (self._page_ratio_calculation(
                    db,scope,generation_id,members,after,limit+1)
                    if typed_ratio else self._page_typed_unit_calculation(
                    db,scope,generation_id,members,after,limit+1)
                    if typed_unit else self._page_calculation(
                    db,scope,generation_id,members,after,limit+1))
                placement_lineage=[]
                recursive_placement=False
                if (generation['function_name']=='facts.planning.rollup.sum'
                        and isinstance(generation['job_result'],dict)
                        and ('placementContext' in generation['job_result']
                             or 'placementPathContext' in generation['job_result'])):
                    recursive_placement=('placementPathContext' in generation['job_result'])
                    placement_lineage=db.execute('''SELECT
                        l.placement_relationship_id AS relationship_id,
                        l.placement_parent_member_id AS parent_member_id,
                        l.placement_child_member_id AS child_member_id,
                        l.placement_path_id,l.placement_path_ordinal,
                        c.members AS source_members,
                        l.source_amount,l.source_change_id
                        FROM epm.rollup_source_lineage l
                        JOIN epm.coordinate c ON c.workspace_id=l.workspace_id
                         AND c.application_id=l.application_id
                         AND c.coordinate_id=l.source_coordinate_id
                        WHERE l.workspace_id=%s AND l.application_id=%s
                         AND l.generation_id=%s
                         AND l.placement_relationship_id IS NOT NULL
                        ORDER BY l.placement_path_ordinal NULLS FIRST,
                         l.placement_relationship_id,c.series_key
                        LIMIT 501''',(scope.workspace_id,
                        scope.application_id,generation_id)).fetchall()
                    if len(placement_lineage)>500:
                        raise ValueError('ROLLUP_SOURCE_LIMIT')
                raw_page=rows[:limit]
                page=filter_read_rows(
                    db,self.identity,scope,raw_page)
                if generation['function_name']=='facts.expression.calculate':
                    redact_expression_lineage(
                        db,self.identity,scope,generation['normalized_program'],
                        page)
                redact_calculation_lineage(
                    db,self.identity,scope,page)
                after_state = db.execute('''SELECT metadata_revision,
                    security_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (after_state is None or
                        after_state['metadata_revision'] != metadata_revision):
                    raise ValueError('STALE_METADATA_REVISION')
                if after_state['security_revision'] != security_revision:
                    raise ValueError('STALE_SECURITY_REVISION')
        has_more = len(rows) > limit
        next_cursor = (self._pack({
            'function': FUNCTION,
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'resultKey': result_key, 'members': members,
            'generationId': generation_id,
            'publishedRevision': published_revision,
            'metadataRevision': metadata_revision,
            'securityRevision': security_revision,
            'limit': limit,
            'after': ({'seriesKey':raw_page[-1]['seriesKey'],
                       'dimensionId':raw_page[-1]['outputUnit']['dimensionId'],
                       'memberId':raw_page[-1]['outputUnit']['memberId']}
                      if typed_unit else raw_page[-1]['seriesKey']),
            'expiresAt': int(time.time()) + 3600,
        }) if has_more else None)
        result = {'resultKey': result_key, 'generationId': generation_id,
                'publishedRevision': published_revision,
                'sourceCommitRevision': generation['source_commit_revision'],
                'sourceMetadataRevision': generation['source_metadata_revision'],
                'function': generation['function_name'],
                'inputRevisionStatus': input_revision_status(generation),
                'producerCapabilities':producer_capability_status(generation['function_name'],
                    generation['normalized_program'],generation['enabled_capabilities'],generation['capability_revision']),
                'metadataRevision': metadata_revision,
                'securityRevision':security_revision,
                'rows': page, 'hasMore': has_more,
                'nextCursor': next_cursor, 'layer': 'calculated'}
        if period_nci_status is not None:
            result['periodNciSourceStatus']=period_nci_status
            result['periodNciContext']=generation['job_result']
            result['inputRevisionStatus']['matchesAtRead'] &= period_nci_status['matchesAtRead']
        if equity_source_status is not None:
            result['equitySourceStatus'] = equity_source_status
            result['equityContextStatus'] = equity_context_status
            result['inputRevisionStatus']['matchesAtRead'] &= (
                equity_source_status['matchesAtRead'] and
                equity_context_status['matchesAtRead'])
        if proportional_source_status is not None:
            result['proportionalSourceStatus']=proportional_source_status
            result['proportionalContextStatus']=proportional_context_status
            result['inputRevisionStatus']['matchesAtRead'] &= (
                proportional_source_status['matchesAtRead'] and
                proportional_context_status['matchesAtRead'])
        if method_total_source_status is not None:
            result['methodTotalSourceStatus']=method_total_source_status
            result['inputRevisionStatus']['matchesAtRead'] &= method_total_source_status['matchesAtRead']
        if inventory_unrealized_status is not None:
            result['inventoryUnrealizedSourceStatus']=inventory_unrealized_status
            result['inputRevisionStatus']['matchesAtRead'] &= inventory_unrealized_status['matchesAtRead']
        if allocation_ratio_status is not None:
            result['publishedRatioBasisStatus']=allocation_ratio_status
            result['inputRevisionStatus']['matchesAtRead'] &= (
                allocation_ratio_status['matchesAtRead'])
        if generation['function_name'] == 'facts.expression.calculate':
            program = generation['normalized_program']
            result['publishedInputs'] = program.get('publishedInputs', [])
            if isinstance(generation['job_result'],dict) and (
                    'sourceLookups' in generation['job_result']):
                result['sourceLookups'] = generation['job_result'][
                    'sourceLookups']
            if isinstance(generation['job_result'],dict) and (
                    'sourceTextLookups' in generation['job_result']):
                result['sourceTextLookups']=generation['job_result'][
                    'sourceTextLookups']
            if program.get('savedRule'):
                result['savedRule'] = program['savedRule']
            if program.get('driverPolicy'):
                result['driverPolicy'] = program['driverPolicy']
            if program.get('targetMembers'):
                result['outputMapping'] = {
                    'sourceMembers': program['sourceMembers'],
                    'targetMembers': program['targetMembers']}
                if program.get('sourceMemberSets'):
                    result['outputMapping']['sourceMemberSets']=(
                        program['sourceMemberSets'])
                    result['sourceMemberSets']=program['sourceMemberSets']
                for row in result['rows']:
                    if not row.get('sourceLineageRestricted'):
                        row['sourceMembers'] = {
                            **row['members'], **program['sourceMembers']}
            if program.get('targetMemberSet'):
                result['outputMapping'] = {
                    'sourceMembers': program['sourceMembers'],
                    'targetMemberSet': program['targetMemberSet']}
                for row in result['rows']:
                    if not row.get('sourceLineageRestricted'):
                        row['sourceMembers'] = {
                            **row['members'], **program['sourceMembers']}
            if program.get('targetMemberSets'):
                result['outputMapping']={
                    'sourceMembers':program['sourceMembers'],
                    'targetMemberSets':program['targetMemberSets']}
                for row in result['rows']:
                    if not row.get('sourceLineageRestricted'):
                        row['sourceMembers']={
                            **row['members'],**program['sourceMembers']}
            if program.get('reduceMemberSet'):
                result['outputMapping']={
                    'sourceMembers':program['sourceMembers'],
                    'reduceMemberSet':program['reduceMemberSet']}
                if program.get('amountUnit'):
                    result['outputMapping']['amountUnit'] = program['amountUnit']
                if program.get('hierarchyReductionContext'):
                    result['outputMapping']['hierarchySelection'] = (
                        program['hierarchyReductionContext'])
            if program.get('reduceMemberSets'):
                result['outputMapping']={
                    'sourceMembers':program['sourceMembers'],
                    'reduceMemberSets':program['reduceMemberSets']}
            _decorate_expression_reduction_counts(program,result['rows'])
            if program.get('hierarchyTwoAxisReductionContext'):
                result['outputMapping']['hierarchySelections']=(
                    program['hierarchyTwoAxisReductionContext'])
            if program.get('sourceDomain'):
                result['outputMapping']={'sourceDomain':program['sourceDomain'],
                    'missingDefault':program['missingDefault']}
                for row in result['rows']:
                    row.setdefault('sourcePresent',True)
            if input_dependency_status is not None:
                result['publishedInputStatus'] = input_dependency_status
                result['inputRevisionStatus']['matchesAtRead'] &= (
                    input_dependency_status['matchesAtRead'])
            if raw_driver_status is not None:
                result['rawDriverStatus']=raw_driver_status
                result['inputRevisionStatus']['matchesAtRead'] &= (
                    raw_driver_status['matchesAtRead'])
            if context_dependency_status is not None:
                result['contextDependencyStatus']=context_dependency_status
                result['contextAssertions']=program.get(
                    'contextAssertions',[])
                result['inputRevisionStatus']['matchesAtRead'] &= (
                    context_dependency_status['matchesAtRead'])
            redact_expression_result_metadata(result)
        if generation['function_name'] == (
                'facts.planning.spread.calendar.equal'):
            program=generation['normalized_program']
            calendar_selection={
                'yearId':program['yearId'],
                'firstOrdinal':program['firstOrdinal'],
                'lastOrdinal':program['lastOrdinal'],
                'targetMembers':program['targetMembers']}
            if program.get('reusablePolicy'):
                calendar_selection['roundingPolicy']=(
                    'largestRemainderFiscalOrdinal')
                result['reusablePolicy']=program['reusablePolicy']
            result['calendarSelection']=calendar_selection
        if generation['function_name'] == 'facts.planning.rollup.sum':
            receipt=generation['job_result']
            if (isinstance(receipt,dict)
                    and (isinstance(receipt.get('placementContext'),dict)
                         or isinstance(receipt.get('placementPathContext'),dict))):
                if recursive_placement:
                    result['placementPathContext']=receipt['placementPathContext']
                else:result['placementContext']=receipt['placementContext']
                result['placementLineage']=[{
                    'relationshipId':row['relationship_id'],
                    'parentMemberId':row['parent_member_id'],
                    'childMemberId':row['child_member_id'],
                    'sourceMembers':row['source_members'],
                    'sourceAmount':format(row['source_amount'],'.8f'),
                    'sourceChangeId':row['source_change_id'],
                    **({'pathId':row['placement_path_id'],
                        'pathOrdinal':row['placement_path_ordinal']}
                       if row['placement_path_id'] is not None else {})}
                    for row in placement_lineage]
        if generation['function_name'] in (
                'consolidation.full.contribute',
                'consolidation.full.typed.contribute'):
            receipt = generation['job_result']
            if not isinstance(receipt, dict):
                raise ValueError('CONTRIBUTION_RECEIPT_UNAVAILABLE')
            result['contributionContext'] = {key: receipt[key]
                for key in ('relationshipId', 'parentEntityId',
                            'childEntityId', 'sourceMembers',
                            'targetMembers', 'sourceChangeId',
                            'pown', 'effectivePcon', 'pconFallback',
                            'accountingStage', 'accountingPolicyStatus')}
            if 'outputUnit' in receipt:
                result['contributionContext']['outputUnit']=receipt['outputUnit']
            if 'policy' in receipt:
                result['contributionContext']['policy']=receipt['policy']
            if 'ownership' in receipt:
                result['contributionContext']['ownership']=receipt['ownership']
            if generation['function_name']==(
                    'consolidation.full.typed.contribute'):
                from .postgres_consolidation_full import typed_full_context_status
                result['typedFullContextStatus']=typed_full_context_status(
                    db,scope,generation['normalized_program'],receipt)
                result['inputRevisionStatus']['matchesAtRead'] &= (
                    result['typedFullContextStatus']['matchesAtRead'])
        if (generation['function_name']=='consolidation.nci.period.publish'
                and generation.get('compiler_version') in (
                    'period-nci-attribution-v7-typed-unit',
                    'period-nci-attribution-v8-ic-adjusted-typed-unit')):
            from .postgres_period_nci_publication import source_status
            result['periodNciSourceStatus']=source_status(
                db,scope,generation['normalized_program'])
            result['inputRevisionStatus']['matchesAtRead'] &= (
                result['periodNciSourceStatus']['matchesAtRead'])
        if generation['function_name'] == 'currency.translation.publish':
            receipt=generation['job_result']
            if not isinstance(receipt,dict):
                raise ValueError('TRANSLATION_RECEIPT_UNAVAILABLE')
            result['translationContext']={key:receipt[key]
                for key in ('sourceMembers','targetMembers','method',
                            'rateKind','fromCurrencyMemberId',
                            'toCurrencyMemberId','exactAmount',
                            'periods','accountingStage',
                            'accountingPolicyStatus')}
            result['translationContext'].update({key:receipt[key] for key in ('sourceLayer','icParentEntityId','sourceBasis') if key in receipt})
        if (generation['function_name']=='facts.planning.rollup.sum'
                and generation['normalized_program'].get('version')==3):
            result['rollupSliceContext']={key:generation['normalized_program'][key]
                for key in ('dimension','parent','fixedMembers','sliceSelection',
                            'placementIds','reusablePolicy')}
        if generation['function_name'] == (
                'currency.calculation.translation.publish'):
            receipt=generation['job_result']
            if not isinstance(receipt,dict):
                raise ValueError(
                    'CALCULATION_TRANSLATION_RECEIPT_UNAVAILABLE')
            result['publishedCalculationTranslationStatus']=\
                calculation_translation_status
            result['inputRevisionStatus']['matchesAtRead'] &= (
                calculation_translation_status['matchesAtRead'])
            result['calculationTranslationContext']={key:receipt[key]
                for key in ('sourceMembers','targetMembers','method',
                    'rateKind','fromCurrencyMemberId',
                    'toCurrencyMemberId','exactAmount','periodPins',
                    'periods','accountingStage',
                    'accountingPolicyStatus')} | (
                    {'sourceLayer':receipt['sourceLayer']}
                    if 'sourceLayer' in receipt else {}) | (
                    {'sourceBasis':receipt['sourceBasis']}
                    if 'sourceBasis' in receipt else {})
        if generation['function_name'] == 'consolidation.full.aggregate':
            receipt = generation['job_result']
            if not isinstance(receipt, dict):
                raise ValueError('FULL_AGGREGATE_RECEIPT_UNAVAILABLE')
            if dependency_status is not None:
                result['publishedChildStatus'] = dependency_status
                result['inputRevisionStatus']['matchesAtRead'] &= (
                    dependency_status['matchesAtRead'])
            result['aggregateContext'] = {key: receipt[key]
                for key in ('parentMembers', 'parentEntityId',
                            'relationshipIds', 'includeParentSource',
                            'sourceLayer', 'sources', 'sourceChangeId',
                            'accountingStage', 'accountingPolicyStatus')}
        if generation['function_name'] == (
                'consolidation.full.translated.aggregate'):
            receipt=generation['job_result']
            if not isinstance(receipt,dict):
                raise ValueError('TRANSLATED_AGGREGATE_RECEIPT_UNAVAILABLE')
            result['publishedTranslationStatus']=translation_status
            result['inputRevisionStatus']['matchesAtRead'] &= (
                translation_status['matchesAtRead'])
            result['translatedAggregateContext']={key:receipt[key]
                for key in ('parentMembers','parentEntityId',
                            'targetCurrencyMemberId','sources',
                            'sourceChangeId','accountingStage',
                            'accountingPolicyStatus')} | (
                    {'sourceLayer':receipt['sourceLayer']}
                    if 'sourceLayer' in receipt else {})
        return result

    @staticmethod
    def _page_typed_unit_calculation(db,scope,generation_id,members,after,
                                     fetch_limit):
        filters=[];filter_params=[]
        for axis,member in members.items():
            filters.append('''AND EXISTS (SELECT 1 FROM epm.coordinate_member cm
                WHERE cm.workspace_id=c.workspace_id
                AND cm.application_id=c.application_id
                AND cm.coordinate_id=c.coordinate_id
                AND cm.dimension_id=%s AND cm.member_id=%s)''')
            filter_params.extend((axis,member))
        rows=db.execute(f'''SELECT c.series_key,c.members,r.source_amount,
                r.source_change_id,r.source_evidence_digest,r.amount,
                r.output_unit_currency_dimension_id,
                r.output_unit_currency_member_id,r.rate_strategy,
                r.rate_numerator::text AS rate_numerator,
                r.rate_denominator::text AS rate_denominator,r.rate_sources,
                r.source_lookup_lineage
            FROM epm.calculation_unit_result r JOIN epm.coordinate c
            USING(workspace_id,application_id,coordinate_id)
            WHERE r.workspace_id=%s AND r.application_id=%s
              AND r.generation_id=%s
              AND (c.series_key,r.output_unit_currency_dimension_id,
                   r.output_unit_currency_member_id)>(%s,%s,%s)
              {''.join(filters)}
            ORDER BY c.series_key,r.output_unit_currency_dimension_id,
                     r.output_unit_currency_member_id LIMIT %s''',
            (scope.workspace_id,scope.application_id,generation_id,
             after['seriesKey'],after['dimensionId'],after['memberId'],
             *filter_params,fetch_limit)).fetchall()
        return [{'seriesKey':row['series_key'],'members':row['members'],
            'sourceAmount':format(row['source_amount'],'.8f'),
            'amount':format(row['amount'],'.8f'),
            'outputUnit':{'type':'Currency',
                'dimensionId':row['output_unit_currency_dimension_id'],
                'memberId':row['output_unit_currency_member_id']},
            'rateLineage':{'strategy':row['rate_strategy'],
                'exactFactor':{'numerator':row['rate_numerator'],
                    'denominator':row['rate_denominator']},
                'sources':row['rate_sources']},
            **({'sourceChangeId':row['source_change_id']}
               if row['source_change_id'] is not None else {}),
            **({'sourceEvidenceDigest':row['source_evidence_digest']}
               if row['source_evidence_digest'] is not None else {}),
            **({'sourceLookupLineage':row['source_lookup_lineage']}
               if row['source_lookup_lineage'] else {})} for row in rows]

    @staticmethod
    def _page_ratio_calculation(db,scope,generation_id,members,after,
                                fetch_limit):
        filters=[];filter_params=[]
        for axis,member in members.items():
            filters.append('''AND EXISTS (SELECT 1 FROM epm.coordinate_member cm
                WHERE cm.workspace_id=c.workspace_id
                AND cm.application_id=c.application_id
                AND cm.coordinate_id=c.coordinate_id
                AND cm.dimension_id=%s AND cm.member_id=%s)''')
            filter_params.extend((axis,member))
        rows=db.execute(f'''SELECT c.series_key,c.members,r.source_amount,
                r.source_change_id,r.source_present,r.ratio,
                r.source_lookup_lineage
            FROM epm.calculation_ratio_result r JOIN epm.coordinate c
            USING(workspace_id,application_id,coordinate_id)
            WHERE r.workspace_id=%s AND r.application_id=%s
              AND r.generation_id=%s AND c.series_key>%s
              {''.join(filters)} ORDER BY c.series_key LIMIT %s''',(
            scope.workspace_id,scope.application_id,generation_id,after,
            *filter_params,fetch_limit)).fetchall()
        result=[]
        for row in rows:
            item={'seriesKey':row['series_key'],'members':row['members'],
                'sourcePresent':row['source_present'],
                'value':{'type':'Ratio','decimal':format(row['ratio'],'.12f')},
                'resultUnit':{'type':'Ratio','scale':12}}
            if row['source_present']:
                item['sourceAmount']=format(row['source_amount'],'.8f')
                item['sourceChangeId']=row['source_change_id']
            if row['source_lookup_lineage']:
                item['sourceLookupLineage']=row['source_lookup_lineage']
            result.append(item)
        return result

    @staticmethod
    def _page_calculation(db, scope, generation_id, members, after, fetch_limit):
        filters = []
        filter_params = []
        for axis, member in members.items():
            filters.append('''AND EXISTS (SELECT 1 FROM epm.coordinate_member cm
                WHERE cm.workspace_id=c.workspace_id
                AND cm.application_id=c.application_id
                AND cm.coordinate_id=c.coordinate_id
                AND cm.dimension_id=%s AND cm.member_id=%s)''')
            filter_params.extend((axis, member))
        rows = db.execute(f'''SELECT c.series_key,c.members,
                r.source_amount,r.source_change_id,r.source_present,r.amount,
                r.source_lookup_lineage
            FROM epm.calculation_result r JOIN epm.coordinate c
              ON c.workspace_id=r.workspace_id
             AND c.application_id=r.application_id
             AND c.coordinate_id=r.coordinate_id
            WHERE r.workspace_id=%s AND r.application_id=%s
              AND r.generation_id=%s AND c.series_key>%s
              {''.join(filters)}
            ORDER BY c.series_key LIMIT %s''',
            (scope.workspace_id, scope.application_id, generation_id,
             after, *filter_params, fetch_limit)).fetchall()
        return [({'seriesKey': row['series_key'], 'members': row['members'],
                 'amount': format(row['amount'], '.8f')} |
                ({'sourceAmount':format(row['source_amount'],'.8f'),
                  'sourceChangeId':row['source_change_id']}
                 if row['source_present'] else {'sourcePresent':False}) |
                ({'sourceLookupLineage':row['source_lookup_lineage']}
                 if row['source_lookup_lineage'] else {}))
                for row in rows]

    def _unpack_calculation(self, token, scope):
        if not isinstance(token, str) or len(token) > 16384:
            raise ValueError('CALCULATION_CURSOR_INVALID')
        try:
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(
                    hmac.new(self.cursor_secret, raw, sha256).digest(),
                    signature):
                raise ValueError('Invalid signature')
            payload = json.loads(raw)
        except (ValueError, TypeError, binascii.Error) as error:
            raise ValueError('CALCULATION_CURSOR_INVALID') from error
        if (not isinstance(payload, dict)
                or set(payload) != {'function', 'scope', 'identity',
                                    'resultKey', 'members', 'generationId',
                                    'publishedRevision', 'metadataRevision',
                                    'securityRevision','limit', 'after',
                                    'expiresAt'}
                or payload['function'] != FUNCTION
                or payload['scope'] != [scope.workspace_id, scope.application_id]
                or payload['identity'] != [self.identity.issuer,
                                           self.identity.subject_id]
                or not isinstance(payload['resultKey'], str)
                or not _RESULT_KEY.fullmatch(payload['resultKey'])
                or not isinstance(payload['generationId'], str)
                or not _GENERATION_ID.fullmatch(payload['generationId'])
                or not ((isinstance(payload['after'], str)
                         and _SERIES_KEY.fullmatch(payload['after']))
                    or (isinstance(payload['after'],dict)
                        and set(payload['after'])==
                            {'seriesKey','dimensionId','memberId'}
                        and isinstance(payload['after']['seriesKey'],str)
                        and _SERIES_KEY.fullmatch(
                            payload['after']['seriesKey'])
                        and all(isinstance(payload['after'][key],str)
                            and 1<=len(payload['after'][key])<=200
                            for key in ('dimensionId','memberId'))))
                or type(payload['publishedRevision']) is not int
                or payload['publishedRevision'] <= 0
                or type(payload['metadataRevision']) is not int
                or payload['metadataRevision'] < 0
                or type(payload['securityRevision']) is not int
                or payload['securityRevision'] < 0
                or type(payload['limit']) is not int
                or not 1 <= payload['limit'] <= 500
                or type(payload['expiresAt']) is not int
                or payload['expiresAt'] < time.time()):
            raise ValueError('CALCULATION_CURSOR_INVALID')
        _filter_members(payload['members'])
        return payload
