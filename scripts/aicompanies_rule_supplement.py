"""Offline scalar View/seed translations from the pinned AIcompanies source.

The original rule packet is immutable. This supplement uses distinct definition
and result IDs, live source references, and explicit source coverage/typing gates.
"""
from __future__ import annotations
import argparse
from collections import Counter
from decimal import Decimal, InvalidOperation
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != 'scripts':
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from scripts.aicompanies_mcp_journey import AXES, contained, load_packet
from scripts.aicompanies_cube_payload import table_rows
from scripts.aicompanies_rule_definitions import (
    CoverageError, Expression, SourceIndex, context, coordinate, expression_case,
    business_rule)

FORMAT = 'openepm-aicompanies-scalar-supplement-v1'


class SupplementSourceIndex(SourceIndex):
    def validate_inputs(self, rows, *, monetary=False):
        # Source uses both '~' and the explicit word 'Approximate' for point
        # estimates. Normalize validation only; preserve original provenance.
        normalized = [row | {'fields': row['fields'] | {'ValueQualifier': '~'}}
                      if row['fields'].get('ValueQualifier') == 'Approximate' else row
                      for row in rows]
        result = super().validate_inputs(normalized, monetary=monetary)
        result['sourceQualifiers'] = sorted({r['fields'].get('ValueQualifier') for r in rows})
        return result


def _reference(output):
    ctx, fields = context(output), output['fields']
    year, period = ctx.get('referenceYearKey'), ctx.get('referencePeriodKey')
    if year is not None or period is not None:
        if not year or not period:
            raise CoverageError('SOURCE_REFERENCE_WINDOW_INCOMPLETE')
        return year, period
    original = ctx.get('originalAccountKey', '')
    year, period = fields['YearKey'], fields['PeriodKey']
    if len(year) != 5 or not year.startswith('Y') or not year[1:].isdigit():
        raise CoverageError('SOURCE_REFERENCE_YEAR_INVALID')
    if fields['ViewKey'] in ('V_YOY_GROWTH', 'V_YOY_PP_CHANGE') or 'YOY' in original:
        return 'Y' + str(int(year[1:]) - 1), period
    if fields['ViewKey'] in ('V_QOQ_GROWTH', 'V_QOQ_PP_CHANGE') or 'QOQ' in original:
        if ctx.get('baseView') != 'V_QTD' or period not in ('P_M03', 'P_M06', 'P_M09', 'P_M12'):
            raise CoverageError('SOURCE_QUARTER_REFERENCE_UNESTABLISHED')
        month = int(period[3:])
        return ('Y' + str(int(year[1:]) - 1), 'P_M12') if month == 3 else (year, f'P_M{month-3:02}')
    raise CoverageError('SOURCE_REFERENCE_WINDOW_UNESTABLISHED')


def view_case(output, index):
    ctx, members = context(output), coordinate(output)
    original = ctx.get('originalAccountKey')
    if not original or not ctx.get('baseView'):
        raise CoverageError('SOURCE_VIEW_DEFINITION_UNESTABLISHED')
    view = members['View']
    growth = view in ('V_YOY_GROWTH', 'V_QOQ_GROWTH', 'V_GROWTH')
    pp = view in ('V_YOY_PP_CHANGE', 'V_QOQ_PP_CHANGE')
    change = view == 'V_CHANGE' or members['Movement'] == 'M_INCREASE'
    if not (growth or pp or change):
        raise CoverageError('SOURCE_VIEW_OPERATION_UNESTABLISHED')
    year, period = _reference(output)
    movement = 'M_CLOSE' if members['Account'] == 'STAT_HC_CLOSE' else 'M_NA'
    overrides = {'View': ctx['baseView'], 'Movement': movement}
    current = index.match(output, members['Account'], overrides=overrides, statistical=True)
    prior = index.match(output, members['Account'], overrides=overrides | {'Year': year, 'Period': period}, statistical=True)
    if current['recordId'] == prior['recordId']:
        raise CoverageError('SOURCE_REFERENCE_NOT_DISTINCT')
    if current['fields'].get('ValueUnit') != prior['fields'].get('ValueUnit'):
        raise CoverageError('SOURCE_VIEW_INPUT_UNIT_MISMATCH')
    left, right = Expression.source(current), Expression.source(prior)
    if growth:
        if str(output['fields'].get('ValueUnit')).lower() not in ('percent', '%', 'percentage'):
            raise CoverageError('SOURCE_GROWTH_PERCENTAGE_POINT_UNIT_REQUIRED')
        expression = left.binary('/', right).binary('-', Expression.ratio('1')).binary('*', Expression.amount('100'))
        formula = '(current / comparable prior - 1) * 100; source percentage points'
    else:
        if pp and (str(current['fields'].get('ValueUnit')).lower() not in ('percent', '%', 'percentage')
                   or str(output['fields'].get('ValueUnit')).lower() not in ('percentage points', 'percent', '%')):
            raise CoverageError('SOURCE_PERCENTAGE_POINT_UNIT_REQUIRED')
        expression = left.binary('-', right)
        factor = ctx.get('expenseIncreaseSignFactor') if change else None
        if factor not in (None, -1, 1):
            raise CoverageError('SOURCE_CHANGE_SIGN_UNESTABLISHED')
        if factor is not None:
            expression = expression.binary('*', Expression.ratio(str(factor)))
        if not pp and output['fields'].get('ValueUnit') != current['fields'].get('ValueUnit'):
            raise CoverageError('SOURCE_CHANGE_OUTPUT_UNIT_MISMATCH')
        formula = 'current - comparable prior' + (f'; source sign factor {factor}' if factor is not None else '')
    case = expression_case(formula, output, index, expression, monetary=False)
    case.update(sourceOriginalAccountKey=original, sourceReferenceWindow={'year': year, 'period': period},
                sourceBaseView=ctx['baseView'], isCompleteExplainedBridge=False)
    case['resultKey'] = 'aic.supp.view.' + sha256(output['recordId'].encode()).hexdigest()[:24]
    return case


def seed_case(link, index):
    if not isinstance(link, dict) or not all(isinstance(link.get(k), str) for k in ('actualRecordId', 'simulationRecordId')):
        raise CoverageError('SOURCE_SEED_LINK_INVALID')
    source, output = index.by_id(link['actualRecordId']), index.by_id(link['simulationRecordId'])
    a, b = coordinate(source), coordinate(output)
    if a['Scenario'] != 'SC_ACTUALS' or b['Scenario'] != 'SC_SIMULATION':
        raise CoverageError('SOURCE_SEED_SCENARIO_INVALID')
    if any(a[k] != b[k] for k in a if k != 'Scenario'):
        raise CoverageError('SOURCE_SEED_COORDINATE_MISMATCH')
    raw = output['fields'].get('CalculationContext') or '{}'
    raw = json.loads(raw) if isinstance(raw, str) else raw
    if raw.get('simulationSeed') is not True or raw.get('originalActualRecordId') != source['recordId']:
        raise CoverageError('SOURCE_SEED_PROVENANCE_MISMATCH')
    if link.get('actualCanonicalKey') != '|'.join(source['fields'][key] for key, _, _ in AXES):
        raise CoverageError('SOURCE_SEED_CANONICAL_KEY_MISMATCH')
    if output['fields'].get('ValueQualifier') != source['fields'].get('ValueQualifier'):
        raise CoverageError('SOURCE_SEED_QUALIFIER_MISMATCH')
    if output['fields'].get('ValueUnit') != source['fields'].get('ValueUnit'):
        raise CoverageError('SOURCE_SEED_UNIT_MISMATCH')
    if str(link.get('actualValue')) != source['numericLexicalValue']:
        # Lexical formatting may differ; compare exact decimal values, never floats.
        try:
            equal = Decimal(str(link.get('actualValue'))) == Decimal(source['numericLexicalValue'])
        except (InvalidOperation, TypeError, ValueError) as error:
            raise CoverageError('SOURCE_SEED_LINK_VALUE_INVALID') from error
        if not equal:
            raise CoverageError('SOURCE_SEED_LINK_VALUE_MISMATCH')
    case = expression_case('Exact source-declared Actual to Simulation seed', output, index,
                           Expression.source(source), monetary=False)
    case['resultKey'] = 'aic.supp.seed.' + sha256(output['recordId'].encode()).hexdigest()[:24]
    case['sourceSeedLink'] = {'actualRecordId': source['recordId'], 'simulationRecordId': output['recordId']}
    case['sourceQualifier'] = source['fields'].get('ValueQualifier')
    case['numericCopyExact'] = True
    case['reportedMeasurementIsExact'] = case['sourceQualifier'] == 'Equal'
    return case


def prepare_supplement(tables, records, model, baseline):
    index = SupplementSourceIndex(records, tables)
    prior_results = {c['resultKey'] for d in baseline.get('definitions', []) + baseline.get('inactiveDefinitions', []) for c in d['cases']}
    known = {r['memberId'] for r in baseline['numericKindRequirements']
             if r['numericValueKind'] == 'amount' and not r['conflict']}
    cases, coverage = {'view': [], 'seed': []}, []
    outputs = [r for r in index.rows if context(r).get('baseView') and context(r).get('originalAccountKey')]
    links = model.get('simulationPolicy', {}).get('seedLinks', [])
    identities = [l.get('simulationRecordId') for l in links]
    if len(identities) != len(set(identities)):
        raise ValueError('SOURCE_DUPLICATE_SEED_LINK')
    for family, objects in (('view', sorted(outputs, key=lambda r: r['recordId'])),
                            ('seed', sorted(links, key=lambda r: r['simulationRecordId']))):
        for item in objects:
            identity = item['recordId'] if family == 'view' else item['simulationRecordId']
            try:
                candidate = view_case(item, index) if family == 'view' else seed_case(item, index)
                if not candidate['matchesSourceControlAtEightDecimals']:
                    raise CoverageError('SOURCE_FORMULA_CONTROL_CONFLICT')
                cases[family].append(candidate)
                coverage.append({'family': family, 'sourceObservationId': identity, 'status': 'prepared'})
            except CoverageError as error:
                coverage.append({'family': family, 'sourceObservationId': identity,
                                 'status': 'unresolved', 'reason': str(error)})
    definitions, requirements = [], {}
    for family, values in cases.items():
        prepared = business_rule('aic.supp.' + family,
                'AIcompanies source ' + family, values)
        for rid, batch, source, relations in (() if prepared is None else (prepared,)):
            accounts = {m['Account'] for c in batch for m in [c['targetMembers']] + [i['members'] for i in c['inputs']]}
            pending = sorted(accounts - known)
            for account in accounts:
                requirements[account] = {'dimensionId': 'Account', 'memberId': account,
                    'numericValueKind': 'amount', 'inExistingDeclarationPacket': account in known}
            definitions.append({'definitionId': rid, 'kind': 'ApplicationRule',
                'family': family, 'name': 'AIcompanies source ' + family, 'source': source,
                'sourceDigest': sha256(source.encode()).hexdigest(), 'cases': batch,
                'activationEligible': not pending, 'requiresNumericKindDeclaration': pending,
                'activationPerformed': False, 'rawFactMutation': False,
                'applicabilityRelations':[item['definition']
                                          for item in relations]})
    keys = [c['resultKey'] for values in cases.values() for c in values]
    if len(keys) != len(set(keys)) or prior_results.intersection(keys):
        raise ValueError('SUPPLEMENT_RESULT_IDENTITY_COLLISION')
    relation_definitions=[relation for definition in definitions
        for relation in definition.get('applicabilityRelations',[])]
    return {'format': FORMAT, 'targetMutationPerformed': False,
        'definitions': definitions,
        'applicabilityRelations': relation_definitions,
        'coverage': coverage, 'numericKindRequirements': [requirements[k] for k in sorted(requirements)],
        'counts': {'definitions': len(definitions), 'viewCases': len(cases['view']), 'seedCases': len(cases['seed']),
                   'metadataReadyDefinitions': sum(d['activationEligible'] for d in definitions),
                   'additionalNumericKindDeclarations': sum(not r['inExistingDeclarationPacket'] for r in requirements.values()),
                   'unresolved': dict(Counter(r['reason'] for r in coverage if r['status'] == 'unresolved'))},
        'executionBoundary': 'Offline source-bound candidates. Metadata readiness refers only to the pinned declaration packet, not a live authorization check. Current semantic Validation, private Test and exact activation remain required. Preserve raw controls and source qualifiers; no shared writes performed.'}


def audit_direct_child_formulas(tables, records, graphs):
    """Distinguish missing children, incomplete inputs and contradictory controls."""
    from scripts.aicompanies_rule_definitions import number, rounded
    index = SourceIndex(records, tables)
    graph = next(g for g in graphs if g['dimensionId'] == 'Account' and g['isDefault'])
    output = []
    for row in tables['DimAccount']:
        fields = row['fields']
        if fields.get('CalculationRule') != 'SUM direct children' or fields.get('IsActive') != '1':
            continue
        account = fields['AccountKey']
        placements = [e for e in graph['placements'] if e['parentMemberId'] == account and e['status'] == 'Active']
        children = [e['childMemberId'] for e in placements]
        counts, conflicts = Counter(), []
        for control in index.accounts.get(account, []):
            if context(control).get('operation') == 'Closing minus Opening':
                counts['separateMatchedStockChange'] += 1
                continue
            if not children:
                counts['noDeclaredActiveChildren'] += 1
                continue
            if any(e['aggregationOperatorOverride'] != 'Add' for e in placements):
                counts['nonAdditiveOrSignedPlacementRequiresBinding'] += 1
                continue
            try:
                inputs = [index.match(control, child) for child in children]
                index.validate_inputs(inputs, monetary=True)
                amount = rounded(sum((number(item) for item in inputs), start=0), 8)
                equal = amount == rounded(number(control), 8)
                counts['completeMatching' if equal else 'completeConflicting'] += 1
                if not equal:
                    conflicts.append({'sourceObservationId': control['recordId'], 'inputRecordIds': [r['recordId'] for r in inputs],
                                      'childTotal': amount, 'sourceControl': control['numericLexicalValue']})
            except CoverageError as error:
                counts[str(error).split(':')[0]] += 1
        output.append({'sourceAccountId': account, 'hierarchyId': graph['hierarchyId'],
                       'sourceDefinitionSha256': graph['sourceDefinitionSha256'],
                       'activeDirectChildren': children, 'counts': dict(counts), 'conflicts': conflicts})
    headcount = Counter((r['fields']['ScenarioKey'], r['fields']['MovementKey'])
                       for r in index.accounts.get('STAT_HC_CLOSE', []))
    flow_rows = sum(n for (_, movement), n in headcount.items() if movement in ('M_OPEN', 'M_HIRE', 'M_DISMISS', 'M_VOL_RETIRE', 'M_RECLASS', 'M_ACQ', 'M_OTHER'))
    return {'directChildRules': output,
            'headcountMovementCounts': [{'scenario': s, 'movement': m, 'count': n} for (s, m), n in sorted(headcount.items())],
            'headcountOpeningOrFlowRows': flow_rows,
            'headcountBridgeConclusion': ('No opening or signed-flow cells exist under the declared Headcount account. Matched closing-stock differences remain changes, not explained bridges.' if flow_rows == 0 else 'Opening/flow cells require complete scope and material-flow coverage qualification before any explained bridge.'),
            'scope': 'Exact declared active direct children in the source default Account hierarchy. Missing cells are not zero; existing stock-change derivations are counted separately. Matching totals alone would still require source exclusivity review.'}


def generate(manifest_path, pin, baseline_path, baseline_pin, output):
    manifest_path, baseline_path, output = Path(manifest_path), Path(baseline_path), Path(output)
    manifest, _, tables = load_packet(manifest_path, pin)
    raw = baseline_path.read_bytes()
    if sha256(raw).hexdigest() != baseline_pin:
        raise ValueError('BASELINE_COVERAGE_DIGEST_MISMATCH')
    baseline = json.loads(raw)
    if baseline.get('sourcePacketManifestSha256') != pin:
        raise ValueError('BASELINE_SOURCE_PACKET_MISMATCH')
    if output.exists() or output.resolve().is_relative_to(Path(manifest['sourceRoot']).resolve()):
        raise ValueError('OUTPUT_MUST_BE_NEW_AND_OUTSIDE_SOURCE')
    model = json.loads(gzip.decompress(contained(manifest_path.parent, 'source/model.json.gz').read_bytes()))
    records = table_rows(manifest_path.parent, manifest, 'FactFinancial')
    result = prepare_supplement(tables, records, model, baseline)
    from scripts.aicompanies_hierarchy_journey import source_graphs
    graphs, _ = source_graphs(manifest_path, manifest, tables)
    result['applicabilityAudit'] = audit_direct_child_formulas(tables, records, graphs)
    result.update(sourcePacketManifestSha256=pin, baselineCoverageSha256=baseline_pin,
                  generatorSourceSha256=sha256(Path(__file__).read_bytes()).hexdigest())
    load_packet(manifest_path, pin)
    if sha256(baseline_path.read_bytes()).hexdigest() != baseline_pin:
        raise ValueError('BASELINE_COVERAGE_DIGEST_MISMATCH')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.aic-supplement-', dir=output.parent) as scratch:
        staging = Path(scratch) / 'prepared'; staging.mkdir(mode=0o700)
        for definition in result['definitions']:
            name = definition['definitionId'] + '.py'
            path = staging / name; path.write_text(definition.pop('source')); path.chmod(0o600)
            definition['sourceFile'] = name
        path = staging / 'coverage.json'; path.write_text(json.dumps(result, indent=2) + '\n'); path.chmod(0o600)
        os.rename(staging, output)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--baseline-coverage', type=Path, required=True)
    parser.add_argument('--baseline-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = generate(args.manifest, args.manifest_sha256,
        args.baseline_coverage, args.baseline_sha256, args.output)
    print(json.dumps(result['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
