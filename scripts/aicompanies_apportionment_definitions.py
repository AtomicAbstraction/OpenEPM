"""Translate the pinned AIcompanies joint models to readable generic rules.

Weights and component formulas are source policy; live amounts are referenced
cells. Stored family leaves serve solely as the independent acceptance oracle.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from decimal import Decimal, ROUND_HALF_EVEN, ROUND_FLOOR, localcontext
from fractions import Fraction
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != 'scripts':
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from openepm import (ApportionmentFormula, ApplicationRule, CubeExpression,
    Program, Ratio, RelationOperand)
from epm_core.applicability_relation_contract import canonical_applicability_relation
from openepm.source_validation import MAX_SOURCE_BYTES, validate_python_source
from scripts.aicompanies_mcp_journey import contained, load_packet
from scripts.aicompanies_cube_payload import table_rows
from scripts.aicompanies_rule_definitions import coordinate, context, number, rounded
from scripts.aicompanies_rule_supplement import SupplementSourceIndex

FORMAT = 'openepm-aicompanies-apportionment-v1'
BASE = 'simulation-company-drivers.v1:'
REVIEW = 'openai_anthropic_financial_review_2026_11_01:'
PRODUCERS = ('data/simulation_completion_2026_11_01/build_candidate.py',
             'data/openai_anthropic_financial_review_2026_11_01/prepare_candidate.py')


def exact(value):
    if isinstance(value, float):
        raise ValueError('MODEL_BINARY_FLOAT_NOT_ALLOWED')
    result = Decimal(str(value))
    if not result.is_finite():
        raise ValueError('MODEL_NONFINITE_NUMBER')
    return result


def expression_source(node):
    op = node['op']
    if op == 'SourceAmount': return 'CubeExpression.source_amount()'
    if op == 'SourceValue': return f"CubeExpression.source_value({node['memberOverrides']!r}, measure_dimension_id='Account')"
    if op == 'ComponentAmount': return f"CubeExpression.component_amount({node['componentId']!r})"
    if op == 'RelationOperand': return f"CubeExpression.relation_operand({node['operandId']!r})"
    if op == 'RatioLiteral': return f"Ratio({node['decimal']!r})"
    if op in ('Add', 'Subtract', 'Multiply'):
        symbol = {'Add': '+', 'Subtract': '-', 'Multiply': '*'}[op]
        return f"({expression_source(node['left'])} {symbol} {expression_source(node['right'])})"
    raise ValueError('SOURCE_COMPONENT_NODE_UNSUPPORTED')


def evaluate(node, anchor, rows, components):
    op = node['op']
    if op == 'SourceAmount': return number(anchor)
    if op == 'SourceValue': return number(rows[json.dumps(node['memberOverrides'], sort_keys=True)])
    if op == 'ComponentAmount': return Fraction(components[node['componentId']])
    if op == 'RatioLiteral': return Fraction(exact(node['decimal']))
    left, right = (evaluate(node[k], anchor, rows, components) for k in ('left', 'right'))
    return {'Add': lambda: left + right, 'Subtract': lambda: left - right,
            'Multiply': lambda: left * right}[op]()


def apportion_oracle(amount, targets, quantum, ties):
    """Independent exact rational reproduction of the source largest remainder."""
    q = Fraction(exact(quantum)); units = abs(Fraction(amount)) / q
    if units.denominator != 1:
        raise ValueError('SOURCE_COMPONENT_NOT_QUANTIZED')
    weights = [Fraction(exact(t['weight'])) for t in targets]
    if not weights or any(w <= 0 for w in weights): raise ValueError('SOURCE_WEIGHT_INVALID')
    total = sum(weights); raw = [units * w / total for w in weights]
    floors = [v.numerator // v.denominator for v in raw]
    remaining = int(units) - sum(floors)
    ordering = sorted(range(len(targets)), key=lambda i: (-(raw[i] - floors[i]), tuple(targets[i]['members'][d] for d in ties)))
    for i in ordering[:remaining]: floors[i] += 1
    sign = -1 if amount < 0 else 1
    return [sign * n * q for n in floors]


def source_decimal28_oracle(amount, targets, quantum, ties):
    """Reproduce the historical source producer for comparison, never execution."""
    with localcontext() as ctx:
        ctx.prec = 28
        q = exact(quantum); units = abs(amount) / q
        weights = [exact(t['weight']) for t in targets]; denominator = sum(weights)
        quotas = [units * w / denominator for w in weights]
        base = [int(v.to_integral_value(rounding=ROUND_FLOOR)) for v in quotas]
        order = sorted(range(len(targets)), key=lambda i: (-(quotas[i] - base[i]),
            str(tuple(targets[i]['members'][d] for d in ties))))
        for i in order[:int(units) - sum(base)]: base[i] += 1
        return [Fraction(Decimal(v) * q * (-1 if amount < 0 else 1)) for v in base]


def json_decimal(value):
    """Keep source provenance decimals exact without converting through float."""
    if isinstance(value, Decimal) and value.is_finite():
        return format(value, 'f')
    raise TypeError('SOURCE_PROVENANCE_JSON_TYPE_UNSUPPORTED')


def precision_evidence(amount, targets, quantum, ties):
    exact_values = apportion_oracle(amount, targets, quantum, ties)
    old_values = source_decimal28_oracle(amount, targets, quantum, ties)
    if exact_values == old_values:
        return []
    units = abs(Fraction(amount)) / Fraction(exact(quantum))
    weights = [Fraction(exact(t['weight'])) for t in targets]
    quotas = [units * w / sum(weights) for w in weights]
    floors = [v.numerator // v.denominator for v in quotas]
    order = sorted(range(len(targets)), key=lambda i: (-(quotas[i] - floors[i]),
        tuple(targets[i]['members'][d] for d in ties)))
    with localcontext() as ctx:
        ctx.prec = 28
        old_weights = [exact(t['weight']) for t in targets]
        old_units = abs(amount) / exact(quantum)
        old_quotas = [old_units * w / sum(old_weights) for w in old_weights]
        old_floors = [int(v.to_integral_value(rounding=ROUND_FLOOR)) for v in old_quotas]
        old_remainders = [v - n for v, n in zip(old_quotas, old_floors)]
        old_order = sorted(range(len(targets)), key=lambda i: (-old_remainders[i],
            str(tuple(targets[i]['members'][d] for d in ties))))
    rows = []
    for i, (new, old) in enumerate(zip(exact_values, old_values)):
        if new != old:
            rows.append({'members': targets[i]['members'], 'weight': targets[i]['weight'],
                'exactQuota': str(quotas[i]), 'exactRemainder': str(quotas[i] - floors[i]),
                'sourceDecimal28Quota': str(old_quotas[i]),
                'sourceDecimal28Remainder': str(old_remainders[i]),
                'exactRemainderRank': order.index(i) + 1,
                'sourceDecimal28RemainderRank': old_order.index(i) + 1,
                'sourceDecimal28Amount': rounded(old, 8), 'exactAmount': rounded(new, 8)})
    return rows


class SourceModels:
    def __init__(self, tables, records, model):
        self.index = SupplementSourceIndex(records, tables)
        self.policy = model['simulationPolicy']
        self.families = self.policy['families']
        self.by_scope = {}
        for f in self.families:
            key = tuple(f['scope'][k] for k in ('CompanyKey', 'YearKey', 'PeriodKey', 'AccountKey'))
            if key in self.by_scope: raise ValueError('SOURCE_DUPLICATE_FAMILY_SCOPE')
            self.by_scope[key] = f
        self.masters = {axis: {r['fields'][key]: r['fields'] for r in tables[table]}
                        for axis, key, table in (('Segment', 'SegmentKey', 'DimSegment'),
                            ('Counterparty', 'CounterpartyKey', 'DimCounterparty'))}

    def member(self, dimension, name):
        rows = self.masters[dimension]
        if name in rows: return name
        matches = [key for key, row in rows.items() if str(row[dimension + 'Name']).casefold() == name.casefold()]
        if len(matches) != 1: raise ValueError('SOURCE_WEIGHT_MEMBER_AMBIGUOUS:' + name)
        return matches[0]

    def weights(self, dimension, values):
        result = {}
        for name, value in values.items():
            member = self.member(dimension, name)
            if member in result: raise ValueError('SOURCE_WEIGHT_MEMBER_DUPLICATE')
            result[member] = exact(value)
        return result

    def bind(self, family):
        scope = family['scope']; co, year, period, account = (scope[k] for k in ('CompanyKey', 'YearKey', 'PeriodKey', 'AccountKey'))
        if family['status'] != 'active' or not family['coverageComplete'] or family['axes'] != ['CounterpartyKey', 'SegmentKey']:
            raise ValueError('SOURCE_FAMILY_CONTRACT_UNSUPPORTED')
        reference = family['modelReference']
        if reference not in (BASE + co, REVIEW + co): raise ValueError('SOURCE_MODEL_REFERENCE_UNKNOWN')
        overlay = reference.startswith(REVIEW)
        anchor = self.index.by_id(family['anchorRecordId']); anchor_members = coordinate(anchor)
        if anchor_members['Scenario'] != 'SC_SIMULATION': raise ValueError('SOURCE_FAMILY_SCENARIO_INVALID')
        inputs = {anchor['recordId']: anchor}
        def ref_row(row):
            members = coordinate(row); inputs[row['recordId']] = row
            if members == anchor_members: return CubeExpression.source_amount()
            return CubeExpression.source_value(members, measure_dimension_id='Account')
        def ref(a):
            other = self.by_scope.get((co, year, period, a))
            if other is None: raise ValueError('SOURCE_COMPONENT_FAMILY_MISSING:' + a)
            return ref_row(self.index.by_id(other['anchorRecordId']))
        def component(name): return CubeExpression.component_amount(name)
        profile = self.policy['profiles'][co]
        segments = self.weights('Segment', profile['segments'])
        customers = self.weights('Counterparty', profile['customerMix'])
        vendors = self.weights('Counterparty', profile['vendorMix'])
        cp = {key: self.member('Counterparty', name) for key, name in {
            'employees': 'Employees and benefit providers', 'tax': 'Tax authorities',
            'equity': 'Equity capital providers', 'banks': 'Banks and debt capital providers',
            'assets': 'Banks and custodians of financial assets', 'other': 'Other infrastructure suppliers',
            'operating': 'Other operating counterparties'}.items()}
        cost_weights = defaultdict(Decimal)
        for k, weight in vendors.items(): cost_weights[k] += weight * Decimal('.7')
        cost_weights[cp['employees']] += Decimal('.3')
        quantum = '1' if family['unit'] == 'People' else '0.000001' if family['unit'] == 'GW' else '0.01'
        recipes = []
        def add(name, expression, weights, sg=None, rounding=None):
            target = anchor_members | {'DataType': 'O_CALC_DERIVED'}
            targets = []
            for partner, weight in sorted(weights.items()):
                for segment, segment_weight in sorted((sg or segments).items()):
                    joint = weight * segment_weight
                    if joint <= 0: raise ValueError('SOURCE_NONPOSITIVE_JOINT_WEIGHT')
                    members = target | {'Counterparty': partner, 'Segment': segment}
                    targets.append({'members': members, 'memberOverrides': {k:v for k,v in members.items() if anchor_members[k] != v},
                                    'weight': format(joint, 'f')})
            recipes.append({'componentId': name, 'expression': expression.to_wire(),
                'sourceRounding': rounding or ('exact' if overlay else 'half_even'), 'targets': targets})
        def revenue(): add('revenue', ref('IS_REV'), customers)
        def cost():
            if overlay and co == 'E_OPENAI' and year == 'Y2025' and period == 'P_M12':
                rows = [self.index.linked(anchor, f'fact:REVIEW-OPENAI-{a}-2025-P_M12-V_YTD-CP-MICROSOFT')
                        for a in ('IS_COGS', 'IS_RD', 'IS_SM', 'IS_GA')]
                ms = ref_row(rows[0])
                for row in rows[1:]: ms = ms + ref_row(row)
                microsoft = self.member('Counterparty', 'Microsoft')
                add('cost_microsoft', ms, {microsoft: Decimal(1)})
                add('cost_employees', ref('IS_COSTS') * Ratio('.30'), {cp['employees']: Decimal(1)}, rounding='half_even')
                other = {k:w for k,w in cost_weights.items() if k not in (microsoft, cp['employees'])}
                add('cost_other', ref('IS_COSTS') - component('cost_microsoft') - component('cost_employees'), other)
            else: add('cost', ref('IS_COSTS'), cost_weights)
        def operating(): revenue(); cost()
        def pretax():
            operating(); add('financing_nonoperating', ref('IS_PRETAX') - ref('IS_OP'), {cp['banks']: Decimal(1)})
        def tax(): add('tax', ref('IS_TAX'), {cp['tax']: Decimal(1)})
        def net():
            pretax(); tax(); add('net_scope', ref('IS_NET') - ref('IS_PRETAX') - ref('IS_TAX'), {cp['equity']: Decimal(1)})
        if account == 'IS_REV': revenue()
        elif account == 'IS_COSTS': cost()
        elif account == 'IS_OP': operating()
        elif account == 'IS_PRETAX': pretax()
        elif account == 'IS_TAX': tax()
        elif account == 'IS_NET': net()
        elif account == 'IS_NET_CONSOLIDATED':
            if co == 'E_OPENAI': pretax(); tax()
            elif co == 'E_ANTHROPIC': net()
            else: raise ValueError('SOURCE_CONSOLIDATED_SCOPE_UNKNOWN')
        elif account == 'BS_ASSETS':
            weights = {cp['assets']: Decimal('.55')}
            for k,w in customers.items(): weights[k] = w * Decimal('.45')
            add('assets', ref(account), weights)
        elif account == 'BS_LIAB': add('liabilities', ref(account), {cp['banks']: Decimal('.65'), cp['other']: Decimal('.25'), cp['employees']: Decimal('.10')})
        elif account == 'BS_EQUITY': add('equity', ref(account), {cp['equity']: Decimal(1)})
        elif account == 'ANT_DISC_6AECF0C391':
            operating(); adjustment = ref(account) - ref('IS_OP') if overlay else ref(account) - ref('IS_REV') - ref('IS_COSTS')
            add('operating_adjustment', adjustment, {cp['operating']: Decimal(1)})
        elif account == 'ANT_DISC_FD6893BBC0': add('investing', ref(account), cost_weights if overlay else vendors)
        elif account == 'CF_FINANCING': add('financing', ref(account), {cp['banks']: Decimal('.65'), cp['equity']: Decimal('.35')})
        elif account == 'STAT_HC_CLOSE': add('headcount', ref(account), {'CP_NA': Decimal(1)})
        elif account in ('STAT_COMPUTE_GW', 'STAT_PLANNED_GW'):
            capacity = {k:w for k,w in segments.items() if any(word in self.masters['Segment'][k]['SegmentName'].lower()
                for word in ('cloud','model','technology','core','anthropic','data-centre'))}
            add('capacity', ref(account), {'CP_NA': Decimal(1)}, sg=capacity or segments)
        else: raise ValueError('SOURCE_FAMILY_ACCOUNT_UNSUPPORTED:' + account)
        if len(recipes) > 8: raise ValueError('SOURCE_COMPONENT_BOUND_EXCEEDED')
        # Reproduce actual source component rounding and exact remainder order.
        values = {json.dumps(coordinate(r), sort_keys=True): r for r in inputs.values()}
        rounded_components, calculated, historical = {}, defaultdict(Fraction), defaultdict(Fraction)
        precision_components = []
        with localcontext() as decimal_context:
            decimal_context.prec = 80
            pending = {r['componentId']:r for r in recipes}
            while pending:
                ready = []
                for name, r in pending.items():
                    try: amount = evaluate(r['expression'], anchor, values, rounded_components)
                    except KeyError: continue
                    value = Decimal(amount.numerator) / Decimal(amount.denominator)
                    rounded_value = value.quantize(exact(quantum), rounding=ROUND_HALF_EVEN)
                    if r['sourceRounding'] == 'exact' and value != rounded_value:
                        raise ValueError('SOURCE_EXACT_COMPONENT_NOT_QUANTIZED:' + family['id'] + ':' + name)
                    rounded_components[name] = rounded_value
                    trace = precision_evidence(rounded_value, r['targets'], quantum, ('Counterparty','Segment'))
                    if trace:
                        precision_components.append({'componentId': name, 'roundedSourceAmount': str(rounded_value),
                            'quantum': quantum, 'targets': trace})
                    for target, amount in zip(r['targets'], apportion_oracle(rounded_value, r['targets'], quantum, ('Counterparty','Segment'))):
                        calculated[json.dumps(target['members'], sort_keys=True)] += amount
                    for target, amount in zip(r['targets'], source_decimal28_oracle(rounded_value, r['targets'], quantum, ('Counterparty','Segment'))):
                        historical[json.dumps(target['members'], sort_keys=True)] += amount
                    ready.append(name)
                if not ready: raise ValueError('SOURCE_COMPONENT_CYCLE_OR_MISSING')
                for name in ready: del pending[name]
        if sum(calculated.values()) != number(anchor): raise ValueError('SOURCE_CONTROL_CONSERVATION_MISMATCH:' + family['id'])
        expected = {}
        for identifier in family['leafRecordIds']:
            row = self.index.by_id(identifier); members = coordinate(row) | {'DataType': 'O_CALC_DERIVED'}
            key = json.dumps(members, sort_keys=True)
            if key in expected: raise ValueError('SOURCE_DUPLICATE_LEAF_COORDINATE')
            expected[key] = number(row)
        if expected != historical: raise ValueError('SOURCE_LEAF_RECONSTRUCTION_MISMATCH:' + family['id'])
        if set(expected) != set(calculated): raise ValueError('SOURCE_TARGET_MEMBERSHIP_MISMATCH')
        if any(not re.fullmatch('[A-Z0-9_]+', members[d]) for key in calculated for members in [json.loads(key)] for d in ('Counterparty','Segment')):
            raise ValueError('SOURCE_TUPLE_SORT_COMPATIBILITY_UNQUALIFIED')
        assumptions = []
        for row in inputs.values():
            members = coordinate(row)
            if any(v not in self.index.active[d] for d,v in members.items()): raise ValueError('SOURCE_INPUT_MEMBER_INACTIVE')
            if members['Scenario'] != 'SC_SIMULATION' or members['Entity'] != co or members['Year'] != year or members['Period'] != period:
                raise ValueError('SOURCE_COMPONENT_SCOPE_MISMATCH')
            if members['SourceCurrency'] != anchor_members['SourceCurrency'] or row['fields'].get('ValueUnit') != family['unit']:
                raise ValueError('SOURCE_COMPONENT_UNIT_MISMATCH')
            qualifier = row['fields'].get('ValueQualifier')
            if qualifier not in ('Equal', '~', 'Approximate'):
                ctx = context(row); method = ctx.get('method', {})
                if (qualifier not in ('>', 'Greater than') or ctx.get('simulationModel') is not True
                        or method.get('method') != 'Primary issuer gross contracted capacity lower-bound point assumption'):
                    raise ValueError('SOURCE_BOUNDED_INPUT_HAS_NO_POINT_ASSUMPTION')
                assumptions.append({'recordId':row['recordId'],'sourceQualifier':qualifier,
                    'pointAssumption':method,'notExactReportedMeasurement':True})
        for key in calculated:
            if any(v not in self.index.active[d] for d,v in json.loads(key).items()): raise ValueError('SOURCE_TARGET_MEMBER_INACTIVE')
        return {'sourceFamilyId': family['id'], 'sourceFamilyVersion': family['version'],
            'modelReference': reference, 'anchorRecordId': anchor['recordId'], 'anchorMembers': anchor_members,
            'control': CubeExpression.source_amount().to_wire(), 'quantum': quantum,
            'tieDimensions': ['Counterparty','Segment'], 'components': recipes,
            'inputs': [{'recordId':k,'members':coordinate(v),'sourceValue':v['numericLexicalValue'],
                        'sourceQualifier':v['fields'].get('ValueQualifier'),'sourceUnit':v['fields'].get('ValueUnit')}
                       for k,v in sorted(inputs.items())],
            'expectedRows': [{'members':json.loads(k),'amount':rounded(v,8)} for k,v in sorted(calculated.items())],
            'sourceControlRows': [{'members':json.loads(k),'amount':rounded(v,8)} for k,v in sorted(expected.items())],
            'sourcePrecisionConflicts': [{'members':json.loads(k),'sourceDecimal28Amount':rounded(expected[k],8),
                'exactAmount':rounded(calculated[k],8),'difference':rounded(calculated[k]-expected[k],8)}
                for k in sorted(expected) if expected[k] != calculated[k]],
            'sourcePrecisionComponents': precision_components,
            'activationEligible': expected == calculated,
            'resultKey': 'aic.apportion.' + sha256(family['id'].encode()).hexdigest()[:24],
            'sourceProvenance': {'method':family['method'],'rounding':family['rounding'],'anchorContext':context(anchor),
                                 'anchorQualifier':anchor['fields'].get('ValueQualifier'),'reportingPerimeter':family['reportingPerimeter']},
            'sourcePointAssumptions':assumptions, 'rawFactMutation':False}


def _relation_expression(node, slots):
    op = node['op']
    if op == 'SourceValue':
        coordinate_key = json.dumps(node['memberOverrides'], sort_keys=True,
                                    separators=(',', ':'))
        if coordinate_key not in slots:
            slots[coordinate_key] = len(slots) + 1
        return {'op': 'RelationOperand',
                'operandId': 'input_' + str(slots[coordinate_key]),
                'valueType': 'amount'}
    if op in ('SourceAmount', 'ComponentAmount', 'RatioLiteral'):
        return dict(node)
    if op in ('Add', 'Subtract', 'Multiply'):
        return {'op': op, 'left': _relation_expression(node['left'], slots),
                'right': _relation_expression(node['right'], slots)}
    raise ValueError('SOURCE_COMPONENT_NODE_UNSUPPORTED')


def _relation_policy(rule_id, cases):
    if any(case['control'] != {'op': 'SourceAmount'} for case in cases):
        raise ValueError('SOURCE_APPORTIONMENT_CONTROL_UNSUPPORTED')
    prepared, formulas, max_operands = [], {}, 0
    for case in cases:
        components = []
        for component in case['components']:
            slots = {}
            expression = _relation_expression(component['expression'], slots)
            formula_id = 'formula-' + sha256(json.dumps(expression,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:20]
            prior = formulas.setdefault(formula_id, expression)
            if prior != expression:
                raise ValueError('SOURCE_APPORTIONMENT_FORMULA_COLLISION')
            operands = {slot: json.loads(coordinate_key)
                        for coordinate_key, slot in slots.items()}
            max_operands = max(max_operands, len(operands))
            components.append({**component, 'formulaId': formula_id,
                               'operands': operands})
        prepared.append((case, components))
    anchor_columns = {axis: 'Anchor_' + axis for axis in sorted(cases[0]['anchorMembers'])}
    target_columns = {axis: 'Target_' + axis for axis in sorted(cases[0]['anchorMembers'])}
    operand_columns = {index: {axis: f'Input_{index}_{axis}'
        for axis in sorted(cases[0]['anchorMembers'])}
        for index in range(1, max_operands + 1)}
    columns = ([{'columnId': column, 'type': 'Member', 'dimensionId': axis}
        for axis, column in anchor_columns.items()] +
        [{'columnId': column, 'type': 'Member', 'dimensionId': axis}
        for axis, column in target_columns.items()] +
        [{'columnId': column, 'type': 'Member', 'dimensionId': axis}
        for index in operand_columns for axis, column in operand_columns[index].items()] +
        [{'columnId': 'Group', 'type': 'String', 'dimensionId': None},
         {'columnId': 'Component', 'type': 'String', 'dimensionId': None},
         {'columnId': 'Formula', 'type': 'String', 'dimensionId': None},
         {'columnId': 'Weight', 'type': 'Ratio', 'dimensionId': None},
         {'columnId': 'Quantum', 'type': 'Amount', 'dimensionId': None},
         {'columnId': 'Rounding', 'type': 'String', 'dimensionId': None}])
    if len(columns) > 128:
        raise ValueError('SOURCE_APPORTIONMENT_RELATION_COLUMN_LIMIT')
    rows = []
    for case, components in prepared:
        for component in components:
            for ordinal, target in enumerate(component['targets'], 1):
                target_members = {**case['anchorMembers'],
                                  **target['memberOverrides']}
                values = {column: case['anchorMembers'][axis]
                          for axis, column in anchor_columns.items()}
                values.update({column: target_members[axis]
                               for axis, column in target_columns.items()})
                for index, bindings in operand_columns.items():
                    members = component['operands'].get(index,
                                                        case['anchorMembers'])
                    values.update({column: members.get(axis,
                        case['anchorMembers'][axis])
                        for axis, column in bindings.items()})
                values.update(Group=case['sourceFamilyId'],
                    Component=component['componentId'],
                    Formula=component['formulaId'], Weight=target['weight'],
                    Quantum=case['quantum'],
                    Rounding=component['sourceRounding'])
                identity = json.dumps([case['sourceFamilyId'],
                    component['componentId'], ordinal, target_members],
                    sort_keys=True, separators=(',', ':'))
                rows.append({'rowId': 'row-' + sha256(
                    identity.encode()).hexdigest()[:24], 'values': values})
    relation_id = rule_id + '.policy'
    definition = canonical_applicability_relation({
        'format': 'openepm-applicability-relation-v1',
        'relationId': relation_id,
        'name': 'AIcompanies grouped apportionment policy',
        'columns': columns, 'rows': rows})
    return {'relationId': relation_id, 'definition': definition,
        'anchorColumns': anchor_columns, 'targetColumns': target_columns,
        'operandColumns': operand_columns, 'formulas': formulas,
        'resultKey': rule_id + '.current', 'groupCount': len(cases)}


def render_rule(rule_id, cases):
    relation = _relation_policy(rule_id, cases)
    lines = ['from openepm import (ApportionmentFormula, ApplicationRule,',
        '    CubeExpression, Program, Ratio, RelationOperand)', '',
        'def build(context, parameters):', '    del parameters',
        f"    relation = context.app.applicability_relation({relation['relationId']!r})",
        '    domain = relation.apportionment_domain(',
        f"        anchor_columns={relation['anchorColumns']!r},",
        f"        target_columns={relation['targetColumns']!r},",
        '        operands=(']
    for index, columns in relation['operandColumns'].items():
        lines.append(f"            RelationOperand({'input_' + str(index)!r}, {columns!r}),")
    lines.extend(["        ), group_column_id='Group',",
        "        component_column_id='Component', formula_column_id='Formula',",
        "        weight_column_id='Weight', quantum_column_id='Quantum',",
        "        rounding_column_id='Rounding',",
        "        tie_dimensions=('Counterparty', 'Segment'),",
        f"        max_rows={len(relation['definition']['rows'])!r}, max_groups={len(cases)!r})",
        '    formulas = ('])
    for formula_id, expression in sorted(relation['formulas'].items()):
        lines.append(f"        ApportionmentFormula({formula_id!r}, {expression_source(expression)}),")
    lines.extend(['    )', '    program = Program.applicability_apportionment(',
        f"        domain, formulas, {relation['resultKey']!r})",
        f"    return ApplicationRule({rule_id!r}, program)", ''])
    return '\n'.join(lines)


def rule_from_source(source, context=None):
    namespace = {}; exec(compile(source, '<source-apportionment>', 'exec'), namespace)
    if context is None:
        match = re.search(r"applicability_relation\((['\"])([^'\"]+)\1\)",
                          source)
        if match is None:
            raise ValueError('SOURCE_APPORTIONMENT_RELATION_UNAVAILABLE')
        from openepm import Application, BuildContext
        descriptor = {'relationId': match.group(2), 'name': match.group(2),
            'stateToken': '1' * 64, 'definitionDigest': '2' * 64,
            'status': 'Active', 'columns': []}
        context = BuildContext(Application('w', 'a'), 0, 0, 357,
            {'metadata': {'workspaceId': 'w', 'applicationId': 'a',
                'metadataRevision': 0, 'dimensions': [],
                'applicabilityRelations': [descriptor]}})
    return namespace['build'](context, {})


def work_bounds(cases):
    return {'units': len(cases),
        'cellsUpperBound': sum(len(c['inputs']) + len(c['expectedRows']) for c in cases),
        'visitsUpperBound': sum(len(c['inputs']) + sum(len(x['targets']) for x in c['components']) for c in cases)}


def business_rule(cases, rule_id, *, max_source_bytes=MAX_SOURCE_BYTES,
                  max_plan_bytes=4 * 1024 * 1024):
    """Return one policy rule; technical limits never create authored IDs."""
    if not cases:
        return None
    source = render_rule(rule_id, cases)
    bounds = work_bounds(cases)
    relation = _relation_policy(rule_id, cases)
    from openepm import Application, BuildContext
    descriptor = {'relationId': relation['relationId'],
        'name': relation['definition']['name'], 'stateToken': '1' * 64,
        'definitionDigest': '2' * 64, 'status': 'Active',
        'columns': relation['definition']['columns']}
    context = BuildContext(Application('w', 'a'), 0, 0, 357,
        {'metadata': {'workspaceId': 'w', 'applicationId': 'a',
            'metadataRevision': 0, 'dimensions': [],
            'applicabilityRelations': [descriptor]}})
    wire = rule_from_source(source, context).to_definition()
    if (len(source.encode()) > max_source_bytes
            or len(json.dumps(wire, separators=(',', ':')).encode()) > max_plan_bytes):
        raise ValueError('SOURCE_BUSINESS_RULE_REQUIRES_SERVER_WORK_PLAN')
    return rule_id, cases, source, relation


def prepare_definitions(tables, records, model):
    bound = SourceModels(tables, records, model)
    cases = [bound.bind(f) for f in sorted(bound.families, key=lambda f:f['id'])]
    if len({case['resultKey'] for case in cases}) != len(cases):
        raise ValueError('SOURCE_FAMILY_RESULT_KEY_COLLISION')
    definitions, inactive, accounts = [], [], set()
    for case in cases:
        accounts.update(r['members']['Account'] for r in case['inputs'])
        accounts.update(r['members']['Account'] for r in case['expectedRows'])
    for active, prefix, destination in ((True, 'aic.apportion.policy', definitions),
                                       (False, 'aic.apportion.source_precision', inactive)):
        selected = [c for c in cases if c['activationEligible'] is active]
        prepared = business_rule(selected, prefix)
        for rid, rows, source, relation in (() if prepared is None else (prepared,)):
            validate_python_source(source)
            descriptor = {'relationId': relation['relationId'],
                'name': relation['definition']['name'], 'stateToken': '1' * 64,
                'definitionDigest': '2' * 64, 'status': 'Active',
                'columns': relation['definition']['columns']}
            from openepm import Application, BuildContext
            context = BuildContext(Application('w', 'a'), 0, 0, 357,
                {'metadata': {'workspaceId': 'w', 'applicationId': 'a',
                    'metadataRevision': 0, 'dimensions': [],
                    'applicabilityRelations': [descriptor]}})
            rule = rule_from_source(source, context)
            # Validate the single grouped relation profile structurally.
            from epm_core.postgres_application_rules import validate_definition
            from epm_core.expression_apportionment import normalize_relation_program
            validate_definition(rule.to_definition())
            for unit in rule.to_plan()['units']:
                for operation in unit['operations']:
                    normalize_relation_program(operation)
            destination.append({'definitionId':rid,'kind':'ApplicationRule',
                'name':'AIcompanies source joint apportionment','source':source,
                'sourceDigest':sha256(source.encode()).hexdigest(),'cases':rows,
                'activationEligible':active,'activationPerformed':False,'rawFactMutation':False,
                'applicabilityRelations':[relation['definition']],
                'bounds':work_bounds(rows) | {'sourceBytes':len(source.encode()),
                    'definitionBytes':len(json.dumps(rule.to_definition(),separators=(',',':')).encode())}})
    relations=[relation for definition in definitions+inactive
        for relation in definition.get('applicabilityRelations',[])]
    return {'format':FORMAT,'targetMutationPerformed':False,'definitions':definitions,'inactiveDefinitions':inactive,
        'applicabilityRelations':relations,
        'numericKindRequirements':[{'dimensionId':'Account','memberId':a,'numericValueKind':'amount'} for a in sorted(accounts)],
        'counts':{'sourceFamilies':len(cases),'activationEligibleFamilies':sum(c['activationEligible'] for c in cases),
            'sourcePrecisionConflictFamilies':sum(not c['activationEligible'] for c in cases),
            'sourceLeaves':sum(len(c['expectedRows']) for c in cases),'preparedDefinitions':len(definitions),
            'inactiveDefinitions':len(inactive),'maxComponents':max(len(c['components']) for c in cases),
            'maxTargets':max(len(c['expectedRows']) for c in cases),
            'mixedSignFamilies':sum(any(exact(r['amount']) < 0 for r in c['expectedRows']) and any(exact(r['amount']) > 0 for r in c['expectedRows']) for c in cases)},
        'sourcePrecisionPolicy':'Historical producer Decimal precision28 reproduced all source leaves; generic execution uses exact rational quota/remainder ordering. Conflicting source formulas remain inactive pending explicit resolution. No weights/order/output constants were altered.',
        'executionBoundary':'Offline native Python definitions only; exact current Validation/Test and activation remain required. Raw source facts and comparison controls are preserved.'}


def generate(manifest_path, pin, output):
    manifest_path, output = Path(manifest_path), Path(output)
    manifest, _, tables = load_packet(manifest_path, pin)
    if output.exists() or output.resolve().is_relative_to(Path(manifest['sourceRoot']).resolve()):
        raise ValueError('OUTPUT_MUST_BE_NEW_AND_OUTSIDE_SOURCE')
    model = json.loads(gzip.decompress(contained(manifest_path.parent, 'source/model.json.gz').read_bytes()), parse_float=Decimal)
    producer_paths = [Path(manifest['sourceRoot']) / name for name in PRODUCERS]
    producer_pins = {name:sha256(p.read_bytes()).hexdigest() for name,p in zip(PRODUCERS,producer_paths)}
    result = prepare_definitions(tables,
        table_rows(manifest_path.parent, manifest, 'FactFinancial'), model)
    result.update(sourcePacketManifestSha256=pin, sourceProducerSha256=producer_pins,
                  generatorSourceSha256=sha256(Path(__file__).read_bytes()).hexdigest())
    load_packet(manifest_path,pin)
    if producer_pins != {name:sha256(p.read_bytes()).hexdigest() for name,p in zip(PRODUCERS,producer_paths)}:
        raise ValueError('SOURCE_PRODUCER_CHANGED')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.aic-apportionment-',dir=output.parent) as scratch:
        staging=Path(scratch)/'prepared';staging.mkdir(mode=0o700)
        for d in result['definitions']+result['inactiveDefinitions']:
            name=d['definitionId']+'.py';p=staging/name;p.write_text(d.pop('source'));p.chmod(0o600);d['sourceFile']=name
        p=staging/'coverage.json';p.write_text(json.dumps(result,indent=2,default=json_decimal)+'\n');p.chmod(0o600)
        os.rename(staging,output)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    print(json.dumps(generate(args.manifest,args.manifest_sha256,args.output)['counts'],sort_keys=True))


if __name__=='__main__':
    main()
