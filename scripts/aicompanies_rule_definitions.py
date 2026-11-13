"""Prepare source-bound native AIcompanies rules without target operations.

Reads the established hash-pinned migration packet. Every emitted expression
reads matched input cells; source result values are acceptance controls only.
Incomplete, ambiguous, retired and unsupported definitions remain in coverage.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal, localcontext, ROUND_HALF_EVEN
from fractions import Fraction
import gzip
from hashlib import sha256
import json
import os
import pprint
import tempfile
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != 'scripts':
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from openepm.source_validation import MAX_SOURCE_BYTES, validate_python_source
from scripts.aicompanies_mcp_journey import AXES, canonical, contained, load_packet
from scripts.aicompanies_cube_payload import table_rows, VALUE_MEMBER

FORMAT = 'openepm-aicompanies-native-rules-v1'
DERIVED_ORIGIN = 'O_CALC_DERIVED'
STATISTICAL = frozenset((
    'STAT_PERSONNEL_PCT_REVENUE', 'STAT_NON_SBC_PCT_REVENUE',
    'STAT_SBC_SHARE_PERSONNEL_INCREASE_H1', 'STAT_SMP_PCT_REVENUE',
    'STAT_CHANNEL_SHARE_SMP_INCREASE_H1', 'STAT_CSP_MARKETPLACE_REVENUE_ESTIMATE',
    'STAT_INTERNATIONAL_REVENUE_SHARE', 'STAT_BILLING_REVENUE_GROWTH_H1_YOY'))
CASH_FLOW = frozenset(('CF_OPER_BEFORE_WC', 'CF_OPER_WC_CASH_IMPACT'))


class CoverageError(ValueError):
    """A source binding is not established; never synthesize its missing input."""


def reconcile_numeric_kind_requirements(packets, current_members):
    """Reconcile source requirements against authorized current metadata."""
    required = {}
    conflicted_keys = set()
    requirement_conflicts = []
    for packet in packets:
        for item in packet.get('numericKindRequirements', []):
            dimension = item.get('dimensionId')
            member = item.get('memberId')
            kind = item.get('numericValueKind')
            key = (dimension, member)
            if (not isinstance(dimension, str) or not isinstance(member, str)
                    or kind not in ('amount', 'ratio') or item.get('conflict')):
                requirement_conflicts.append({
                    'dimensionId': dimension, 'memberId': member,
                    'numericValueKind': kind,
                    'reason': 'SOURCE_REQUIREMENT_CONFLICT'})
                continue
            if key in conflicted_keys:
                continue
            prior = required.get(key)
            if prior is not None and prior != kind:
                requirement_conflicts.append({
                    'dimensionId': dimension, 'memberId': member,
                    'numericValueKind': None,
                    'reason': 'SOURCE_REQUIREMENT_KIND_CONFLICT'})
                required.pop(key, None)
                conflicted_keys.add(key)
            elif key not in required:
                required[key] = kind
    current = {}
    duplicates = []
    for item in current_members:
        dimension = item.get('dimension_id', item.get('dimensionId'))
        member = item.get('member_id', item.get('memberId'))
        if not isinstance(dimension, str) or not isinstance(member, str):
            continue
        key = (dimension, member)
        if key in current:
            duplicates.append({'dimensionId': dimension, 'memberId': member})
        current[key] = item
    missing, inactive, mismatched, satisfied = [], [], [], []
    for (dimension, member), kind in sorted(required.items()):
        expected = {'dimensionId': dimension, 'memberId': member,
                    'numericValueKind': kind}
        actual = current.get((dimension, member))
        if actual is None:
            missing.append(expected)
            continue
        status = actual.get('status')
        actual_kind = actual.get('numeric_value_kind',
                                 actual.get('numericValueKind'))
        if status != 'Active':
            inactive.append({**expected, 'actualStatus': status,
                             'actualNumericValueKind': actual_kind})
        elif actual_kind != kind:
            mismatched.append({**expected,
                               'actualNumericValueKind': actual_kind})
        else:
            satisfied.append(expected)
    blockers = (requirement_conflicts + duplicates + missing + inactive
                + mismatched)
    return {
        'required': len(required),
        'satisfied': len(satisfied),
        'ready': not blockers,
        'sourceRequirementConflicts': requirement_conflicts,
        'duplicateCurrentMembers': duplicates,
        'missing': missing,
        'inactive': inactive,
        'mismatched': mismatched,
    }


def context(row):
    value = row['fields'].get('CalculationContext')
    if value in (None, ''):
        return {}
    if isinstance(value, str):
        value = json.loads(value, parse_float=Decimal)
    if not isinstance(value, dict):
        raise ValueError('SOURCE_CALCULATION_CONTEXT_INVALID')
    if value.get('simulationSeed') is True and isinstance(value.get('originalCalculationContext'), str):
        nested = json.loads(value['originalCalculationContext'], parse_float=Decimal)
        if not isinstance(nested, dict):
            raise ValueError('SOURCE_CALCULATION_CONTEXT_INVALID')
        return nested
    return value


def coordinate(row):
    result = {target: row['fields'][source] for source, _, target in AXES}
    result['Value'] = VALUE_MEMBER
    return result


def number(row):
    value = row['numericLexicalValue']
    if not isinstance(value, str):
        raise ValueError('SOURCE_EXACT_VALUE_REQUIRED')
    result = Decimal(value)
    if not result.is_finite():
        raise ValueError('SOURCE_NONFINITE_VALUE')
    return Fraction(result)


def rounded(value, scale):
    # Exact rational oracle, with sufficient precision before the sole rounding.
    with localcontext() as ctx:
        ctx.prec = max(80, len(str(abs(value.numerator))) + len(str(value.denominator)) + scale + 10)
        result = (Decimal(value.numerator) / Decimal(value.denominator)).quantize(
            Decimal(1).scaleb(-scale), rounding=ROUND_HALF_EVEN)
    return format(result, f'.{scale}f')


@dataclass(frozen=True)
class Expression:
    op: str
    args: tuple
    kind: str

    @classmethod
    def source(cls, row):
        return cls('source', (row,), 'amount')

    @classmethod
    def ratio(cls, value):
        return cls('ratio', (str(value),), 'ratio')

    @classmethod
    def amount(cls, value):
        return cls('amount', (str(value),), 'amount')

    def binary(self, op, other):
        if op in ('+', '-'):
            if self.kind != other.kind:
                raise CoverageError('EXPRESSION_UNIT_MISMATCH')
            kind = self.kind
        elif op == '*':
            if self.kind == other.kind == 'amount':
                raise CoverageError('EXPRESSION_AMOUNT_PRODUCT_UNSUPPORTED')
            kind = 'amount' if 'amount' in (self.kind, other.kind) else 'ratio'
        else:
            if self.kind == 'ratio' and other.kind == 'amount':
                raise CoverageError('EXPRESSION_UNIT_MISMATCH')
            kind = 'ratio' if self.kind == other.kind else 'amount'
        return Expression(op, (self, other), kind)

    def evaluate(self):
        if self.op == 'source':
            return number(self.args[0])
        if self.op in ('amount', 'ratio'):
            return Fraction(Decimal(self.args[0]))
        left, right = (x.evaluate() for x in self.args)
        if self.op == '/' and not right:
            raise CoverageError('SOURCE_DIVISOR_ZERO')
        return {'+': lambda: left + right, '-': lambda: left - right,
                '*': lambda: left * right, '/': lambda: left / right}[self.op]()

    def inputs(self):
        if self.op == 'source':
            return [self.args[0]]
        if self.op in ('amount', 'ratio'):
            return []
        return [row for child in self.args for row in child.inputs()]

    def code(self, names):
        if self.op == 'source':
            return names[self.args[0]['recordId']]
        if self.op in ('amount', 'ratio'):
            return ('Amount' if self.op == 'amount' else 'Ratio') + '(' + repr(self.args[0]) + ')'
        return '(' + self.args[0].code(names) + ' ' + self.op + ' ' + self.args[1].code(names) + ')'


class SourceIndex:
    def __init__(self, records, tables):
        self.rows = list(records)
        self.ids, self.aliases, self.accounts = {}, defaultdict(list), defaultdict(list)
        self.simulation_copies = defaultdict(list)
        self.active = {target: {r['fields'][key] for r in tables[table]
                      if r['fields'].get('IsActive') == '1'} for key, table, target in AXES}
        self.active['Value'] = {VALUE_MEMBER}
        seen = set()
        for row in self.rows:
            rid, members = row['recordId'], coordinate(row)
            if rid in self.ids or canonical(members) in seen:
                raise ValueError('SOURCE_DUPLICATE_IDENTITY_OR_COORDINATE')
            number(row)
            self.ids[rid] = row
            seen.add(canonical(members))
            self.accounts[members['Account']].append(row)
            raw_context = row['fields'].get('CalculationContext') or '{}'
            raw_context = json.loads(raw_context) if isinstance(raw_context, str) else raw_context
            if raw_context.get('simulationSeed') is True:
                self.simulation_copies[raw_context.get('originalActualRecordId')].append(row)
            for alias in {rid, rid.removeprefix('fact:'), row['fields'].get('ObservationID'),
                          row['fields'].get('SourceObservationID')} - {None, ''}:
                self.aliases[alias].append(row)

    def by_id(self, identifier):
        rows = self.aliases.get(identifier, [])
        if len(rows) != 1:
            raise CoverageError('SOURCE_INPUT_ID_UNAVAILABLE_OR_AMBIGUOUS:' + identifier)
        return rows[0]

    def linked(self, output, identifier):
        row = self.by_id(identifier)
        if coordinate(row)['Scenario'] == coordinate(output)['Scenario']:
            return row
        copies = [r for r in self.simulation_copies.get(row['recordId'], [])
                  if coordinate(r)['Scenario'] == coordinate(output)['Scenario']
                  and all(v == coordinate(r)[k] for k, v in coordinate(row).items() if k != 'Scenario')]
        if len(copies) != 1:
            raise CoverageError('SOURCE_SCENARIO_COPY_MISSING_OR_AMBIGUOUS:' + identifier)
        return copies[0]

    def match(self, output, account, *, overrides=None, statistical=False):
        target = coordinate(output) | {'Account': account} | (overrides or {})
        ignored = {'DataType'} | ({'SourceCurrency'} if statistical else set())
        candidates = [row for row in self.accounts.get(account, []) if all(
            coordinate(row)[key] == value for key, value in target.items() if key not in ignored)]
        if not candidates and statistical and target.get('Geography') == 'GEO_TOTAL':
            # This is a declared company-wide source total, not NONE/TOTAL equivalence.
            group = context(output).get('canonicalReportingGroup')
            candidates = [row for row in self.accounts.get(account, []) if group
                and coordinate(row)['Geography'] == 'GEO_NONE'
                and context(row).get('canonicalReportingGroup') == group
                and 'GeographyKey' in context(row).get('sourceTotalOfDimensions', [])
                and all(coordinate(row)[key] == value for key, value in target.items()
                        if key not in ignored | {'Geography'})]
        # A source origin is a distinction, not an arbitrary priority list.
        # Existing raw/allocated cases only bind inputs at their own origin.
        if target['DataType'] != DERIVED_ORIGIN:
            candidates = [r for r in candidates if coordinate(r)['DataType'] == target['DataType']]
        if len(candidates) != 1:
            raise CoverageError(('SOURCE_INPUT_MISSING:' if not candidates else 'SOURCE_INPUT_AMBIGUOUS:') + account)
        return candidates[0]

    def validate_inputs(self, rows, *, monetary=False):
        scopes, intervals, units = set(), set(), set()
        for row in rows:
            members = coordinate(row)
            if any(member not in self.active.get(axis, ()) for axis, member in members.items()):
                raise CoverageError('SOURCE_INPUT_MEMBER_INACTIVE')
            qualifier = row['fields'].get('ValueQualifier')
            if qualifier not in ('Equal', '~'):
                raise CoverageError('SOURCE_BOUND_OR_UNKNOWN_QUALIFIER')
            ctx = context(row)
            if ctx.get('canonicalReportingGroup'):
                scopes.add(ctx['canonicalReportingGroup'])
            if ctx.get('sourceStart') and ctx.get('sourceEnd'):
                intervals.add((ctx['sourceStart'], ctx['sourceEnd']))
            units.add(row['fields'].get('ValueUnit'))
        if len(scopes) > 1:
            raise CoverageError('SOURCE_REPORTING_SCOPE_MISMATCH')
        currencies = {coordinate(r)['SourceCurrency'] for r in rows} - {'CUR_NONE'}
        if len(currencies) > 1:
            raise CoverageError('SOURCE_CURRENCY_MISMATCH')
        if monetary and len(intervals) > 1:
            raise CoverageError('SOURCE_INTERVAL_MISMATCH')
        if monetary and len(units) > 1:
            raise CoverageError('SOURCE_UNIT_MISMATCH')
        return {'qualifiers': sorted({r['fields'].get('ValueQualifier') for r in rows}),
                'units': sorted(str(x) for x in units), 'sourceIntervals': sorted(intervals)}


def algebraic(formula, output, index):
    """Only declared account names and signed sums; never execute formula text."""
    try:
        tree = ast.parse(formula, mode='eval').body
    except SyntaxError as error:
        raise CoverageError('SOURCE_FORMULA_NOT_ALGEBRAIC') from error
    ids = context(output).get('inputRecordIds')
    linked = [index.linked(output, identity) for identity in ids] if isinstance(ids, list) and ids else []
    def visit(node):
        if isinstance(node, ast.Name):
            if linked:
                candidates = [r for r in linked if coordinate(r)['Account'] == node.id]
                if len(candidates) != 1:
                    raise CoverageError('SOURCE_EXPLICIT_ACCOUNT_BINDING_MISSING_OR_AMBIGUOUS:' + node.id)
                return Expression.source(candidates[0])
            return Expression.source(index.match(output, node.id))
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            return visit(node.left).binary('+' if isinstance(node.op, ast.Add) else '-', visit(node.right))
        raise CoverageError('SOURCE_FORMULA_REQUIRES_EXPLICIT_BINDING')
    result = visit(tree)
    if linked and {r['recordId'] for r in result.inputs()} != {r['recordId'] for r in linked}:
        raise CoverageError('SOURCE_EXPLICIT_INPUTS_NOT_COVERED_BY_FORMULA')
    return result


def statistical(account, output, index):
    fields, ctx = output['fields'], context(output)
    if ctx.get('originalAccountKey', account) != account:
        raise CoverageError('RETIRED_FORMULA_HAS_SEPARATE_VIEW_BINDING')
    if fields['ViewKey'] not in ('V_YTD', 'V_QTD', 'V_HTD', 'V_PER'):
        raise CoverageError('SOURCE_STATISTICAL_VIEW_NOT_BASE_MEASURE')
    def ref(member, **overrides):
        return Expression.source(index.match(output, member, overrides=overrides, statistical=True))
    # Source percent observations store percentage-point quantities, not fractions.
    hundred = Expression.amount('100')
    if account == 'STAT_PERSONNEL_PCT_REVENUE':
        return ref('IS_PERSONNEL_NATURE').binary('*', Expression.ratio('-1')).binary('/', ref('IS_REV')).binary('*', hundred)
    if account == 'STAT_NON_SBC_PCT_REVENUE':
        return ref('STAT_NON_SBC_PERSONNEL_CONTROL').binary('/', ref('IS_REV')).binary('*', hundred)
    if account == 'STAT_SMP_PCT_REVENUE':
        return ref('IS_SMP_NATURE').binary('*', Expression.ratio('-1')).binary('/', ref('IS_REV')).binary('*', hundred)
    if account == 'STAT_CHANNEL_SHARE_SMP_INCREASE_H1':
        return ref('IS_CHANNEL_FEES', Movement='M_INCREASE').binary('/', ref('IS_SMP_NATURE', Movement='M_INCREASE')).binary('*', hundred)
    if account == 'STAT_CSP_MARKETPLACE_REVENUE_ESTIMATE':
        return ref('IS_REV').binary('*', ref('STAT_CSP_MARKETPLACE_REVENUE_SHARE').binary('/', Expression.amount('100')))
    if account == 'STAT_INTERNATIONAL_REVENUE_SHARE':
        return ref('IS_REV', Geography='GEO_INTL').binary('/', ref('IS_REV', Geography='GEO_TOTAL')).binary('*', hundred)
    if account == 'STAT_SBC_SHARE_PERSONNEL_INCREASE_H1':
        return ref('IS_PERSONNEL_SBC', Movement='M_INCREASE').binary('/', ref('IS_PERSONNEL_NATURE', Movement='M_INCREASE')).binary('*', hundred)
    if account == 'STAT_BILLING_REVENUE_GROWTH_H1_YOY':
        year = fields['YearKey']
        if len(year) != 5 or not year[1:].isdigit() or fields['PeriodKey'] != 'P_M06':
            raise CoverageError('SOURCE_REFERENCE_WINDOW_UNESTABLISHED')
        return ref('IS_REV').binary('/', ref('IS_REV', Year='Y' + str(int(year[1:]) - 1))).binary('-', Expression.ratio('1')).binary('*', hundred)
    raise CoverageError('SOURCE_STATISTICAL_FORMULA_UNBOUND')


def linked_cash_flow(output, index):
    ctx = context(output)
    inputs, ids = ctx.get('calculationInputs'), ctx.get('inputRecordIds')
    if not isinstance(inputs, list) or not inputs or not isinstance(ids, list) or len(ids) != len(set(ids)):
        raise CoverageError('SOURCE_LINKED_INPUTS_UNESTABLISHED')
    rows = [index.linked(output, identity) for identity in ids]
    terms = []
    for item in inputs:
        row = index.linked(output, item['sourceObservationId'])
        if row not in rows or number(row) != Fraction(Decimal(str(item['value']))):
            raise CoverageError('SOURCE_LINKED_INPUT_VALUE_MISMATCH')
        weight = str(item['weight'])
        terms.append(Expression.source(row).binary('*', Expression.ratio(weight)))
    if len(terms) != len(rows) or {r['recordId'] for r in rows} != {
            index.linked(output, i['sourceObservationId'])['recordId'] for i in inputs}:
        raise CoverageError('SOURCE_LINKED_INPUT_COVERAGE_MISMATCH')
    result = terms[0]
    for term in terms[1:]:
        result = result.binary('+', term)
    return result


def case_for(account, formula, output, index):
    if account in CASH_FLOW:
        expression = linked_cash_flow(output, index)
    elif account in STATISTICAL:
        expression = statistical(account, output, index)
    else:
        expression = algebraic(formula, output, index)
    return expression_case(formula, output, index, expression, monetary=account not in STATISTICAL)


def expression_case(formula, output, index, expression, *, monetary=True):
    inputs = {r['recordId']: r for r in expression.inputs()}
    if not inputs or output['recordId'] in inputs:
        raise CoverageError('SOURCE_OUTPUT_CANNOT_SUBSTITUTE_FOR_INPUT')
    semantics = index.validate_inputs(list(inputs.values()), monetary=monetary)
    output_group = context(output).get('canonicalReportingGroup')
    if output_group and any(context(row).get('canonicalReportingGroup') not in (None, output_group)
                            for row in inputs.values()):
        raise CoverageError('SOURCE_OUTPUT_REPORTING_SCOPE_MISMATCH')
    if monetary and semantics['units'] != [str(output['fields'].get('ValueUnit'))]:
        raise CoverageError('SOURCE_OUTPUT_UNIT_MISMATCH')
    target = coordinate(output) | {'DataType': DERIVED_ORIGIN}
    if any(member not in index.active.get(axis, ()) for axis, member in target.items()):
        raise CoverageError('SOURCE_TARGET_MEMBER_INACTIVE')
    # Drive from a genuine input, never the existing calculated/output cell.
    anchor = min(inputs.values(), key=lambda r: (sum(coordinate(r)[k] != v for k, v in target.items()), r['recordId']))
    changed = {k: v for k, v in target.items() if coordinate(anchor)[k] != v}
    if len(changed) > 32:
        raise CoverageError('NATIVE_TARGET_REMAP_EXCEEDS_DIMENSION_BOUND')
    names = {rid: 'input_' + str(i + 1) for i, rid in enumerate(sorted(inputs))}
    scale = 12 if expression.kind == 'ratio' else 8
    value = rounded(expression.evaluate(), scale)
    return {'sourceObservationId': output['recordId'], 'sourceRow': output.get('row'),
        'sourceFormula': formula, 'targetMembers': target, 'anchorMembers': coordinate(anchor),
        'targetRemap': changed, 'expressionCode': expression.code(names), 'resultUnit': expression.kind,
        'inputs': [{'name': names[rid], 'recordId': rid, 'members': coordinate(row),
                    'sourceValue': row['numericLexicalValue']} for rid, row in sorted(inputs.items())],
        'sourceValueUnit': output['fields'].get('ValueUnit'),
        'expectedCalculatedValue': value, 'sourceControlValue': output['numericLexicalValue'],
        'matchesSourceControlAtEightDecimals': rounded(expression.evaluate(), 8) == rounded(number(output), 8),
        'semantics': semantics, 'resultKey': 'aic.calc.' + sha256(output['recordId'].encode()).hexdigest()[:24]}


def movement_case(output, index):
    ctx, fields = context(output), output['fields']
    ids = ctx.get('openingSourceIds')
    if ctx.get('operation') != 'Closing minus Opening' or not isinstance(ids, list) or len(set(ids)) != 2:
        raise CoverageError('SOURCE_CHANGE_INPUT_IDS_UNESTABLISHED')
    rows = [index.linked(output, identity) for identity in ids]
    current = (fields['YearKey'], fields['PeriodKey'])
    previous = (fields.get('ReferenceYearKey'), fields.get('ReferencePeriodKey'))
    if None in previous or current == previous:
        raise CoverageError('SOURCE_CHANGE_REFERENCE_WINDOW_UNESTABLISHED')
    closing = [r for r in rows if (r['fields']['YearKey'], r['fields']['PeriodKey']) == current]
    opening = [r for r in rows if (r['fields']['YearKey'], r['fields']['PeriodKey']) == previous]
    if len(closing) != 1 or len(opening) != 1:
        raise CoverageError('SOURCE_CHANGE_WINDOW_BINDING_MISMATCH')
    for row in rows:
        if any(coordinate(row)[k] != v for k, v in coordinate(output).items()
               if k not in ('Year', 'Period', 'View', 'Movement', 'DataType')):
            raise CoverageError('SOURCE_CHANGE_SCOPE_MISMATCH')
    if {r['fields'].get('ValueUnit') for r in rows} != {fields.get('ValueUnit')}:
        raise CoverageError('SOURCE_CHANGE_UNIT_MISMATCH')
    expression = Expression.source(closing[0]).binary('-', Expression.source(opening[0]))
    result = expression_case('Closing minus Opening', output, index, expression, monetary=False)
    result['isCompleteExplainedBridge'] = False
    result['sourceReferenceWindow'] = {'year': previous[0], 'period': previous[1]}
    return result


def _render_rule_expanded(rule_id, name, cases):
    """Retained only as an exact-plan oracle for the compact W11 renderer."""
    lines = ['from openepm import Amount, Ratio, ApplicationRule, CubeExpression, Program', '',
             '# ' + repr(name), 'def build(context, parameters):', '    calculations = []']
    for ordinal, case in enumerate(cases, 1):
        lines.extend(['', f"    # Source: {case['sourceObservationId']!r}",
                      '    # ' + repr(case['sourceFormula'])])
        for item in case['inputs']:
            if item['members'] == case['anchorMembers']:
                lines.append(f"    {item['name']} = CubeExpression.source_amount()")
            else:
                lines.append(f"    {item['name']} = CubeExpression.source_value({item['members']!r}, measure_dimension_id='Account')")
        lines.extend(['    calculations.append(Program.expression_calculation(',
            f"        {case['anchorMembers']!r},", f"        {case['expressionCode']}, {case['resultKey']!r},",
            f"        target_members={case['targetRemap']!r}," if case['targetRemap'] else '',
            "        result_unit='ratio'," if case['resultUnit'] == 'ratio' else '',
            f"        name={'case-' + str(ordinal)!r}))"])
    lines.extend(['', '    program = Program(tuple(unit for calculation in calculations for unit in calculation.units))',
                  f'    return ApplicationRule({rule_id!r}, program)', ''])
    return '\n'.join(lines)


def _expression_arguments(expression_code):
    tree = ast.parse(expression_code, mode='eval')
    names = sorted({node.id for node in ast.walk(tree)
                    if isinstance(node, ast.Name) and node.id.startswith('input_')},
                   key=lambda value: int(value.removeprefix('input_')))
    if names != [f'input_{index}' for index in range(1, len(names) + 1)]:
        raise ValueError('SOURCE_EXPRESSION_INPUT_SEQUENCE_INVALID')
    return names


def render_rule(rule_id, name, cases):
    """Render one set-oriented operation per genuine formula shape."""
    groups = _relation_groups(rule_id, name, cases)
    lines = ['from openepm import (Amount, Ratio, ApplicationRule,',
             '                     CubeExpression, Program, RelationOperand)', '',
             '# Family: ' + repr(name),
             '# Mapping tuples are current application data, not rule batches.', '']
    for ordinal, group in enumerate(groups, 1):
        arguments = _expression_arguments(group['expressionCode'])
        lines.extend([f"def _formula_{ordinal}({', '.join(arguments)}):",
                      f"    return {group['expressionCode']}", ''])
    lines.extend(['def build(context, parameters):', '    del parameters',
                  '    calculations = []'])
    for ordinal, group in enumerate(groups, 1):
        operands = tuple((f'input_{index}', columns)
            for index, columns in enumerate(group['operandColumns'], 1))
        lines.extend([
            f"    relation_{ordinal} = context.app.applicability_relation({group['relationId']!r})",
            f"    domain_{ordinal} = relation_{ordinal}.domain(",
            f"        anchor_columns={group['anchorColumns']!r},",
            f"        target_columns={group['targetColumns']!r},",
            "        operands=(",
            *(f"            RelationOperand({operand!r}, {columns!r}),"
              for operand, columns in operands),
            "        ), max_rows=100_000)",
            f"    expression_{ordinal} = _formula_{ordinal}(",
            *(f"        CubeExpression.relation_operand('input_{index}'),"
              for index in range(1, len(operands) + 1)),
            "    )",
            "    calculations.append(Program.applicability_expression_calculation(",
            f"        domain_{ordinal}, expression_{ordinal}, {group['resultKey']!r},",
            f"        name={'formula-' + str(ordinal)!r}))",
        ])
    lines.extend(['    program = Program(tuple(unit for calculation in calculations for unit in calculation.units))',
                  f'    return ApplicationRule({rule_id!r}, program)', ''])
    source = '\n'.join(lines)
    validate_python_source(source)
    return source


def _relation_groups(rule_id, name, cases):
    """Build stable current business relations, never execution partitions."""
    from epm_core.applicability_relation_contract import (
        canonical_applicability_relation)
    grouped = defaultdict(list)
    for case in cases:
        grouped[(case['expressionCode'],case['resultUnit'])].append(case)
    result=[]
    for ordinal,((expression_code,result_unit),rows) in enumerate(
            sorted(grouped.items()),1):
        input_count=len(_expression_arguments(expression_code))
        if any(len(case['inputs'])!=input_count for case in rows):
            raise ValueError('SOURCE_EXPRESSION_INPUT_SEQUENCE_INVALID')
        axes=tuple(sorted(rows[0]['anchorMembers']))
        if any(tuple(sorted(case['anchorMembers']))!=axes for case in rows):
            raise ValueError('SOURCE_RELATION_GRAIN_MISMATCH')
        anchor_columns={axis:f'Anchor_{axis}' for axis in axes}
        target_axes=tuple(axis for axis in axes if any(
            case['targetMembers'][axis]!=case['anchorMembers'][axis]
            for case in rows))
        target_columns={axis:f'Target_{axis}' for axis in target_axes}
        operand_columns=[]
        for index in range(input_count):
            selected=tuple(axis for axis in axes if any(
                case['inputs'][index]['members'][axis]!=
                    case['anchorMembers'][axis] for case in rows))
            operand_columns.append({axis:f'Input{index+1}_{axis}'
                                    for axis in selected})
        columns=(
            [{'columnId':column,'type':'Member','dimensionId':axis}
             for axis,column in anchor_columns.items()]+
            [{'columnId':column,'type':'Member','dimensionId':axis}
             for axis,column in target_columns.items()]+
            [{'columnId':column,'type':'Member','dimensionId':axis}
             for mapping in operand_columns for axis,column in mapping.items()]+
            [{'columnId':'SourceObservationId','type':'String','dimensionId':None},
             {'columnId':'LegacyResultKey','type':'String','dimensionId':None}])
        if len(columns)>128:
            raise ValueError('SOURCE_RELATION_COLUMN_BUDGET')
        relation_rows=[]
        for case in sorted(rows,key=lambda item:item['sourceObservationId']):
            values={column:case['anchorMembers'][axis]
                    for axis,column in anchor_columns.items()}
            values.update({column:case['targetMembers'][axis]
                           for axis,column in target_columns.items()})
            for index,mapping in enumerate(operand_columns):
                values.update({column:case['inputs'][index]['members'][axis]
                               for axis,column in mapping.items()})
            values.update(SourceObservationId=case['sourceObservationId'],
                          LegacyResultKey=case['resultKey'])
            relation_rows.append({'rowId':'case-'+sha256(
                case['sourceObservationId'].encode()).hexdigest()[:32],
                'values':values})
        suffix=(rule_id.removeprefix('aic.rule.').replace(':','-'))
        relation_id=f'aic.relation.{suffix}.{ordinal}'
        definition=canonical_applicability_relation({
            'format':'openepm-applicability-relation-v1',
            'relationId':relation_id,'name':f'{name} applicability {ordinal}',
            'columns':columns,'rows':relation_rows})
        result.append({'relationId':relation_id,
            'resultKey':f'aic.family.{sha256((rule_id+":"+str(ordinal)).encode()).hexdigest()[:24]}',
            'expressionCode':expression_code,'resultUnit':result_unit,
            'anchorColumns':anchor_columns,'targetColumns':target_columns,
            'operandColumns':operand_columns,'definition':definition})
    return result


def business_rule(rule_id, name, cases):
    """Return one semantic rule or fail; execution budgets never create IDs."""
    if not cases:
        return None
    relations=_relation_groups(rule_id,name,cases)
    source = render_rule(rule_id, name, cases)
    if len(source.encode()) > MAX_SOURCE_BYTES:
        raise ValueError('SOURCE_BUSINESS_RULE_REQUIRES_SERVER_WORK_PLAN')
    validate_python_source(source)
    return rule_id, cases, source, relations


def prepare_definitions(tables, records, model):
    index = SourceIndex(records, tables)
    coverage, definitions, blocked_cases = [], [], []
    for row in tables['DimAccount']:
        fields = row['fields']
        formula = fields.get('CalculationRule')
        if not formula:
            continue
        account = fields['AccountKey']
        report = {'sourceId': account, 'sourceName': fields['AccountName'],
                  'sourceFormula': formula, 'sourceStatus': 'Active' if fields.get('IsActive') == '1' else 'Inactive',
                  'sourceLocation': {'table': 'DimAccount', 'row': row.get('row')},
                  'modelDefinition': model.get('calculatedAccounts', {}).get(account),
                  'sourceObservationCount': len(index.accounts.get(account, [])),
                  'definitionIds': [], 'cases': 0, 'uncovered': []}
        if fields.get('IsActive') != '1':
            report.update(status='retained-inactive', reason='SOURCE_ACCOUNT_RETIRED_NO_REACTIVATION')
        elif formula == 'SUM direct children':
            report.update(status='requires-source-coverage', reason='EXCLUSIVE_COMPATIBLE_CHILD_SET_AND_COMPLETE_COVERAGE_REQUIRED')
        elif account == 'STAT_HC_CLOSE':
            report.update(status='requires-source-coverage', reason='COMPLETE_MATCHED_OPENING_AND_ALL_MATERIAL_FLOWS_REQUIRED')
        else:
            cases = []
            for output in sorted(index.accounts.get(account, []), key=lambda r: r['recordId']):
                try:
                    if context(output).get('operation') == 'Closing minus Opening':
                        raise CoverageError('SEPARATE_MATCHED_BALANCE_CHANGE_DEFINITION')
                    candidate = case_for(account, formula, output, index)
                    if not candidate['matchesSourceControlAtEightDecimals']:
                        blocked_cases.append(candidate | {'reason': 'SOURCE_FORMULA_CONTROL_CONFLICT'})
                        raise CoverageError('SOURCE_FORMULA_CONTROL_CONFLICT')
                    cases.append(candidate)
                except CoverageError as error:
                    report['uncovered'].append({'sourceObservationId': output['recordId'], 'reason': str(error)})
            prepared = business_rule('aic.rule.' + account.lower(), fields['AccountName'], cases)
            for rid, batch, source, relations in (() if prepared is None else (prepared,)):
                definitions.append({'definitionId': rid, 'kind': 'ApplicationRule',
                    'name': fields['AccountName'], 'sourceAccountId': account, 'cases': batch,
                    'source': source, 'sourceDigest': sha256(source.encode()).hexdigest(),
                    'requiresCapabilities': ['private-expression-source-value'],
                    'rawFactMutation': False, 'activationEligible': True,
                    'activationPerformed': False,
                    'applicabilityRelations':[item['definition']
                                              for item in relations]})
                report['definitionIds'].append(rid)
            report['cases'] = len(cases)
            report['status'] = 'prepared' if cases and not report['uncovered'] else 'partially-prepared' if cases else 'requires-source-binding'
            if not cases:
                report['reason'] = 'NO_COMPLETE_UNAMBIGUOUS_INPUT_BINDINGS'
        coverage.append(report)
    changes = {'sourceId': 'matched-balance-change', 'sourceFormula': 'Closing minus Opening',
               'sourceObservationCount': 0, 'cases': 0, 'definitionIds': [], 'uncovered': []}
    change_cases = []
    for output in sorted(index.rows, key=lambda r: r['recordId']):
        if context(output).get('operation') != 'Closing minus Opening':
            continue
        changes['sourceObservationCount'] += 1
        try:
            candidate = movement_case(output, index)
            if not candidate['matchesSourceControlAtEightDecimals']:
                blocked_cases.append(candidate | {'reason': 'SOURCE_FORMULA_CONTROL_CONFLICT'})
                raise CoverageError('SOURCE_FORMULA_CONTROL_CONFLICT')
            change_cases.append(candidate)
        except CoverageError as error:
            changes['uncovered'].append({'sourceObservationId': output['recordId'], 'reason': str(error)})
    prepared = business_rule('aic.rule.balance-change',
            'Observed balance change; not an explained bridge', change_cases)
    for rid, batch, source, relations in (() if prepared is None else (prepared,)):
        definitions.append({'definitionId': rid, 'kind': 'ApplicationRule',
            'name': 'Observed balance change', 'cases': batch, 'source': source,
            'sourceDigest': sha256(source.encode()).hexdigest(),
            'requiresCapabilities': ['private-expression-source-value'],
            'rawFactMutation': False, 'activationEligible': True,
            'activationPerformed': False,
            'applicabilityRelations':[item['definition']
                                      for item in relations]})
        changes['definitionIds'].append(rid)
    changes['cases'] = len(change_cases)
    inactive_definitions = []
    conflicts_by_account = defaultdict(list)
    for case in blocked_cases:
        conflicts_by_account[case['targetMembers']['Account']].append(case)
    for account, cases in sorted(conflicts_by_account.items()):
        prepared = business_rule('aic.rule.' + account.lower() + '.conflict',
                account + ' unresolved formula/control conflict', cases)
        for rid, batch, source, relations in (() if prepared is None else (prepared,)):
            inactive_definitions.append({'definitionId': rid, 'kind': 'ApplicationRule',
                'name': account + ' unresolved formula/control conflict', 'sourceAccountId': account,
                'cases': batch, 'source': source, 'sourceDigest': sha256(source.encode()).hexdigest(),
                'requiresCapabilities': ['private-expression-source-value'],
                'activationEligible': False, 'activationPerformed': False, 'rawFactMutation': False,
                'requiredResolution': 'SOURCE_FORMULA_CONTROL_CONFLICT',
                'applicabilityRelations':[item['definition']
                                          for item in relations],
                'authoringDisposition': 'Save readable source and semantic Validation only; remain inactive pending source-policy resolution.'})
    keys = [case['resultKey'] for definition in definitions + inactive_definitions for case in definition['cases']]
    if len(keys) != len(set(keys)):
        raise ValueError('GENERATED_RESULT_IDENTITY_COLLISION')
    kinds = defaultdict(lambda: {'inputKinds': set(), 'outputKinds': set(), 'sourceUnits': set()})
    for definition in definitions + inactive_definitions:
        for case in definition['cases']:
            target = kinds[case['targetMembers']['Account']]
            target['outputKinds'].add(case['resultUnit'])
            target['sourceUnits'].add(str(case['sourceValueUnit']))
            for item in case['inputs']:
                entry = kinds[item['members']['Account']]
                entry['inputKinds'].add('amount')
                entry['sourceUnits'].add(str(index.ids[item['recordId']]['fields'].get('ValueUnit')))
    requirements = []
    for account, entry in sorted(kinds.items()):
        all_kinds = entry['inputKinds'] | entry['outputKinds']
        requirements.append({'dimensionId': 'Account', 'memberId': account,
            'numericValueKind': next(iter(all_kinds)) if len(all_kinds) == 1 else None,
            'conflict': len(all_kinds) != 1,
            **{key: sorted(values) for key, values in entry.items()},
            'function': 'metadata.member.numeric-kind.set'})
    relation_definitions=[relation for definition in
        definitions+inactive_definitions
        for relation in definition.get('applicabilityRelations',[])]
    if len({item['relationId'] for item in relation_definitions})!=len(relation_definitions):
        raise ValueError('GENERATED_RELATION_IDENTITY_COLLISION')
    return {'format': FORMAT, 'targetMutationPerformed': False,
            'definitions': definitions,
            'applicabilityRelations': relation_definitions,
            'numericKindRequirements': requirements, 'blockedCases': blocked_cases,
            'inactiveDefinitions': inactive_definitions,
            'coverage': coverage, 'movementCoverage': changes, 'counts': {'accountRules': len(coverage),
                'activeAccountRules': sum(x['sourceStatus'] == 'Active' for x in coverage),
                'preparedDefinitions': len(definitions), 'inactiveProposalDefinitions': len(inactive_definitions), 'blockedFormulaControlConflicts': len(blocked_cases), 'preparedCases': sum(x['cases'] for x in coverage) + len(change_cases),
                'preparedAccountCases': sum(x['cases'] for x in coverage), 'preparedMovementCases': len(change_cases),
                'statuses': dict(Counter(x['status'] for x in coverage))},
            'remainingModelFamilies': ['other period/view derivations', 'Simulation seed and sparse joint allocation',
                'source-specific statement bridges and policy coverage'],
            'executionBoundary': 'Offline candidates only. Validate/Test exact source and real current inputs before exact activation. Inputs are live cell references; source control values appear only in acceptance metadata. Each case publishes a separate calculated result, preserving raw observations.'}


def generate(manifest_path, pin, output):
    manifest_path, output = Path(manifest_path), Path(output)
    manifest, _, tables = load_packet(manifest_path, pin)
    if output.exists() or output.resolve().is_relative_to(Path(manifest['sourceRoot']).resolve()):
        raise ValueError('OUTPUT_MUST_BE_NEW_AND_OUTSIDE_SOURCE')
    model = json.loads(gzip.decompress(contained(manifest_path.parent, 'source/model.json.gz').read_bytes()))
    records = table_rows(manifest_path.parent, manifest, 'FactFinancial')
    result = prepare_definitions(tables, records, model)
    result.update(sourcePacketManifestSha256=pin, sourceRevision=manifest['sourceRevision'],
                  generatorSourceSha256=sha256(Path(__file__).read_bytes()).hexdigest())
    # Recheck source and packet bytes before writing any deliverable.
    load_packet(manifest_path, pin)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.aicompanies-rules-', dir=output.parent) as scratch:
        staging = Path(scratch) / 'prepared'
        staging.mkdir(mode=0o700)
        for definition in result['definitions'] + result['inactiveDefinitions']:
            name = definition['definitionId'] + '.py'
            source = definition.pop('source')
            path = staging / name
            path.write_text(source, encoding='utf-8'); path.chmod(0o600)
            definition['sourceFile'] = name
        path = staging / 'coverage.json'
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8'); path.chmod(0o600)
        os.rename(staging, output)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    result = generate(args.manifest, args.manifest_sha256, args.output)
    print(canonical(result['counts']))


if __name__ == '__main__':
    main()
