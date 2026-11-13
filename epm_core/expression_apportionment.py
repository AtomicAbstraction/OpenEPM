"""Bounded generic signed apportionment; no planning-policy registry or raw writes.

The request is an explicitly vector-valued profile of facts.expression.calculate.
Only trusted adapters may supply live values to the shared rational/integer kernel.
"""
from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
import json
import re
from typing import Mapping

from .persistence_contract import Coordinate
from .postgres_expression import _decimal, _expression, source_lookups
from .apportionment_domain_contract import normalize_apportionment_domain

FUNCTION = 'facts.expression.calculate'
COMPILER = 'typed-numeric-expression-v36'
RELATION_COMPILER = 'typed-numeric-expression-v40'
MAX_COMPONENTS = 8
MAX_FORMULAS = 64
MAX_INPUTS = 64
MAX_TARGETS = 500
MAX_CONTRIBUTIONS = 2000
MAX_PLAN_BYTES = 8_000_000
MAX_RESULT_BYTES = 32 * 1024 * 1024
QUANTA = ('1',) + tuple('0.' + '0' * (scale - 1) + '1' for scale in range(1, 9))
PLAN_DIGEST = sha256(json.dumps({
    'function': FUNCTION, 'version': 36, 'profile': 'sparse_signed_apportionment_v1',
    'expressionArithmetic': 'shared_ordered_integer_rational_kernel_exact_projection',
    'sourceRounding': ['exact', 'half_even'], 'quantumScale': [0, 8],
    'distribution': 'absolute_integer_largest_remainder_then_sign',
    'ties': 'declared_unique_member_tuple_codepoint_order',
    'components': 'canonical_id_topological_order_quantized_amount_dependencies',
    'control': 'exact_live_quantum_aligned_total', 'presentZeros': True,
    'inputs': 'typed_present_raw_numeric_full_coordinates',
    'bounds': {'components': MAX_COMPONENTS, 'inputs': MAX_INPUTS,
               'targets': MAX_TARGETS, 'contributions': MAX_CONTRIBUTIONS,
               'planBytes': MAX_PLAN_BYTES, 'resultBytes': MAX_RESULT_BYTES,
               'lookupsPerExpression': 8, 'nodesPerExpression': 64, 'depth': 12},
}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
RELATION_PLAN_DIGEST = sha256(json.dumps({
    'function': FUNCTION, 'compiler': RELATION_COMPILER,
    'profile': 'grouped_relation_apportionment_v1',
    'relation': 'current_digest_pinned_business_policy_rows',
    'work': 'server_owned_group_windows_atomic_current_result',
    'arithmetic': 'shared_v36_exact_rational_largest_remainder',
    'bounds': {'rows': 100_000, 'groups': 10_000,
               'formulas': MAX_FORMULAS},
}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
_ID = re.compile(r'[^\x00]{1,200}\Z')
_RESULT = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_SCALAR_NODES = frozenset(('SourceAmount', 'SourceValue', 'AmountLiteral',
    'RatioLiteral', 'Add', 'Subtract', 'Multiply', 'Divide', 'Compare', 'If'))


def _id(value):
    if (type(value) is not str or not _ID.fullmatch(value)
            or value != value.strip()):
        raise ValueError('EXPRESSION_APPORTIONMENT_ID_INVALID')
    return value


def _members(value, *, empty=False):
    if (type(value) is not dict or not (0 if empty else 1) <= len(value) <= 32):
        raise ValueError('EXPRESSION_APPORTIONMENT_COORDINATE_INVALID')
    return dict(sorted((_id(axis), _id(member)) for axis, member in value.items()))


def _nodes(node):
    yield node
    for field in ('left', 'right', 'test', 'then', 'else'):
        if field in node:
            yield from _nodes(node[field])


def _normalize_expression(value, source, *, component=False):
    def leaf(node):
        if node.get('op') == 'ComponentAmount':
            if not component or set(node) != {'op', 'componentId'}:
                raise ValueError('EXPRESSION_APPORTIONMENT_COMPONENT_REFERENCE_INVALID')
            return {'op': 'ComponentAmount', 'componentId': _id(node['componentId'])}, 'amount'
        if node.get('op') not in _SCALAR_NODES:
            raise ValueError('EXPRESSION_APPORTIONMENT_EXPRESSION_UNSUPPORTED')
        return None
    normalized, kind = _expression(value, leaf_parser=leaf)
    if kind != 'amount':
        raise ValueError('EXPRESSION_APPORTIONMENT_AMOUNT_REQUIRED')
    for node in _nodes(normalized):
        if node['op'] == 'SourceValue':
            if 'measureDimensionId' not in node:
                raise ValueError('EXPRESSION_MEASURE_BINDING_REQUIRED')
            if set(node['memberOverrides']) - set(source):
                raise ValueError('EXPRESSION_APPORTIONMENT_SOURCE_AXIS_INVALID')
    source_lookups(normalized)  # The shared eight-lookup bound is unchanged.
    return normalized


def topological_components(request):
    components = {item['componentId']: item
                  for item in request['apportionment']['components']}
    dependencies = {key: {node['componentId'] for node in _nodes(item['expression'])
                         if node['op'] == 'ComponentAmount'}
                    for key, item in components.items()}
    if any(key in refs or refs - components.keys() for key, refs in dependencies.items()):
        raise ValueError('EXPRESSION_APPORTIONMENT_COMPONENT_REFERENCE_INVALID')
    ordered = []
    while len(ordered) != len(components):
        ready = sorted(key for key, refs in dependencies.items()
                       if key not in ordered and refs <= set(ordered))
        if not ready:
            raise ValueError('EXPRESSION_APPORTIONMENT_COMPONENT_CYCLE')
        ordered.append(ready[0])
    return tuple(ordered)


def input_coordinates(request):
    """All input identities, including the anchor, before any database fetch."""
    source = request['sourceMembers']
    coordinates = {Coordinate.from_mapping(source)}
    expressions = [request['apportionment']['control']] + [
        item['expression'] for item in request['apportionment']['components']]
    for expression in expressions:
        for overrides in source_lookups(expression):
            coordinates.add(Coordinate.from_mapping({**source, **dict(overrides)}))
    if len(coordinates) > MAX_INPUTS:
        raise ValueError('EXPRESSION_APPORTIONMENT_INPUT_LIMIT')
    return tuple(sorted(coordinates, key=lambda item: item.series_key))


def target_coordinates(request):
    source = request['sourceMembers']
    return tuple(sorted({Coordinate.from_mapping({**source, **target['memberOverrides']})
        for component in request['apportionment']['components']
        for target in component['targets']}, key=lambda item: item.series_key))


def normalize_request(value):
    if (type(value) is not dict or set(value) != {
            'sourceMembers', 'resultKey', 'apportionment'}):
        raise ValueError('EXPRESSION_APPORTIONMENT_REQUEST_INVALID')
    source = _members(value['sourceMembers'])
    result_key = value['resultKey']
    if type(result_key) is not str or not _RESULT.fullmatch(result_key):
        raise ValueError('EXPRESSION_APPORTIONMENT_RESULT_KEY_INVALID')
    raw = value['apportionment']
    if (type(raw) is not dict or set(raw) != {
            'version', 'quantum', 'tieDimensions', 'control', 'components'}
            or type(raw['version']) is not int or raw['version'] != 1):
        raise ValueError('EXPRESSION_APPORTIONMENT_REQUEST_INVALID')
    quantum_value = Decimal(_decimal(raw['quantum'], amount=True))
    quantum = next((q for q in QUANTA if Decimal(q) == quantum_value), None)
    if quantum is None:
        raise ValueError('EXPRESSION_APPORTIONMENT_QUANTUM_INVALID')
    ties = raw['tieDimensions']
    if (type(ties) is not list or not 1 <= len(ties) <= 32
            or any(type(axis) is not str or axis not in source for axis in ties)
            or len(ties) != len(set(ties))):
        raise ValueError('EXPRESSION_APPORTIONMENT_TIE_DIMENSIONS_INVALID')
    components = raw['components']
    if type(components) is not list or not 1 <= len(components) <= MAX_COMPONENTS:
        raise ValueError('EXPRESSION_APPORTIONMENT_COMPONENT_LIMIT')
    normalized = []
    union = {}
    ids = set()
    count = 0
    for component in components:
        if type(component) is not dict or set(component) != {
                'componentId', 'expression', 'sourceRounding', 'targets'}:
            raise ValueError('EXPRESSION_APPORTIONMENT_COMPONENT_INVALID')
        identity = _id(component['componentId'])
        if identity in ids:
            raise ValueError('EXPRESSION_APPORTIONMENT_DUPLICATE_COMPONENT')
        ids.add(identity)
        if component['sourceRounding'] not in ('exact', 'half_even'):
            raise ValueError('EXPRESSION_APPORTIONMENT_ROUNDING_INVALID')
        targets = component['targets']
        if type(targets) is not list or not 1 <= len(targets) <= MAX_TARGETS:
            raise ValueError('EXPRESSION_APPORTIONMENT_TARGET_LIMIT')
        count += len(targets)
        if count > MAX_CONTRIBUTIONS:
            raise ValueError('EXPRESSION_APPORTIONMENT_CONTRIBUTION_LIMIT')
        prepared = []
        seen = set()
        for target in targets:
            if type(target) is not dict or set(target) != {'memberOverrides', 'weight'}:
                raise ValueError('EXPRESSION_APPORTIONMENT_TARGET_INVALID')
            overrides = _members(target['memberOverrides'], empty=True)
            if set(overrides) - set(source):
                raise ValueError('EXPRESSION_APPORTIONMENT_TARGET_AXIS_INVALID')
            full = {**source, **overrides}
            key = Coordinate.from_mapping(full).series_key
            if key in seen:
                raise ValueError('EXPRESSION_APPORTIONMENT_DUPLICATE_TARGET')
            seen.add(key)
            tie = tuple(full[axis] for axis in ties)
            union[key] = tie
            weight = _decimal(target['weight'], amount=False)
            if Decimal(weight) <= 0:
                raise ValueError('EXPRESSION_APPORTIONMENT_WEIGHT_INVALID')
            prepared.append((tie, {'memberOverrides': {axis: member
                for axis, member in overrides.items() if source[axis] != member},
                'weight': weight}))
        normalized.append({'componentId': identity,
            'expression': _normalize_expression(component['expression'], source, component=True),
            'sourceRounding': component['sourceRounding'],
            'targets': [item for _, item in sorted(prepared, key=lambda pair: pair[0])]})
    if len(union) > MAX_TARGETS:
        raise ValueError('EXPRESSION_APPORTIONMENT_TARGET_LIMIT')
    if len(set(union.values())) != len(union):
        raise ValueError('EXPRESSION_APPORTIONMENT_TIE_AMBIGUOUS')
    result = {'sourceMembers': source, 'resultKey': result_key,
        'apportionment': {'version': 1, 'quantum': quantum, 'tieDimensions': list(ties),
            'control': _normalize_expression(raw['control'], source),
            'components': sorted(normalized, key=lambda item: item['componentId'])}}
    topological_components(result)
    input_coordinates(result)
    if len(json.dumps(result, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()) > MAX_PLAN_BYTES:
        raise ValueError('EXPRESSION_APPORTIONMENT_PLAN_LIMIT')
    return result


def normalize_program(program):
    if (type(program) is not dict or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion'] != 2
            or program['function'] != FUNCTION):
        raise ValueError('EXPRESSION_APPORTIONMENT_REQUEST_INVALID')
    return normalize_request(program['arguments'])


def _normalize_relation_expression(value, operand_ids, *, component=False):
    def leaf(node):
        operation = node.get('op') if isinstance(node, dict) else None
        if operation == 'ComponentAmount':
            if not component or set(node) != {'op', 'componentId'}:
                raise ValueError(
                    'EXPRESSION_APPORTIONMENT_COMPONENT_REFERENCE_INVALID')
            return {'op': 'ComponentAmount',
                    'componentId': _id(node['componentId'])}, 'amount'
        if operation == 'RelationOperand':
            if (set(node) != {'op', 'operandId', 'valueType'}
                    or node['operandId'] not in operand_ids
                    or node['valueType'] not in ('amount', 'ratio')):
                raise ValueError(
                    'EXPRESSION_APPORTIONMENT_RELATION_OPERAND_INVALID')
            return dict(node), node['valueType']
        if operation not in _SCALAR_NODES:
            raise ValueError('EXPRESSION_APPORTIONMENT_EXPRESSION_UNSUPPORTED')
        return None
    normalized, kind = _expression(value, leaf_parser=leaf)
    if kind != 'amount':
        raise ValueError('EXPRESSION_APPORTIONMENT_AMOUNT_REQUIRED')
    if any(node['op'] == 'SourceValue' for node in _nodes(normalized)):
        raise ValueError('EXPRESSION_APPORTIONMENT_RELATION_SOURCE_VALUE_FORBIDDEN')
    return normalized


def normalize_relation_request(value):
    """Normalize one grouped relation-backed apportionment operation."""
    if (type(value) is not dict or set(value) != {
            'apportionmentDomain', 'control', 'formulas', 'resultKey'}):
        raise ValueError('EXPRESSION_APPORTIONMENT_RELATION_REQUEST_INVALID')
    domain = normalize_apportionment_domain(value['apportionmentDomain'])
    result_key = value['resultKey']
    if type(result_key) is not str or not _RESULT.fullmatch(result_key):
        raise ValueError('EXPRESSION_APPORTIONMENT_RESULT_KEY_INVALID')
    operand_ids = {item['operandId'] for item in domain['operands']}
    control = _normalize_relation_expression(
        value['control'], operand_ids, component=False)
    formulas = value['formulas']
    if type(formulas) is not list or not 1 <= len(formulas) <= MAX_FORMULAS:
        raise ValueError('EXPRESSION_APPORTIONMENT_FORMULA_LIMIT')
    prepared = []
    seen = set()
    for formula in formulas:
        if type(formula) is not dict or set(formula) != {
                'formulaId', 'expression'}:
            raise ValueError('EXPRESSION_APPORTIONMENT_FORMULA_INVALID')
        identity = _id(formula['formulaId'])
        if identity in seen:
            raise ValueError('EXPRESSION_APPORTIONMENT_FORMULA_DUPLICATE')
        seen.add(identity)
        prepared.append({'formulaId': identity,
            'expression': _normalize_relation_expression(
                formula['expression'], operand_ids, component=True)})
    return {'apportionmentDomain': domain, 'control': control,
        'formulas': sorted(prepared, key=lambda item: item['formulaId']),
        'resultKey': result_key}


def normalize_relation_program(program):
    if (type(program) is not dict
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != FUNCTION):
        raise ValueError('EXPRESSION_APPORTIONMENT_RELATION_REQUEST_INVALID')
    return normalize_relation_request(program['arguments'])


def apportion_units(amount: Fraction, weights: Mapping[str, Fraction], *,
                    quantum: Fraction, rounding: str,
                    tie_keys: Mapping[str, tuple[str, ...]]):
    """One exact shared largest-remainder calculation, returning signed units."""
    if (not isinstance(amount, Fraction) or not isinstance(quantum, Fraction)
            or quantum not in {Fraction(q) for q in QUANTA}
            or rounding not in ('exact', 'half_even')
            or not 1 <= len(weights) <= MAX_TARGETS
            or set(weights) != set(tie_keys)
            or any(not isinstance(weight, Fraction) or weight <= 0 for weight in weights.values())
            or any(not isinstance(tie, tuple) or not tie
                   or any(type(part) is not str for part in tie) for tie in tie_keys.values())
            or len(set(tie_keys.values())) != len(tie_keys)):
        raise ValueError('EXPRESSION_APPORTIONMENT_PREPARED_INPUT_INVALID')
    if abs(amount) >= 10**20:
        raise ValueError('EXPRESSION_RESULT_OUT_OF_RANGE')
    scaled = abs(amount) / quantum
    units, residue = divmod(scaled.numerator, scaled.denominator)
    if residue and rounding == 'exact':
        raise ValueError('EXPRESSION_APPORTIONMENT_SOURCE_QUANTUM_MISMATCH')
    if rounding == 'half_even' and (2 * residue > scaled.denominator
            or (2 * residue == scaled.denominator and units % 2)):
        units += 1
    if units * quantum >= 10**20:
        raise ValueError('EXPRESSION_RESULT_OUT_OF_RANGE')
    sign = -1 if amount < 0 else 1
    total_weight = sum(weights.values(), Fraction())
    base = {}
    remainders = {}
    for key, weight in weights.items():
        share = units * weight / total_weight
        base[key], rem = divmod(share.numerator, share.denominator)
        remainders[key] = Fraction(rem, share.denominator)
    remainder_units = units - sum(base.values())
    order = sorted(weights, key=lambda key: (-remainders[key], tie_keys[key]))
    awarded = set(order[:remainder_units])
    result = {key: sign * (base[key] + int(key in awarded)) for key in sorted(weights)}
    if not 0 <= remainder_units < len(weights) or sum(result.values()) != sign * units:
        raise ValueError('EXPRESSION_APPORTIONMENT_CONSERVATION_FAILED')
    return sign * units, result, {'quantizedSourceUnits': str(sign * units),
        'remainderUnits': remainder_units,
        'extraUnitTargets': sorted(awarded, key=lambda key: tie_keys[key])}


def catalog_program_schema():
    """Profile discriminants and v36 shape; fixed type/metadata checks remain authoritative."""
    from .postgres_numeric_catalog import obj, program_schema
    identifier = {'type': 'string', 'minLength': 1, 'maxLength': 200}
    members = {'type': 'object', 'minProperties': 1, 'maxProperties': 32,
               'propertyNames': identifier, 'additionalProperties': identifier}
    overrides = {**members, 'minProperties': 0}
    expression = {'type': 'object'}
    target = obj({'memberOverrides': overrides, 'weight': {'type': 'string'}})
    component = obj({'componentId': identifier, 'expression': expression,
        'sourceRounding': {'enum': ['exact', 'half_even']},
        'targets': {'type': 'array', 'minItems': 1, 'maxItems': MAX_TARGETS, 'items': target}})
    profile = obj({'version': {'type': 'integer', 'const': 1}, 'quantum': {'type': 'string', 'description': 'Exact finite decimal power of ten from 1 through 0.00000001; fixed compiler normalizes equivalent decimal spellings and enforces range.'},
        'tieDimensions': {'type': 'array', 'minItems': 1, 'maxItems': 32,
                          'uniqueItems': True, 'items': identifier},
        'control': expression, 'components': {'type': 'array', 'minItems': 1,
            'maxItems': MAX_COMPONENTS, 'items': component}})
    result_key = {'type': 'string', 'pattern': r'^[A-Za-z0-9._-]{8,128}$'}
    # Historical scalar/reduction profiles have different optional source grains.
    # Currency member-set v23 is also a vector alternative without expression.
    scalar = {'type': 'object', 'required': ['expression', 'resultKey'],
        'properties': {'expression': expression, 'resultKey': result_key},
        'oneOf': [{'required': ['sourceMembers']}, {'required': ['sourceDomain', 'missingDefault']}],
        'not': {'anyOf': [{'required': ['apportionment']}, {'required': ['selection']}]}}
    apportioned = obj({'sourceMembers': members, 'resultKey': result_key, 'apportionment': profile})
    applicability = obj({'applicabilityDomain': {'type':'object',
        'required':['format','relationId','relationStateToken',
            'relationDigest','anchorMemberColumns','targetMemberColumns',
            'operands','values','missingPolicy','maxRows']},
        'expression':expression,'resultKey':result_key})
    relation_apportionment = obj({'apportionmentDomain': {'type':'object'},
        'control': expression,
        'formulas': {'type':'array','minItems':1,'maxItems':MAX_FORMULAS,
            'items':obj({'formulaId':identifier,'expression':expression})},
        'resultKey':result_key})
    currency = obj({'grain': {'type': 'object'}, 'fixedMembers': {'type': 'object'},
        'selection': {'type': 'object'}, 'sourceUnitBinding': {'const': 'EntityDefaultCurrency'},
        'toCurrencyMemberId': identifier, 'outputUnitCurrencyMemberId': identifier,
        'rateKind': {'enum': ['balance', 'flow']}, 'resultKey': result_key})
    return program_schema(FUNCTION, {'oneOf': [scalar, applicability,
        relation_apportionment,
                                               apportioned, currency]})
