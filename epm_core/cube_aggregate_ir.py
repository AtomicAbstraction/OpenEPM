"""Pure aggregate intent/grain normalization; not a callable EPM operation.

The caller supplies a trusted active fact layout and its roles. This module
does not resolve members/hierarchies, authorize, read amounts, choose an engine,
or prove unit/additivity/snapshot/resource eligibility. It is not wired into
the catalog, MCP, PostgreSQL modules, worker, or packaged application image.
"""
from dataclasses import dataclass
from hashlib import sha256
import json

COMPILER = 'cube-aggregate-raw-v1'
REDUCTION_COMPILER = 'cube-aggregate-exact-reduction-v2'
GENERIC_COMPILER = 'cube-aggregate-generic-unique-v1'
GENERIC_WEIGHTED_COMPILER = 'cube-aggregate-generic-unique-v2'
GENERIC_PLACEMENT_COMPILER = 'cube-aggregate-generic-placement-v3'
HIERARCHY_UNIQUE_COMPILER = 'cube-aggregate-hierarchy-unique-v4'
HIERARCHY_PLACEMENT_COMPILER = 'cube-aggregate-hierarchy-placement-v5'
FUNCTION = 'facts.cube.aggregate.request'
MAX_INTENT_BYTES = 16384
_ROLES = frozenset(('Scenario', 'Year', 'Period', 'View', 'Entity', 'Value',
                    'Account', 'ICP', 'Currency', 'DataType', 'Custom'))
_FINANCE_ROLES = _ROLES - {'Custom'}


def _id(value):
    if (type(value) is not str or not 1 <= len(value) <= 200
            or value != value.strip() or any(ord(c) < 32 for c in value)):
        raise ValueError('CUBE_AGGREGATE_ID_INVALID')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError as error:
        raise ValueError('CUBE_AGGREGATE_ID_INVALID') from error
    return value


def _axes(value, maximum, *, empty=False):
    if type(value) not in (list, tuple) or not (0 if empty else 1) <= len(value) <= maximum:
        raise ValueError('CUBE_AGGREGATE_GRAIN_INVALID')
    axes = tuple(_id(axis) for axis in value)
    if len(set(axes)) != len(axes):
        raise ValueError('CUBE_AGGREGATE_GRAIN_INVALID')
    return axes


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


@dataclass(frozen=True, slots=True)
class AggregateSelector:
    dimension: str
    kind: str
    member_ids: tuple[str, ...] = ()
    root_member_id: str | None = None
    include_self: bool | None = None
    hierarchy_id: str | None = None

    def normalized(self):
        if self.kind == 'Members':
            return {'kind': self.kind, 'memberIds': list(self.member_ids)}
        return {'kind': self.kind, 'rootMemberId': self.root_member_id,
                'includeSelf': self.include_self,
                **({'hierarchyId': self.hierarchy_id} if self.hierarchy_id is not None else {})}


@dataclass(frozen=True, slots=True)
class CubeAggregateIR:
    input_dimensions: tuple[str, ...]
    dimension_roles: tuple[tuple[str, str | None], ...]
    group_by: tuple[str, ...]
    reduce_dimensions: tuple[str, ...]
    fixed_dimensions: tuple[str, ...]
    selectors: tuple[AggregateSelector, ...]
    measures: tuple[str, ...]
    aggregation: str
    generic_pins: tuple[tuple[str, object], ...] = ()
    hierarchy_pins: tuple[tuple[str, object], ...] = ()
    operator_weights: tuple[tuple[str, tuple[tuple[str, int], ...]], ...] = ()
    placement_weights: tuple[tuple[str, tuple[tuple[str, tuple[int, int]], ...]], ...] = ()

    @property
    def normalized_arguments(self):
        result = {'source': 'raw_numeric', 'grain': {
                    'inputDimensions': list(self.input_dimensions),
                    'groupBy': list(self.group_by),
                    'reduceDimensions': list(self.reduce_dimensions)},
                'selectors': {s.dimension: s.normalized() for s in self.selectors},
                'measures': [{'kind': kind} for kind in self.measures],
                'missing': 'exclude', 'aggregation': self.aggregation}
        if self.generic_pins:
            result['genericPins'] = dict(self.generic_pins)
        if self.hierarchy_pins:
            result['hierarchyPins'] = dict(self.hierarchy_pins)
        if self.operator_weights:
            result['operatorWeights'] = {
                dimension: dict(weights)
                for dimension, weights in self.operator_weights}
        if self.placement_weights:
            result['placementWeights'] = {
                dimension: {member: {'sumWeight': weights[0],
                                     'countWeight': weights[1]}
                            for member, weights in by_member}
                for dimension, by_member in self.placement_weights}
        return result

    @property
    def normalized_program(self):
        compiler = (HIERARCHY_PLACEMENT_COMPILER
                    if self.aggregation == 'hierarchy_placement_weighted_sum'
                    else HIERARCHY_UNIQUE_COMPILER
                    if self.aggregation == 'hierarchy_unique_member_weighted_sum'
                    else GENERIC_PLACEMENT_COMPILER
                    if self.aggregation == 'generic_placement_weighted_sum'
                    else GENERIC_WEIGHTED_COMPILER
                    if self.aggregation == 'generic_unique_member_weighted_sum'
                    else GENERIC_COMPILER
                    if self.aggregation == 'generic_unique_member_sum'
                    else COMPILER if self.aggregation == 'unique_coordinate_sum'
                    else REDUCTION_COMPILER)
        roles = ({axis: None for axis in self.input_dimensions}
                 if compiler in (GENERIC_COMPILER,GENERIC_WEIGHTED_COMPILER,
                                 GENERIC_PLACEMENT_COMPILER,
                                 HIERARCHY_UNIQUE_COMPILER,
                                 HIERARCHY_PLACEMENT_COMPILER)
                 else dict(self.dimension_roles))
        return {'version': (5 if compiler == HIERARCHY_PLACEMENT_COMPILER else
                            4 if compiler == HIERARCHY_UNIQUE_COMPILER else
                            3 if compiler == GENERIC_PLACEMENT_COMPILER else
                            1 if compiler in (COMPILER,GENERIC_COMPILER) else 2),
                'compiler': compiler, 'function': FUNCTION,
                'arguments': self.normalized_arguments,
                'layoutRoles': roles}

    @property
    def plan_digest(self):
        return sha256(_canonical(self.normalized_program).encode('ascii')).hexdigest()


def compile_cube_aggregate(arguments, *, input_dimensions, dimension_roles):
    """Normalize syntax against server layout, leaving semantic admission undone.

    input_dimensions excludes the separate Currency metadata dimension, matching
    the current full-coordinate source model. Role mapping covers every axis;
    None and Custom are generic, every other existing role is protected.
    """
    layout = tuple(sorted(_axes(input_dimensions, 128)))
    if (type(dimension_roles) is not dict or set(dimension_roles) != set(layout)
            or any(role is not None and (type(role) is not str or role not in _ROLES)
                   for role in dimension_roles.values())
            or 'Currency' in dimension_roles.values()):
        raise ValueError('CUBE_AGGREGATE_LAYOUT_INVALID')
    base={'source','grain','selectors','measures','missing','aggregation'}
    allowed=(base,base|{'genericPins'},
             base|{'genericPins','operatorWeights'},
             base|{'genericPins','placementWeights'},
             base|{'hierarchyPins','operatorWeights'},
             base|{'hierarchyPins','placementWeights'})
    if type(arguments) is not dict or set(arguments) not in allowed:
        raise ValueError('CUBE_AGGREGATE_ARGUMENTS_INVALID')
    generic=arguments.get('aggregation') in (
        'generic_unique_member_sum','generic_unique_member_weighted_sum',
        'generic_placement_weighted_sum')
    if generic != ('genericPins' in arguments):
        raise ValueError('CUBE_AGGREGATE_ARGUMENTS_INVALID')
    hierarchy=arguments.get('aggregation') in (
        'hierarchy_unique_member_weighted_sum',
        'hierarchy_placement_weighted_sum')
    if hierarchy != ('hierarchyPins' in arguments):
        raise ValueError('CUBE_AGGREGATE_ARGUMENTS_INVALID')
    weighted=arguments.get('aggregation') in (
        'generic_unique_member_weighted_sum',
        'hierarchy_unique_member_weighted_sum')
    if weighted != ('operatorWeights' in arguments):
        raise ValueError('CUBE_AGGREGATE_ARGUMENTS_INVALID')
    placement=arguments.get('aggregation') in (
        'generic_placement_weighted_sum',
        'hierarchy_placement_weighted_sum')
    if placement != ('placementWeights' in arguments):
        raise ValueError('CUBE_AGGREGATE_ARGUMENTS_INVALID')
    if (arguments['source'] != 'raw_numeric' or arguments['missing'] != 'exclude'
            or arguments['aggregation'] not in
                ('unique_coordinate_sum', 'unique_coordinate_reduction',
                 'generic_unique_member_sum',
                 'generic_unique_member_weighted_sum',
                 'generic_placement_weighted_sum',
                 'hierarchy_unique_member_weighted_sum',
                 'hierarchy_placement_weighted_sum')):
        raise ValueError('CUBE_AGGREGATE_SEMANTICS_UNSUPPORTED')
    generic_pins=()
    hierarchy_pins=()
    if generic:
        pins=arguments['genericPins']
        expected_pins={'selectionId','resolutionDigest','metadataRevision',
                       'policyRevision'}
        if placement:
            expected_pins.add('placementLineageDigest')
        if (type(pins) is not dict or set(pins)!=expected_pins
                or type(pins['selectionId']) is not str
                or not 8<=len(pins['selectionId'])<=200
                or type(pins['resolutionDigest']) is not str
                or len(pins['resolutionDigest'])!=64
                or any(c not in '0123456789abcdef' for c in pins['resolutionDigest'])
                or type(pins['metadataRevision']) is not int
                or pins['metadataRevision']<1
                or type(pins['policyRevision']) is not int
                or pins['policyRevision']<0
                or (placement and (type(pins['placementLineageDigest']) is not str
                    or len(pins['placementLineageDigest'])!=64
                    or any(c not in '0123456789abcdef'
                           for c in pins['placementLineageDigest'])))):
            raise ValueError('CUBE_AGGREGATE_GENERIC_PINS_INVALID')
        generic_pins=tuple(sorted(pins.items()))
    if hierarchy:
        pins=arguments['hierarchyPins']
        expected={'nodeDefinitionDigest','contributionDigest','hierarchyId',
                  'hierarchyStateToken','metadataRevision','policyRevision'}
        if placement:
            expected.add('placementLineageDigest')
        digest_keys={'nodeDefinitionDigest','contributionDigest','hierarchyStateToken'}
        if placement:
            digest_keys.add('placementLineageDigest')
        if (type(pins) is not dict or set(pins)!=expected
                or any(type(pins.get(key)) is not str
                       or len(pins[key])!=64
                       or any(c not in '0123456789abcdef' for c in pins[key])
                       for key in digest_keys)
                or type(pins.get('hierarchyId')) is not str
                or not 1<=len(pins['hierarchyId'])<=200
                or type(pins.get('metadataRevision')) is not int
                or pins['metadataRevision']<1
                or type(pins.get('policyRevision')) is not int
                or pins['policyRevision']<0):
            raise ValueError('CUBE_AGGREGATE_HIERARCHY_PINS_INVALID')
        hierarchy_pins=tuple(sorted(pins.items()))
    grain = arguments['grain']
    if type(grain) is not dict or set(grain) != {'inputDimensions', 'groupBy', 'reduceDimensions'}:
        raise ValueError('CUBE_AGGREGATE_GRAIN_INVALID')
    # Authored JSON axes must be arrays; trusted layout may be a tuple.
    if any(type(grain[k]) is not list for k in grain):
        raise ValueError('CUBE_AGGREGATE_GRAIN_INVALID')
    authored = tuple(sorted(_axes(grain['inputDimensions'], 128)))
    grouped = _axes(grain['groupBy'], 6, empty=True)
    reduced = tuple(sorted(_axes(grain['reduceDimensions'], 128, empty=True)))
    if (authored != layout or not set(grouped + reduced) <= set(layout)
            or set(grouped) & set(reduced)):
        raise ValueError('CUBE_AGGREGATE_GRAIN_MISMATCH')
    if (not generic and not hierarchy and
            any(dimension_roles[axis] in _FINANCE_ROLES for axis in reduced)):
        raise ValueError('CUBE_AGGREGATE_FINANCE_REDUCTION_UNSUPPORTED')
    raw_selectors = arguments['selectors']
    if type(raw_selectors) is not dict or len(raw_selectors) > 16:
        raise ValueError('CUBE_AGGREGATE_SELECTORS_INVALID')
    selectors = []
    explicit_members = 0
    for axis, selector in raw_selectors.items():
        _id(axis)
        if axis not in layout or type(selector) is not dict:
            raise ValueError('CUBE_AGGREGATE_SELECTOR_AXIS_INVALID')
        kind = selector.get('kind')
        if kind == 'Members':
            if set(selector) != {'kind', 'memberIds'} or type(selector['memberIds']) is not list:
                raise ValueError('CUBE_AGGREGATE_SELECTOR_INVALID')
            members = tuple(sorted(_axes(selector['memberIds'], 500)))
            explicit_members += len(members)
            selectors.append(AggregateSelector(axis, kind, members))
        elif kind in ('Children', 'Descendants', 'Leaves'):
            if set(selector) not in ({'kind', 'rootMemberId', 'includeSelf'},
                                     {'kind', 'rootMemberId', 'includeSelf', 'hierarchyId'}):
                raise ValueError('CUBE_AGGREGATE_SELECTOR_INVALID')
            if type(selector['includeSelf']) is not bool:
                raise ValueError('CUBE_AGGREGATE_HIERARCHY_INVALID')
            selectors.append(AggregateSelector(axis, kind, (), _id(selector['rootMemberId']),
                                               selector['includeSelf'],
                                               _id(selector['hierarchyId']) if 'hierarchyId' in selector else None))
        else:
            raise ValueError('CUBE_AGGREGATE_SELECTOR_INVALID')
    if explicit_members > 500:
        raise ValueError('CUBE_AGGREGATE_SELECTOR_BUDGET')
    fixed = tuple(sorted(set(layout) - set(grouped) - set(reduced)))
    by_axis = {s.dimension: s for s in selectors}
    if any(axis not in by_axis or by_axis[axis].kind != 'Members'
           or len(by_axis[axis].member_ids) != 1 for axis in fixed):
        raise ValueError('CUBE_AGGREGATE_IMPLICIT_REDUCTION_FORBIDDEN')
    operator_weights=()
    if weighted:
        raw_weights=arguments['operatorWeights']
        if type(raw_weights) is not dict or set(raw_weights)!=set(reduced):
            raise ValueError('CUBE_AGGREGATE_OPERATOR_WEIGHTS_INVALID')
        normalized_weights=[]
        for axis in reduced:
            weights=raw_weights[axis]
            selector=by_axis.get(axis)
            if (type(weights) is not dict or selector is None
                    or selector.kind!='Members'
                    or set(weights)!=set(selector.member_ids)
                    or any(type(member) is not str or type(weight) is not int
                           or weight not in (-1,0,1)
                           for member,weight in weights.items())):
                raise ValueError('CUBE_AGGREGATE_OPERATOR_WEIGHTS_INVALID')
            normalized_weights.append((axis,tuple(sorted(weights.items()))))
        if (arguments['aggregation']=='generic_unique_member_weighted_sum'
                and not any(weight != 1 for _,weights in normalized_weights
                            for _,weight in weights)):
            raise ValueError('CUBE_AGGREGATE_OPERATOR_WEIGHTS_REDUNDANT')
        operator_weights=tuple(normalized_weights)
    placement_weights=()
    if placement:
        raw_weights=arguments['placementWeights']
        if type(raw_weights) is not dict or set(raw_weights)!=set(reduced):
            raise ValueError('CUBE_AGGREGATE_PLACEMENT_WEIGHTS_INVALID')
        normalized=[]
        for axis in reduced:
            weights=raw_weights[axis]
            selector=by_axis.get(axis)
            if (type(weights) is not dict or selector is None
                    or selector.kind!='Members'
                    or set(weights)!=set(selector.member_ids)):
                raise ValueError('CUBE_AGGREGATE_PLACEMENT_WEIGHTS_INVALID')
            members=[]
            for member,item in weights.items():
                if (type(item) is not dict
                        or set(item)!={'sumWeight','countWeight'}
                        or type(item['sumWeight']) is not int
                        or type(item['countWeight']) is not int
                        or not -500<=item['sumWeight']<=500
                        or not 0<=item['countWeight']<=500
                        or abs(item['sumWeight'])>item['countWeight']):
                    raise ValueError('CUBE_AGGREGATE_PLACEMENT_WEIGHTS_INVALID')
                members.append((member,(item['sumWeight'],item['countWeight'])))
            normalized.append((axis,tuple(sorted(members))))
        placement_weights=tuple(normalized)
    measures = arguments['measures']
    if type(measures) is not list or not 1 <= len(measures) <= 4:
        raise ValueError('CUBE_AGGREGATE_MEASURE_INVALID')
    kinds = []
    for measure in measures:
        if (type(measure) is not dict or set(measure) != {'kind'}
                or type(measure['kind']) is not str
                or measure['kind'] not in
                    ('SumAmount', 'CountPresent', 'MinAmount', 'MaxAmount')):
            raise ValueError('CUBE_AGGREGATE_MEASURE_INVALID')
        kinds.append(measure['kind'])
    if len(set(kinds)) != len(kinds):
        raise ValueError('CUBE_AGGREGATE_MEASURE_INVALID')
    if (arguments['aggregation'] in
            ('unique_coordinate_sum','generic_unique_member_sum',
             'generic_unique_member_weighted_sum',
             'generic_placement_weighted_sum',
             'hierarchy_unique_member_weighted_sum',
             'hierarchy_placement_weighted_sum')
            and set(kinds) - {'SumAmount', 'CountPresent'}):
        # Preserve every accepted v1 digest and semantic contract. Exact
        # non-additive reductions require the explicit v2 intent marker.
        raise ValueError('CUBE_AGGREGATE_SEMANTICS_UNSUPPORTED')
    ir = CubeAggregateIR(layout, tuple((a, dimension_roles[a]) for a in layout), grouped,
                         reduced, fixed, tuple(sorted(selectors, key=lambda s: s.dimension)),
                         tuple(sorted(kinds)), arguments['aggregation'],
                         generic_pins,hierarchy_pins,operator_weights,
                         placement_weights)
    if len(_canonical(ir.normalized_arguments).encode('ascii')) > MAX_INTENT_BYTES:
        raise ValueError('CUBE_AGGREGATE_INTENT_BUDGET')
    return ir
