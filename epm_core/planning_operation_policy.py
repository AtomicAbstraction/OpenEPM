"""Pure current reusable-policy contract for generic planning operations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re


FORMAT = 'openepm-planning-operation-policy-v1'
FORMAT_V2 = 'openepm-planning-operation-policy-v2'
KINDS = {'Seed', 'Driver', 'Rollup', 'Spread', 'Allocation'}
_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$')
MAX_PARAMETERS = 100
MAX_MEMBERS = 500
MAX_DEPENDENCIES = 100
MAX_BYTES = 1024 * 1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _stable_id(value, label='ID'):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError('PLANNING_POLICY_' + label.upper() + '_INVALID')
    return value


def _integer(value, label, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError('PLANNING_POLICY_' + label.upper() + '_INVALID')
    return value


def _iso(value, label):
    if not isinstance(value, str):
        raise ValueError('PLANNING_POLICY_' + label.upper() + '_INVALID')
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError('PLANNING_POLICY_' + label.upper() + '_INVALID') from error
    if parsed.isoformat() != value:
        raise ValueError('PLANNING_POLICY_' + label.upper() + '_INVALID')
    return value


def _decimal(value, label):
    if not isinstance(value, str):
        raise ValueError('PLANNING_POLICY_' + label.upper() + '_DECIMAL_INVALID')
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ValueError('PLANNING_POLICY_' + label.upper() + '_DECIMAL_INVALID') from error
    if not parsed.is_finite() or value.strip() != value:
        raise ValueError('PLANNING_POLICY_' + label.upper() + '_DECIMAL_INVALID')
    return format(parsed, 'f')


def _member_set(value):
    if (not isinstance(value, dict) or set(value) != {'kind', 'memberIds'}
            or value['kind'] != 'Members'
            or not isinstance(value['memberIds'], list)
            or not 1 <= len(value['memberIds']) <= MAX_MEMBERS):
        raise ValueError('PLANNING_POLICY_MEMBER_SET_INVALID')
    members = [_stable_id(item, 'MEMBER') for item in value['memberIds']]
    if len(members) != len(set(members)):
        raise ValueError('PLANNING_POLICY_MEMBER_SET_DUPLICATE')
    return {'kind': 'Members', 'memberIds': sorted(members)}


def _grain(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise ValueError('PLANNING_POLICY_GRAIN_INVALID')
    result = [_stable_id(item, 'DIMENSION') for item in value]
    if len(result) != len(set(result)):
        raise ValueError('PLANNING_POLICY_GRAIN_INVALID')
    return sorted(result)


def _unit(value):
    if value in ('Amount', 'Ratio'):
        return value
    if isinstance(value, str) and value.startswith('Currency:'):
        _stable_id(value[9:], 'CURRENCY')
        return value
    raise ValueError('PLANNING_POLICY_UNIT_INVALID')


def _reference(value, parameters, expected='Member'):
    if isinstance(value, str):
        return _stable_id(value, expected.upper())
    if (not isinstance(value, dict) or set(value) != {'parameter'}
            or value['parameter'] not in parameters
            or parameters[value['parameter']]['type'] != expected):
        raise ValueError('PLANNING_POLICY_PARAMETER_REFERENCE_INVALID')
    return {'parameter': value['parameter']}


def _parameters(value):
    if not isinstance(value, dict) or len(value) > MAX_PARAMETERS:
        raise ValueError('PLANNING_POLICY_PARAMETERS_INVALID')
    result = {}
    for name, spec in sorted(value.items()):
        _stable_id(name, 'PARAMETER')
        if (not isinstance(spec, dict) or set(spec) != {'type', 'required'}
                or spec['type'] not in ('Member', 'Decimal', 'Integer', 'Text')
                or type(spec['required']) is not bool):
            raise ValueError('PLANNING_POLICY_PARAMETER_INVALID')
        result[name] = dict(spec)
    return result


def _seed(raw, parameters):
    required = {'scenarioDimension', 'sourceMember', 'targetMember',
                'filterMembers', 'mode', 'provenancePolicy'}
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError('PLANNING_POLICY_SEED_INVALID')
    filters = raw['filterMembers']
    if not isinstance(filters, dict) or len(filters) > 31:
        raise ValueError('PLANNING_POLICY_SEED_FILTER_INVALID')
    result = {'scenarioDimension': _stable_id(raw['scenarioDimension'], 'DIMENSION'),
        'sourceMember': _reference(raw['sourceMember'], parameters),
        'targetMember': _reference(raw['targetMember'], parameters),
        'filterMembers': {_stable_id(axis, 'DIMENSION'):
            _reference(member, parameters) for axis, member in sorted(filters.items())},
        'mode': raw['mode'], 'provenancePolicy': raw['provenancePolicy']}
    if result['mode'] not in ('merge', 'replace') or result['provenancePolicy'] != 'copy_source_lineage':
        raise ValueError('PLANNING_POLICY_SEED_SEMANTICS_INVALID')
    if result['scenarioDimension'] in result['filterMembers']:
        raise ValueError('PLANNING_POLICY_SEED_GRAIN_AMBIGUOUS')
    return result


def _driver(raw, parameters, *, v2=False):
    if (not isinstance(raw, dict) or set(raw) != {
            'calculationKind', 'inputs', 'output', 'dependencies'}):
        raise ValueError('PLANNING_POLICY_DRIVER_INVALID')
    inputs = raw['inputs']
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 100:
        raise ValueError('PLANNING_POLICY_DRIVER_INPUTS_INVALID')
    normalized = []
    names = set()
    for item in inputs:
        fields = {'name', 'members', 'unit', 'grain'} | (
            {'sourceKind'} if v2 else set())
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError('PLANNING_POLICY_DRIVER_INPUT_INVALID')
        name = _stable_id(item['name'], 'INPUT')
        if name in names:
            raise ValueError('PLANNING_POLICY_DRIVER_INPUT_DUPLICATE')
        names.add(name)
        normalized.append({'name': name, 'members': _member_set(item['members']),
                           'unit': _unit(item['unit']), 'grain': _grain(item['grain']),
                           **({'sourceKind':item['sourceKind']} if v2 else {})})
    output = raw['output']
    if not isinstance(output, dict) or set(output) != {'members', 'unit', 'grain'}:
        raise ValueError('PLANNING_POLICY_DRIVER_OUTPUT_INVALID')
    output = {'members': _member_set(output['members']),
              'unit': _unit(output['unit']), 'grain': _grain(output['grain'])}
    kind = raw['calculationKind']
    units = [item['unit'] for item in normalized]
    if kind == 'Copy' and (v2 or len(normalized) != 1 or units[0] != output['unit']):
        raise ValueError('PLANNING_POLICY_DRIVER_UNIT_INCOMPATIBLE')
    if kind == 'MultiplyAmountByRatio' and (len(normalized) != 2
            or v2 or sorted(units) != ['Amount', 'Ratio'] or output['unit'] != 'Amount'):
        raise ValueError('PLANNING_POLICY_DRIVER_UNIT_INCOMPATIBLE')
    if kind == 'MultiplyPublishedAmountByRatio':
        kinds = sorted((item['sourceKind'], item['unit']) for item in normalized)
        if (not v2 or len(normalized) != 2 or output['unit'] != 'Amount'
                or kinds != [('PublishedAmount', 'Amount'), ('Raw', 'Ratio')]):
            raise ValueError('PLANNING_POLICY_DRIVER_UNIT_INCOMPATIBLE')
    if kind not in ('Copy', 'MultiplyAmountByRatio',
                    'MultiplyPublishedAmountByRatio'):
        raise ValueError('PLANNING_POLICY_DRIVER_KIND_INVALID')
    if any(item['grain'] != output['grain'] for item in normalized):
        raise ValueError('PLANNING_POLICY_DRIVER_GRAIN_INCOMPATIBLE')
    dependencies = raw['dependencies']
    if (not isinstance(dependencies, list)
            or len(dependencies) > MAX_DEPENDENCIES):
        raise ValueError('PLANNING_POLICY_DEPENDENCIES_INVALID')
    edges = []
    graph = {name: set() for name in names}
    if v2:graph['Output']=set()
    for edge in dependencies:
        if (not isinstance(edge, dict) or set(edge) != {'before', 'after'}
                or edge['before'] not in graph or edge['after'] not in graph
                or edge['before'] == edge['after']):
            raise ValueError('PLANNING_POLICY_DEPENDENCY_INVALID')
        pair = (edge['before'], edge['after'])
        if pair in edges:
            raise ValueError('PLANNING_POLICY_DEPENDENCY_DUPLICATE')
        edges.append(pair); graph[pair[0]].add(pair[1])
    if v2 and set(edges)!={(name,'Output') for name in names}:
        raise ValueError('PLANNING_POLICY_DEPENDENCY_UNSUPPORTED')
    visiting, visited = set(), set()
    def visit(node):
        if node in visiting: raise ValueError('PLANNING_POLICY_DEPENDENCY_CYCLE')
        if node in visited: return
        visiting.add(node)
        for child in graph[node]: visit(child)
        visiting.remove(node); visited.add(node)
    for name in sorted(names): visit(name)
    return {'calculationKind': kind, 'inputs': sorted(normalized, key=lambda x:x['name']),
            'output': output, 'dependencies': [
                {'before': before, 'after': after} for before, after in sorted(edges)]}


def _rollup(raw, parameters, *, v2=False):
    if v2:
        required={'dimension','parent','fixedMembers','sliceSelection',
                  'sharedMemberPolicy','placementIds'}
        if not isinstance(raw,dict) or set(raw)!=required:
            raise ValueError('PLANNING_POLICY_ROLLUP_INVALID')
        fixed=raw['fixedMembers'];selection=raw['sliceSelection']
        if (not isinstance(fixed,dict) or len(fixed)>30
                or any(not isinstance(axis,str) or not axis
                       for axis in fixed)
                or not isinstance(selection,dict)
                or set(selection)!={'dimensionId','memberIds'}
                or not isinstance(selection['dimensionId'],str)
                or not selection['dimensionId']
                or not isinstance(selection['memberIds'],list)
                or not 1<=len(selection['memberIds'])<=100):
            raise ValueError('PLANNING_POLICY_ROLLUP_SLICE_INVALID')
        members=sorted(_stable_id(x,'MEMBER') for x in selection['memberIds'])
        if (len(members)!=len(set(members))
                or raw['dimension'] in fixed
                or raw['dimension']==selection['dimensionId']
                or selection['dimensionId'] in fixed):
            raise ValueError('PLANNING_POLICY_ROLLUP_SLICE_INVALID')
        policy=raw['sharedMemberPolicy'];placements=raw['placementIds']
        if policy not in ('unique_member','placement_explicit') or not isinstance(placements,list):
            raise ValueError('PLANNING_POLICY_ROLLUP_PLACEMENT_INVALID')
        placements=sorted(_stable_id(x,'PLACEMENT') for x in placements)
        if (len(placements)!=len(set(placements))
                or len(placements)>100
                or (policy=='unique_member' and placements)
                or (policy=='placement_explicit' and not placements)):
            raise ValueError('PLANNING_POLICY_ROLLUP_PLACEMENT_INVALID')
        return {'dimension':_stable_id(raw['dimension'],'DIMENSION'),
            'parent':_reference(raw['parent'],parameters),
            'fixedMembers':{_stable_id(a,'DIMENSION'):_reference(m,parameters)
                            for a,m in sorted(fixed.items())},
            'sliceSelection':{'dimensionId':_stable_id(
                selection['dimensionId'],'DIMENSION'),'memberIds':members},
            'sharedMemberPolicy':policy,'placementIds':placements}
    if not isinstance(raw, dict) or set(raw) != {'dimension', 'parent', 'slice', 'sharedMemberPolicy', 'placementIds'}:
        raise ValueError('PLANNING_POLICY_ROLLUP_INVALID')
    policy = raw['sharedMemberPolicy']
    placements = raw['placementIds']
    if policy not in ('unique_member', 'placement_explicit') or not isinstance(placements, list):
        raise ValueError('PLANNING_POLICY_ROLLUP_PLACEMENT_INVALID')
    placements = sorted(_stable_id(x, 'PLACEMENT') for x in placements)
    if len(placements) != len(set(placements)) or (policy == 'unique_member' and placements) or (policy == 'placement_explicit' and not placements):
        raise ValueError('PLANNING_POLICY_ROLLUP_PLACEMENT_INVALID')
    return {'dimension': _stable_id(raw['dimension'], 'DIMENSION'),
            'parent': _reference(raw['parent'], parameters),
            'slice': _member_set(raw['slice']), 'sharedMemberPolicy': policy,
            'placementIds': placements}


def _spread(raw, parameters, *, v2=False):
    if not isinstance(raw, dict) or set(raw) != {'sourceMembers', 'targetDimension', 'targetMembers', 'calendarPolicy', 'totalPreservation', 'roundingPolicy'}:
        raise ValueError('PLANNING_POLICY_SPREAD_INVALID')
    expected=('largestRemainderFiscalOrdinal' if v2
              else 'largestRemainderStableMember')
    if ((v2 and raw['calendarPolicy']!='fiscal_ordinal')
            or (not v2 and raw['calendarPolicy'] not in (
                'selection_order','fiscal_ordinal'))
            or raw['totalPreservation']!='exact'
            or raw['roundingPolicy']!=expected):
        raise ValueError('PLANNING_POLICY_SPREAD_SEMANTICS_INVALID')
    return {'sourceMembers': _member_set(raw['sourceMembers']),
            'targetDimension': _stable_id(raw['targetDimension'], 'DIMENSION'),
            'targetMembers': _member_set(raw['targetMembers']),
            'calendarPolicy': raw['calendarPolicy'], 'totalPreservation': 'exact',
            'roundingPolicy': raw['roundingPolicy']}


def _allocation(raw, parameters, *, v2=False):
    required = {'sourceMembers', 'basisMembers', 'targetDimension',
                'targetMembers', 'lockedTargetPolicy', 'conservationScope',
                'remainderPolicy'} | ({'basisSourceKind'} if v2 else set())
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError('PLANNING_POLICY_ALLOCATION_INVALID')
    if v2 and raw['basisSourceKind'] != 'PublishedRatio':
        raise ValueError('PLANNING_POLICY_ALLOCATION_BASIS_INVALID')
    if raw['lockedTargetPolicy'] != 'reject' or raw['conservationScope'] != 'sourceCoordinate' or raw['remainderPolicy'] != 'largestRemainderStableMember':
        raise ValueError('PLANNING_POLICY_ALLOCATION_NONCONSERVING')
    return {'sourceMembers': _member_set(raw['sourceMembers']),
            'basisMembers': _member_set(raw['basisMembers']),
            'targetDimension': _stable_id(raw['targetDimension'], 'DIMENSION'),
            'targetMembers': _member_set(raw['targetMembers']),
            'lockedTargetPolicy': 'reject', 'conservationScope': 'sourceCoordinate',
            'remainderPolicy': 'largestRemainderStableMember',
            **({'basisSourceKind':'PublishedRatio'} if v2 else {})}


@dataclass(frozen=True)
class PlanningOperationPolicy:
    document: dict
    digest: str
    canonical_bytes: bytes

    @property
    def kind(self): return self.document['kind']


def compile_planning_operation_policy(document: object) -> PlanningOperationPolicy:
    required = {'format', 'policyId', 'kind', 'effectiveFrom',
                'effectiveBefore', 'metadataRevision', 'policyRevision',
                'parameters', 'definition'}
    if (not isinstance(document, dict) or set(document) != required
            or document.get('format') not in (FORMAT, FORMAT_V2)):
        raise ValueError('PLANNING_POLICY_DOCUMENT_INVALID')
    v2=document['format']==FORMAT_V2
    start, end = _iso(document['effectiveFrom'], 'EFFECTIVE_FROM'), _iso(document['effectiveBefore'], 'EFFECTIVE_BEFORE')
    if start >= end: raise ValueError('PLANNING_POLICY_EFFECTIVE_RANGE_INVALID')
    parameters = _parameters(document['parameters'])
    kind = document['kind']
    if kind not in KINDS: raise ValueError('PLANNING_POLICY_KIND_INVALID')
    if v2 and kind not in ('Driver', 'Rollup', 'Spread', 'Allocation'):
        raise ValueError('PLANNING_POLICY_V2_KIND_UNSUPPORTED')
    compiler = {'Seed': _seed,
                'Driver': (lambda raw,params:_driver(raw,params,v2=v2)),
                'Rollup': (lambda raw,params:_rollup(raw,params,v2=v2)),
                'Spread': (lambda raw,params:_spread(raw,params,v2=v2)),
                'Allocation': (lambda raw,params:_allocation(raw,params,v2=v2))}[kind]
    normalized = {'format': document['format'], 'policyId': _stable_id(document['policyId'], 'ID'),
        'kind': kind,
        'effectiveFrom': start, 'effectiveBefore': end,
        'metadataRevision': _integer(document['metadataRevision'], 'METADATA_REVISION'),
        'policyRevision': _integer(document['policyRevision'], 'POLICY_REVISION'),
        'parameters': parameters, 'definition': compiler(document['definition'], parameters)}
    encoded = _canonical(normalized)
    if len(encoded) > MAX_BYTES: raise ValueError('PLANNING_POLICY_SIZE_LIMIT')
    return PlanningOperationPolicy(normalized, sha256(encoded).hexdigest(), encoded)


def bind_planning_operation_policy(policy: PlanningOperationPolicy, bindings: object, *, metadata_revision: int, policy_revision: int, effective_on: str) -> dict:
    if not isinstance(policy, PlanningOperationPolicy) or not isinstance(bindings, dict):
        raise ValueError('PLANNING_POLICY_BINDINGS_INVALID')
    names = set(policy.document['parameters'])
    required = {name for name, spec in policy.document['parameters'].items()
                if spec['required']}
    if not required <= set(bindings) <= names:
        raise ValueError('PLANNING_POLICY_BINDINGS_INVALID')
    _integer(metadata_revision, 'METADATA_REVISION'); _integer(policy_revision, 'POLICY_REVISION')
    if (metadata_revision != policy.document['metadataRevision'] or
            policy_revision != policy.document['policyRevision']):
        raise ValueError('PLANNING_POLICY_STALE_PINS')
    on = _iso(effective_on, 'EFFECTIVE_ON')
    if not policy.document['effectiveFrom'] <= on < policy.document['effectiveBefore']:
        raise ValueError('PLANNING_POLICY_NOT_EFFECTIVE')
    normalized = {}
    for name, spec in policy.document['parameters'].items():
        if name not in bindings:
            continue
        value = bindings[name]
        if spec['type'] == 'Member': value = _stable_id(value, 'MEMBER')
        elif spec['type'] == 'Decimal': value = _decimal(value, 'BINDING')
        elif spec['type'] == 'Integer': value = _integer(value, 'BINDING')
        elif not isinstance(value, str) or len(value) > 2000: raise ValueError('PLANNING_POLICY_BINDING_INVALID')
        normalized[name] = value
    def resolve(value):
        if isinstance(value, dict) and set(value) == {'parameter'}:
            if value['parameter'] not in normalized:
                raise ValueError('PLANNING_POLICY_BINDING_REQUIRED_BY_DEFINITION')
            return normalized[value['parameter']]
        if isinstance(value, dict): return {k: resolve(v) for k,v in value.items()}
        if isinstance(value, list): return [resolve(v) for v in value]
        return value
    return {'policyId': policy.document['policyId'],
            'policyDigest': policy.digest, 'kind': policy.kind,
            'metadataRevision': metadata_revision,
            'policyRevision': policy_revision,
            'effectiveOn': on, 'bindings': normalized,
            'definition': resolve(policy.document['definition']),
            **({'policyFormat':FORMAT_V2}
               if policy.document['format']==FORMAT_V2 else {})}


def lower_bound_seed_to_legacy_v2(bound: object, *, expected_data_revision: int,
                                  idempotency_key: str) -> dict:
    """Lower the shared Seed contract to the existing compatible V2 function.

    Other policy kinds deliberately remain at the shared normalized boundary until
    their legacy operation shapes can represent every declared invariant.
    """
    if (not isinstance(bound, dict)
            or set(bound) != {'policyId', 'policyDigest', 'kind',
                              'metadataRevision', 'policyRevision', 'effectiveOn',
                              'bindings', 'definition'}
            or bound['kind'] != 'Seed'):
        raise ValueError('PLANNING_POLICY_SEED_LOWERING_INVALID')
    _integer(expected_data_revision, 'EXPECTED_DATA_REVISION')
    if (not isinstance(idempotency_key, str)
            or not re.fullmatch(r'[A-Za-z0-9._-]{8,128}', idempotency_key)):
        raise ValueError('PLANNING_POLICY_IDEMPOTENCY_KEY_INVALID')
    definition = bound['definition']
    if (not isinstance(definition, dict)
            or set(definition) != {'scenarioDimension', 'sourceMember',
                                   'targetMember', 'filterMembers', 'mode',
                                   'provenancePolicy'}
            or definition['provenancePolicy'] != 'copy_source_lineage'):
        raise ValueError('PLANNING_POLICY_SEED_LOWERING_INVALID')
    return {'languageVersion': 2,
            'function': 'facts.planning.scenario.copy.prepare',
            'arguments': {
                'scenarioDimension': definition['scenarioDimension'],
                'sourceMember': definition['sourceMember'],
                'targetMember': definition['targetMember'],
                'filterMembers': dict(definition['filterMembers']),
                'mode': definition['mode'],
                'expectedMetadataRevision': bound['metadataRevision'],
                'expectedDataRevision': expected_data_revision,
                'idempotencyKey': idempotency_key}}
