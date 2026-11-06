"""Fail-closed adapters from bound reusable policies to legacy V2 operations."""
from __future__ import annotations

from dataclasses import dataclass
import re

from .planning_operation_policy import lower_bound_seed_to_legacy_v2
from .postgres_planning_allocation import compile_allocation_program
from .postgres_planning_rollup import compile_rollup_program
from .postgres_planning_spread import compile_spread_program


@dataclass(frozen=True, slots=True)
class LoweredPlanningOperation:
    policy_id: str
    policy_version: int
    policy_digest: str
    metadata_revision: int
    policy_revision: int
    program: dict
    compiler_arguments: dict


def _integer(value, label, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f'PLANNING_POLICY_LOWERING_{label}_INVALID')
    return value


def _key(value):
    if not isinstance(value, str):
        raise ValueError('PLANNING_POLICY_LOWERING_RESULT_KEY_INVALID')
    return value


def _coordinate(value, label):
    if (not isinstance(value, dict) or not 1 <= len(value) <= 32
            or any(not isinstance(axis, str) or not axis
                   or not isinstance(member, str) or not member
                   for axis, member in value.items())):
        raise ValueError(f'PLANNING_POLICY_LOWERING_{label}_INVALID')
    return dict(sorted(value.items()))


def _bound(bound, kind):
    required = {'policyId', 'version', 'policyDigest', 'kind',
                'metadataRevision', 'policyRevision', 'effectiveOn',
                'bindings', 'definition'}
    if (not isinstance(bound, dict) or set(bound) not in (
            required,required|{'policyFormat'})
            or ('policyFormat' in bound and
                bound['policyFormat']!='openepm-planning-operation-policy-v2')
            or bound.get('kind') != kind
            or not isinstance(bound.get('policyId'), str)
            or not bound['policyId']
            or type(bound.get('version')) is not int or bound['version'] < 1
            or not isinstance(bound.get('policyDigest'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', bound['policyDigest'])):
        raise ValueError('PLANNING_POLICY_LOWERING_BOUND_POLICY_INVALID')
    _integer(bound['metadataRevision'], 'METADATA_REVISION')
    _integer(bound['policyRevision'], 'POLICY_REVISION')
    return bound['definition']


def _result(bound, program, compiler_arguments):
    return LoweredPlanningOperation(
        bound['policyId'], bound['version'], bound['policyDigest'],
        bound['metadataRevision'], bound['policyRevision'], program,
        dict(compiler_arguments))


def lower_bound_policy_to_legacy_v2(bound: object, execution: object
                                    ) -> LoweredPlanningOperation:
    """Lower only semantics the existing operation can represent exactly.

    Execution supplies runtime coordinates and publication pins. Every coordinate
    member must equal the explicit policy member set; it is never an expansion or
    implicit default-member mechanism.
    """
    if not isinstance(bound, dict) or not isinstance(execution, dict):
        raise ValueError('PLANNING_POLICY_LOWERING_INPUT_INVALID')
    kind = bound.get('kind')
    if kind == 'Seed':
        if set(execution) != {'expectedDataRevision', 'idempotencyKey'}:
            raise ValueError('PLANNING_POLICY_LOWERING_EXECUTION_INVALID')
        program = lower_bound_seed_to_legacy_v2(
            bound, expected_data_revision=execution['expectedDataRevision'],
            idempotency_key=execution['idempotencyKey'])
        return _result(bound, program, {})
    if kind == 'Driver':
        _bound(bound, 'Driver')
        # Current driver policies are Copy or Amount*Ratio; the legacy group
        # operator is exact SUM, so substituting it would change semantics.
        raise ValueError('PLANNING_POLICY_DRIVER_LEGACY_UNSUPPORTED')
    if kind == 'Rollup':
        definition = _bound(bound, 'Rollup')
        if set(execution) != {'otherMembers', 'resultKey', 'hierarchyVersion',
                              'expectedPublicationRevision'}:
            raise ValueError('PLANNING_POLICY_LOWERING_EXECUTION_INVALID')
        if definition['sharedMemberPolicy'] not in (
                'unique_member','placement_explicit'):
            raise ValueError('PLANNING_POLICY_ROLLUP_PLACEMENT_UNSUPPORTED')
        others = _coordinate(execution['otherMembers'], 'OTHER_MEMBERS')
        if (set(others.values()) != set(definition['slice']['memberIds'])
                or definition['dimension'] in others):
            raise ValueError('PLANNING_POLICY_ROLLUP_SLICE_MISMATCH')
        hierarchy = _integer(execution['hierarchyVersion'],
                             'HIERARCHY_VERSION', minimum=1)
        publication = _integer(execution['expectedPublicationRevision'],
                               'PUBLICATION_REVISION')
        program = {'languageVersion': 2,
                   'function': 'facts.planning.rollup.sum',
                   'arguments': {'dimension': definition['dimension'],
                                 'parent': definition['parent'],
                                 'otherMembers': others,
                                 'resultKey': _key(execution['resultKey']),
                                 **({'placementIds':definition['placementIds']}
                                    if definition['sharedMemberPolicy']==
                                       'placement_explicit' else {})}}
        compile_rollup_program(program, hierarchy_version=hierarchy,
                               expected_publication_revision=publication)
        return _result(bound, program, {
            'hierarchy_version': hierarchy,
            'expected_publication_revision': publication})
    if kind == 'Spread':
        definition = _bound(bound, 'Spread')
        if set(execution) != {'source', 'resultKey',
                              'expectedPublicationRevision'}:
            raise ValueError('PLANNING_POLICY_LOWERING_EXECUTION_INVALID')
        if definition['calendarPolicy'] != 'selection_order':
            raise ValueError('PLANNING_POLICY_SPREAD_CALENDAR_UNSUPPORTED')
        source = _coordinate(execution['source'], 'SOURCE')
        if set(source.values()) != set(definition['sourceMembers']['memberIds']):
            raise ValueError('PLANNING_POLICY_SPREAD_SOURCE_MISMATCH')
        publication = _integer(execution['expectedPublicationRevision'],
                               'PUBLICATION_REVISION')
        program = {'languageVersion': 2,
                   'function': 'facts.planning.spread.equal',
                   'arguments': {'source': source,
                                 'targetDimension': definition['targetDimension'],
                                 'targetMembers': definition['targetMembers']['memberIds'],
                                 'resultKey': _key(execution['resultKey'])}}
        compile_spread_program(program,
                               expected_publication_revision=publication)
        return _result(bound, program, {
            'expected_publication_revision': publication})
    if kind == 'Allocation':
        definition = _bound(bound, 'Allocation')
        v2=bound.get('policyFormat')=='openepm-planning-operation-policy-v2'
        expected={'source','basisTemplate','resultKey','expectedPublicationRevision'}
        if v2:expected.add('basisPublishedInput')
        if set(execution) != expected:
            raise ValueError('PLANNING_POLICY_LOWERING_EXECUTION_INVALID')
        source = _coordinate(execution['source'], 'SOURCE')
        basis = _coordinate(execution['basisTemplate'], 'BASIS')
        if (set(source.values()) != set(definition['sourceMembers']['memberIds'])
                or set(basis.values()) != set(definition['basisMembers']['memberIds'])):
            raise ValueError('PLANNING_POLICY_ALLOCATION_MEMBERS_MISMATCH')
        publication = _integer(execution['expectedPublicationRevision'],
                               'PUBLICATION_REVISION')
        program = {'languageVersion': 2,
                   'function': 'facts.planning.allocate.weighted',
                   'arguments': {'source': source, 'basisTemplate': basis,
                                 'targetDimension': definition['targetDimension'],
                                 'targetMembers': definition['targetMembers']['memberIds'],
                                 'resultKey': _key(execution['resultKey']),
                                 'conservationScope': definition['conservationScope'],
                                 'roundingPolicy': definition['remainderPolicy']}}
        if v2:
            program['arguments']['publishedRatioBasis']=execution['basisPublishedInput']
        compile_allocation_program(program,
                                   expected_publication_revision=publication)
        return _result(bound, program, {
            'expected_publication_revision': publication})
    raise ValueError('PLANNING_POLICY_LOWERING_KIND_INVALID')
