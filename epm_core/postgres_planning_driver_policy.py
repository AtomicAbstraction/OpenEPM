"""Private reusable Driver-policy adapter over exact relational expressions."""
from __future__ import annotations

from dataclasses import dataclass

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_expression import compile_expression_program, compiler_for
from .planning_operation_policy import FORMAT_V2

UPSTREAM_LINEAGE_MAX_BYTES = 65536
UPSTREAM_LINEAGE_MAX_DEPTH = 8


@dataclass(frozen=True, slots=True)
class DriverPolicyPlan:
    program: dict
    driver_policy: dict
    compiler_version: str
    plan_digest: str


def _mapping(value, label):
    if (not isinstance(value, dict) or not 1 <= len(value) <= 128
            or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                   or not isinstance(member, str) or not 1 <= len(member) <= 200
                   for axis, member in value.items())):
        raise ValueError(f'DRIVER_POLICY_{label}_INVALID')
    return dict(sorted(value.items()))


def compile_driver_policy_program(bound: object, execution: object,
                                  *, expected_publication_revision: int = 0,
                                  published_pointer: dict | None = None,
                                  resolved_dependency: dict | None = None,
                                  ) -> DriverPolicyPlan:
    fields = {'policyId', 'version', 'policyDigest', 'kind',
              'metadataRevision', 'policyRevision', 'effectiveOn',
              'bindings', 'definition'}
    v2=(isinstance(bound,dict) and bound.get('policyFormat')==FORMAT_V2)
    if v2:fields.add('policyFormat')
    execution_fields={'inputMemberMappings','outputMemberMapping','activeGrain',
                      'measureDimensionId','resultKey'}
    if v2:execution_fields.add('publishedInputBindings')
    if (not isinstance(bound, dict) or set(bound) != fields
            or bound.get('kind') != 'Driver'
            or type(expected_publication_revision) is not int
            or expected_publication_revision < 0
            or not isinstance(execution, dict)
            or set(execution) != execution_fields):
        raise ValueError('DRIVER_POLICY_EXECUTION_INVALID')
    definition = bound['definition']
    inputs = definition['inputs']
    mappings = execution['inputMemberMappings']
    if (not isinstance(mappings, dict)
            or set(mappings) != {item['name'] for item in inputs}):
        raise ValueError('DRIVER_POLICY_INPUT_MAPPING_INVALID')
    normalized = {name: _mapping(value, 'INPUT_MAPPING')
                  for name, value in sorted(mappings.items())}
    by_name = {item['name']: item for item in inputs}
    for name, mapping in normalized.items():
        if set(mapping.values()) != set(by_name[name]['members']['memberIds']):
            raise ValueError('DRIVER_POLICY_INPUT_MEMBERS_MISMATCH')
    output = _mapping(execution['outputMemberMapping'], 'OUTPUT_MAPPING')
    if set(output.values()) != set(definition['output']['members']['memberIds']):
        raise ValueError('DRIVER_POLICY_OUTPUT_MEMBERS_MISMATCH')
    grain = execution['activeGrain']
    if (not isinstance(grain, list) or len(grain) != len(set(grain))
            or sorted(grain) != definition['output']['grain']):
        raise ValueError('DRIVER_POLICY_GRAIN_MISMATCH')
    measure_axis = execution['measureDimensionId']
    if (not isinstance(measure_axis, str) or not measure_axis
            or any(measure_axis not in mapping for mapping in normalized.values())
            or measure_axis not in output
            or not set(output) <= set(next(iter(normalized.values())))):
        raise ValueError('DRIVER_POLICY_MEASURE_MAPPING_INVALID')
    kind = definition['calculationKind']
    amount_inputs = [item for item in inputs if item['unit'] == 'Amount']
    ratio_inputs = [item for item in inputs if item['unit'] == 'Ratio']
    if kind == 'Copy' and not v2 and len(amount_inputs) == 1 and not ratio_inputs:
        anchor = amount_inputs[0]
        expression = {'op': 'SourceValue',
                      'memberOverrides': normalized[anchor['name']],
                      'measureDimensionId': measure_axis,
                      'valueType': 'amount'}
    elif (kind == 'MultiplyAmountByRatio' and not v2 and len(amount_inputs) == 1
          and len(ratio_inputs) == 1):
        anchor = amount_inputs[0]
        expression = {'op': 'Multiply',
            'left': {'op': 'SourceValue',
                     'memberOverrides': normalized[anchor['name']],
                     'measureDimensionId': measure_axis,
                     'valueType': 'amount'},
            'right': {'op': 'SourceValue',
                      'memberOverrides': normalized[ratio_inputs[0]['name']],
                      'measureDimensionId': measure_axis,
                      'valueType': 'ratio'}}
    elif (kind == 'MultiplyPublishedAmountByRatio' and v2
          and len(amount_inputs) == 1 and len(ratio_inputs) == 1):
        published=amount_inputs[0];raw=ratio_inputs[0]
        if (published.get('sourceKind')!='PublishedAmount'
                or raw.get('sourceKind')!='Raw'):
            raise ValueError('DRIVER_POLICY_TRANSFORM_UNSUPPORTED')
        bindings=execution['publishedInputBindings']
        if (not isinstance(bindings,dict) or set(bindings)!={published['name']}
                or not isinstance(bindings[published['name']],dict)
                or set(bindings[published['name']])!={
                    'resultKey','generationId','publishedRevision'}):
            raise ValueError('DRIVER_POLICY_PUBLISHED_INPUT_INVALID')
        binding=bindings[published['name']]
        if (not isinstance(resolved_dependency,dict)
                or set(resolved_dependency)!={
                    'inputName','resultKey','generationId',
                    'publishedRevision','jobId'}
                or resolved_dependency['inputName']!=published['name']
                or any(resolved_dependency[name]!=binding[name]
                       for name in ('resultKey','generationId',
                                    'publishedRevision'))):
            raise ValueError('DRIVER_POLICY_PUBLISHED_INPUT_STALE')
        anchor=raw
        expression={'op':'Multiply',
            'left':{'op':'PublishedAmount','resultKey':binding['resultKey'],
                    'memberOverrides':normalized[published['name']]},
            'right':{'op':'SourceValue',
                     'memberOverrides':normalized[raw['name']],
                     'measureDimensionId':measure_axis,
                     'valueType':'ratio'}}
    else:
        raise ValueError('DRIVER_POLICY_TRANSFORM_UNSUPPORTED')
    if (not isinstance(execution['resultKey'], str)
            or not execution['resultKey']):
        raise ValueError('DRIVER_POLICY_RESULT_KEY_INVALID')
    policy_pin = {key: bound[key] for key in (
        'policyId', 'version', 'policyDigest', 'metadataRevision',
        'policyRevision')}
    if v2:
        if execution['resultKey']==resolved_dependency['resultKey']:
            raise ValueError('DRIVER_POLICY_DEPENDENCY_CYCLE')
        policy_pin.update({'policyFormat':FORMAT_V2,
            'publishedDependency':resolved_dependency,'maxCells':500,
            'upstreamLineageBudget':{
                'maxCanonicalBytes':UPSTREAM_LINEAGE_MAX_BYTES,
                'maxDepth':UPSTREAM_LINEAGE_MAX_DEPTH}})
    if published_pointer is not None:
        if (not isinstance(published_pointer, dict)
                or set(published_pointer) != {
                    'authoredMetadataRevision', 'authoredPolicyRevision',
                    'pointerVersion', 'stateRevision'}
                or any(type(value) is not int or value < 0
                       for value in published_pointer.values())):
            raise ValueError('DRIVER_POLICY_PUBLISHED_POINTER_INVALID')
        policy_pin.update(published_pointer)
    program = {'languageVersion': 2, 'function': 'facts.expression.calculate',
               'arguments': {'sourceMembers': normalized[anchor['name']],
                             'expression': expression,
                             'targetMembers': output,
                             'resultKey': execution['resultKey']}}
    plan = compile_expression_program(
        program, expected_publication_revision=expected_publication_revision,
        driver_policy=policy_pin)
    compiler, digest = compiler_for(plan)
    return DriverPolicyPlan(program, policy_pin, compiler, digest)


class PostgresPlanningDriverPolicy:
    """Private preview/admission facade; the existing worker owns publication."""
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        # The V2 registry exposes a public adapter built on this compiler, so
        # defer the registry import until an instance is constructed.
        from .postgres_language_v2 import PostgresLanguageV2
        self.language = PostgresLanguageV2(
            dsn, identity=identity, preview_secret=preview_secret)

    def preview(self, scope: ApplicationScope, bound: object,
                execution: object) -> dict:
        compiled = compile_driver_policy_program(bound, execution)
        result = self.language._preview_expression(
            scope, compiled.program, driver_policy=compiled.driver_policy)
        revisions = result['revisionVector']
        if (revisions['metadata_revision'] != compiled.driver_policy[
                'metadataRevision'] or revisions['policy_revision'] !=
                compiled.driver_policy['policyRevision']):
            raise ValueError('DRIVER_POLICY_STALE_PINS')
        return {**result, 'driverPolicy': compiled.driver_policy,
                'compilerVersion': compiled.compiler_version,
                'planDigest': compiled.plan_digest}

    def submit(self, scope: ApplicationScope, bound: object,
               execution: object, *, preview_token: str,
               idempotency_key: str,
               depends_on_job_ids: tuple[str, ...] = ()) -> dict:
        compiled = compile_driver_policy_program(bound, execution)
        return self.language._submit_expression(
            scope, compiled.program, preview_token=preview_token,
            idempotency_key=idempotency_key,
            depends_on_job_ids=depends_on_job_ids,
            driver_policy=compiled.driver_policy)
