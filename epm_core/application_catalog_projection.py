"""One semantic discovery projection for authorized application adapters.

Callers resolve current identity, permissions and state in their own authenticated
transaction. This module never grants execution authority. Paging is over that
fresh authorized projection; a continuation cannot retain an earlier grant.
"""
from __future__ import annotations

from copy import deepcopy
import re

from openepm.public_diagnostics import (
    CATALOG_CONTINUATION_INVALID, CATALOG_CONTINUATION_STALE, CATALOG_DISCOVERY_CODES,
    CATALOG_QUERY_INVALID, catalog_diagnostic)

from .postgres_capability_contract import (
    FUNCTION_REGISTRY_FORMAT, filter_catalog, function_registry_digest)
from .postgres_processing_limits import policy as processing_policy
from .application_authorization_actions import action_allows_operation
from .processing_operation_registry import (
    PROCESSING_REGISTRY_FORMAT, operation_contracts, processing_registry_digest)

_DIGEST = re.compile(r'[0-9a-f]{64}')
_FIRST_READ = {'languageVersion': 2, 'function': 'application.state.read', 'arguments': {}}


class CatalogDiscoveryError(ValueError):
    def __init__(self, code: str, path: str):
        self.diagnostics = catalog_diagnostic(code, path)
        super().__init__(code)


def _query_text(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 200


def with_example_use(name: str, specification: dict) -> dict:
    """Classify all examples of a public function without changing their programs."""
    examples = specification.get('programContract', {}).get('examples')
    if not examples:
        return specification
    if specification.get('availability', {}).get('status') == 'unsupported':
        use = 'diagnostic-only'
    elif (name == _FIRST_READ['function'] and specification.get('mode') == 'read_only'
          and len(examples) == 1 and examples[0].get('program') == _FIRST_READ):
        use = 'authorized-read'
    else:
        use = 'fixture-only'
    return {**specification, 'exampleUse': use}


def application_functions(catalog: dict, *, security_functions: dict,
                          enabled, allowed: set[str], authorization_actions=None) -> dict:
    """Select semantic contracts; static references pass explicit full permissions."""
    functions = filter_catalog(catalog, enabled)['functions']
    functions.update(deepcopy(security_functions))
    if authorization_actions is not None:
        from .source_staging_status import numeric_import_spec
        return {name: with_example_use(name, numeric_import_spec(name, spec)) for name, spec in functions.items()
                if action_allows_operation(authorization_actions, name)}
    return {name: with_example_use(name, spec) for name, spec in functions.items()
            if spec['permission'] in allowed}


def application_catalog(catalog: dict, *, security_functions: dict,
                        enabled, allowed: set[str], scope, state: dict,
                        channel='mcp') -> dict:
    """Project the same business contract before channel-specific decoration."""
    functions = application_functions(catalog, security_functions=security_functions,
                                      enabled=enabled, allowed=allowed,
                                      authorization_actions=state.get('authorization_actions'))
    # Previously admitted owner work can still be recalled when a planning policy pauses new submissions.
    owns_numeric_jobs = 'authorization_actions' in state and 'facts.numeric.batch' in functions
    if state.get('group_workflow_role_unbound'):
        # Recall and cancel remain available for previously staged input.
        # Exact published receipts retain their original recovery route.
        from .application_authorization_actions import GROUP_SOURCE_IMPORT_FUNCTIONS
        gated = (GROUP_SOURCE_IMPORT_FUNCTIONS - {'facts.source.cancel','facts.source.staging.read'}
                 | {'facts.numeric.batch','python.program.test','python.program.activate','application.rule.run'})
        functions = {name: spec for name, spec in functions.items() if name not in gated}
    contracts = operation_contracts(functions, scope='application')
    digest = function_registry_digest(functions)
    return {'languageVersion': 2,
            'registryFormat': FUNCTION_REGISTRY_FORMAT,
            'registryDigest': digest,
            'semanticRegistryDigest': digest,
            'processingRegistryFormat': PROCESSING_REGISTRY_FORMAT,
            'processingRegistryDigest': processing_registry_digest(contracts),
            'operationContracts': contracts,
            'processingPolicy': processing_policy(channel=channel),
            'listener': {'scope': 'application',
                         'workspaceId': scope.workspace_id,
                         'applicationId': scope.application_id},
            'enabledCapabilities': sorted(enabled),
            'capabilityRevision': state['capability_revision'],
            'securityRevision': state['security_revision'],
            **({'ownedJobOperations': ['read','events','cancel']}
               if owns_numeric_jobs else {}),
            **({'accessContext': state['access_context']} if 'access_context' in state else {}),
            'functions': functions}


def discover_catalog(catalog: dict, discovery: dict | None = None) -> dict:
    """Return summary, bounded contracts or the explicit complete enumeration.

    The continuation is a checked seek reference, not an authority token. Its
    scope, query, current visible contracts, effective access and revisions
    must match on every page. A missing or inaccessible exact function has the
    same empty response. No hidden-function counts or suggestions are emitted.
    """
    query = {} if discovery is None else discovery
    if (not isinstance(query, dict)
            or set(query) - {'view', 'family', 'function', 'limit', 'after'}):
        raise CatalogDiscoveryError(CATALOG_QUERY_INVALID, '$.discovery')
    view = query.get('view', 'full')
    family, function = query.get('family'), query.get('function')
    limit, after = query.get('limit', 50), query.get('after')
    if view not in ('full', 'summary', 'functions'):
        raise CatalogDiscoveryError(CATALOG_QUERY_INVALID, '$.discovery.view')
    if view != 'functions' and set(query) - {'view'}:
        raise CatalogDiscoveryError(CATALOG_QUERY_INVALID, '$.discovery')
    if type(limit) is not int or not 1 <= limit <= 100:
        raise CatalogDiscoveryError(CATALOG_QUERY_INVALID, '$.discovery.limit')
    for field, value in (('family', family), ('function', function)):
        if value is not None and not _query_text(value):
            raise CatalogDiscoveryError(CATALOG_QUERY_INVALID, '$.discovery.' + field)
    contracts = catalog['operationContracts']
    functions = catalog['functions']
    families = {}
    for name in sorted(functions):
        contract = contracts[name]
        key = contract['family']
        if key not in families:
            families[key] = {'family': key,
                             'purpose': contract['productPurpose'], 'count': 0}
        families[key]['count'] += 1
    binding = {'format': 'openepm-catalog-page-v1',
               'workspaceId': catalog['listener']['workspaceId'],
               'applicationId': catalog['listener']['applicationId'],
               'semanticRegistryDigest': catalog['semanticRegistryDigest'],
               'registryDigest': catalog['registryDigest'],
               'securityRevision': catalog['securityRevision'],
               'capabilityRevision': catalog['capabilityRevision'],
               'family': family, 'function': function}
    if 'accessContext' in catalog:
        binding['accessContext'] = catalog['accessContext']
    names = sorted(name for name in functions
                   if (family is None or contracts[name]['family'] == family)
                   and (function is None or name == function))
    total = len(names)
    if after is not None:
        if (not isinstance(after, dict)
                or set(after) - {'accessContext'} != (set(binding) - {'accessContext'}) | {'last'}
                or not _query_text(after['last'])
                or any(type(after[key]) is not int or after[key] < 0
                       for key in ('securityRevision', 'capabilityRevision'))
                or any(not isinstance(after[key], str) or not after[key]
                       for key in ('format', 'workspaceId', 'applicationId'))
                or any(not isinstance(after[key], str) or not _DIGEST.fullmatch(after[key])
                       for key in ('semanticRegistryDigest', 'registryDigest'))
                or ('accessContext' in after and (not isinstance(after['accessContext'], str)
                    or not _DIGEST.fullmatch(after['accessContext'])))
                or any(after[key] is not None and not _query_text(after[key])
                       for key in ('family', 'function'))):
            raise CatalogDiscoveryError(CATALOG_CONTINUATION_INVALID, '$.discovery.after')
        if (after.get('accessContext') != binding.get('accessContext')
                or any(after.get(key) != value for key, value in binding.items())):
            raise CatalogDiscoveryError(CATALOG_CONTINUATION_STALE, '$.discovery.after')
        if after['last'] not in names:
            raise CatalogDiscoveryError(CATALOG_CONTINUATION_INVALID, '$.discovery.after')
        names = [name for name in names if name > after['last']]
    has_more = view == 'functions' and len(names) > limit
    selected = ([] if view == 'summary' else
                names[:limit] if view == 'functions' else names)
    result = {**catalog,
              'functions': {name: functions[name] for name in selected},
              'operationContracts': {name: contracts[name] for name in selected}}
    # Existing digest consumers can verify the exact returned projection.
    result['registryDigest'] = function_registry_digest(result['functions'])
    result['processingRegistryDigest'] = processing_registry_digest(
        result['operationContracts'])
    result['discovery'] = {
        'format': 'openepm-catalog-discovery-v1', 'view': view,
        'catalogRegistryDigest': catalog['registryDigest'],
        'families': [families[key] for key in sorted(families)],
        'matchingFunctionCount': total, 'returnedFunctionCount': len(selected),
        'contractsComplete': view != 'summary' and not has_more and after is None,
        'hasMore': has_more,
        'next': {**binding, 'last': selected[-1]} if has_more else None,
        'firstRead': ({'workspaceId': binding['workspaceId'],
                       'applicationId': binding['applicationId'],
                       'program': deepcopy(_FIRST_READ)}
                      if _FIRST_READ['function'] in functions else None)}
    return result
