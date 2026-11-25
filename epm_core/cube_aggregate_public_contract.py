"""Shared public wire shapes for the durable aggregate query lifecycle."""
from .cube_aggregate_lifecycle import (
    AMOUNT_MEASURE_REQUIRED, AUTHORIZATION_REVOKED, MAX_GROUPS, MAX_PAGE_SIZE, MAX_RESULT_BYTES,
    RESULT_TTL_SECONDS, STALE_CONTEXT, AggregateQueryStatus, AggregateSourcePins,
)
from .generic_aggregate_contract import MEASURES
from .generic_placement import MAX_PLACEMENT_DEPTH, MAX_PLACEMENT_PATHS
from .metadata_read_contract import read_contract, read_example
from .postgres_numeric_catalog import obj


RAW = 'facts.cube.aggregate'
GENERIC = 'cube.aggregate'
LINEAGE = GENERIC + '.lineage.read'
FUNCTIONS = frozenset(prefix + '.' + operation for prefix in (RAW, GENERIC)
                      for operation in ('request', 'read', 'cancel')) | {LINEAGE}

ID = {'type': 'string', 'minLength': 1, 'maxLength': 200}
DIGEST = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
REVISION = {'type': 'integer', 'minimum': 0}
CURSOR = {'type': 'string', 'minLength': 1}


def bounded(maximum, *, minimum=1):
    return {'type': 'integer', 'minimum': minimum, 'maximum': maximum}


def axis_list(maximum, *, minimum=0):
    return {'type': 'array', 'items': ID, 'minItems': minimum, 'maxItems': maximum,
            'uniqueItems': True}


def mapping(values, **bounds):
    return {'type': 'object', 'propertyNames': ID, 'additionalProperties': values, **bounds}


def raw_query_schema():
    anchored = obj({'kind': {'enum': ['Children', 'Descendants', 'Leaves']},
                    'rootMemberId': ID, 'includeSelf': {'type': 'boolean'}, 'hierarchyId': ID},
                   ['kind', 'rootMemberId', 'includeSelf'])
    selectors = mapping({'oneOf': [obj({'kind': {'const': 'Members'},
                                        'memberIds': axis_list(500, minimum=1)}), anchored]},
                        maxProperties=16)
    measures = {'type': 'array', 'minItems': 1, 'maxItems': 4, 'uniqueItems': True,
                'items': obj({'kind': {'enum': ['SumAmount', 'CountPresent', 'MinAmount', 'MaxAmount']}})}
    # Preserve the existing expanded parser forms. Public clients can use
    # the owner operations for selection and hierarchy resolution directly.
    raw = ('unique_coordinate_sum', 'unique_coordinate_reduction')
    generic = ('generic_unique_member_sum', 'generic_unique_member_weighted_sum',
               'generic_placement_weighted_sum')
    hierarchy = ('hierarchy_unique_member_weighted_sum', 'hierarchy_placement_weighted_sum')
    pins = {'metadataRevision': {**REVISION, 'minimum': 1}, 'policyRevision': REVISION}
    generic_pins = {'selectionId': {**ID, 'minLength': 8}, 'resolutionDigest': DIGEST, **pins}
    hierarchy_pins = {'hierarchyId': ID, 'hierarchyStateToken': DIGEST,
                      'nodeDefinitionDigest': DIGEST, 'contributionDigest': DIGEST, **pins}
    fields = {'source': {'const': 'raw_numeric'}, 'missing': {'const': 'exclude'},
        'aggregation': {'enum': [*raw, *generic, *hierarchy]}, 'selectors': selectors,
        'grain': obj({'inputDimensions': axis_list(128, minimum=1), 'groupBy': axis_list(6),
                      'reduceDimensions': axis_list(128)}), 'measures': measures}
    expanded = {
        'genericPins': obj({**generic_pins, 'placementLineageDigest': DIGEST}, list(generic_pins)),
        'hierarchyPins': obj({**hierarchy_pins, 'placementLineageDigest': DIGEST}, list(hierarchy_pins)),
        'operatorWeights': mapping(mapping({'enum': [-1, 0, 1]})),
        'placementWeights': mapping(mapping(obj({'sumWeight': bounded(500, minimum=-500),
                                                   'countWeight': bounded(500, minimum=0)}))),
    }
    query = obj({**fields, **expanded}, list(fields))
    query['allOf'] = [
        {'if': {'properties': {'aggregation': {'enum': modes}}},
         'then': {'required': [name]}, 'else': {'not': {'required': [name]}}}
        for name, modes in (
            ('genericPins', list(generic)), ('hierarchyPins', list(hierarchy)),
            ('operatorWeights', [generic[1], hierarchy[0]]),
            ('placementWeights', [generic[2], hierarchy[1]]),
        )
    ]
    return query


def request_arguments(is_generic):
    limits = obj({'maxGroups': bounded(MAX_GROUPS), 'maxResultBytes': bounded(MAX_RESULT_BYTES),
                  'pageSize': bounded(MAX_PAGE_SIZE), 'ttlSeconds': bounded(RESULT_TTL_SECONDS)}, [])
    if not is_generic:
        return obj({'query': raw_query_schema(), 'limits': limits}, ['query'])
    fields = {'selectionId': {'type': 'string', 'minLength': 8, 'maxLength': 200},
        'groupBy': axis_list(6), 'reduceDimensions': axis_list(128),
        'measures': {'type': 'array', 'minItems': 1, 'maxItems': len(MEASURES), 'uniqueItems': True,
                     'items': {'enum': sorted(MEASURES)}},
        'membershipSemantics': {'enum': ['unique_member', 'placement']},
        'memberOperatorPolicy': {'const': 'configured'}, 'missing': {'const': 'exclude'}}
    arguments = obj({**fields, 'limits': {'anyOf': [limits, {'type': 'null'}]}}, list(fields))
    arguments['allOf'] = [{
        'if': {'properties': {'membershipSemantics': {'const': 'placement'}}},
        'then': {'properties': {'reduceDimensions': {'minItems': 1}}},
    }]
    return arguments


def technical_certificate_schema():
    return obj({'kind': {'const': 'technical-query-certificate'},
        'planDigest': DIGEST, 'backendProfile': ID,
        'sourcePins': obj(dict.fromkeys(AggregateSourcePins.__dataclass_fields__, REVISION)),
        'hierarchyDigest': DIGEST, 'resultDigest': DIGEST,
        'groupCount': bounded(MAX_GROUPS, minimum=0), 'resultBytes': bounded(MAX_RESULT_BYTES, minimum=0)})


def read_result():
    amount = {'type': ['string', 'null'], 'description': 'Exact decimal text or null for no amount.'}
    row = obj({'ordinal': bounded(MAX_GROUPS), 'members': mapping(ID),
               'sumAmount': amount, 'minAmount': amount, 'maxAmount': amount,
               'countPresent': {'type': 'string', 'pattern': r'^(0|[1-9][0-9]*)(?![\s\S])'}},
              ['ordinal', 'members'])
    return {'oneOf': [
        obj({'queryId': ID, 'status': {'enum': [s.value for s in AggregateQueryStatus
                                             if s not in (AggregateQueryStatus.SEALED,
                                                          AggregateQueryStatus.FAILED)]}}),
        obj({'queryId': ID, 'status': {'const': 'failed'},
             'errorCode': {'enum': [AMOUNT_MEASURE_REQUIRED, AUTHORIZATION_REVOKED, STALE_CONTEXT]}}, ['queryId', 'status']),
        obj({'queryId': ID, 'status': {'const': 'sealed'},
             'rows': {'type': 'array', 'maxItems': MAX_PAGE_SIZE, 'items': row},
             'nextCursor': {'anyOf': [CURSOR, {'type': 'null'}]},
             'technicalCertificate': technical_certificate_schema()}),
    ]}


def lineage_result():
    operator = {'enum': ['Add', 'Subtract', 'Ignore']}
    step = obj({'relationshipId': ID, 'parentMemberId': ID, 'childMemberId': ID,
                'effectiveOperator': operator})
    path = obj({'memberId': ID, 'steps': {'type': 'array', 'maxItems': MAX_PLACEMENT_DEPTH, 'items': step},
                'sumWeight': {'enum': [-1, 0, 1]}, 'countWeight': {'enum': [0, 1]}})
    weights = obj({'sumWeight': bounded(MAX_PLACEMENT_PATHS, minimum=-MAX_PLACEMENT_PATHS),
                   'countWeight': bounded(MAX_PLACEMENT_PATHS, minimum=0)})
    contribution = obj({'dimensionId': ID, 'format': {'const': 'openepm-placement-contributions-v1'},
        'rootMemberId': {'anyOf': [ID, {'type': 'null'}]},
        'selectorOperator': {'enum': ['children', 'descendants', 'leaves', 'composed']},
        'includeSelf': {'type': 'boolean'}, 'paths': {'type': 'array', 'maxItems': MAX_PLACEMENT_PATHS, 'items': path},
        'weights': mapping(weights), 'lineageDigest': DIGEST})
    generic = obj({'format': {'const': 'openepm-placement-lineage-v1'}, 'lineageDigest': DIGEST,
                   'dimensions': {'type': 'array', 'minItems': 1, 'maxItems': 128, 'items': contribution}})
    hierarchy = obj({'format': {'const': 'openepm-hierarchy-node-lineage-v1'}, 'lineageDigest': DIGEST,
        'sumWeights': mapping({'type': 'integer'}), 'countWeights': mapping({'type': 'integer', 'minimum': 0}),
        'placementPaths': {'type': 'array', 'items': obj({'memberId': ID,
            'path': {'type': 'array', 'items': ID}, 'weight': {'enum': [-1, 1]}})},
        'effectiveOperators': mapping(obj({'operator': operator, 'source': {'type': 'string'}}))})
    return obj({'queryId': ID, 'status': {'enum': [status.value for status in AggregateQueryStatus]},
                'lineageDigest': DIGEST, 'lineage': {'oneOf': [generic, hierarchy]}})


def aggregate_program_contract(function):
    if function not in FUNCTIONS:
        return None
    operation = function.rsplit('.', 1)[-1]
    is_generic = function.startswith(GENERIC + '.')
    query_reference = {'queryId': 'example-aggregate-query'}
    rules = ['Use the current application READ grant and original query owner for status, paging and cancellation.']
    if operation == 'request':
        arguments = request_arguments(is_generic)
        result = obj({'queryId': ID, 'status': {'const': 'ready'}, 'requestDigest': DIGEST,
                      'planDigest': DIGEST, 'expiresAt': REVISION})
        if is_generic:
            example = {'selectionId': 'example-sealed-selection', 'groupBy': ['Account'],
                       'reduceDimensions': ['Entity'], 'measures': ['count_present'],
                       'membershipSemantics': 'unique_member', 'memberOperatorPolicy': 'configured',
                       'missing': 'exclude'}
            binding = ('Use an ID returned by cube.selection.seal for this actor and application. '
                       'Use the exact axis IDs from that selection and choose one member on each fixed axis.')
        else:
            example = {'query': {'source': 'raw_numeric',
                'grain': {'inputDimensions': ['Account', 'Entity'], 'groupBy': ['Account', 'Entity'],
                          'reduceDimensions': []},
                'selectors': {'Account': {'kind': 'Members', 'memberIds': ['Hours']}},
                'measures': [{'kind': 'CountPresent'}], 'missing': 'exclude',
                'aggregation': 'unique_coordinate_sum'}}
            binding = ('Use all active fact-axis IDs from the authorized application, excluding a contextual Currency registry. '
                       'Select exactly one member on every axis outside groupBy and reduceDimensions. '
                       'Use cube.aggregate.request for role-neutral reduction through a sealed selection.')
        examples = [read_example(function, example, name='Request a bounded count of present observations', binding=binding)]
        rules.extend(['The worker computes asynchronously after the fixed core accepts the query. The request returns a query ID and expiry, with no business receipt.',
                      'Repeated submissions can create new queries. Keep the returned query ID and poll it before submitting again.'])
        recovery = ('Rediscover the current axes and members after a layout mismatch. For a stale generic selection, '
                    'review the current selection and seal it again before starting another query.')
    elif function == LINEAGE:
        arguments = obj({'queryId': ID})
        result = lineage_result()
        examples = [read_example(function, query_reference, name='Read one placement contribution record',
            binding='Use a query ID returned for placement membership in this application as the original actor.')]
        rules = ['The fixed core checks the original query owner, current dimensional scope and the pinned metadata and policy revisions.',
                 'A recorded contribution path describes the plan. Use the matching aggregate status read to establish whether execution sealed.']
        recovery = 'If authority or the source context changed, rediscover the permitted selection and create a new query.'
    elif operation == 'read':
        arguments = obj({'queryId': ID, 'cursor': CURSOR, 'pageSize': bounded(MAX_PAGE_SIZE)}, ['queryId'])
        result = read_result()
        examples = [read_example(function, query_reference, name='Inspect one accepted aggregate query',
            binding='Use the queryId returned by the matching aggregate request in this application.'),
            read_example(function, {**query_reference, 'cursor': 'example-signed-cursor'},
                name='Continue from the last sealed page',
                binding='Replace both fixture strings with the original queryId and the exact non-null nextCursor.')]
        rules.extend(['Only a sealed page contains rows and a technical query certificate. A null nextCursor ends the result.',
                      'A failed result with CUBE_AGGREGATE_STALE_CONTEXT could not seal under its original metadata, security or policy context. Review the current scope before requesting a new result.',
                      'CUBE_AGGREGATE_AUTHORIZATION_REVOKED records that the query lost its admitted access before sealing. Read the original status under current access before starting a replacement query.',
                      'Keep the page size bound by the first page. Each page rechecks the current scope and source revisions.',
                      'Count present is exact integer text and includes present zero. An empty amount reduction can return null.'])
        recovery = (f'For {AMOUNT_MEASURE_REQUIRED}, count present observations or use an authored expression '
                    'to divide total quantity by the declared denominator. For stale or expired results, '
                    'review the current inputs and start a fresh query.')
    else:
        arguments = obj({'queryId': ID})
        result = obj({'queryId': ID, 'status': {'enum': ['cancel_requested', 'cancelled']}})
        examples = [read_example(function, query_reference, name='Request cancellation of an aggregate query',
            binding='Use the queryId returned by the matching aggregate request in this application.')]
        rules.append('Cancellation changes technical query state. A cancel_requested response still requires polling.')
        recovery = 'If cancellation is unavailable, read the original query status to determine its current outcome.'
    owner = 'PostgresCubeAggregateRepository' if function == LINEAGE else 'CubeAggregateService'
    contract = read_contract(function, arguments, result, owner=owner,
                             examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = recovery
    return contract
