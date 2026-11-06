"""Executable entrypoint for one isolated, capability-bound plan build."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import sys
from urllib.request import Request, urlopen

from .model import Application, BuildContext, Program

MAX_INPUT = 8192
MAX_RESPONSE = 2 * 1024 * 1024
MAX_LOG = 1024 * 1024


def _read_limited(stream, maximum: int) -> bytes:
    value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError('BUILDER_INPUT_LIMIT')
    return value


def _read_launch_request(stream) -> bytes:
    """Read one bounded frame without waiting for container stdin EOF."""
    value = stream.readline(MAX_INPUT + 1)
    if len(value) > MAX_INPUT or not value.endswith(b'\n'):
        raise ValueError('BUILDER_INPUT_LIMIT')
    return value


def _broker(request: dict, action: str) -> dict:
    payload = json.dumps({
        'workspaceId': request['workspaceId'],
        'applicationId': request['applicationId'],
        'buildId': request['buildId'],
        'claimGeneration': request['claimGeneration'],
        'action': action,
        'capabilityToken': request['capabilityToken']},
        sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    call = Request(request['brokerUrl'], data=payload, method='POST',
        headers={'content-type': 'application/json', 'cache-control': 'no-store'})
    with urlopen(call, timeout=10) as response:
        if response.status != 200:
            raise ValueError('BUILDER_BROKER_DENIED')
        raw = _read_limited(response, MAX_RESPONSE)
    value = json.loads(raw)
    if type(value) is not dict:
        raise ValueError('BUILDER_BROKER_RESPONSE_INVALID')
    return value


def execute(request: dict) -> dict:
    required = {'workspaceId', 'applicationId', 'buildId', 'claimGeneration',
                'capabilityToken', 'brokerUrl'}
    if (type(request) is not dict or set(request) != required
            or type(request['claimGeneration']) is not int
            or request['claimGeneration'] < 1):
        raise ValueError('BUILDER_REQUEST_INVALID')
    source = _broker(request, 'python.build.source.read')
    context = _broker(request, 'python.build.context.read')
    if (set(source) != {'sourceText', 'entryPoint'}
            or type(source['sourceText']) is not str
            or type(source['entryPoint']) is not str
            or set(context) != {'parameterValues', 'buildContext'}
            or type(context['parameterValues']) is not dict
            or type(context['buildContext']) is not dict):
        raise ValueError('BUILDER_BROKER_RESPONSE_INVALID')
    raw_context = context['buildContext']
    if set(raw_context) != {'workspaceId', 'applicationId', 'metadataRevision',
                            'policyRevision', 'schemaEpoch', 'references'}:
        raise ValueError('BUILDER_CONTEXT_INVALID')
    build_context = BuildContext(Application(raw_context['workspaceId'],
        raw_context['applicationId']), raw_context['metadataRevision'],
        raw_context['policyRevision'], raw_context['schemaEpoch'],
        raw_context['references'])
    namespace = {'__name__': '__openepm_program__', '__builtins__': __builtins__}
    log = StringIO()
    with redirect_stdout(log), redirect_stderr(log):
        code = compile(source['sourceText'], '<openepm-program>', 'exec',
                       dont_inherit=True, optimize=0)
        exec(code, namespace, namespace)
        builder = namespace.get(source['entryPoint'])
        if not callable(builder):
            raise ValueError('BUILDER_ENTRY_POINT_INVALID')
        plan = builder(build_context, context['parameterValues'])
    if not isinstance(plan, Program):
        raise ValueError('BUILDER_RESULT_INVALID')
    build_log = log.getvalue()
    if len(build_log.encode('utf-8')) > MAX_LOG:
        raise ValueError('BUILDER_LOG_LIMIT')
    return {'plan': plan.to_wire(), 'sourceMap': {}, 'buildLog': build_log}


def main() -> None:
    try:
        request = json.loads(_read_launch_request(sys.stdin.buffer))
        output = execute(request)
        sys.stdout.write(json.dumps(output, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True))
    except Exception:
        # Never echo source, parameters, capability tokens or exception text.
        sys.stderr.write('OPEN_EPM_BUILDER_FAILED\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
