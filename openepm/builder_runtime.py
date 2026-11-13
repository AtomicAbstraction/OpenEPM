"""Executable entrypoint for one isolated, capability-bound plan build."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import sys
from urllib.request import Request, urlopen

from .model import Application, BuildContext, Program
from .diagnostics import Diagnostic, SourceValidationError, diagnostic_payload
from .source_validation import validate_python_source
from .source_mapping import capture_source, program_source_map, FILENAME
from .authoring import MetadataAuthoringError
from .metadata_references import BOOTSTRAP_CONTRACT_DIGEST

MAX_INPUT = 8192
MAX_RESPONSE = 2 * 1024 * 1024
MAX_LOG = 1024 * 1024


def _metadata_failure(error: Exception):
    """Only fixed SDK classifications may specialize a build diagnostic.

    Caller names, candidate matches and arbitrary exception messages never
    cross this boundary. A missing name and a denied name have one response.
    """
    if type(error) is not MetadataAuthoringError:
        return None
    if type(error.code) is not str or type(error.kind) is not str:
        return None
    if error.kind in ("dimension", "member"):
        kind = error.kind
        options = {
            "METADATA_NAME_REQUIRED": (
                f"A nonempty {kind} name or ID is required.",
                f"Supply the {kind}'s exact name or stable ID from the application metadata."),
            "METADATA_NAME_UNAVAILABLE": (
                f"The {kind} is unavailable in the authorized metadata snapshot.",
                f"Check the {kind} name or ID and your access, then refresh metadata and save again."),
            "METADATA_NAME_AMBIGUOUS": (
                f"The {kind} name matches more than one authorized object.",
                f"Use the intended {kind}'s unique stable ID from the application metadata."),
        }
        if error.code in options:
            return error.code, *options[error.code]
    if (error.code, error.kind) == ("METADATA_HIERARCHY_UNAVAILABLE", "hierarchy"):
        return (error.code, "A hierarchy built for the current metadata revision is unavailable.",
                "Build the dimension hierarchy at the current metadata revision, then save again.")
    if (error.code, error.kind) == ("AUTHORING_METADATA_CONTEXT_UNAVAILABLE", "context"):
        return (error.code, "The authorized application metadata snapshot is unavailable or stale.",
                "Refresh the application metadata and start a new validation build.")
    return None


def _source_failure(error: Exception, source_digest: str) -> SourceValidationError:
    """Classify a user-code failure without reflecting its message or values."""
    messages = {
        NameError: ('PYTHON_NAME_UNRESOLVED', 'A name used by this rule is not defined.',
                    'Check the name, imports, and the variables defined before this line.'),
        AttributeError: ('PYTHON_ATTRIBUTE_UNAVAILABLE', 'The object has no such field or method.',
                        'Use a field or method from the published Open EPM authoring API.'),
        TypeError: ('PYTHON_ARGUMENT_TYPE_INVALID', 'An argument or operation has an incompatible type.',
                    'Check the primitive signature and use the required typed values.'),
        ValueError: ('PYTHON_ARGUMENT_VALUE_INVALID', 'A supplied value is invalid for this operation.',
                    'Check the primitive constraints and exact numeric values.'),
        ImportError: ('PYTHON_IMPORT_UNAVAILABLE', 'A required import is unavailable.',
                     'Use a module provided by the selected approved Python environment.'),
        ModuleNotFoundError: ('PYTHON_IMPORT_UNAVAILABLE', 'A required import is unavailable.',
                     'Use a module provided by the selected approved Python environment.'),
        ZeroDivisionError: ('PYTHON_DIVISION_BY_ZERO', 'A Python calculation divided by zero.',
                           'Check the divisor or construct a conditional expression.'),
    }
    code, message, hint = _metadata_failure(error) or messages.get(type(error), (
        'PYTHON_AUTHORING_FAILED', 'The authored Python could not build a plan.',
        'Correct the highlighted code and save again.'))
    span = None
    trace = error.__traceback__
    while trace is not None:
        if trace.tb_frame.f_code.co_filename == FILENAME:
            span = (trace.tb_lineno, 1, trace.tb_lineno, 1)
        trace = trace.tb_next
    return SourceValidationError(diagnostic_payload(source_digest, (
        Diagnostic(code, message, 'build', span=span, hint=hint),)))


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
        'authoringContractDigest': BOOTSTRAP_CONTRACT_DIGEST,
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
    digest = validate_python_source(source['sourceText'])
    namespace = {'__name__': '__openepm_program__', '__builtins__': __builtins__}
    log = StringIO()
    try:
        with capture_source(source['sourceText']), redirect_stdout(log), redirect_stderr(log):
            code = compile(source['sourceText'], FILENAME, 'exec',
                           dont_inherit=True, optimize=0)
            exec(code, namespace, namespace)
            builder = namespace.get(source['entryPoint'])
            if not callable(builder):
                raise SourceValidationError(diagnostic_payload(digest, (Diagnostic(
                    'PYTHON_ENTRY_POINT_INVALID', 'The declared build function is missing or not callable.',
                    'build', path='/entryPoint',
                    hint='Define the declared function with context and parameters arguments.'),)))
            plan = builder(build_context, context['parameterValues'])
            if not isinstance(plan, Program):
                from .definition_builds import definition_program
                plan = definition_program(plan, build_context)
    except SourceValidationError:
        raise
    except Exception as error:
        raise _source_failure(error, digest) from None
    if not isinstance(plan, Program):
        raise ValueError('BUILDER_RESULT_INVALID')
    build_log = log.getvalue()
    if len(build_log.encode('utf-8')) > MAX_LOG:
        raise ValueError('BUILDER_LOG_LIMIT')
    return {'plan': plan.to_wire(),
            'sourceMap': program_source_map(plan, source['sourceText']), 'buildLog': build_log}


def main() -> None:
    try:
        request = json.loads(_read_launch_request(sys.stdin.buffer))
        output = execute(request)
        sys.stdout.write(json.dumps(output, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True))
    except SourceValidationError as error:
        # A recognized authoring failure is a bounded machine-readable result.
        # No partial plan, source excerpt or user exception text is returned.
        sys.stdout.write(json.dumps({'diagnostics': error.diagnostics},
            sort_keys=True, separators=(',', ':'), ensure_ascii=True))
    except Exception:
        # Never echo source, parameters, capability tokens or exception text.
        sys.stderr.write('OPEN_EPM_BUILDER_FAILED\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
