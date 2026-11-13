"""Source locations for authored operations; never part of executable identity."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from hashlib import sha256
import sys
import re

from .diagnostics import Diagnostic


_SOURCE = ContextVar('openepm_authoring_source', default=None)
FILENAME = '<openepm-program>'
FORMAT = 'openepm-source-map-v1'


@contextmanager
def capture_source(source: str):
    token = _SOURCE.set(source)
    try:
        yield
    finally:
        _SOURCE.reset(token)


def current_span() -> tuple[int, int, int, int] | None:
    """Find the actual authored call site, including calls through SDK helpers."""
    source = _SOURCE.get()
    if source is None:
        return None
    frame = sys._getframe(1)
    try:
        while frame is not None:
            if frame.f_code.co_filename == FILENAME:
                line = frame.f_lineno
                # A line is useful even on Python versions without bytecode
                # position metadata. Do not manufacture an exact call column.
                lines = source.splitlines()
                end = len(lines[line - 1].encode('utf-16-le')) // 2 + 1
                return (line, 1, line, end)
            frame = frame.f_back
    finally:
        del frame
    return None


def program_source_map(program, source: str) -> dict:
    entries = []
    for unit_index, unit in enumerate(program.units):
        for operation_index, span in enumerate(unit._source_spans):
            if span is not None:
                entries.append({'path': f'/units/{unit_index}/operations/{operation_index}',
                    'span': dict(zip(('startLine', 'startColumn', 'endLine', 'endColumn'), span))})
    return {'format': FORMAT, 'sourceDigest': sha256(source.encode('utf-8')).hexdigest(),
            'positionEncoding': 'utf-16', 'entries': entries}


def validate_source_map(value: object) -> dict:
    if (type(value) is not dict or set(value) != {
            'format', 'sourceDigest', 'positionEncoding', 'entries'}
            or value['format'] != FORMAT or value['positionEncoding'] != 'utf-16'
            or type(value['sourceDigest']) is not str
            or re.fullmatch(r'[0-9a-f]{64}', value['sourceDigest']) is None
            or type(value['entries']) is not list or len(value['entries']) > 10_000):
        raise ValueError('PYTHON_SOURCE_MAP_INVALID')
    entries, paths = [], set()
    keys = ('startLine', 'startColumn', 'endLine', 'endColumn')
    for entry in value['entries']:
        if (type(entry) is not dict or set(entry) != {'path', 'span'}
                or type(entry['path']) is not str
                or re.fullmatch(r'/units/(0|[1-9][0-9]{0,3})/operations/(0|[1-9][0-9]{0,3})',
                                entry['path']) is None
                or entry['path'] in paths or type(entry['span']) is not dict
                or set(entry['span']) != set(keys)):
            raise ValueError('PYTHON_SOURCE_MAP_INVALID')
        span = tuple(entry['span'][key] for key in keys)
        checked = Diagnostic('SOURCE_LOCATION', 'Source location', 'source', span=span)
        entries.append({'path': entry['path'], 'span': checked.to_wire()['span']})
        paths.add(entry['path'])
    return {**value, 'entries': entries}
