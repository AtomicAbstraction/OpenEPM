"""Pure, bounded diagnostics for generic multidimensional source imports.

This module does not read metadata or persist results.  Fixed core code supplies
already-authorized resolution candidates and may later persist the canonical
result.  Messages and severities are server-owned; source values never become
exception text or executable content.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from enum import StrEnum
from hashlib import sha256
import hmac
import json
import re
from typing import Mapping, Sequence

from .persistence_contract import LineItem, NumericCell, TextCell


CONTRACT_VERSION = 'openepm-source-import-diagnostics-v1'
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[^\x00-\x1f\x7f]{1,200}\Z')


class DiagnosticSeverity(StrEnum):
    ERROR = 'error'
    WARNING = 'warning'


class DiagnosticCode(StrEnum):
    ROW_SHAPE_INVALID = 'ROW_SHAPE_INVALID'
    SOURCE_REFERENCE_INVALID = 'SOURCE_REFERENCE_INVALID'
    UNKNOWN_DIMENSION = 'UNKNOWN_DIMENSION'
    AMBIGUOUS_DIMENSION = 'AMBIGUOUS_DIMENSION'
    UNKNOWN_MEMBER = 'UNKNOWN_MEMBER'
    AMBIGUOUS_MEMBER = 'AMBIGUOUS_MEMBER'
    MISSING_REQUIRED_COORDINATE = 'MISSING_REQUIRED_COORDINATE'
    SCOPE_MODE_INVALID = 'SCOPE_MODE_INVALID'
    SCOPE_DECLARATION_INVALID = 'SCOPE_DECLARATION_INVALID'
    ROW_OUTSIDE_SCOPE = 'ROW_OUTSIDE_SCOPE'
    REPLACE_SCOPE_EMPTY_INPUT = 'REPLACE_SCOPE_EMPTY_INPUT'
    VALUE_LITERAL_SHAPE_INVALID = 'VALUE_LITERAL_SHAPE_INVALID'
    NUMERIC_FLOAT_FORBIDDEN = 'NUMERIC_FLOAT_FORBIDDEN'
    NUMERIC_BOOLEAN_FORBIDDEN = 'NUMERIC_BOOLEAN_FORBIDDEN'
    NUMERIC_LITERAL_INVALID = 'NUMERIC_LITERAL_INVALID'
    NUMERIC_OUT_OF_RANGE = 'NUMERIC_OUT_OF_RANGE'
    TEXT_LITERAL_INVALID = 'TEXT_LITERAL_INVALID'
    TEXT_TOO_LARGE = 'TEXT_TOO_LARGE'
    DETAIL_LITERAL_INVALID = 'DETAIL_LITERAL_INVALID'
    DETAIL_ITEM_LIMIT = 'DETAIL_ITEM_LIMIT'
    DETAIL_ITEM_INVALID = 'DETAIL_ITEM_INVALID'
    DETAIL_TOTAL_OUT_OF_RANGE = 'DETAIL_TOTAL_OUT_OF_RANGE'
    DIAGNOSTICS_TRUNCATED = 'DIAGNOSTICS_TRUNCATED'


_MESSAGES = {
    DiagnosticCode.ROW_SHAPE_INVALID:
        'The source row does not match the required transfer shape.',
    DiagnosticCode.SOURCE_REFERENCE_INVALID:
        'The source reference is missing or exceeds its safe bound.',
    DiagnosticCode.UNKNOWN_DIMENSION:
        'A coordinate dimension cannot be resolved.',
    DiagnosticCode.AMBIGUOUS_DIMENSION:
        'A coordinate dimension resolves to more than one dimension.',
    DiagnosticCode.UNKNOWN_MEMBER:
        'A coordinate member cannot be resolved.',
    DiagnosticCode.AMBIGUOUS_MEMBER:
        'A coordinate member resolves to more than one member.',
    DiagnosticCode.MISSING_REQUIRED_COORDINATE:
        'The coordinate omits one or more required dimensions.',
    DiagnosticCode.SCOPE_MODE_INVALID:
        'The transfer mode must be merge or replace.',
    DiagnosticCode.SCOPE_DECLARATION_INVALID:
        'The transfer scope declaration is inconsistent.',
    DiagnosticCode.ROW_OUTSIDE_SCOPE:
        'The resolved coordinate is outside the declared transfer scope.',
    DiagnosticCode.REPLACE_SCOPE_EMPTY_INPUT:
        'An empty replace input would clear the declared scope.',
    DiagnosticCode.VALUE_LITERAL_SHAPE_INVALID:
        'The value does not match a supported typed literal shape.',
    DiagnosticCode.NUMERIC_FLOAT_FORBIDDEN:
        'Binary floating-point values are not accepted for exact amounts.',
    DiagnosticCode.NUMERIC_BOOLEAN_FORBIDDEN:
        'Boolean values are not accepted as exact amounts.',
    DiagnosticCode.NUMERIC_LITERAL_INVALID:
        'The amount must be a finite exact decimal string.',
    DiagnosticCode.NUMERIC_OUT_OF_RANGE:
        'The amount exceeds the supported exact numeric precision or scale.',
    DiagnosticCode.TEXT_LITERAL_INVALID:
        'The text literal must contain a string without NUL.',
    DiagnosticCode.TEXT_TOO_LARGE:
        'The text literal exceeds 32768 characters.',
    DiagnosticCode.DETAIL_LITERAL_INVALID:
        'Supporting detail must be a typed item array.',
    DiagnosticCode.DETAIL_ITEM_LIMIT:
        'Supporting detail exceeds 500 items.',
    DiagnosticCode.DETAIL_ITEM_INVALID:
        'A supporting-detail item has an invalid description or amount.',
    DiagnosticCode.DETAIL_TOTAL_OUT_OF_RANGE:
        'The supporting-detail total exceeds exact numeric bounds.',
    DiagnosticCode.DIAGNOSTICS_TRUNCATED:
        'Additional diagnostics were omitted by configured response bounds.',
}

_WARNINGS = frozenset((DiagnosticCode.REPLACE_SCOPE_EMPTY_INPUT,
                       DiagnosticCode.DIAGNOSTICS_TRUNCATED))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _coordinate_valid(value: object) -> bool:
    if not isinstance(value, tuple) or len(value) > 32:
        return False
    for item in value:
        if (not isinstance(item, tuple) or len(item) != 2
                or not isinstance(item[0], str) or not _ID.fullmatch(item[0])
                or not isinstance(item[1], str) or not _ID.fullmatch(item[1])):
            return False
    return (tuple(sorted(value)) == value
            and len({item[0] for item in value}) == len(value))


@dataclass(frozen=True, slots=True)
class SourceDiagnosticIdentity:
    manifest_digest: str
    content_digest: str
    schema_digest: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not _DIGEST.fullmatch(value)
               for value in (self.manifest_digest, self.content_digest,
                             self.schema_digest)):
            raise ValueError('SOURCE_DIAGNOSTIC_IDENTITY_INVALID')

    def wire(self) -> dict:
        return {'manifestDigest': self.manifest_digest,
                'contentDigest': self.content_digest,
                'schemaDigest': self.schema_digest}


@dataclass(frozen=True, slots=True)
class SourceDiagnostic:
    code: DiagnosticCode
    severity: DiagnosticSeverity
    row_index: int | None
    field: str | None
    coordinate: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if (not isinstance(self.code, DiagnosticCode)
                or not isinstance(self.severity, DiagnosticSeverity)):
            raise ValueError('SOURCE_DIAGNOSTIC_INVALID')
        expected = (DiagnosticSeverity.WARNING if self.code in _WARNINGS
                    else DiagnosticSeverity.ERROR)
        if (self.severity != expected
                or (self.row_index is not None and
                    (type(self.row_index) is not int
                     or not 1 <= self.row_index <= 100000))
                or (self.field is not None and
                    (not isinstance(self.field, str)
                     or not _ID.fullmatch(self.field)))
                or not _coordinate_valid(self.coordinate)):
            raise ValueError('SOURCE_DIAGNOSTIC_INVALID')

    @classmethod
    def fixed(cls, code: DiagnosticCode, *, row_index: int | None = None,
              field: str | None = None,
              coordinate: Mapping[str, str] | None = None):
        if not isinstance(code, DiagnosticCode):
            raise ValueError('SOURCE_DIAGNOSTIC_CODE_INVALID')
        safe = tuple(sorted((coordinate or {}).items()))
        return cls(code, DiagnosticSeverity.WARNING if code in _WARNINGS
                   else DiagnosticSeverity.ERROR, row_index, field, safe)

    def wire(self) -> dict:
        value = {'code': self.code.value, 'severity': self.severity.value,
                 'message': _MESSAGES[self.code]}
        if self.row_index is not None:
            value['rowIndex'] = self.row_index
        if self.field is not None:
            value['field'] = self.field
        if self.coordinate:
            value['coordinate'] = dict(self.coordinate)
        return value

    def sort_key(self) -> tuple:
        return (0 if self.row_index is None else 1, self.row_index or 0,
                self.code.value, self.field or '', self.coordinate)


def _candidate_map(value: object, *, nested: bool = False):
    if not isinstance(value, Mapping):
        raise ValueError('SOURCE_DIAGNOSTIC_RESOLUTION_INVALID')
    result = {}
    for key, candidates in value.items():
        if not isinstance(key, str) or not _ID.fullmatch(key):
            raise ValueError('SOURCE_DIAGNOSTIC_RESOLUTION_INVALID')
        if nested:
            result[key] = _candidate_map(candidates)
            continue
        if (not isinstance(candidates, Sequence)
                or isinstance(candidates, (str, bytes))
                or len(candidates) > 32
                or any(not isinstance(item, str) or not _ID.fullmatch(item)
                       for item in candidates)):
            raise ValueError('SOURCE_DIAGNOSTIC_RESOLUTION_INVALID')
        result[key] = tuple(sorted(set(candidates)))
    return result


def _value_diagnostics(value: object, row_index: int,
                       coordinate: Mapping[str, str]) -> list[SourceDiagnostic]:
    def item(code, field='value'):
        return SourceDiagnostic.fixed(code, row_index=row_index, field=field,
                                      coordinate=coordinate)

    if not isinstance(value, dict) or not isinstance(value.get('type'), str):
        return [item(DiagnosticCode.VALUE_LITERAL_SHAPE_INVALID)]
    kind = value['type']
    if kind == 'AmountLiteral':
        if set(value) != {'type', 'decimal'}:
            return [item(DiagnosticCode.VALUE_LITERAL_SHAPE_INVALID)]
        raw = value['decimal']
        if isinstance(raw, bool):
            return [item(DiagnosticCode.NUMERIC_BOOLEAN_FORBIDDEN,
                         'value.decimal')]
        if isinstance(raw, float):
            return [item(DiagnosticCode.NUMERIC_FLOAT_FORBIDDEN,
                         'value.decimal')]
        if not isinstance(raw, str):
            return [item(DiagnosticCode.NUMERIC_LITERAL_INVALID,
                         'value.decimal')]
        try:
            decimal = Decimal(raw)
        except (InvalidOperation, ValueError):
            return [item(DiagnosticCode.NUMERIC_LITERAL_INVALID,
                         'value.decimal')]
        if not decimal.is_finite():
            return [item(DiagnosticCode.NUMERIC_LITERAL_INVALID,
                         'value.decimal')]
        try:
            NumericCell(True, decimal, '')
        except ValueError:
            return [item(DiagnosticCode.NUMERIC_OUT_OF_RANGE,
                         'value.decimal')]
        return []
    if kind == 'TextLiteral':
        if set(value) != {'type', 'text'} or not isinstance(value['text'], str):
            return [item(DiagnosticCode.TEXT_LITERAL_INVALID, 'value.text')]
        if len(value['text']) > 32768:
            return [item(DiagnosticCode.TEXT_TOO_LARGE, 'value.text')]
        try:
            TextCell(True, value['text'], '')
        except ValueError:
            return [item(DiagnosticCode.TEXT_LITERAL_INVALID, 'value.text')]
        return []
    if kind == 'LineDetailLiteral':
        if set(value) != {'type', 'items'} or not isinstance(value['items'], list):
            return [item(DiagnosticCode.DETAIL_LITERAL_INVALID, 'value.items')]
        if len(value['items']) > 500:
            return [item(DiagnosticCode.DETAIL_ITEM_LIMIT, 'value.items')]
        amounts = []
        for detail in value['items']:
            if (not isinstance(detail, dict)
                    or set(detail) != {'description', 'decimal'}
                    or not isinstance(detail.get('description'), str)
                    or isinstance(detail.get('decimal'), (bool, float))
                    or not isinstance(detail.get('decimal'), str)):
                return [item(DiagnosticCode.DETAIL_ITEM_INVALID,
                             'value.items')]
            try:
                amount = Decimal(detail['decimal'])
                LineItem(detail['description'], amount)
            except (InvalidOperation, ValueError):
                return [item(DiagnosticCode.DETAIL_ITEM_INVALID,
                             'value.items')]
            amounts.append(amount)
        try:
            with localcontext() as precision:
                precision.prec = 80
                total = sum(amounts, Decimal(0))
            NumericCell(True, total, '')
        except (ArithmeticError, ValueError):
            return [item(DiagnosticCode.DETAIL_TOTAL_OUT_OF_RANGE,
                         'value.items')]
        return []
    return [item(DiagnosticCode.VALUE_LITERAL_SHAPE_INVALID)]


def compile_source_import_diagnostics(*, identity: SourceDiagnosticIdentity,
        rows: list[object], required_dimensions: Sequence[str],
        dimension_candidates: Mapping[str, Sequence[str]],
        member_candidates: Mapping[str, Mapping[str, Sequence[str]]],
        mode: str, scope_members: Mapping[str, str], scope_all: bool,
        max_diagnostics: int = 1000,
        max_payload_bytes: int = 262144) -> dict:
    """Compile deterministic diagnostics without database or caller code."""
    if (not isinstance(identity, SourceDiagnosticIdentity)
            or not isinstance(rows, list) or len(rows) > 100000
            or not isinstance(required_dimensions, Sequence)
            or isinstance(required_dimensions, (str, bytes))
            or len(required_dimensions) > 32
            or any(not isinstance(axis, str) or not _ID.fullmatch(axis)
                   for axis in required_dimensions)
            or len(set(required_dimensions)) != len(required_dimensions)
            or not isinstance(scope_members, Mapping)
            or len(scope_members) > 32
            or any(not isinstance(axis, str) or not _ID.fullmatch(axis)
                   or not isinstance(member, str) or not _ID.fullmatch(member)
                   for axis, member in scope_members.items())
            or not isinstance(scope_all, bool)
            or type(max_diagnostics) is not int
            or not 1 <= max_diagnostics <= 10000
            or type(max_payload_bytes) is not int
            or not 512 <= max_payload_bytes <= 4194304):
        raise ValueError('SOURCE_DIAGNOSTIC_COMPILER_INPUT_INVALID')
    dimensions = _candidate_map(dimension_candidates)
    members = _candidate_map(member_candidates, nested=True)
    required = tuple(sorted(required_dimensions))
    retained: list[SourceDiagnostic] = []
    observed = errors = warnings = 0

    def emit(values: Sequence[SourceDiagnostic]) -> None:
        nonlocal observed, errors, warnings
        unique = {diagnostic.sort_key(): diagnostic for diagnostic in values}
        for diagnostic in sorted(unique.values(), key=lambda item: item.sort_key()):
            observed += 1
            if diagnostic.severity == DiagnosticSeverity.ERROR:
                errors += 1
            else:
                warnings += 1
            if len(retained) < max_diagnostics + 1:
                retained.append(diagnostic)

    top = []
    if mode not in ('merge', 'replace'):
        top.append(SourceDiagnostic.fixed(DiagnosticCode.SCOPE_MODE_INVALID,
                                          field='mode'))
    if scope_all != (len(scope_members) == 0):
        top.append(SourceDiagnostic.fixed(
            DiagnosticCode.SCOPE_DECLARATION_INVALID, field='scopeMembers'))
    if mode == 'replace' and not rows:
        top.append(SourceDiagnostic.fixed(
            DiagnosticCode.REPLACE_SCOPE_EMPTY_INPUT, field='rows'))
    emit(top)

    for row_index, row in enumerate(rows, 1):
        current = []
        if (not isinstance(row, dict)
                or set(row) != {'members', 'value', 'sourceRef'}
                or not isinstance(row.get('members'), dict)
                or len(row.get('members', {})) > 32):
            emit([SourceDiagnostic.fixed(DiagnosticCode.ROW_SHAPE_INVALID,
                                         row_index=row_index)])
            continue
        source_ref = row['sourceRef']
        if (not isinstance(source_ref, str) or not 1 <= len(source_ref) <= 200
                or '\x00' in source_ref):
            current.append(SourceDiagnostic.fixed(
                DiagnosticCode.SOURCE_REFERENCE_INVALID,
                row_index=row_index, field='sourceRef'))
        resolved: dict[str, str] = {}
        for raw_axis, raw_member in sorted(row['members'].items(),
                                           key=lambda item: str(item[0])):
            if (not isinstance(raw_axis, str) or not _ID.fullmatch(raw_axis)
                    or not isinstance(raw_member, str)
                    or not _ID.fullmatch(raw_member)):
                current.append(SourceDiagnostic.fixed(
                    DiagnosticCode.ROW_SHAPE_INVALID, row_index=row_index,
                    field='members'))
                continue
            axis_matches = dimensions.get(raw_axis, ())
            if not axis_matches:
                current.append(SourceDiagnostic.fixed(
                    DiagnosticCode.UNKNOWN_DIMENSION, row_index=row_index,
                    field='members'))
                continue
            if len(axis_matches) != 1 or axis_matches[0] in resolved:
                current.append(SourceDiagnostic.fixed(
                    DiagnosticCode.AMBIGUOUS_DIMENSION, row_index=row_index,
                    field='members'))
                continue
            axis = axis_matches[0]
            member_matches = members.get(axis, {}).get(raw_member, ())
            if not member_matches:
                current.append(SourceDiagnostic.fixed(
                    DiagnosticCode.UNKNOWN_MEMBER, row_index=row_index,
                    field='members', coordinate=resolved))
                continue
            if len(member_matches) != 1:
                current.append(SourceDiagnostic.fixed(
                    DiagnosticCode.AMBIGUOUS_MEMBER, row_index=row_index,
                    field='members', coordinate=resolved))
                continue
            resolved[axis] = member_matches[0]
        if set(resolved) != set(required):
            current.append(SourceDiagnostic.fixed(
                DiagnosticCode.MISSING_REQUIRED_COORDINATE,
                row_index=row_index, field='members', coordinate=resolved))
        if any(resolved.get(axis) != member
               for axis, member in scope_members.items()):
            current.append(SourceDiagnostic.fixed(
                DiagnosticCode.ROW_OUTSIDE_SCOPE, row_index=row_index,
                field='members', coordinate=resolved))
        current.extend(_value_diagnostics(row['value'], row_index, resolved))
        emit(current)

    retained.sort(key=lambda item: item.sort_key())
    full = [item.wire() for item in retained[:max_diagnostics]]
    if observed <= max_diagnostics and len(_canonical(full)) <= max_payload_bytes:
        output = full
        truncated = False
        omitted = 0
    else:
        summary = SourceDiagnostic.fixed(
            DiagnosticCode.DIAGNOSTICS_TRUNCATED).wire()
        selected = []
        for diagnostic in retained:
            if len(selected) >= max_diagnostics - 1:
                break
            candidate = [*selected, diagnostic.wire(), summary]
            if len(_canonical(candidate)) > max_payload_bytes:
                break
            selected.append(diagnostic.wire())
        output = [*selected, summary]
        truncated = True
        omitted = observed - len(selected)
    payload_bytes = len(_canonical(output))
    result = {
        'contractVersion': CONTRACT_VERSION,
        'sourceIdentity': identity.wire(),
        'diagnostics': output,
        'diagnosticCount': len(output),
        'observedCount': observed,
        'errorCount': errors,
        'warningCount': warnings,
        'truncated': truncated,
        'omittedCount': omitted,
        'diagnosticsPayloadBytes': payload_bytes,
        'accepted': errors == 0,
    }
    result['diagnosticsDigest'] = sha256(_canonical(result)).hexdigest()
    return result


def source_diagnostics_digest_matches(result: object) -> bool:
    """Check the canonical identity after persistence or transport."""
    if (not isinstance(result, dict)
            or not isinstance(result.get('diagnosticsDigest'), str)
            or not _DIGEST.fullmatch(result['diagnosticsDigest'])):
        return False
    unsigned = dict(result)
    claimed = unsigned.pop('diagnosticsDigest')
    try:
        actual = sha256(_canonical(unsigned)).hexdigest()
    except (RecursionError, TypeError, ValueError, UnicodeError):
        return False
    return hmac.compare_digest(claimed, actual)
