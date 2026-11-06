"""Fail-closed admission policy for pg_duckdb cube-aggregate profiles.

This module does not execute queries and cannot enable an engine by itself.  It
turns a complete, paired public-route qualification record into a server-owned
decision.  Missing controls, non-DuckDB execution, unequal results or less than
the required end-to-end p95 improvement always retain PostgreSQL.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re


FORMAT = 'openepm-pgduckdb-public-route-v1'
NATIVE = 'postgres_exact_sql'
ACCELERATED = 'pg_duckdb_exact_sum_count_v1'
MIN_PAIRS = 5
MIN_P95_IMPROVEMENT = 0.20
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$')


@dataclass(frozen=True, slots=True)
class AccelerationDecision:
    profile_id: str
    admitted: bool
    native_p95_ms: float | None
    accelerated_p95_ms: float | None
    p95_improvement: float | None
    minimum_source_cells: int
    reasons: tuple[str, ...]

    def wire(self) -> dict:
        return {'profileId': self.profile_id, 'admitted': self.admitted,
            'nativeP95Ms': self.native_p95_ms,
            'acceleratedP95Ms': self.accelerated_p95_ms,
            'p95Improvement': self.p95_improvement,
            'minimumSourceCells': self.minimum_source_cells,
            'reasons': list(self.reasons)}


_CONTROL_FIELDS = (
    'authorizationIsolation', 'sameWorkspaceCrossApplicationIsolation',
    'repeatableReadSnapshot', 'concurrentWriterFence', 'ownedCancellation',
    'failureRecovery', 'boundedMemoryAndSpill', 'externalAccessDisabled',
    'automaticExtensionLoadingDisabled', 'exactNumericRange',
)


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _digest(value: object, code: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _positive_number(value: object, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(code)
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(code)
    return result


def _p95(values: list[float]) -> float:
    # Nearest-rank is deterministic and conservative for the required bounded
    # repeat set.  With five pairs it selects the slowest observation.
    ordered = sorted(values)
    return ordered[math.ceil(.95 * len(ordered)) - 1]


def evaluate_pgduckdb_profile(evidence: object) -> AccelerationDecision:
    """Validate one frozen qualification artifact and return its admission.

    A structurally invalid artifact is rejected with ``ValueError`` because it
    cannot be retained as auditable evidence.  A well-formed but insufficient
    artifact returns a non-admitted decision with exact reason codes.
    """
    if type(evidence) is not dict or set(evidence) != {
            'format', 'profile', 'controls', 'samples'}:
        raise ValueError('PGDUCKDB_QUALIFICATION_INVALID')
    if evidence['format'] != FORMAT:
        raise ValueError('PGDUCKDB_QUALIFICATION_FORMAT_UNSUPPORTED')
    profile = evidence['profile']
    required_profile = {'profileId', 'postgresVersion', 'extensionVersion',
        'databaseImageDigest', 'hardwareProfileDigest', 'hostArchitecture',
        'compilerProfile', 'publicRouteVersion',
        'queryShape', 'sourceTypes', 'outputTypes', 'numericRange',
        'memoryMiB', 'spillMiB', 'statementTimeoutMs', 'minimumSourceCells',
        'executionImplementationQualified'}
    if type(profile) is not dict or set(profile) != required_profile:
        raise ValueError('PGDUCKDB_PROFILE_INVALID')
    profile_id = _identifier(profile['profileId'], 'PGDUCKDB_PROFILE_INVALID')
    for field in ('postgresVersion', 'extensionVersion', 'hostArchitecture',
                  'compilerProfile', 'publicRouteVersion', 'queryShape'):
        _identifier(profile[field], 'PGDUCKDB_PROFILE_INVALID')
    _digest(profile['databaseImageDigest'], 'PGDUCKDB_PROFILE_INVALID')
    _digest(profile['hardwareProfileDigest'], 'PGDUCKDB_PROFILE_INVALID')
    if (type(profile['sourceTypes']) is not list or not profile['sourceTypes']
            or any(type(item) is not str or not item for item in profile['sourceTypes'])
            or type(profile['outputTypes']) is not list or not profile['outputTypes']
            or any(type(item) is not str or not item for item in profile['outputTypes'])
            or type(profile['numericRange']) is not dict
            or set(profile['numericRange']) != {'minimum', 'maximum', 'scale'}
            or type(profile['numericRange']['minimum']) is not str
            or type(profile['numericRange']['maximum']) is not str
            or type(profile['numericRange']['scale']) is not int
            or not 0 <= profile['numericRange']['scale'] <= 28
            or any(type(profile[field]) is not int or profile[field] <= 0
                   for field in ('memoryMiB', 'spillMiB', 'statementTimeoutMs',
                                 'minimumSourceCells'))
            or type(profile['executionImplementationQualified']) is not bool):
        raise ValueError('PGDUCKDB_PROFILE_INVALID')
    controls = evidence['controls']
    if (type(controls) is not dict or set(controls) != set(_CONTROL_FIELDS)
            or any(type(value) is not bool for value in controls.values())):
        raise ValueError('PGDUCKDB_CONTROLS_INVALID')
    samples = evidence['samples']
    if type(samples) is not list:
        raise ValueError('PGDUCKDB_SAMPLES_INVALID')
    pairs: dict[str, dict[str, tuple[float, str, str]]] = {}
    for sample in samples:
        if type(sample) is not dict or set(sample) != {
                'pairId', 'requestedBackend', 'selectedBackend',
                'endToEndMs', 'resultDigest', 'sourcePinsDigest'}:
            raise ValueError('PGDUCKDB_SAMPLE_INVALID')
        pair_id = _identifier(sample['pairId'], 'PGDUCKDB_SAMPLE_INVALID')
        requested = sample['requestedBackend']
        if requested not in (NATIVE, ACCELERATED):
            raise ValueError('PGDUCKDB_SAMPLE_INVALID')
        selected = sample['selectedBackend']
        if selected not in (NATIVE, ACCELERATED, 'execution_error'):
            raise ValueError('PGDUCKDB_SAMPLE_INVALID')
        elapsed = _positive_number(sample['endToEndMs'],
                                   'PGDUCKDB_SAMPLE_INVALID')
        result = _digest(sample['resultDigest'], 'PGDUCKDB_SAMPLE_INVALID')
        pins = _digest(sample['sourcePinsDigest'], 'PGDUCKDB_SAMPLE_INVALID')
        slot = pairs.setdefault(pair_id, {})
        if requested in slot:
            raise ValueError('PGDUCKDB_SAMPLE_DUPLICATE')
        slot[requested] = (elapsed, result, pins, selected)

    reasons: list[str] = []
    if not profile['executionImplementationQualified']:
        reasons.append('EXECUTION_IMPLEMENTATION_UNQUALIFIED')
    for field in _CONTROL_FIELDS:
        if not controls[field]:
            reasons.append('CONTROL_FAILED_' + re.sub(
                r'(?<!^)(?=[A-Z])', '_', field).upper())
    complete = [pair for pair in pairs.values()
                if set(pair) == {NATIVE, ACCELERATED}]
    if len(complete) < MIN_PAIRS:
        reasons.append('INSUFFICIENT_PAIRED_SAMPLES')
    if len(complete) != len(pairs):
        reasons.append('INCOMPLETE_SAMPLE_PAIR')
    native_values: list[float] = []
    accelerated_values: list[float] = []
    for pair in complete:
        native, accelerated = pair[NATIVE], pair[ACCELERATED]
        native_values.append(native[0]); accelerated_values.append(accelerated[0])
        if native[3] != NATIVE:
            reasons.append('NATIVE_BACKEND_NOT_SELECTED')
        if accelerated[3] != ACCELERATED:
            reasons.append('ACCELERATED_BACKEND_NOT_SELECTED')
        if native[1] != accelerated[1]:
            reasons.append('RESULT_DIGEST_MISMATCH')
        if native[2] != accelerated[2]:
            reasons.append('SOURCE_PINS_MISMATCH')
    native_p95 = _p95(native_values) if native_values else None
    accelerated_p95 = _p95(accelerated_values) if accelerated_values else None
    improvement = (None if native_p95 is None or accelerated_p95 is None else
                   (native_p95 - accelerated_p95) / native_p95)
    if improvement is None or improvement < MIN_P95_IMPROVEMENT:
        reasons.append('P95_IMPROVEMENT_BELOW_THRESHOLD')
    reasons = list(dict.fromkeys(reasons))
    return AccelerationDecision(profile_id, not reasons, native_p95,
        accelerated_p95, improvement, profile['minimumSourceCells'],
        tuple(reasons))


def select_cube_aggregate_backend(decision: AccelerationDecision | None, *,
                                  source_cells: int, measures: tuple[str, ...],
                                  has_financial_roles: bool) -> str:
    """Server-only selection.  No public request value is accepted here."""
    if (not isinstance(decision, AccelerationDecision) or not decision.admitted
            or type(source_cells) is not int
            or source_cells < decision.minimum_source_cells
            or type(measures) is not tuple
            or not measures or set(measures) - {'SumAmount', 'CountPresent'}
            or type(has_financial_roles) is not bool or has_financial_roles):
        return NATIVE
    return ACCELERATED
