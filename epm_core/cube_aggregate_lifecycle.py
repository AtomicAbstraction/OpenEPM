"""Pure lifecycle contracts for future durable cube aggregate queries.

This module deliberately contains no in-memory repository and no database
adapter.  A production implementation must persist transitions and rows in
PostgreSQL, use current authorization at each effect boundary, and connect the
compute stage to the server-owned worker coordinator.
"""
from __future__ import annotations

import base64
import hmac
import json
import time
from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
from typing import Protocol, Sequence

from .persistence_contract import ApplicationScope

MAX_GROUPS = 100_000
MAX_RESULT_BYTES = 32 * 1024 * 1024
MAX_PAGE_SIZE = 500
RESULT_TTL_SECONDS = 15 * 60
POSTGRES_EXACT_DIMENSIONAL_BACKEND = (
    'postgres_exact_sql')


def _identifier(value: object, code: str) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 200
            or value != value.strip() or any(ord(char) < 32 for char in value)):
        raise ValueError(code)
    return value


def _digest(value: object, code: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(char not in '0123456789abcdef' for char in value)):
        raise ValueError(code)
    return value


def _positive(value: object, maximum: int, code: str) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(code)
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID') from error


class AggregateQueryStatus(StrEnum):
    ACCEPTED = 'accepted'
    READY = 'ready'
    RUNNING = 'running'
    COMPUTED = 'computed'
    SEALED = 'sealed'
    CANCEL_REQUESTED = 'cancel_requested'
    CANCELLED = 'cancelled'
    FAILED = 'failed'
    EXPIRED = 'expired'


_TRANSITIONS = {
    AggregateQueryStatus.ACCEPTED: frozenset((AggregateQueryStatus.READY,
                                              AggregateQueryStatus.CANCELLED,
                                              AggregateQueryStatus.FAILED)),
    AggregateQueryStatus.READY: frozenset((AggregateQueryStatus.RUNNING,
                                           AggregateQueryStatus.CANCELLED,
                                           AggregateQueryStatus.FAILED)),
    AggregateQueryStatus.RUNNING: frozenset((AggregateQueryStatus.COMPUTED,
                                             AggregateQueryStatus.CANCEL_REQUESTED,
                                             AggregateQueryStatus.FAILED)),
    AggregateQueryStatus.COMPUTED: frozenset((AggregateQueryStatus.SEALED,
                                              AggregateQueryStatus.CANCELLED,
                                              AggregateQueryStatus.FAILED)),
    AggregateQueryStatus.CANCEL_REQUESTED: frozenset((AggregateQueryStatus.CANCELLED,
                                                       AggregateQueryStatus.COMPUTED,
                                                       AggregateQueryStatus.FAILED)),
    AggregateQueryStatus.SEALED: frozenset((AggregateQueryStatus.EXPIRED,)),
    AggregateQueryStatus.CANCELLED: frozenset(),
    AggregateQueryStatus.FAILED: frozenset(),
    AggregateQueryStatus.EXPIRED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class AggregateQueryBudgets:
    max_groups: int = MAX_GROUPS
    max_result_bytes: int = MAX_RESULT_BYTES
    page_size: int = MAX_PAGE_SIZE
    ttl_seconds: int = RESULT_TTL_SECONDS

    def __post_init__(self) -> None:
        _positive(self.max_groups, MAX_GROUPS, 'CUBE_AGGREGATE_GROUP_BUDGET_INVALID')
        _positive(self.max_result_bytes, MAX_RESULT_BYTES,
                  'CUBE_AGGREGATE_BYTE_BUDGET_INVALID')
        _positive(self.page_size, MAX_PAGE_SIZE, 'CUBE_AGGREGATE_PAGE_SIZE_INVALID')
        _positive(self.ttl_seconds, RESULT_TTL_SECONDS,
                  'CUBE_AGGREGATE_TTL_INVALID')


@dataclass(frozen=True, slots=True)
class AggregateSourcePins:
    commit_revision: int
    data_revision: int
    metadata_revision: int
    policy_revision: int
    security_revision: int
    schema_epoch: int
    active_projection_generation: int

    def __post_init__(self) -> None:
        for value in (self.commit_revision, self.data_revision,
                      self.metadata_revision, self.policy_revision,
                      self.security_revision,
                      self.schema_epoch, self.active_projection_generation):
            if type(value) is not int or value < 0:
                raise ValueError('CUBE_AGGREGATE_SOURCE_PINS_INVALID')

    def wire(self) -> dict[str, int]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class AggregateTechnicalCertificate:
    """Compute evidence only; it is never a business operation receipt."""

    plan_digest: str
    backend_profile: str
    source_pins: AggregateSourcePins
    hierarchy_digest: str
    result_digest: str
    group_count: int
    result_bytes: int

    def __post_init__(self) -> None:
        _digest(self.plan_digest, 'CUBE_AGGREGATE_PLAN_DIGEST_INVALID')
        _identifier(self.backend_profile, 'CUBE_AGGREGATE_BACKEND_PROFILE_INVALID')
        if not isinstance(self.source_pins, AggregateSourcePins):
            raise ValueError('CUBE_AGGREGATE_SOURCE_PINS_INVALID')
        _digest(self.hierarchy_digest, 'CUBE_AGGREGATE_HIERARCHY_DIGEST_INVALID')
        _digest(self.result_digest, 'CUBE_AGGREGATE_RESULT_DIGEST_INVALID')
        if type(self.group_count) is not int or not 0 <= self.group_count <= MAX_GROUPS:
            raise ValueError('CUBE_AGGREGATE_GROUP_COUNT_INVALID')
        if type(self.result_bytes) is not int or not 0 <= self.result_bytes <= MAX_RESULT_BYTES:
            raise ValueError('CUBE_AGGREGATE_RESULT_BYTES_INVALID')


@dataclass(frozen=True, slots=True)
class AggregateQueryRecord:
    query_id: str
    scope: ApplicationScope
    issuer: str
    subject: str
    request_digest: str
    plan_digest: str
    status: AggregateQueryStatus
    budgets: AggregateQueryBudgets
    accepted_at: int
    expires_at: int
    certificate: AggregateTechnicalCertificate | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.query_id, 'CUBE_AGGREGATE_QUERY_ID_INVALID')
        if not isinstance(self.scope, ApplicationScope):
            raise ValueError('CUBE_AGGREGATE_SCOPE_INVALID')
        _identifier(self.issuer, 'CUBE_AGGREGATE_IDENTITY_INVALID')
        _identifier(self.subject, 'CUBE_AGGREGATE_IDENTITY_INVALID')
        _digest(self.request_digest, 'CUBE_AGGREGATE_REQUEST_DIGEST_INVALID')
        _digest(self.plan_digest, 'CUBE_AGGREGATE_PLAN_DIGEST_INVALID')
        if not isinstance(self.status, AggregateQueryStatus):
            raise ValueError('CUBE_AGGREGATE_STATUS_INVALID')
        if not isinstance(self.budgets, AggregateQueryBudgets):
            raise ValueError('CUBE_AGGREGATE_BUDGETS_INVALID')
        if (type(self.accepted_at) is not int or type(self.expires_at) is not int
                or self.accepted_at < 0
                or self.expires_at != self.accepted_at + self.budgets.ttl_seconds):
            raise ValueError('CUBE_AGGREGATE_EXPIRY_INVALID')
        if self.certificate is not None and self.certificate.plan_digest != self.plan_digest:
            raise ValueError('CUBE_AGGREGATE_CERTIFICATE_PLAN_MISMATCH')
        if self.status == AggregateQueryStatus.SEALED and self.certificate is None:
            raise ValueError('CUBE_AGGREGATE_CERTIFICATE_REQUIRED')
        if self.status == AggregateQueryStatus.FAILED:
            _identifier(self.error_code, 'CUBE_AGGREGATE_ERROR_REQUIRED')
        elif self.error_code is not None:
            raise ValueError('CUBE_AGGREGATE_ERROR_UNEXPECTED')

    def transition(self, target: AggregateQueryStatus, *,
                   certificate: AggregateTechnicalCertificate | None = None,
                   error_code: str | None = None) -> 'AggregateQueryRecord':
        if not isinstance(target, AggregateQueryStatus) or target not in _TRANSITIONS[self.status]:
            raise ValueError('CUBE_AGGREGATE_STATUS_TRANSITION_INVALID')
        if target in (AggregateQueryStatus.COMPUTED, AggregateQueryStatus.SEALED):
            certificate = certificate or self.certificate
            if certificate is None:
                raise ValueError('CUBE_AGGREGATE_CERTIFICATE_REQUIRED')
        elif target != AggregateQueryStatus.FAILED:
            certificate = self.certificate
        return replace(self, status=target, certificate=certificate,
                       error_code=error_code)

    def request_cancel(self) -> 'AggregateQueryRecord':
        if self.status in (AggregateQueryStatus.ACCEPTED, AggregateQueryStatus.READY,
                           AggregateQueryStatus.COMPUTED):
            return self.transition(AggregateQueryStatus.CANCELLED)
        if self.status == AggregateQueryStatus.RUNNING:
            return self.transition(AggregateQueryStatus.CANCEL_REQUESTED)
        if self.status in (AggregateQueryStatus.CANCEL_REQUESTED,
                           AggregateQueryStatus.CANCELLED):
            return self
        raise ValueError('CUBE_AGGREGATE_CANCEL_NOT_AVAILABLE')


@dataclass(frozen=True, slots=True)
class AggregateCursor:
    query_id: str
    scope: ApplicationScope
    issuer: str
    subject: str
    request_digest: str
    result_digest: str
    page_size: int
    last_ordinal: int
    expires_at: int

    def __post_init__(self) -> None:
        _identifier(self.query_id, 'CUBE_AGGREGATE_CURSOR_INVALID')
        if not isinstance(self.scope, ApplicationScope):
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
        _identifier(self.issuer, 'CUBE_AGGREGATE_CURSOR_INVALID')
        _identifier(self.subject, 'CUBE_AGGREGATE_CURSOR_INVALID')
        _digest(self.request_digest, 'CUBE_AGGREGATE_CURSOR_INVALID')
        _digest(self.result_digest, 'CUBE_AGGREGATE_CURSOR_INVALID')
        _positive(self.page_size, MAX_PAGE_SIZE, 'CUBE_AGGREGATE_CURSOR_INVALID')
        if type(self.last_ordinal) is not int or self.last_ordinal < 0:
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
        if type(self.expires_at) is not int or self.expires_at < 0:
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')

    def wire(self) -> dict:
        return {'version': 1, 'queryId': self.query_id,
                'workspaceId': self.scope.workspace_id,
                'applicationId': self.scope.application_id,
                'issuer': self.issuer, 'subject': self.subject,
                'requestDigest': self.request_digest,
                'resultDigest': self.result_digest,
                'pageSize': self.page_size, 'lastOrdinal': self.last_ordinal,
                'expiresAt': self.expires_at}


class AggregateCursorCodec:
    def __init__(self, secret: bytes):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('CUBE_AGGREGATE_CURSOR_SECRET_INVALID')
        self._secret = secret

    @staticmethod
    def _encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

    @staticmethod
    def _decode(value: str) -> bytes:
        if type(value) is not str or not value or len(value) > 4096:
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
        try:
            return base64.b64decode(value + '=' * (-len(value) % 4),
                                    altchars=b'-_', validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID') from error

    def pack(self, cursor: AggregateCursor) -> str:
        if not isinstance(cursor, AggregateCursor):
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
        payload = _canonical(cursor.wire())
        signature = hmac.new(self._secret, payload, sha256).digest()
        return self._encode(payload) + '.' + self._encode(signature)

    def unpack(self, token: str, *, scope: ApplicationScope, issuer: str,
               subject: str, now: int | None = None) -> AggregateCursor:
        if type(token) is not str or token.count('.') != 1:
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
        encoded, encoded_signature = token.split('.')
        payload, signature = self._decode(encoded), self._decode(encoded_signature)
        if not hmac.compare_digest(hmac.new(self._secret, payload, sha256).digest(),
                                   signature):
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
        try:
            value = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID') from error
        expected = {'version', 'queryId', 'workspaceId', 'applicationId',
                    'issuer', 'subject', 'requestDigest', 'resultDigest',
                    'pageSize', 'lastOrdinal', 'expiresAt'}
        if type(value) is not dict or set(value) != expected or value['version'] != 1:
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
        cursor = AggregateCursor(value['queryId'],
            ApplicationScope(value['workspaceId'], value['applicationId']),
            value['issuer'], value['subject'], value['requestDigest'],
            value['resultDigest'], value['pageSize'], value['lastOrdinal'],
            value['expiresAt'])
        observed = int(time.time()) if now is None else now
        if (type(observed) is not int or cursor.scope != scope
                or cursor.issuer != issuer or cursor.subject != subject
                or cursor.expires_at < observed):
            raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
        return cursor


class AggregateAuthorization(Protocol):
    """Implementations perform a fresh current read-authority/context check."""

    def authorize_read(self, scope: ApplicationScope, *, issuer: str,
                       subject: str, pins: AggregateSourcePins | None = None) -> None: ...


class AggregateQueryRepository(Protocol):
    """Required durable PostgreSQL boundary; no fallback store is provided."""

    def insert(self, record: AggregateQueryRecord, *, normalized_request: dict) -> None: ...
    def get(self, scope: ApplicationScope, query_id: str) -> AggregateQueryRecord | None: ...
    def compare_and_transition(self, current: AggregateQueryRecord,
                               updated: AggregateQueryRecord) -> bool: ...
    def claim_query(self, scope: ApplicationScope, query_id: str,
                    claimant: str, *, lease_seconds: int = 30) -> dict | None: ...
    def store_computed(self, current: AggregateQueryRecord,
                       certificate: AggregateTechnicalCertificate,
                       rows: Sequence[dict], *, claim: dict
                       ) -> AggregateQueryRecord: ...
    def page(self, record: AggregateQueryRecord, *, after_ordinal: int,
             limit: int) -> tuple[Sequence[dict], bool]: ...
    def delete_expired_result(self, record: AggregateQueryRecord) -> None: ...

