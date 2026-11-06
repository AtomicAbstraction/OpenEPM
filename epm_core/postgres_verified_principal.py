"""Server-owned identity handoff after cryptographic HTTP authentication.

The serialized representation is private parent-to-worker protocol data.  It is
never accepted from an MCP argument or HTTP header.  Business authorization is
still rechecked from PostgreSQL for every operation.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import re


_FORMAT_VERSION = 3
_DIGEST = re.compile(r'[0-9a-f]{64}')
_bound_principal: ContextVar[VerifiedPrincipal | None] = ContextVar(
    'openepm_internal_verified_principal', default=None)


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    """A bounded identity created only from a successfully verified token."""

    issuer: str
    subject: str
    groups: tuple[str, ...]
    login_id: str
    login_id_sha256: str
    audience_kind: str
    audience: str
    issued_at: int = 0
    version: int = _FORMAT_VERSION

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != _FORMAT_VERSION:
            raise ValueError('VERIFIED_PRINCIPAL_VERSION_INVALID')
        if self.audience_kind not in ('mcp', 'web'):
            raise ValueError('VERIFIED_PRINCIPAL_AUDIENCE_KIND_INVALID')
        if (not isinstance(self.audience, str) or not self.audience
                or len(self.audience) > 256):
            raise ValueError('VERIFIED_PRINCIPAL_AUDIENCE_INVALID')
        if type(self.issued_at) is not int or self.issued_at < 0:
            raise ValueError('VERIFIED_PRINCIPAL_ISSUED_AT_INVALID')
        if (not isinstance(self.issuer, str) or not self.issuer
                or len(self.issuer) > 512):
            raise ValueError('VERIFIED_PRINCIPAL_ISSUER_INVALID')
        if (not isinstance(self.subject, str) or not self.subject
                or len(self.subject) > 256):
            raise ValueError('VERIFIED_PRINCIPAL_SUBJECT_INVALID')
        if (not isinstance(self.groups, tuple) or len(self.groups) > 100
                or any(not isinstance(group, str) or not group
                       or len(group) > 300 or '*' in group
                       for group in self.groups)
                or tuple(sorted(self.groups)) != self.groups
                or len(set(self.groups)) != len(self.groups)):
            raise ValueError('VERIFIED_PRINCIPAL_GROUPS_INVALID')
        if (not isinstance(self.login_id_sha256, str)
                or not _DIGEST.fullmatch(self.login_id_sha256)):
            raise ValueError('VERIFIED_PRINCIPAL_LOGIN_ID_DIGEST_INVALID')
        if (not isinstance(self.login_id, str) or not self.login_id
                or len(self.login_id) > 255
                or self.login_id != self.login_id.strip()
                or any(ord(character) < 32 for character in self.login_id)
                or hashlib.sha256(self.login_id.encode('utf-8')).hexdigest()
                   != self.login_id_sha256):
            raise ValueError('VERIFIED_PRINCIPAL_LOGIN_ID_INVALID')

    def serialized(self) -> dict:
        return {
            'version': self.version,
            'audienceKind': self.audience_kind,
            'audience': self.audience,
            'issuer': self.issuer,
            'subject': self.subject,
            'groups': list(self.groups),
            'loginId': self.login_id,
            'loginIdSha256': self.login_id_sha256,
            'issuedAt': self.issued_at,
        }


def deserialize_verified_principal(raw: object) -> VerifiedPrincipal:
    if not isinstance(raw, dict) or set(raw) != {
            'version', 'audienceKind', 'audience', 'issuer', 'subject',
            'groups', 'loginId', 'loginIdSha256', 'issuedAt'} \
            or not isinstance(raw.get('groups'), list):
        raise ValueError('VERIFIED_PRINCIPAL_FORMAT_INVALID')
    return VerifiedPrincipal(
        version=raw['version'], audience_kind=raw['audienceKind'],
        audience=raw['audience'], issuer=raw['issuer'], subject=raw['subject'],
        groups=tuple(raw['groups']), login_id=raw['loginId'],
        login_id_sha256=raw['loginIdSha256'], issued_at=raw['issuedAt'])


def verified_principal_from_claims(claims: dict, audience_kind: str) -> VerifiedPrincipal:
    """Seal already-verified token claims with server-owned audience config."""
    from .postgres_auth import _config

    if not isinstance(claims, dict):
        raise ValueError('VERIFIED_PRINCIPAL_CLAIMS_INVALID')
    _, issuer, audience = _config(audience_kind)
    if claims.get('issuer') != issuer:
        raise ValueError('VERIFIED_PRINCIPAL_ISSUER_INVALID')
    login_id = claims.get('loginId')
    if not isinstance(login_id, str) or not login_id:
        raise ValueError('VERIFIED_PRINCIPAL_LOGIN_ID_INVALID')
    return VerifiedPrincipal(
        issuer=issuer, subject=claims.get('subject'),
        groups=tuple(claims.get('groups', ())),
        login_id=login_id,
        login_id_sha256=hashlib.sha256(login_id.encode('utf-8')).hexdigest(),
        audience_kind=audience_kind, audience=audience,
        issued_at=claims.get('issuedAt'))


def validate_principal_configuration(principal: VerifiedPrincipal) -> None:
    """Recheck local issuer/audience configuration without external I/O."""
    from .postgres_auth import _config

    _, issuer, audience = _config(principal.audience_kind)
    if principal.issuer != issuer or principal.audience != audience:
        raise ValueError('VERIFIED_PRINCIPAL_CONFIGURATION_MISMATCH')


@contextmanager
def bind_verified_principal(principal: VerifiedPrincipal):
    if not isinstance(principal, VerifiedPrincipal):
        raise ValueError('VERIFIED_PRINCIPAL_REQUIRED')
    token = _bound_principal.set(principal)
    try:
        yield principal
    finally:
        _bound_principal.reset(token)


def current_verified_principal() -> VerifiedPrincipal | None:
    return _bound_principal.get()


def principal_claims(assertion: str, audience_kind: str) -> dict:
    """Use the private verified handoff, falling back for direct trusted calls."""
    principal = current_verified_principal()
    if principal is not None:
        if principal.audience_kind != audience_kind:
            raise ValueError('VERIFIED_PRINCIPAL_AUDIENCE_KIND_MISMATCH')
        validate_principal_configuration(principal)
        return {
            'issuer': principal.issuer, 'subject': principal.subject,
            'groups': principal.groups,
            'loginId': principal.login_id,
            'loginIdSha256': principal.login_id_sha256,
            'audience': principal.audience,
            'issuedAt': principal.issued_at,
        }
    from .postgres_auth import verify_access_jwt
    claims = verify_access_jwt(assertion, audience_kind)
    sealed = verified_principal_from_claims(claims, audience_kind)
    return {
        **claims, 'loginIdSha256': sealed.login_id_sha256,
        'audience': sealed.audience,
    }


def verified_identity_binding_for_assertion(assertion: str,
                                             audience_kind: str) -> dict:
    claims = principal_claims(assertion, audience_kind)
    return {
        'issuer': claims['issuer'],
        'subject': claims['subject'],
        'loginIdSha256': claims['loginIdSha256'],
        'audience': claims['audience'],
    }
