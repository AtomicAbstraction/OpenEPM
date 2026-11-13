"""Verified OIDC identities for fixed-core application authorization.

Keycloak authenticates native callers. Open EPM remains
the sole authority for transactional workspace, application and dimensional
permissions. Cloudflare is transport only and no Cloudflare assertion is an
accepted identity credential.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from http.client import HTTPException
import json
import os
import re
import threading
from .observability import record_operational_signal
import time
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class AuthError(ValueError):
    """One safe machine-readable authentication failure.

    ``message`` remains useful to native clients and existing diagnostics, but
    transports must use ``code`` rather than parsing that prose.  The code is
    deliberately bounded and never contains token, claim or configuration
    values.
    """
    def __init__(self, message: str, status: int = 401, *,
                 code: str = 'AUTHENTICATION_FAILED'):
        super().__init__(message)
        self.status = status
        self.code = code


_jwks_cache: dict[str, tuple[float, dict]] = {}
_jwks_negative_cache: dict[str, float] = {}
_jwks_last_fetch: dict[str, float] = {}
_jwks_flights: dict[str, threading.Event] = {}
_jwks_lock = threading.Lock()
_JWKS_FETCH_ATTEMPTS = 3
_JWKS_FETCH_TIMEOUT_SECONDS = 2
_JWKS_FETCH_RETRY_SECONDS = .1
_JWKS_NEGATIVE_CACHE_SECONDS = 2
_JWKS_REFRESH_THROTTLE_SECONDS = 1
_JWKS_SINGLE_FLIGHT_WAIT_SECONDS = 7
_ROLE_RANK = {'Reader': 1, 'Editor': 2, 'Administrator': 3}
_PERMISSION_RANK = {'read': 1, 'write': 2, 'admin': 3, 'workspace_admin': 3,
                    'rule_design': 1, 'rule_publish': 1, 'rule_run': 1}
_RULE_PERMISSION_COLUMN = {'rule_design': 'CanDesign',
                           'rule_publish': 'CanPublish', 'rule_run': 'CanRun'}


class _NoKeyRedirect(HTTPRedirectHandler):
    """Keep signing-key retrieval on the configured HTTPS endpoint."""
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def mode() -> str:
    value = os.environ.get('EPM_AUTH_MODE', 'local').lower()
    if value not in ('local', 'oidc'):
        raise AuthError('EPM_AUTH_MODE must be local or oidc', 503,
                        code='AUTH_CONFIGURATION_INVALID')
    return value


def _config(audience: str) -> tuple[str, str, str]:
    if mode() != 'oidc':
        raise AuthError('OIDC authentication is required', 503,
                        code='AUTH_CONFIGURATION_INVALID')
    issuer = os.environ.get('EPM_OIDC_ISSUER', '').strip()
    jwks_url = os.environ.get('EPM_OIDC_JWKS_URL', '').strip()
    issuer_parts, jwks_parts = urlparse(issuer), urlparse(jwks_url)
    allow_internal = os.environ.get(
        'EPM_OIDC_ALLOW_INTERNAL_HTTP_JWKS', '').strip()
    if allow_internal not in ('', '1'):
        raise AuthError('Configure trusted OIDC signing-key transport', 503,
                        code='AUTH_CONFIGURATION_INVALID')
    internal_key_path = (issuer_parts.path.rstrip('/') +
                         '/protocol/openid-connect/certs')
    internal_jwks = (
        allow_internal == '1' and jwks_parts.scheme == 'http' and
        jwks_parts.hostname == 'identity' and jwks_parts.port == 8080 and
        jwks_parts.netloc == 'identity:8080' and
        jwks_parts.path == internal_key_path and not jwks_parts.query)
    secure_jwks = jwks_parts.scheme == 'https'
    if (issuer_parts.scheme != 'https' or not issuer_parts.netloc or
            issuer_parts.username or issuer_parts.password or
            issuer_parts.query or issuer_parts.fragment or
            not (secure_jwks or internal_jwks) or not jwks_parts.netloc or
            jwks_parts.username or jwks_parts.password or
            jwks_parts.query or jwks_parts.fragment or len(issuer) > 512 or
            len(jwks_url) > 512):
        raise AuthError('Configure HTTPS OIDC issuer and trusted JWKS URL', 503,
                        code='AUTH_CONFIGURATION_INVALID')
    key = {'web': 'EPM_OIDC_AUD_WEB', 'mcp': 'EPM_OIDC_AUD_MCP'}.get(audience)
    if not key:
        raise AuthError('Unknown authentication audience', 500,
                        code='AUTH_AUDIENCE_CONFIGURATION_INVALID')
    expected = os.environ.get(key, '').strip()
    if not expected or len(expected) > 256:
        raise AuthError(f'Configure {key}', 503,
                        code='AUTH_CONFIGURATION_INVALID')
    other = ('EPM_OIDC_AUD_WEB' if audience == 'mcp'
             else 'EPM_OIDC_AUD_MCP')
    if expected == os.environ.get(other, '').strip():
        raise AuthError('OIDC MCP and web audiences must differ', 503,
                        code='AUTH_AUDIENCE_CONFIGURATION_INVALID')
    return jwks_url, issuer, expected


def _decode(segment: str) -> bytes:
    if not re.fullmatch(r'[A-Za-z0-9_-]+', segment):
        raise AuthError('Invalid Access token', code='AUTH_TOKEN_INVALID')
    try:
        return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))
    except (ValueError, binascii.Error) as error:
        raise AuthError('Invalid Access token', code='AUTH_TOKEN_INVALID') from error


def _fetch_jwks(domain: str) -> dict:
    url = domain if domain.startswith(('https://', 'http://')) else \
        f'https://{domain}/cdn-cgi/access/certs'
    request = Request(url,
                      headers={'Accept': 'application/json'})
    last_error = None
    for attempt in range(_JWKS_FETCH_ATTEMPTS):
        try:
            with build_opener(_NoKeyRedirect()).open(
                    request, timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as response:
                body = response.read(131073)
            break
        except (OSError, HTTPException) as error:
            last_error = error
            if attempt + 1 < _JWKS_FETCH_ATTEMPTS:
                time.sleep(_JWKS_FETCH_RETRY_SECONDS)
    else:
        raise AuthError(
            'Could not verify identity-provider signing keys', 503,
            code='AUTH_SIGNING_KEYS_UNAVAILABLE') from last_error
    try:
        if len(body) > 131072:
            raise ValueError('Certificate response is too large')
        keys = json.loads(body)
        if not isinstance(keys, dict) or not isinstance(keys.get('keys'), list):
            raise ValueError('Invalid certificate response')
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise AuthError('Could not verify identity-provider signing keys', 503,
                        code='AUTH_SIGNING_KEYS_UNAVAILABLE') from error
    return keys


def _jwks(domain: str, *, refresh: bool = False) -> dict:
    now = time.monotonic()
    with _jwks_lock:
        cached = _jwks_cache.get(domain)
        if cached and cached[0] > now and (not refresh or
                now - _jwks_last_fetch.get(domain, 0)
                < _JWKS_REFRESH_THROTTLE_SECONDS):
            return cached[1]
        if _jwks_negative_cache.get(domain, 0) > now:
            raise AuthError('Could not verify identity-provider signing keys', 503,
                            code='AUTH_SIGNING_KEYS_UNAVAILABLE')
        flight = _jwks_flights.get(domain)
        leader = flight is None
        if leader:
            flight = threading.Event()
            _jwks_flights[domain] = flight
    if not leader:
        if not flight.wait(_JWKS_SINGLE_FLIGHT_WAIT_SECONDS):
            raise AuthError('Could not verify identity-provider signing keys', 503,
                            code='AUTH_SIGNING_KEYS_UNAVAILABLE')
        with _jwks_lock:
            cached = _jwks_cache.get(domain)
            if cached and cached[0] > time.monotonic():
                return cached[1]
        raise AuthError('Could not verify identity-provider signing keys', 503,
                        code='AUTH_SIGNING_KEYS_UNAVAILABLE')
    try:
        keys = _fetch_jwks(domain)
    except Exception:
        record_operational_signal('signing_key_available',False)
        with _jwks_lock:
            _jwks_negative_cache[domain] = (
                time.monotonic() + _JWKS_NEGATIVE_CACHE_SECONDS)
        raise
    else:
        record_operational_signal('signing_key_available',True)
        with _jwks_lock:
            fetched = time.monotonic()
            _jwks_cache[domain] = (fetched + 300, keys)
            _jwks_last_fetch[domain] = fetched
            _jwks_negative_cache.pop(domain, None)
        return keys
    finally:
        with _jwks_lock:
            completed = _jwks_flights.pop(domain, None)
            if completed:
                completed.set()


def reset_jwks_cache_for_tests() -> None:
    """Clear bounded signing-key state; production code never calls this."""
    with _jwks_lock:
        _jwks_cache.clear()
        _jwks_negative_cache.clear()
        _jwks_last_fetch.clear()
        for flight in _jwks_flights.values():
            flight.set()
        _jwks_flights.clear()


def assert_oidc_readiness(
        audiences: tuple[str, ...] = ('mcp', 'web')) -> None:
    """Prove configured audiences and at least one usable signing key exist.

    This is deliberately a readiness operation, not token authentication.  It
    performs the same bounded, no-redirect JWKS retrieval used by admission and
    rejects an empty or structurally unusable key set.  It never logs issuer
    configuration or key material.
    """
    if (not audiences or len(audiences) > 2
            or any(audience not in ('mcp', 'web') for audience in audiences)
            or len(set(audiences)) != len(audiences)):
        raise AuthError('OIDC readiness audience selection is invalid', 503,
                        code='AUTH_AUDIENCE_CONFIGURATION_INVALID')
    urls = [_config(audience)[0] for audience in audiences]
    if len(set(urls)) != 1:
        raise AuthError('OIDC audiences must use one signing-key authority', 503,
                        code='AUTH_AUDIENCE_CONFIGURATION_INVALID')
    keys = _jwks(urls[0]).get('keys', [])
    usable = []
    for key in keys:
        if (not isinstance(key, dict)
                or not isinstance(key.get('kid'), str) or not key['kid']
                or key.get('kty') != 'RSA'
                or key.get('use', 'sig') != 'sig'
                or key.get('alg', 'RS256') != 'RS256'):
            continue
        try:
            public = rsa.RSAPublicNumbers(
                int.from_bytes(_decode(key['e']), 'big'),
                int.from_bytes(_decode(key['n']), 'big')).public_key()
            if public.key_size < 2048:
                continue
        except (ValueError, KeyError, TypeError):
            continue
        usable.append(key)
    if not usable:
        raise AuthError('Access signing key is unavailable', 503,
                        code='AUTH_SIGNING_KEYS_UNAVAILABLE')


def verify_access_jwt(token: str, audience: str, *, jwks: dict | None = None,
                      now: int | None = None) -> dict:
    """Return only verified identity fields; never trust caller-supplied email."""
    domain, issuer, expected_audience = _config(audience)
    if not isinstance(token, str) or len(token) > 16384:
        raise AuthError('OIDC access token is required',
                        code='AUTH_TOKEN_REQUIRED')
    parts = token.split('.')
    if len(parts) != 3:
        raise AuthError('Invalid Access token', code='AUTH_TOKEN_INVALID')
    try:
        header = json.loads(_decode(parts[0]))
        claim = json.loads(_decode(parts[1]))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AuthError('Invalid Access token', code='AUTH_TOKEN_INVALID') from error
    if (not isinstance(header, dict) or header.get('alg') != 'RS256' or
            not isinstance(header.get('kid'), str) or not header['kid'] or
            any(item in header for item in ('crit','jku','x5u','enc'))):
        raise AuthError('Unsupported Access token signature',
                        code='AUTH_TOKEN_SIGNATURE_INVALID')
    if (not isinstance(header.get('typ'), str) or
            header['typ'].lower() not in ('at+jwt','application/at+jwt')):
        raise AuthError('OIDC bearer must be a JWT access token',
                        code='AUTH_TOKEN_INVALID')
    if not isinstance(claim, dict):
        raise AuthError('Invalid Access token', code='AUTH_TOKEN_INVALID')
    keys = jwks if jwks is not None else _jwks(domain)
    def matching(source):
        return [key for key in source.get('keys', []) if isinstance(key, dict) and
                key.get('kid') == header['kid'] and key.get('kty') == 'RSA' and
                key.get('use', 'sig') == 'sig' and
                key.get('alg', 'RS256') == 'RS256']
    candidates = matching(keys)
    if not candidates and jwks is None:
        candidates = matching(_jwks(domain, refresh=True))
    if len(candidates) != 1:
        raise AuthError('Access signing key is unavailable',
                        code='AUTH_SIGNING_KEY_UNKNOWN')
    def verify_signature(key: dict) -> None:
        public = rsa.RSAPublicNumbers(
            int.from_bytes(_decode(key['e']), 'big'),
            int.from_bytes(_decode(key['n']), 'big')).public_key()
        if public.key_size < 2048:
            raise ValueError('RSA signing key is too small')
        public.verify(_decode(parts[2]), f'{parts[0]}.{parts[1]}'.encode(),
                      padding.PKCS1v15(), hashes.SHA256())

    try:
        verify_signature(candidates[0])
    except (InvalidSignature, ValueError, KeyError, TypeError) as first_error:
        # Providers may rotate key material while retaining a kid.  A cached
        # matching kid therefore cannot make signature failure terminal until
        # one bounded refresh is attempted.  _jwks owns refresh throttling,
        # negative caching and single-flight work, so hostile signatures cannot
        # create one outbound request per caller.
        if jwks is not None:
            raise AuthError('Invalid Access token signature',
                            code='AUTH_TOKEN_SIGNATURE_INVALID') from first_error
        refreshed = matching(_jwks(domain, refresh=True))
        if len(refreshed) != 1:
            raise AuthError('Invalid Access token signature',
                            code='AUTH_TOKEN_SIGNATURE_INVALID') from first_error
        try:
            verify_signature(refreshed[0])
        except (InvalidSignature, ValueError, KeyError, TypeError) as error:
            raise AuthError('Invalid Access token signature',
                            code='AUTH_TOKEN_SIGNATURE_INVALID') from error
    current = int(time.time()) if now is None else int(now)
    audiences = claim.get('aud')
    if isinstance(audiences, str):
        audiences = [audiences]
    if (claim.get('iss') != issuer or not isinstance(audiences, list) or
            expected_audience not in audiences):
        raise AuthError('Access token is for another application',
                        code='AUTH_TOKEN_AUDIENCE_INVALID')
    if (not isinstance(claim.get('exp'), (int, float)) or
            claim['exp'] <= current - 30 or
            not isinstance(claim.get('iat'), (int, float)) or
            claim['iat'] > current + 30 or
            ('nbf' in claim and (not isinstance(claim['nbf'], (int, float)) or
                                claim['nbf'] > current + 30))):
        raise AuthError('Access token is expired or not yet valid',
                        code='AUTH_TOKEN_EXPIRED')
    subject, login_id = claim.get('sub'), claim.get('preferred_username')
    if (not isinstance(subject, str) or not subject or len(subject) > 256 or
            not isinstance(login_id, str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._@+-]{0,199}',
                                login_id)):
        raise AuthError('Access token has no bounded native user identity',
                        code='AUTH_IDENTITY_INVALID')
    groups=claim.get('groups',[])
    if (not isinstance(groups,list) or len(groups)>100
            or any(not isinstance(group,str) or not group
                   or len(group)>300 or '*' in group for group in groups)
            or len(groups)!=len(set(groups))):
        raise AuthError('Access token has invalid group claims',
                        code='AUTH_GROUPS_INVALID')
    return {'issuer': issuer, 'subject': subject, 'loginId': login_id,
            'groups':tuple(sorted(groups)), 'issuedAt': int(claim['iat'])}


def verified_identity_binding(token: str, audience: str) -> dict:
    """Return the authenticated caller's safe self-binding for client setup."""
    principal = verify_access_jwt(token, audience)
    _, _, expected_audience = _config(audience)
    return {
        'issuer': principal['issuer'],
        'subject': principal['subject'],
        'loginIdSha256': hashlib.sha256(
            principal['loginId'].encode('utf-8')).hexdigest(),
        'audience': expected_audience,
    }


def access_token(headers) -> str:
    """Return the configured signed assertion; a browser cookie is not identity."""
    if not headers:
        return ''
    for name, value in headers.items():
        if name.lower() == 'authorization':
            match = re.fullmatch(r'Bearer ([A-Za-z0-9_.-]+)', value) if isinstance(value,str) else None
            return match.group(1) if match else ''
    return ''


