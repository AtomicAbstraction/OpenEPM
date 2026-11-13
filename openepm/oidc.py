"""Bounded in-memory OIDC device authorization for managed SDK clients.

The provider is intended for external Python and terminal clients that cannot safely
receive a loopback browser callback.  It never persists access or refresh
tokens and exposes only the short-lived user prompt returned by the issuer.
"""
from __future__ import annotations

from base64 import urlsafe_b64encode
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPException, IncompleteRead
import json
import secrets
import ssl
import threading
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from ._client_identity import USER_AGENT


class OidcDeviceError(RuntimeError):
    """Safe failure with bounded diagnostics, never raw issuer response text."""

    _PHASES = frozenset({"device_authorization", "device_token", "refresh", "revocation"})
    _FAILURES = frozenset({"transport", "invalid_response", "protocol_error",
                          "authorization_required", "authorization_expired",
                          "revocation_required"})
    _OAUTH_ERRORS = frozenset({"invalid_request", "invalid_client", "invalid_grant",
        "unauthorized_client", "unsupported_grant_type", "invalid_scope",
        "access_denied", "authorization_pending", "slow_down", "expired_token",
        "server_error", "temporarily_unavailable", "invalid_token"})

    def __init__(self, message: str, *, phase: str | None = None,
                 failure: str | None = None, http_status: int | None = None,
                 oauth_error: object = None):
        super().__init__(message)
        self.phase = phase if isinstance(phase, str) and phase in self._PHASES else None
        self.failure = (failure if isinstance(failure, str)
                        and failure in self._FAILURES else None)
        self.http_status = (http_status if type(http_status) is int
                            and 100 <= http_status <= 599 else None)
        self.oauth_error = (oauth_error if isinstance(oauth_error, str)
                            and oauth_error in self._OAUTH_ERRORS else None)

    def diagnostics(self) -> dict:
        """Return only fixed enums and an HTTP status, not exception text."""
        return {key: value for key, value in {
            "phase": self.phase, "failure": self.failure,
            "httpStatus": self.http_status, "oauthError": self.oauth_error,
        }.items() if value is not None}


@contextmanager
def _error_context(phase: str):
    try:
        yield
    except OidcDeviceError as error:
        if error.phase is None:
            error.phase = phase
        raise


class _OidcTransportError(OidcDeviceError):
    """A network failure that leaves a pending device exchange retryable."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationPrompt:
    verification_uri: str
    user_code: str
    verification_uri_complete: str | None
    expires_in: int
    interval: int


class OidcDeviceTokenProvider:
    """Acquire and refresh one user's MCP token entirely in memory."""

    def __init__(self, issuer: str, *, client_id: str = "openepm-mcp",
                 scope: str = "openid profile", ca_file: str | None = None,
                 timeout_seconds: float = 10,
                 clock: Callable[[], float] = time.time,
                 sleeper: Callable[[float], None] = time.sleep):
        parsed = urlsplit(issuer) if isinstance(issuer, str) else None
        if (parsed is None or parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or issuer.endswith("/")):
            raise ValueError("OIDC issuer must be a credential-free HTTPS URL")
        if (not isinstance(client_id, str) or not client_id
                or len(client_id) > 200 or any(c in client_id for c in "\r\n\x00")):
            raise ValueError("OIDC client identifier is invalid")
        scopes = scope.split() if isinstance(scope, str) else []
        if (not scopes or len(scopes) > 16 or any(
                not value or len(value) > 100 or not value.replace("-", "")
                .replace("_", "").replace(".", "").isalnum()
                for value in scopes)):
            raise ValueError("OIDC scope is invalid")
        if (isinstance(timeout_seconds, bool)
                or not isinstance(timeout_seconds, (int, float))
                or not 0 < float(timeout_seconds) <= 30):
            raise ValueError("OIDC timeout must be greater than zero and at most 30")
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
        self._device_endpoint = issuer + "/protocol/openid-connect/auth/device"
        self._token_endpoint = issuer + "/protocol/openid-connect/token"
        self._revocation_endpoint = issuer + "/protocol/openid-connect/revoke"
        self._client_id, self._scope = client_id, " ".join(scopes)
        self._timeout = float(timeout_seconds)
        self._clock, self._sleep = clock, sleeper
        self._lock = threading.RLock()
        self._device_code: str | None = None
        self._device_verifier: str | None = None
        self._device_expires_at = 0.0
        self._device_retry_not_before = 0.0
        self._interval = 5
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._access_expires_at = 0.0
        self._revocation_pending = False

    def begin(self) -> DeviceAuthorizationPrompt:
        """Start a fresh device login and return only the user-facing prompt."""
        with self._lock, _error_context("device_authorization"):
            if self._revocation_pending:
                raise OidcDeviceError(
                    "OIDC session revocation must be retried before login",
                    failure="revocation_required")
            self._clear_device_authorization()
            verifier = secrets.token_urlsafe(32)
            challenge = urlsafe_b64encode(
                sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
            status, value = self._post_form(self._device_endpoint, {
                "client_id": self._client_id, "scope": self._scope,
                "code_challenge": challenge, "code_challenge_method": "S256"})
            if status != 200:
                raise OidcDeviceError("OIDC device authorization failed",
                    failure="protocol_error", http_status=status,
                    oauth_error=value.get("error"))
            device = self._bounded(value.get("device_code"), 16384)
            user = self._bounded(value.get("user_code"), 256)
            verification = self._https_url(value.get("verification_uri"))
            complete = value.get("verification_uri_complete")
            if complete is not None:
                complete = self._https_url(complete)
            expires = value.get("expires_in")
            interval = value.get("interval", 5)
            if (type(expires) is not int or not 30 <= expires <= 1800
                    or type(interval) is not int or not 1 <= interval <= 30):
                raise OidcDeviceError("OIDC device authorization response is invalid", failure="invalid_response")
            self._device_code, self._device_verifier = device, verifier
            self._device_expires_at = self._clock() + expires
            self._interval = interval
            self._access_token = self._refresh_token = None
            self._access_expires_at = 0
            return DeviceAuthorizationPrompt(
                verification, user, complete, expires, interval)

    def await_token(self) -> None:
        """Poll the issuer until the user completes or rejects the login."""
        with self._lock, _error_context("device_token"):
            if self._device_code is None or self._device_verifier is None:
                raise OidcDeviceError("OIDC device authorization has not started",
                                      failure="authorization_required")
            while self._clock() < self._device_expires_at:
                delay = self._device_retry_not_before - self._clock()
                if delay > 0:
                    self._sleep(delay)
                    continue
                self._device_retry_not_before = 0.0
                try:
                    status, value = self._post_form(self._token_endpoint, {
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "client_id": self._client_id,
                        "device_code": self._device_code,
                        "code_verifier": self._device_verifier})
                except _OidcTransportError:
                    self._interval *= 2
                    self._device_retry_not_before = min(
                        self._device_expires_at, self._clock() + self._interval)
                    raise
                except OidcDeviceError:
                    self._clear_device_authorization()
                    raise
                if status == 200:
                    try:
                        self._accept_tokens(value)
                    except OidcDeviceError as token_error:
                        token_error.http_status = 200
                        raise
                    finally:
                        # A one-time token exchange is terminal even if its
                        # successful response contains malformed credentials.
                        self._clear_device_authorization()
                    return
                response_error = value.get("error")
                if response_error == "authorization_pending":
                    self._sleep(self._interval)
                    continue
                if response_error == "slow_down":
                    self._interval += 5
                    self._sleep(self._interval)
                    continue
                self._clear_device_authorization()
                if response_error == "access_denied":
                    raise OidcDeviceError("OIDC device authorization was denied",
                        failure="protocol_error", http_status=status,
                        oauth_error=response_error)
                if response_error == "expired_token":
                    raise OidcDeviceError("OIDC device authorization expired",
                        failure="protocol_error", http_status=status,
                        oauth_error=response_error)
                raise OidcDeviceError("OIDC device token request failed",
                    failure="protocol_error", http_status=status,
                    oauth_error=response_error)
            self._clear_device_authorization()
            raise OidcDeviceError("OIDC device authorization expired",
                                  failure="authorization_expired")

    def __call__(self) -> str:
        """Return a current access token, refreshing it in memory when needed."""
        with self._lock, _error_context("refresh"):
            if self._access_token is None:
                raise OidcDeviceError("OIDC device authorization is required",
                                      failure="authorization_required")
            if self._clock() + 30 < self._access_expires_at:
                return self._access_token
            if self._refresh_token is None:
                self._clear_tokens()
                raise OidcDeviceError("OIDC device authorization must be renewed",
                                      failure="authorization_required")
            status, value = self._post_form(self._token_endpoint, {
                "grant_type": "refresh_token", "client_id": self._client_id,
                "refresh_token": self._refresh_token})
            if status != 200:
                self._clear_tokens()
                raise OidcDeviceError("OIDC token refresh failed",
                    failure="protocol_error", http_status=status,
                    oauth_error=value.get("error"))
            try:
                self._accept_tokens(value, preserve_refresh=True)
            except OidcDeviceError as error:
                error.http_status = 200
                raise
            return self._access_token

    def close(self) -> None:
        """Forget all in-memory credentials immediately."""
        with self._lock:
            self._clear_device_authorization()
            self._clear_tokens()
            self._revocation_pending = False

    def revoke(self) -> bool:
        """Revoke the refresh-token session, retaining it only for safe retry.

        Local access is disabled before contacting the issuer.  If that call
        fails, the refresh token is kept inaccessible to ``__call__`` so a
        later ``revoke`` can still establish remote invalidation. Return ``True``
        only when the issuer accepts an actual revocation request; ``False``
        means no refresh credential remained to send. Existing callers may
        continue ignoring this additive result.
        """
        with self._lock, _error_context("revocation"):
            refresh = self._refresh_token
            self._clear_device_authorization()
            self._access_token = None
            self._access_expires_at = 0
            if refresh is None:
                self._revocation_pending = False
                return False
            self._revocation_pending = True
            try:
                status = self._post_revoke(refresh)
            except OidcDeviceError:
                raise
            if status not in (200, 204):
                raise OidcDeviceError("OIDC session revocation failed",
                    failure="protocol_error", http_status=status)
            self._refresh_token = None
            self._revocation_pending = False
            return True

    def _accept_tokens(self, value: dict, *, preserve_refresh: bool = False) -> None:
        access = self._bounded(value.get("access_token"), 16384)
        refresh_value = value.get("refresh_token")
        refresh = (self._refresh_token if preserve_refresh and refresh_value is None
                   else self._bounded(refresh_value, 16384))
        expires = value.get("expires_in")
        if (value.get("token_type") != "Bearer" or type(expires) is not int
                or not 30 <= expires <= 86400 or refresh is None):
            raise OidcDeviceError("OIDC token response is invalid", failure="invalid_response")
        self._access_token, self._refresh_token = access, refresh
        self._access_expires_at = self._clock() + expires
        self._revocation_pending = False

    def _clear_device_authorization(self) -> None:
        self._device_code = self._device_verifier = None
        self._device_expires_at = 0.0
        self._device_retry_not_before = 0.0

    def _clear_tokens(self) -> None:
        self._access_token = self._refresh_token = None
        self._access_expires_at = 0

    @staticmethod
    def _bounded(value: object, maximum: int) -> str:
        if (not isinstance(value, str) or not value or len(value) > maximum
                or any(c in value for c in "\r\n\x00")):
            raise OidcDeviceError("OIDC response contains an invalid credential", failure="invalid_response")
        return value

    @staticmethod
    def _https_url(value: object) -> str:
        if not isinstance(value, str):
            raise OidcDeviceError("OIDC verification URL is invalid", failure="invalid_response")
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment):
            raise OidcDeviceError("OIDC verification URL is invalid", failure="invalid_response")
        return value

    def _post_form(self, endpoint: str, values: dict[str, str]) -> tuple[int, dict]:
        request = Request(endpoint, data=urlencode(values).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json",
                     "User-Agent": USER_AGENT}, method="POST")
        try:
            response = self._opener.open(request, timeout=self._timeout)
        except HTTPError as error:
            response, status = error, error.code
        except (URLError, TimeoutError, OSError, IncompleteRead) as error:
            raise _OidcTransportError("OIDC endpoint is unavailable",
                                      failure="transport") from error
        except HTTPException as error:
            raise OidcDeviceError("OIDC response is invalid",
                                  failure="invalid_response") from error
        else:
            status = response.status
        try:
            try:
                raw = response.read(65537)
            finally:
                response.close()
        except (URLError, TimeoutError, OSError, IncompleteRead) as error:
            raise _OidcTransportError("OIDC endpoint is unavailable",
                failure="transport", http_status=status) from error
        except HTTPException as error:
            raise OidcDeviceError("OIDC response is invalid",
                failure="invalid_response", http_status=status) from error
        if len(raw) > 65536:
            raise OidcDeviceError("OIDC response exceeds the configured bound",
                                  failure="invalid_response", http_status=status)
        try:
            decoded = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as error:
            raise OidcDeviceError("OIDC response is invalid JSON",
                failure="invalid_response", http_status=status) from error
        if not isinstance(decoded, dict):
            raise OidcDeviceError("OIDC response is invalid",
                                  failure="invalid_response", http_status=status)
        return status, decoded

    def _post_revoke(self, refresh_token: str) -> int:
        request = Request(self._revocation_endpoint, data=urlencode({
            "client_id": self._client_id, "token": refresh_token,
            "token_type_hint": "refresh_token"}).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": USER_AGENT}, method="POST")
        try:
            response = self._opener.open(request, timeout=self._timeout)
        except HTTPError as error:
            response, status = error, error.code
        except (URLError, TimeoutError, OSError, HTTPException) as error:
            raise OidcDeviceError("OIDC session revocation failed",
                                  failure="transport") from error
        else:
            status = response.status
        try:
            try:
                if len(response.read(1025)) > 1024:
                    raise OidcDeviceError("OIDC revocation response exceeds the configured bound",
                        failure="invalid_response", http_status=status)
            finally:
                response.close()
        except (URLError, TimeoutError, OSError, HTTPException) as error:
            raise OidcDeviceError("OIDC session revocation failed",
                failure="transport", http_status=status) from error
        return status
