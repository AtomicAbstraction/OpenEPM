"""Bounded in-memory OIDC device authorization for managed SDK clients.

The provider is intended for notebook and terminal clients that cannot safely
receive a loopback browser callback.  It never persists access or refresh
tokens and exposes only the short-lived user prompt returned by the issuer.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import ssl
import threading
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class OidcDeviceError(RuntimeError):
    """Safe device-authorization failure without provider response details."""


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
        self._device_expires_at = 0.0
        self._interval = 5
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._access_expires_at = 0.0
        self._revocation_pending = False

    def begin(self) -> DeviceAuthorizationPrompt:
        """Start a fresh device login and return only the user-facing prompt."""
        with self._lock:
            if self._revocation_pending:
                raise OidcDeviceError(
                    "OIDC session revocation must be retried before login")
            status, value = self._post_form(self._device_endpoint, {
                "client_id": self._client_id, "scope": self._scope})
            if status != 200:
                raise OidcDeviceError("OIDC device authorization failed")
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
                raise OidcDeviceError("OIDC device authorization response is invalid")
            self._device_code = device
            self._device_expires_at = self._clock() + expires
            self._interval = interval
            self._access_token = self._refresh_token = None
            self._access_expires_at = 0
            return DeviceAuthorizationPrompt(
                verification, user, complete, expires, interval)

    def await_token(self) -> None:
        """Poll the issuer until the user completes or rejects the login."""
        with self._lock:
            if self._device_code is None:
                raise OidcDeviceError("OIDC device authorization has not started")
            interval = self._interval
            while self._clock() < self._device_expires_at:
                status, value = self._post_form(self._token_endpoint, {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": self._client_id,
                    "device_code": self._device_code})
                if status == 200:
                    self._accept_tokens(value)
                    self._device_code = None
                    return
                error = value.get("error")
                if error == "authorization_pending":
                    self._sleep(interval)
                    continue
                if error == "slow_down":
                    interval = min(30, interval + 5)
                    self._sleep(interval)
                    continue
                self._device_code = None
                if error == "access_denied":
                    raise OidcDeviceError("OIDC device authorization was denied")
                if error == "expired_token":
                    raise OidcDeviceError("OIDC device authorization expired")
                raise OidcDeviceError("OIDC device token request failed")
            self._device_code = None
            raise OidcDeviceError("OIDC device authorization expired")

    def __call__(self) -> str:
        """Return a current access token, refreshing it in memory when needed."""
        with self._lock:
            if self._access_token is None:
                raise OidcDeviceError("OIDC device authorization is required")
            if self._clock() + 30 < self._access_expires_at:
                return self._access_token
            if self._refresh_token is None:
                self._clear_tokens()
                raise OidcDeviceError("OIDC device authorization must be renewed")
            status, value = self._post_form(self._token_endpoint, {
                "grant_type": "refresh_token", "client_id": self._client_id,
                "refresh_token": self._refresh_token})
            if status != 200:
                self._clear_tokens()
                raise OidcDeviceError("OIDC token refresh failed")
            self._accept_tokens(value, preserve_refresh=True)
            return self._access_token

    def close(self) -> None:
        """Forget all in-memory credentials immediately."""
        with self._lock:
            self._device_code = None
            self._clear_tokens()
            self._revocation_pending = False

    def revoke(self) -> None:
        """Revoke the refresh-token session, retaining it only for safe retry.

        Local access is disabled before contacting the issuer.  If that call
        fails, the refresh token is kept inaccessible to ``__call__`` so a
        later ``revoke`` can still establish remote invalidation.
        """
        with self._lock:
            refresh = self._refresh_token
            self._device_code = None
            self._access_token = None
            self._access_expires_at = 0
            if refresh is None:
                self._revocation_pending = False
                return
            self._revocation_pending = True
            try:
                status = self._post_revoke(refresh)
            except OidcDeviceError:
                raise
            if status not in (200, 204):
                raise OidcDeviceError("OIDC session revocation failed")
            self._refresh_token = None
            self._revocation_pending = False

    def _accept_tokens(self, value: dict, *, preserve_refresh: bool = False) -> None:
        access = self._bounded(value.get("access_token"), 16384)
        refresh_value = value.get("refresh_token")
        refresh = (self._refresh_token if preserve_refresh and refresh_value is None
                   else self._bounded(refresh_value, 16384))
        expires = value.get("expires_in")
        if (value.get("token_type") != "Bearer" or type(expires) is not int
                or not 30 <= expires <= 86400 or refresh is None):
            raise OidcDeviceError("OIDC token response is invalid")
        self._access_token, self._refresh_token = access, refresh
        self._access_expires_at = self._clock() + expires
        self._revocation_pending = False

    def _clear_tokens(self) -> None:
        self._access_token = self._refresh_token = None
        self._access_expires_at = 0

    @staticmethod
    def _bounded(value: object, maximum: int) -> str:
        if (not isinstance(value, str) or not value or len(value) > maximum
                or any(c in value for c in "\r\n\x00")):
            raise OidcDeviceError("OIDC response contains an invalid credential")
        return value

    @staticmethod
    def _https_url(value: object) -> str:
        if not isinstance(value, str):
            raise OidcDeviceError("OIDC verification URL is invalid")
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment):
            raise OidcDeviceError("OIDC verification URL is invalid")
        return value

    def _post_form(self, endpoint: str, values: dict[str, str]) -> tuple[int, dict]:
        request = Request(endpoint, data=urlencode(values).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"}, method="POST")
        try:
            response = self._opener.open(request, timeout=self._timeout)
        except HTTPError as error:
            response, status = error, error.code
        except (URLError, TimeoutError, OSError) as error:
            raise OidcDeviceError("OIDC endpoint is unavailable") from error
        else:
            status = response.status
        try:
            raw = response.read(65537)
        finally:
            response.close()
        if len(raw) > 65536:
            raise OidcDeviceError("OIDC response exceeds the configured bound")
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise OidcDeviceError("OIDC response is invalid JSON") from error
        if not isinstance(decoded, dict):
            raise OidcDeviceError("OIDC response is invalid")
        return status, decoded

    def _post_revoke(self, refresh_token: str) -> int:
        request = Request(self._revocation_endpoint, data=urlencode({
            "client_id": self._client_id, "token": refresh_token,
            "token_type_hint": "refresh_token"}).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        try:
            response = self._opener.open(request, timeout=self._timeout)
        except HTTPError as error:
            response, status = error, error.code
        except (URLError, TimeoutError, OSError) as error:
            raise OidcDeviceError("OIDC session revocation failed") from error
        else:
            status = response.status
        try:
            if len(response.read(1025)) > 1024:
                raise OidcDeviceError("OIDC revocation response exceeds the configured bound")
        finally:
            response.close()
        return status
