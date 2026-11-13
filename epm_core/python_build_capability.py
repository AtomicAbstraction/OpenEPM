"""Short-lived, least-privilege capabilities for isolated Python builders.

The token is deliberately not an OIDC token and cannot be presented to any
business publisher.  It is accepted only by :class:`PythonBuildReadBroker`,
which re-resolves the durable claim before returning bounded build inputs.
"""
from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
import binascii
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import re
import secrets
import time
from typing import Callable

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity


SOURCE_READ = "python.build.source.read"
CONTEXT_READ = "python.build.context.read"
PLAN_PROPOSE = "python.build.plan.propose"
BUILDER_ACTIONS = (SOURCE_READ, CONTEXT_READ, PLAN_PROPOSE)


def _b64(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class BuildCapabilityContext:
    scope: ApplicationScope
    identity: VerifiedIdentity
    build_id: str
    claim_generation: int
    program_id: str
    program_source_token: str
    environment_id: str
    environment_state_token: str
    environment_profile_version: int


class SignedBuildCapabilityProvider:
    """Mint and verify fixed-schema HMAC capabilities.

    Restart safety is intentional: replay fencing comes from the durable claim
    generation resolved by the broker, not process-local nonce memory.  A token
    may be reused for the few permitted reads during one live claim; after
    cancellation, recovery or re-claim its generation no longer verifies.
    """

    def __init__(self, secret: bytes, *, audience: str = "openepm-python-builder",
                 ttl_seconds: int = 75, clock=None, nonce_factory=None):
        if (type(secret) is not bytes or len(secret) < 32
                or type(audience) is not str or not audience
                or type(ttl_seconds) is not int or not 15 <= ttl_seconds <= 300):
            raise ValueError("PYTHON_BUILD_CAPABILITY_CONFIGURATION_INVALID")
        self._secret = secret
        self.audience = audience
        self.ttl_seconds = ttl_seconds
        self.clock = clock or (lambda: int(time.time()))
        self.nonce_factory = nonce_factory or (lambda: secrets.token_hex(16))

    def mint(self, *, scope: ApplicationScope, identity: VerifiedIdentity,
             build_id: str, program_id: str, program_source_token: str,
             environment_id: str, environment_state_token: str,
             environment_profile_version: int,
             claim_generation: int) -> str:
        context = BuildCapabilityContext(scope, identity, build_id,
            claim_generation, program_id, program_source_token, environment_id,
            environment_state_token,environment_profile_version)
        self._validate_context(context)
        now = self.clock()
        nonce = self.nonce_factory()
        if type(now) is not int or now < 0 or type(nonce) is not str or len(nonce) < 16:
            raise ValueError("PYTHON_BUILD_CAPABILITY_CONFIGURATION_INVALID")
        payload = {"version": 1, "kind": "openepm-python-build",
            "audience": self.audience, "issuedAt": now,
            "expiresAt": now + self.ttl_seconds, "nonce": nonce,
            "issuer": identity.issuer, "subjectId": identity.subject_id,
            "workspaceId": scope.workspace_id,
            "applicationId": scope.application_id, "buildId": build_id,
            "claimGeneration": claim_generation, "programId": program_id,
            "programSourceToken": program_source_token, "environmentId": environment_id,
            "environmentStateToken": environment_state_token,
            "environmentProfileVersion": environment_profile_version,
            "actions": list(BUILDER_ACTIONS)}
        encoded = _b64(_canonical(payload))
        signature = _b64(hmac.new(self._secret, encoded.encode("ascii"),
                                  sha256).digest())
        return encoded + "." + signature

    def verify(self, token: str, expected: BuildCapabilityContext,
               *, action: str) -> dict:
        self._validate_context(expected)
        payload = self._authenticate(token, action=action)
        wanted = {"issuer": expected.identity.issuer,
            "subjectId": expected.identity.subject_id,
            "workspaceId": expected.scope.workspace_id,
            "applicationId": expected.scope.application_id,
            "buildId": expected.build_id,
            "claimGeneration": expected.claim_generation,
            "programId": expected.program_id,
            "programSourceToken": expected.program_source_token,
            "environmentId": expected.environment_id,
            "environmentStateToken": expected.environment_state_token,
            "environmentProfileVersion": expected.environment_profile_version}
        if any(payload[key] != value for key, value in wanted.items()):
            raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED")
        return payload

    def admit(self, token: str, *, scope: ApplicationScope, build_id: str,
              action: str, claim_generation: int | None = None) -> dict:
        """Authenticate the envelope and request binding before live I/O."""
        if (not isinstance(scope, ApplicationScope)
                or type(build_id) is not str or not build_id
                or (claim_generation is not None and (
                    type(claim_generation) is not int or claim_generation < 1))):
            raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED")
        payload = self._authenticate(token, action=action)
        if (payload["workspaceId"] != scope.workspace_id
                or payload["applicationId"] != scope.application_id
                or payload["buildId"] != build_id
                or (claim_generation is not None
                    and payload["claimGeneration"] != claim_generation)):
            raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED")
        return payload

    def _authenticate(self, token: str, *, action: str) -> dict:
        if action not in BUILDER_ACTIONS or type(token) is not str or len(token) > 4096:
            raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED")
        try:
            encoded, supplied = token.split(".")
            actual = hmac.new(self._secret, encoded.encode("ascii"), sha256).digest()
            if not hmac.compare_digest(actual, _decode(supplied)):
                raise ValueError
            payload = json.loads(_decode(encoded))
        except (ValueError, TypeError, UnicodeError, binascii.Error,
                json.JSONDecodeError) as error:
            raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED") from error
        required = {"version", "kind", "audience", "issuedAt", "expiresAt",
            "nonce", "issuer", "subjectId", "workspaceId", "applicationId",
            "buildId", "claimGeneration", "programId", "programSourceToken",
            "environmentId", "environmentStateToken",
            "environmentProfileVersion", "actions"}
        now = self.clock()
        if (type(payload) is not dict or set(payload) != required
                or payload["version"] != 1
                or payload["kind"] != "openepm-python-build"
                or payload["audience"] != self.audience
                or type(now) is not int
                or type(payload["issuedAt"]) is not int
                or type(payload["expiresAt"]) is not int
                or payload["issuedAt"] > now + 5 or payload["expiresAt"] <= now
                or payload["expiresAt"] - payload["issuedAt"] > self.ttl_seconds
                or type(payload["nonce"]) is not str or len(payload["nonce"]) < 16
                or payload["actions"] != list(BUILDER_ACTIONS)
                or action not in payload["actions"]):
            raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED")
        return payload

    @staticmethod
    def _validate_context(value: BuildCapabilityContext) -> None:
        if (not isinstance(value, BuildCapabilityContext)
                or not isinstance(value.scope, ApplicationScope)
                or not isinstance(value.identity, VerifiedIdentity)
                or type(value.build_id) is not str or not value.build_id
                or type(value.claim_generation) is not int
                or value.claim_generation < 1
                or type(value.program_id) is not str or not value.program_id
                or type(value.program_source_token) is not str
                or not re.fullmatch(r"[0-9a-f]{64}",value.program_source_token)
                or type(value.environment_id) is not str or not value.environment_id
                or type(value.environment_state_token) is not str
                or not re.fullmatch(r"[0-9a-f]{64}",value.environment_state_token)
                or type(value.environment_profile_version) is not int
                or value.environment_profile_version < 1):
            raise ValueError("PYTHON_BUILD_CAPABILITY_CONTEXT_INVALID")


class PythonBuildReadBroker:
    """The only fixed-core boundary at which a builder token is accepted."""

    def __init__(self, provider: SignedBuildCapabilityProvider,
                 context_loader: Callable[..., dict]):
        if not isinstance(provider, SignedBuildCapabilityProvider) or not callable(context_loader):
            raise ValueError("PYTHON_BUILD_BROKER_CONFIGURATION_INVALID")
        self.provider, self.context_loader = provider, context_loader

    def read(self, token: str, *, scope: ApplicationScope, build_id: str,
             action: str, claim_generation: int | None = None) -> dict:
        # Reject forged, expired, cross-scope and wrong-generation envelopes
        # before the loader performs database work or assembles build context.
        self.provider.admit(token, scope=scope, build_id=build_id,
                            action=action, claim_generation=claim_generation)
        # The loader must recheck the live claim, publication/environment state,
        # and current subject authorization.  Revocation therefore takes effect
        # even while a cryptographically valid token has time remaining.
        value = self.context_loader(scope, build_id, action=action)
        required = {"identity", "claimGeneration", "programId",
            "programSourceToken", "environmentId", "environmentStateToken",
            "environmentProfileVersion", "purpose"}
        if action == SOURCE_READ:
            required |= {"sourceText", "entryPoint"}
        elif action == CONTEXT_READ:
            required |= {"parameterValues", "buildContext"}
        if type(value) is not dict or set(value) != required:
            raise ValueError("PYTHON_BUILD_BROKER_CONTEXT_INVALID")
        if value["purpose"] not in ("Plan", "Validation", "ImpactTest"):
            raise ValueError("PYTHON_BUILD_BROKER_CONTEXT_INVALID")
        expected = BuildCapabilityContext(scope, value["identity"], build_id,
            value["claimGeneration"], value["programId"],
            value["programSourceToken"], value["environmentId"],
            value["environmentStateToken"],value["environmentProfileVersion"])
        if (claim_generation is not None
                and claim_generation != expected.claim_generation):
            raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED")
        self.provider.verify(token, expected, action=action)
        if action == SOURCE_READ:
            return {"sourceText": value["sourceText"],
                    "entryPoint": value["entryPoint"]}
        if action == CONTEXT_READ:
            return {"parameterValues": value["parameterValues"],
                    "buildContext": value["buildContext"]}
        if action == PLAN_PROPOSE:
            return {"accepted": True}
        raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED")

    def publish(self, *_args, **_kwargs):
        raise ValueError("PYTHON_BUILD_CAPABILITY_CANNOT_PUBLISH")
