"""Qualification-only orchestration for two public schema-163 lifecycles.

This module neither provisions databases nor synthesizes domain results.  It
requires an owned context manager for each independently initialized database
and approved real adapters for every domain, then closes the first lifecycle
before opening the second.  This keeps fixed host ports and service identities
unambiguous while preserving exact certificate comparison.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Callable, Mapping, Any

from .postgres_schema163_functional_collector import (
    ApprovedDomainAdapter, DisposableCollectorContext, collect_certificate,
)
from .postgres_schema163_functional_parity import DOMAINS, verify_pair


def _fail(code: str) -> None:
    raise ValueError(code)


@dataclass(frozen=True, slots=True)
class PublicLifecycle:
    mode: str
    context: DisposableCollectorContext
    adapters: tuple[ApprovedDomainAdapter, ...]
    service_identities: Mapping[str, str]

    def validate(self) -> None:
        if self.mode not in {"fresh-baseline-164", "semantic-reference-164"}:
            _fail("SCHEMA163_PUBLIC_PAIR_MODE_INVALID")
        self.context.validate()
        if (not isinstance(self.service_identities, Mapping)
                or set(self.service_identities) != {
                    "database", "platform", "workspace", "router", "worker"}
                or any(not isinstance(value, str) or not value
                       for value in self.service_identities.values())):
            _fail("SCHEMA163_PUBLIC_PAIR_SERVICE_IDENTITIES_INVALID")
        if (not isinstance(self.adapters, tuple)
                or tuple(item.domain for item in self.adapters) != DOMAINS):
            _fail("SCHEMA163_PUBLIC_PAIR_ADAPTERS_INVALID")


LifecycleFactory = Callable[[str], AbstractContextManager[PublicLifecycle]]


def run_public_pair(factory: LifecycleFactory) -> dict[str, Any]:
    """Collect exact certificates in two sequential, independently owned runs."""
    if not callable(factory):
        _fail("SCHEMA163_PUBLIC_PAIR_FACTORY_INVALID")
    certificates = []
    identities = []
    modes = ("fresh-baseline-164", "semantic-reference-164")
    for mode in modes:
        manager = factory(mode)
        if not isinstance(manager, AbstractContextManager):
            _fail("SCHEMA163_PUBLIC_PAIR_LIFECYCLE_INVALID")
        with manager as lifecycle:
            if not isinstance(lifecycle, PublicLifecycle):
                _fail("SCHEMA163_PUBLIC_PAIR_LIFECYCLE_INVALID")
            lifecycle.validate()
            if lifecycle.mode != mode:
                _fail("SCHEMA163_PUBLIC_PAIR_MODE_MISMATCH")
            certificate = collect_certificate(lifecycle.context,
                                              lifecycle.adapters)
            certificates.append(certificate)
            identities.append(dict(lifecycle.service_identities))
    result = verify_pair(certificates[0], certificates[1])
    return {"result": result, "certificates": certificates,
            "serviceIdentities": identities,
            "lifecycleModes": list(modes),
            "activationAuthorized": False}
