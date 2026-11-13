"""Typed fixed-core principals for user and Keycloak-group grants."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .postgres_access import VerifiedIdentity


class PrincipalKind(StrEnum):
    USER = "User"
    GROUP = "Group"


def _valid_identifier(value: object, *, maximum: int) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= maximum
            and value == value.strip()
            and all(ord(character) >= 32 for character in value)
            and "*" not in value)


@dataclass(frozen=True, slots=True, order=True)
class AuthorizationPrincipal:
    issuer: str
    kind: PrincipalKind
    principal_id: str

    def __post_init__(self) -> None:
        if (not _valid_identifier(self.issuer, maximum=300)
                or not isinstance(self.kind, PrincipalKind)
                or not _valid_identifier(self.principal_id, maximum=300)):
            raise ValueError("AUTHORIZATION_PRINCIPAL_INVALID")


def principals_for_identity(
        identity: VerifiedIdentity) -> tuple[AuthorizationPrincipal, ...]:
    """Return the only grant principals implied by a verified token.

    Groups are consumed only from :class:`VerifiedIdentity`, which is built by
    the trusted OIDC verifier.  A caller-authored program never supplies this
    tuple.  Stable group IDs must already be canonicalized by the Keycloak
    protocol mapper.
    """
    if not isinstance(identity, VerifiedIdentity):
        raise ValueError("VERIFIED_IDENTITY_REQUIRED")
    if (len(identity.groups) > 100
            or tuple(sorted(set(identity.groups))) != identity.groups
            or any(not _valid_identifier(group, maximum=300)
                   for group in identity.groups)):
        raise ValueError("VERIFIED_IDENTITY_GROUPS_INVALID")
    return (
        AuthorizationPrincipal(
            identity.issuer, PrincipalKind.USER, identity.subject_id),
        *(AuthorizationPrincipal(
            identity.issuer, PrincipalKind.GROUP, group)
          for group in identity.groups),
    )

