"""OIDC authenticator that never exposes the provider subject as a Hub name."""
from __future__ import annotations

import os
from urllib.parse import urlparse

from oauthenticator.generic import GenericOAuthenticator

from managed_notebook_contract import NotebookUserIdentity


def https_url(name: str) -> str:
    value = os.environ.get(name, "")
    parsed = urlparse(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise RuntimeError("MANAGED_NOTEBOOK_OIDC_CONFIGURATION_INVALID")
    return value.rstrip("/")


class OpenEPMOIDCAuthenticator(GenericOAuthenticator):
    """Map a verified OIDC ``sub`` to an issuer-scoped opaque username."""

    def normalize_username(self, username: str) -> str:
        # GenericOAuthenticator obtains this value from the configured ``sub``
        # claim after the server-side code exchange and HTTPS user-info call.
        # The raw subject must not become a container, volume or DNS label.
        issuer = https_url("EPM_HUB_OIDC_ISSUER")
        return NotebookUserIdentity(issuer, username).hub_username

