"""Production managed-notebook Hub configuration (fail-closed contract)."""
from __future__ import annotations

import os
from pathlib import Path

from jupyterhub_traefik_proxy.fileprovider import TraefikFileProviderProxy
from managed_notebook_contract import policy_from_environment, public_hub_url
from managed_spawner import ManagedNotebookSpawner
from openepm_oidc_authenticator import OpenEPMOIDCAuthenticator, https_url


def secret(name: str, maximum: int = 8192) -> str:
    path = Path(os.environ[name])
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("MANAGED_NOTEBOOK_SECRET_UNAVAILABLE")
    value = path.read_text("utf-8").strip()
    if not value or len(value.encode()) > maximum:
        raise RuntimeError("MANAGED_NOTEBOOK_SECRET_INVALID")
    return value


policy = policy_from_environment(os.environ)
issuer = https_url("EPM_HUB_OIDC_ISSUER")
try:
    public_url = public_hub_url(policy, https_url("EPM_HUB_PUBLIC_URL"))
except ValueError as error:
    raise RuntimeError("MANAGED_NOTEBOOK_PUBLIC_URL_MISMATCH") from error

c = get_config()  # noqa: F821 - supplied by JupyterHub
c.JupyterHub.db_url = secret("EPM_HUB_DATABASE_URL_FILE")
c.JupyterHub.cookie_secret = bytes.fromhex(secret("EPM_HUB_COOKIE_SECRET_FILE"))
c.JupyterHub.authenticator_class = OpenEPMOIDCAuthenticator
c.JupyterHub.spawner_class = ManagedNotebookSpawner
c.JupyterHub.proxy_class = TraefikFileProviderProxy
c.JupyterHub.subdomain_host = public_url
c.JupyterHub.bind_url = "http://0.0.0.0:8000"
c.JupyterHub.hub_bind_url = "http://0.0.0.0:8081"
# Single-user containers must receive a stable service name.  The default
# derives the Hub container hostname, which is ephemeral and is not a valid
# cross-container contract (and cannot be resolved reliably under runsc).
c.JupyterHub.hub_connect_url = "http://hub:8081"
c.JupyterHub.allow_named_servers = False
c.JupyterHub.cleanup_servers = True
c.JupyterHub.cleanup_proxy = False
c.JupyterHub.trust_user_provided_tokens = False
c.Authenticator.enable_auth_state = False
c.Authenticator.allow_all = True
c.OAuthenticator.client_id = os.environ["EPM_HUB_OIDC_CLIENT_ID"]
c.OAuthenticator.client_secret = secret("EPM_HUB_OIDC_CLIENT_SECRET_FILE")
c.OAuthenticator.oauth_callback_url = public_url + "/hub/oauth_callback"
c.OAuthenticator.authorize_url = https_url("EPM_HUB_OIDC_AUTHORIZE_URL")
c.OAuthenticator.token_url = https_url("EPM_HUB_OIDC_TOKEN_URL")
c.OAuthenticator.userdata_url = https_url("EPM_HUB_OIDC_USERINFO_URL")
c.OAuthenticator.username_claim = "sub"
c.OAuthenticator.scope = ["openid", "profile"]
c.OAuthenticator.enable_pkce = True
c.OAuthenticator.validate_server_cert = True
c.TraefikFileProviderProxy.should_start = False
c.TraefikFileProviderProxy.dynamic_config_file = (
    "/var/lib/openepm/proxy/jupyterhub.yaml")
c.TraefikFileProviderProxy.traefik_api_url = "http://proxy:8080"
c.TraefikFileProviderProxy.traefik_entrypoint = "websecure"
c.Spawner.start_timeout = 75
c.Spawner.http_timeout = 30
c.Spawner.ip = "0.0.0.0"
c.Spawner.port = 8888
c.Spawner.default_url = "/lab"
c.Spawner.disable_user_config = True
