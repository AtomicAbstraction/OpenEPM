"""Idempotently reconcile the fixed bundled Open EPM Keycloak profile."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


CONFIG = Path("/run/secrets/keycloak_bootstrap_config")
ADMIN_USERNAME = Path("/run/secrets/keycloak_admin_username")
ADMIN_PASSWORD = Path("/run/secrets/keycloak_admin_password")
DIRECTORY_CLIENT_SECRET = Path("/run/secrets/keycloak_directory_client_secret")
WEB_CLIENT_SECRET = Path("/run/secrets/keycloak_web_client_secret")
INITIAL_ADMIN_PASSWORD = Path("/run/secrets/keycloak_initial_admin_password")
FORMAT = "openepm-keycloak-bootstrap-v2"
ADMIN_URL = "https://identity:8443"
REALM = "openepm"
DIRECTORY_CLIENT_ID = "openepm-directory-admin"
MCP_OFFLINE_IDLE_SECONDS = 30 * 24 * 60 * 60
MCP_OFFLINE_MAX_SECONDS = 60 * 24 * 60 * 60
DIRECTORY_ROLES = ("manage-users", "query-groups", "query-users", "view-users")
PROTECTED_USER_ATTRIBUTES = {
    "openepm_kind": ("Open EPM managed identity kind", 64),
    "openepm_display_name": ("Open EPM display name", 200),
    "openepm_short_description": ("Open EPM short description", 500),
    "openepm_semantic_description": ("Open EPM semantic description", 10000),
    "openepm_last_operation": ("Open EPM last operation", 265),
    "openepm_tokens_valid_after": ("Open EPM token revocation cutoff", 20),
}
KEYCLOAK_BUILTIN_ATTRIBUTES = {"username", "email", "firstName", "lastName"}
OPTIONAL_NATIVE_PROFILE_ATTRIBUTES = {"email", "firstName", "lastName"}
LOGIN_FAILURE_MESSAGE = (
    "Sign-in failed. Check your username and password. If this is your first "
    "sign-in or you still cannot continue, contact your server administrator."
)


def read_file(path: Path, maximum: int) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError("KEYCLOAK_BOOTSTRAP_SECRET_INVALID")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum or b"\0" in raw:
        raise ValueError("KEYCLOAK_BOOTSTRAP_SECRET_INVALID")
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ValueError("KEYCLOAK_BOOTSTRAP_SECRET_INVALID") from error


def origin(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID")
    return value.rstrip("/")


def loopback_redirects(value: object) -> list[str]:
    if type(value) is not list or not 1 <= len(value) <= 8 or len(set(value)) != len(value):
        raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID")
    for item in value:
        if not isinstance(item, str):
            raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID")
        parsed = urlsplit(item)
        try: port = parsed.port
        except ValueError as error:
            raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID") from error
        if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1")
                or port is None or not 1024 <= port <= 65535 or parsed.path != "/callback"
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID")
    return value


def configuration(path: Path = CONFIG):
    try:
        value = json.loads(read_file(path, 16384))
    except json.JSONDecodeError as error:
        raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID") from error
    fields = {"format", "adminUrl", "webOrigin", "mcpRedirectUris",
              "initialAdministrator"}
    if (type(value) is not dict or set(value) != fields or value["format"] != FORMAT
            or value["adminUrl"] != ADMIN_URL):
        raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID")
    initial = value["initialAdministrator"]
    if (type(initial) is not dict
            or set(initial) != {"username", "displayName"}
            or not re.fullmatch(r"[A-Za-z0-9._@+-]{3,255}",
                                str(initial.get("username", "")))
            or not isinstance(initial.get("displayName"), str)
            or not 1 <= len(initial["displayName"].strip()) <= 200):
        raise ValueError("KEYCLOAK_BOOTSTRAP_CONFIG_INVALID")
    return (origin(value["webOrigin"]),
            loopback_redirects(value["mcpRedirectUris"]), initial)


class KeycloakApi:
    def __init__(self, base_url: str = ADMIN_URL): self.base_url = base_url

    def request(self, method: str, path: str, *, body=None, token=None,
                form=False, text=False) -> tuple[int, object | None]:
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            if form:
                data = urlencode(body).encode("ascii")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif text:
                if not isinstance(body, str):
                    raise ValueError("KEYCLOAK_BOOTSTRAP_REQUEST_INVALID")
                data = body.encode("utf-8")
                headers["Content-Type"] = "text/plain; charset=utf-8"
            else:
                data = json.dumps(body, sort_keys=True,
                    separators=(",", ":")).encode("utf-8")
                headers["Content-Type"] = "application/json"
        if token: headers["Authorization"] = "Bearer " + token
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("KEYCLOAK_BOOTSTRAP_RESPONSE_INVALID")
                return response.status, json.loads(raw) if raw else None
        except HTTPError as error:
            error.read(1024 * 1024)
            return error.code, None


def audience(name: str, value: str) -> dict:
    return {"name": name + "-audience", "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
        "config": {"included.custom.audience": value,
                   "id.token.claim": "false", "access.token.claim": "true",
                   "introspection.token.claim": "true"}}


def group_membership() -> dict:
    """Emit stable Keycloak group names, never mutable Open EPM display labels."""
    return {"name": "openepm-stable-groups", "protocol": "openid-connect",
        "protocolMapper": "oidc-group-membership-mapper",
        "consentRequired": False, "config": {
            "claim.name": "groups", "full.path": "false",
            "id.token.claim": "false", "access.token.claim": "true",
            "userinfo.token.claim": "true", "introspection.token.claim": "true"}}


def client(client_id: str, audience_value: str, redirects: list[str],
           origins: list[str], *, secret: str | None = None,
           device_authorization: bool = False) -> dict:
    confidential = secret is not None
    value = {"clientId": client_id, "name": client_id, "enabled": True,
        "protocol": "openid-connect", "publicClient": not confidential,
        "bearerOnly": False, "standardFlowEnabled": True,
        "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False, "authorizationServicesEnabled": False,
        "frontchannelLogout": True, "redirectUris": redirects,
        "webOrigins": origins, "defaultClientScopes": ["basic", "profile"],
        "optionalClientScopes": [], "attributes": {
            "pkce.code.challenge.method": "S256",
            "oauth2.device.authorization.grant.enabled": (
                "true" if device_authorization else "false"),
            "access.token.header.type.rfc9068": "true",
            # Browser clients return to their exact application root after
            # RP-initiated logout.  Do not rely on Keycloak's "+" shorthand:
            # it permits only the ordinary callback URIs, not the root.
            "post.logout.redirect.uris": (
                "##".join(item.rstrip("/") + "/" for item in origins)
                if origins else "+")},
        "protocolMappers": [audience(client_id, audience_value),
                            group_membership()]}
    if confidential:
        value["clientAuthenticatorType"] = "client-secret"
        value["secret"] = secret
    return value


def service_client(client_id: str, secret: str) -> dict:
    """Return the non-interactive client used by the narrow directory adapter."""
    return {"clientId": client_id, "name": client_id, "enabled": True,
        "protocol": "openid-connect", "publicClient": False,
        "bearerOnly": False, "standardFlowEnabled": False,
        "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True, "authorizationServicesEnabled": False,
        "frontchannelLogout": False, "redirectUris": [], "webOrigins": [],
        "defaultClientScopes": [], "optionalClientScopes": [],
        "clientAuthenticatorType": "client-secret", "secret": secret,
        "attributes": {"access.token.header.type.rfc9068": "true"},
        "protocolMappers": []}


def mcp_session_attributes() -> dict[str, str]:
    return {"client.offline.session.idle.timeout": str(MCP_OFFLINE_IDLE_SECONDS),
            "client.offline.session.max.lifespan": str(MCP_OFFLINE_MAX_SECONDS)}


def desired(web: str, mcp_redirects: list[str], directory_secret: str,
            web_secret: str) -> list[dict]:
    values = [
        client("openepm-mcp", "openepm-mcp", mcp_redirects, [],
               device_authorization=True),
        client("openepm-web", "openepm-web", [web + "/oidc/callback"], [web],
               secret=web_secret),
        service_client(DIRECTORY_CLIENT_ID, directory_secret)]
    mcp = values[0]
    mcp["optionalClientScopes"] = ["offline_access"]
    mcp["attributes"].update(mcp_session_attributes())
    return values


def reconcile_mcp_offline_access(api: KeycloakApi, token: str,
                                 client_id: str) -> str:
    """Bind the existing built-in scope through its authoritative REST resource.

    Client PUT does not reconcile optional scope bindings on an existing client.
    The built-in scope's offline_access role mapping must remain intact; never
    replace it with an ungoverned custom scope or grant application permissions.
    Session limits are client attributes (supported by Keycloak 26.8.1), leaving
    realm SSO, browser policy and realm refresh-token rotation unchanged.
    """
    base = "/admin/realms/" + REALM
    status, scopes = api.request("GET", base + "/client-scopes", token=token)
    expect(status, (200,))
    matches = [scope for scope in scopes if type(scope) is dict
               and scope.get("name") == "offline_access"] if type(scopes) is list else []
    if (len(matches) != 1 or matches[0].get("protocol") != "openid-connect"
            or not isinstance(matches[0].get("id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", matches[0]["id"])):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_OFFLINE_SCOPE_INVALID")
    scope_id = matches[0]["id"]
    status, role = api.request("GET", base + "/roles/offline_access", token=token)
    expect(status, (200,))
    if (type(role) is not dict or role.get("name") != "offline_access"
            or not isinstance(role.get("id"), str) or role.get("clientRole") is True):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_OFFLINE_ROLE_INVALID")
    status, mapped = api.request("GET", base + "/client-scopes/" + scope_id
                                + "/scope-mappings/realm", token=token)
    expect(status, (200,))
    if (type(mapped) is not list or not any(type(item) is dict
            and item.get("id") == role["id"] and item.get("name") == "offline_access"
            for item in mapped)):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_OFFLINE_ROLE_INVALID")
    path = base + "/clients/" + client_id + "/optional-client-scopes"
    status, current = api.request("GET", path, token=token)
    expect(status, (200,))
    if type(current) is not list:
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_OFFLINE_SCOPE_INVALID")
    if not any(type(item) is dict and item.get("id") == scope_id for item in current):
        status, _ = api.request("PUT", path + "/" + scope_id, token=token)
        expect(status, (204,))
    status, current = api.request("GET", path, token=token)
    expect(status, (200,))
    if (type(current) is not list or not any(type(item) is dict
            and item.get("id") == scope_id and item.get("name") == "offline_access"
            for item in current)):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_OFFLINE_SCOPE_INVALID")
    return scope_id


def retire_hosted_authoring_clients(api: KeycloakApi, token: str) -> None:
    """Revoke only the two previously shipped hosted-authoring clients.

    Deleting the client revokes its sessions. Existing user identities and
    application clients are deliberately outside this reconciliation scope.
    """
    for name in ("openepm-hub", "openepm-jupyterhub"):
        path = f"/admin/realms/{REALM}/clients?clientId={name}"
        status, matches = api.request("GET", path, token=token)
        expect(status, (200,))
        if not isinstance(matches, list) or len(matches) > 1:
            raise RuntimeError("KEYCLOAK_RETIRED_CLIENT_LOOKUP_INVALID")
        if not matches:
            continue
        match = matches[0]
        if (not isinstance(match, dict) or match.get("clientId") != name
                or not isinstance(match.get("id"), str)
                or re.fullmatch(r"[A-Za-z0-9._:-]{1,200}", match["id"]) is None):
            raise RuntimeError("KEYCLOAK_RETIRED_CLIENT_LOOKUP_INVALID")
        status, _ = api.request("DELETE",
            f"/admin/realms/{REALM}/clients/{match['id']}", token=token)
        expect(status, (204,))
        status, remaining = api.request("GET", path, token=token)
        expect(status, (200,))
        if remaining != []:
            raise RuntimeError("KEYCLOAK_RETIRED_CLIENT_REMAINS")


def grant_directory_roles(api: KeycloakApi, token: str,
                          client_internal_id: str) -> None:
    status, service_account = api.request("GET",
        f"/admin/realms/{REALM}/clients/{client_internal_id}/service-account-user",
        token=token)
    expect(status, (200,))
    if (type(service_account) is not dict
            or not isinstance(service_account.get("id"), str)):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_SERVICE_ACCOUNT_INVALID")
    status, matches = api.request("GET",
        f"/admin/realms/{REALM}/clients?clientId=realm-management", token=token)
    expect(status, (200,))
    if (type(matches) is not list or len(matches) != 1
            or not isinstance(matches[0].get("id"), str)):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_REALM_MANAGEMENT_INVALID")
    management_id = matches[0]["id"]
    roles = []
    for role_name in DIRECTORY_ROLES:
        status, role = api.request("GET",
            f"/admin/realms/{REALM}/clients/{management_id}/roles/{role_name}",
            token=token)
        expect(status, (200,))
        if (type(role) is not dict or role.get("name") != role_name
                or not isinstance(role.get("id"), str)):
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_DIRECTORY_ROLE_INVALID")
        roles.append({"id": role["id"], "name": role_name,
                      "containerId": management_id, "clientRole": True})
    status, _ = api.request("POST",
        f"/admin/realms/{REALM}/users/{service_account['id']}"
        f"/role-mappings/clients/{management_id}", body=roles, token=token)
    expect(status, (204,))


def retire_mfa_required_action(api: KeycloakApi, token: str) -> None:
    """Disable the retired TOTP action in an upgraded native-only realm."""
    path = f"/admin/realms/{REALM}/authentication/required-actions"
    status, actions = api.request("GET", path, token=token)
    expect(status, (200,))
    if type(actions) is not list:
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_REQUIRED_ACTION_INVALID")
    matches = [item for item in actions if type(item) is dict
               and item.get("alias") == "CONFIGURE_TOTP"]
    if len(matches) != 1:
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_REQUIRED_ACTION_INVALID")
    current = matches[0]
    desired_action = {**current, "enabled": False, "defaultAction": False}
    status, _ = api.request("PUT", path + "/CONFIGURE_TOTP",
                            body=desired_action, token=token)
    expect(status, (204,))


def reconcile_login_messages(api: KeycloakApi, token: str) -> None:
    """Install one actionable, non-enumerating native sign-in failure.

    The public response deliberately does not distinguish an unknown username
    from a wrong password. Administrators diagnose identity state through the
    governed directory rather than exposing an account-discovery oracle.
    """
    status, _ = api.request(
        "PUT", f"/admin/realms/{REALM}/localization/en/invalidUserMessage",
        body=LOGIN_FAILURE_MESSAGE, token=token, text=True)
    expect(status, (204,))


def reconcile_user_profile(api: KeycloakApi, token: str) -> None:
    """Register the native login ID and Open EPM's protected attributes.

    Keycloak 26's declarative user profile drops undeclared custom attributes.
    Open EPM's native authentication contract is deliberately user ID plus
    password: email, first name and last name are not identity prerequisites
    and must not create a second required-profile action after the mandatory
    first-password replacement. Keeping unmanaged attributes disabled avoids
    turning arbitrary caller data into durable identity state; Open EPM's
    semantic fields remain admin-only.
    """
    path = f"/admin/realms/{REALM}/users/profile"
    status, current = api.request("GET", path, token=token)
    expect(status, (200,))
    if (type(current) is not dict or type(current.get("attributes")) is not list
            or type(current.get("groups", [])) is not list):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_USER_PROFILE_INVALID")
    retained = []
    seen = set()
    for item in current["attributes"]:
        if type(item) is not dict or not isinstance(item.get("name"), str):
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_USER_PROFILE_INVALID")
        name = item["name"]
        if name in seen:
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_USER_PROFILE_INVALID")
        seen.add(name)
        if name in KEYCLOAK_BUILTIN_ATTRIBUTES:
            # Keycloak requires its built-in profile definitions to remain in
            # the representation. They are optional metadata in Open EPM,
            # however, and must never create an Update Profile action after
            # first-password replacement.
            retained.append(
                {key: value for key, value in item.items()
                 if key != "required"}
                if name in OPTIONAL_NATIVE_PROFILE_ATTRIBUTES else item)
    protected = []
    for name, (display_name, maximum) in PROTECTED_USER_ATTRIBUTES.items():
        protected.append({
            "name": name,
            "displayName": display_name,
            "multivalued": False,
            "permissions": {"view": ["admin"], "edit": ["admin"]},
            "validations": {"length": {"max": maximum}},
        })
    desired_profile = {**current, "attributes": retained + protected}
    # Never enable arbitrary unmanaged attributes while reconciling the fixed
    # profile, even if an earlier development realm did so.
    # Keycloak represents the disabled policy by omitting this optional field;
    # the accepted enum contains only policies that enable some unmanaged use.
    desired_profile.pop("unmanagedAttributePolicy", None)
    status, _ = api.request("PUT", path, body=desired_profile, token=token)
    expect(status, (200, 204))


def reconcile_initial_administrator(api: KeycloakApi, token: str,
                                    profile: dict, password: str) -> str:
    query = urlencode({"username": profile["username"], "exact": "true"})
    path = f"/admin/realms/{REALM}/users"
    status, matches = api.request("GET", path + "?" + query, token=token)
    expect(status, (200,))
    if type(matches) is not list or len(matches) > 1:
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_INITIAL_ADMIN_LOOKUP_INVALID")
    base = {
        "username": profile["username"],
        "attributes": {
            "openepm_kind": ["user"],
            "openepm_display_name": [profile["displayName"].strip()],
            "openepm_short_description": ["Initial native server administrator"],
            "openepm_semantic_description": [
                "Native server administrator; Open EPM grants remain authoritative."
            ],
            "openepm_last_operation": ["keycloak-bootstrap-v1"],
        },
    }
    if not matches:
        status, _ = api.request("POST", path, body={
            **base, "enabled": True,
            "requiredActions": ["UPDATE_PASSWORD"],
            "credentials": [{"type": "password", "value": password,
                             "temporary": True}],
        }, token=token)
        expect(status, (201, 204))
        status, matches = api.request("GET", path + "?" + query, token=token)
        expect(status, (200,))
    if (type(matches) is not list or len(matches) != 1
            or not isinstance(matches[0].get("id"), str)):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_INITIAL_ADMIN_LOOKUP_INVALID")
    identifier = matches[0]["id"]
    current = matches[0]
    if current.get("username") != profile["username"]:
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_INITIAL_ADMIN_IDENTITY_CHANGED")
    required_actions = [action for action in
                        current.get("requiredActions", [])
                        if action != "CONFIGURE_TOTP"]
    status, _ = api.request("PUT", path + "/" + identifier,
                            body={**base, "id": identifier,
                                  "enabled": current.get("enabled", True),
                                  "requiredActions": required_actions},
                            token=token)
    expect(status, (204,))
    return identifier


def expect(status: int, allowed: tuple[int, ...]) -> None:
    if status not in allowed: raise RuntimeError("KEYCLOAK_BOOTSTRAP_API_FAILED")


def bootstrap(*, api: KeycloakApi | None = None, config: Path = CONFIG,
              admin_username: Path = ADMIN_USERNAME,
              admin_password: Path = ADMIN_PASSWORD,
              directory_client_secret: Path = DIRECTORY_CLIENT_SECRET,
              web_client_secret: Path = WEB_CLIENT_SECRET,
              initial_admin_password: Path = INITIAL_ADMIN_PASSWORD) -> str:
    web, mcp_redirects, initial_admin = configuration(config)
    username = read_file(admin_username, 256)
    password = read_file(admin_password, 4096)
    directory_secret = read_file(directory_client_secret, 4096)
    web_secret = read_file(web_client_secret, 4096)
    initial_password = read_file(initial_admin_password, 4096)
    if (not re.fullmatch(r"[A-Za-z0-9._@-]{1,255}", username)
            or len(password) < 16
            or len(directory_secret) < 32
            or len(web_secret) < 32
            or len(initial_password) < 16):
        raise ValueError("KEYCLOAK_BOOTSTRAP_SECRET_INVALID")
    api = api or KeycloakApi()
    status, value = api.request("POST", "/realms/master/protocol/openid-connect/token",
        body={"grant_type": "password", "client_id": "admin-cli",
              "username": username, "password": password}, form=True)
    if status != 200 or type(value) is not dict or not isinstance(value.get("access_token"), str):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_AUTHENTICATION_FAILED")
    token = value["access_token"]
    realm = {"realm": REALM, "displayName": "Open EPM", "enabled": True,
        "sslRequired": "external", "registrationAllowed": False,
        "registrationEmailAsUsername": False, "rememberMe": False,
        "verifyEmail": False, "loginWithEmailAllowed": False,
        "duplicateEmailsAllowed": False, "resetPasswordAllowed": False,
        "editUsernameAllowed": False, "bruteForceProtected": True,
        "internationalizationEnabled": True, "supportedLocales": ["en"],
        "defaultLocale": "en",
        "accessTokenLifespan": 600, "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 36000,
        "smtpServer": {}}
    status, _ = api.request("GET", "/admin/realms/" + REALM, token=token)
    if status == 404:
        status, _ = api.request("POST", "/admin/realms", body=realm, token=token)
        expect(status, (201, 204))
    elif status != 200:
        expect(status, (200,))
    status, _ = api.request("PUT", "/admin/realms/" + REALM, body=realm, token=token)
    expect(status, (204,))
    retire_mfa_required_action(api, token)
    retire_hosted_authoring_clients(api, token)
    reconcile_login_messages(api, token)
    reconcile_user_profile(api, token)
    initial_subject = reconcile_initial_administrator(
        api, token, initial_admin, initial_password)
    client_ids = {}
    for representation in desired(web, mcp_redirects, directory_secret, web_secret):
        identifier = representation["clientId"]
        status, matches = api.request("GET", "/admin/realms/openepm/clients?clientId=" +
                                      identifier, token=token)
        expect(status, (200,))
        if type(matches) is not list or len(matches) > 1:
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_CLIENT_LOOKUP_INVALID")
        if not matches:
            status, _ = api.request("POST", "/admin/realms/openepm/clients",
                                    body=representation, token=token)
            expect(status, (201, 204))
            status, matches = api.request("GET", "/admin/realms/openepm/clients?clientId=" +
                                          identifier, token=token)
            expect(status, (200,))
        if (type(matches) is not list or len(matches) != 1
                or not isinstance(matches[0].get("id"), str)):
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_CLIENT_LOOKUP_INVALID")
        status, _ = api.request("PUT", "/admin/realms/openepm/clients/" +
            matches[0]["id"], body={**representation, "id": matches[0]["id"]}, token=token)
        expect(status, (204,))
        client_ids[identifier] = matches[0]["id"]
    reconcile_mcp_offline_access(api, token, client_ids["openepm-mcp"])
    grant_directory_roles(api, token, client_ids[DIRECTORY_CLIENT_ID])
    return initial_subject


def _scope_bindings(api: KeycloakApi, token: str, path: str) -> set[tuple[str, str]]:
    status, values = api.request("GET", path, token=token)
    expect(status, (200,))
    if (type(values) is not list or any(type(value) is not dict
            or not isinstance(value.get("id"), str) or not value["id"]
            or not isinstance(value.get("name"), str) or not value["name"]
            for value in values)):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_MCP_SCOPE_READBACK_INVALID")
    bindings = {(value["id"], value["name"]) for value in values}
    if len(bindings) != len(values) or len({key for key, _ in bindings}) != len(values):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_MCP_SCOPE_READBACK_INVALID")
    return bindings


def mcp_session_policy_only(*, api: KeycloakApi | None = None,
                            admin_username: Path = ADMIN_USERNAME,
                            admin_password: Path = ADMIN_PASSWORD) -> dict:
    """Reconcile only the existing MCP client's persistent session policy.

    No realm, browser-client, user, callback, protocol or rotation mutation is
    permitted by this path. Preserve every unrelated existing client field.
    """
    username, password = read_file(admin_username, 256), read_file(admin_password, 4096)
    if not re.fullmatch(r"[A-Za-z0-9._@-]{1,255}", username) or len(password) < 16:
        raise ValueError("KEYCLOAK_BOOTSTRAP_SECRET_INVALID")
    api = api or KeycloakApi()
    status, session = api.request("POST", "/realms/master/protocol/openid-connect/token",
        body={"grant_type": "password", "client_id": "admin-cli", "username": username,
              "password": password}, form=True)
    if (status != 200 or type(session) is not dict
            or not isinstance(session.get("access_token"), str)
            or not isinstance(session.get("refresh_token"), str)):
        raise RuntimeError("KEYCLOAK_BOOTSTRAP_AUTHENTICATION_FAILED")
    token = session["access_token"]
    try:
        base = "/admin/realms/" + REALM + "/clients"
        status, matches = api.request("GET", base + "?clientId=openepm-mcp", token=token)
        expect(status, (200,))
        if (type(matches) is not list or len(matches) != 1
                or matches[0].get("clientId") != "openepm-mcp"
                or not isinstance(matches[0].get("id"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", matches[0]["id"])):
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_CLIENT_LOOKUP_INVALID")
        path = base + "/" + matches[0]["id"]
        status, current = api.request("GET", path, token=token)
        expect(status, (200,))
        required = {"clientId": "openepm-mcp", "id": matches[0]["id"],
            "protocol": "openid-connect", "publicClient": True, "enabled": True,
            "standardFlowEnabled": True, "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False}
        if (type(current) is not dict or any(current.get(k) != v for k, v in required.items())
                or current.get("webOrigins") != [] or type(current.get("attributes")) is not dict
                or current["attributes"].get("pkce.code.challenge.method") != "S256"):
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_MCP_CLIENT_UNSAFE")
        loopback_redirects(current.get("redirectUris"))
        defaults = _scope_bindings(api, token, path + "/default-client-scopes")
        optionals = _scope_bindings(api, token, path + "/optional-client-scopes")
        attributes = {**current["attributes"], **mcp_session_attributes()}
        changed = current["attributes"] != attributes
        if changed:
            status, _ = api.request("PUT", path, body={**current, "attributes": attributes}, token=token)
            expect(status, (204,))
        offline_id = reconcile_mcp_offline_access(api, token, matches[0]["id"])
        if (_scope_bindings(api, token, path + "/default-client-scopes") != defaults
                or _scope_bindings(api, token, path + "/optional-client-scopes")
                != optionals | {(offline_id, "offline_access")}):
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_MCP_SCOPE_READBACK_INVALID")
        status, observed = api.request("GET", path, token=token)
        expect(status, (200,))
        expected = {**current, "attributes": attributes}
        # Scope bindings have their own authoritative endpoint/readback above.
        ignored = {"optionalClientScopes", "defaultClientScopes"}
        if (type(observed) is not dict or any(observed.get(k) != v
                for k, v in expected.items() if k not in ignored)):
            raise RuntimeError("KEYCLOAK_BOOTSTRAP_MCP_POLICY_READBACK_INVALID")
        return {"format": "openepm-mcp-session-policy-v1", "clientId": "openepm-mcp",
                "offlineIdleSeconds": MCP_OFFLINE_IDLE_SECONDS,
                "offlineMaxSeconds": MCP_OFFLINE_MAX_SECONDS,
                "optionalScope": "offline_access", "verified": True}
    finally:
        status, _ = api.request("POST", "/realms/master/protocol/openid-connect/logout",
            body={"client_id": "admin-cli", "refresh_token": session["refresh_token"]}, form=True)
        expect(status, (204,))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mcp-session-policy-only", action="store_true",
                        help="Update only existing MCP offline-session limits and optional scope")
    arguments = parser.parse_args()
    if arguments.mcp_session_policy_only:
        print(json.dumps(mcp_session_policy_only(), sort_keys=True, separators=(",", ":")))
        return
    subject = bootstrap()
    print(json.dumps({"format": "openepm-keycloak-bootstrap-result-v1",
                      "initialAdministratorSubject": subject},
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__": main()
