"""Bounded Keycloak Admin API client for Open EPM's directory adapter.

This module handles a temporary password only for the bounded administrator
reset operation and never persists or returns it. It authenticates as the
least-privilege service account provisioned by the bundled realm bootstrap.
Open EPM product authorization remains in PostgreSQL fixed-core services.
"""
from __future__ import annotations

import json
import time
import os
import ssl
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen


REALM = "openepm"
CLIENT_ID = "openepm-directory-admin"
MANAGED_USER = "openepm-native-v1"
MANAGED_GROUP = "openepm-group-v1"
MAX_RESPONSE = 1024 * 1024
MAX_GROUP_RETIREMENT_MEMBERS = 10_000
MAX_RECONCILE_USERS = 100_000
MAX_RECONCILE_GROUPS = 10_000
MAX_RECONCILE_MEMBERSHIPS = 1_000_000
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,199}")
PASSWORD = re.compile(r"(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{12,256}")


class KeycloakDirectoryError(RuntimeError):
    """Stable failure boundary; upstream response bodies are never exposed."""


def _secret(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError("KEYCLOAK_DIRECTORY_SECRET_INVALID")
    raw = path.read_bytes()
    if not 32 <= len(raw) <= 4096 or b"\0" in raw:
        raise ValueError("KEYCLOAK_DIRECTORY_SECRET_INVALID")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ValueError("KEYCLOAK_DIRECTORY_SECRET_INVALID") from error
    if len(value) < 32:
        raise ValueError("KEYCLOAK_DIRECTORY_SECRET_INVALID")
    return value


def directory_url(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.hostname is None
            or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("KEYCLOAK_DIRECTORY_URL_INVALID")
    return value.rstrip("/")


def _directory_tls_context(path: Path) -> ssl.SSLContext:
    if not path.is_file() or path.is_symlink():
        raise ValueError("KEYCLOAK_DIRECTORY_CA_INVALID")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValueError("KEYCLOAK_DIRECTORY_CA_INVALID") from error
    if not 1 <= size <= 1024 * 1024:
        raise ValueError("KEYCLOAK_DIRECTORY_CA_INVALID")
    try:
        context = ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError) as error:
        raise ValueError("KEYCLOAK_DIRECTORY_CA_INVALID") from error
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class KeycloakDirectoryApi:
    def __init__(self, base_url: str, client_secret: str, *,
                 ca_certificate: Path | None = None):
        self.base_url = directory_url(base_url)
        if not isinstance(client_secret, str) or len(client_secret) < 32:
            raise ValueError("KEYCLOAK_DIRECTORY_SECRET_INVALID")
        self.client_secret = client_secret
        self.tls_context = (_directory_tls_context(ca_certificate)
                            if ca_certificate is not None else None)

    @classmethod
    def from_environment(cls) -> "KeycloakDirectoryApi":
        path = os.environ.get("EPM_KEYCLOAK_DIRECTORY_CLIENT_SECRET_FILE", "")
        client_secret = _secret(Path(path))
        ca_path = (os.environ.get("EPM_KEYCLOAK_DIRECTORY_CA_FILE", "").strip()
                   or os.environ.get("SSL_CERT_FILE", "").strip())
        if not ca_path:
            raise ValueError("KEYCLOAK_DIRECTORY_CA_INVALID")
        return cls(os.environ.get("EPM_KEYCLOAK_DIRECTORY_URL", ""),
                   client_secret, ca_certificate=Path(ca_path))

    def request(self, method: str, path: str, *, body=None, token=None,
                form=False) -> tuple[int, object | None]:
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            if form:
                data = urlencode(body).encode("ascii")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(body, sort_keys=True,
                    separators=(",", ":")).encode("utf-8")
                headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        request = Request(self.base_url + path, data=data, headers=headers,
                          method=method)
        try:
            with urlopen(request, timeout=15,
                         context=self.tls_context) as response:
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise KeycloakDirectoryError(
                        "KEYCLOAK_DIRECTORY_RESPONSE_TOO_LARGE")
                return response.status, json.loads(raw) if raw else None
        except HTTPError as error:
            error.read(MAX_RESPONSE)
            return error.code, None
        except (OSError, URLError, TimeoutError) as error:
            raise KeycloakDirectoryError(
                "KEYCLOAK_DIRECTORY_UNAVAILABLE") from error


def _text(value: object, maximum: int, code: str, *, empty=False) -> str:
    if (not isinstance(value, str) or len(value) > maximum or "\0" in value
            or value != value.strip() or (not empty and not value)):
        raise ValueError(code)
    return value


def _attributes(value: object) -> dict[str, list[str]]:
    if type(value) is not dict:
        return {}
    result = {}
    for key, items in value.items():
        if isinstance(key, str) and type(items) is list and all(
                isinstance(item, str) for item in items):
            result[key] = items
    return result


def _first(attributes: dict[str, list[str]], key: str) -> str:
    values = attributes.get(key, [])
    return values[0] if len(values) == 1 else ""


def _operation_marker(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("DIRECTORY_OPERATION_MARKER_INVALID")
    operation_id, separator, digest = value.rpartition(":")
    if (separator != ":" or not IDENTIFIER.fullmatch(operation_id)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise ValueError("DIRECTORY_OPERATION_MARKER_INVALID")
    return value


def _is_replay(attributes: dict[str, list[str]], marker: str) -> bool:
    previous = _first(attributes, "openepm_last_operation")
    if previous == marker:
        return True
    if previous and previous.rpartition(":")[0] == marker.rpartition(":")[0]:
        raise ValueError("IDEMPOTENCY_KEY_REUSED")
    return False


class KeycloakDirectory:
    """Strict semantic adapter over a small, reviewed Admin API subset."""

    def __init__(self, api: KeycloakDirectoryApi):
        self.api = api

    def _token(self) -> str:
        status, value = self.api.request("POST",
            f"/realms/{REALM}/protocol/openid-connect/token", form=True,
            body={"grant_type": "client_credentials", "client_id": CLIENT_ID,
                  "client_secret": self.api.client_secret})
        if (status != 200 or type(value) is not dict
                or not isinstance(value.get("access_token"), str)):
            raise KeycloakDirectoryError(
                "KEYCLOAK_DIRECTORY_AUTHENTICATION_FAILED")
        return value["access_token"]

    def _request(self, method: str, path: str, *, body=None,
                 allowed=(200,)) -> object | None:
        status, value = self.api.request(method, path, body=body,
                                         token=self._token())
        if status not in allowed:
            if status == 404:
                raise KeycloakDirectoryError("DIRECTORY_OBJECT_NOT_FOUND")
            if status == 409:
                raise KeycloakDirectoryError("DIRECTORY_OBJECT_CONFLICT")
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_OPERATION_FAILED")
        return value

    @staticmethod
    def _user(value: object) -> dict:
        if (type(value) is not dict or not isinstance(value.get("id"), str)
                or not isinstance(value.get("username"), str)
                or type(value.get("enabled")) is not bool):
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        attributes = _attributes(value.get("attributes"))
        if _first(attributes, "openepm_kind") != MANAGED_USER:
            raise KeycloakDirectoryError("DIRECTORY_USER_NOT_MANAGED")
        return {"subjectId": value["id"], "username": value["username"],
                "displayName": _first(attributes, "openepm_display_name"),
                "shortDescription": _first(attributes, "openepm_short_description"),
                "semanticDescription": _first(attributes, "openepm_semantic_description"),
                "status": "Active" if value["enabled"] else "Inactive"}

    @staticmethod
    def _group(value: object) -> dict:
        if (type(value) is not dict or not isinstance(value.get("id"), str)
                or not isinstance(value.get("name"), str)):
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        attributes = _attributes(value.get("attributes"))
        if _first(attributes, "openepm_kind") != MANAGED_GROUP:
            raise KeycloakDirectoryError("DIRECTORY_GROUP_NOT_MANAGED")
        return {"groupId": value["id"], "groupName": value["name"],
                "displayName": _first(attributes, "openepm_display_name"),
                "shortDescription": _first(attributes, "openepm_short_description"),
                "semanticDescription": _first(attributes, "openepm_semantic_description"),
                "status": _first(attributes, "openepm_status") or "Active"}

    def read_user(self, subject_id: str) -> dict:
        if not isinstance(subject_id, str) or not IDENTIFIER.fullmatch(subject_id):
            raise ValueError("DIRECTORY_SUBJECT_ID_INVALID")
        value = self._request("GET",
            f"/admin/realms/{REALM}/users/{quote(subject_id, safe='')}")
        return self._user(value)

    def list_users(self, *, offset: int, limit: int) -> dict:
        if type(offset) is not int or type(limit) is not int or offset < 0 \
                or not 1 <= limit <= 100:
            raise ValueError("DIRECTORY_PAGE_INVALID")
        query = urlencode({"first": offset, "max": limit + 1,
                           "briefRepresentation": "false"})
        value = self._request("GET",
            f"/admin/realms/{REALM}/users?{query}")
        if type(value) is not list or len(value) > limit + 1:
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        managed = []
        for item in value:
            subject_id = (item.get("id") if type(item) is dict else None)
            if not isinstance(subject_id, str) or not subject_id:
                raise KeycloakDirectoryError(
                    "KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
            # Keycloak may omit custom attributes from collection/search
            # representations even when briefRepresentation=false.  Those
            # attributes are the ownership boundary for native Open EPM
            # identities, so resolve the canonical detail representation
            # before deciding whether the user is managed.  Treating an
            # incomplete list row as unmanaged would incorrectly deactivate
            # a current identity during authoritative reconciliation.
            detail = self._request("GET",
                f"/admin/realms/{REALM}/users/"
                f"{quote(subject_id, safe='')}")
            try:
                managed.append(self._user(detail))
            except KeycloakDirectoryError as error:
                if str(error) != "DIRECTORY_USER_NOT_MANAGED":
                    raise
        return {"items": managed[:limit],
                "nextOffset": offset + limit if len(value) > limit else None}

    def create_user(self, fields: dict, *, operation_marker: str) -> dict:
        if type(fields) is not dict or set(fields) != {
                "username", "displayName", "shortDescription",
                "semanticDescription"}:
            raise ValueError("DIRECTORY_USER_CREATE_INVALID")
        operation_marker = _operation_marker(operation_marker)
        username = _text(fields["username"], 200,
                         "DIRECTORY_USER_CREATE_INVALID")
        if not USERNAME.fullmatch(username):
            raise ValueError("DIRECTORY_USER_CREATE_INVALID")
        attributes = {
            "openepm_kind": [MANAGED_USER],
            "openepm_display_name": [_text(fields["displayName"], 200,
                "DIRECTORY_USER_CREATE_INVALID")],
            "openepm_short_description": [_text(fields["shortDescription"],
                500, "DIRECTORY_USER_CREATE_INVALID", empty=True)],
            "openepm_semantic_description": [_text(
                fields["semanticDescription"], 10000,
                "DIRECTORY_USER_CREATE_INVALID", empty=True)],
            "openepm_last_operation": [operation_marker]}
        # Keycloak user search defaults to a brief representation, which omits
        # the protected management attributes needed to prove ownership and
        # exact replay.  Always request the full representation here.
        query = urlencode({"username": username, "exact": "true",
                           "briefRepresentation": "false"})
        found = self._request("GET",
            f"/admin/realms/{REALM}/users?{query}")
        if type(found) is not list or len(found) > 1:
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        if found:
            subject_id = found[0].get("id") if type(found[0]) is dict else None
            if not isinstance(subject_id, str):
                raise KeycloakDirectoryError(
                    "KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
            # Keycloak 26 may omit custom attributes from search results even
            # when briefRepresentation=false.  Search resolves identity only;
            # ownership and replay are decided from the detail endpoint.
            current = self._request("GET",
                f"/admin/realms/{REALM}/users/{quote(subject_id, safe='')}")
            if type(current) is not dict:
                raise KeycloakDirectoryError(
                    "KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
            if _is_replay(_attributes(current.get("attributes")),
                          operation_marker):
                return self._user(current)
            raise KeycloakDirectoryError("DIRECTORY_OBJECT_CONFLICT")
        body = {"username": username, "enabled": True,
                "attributes": attributes, "requiredActions": []}
        self._request("POST", f"/admin/realms/{REALM}/users", body=body,
                      allowed=(201, 204))
        found = self._request("GET",
            f"/admin/realms/{REALM}/users?{query}")
        subject_id = (found[0].get("id") if type(found) is list
                      and len(found) == 1 and type(found[0]) is dict else None)
        if not isinstance(subject_id, str):
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        current = self._request("GET",
            f"/admin/realms/{REALM}/users/{quote(subject_id, safe='')}")
        return self._user(current)

    def set_temporary_password(self, subject_id: str, password: object) -> dict:
        if (not isinstance(subject_id, str)
                or not IDENTIFIER.fullmatch(subject_id)
                or not isinstance(password, str)
                or any(ord(character) < 32 for character in password)
                or not PASSWORD.fullmatch(password)):
            raise ValueError("DIRECTORY_USER_PASSWORD_INVALID")
        user = self.read_user(subject_id)
        if user["status"] != "Active":
            raise KeycloakDirectoryError("DIRECTORY_USER_INACTIVE")
        self._request("PUT",
            f"/admin/realms/{REALM}/users/{quote(subject_id, safe='')}/reset-password",
            body={"type": "password", "value": password, "temporary": True},
            allowed=(204,))
        self._logout_user(subject_id)
        return {"subjectId": subject_id, "passwordChanged": True,
                "temporary": True, "sessionsRevoked": True,
                "tokensValidAfter": int(time.time())}

    def update_user(self, subject_id: str, fields: dict, *,
                    operation_marker: str) -> dict:
        operation_marker = _operation_marker(operation_marker)
        current = self._request("GET",
            f"/admin/realms/{REALM}/users/{quote(subject_id, safe='')}")
        normalized = self._user(current)
        if _is_replay(_attributes(current.get("attributes")), operation_marker):
            return normalized
        if type(fields) is not dict or set(fields) != {
                "displayName", "shortDescription", "semanticDescription"}:
            raise ValueError("DIRECTORY_USER_UPDATE_INVALID")
        attributes = _attributes(current.get("attributes"))
        attributes.update({
            "openepm_kind": [MANAGED_USER],
            "openepm_display_name": [_text(fields["displayName"], 200,
                "DIRECTORY_USER_UPDATE_INVALID")],
            "openepm_short_description": [_text(fields["shortDescription"],
                500, "DIRECTORY_USER_UPDATE_INVALID", empty=True)],
            "openepm_semantic_description": [_text(
                fields["semanticDescription"], 10000,
                "DIRECTORY_USER_UPDATE_INVALID", empty=True)],
            "openepm_last_operation": [operation_marker]})
        body = {**current, "attributes": attributes}
        self._request("PUT",
            f"/admin/realms/{REALM}/users/{quote(normalized['subjectId'], safe='')}",
            body=body, allowed=(204,))
        return self.read_user(normalized["subjectId"])

    def set_user_status(self, subject_id: str, status: str, *,
                        operation_marker: str) -> dict:
        operation_marker = _operation_marker(operation_marker)
        path = f"/admin/realms/{REALM}/users/{quote(subject_id, safe='')}"
        current = self._request("GET", path)
        normalized = self._user(current)
        attributes = _attributes(current.get("attributes"))
        if _is_replay(attributes, operation_marker):
            if normalized["status"] != "Inactive":
                return {**normalized, "sessionsRevoked": False}
            revoked_after = _first(attributes, "openepm_tokens_valid_after")
            if revoked_after and revoked_after.isascii() and revoked_after.isdigit() \
                    and int(revoked_after) > 0:
                self._logout_user(normalized["subjectId"])
                return {**normalized, "sessionsRevoked": True,
                        "tokensValidAfter": int(revoked_after)}
            # Older profiles dropped the unmanaged cutoff. Revoke through
            # the current time before completing the same deactivation.
            status = "Inactive"
        if status not in ("Active", "Inactive"):
            raise ValueError("DIRECTORY_USER_STATUS_INVALID")
        attributes["openepm_last_operation"] = [operation_marker]
        revoked_after = int(time.time()) if status == "Inactive" else None
        if revoked_after is not None:
            attributes["openepm_tokens_valid_after"] = [str(revoked_after)]
        body = {**current, "enabled": status == "Active",
                "attributes": attributes}
        self._request("PUT", path, body=body, allowed=(204,))
        if status == "Inactive":
            self._logout_user(normalized["subjectId"])
        updated = self._request("GET", path)
        verified = self._user(updated)
        if revoked_after is not None and _first(_attributes(updated.get("attributes")),
                "openepm_tokens_valid_after") != str(revoked_after):
            raise KeycloakDirectoryError("DIRECTORY_USER_REVOCATION_CUTOFF_UNAVAILABLE")
        return {**verified,
                "sessionsRevoked": status == "Inactive",
                **({"tokensValidAfter": revoked_after}
                   if status == "Inactive" else {})}

    def read_group(self, group_id: str) -> dict:
        value = self._group_representation(group_id)
        return self._group(value)

    def _group_internal_id(self, group_id: str) -> str:
        return self._group_representation(group_id)["id"]

    def _group_representation(self, group_id: str) -> dict:
        if not isinstance(group_id, str) or not IDENTIFIER.fullmatch(group_id):
            raise ValueError("DIRECTORY_GROUP_ID_INVALID")
        value = self._request("GET",
            f"/admin/realms/{REALM}/groups/{quote(group_id, safe='')}")
        if type(value) is not dict or value.get("id") != group_id:
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        self._group(value)
        return value

    def list_groups(self, *, offset: int, limit: int) -> dict:
        if type(offset) is not int or type(limit) is not int or offset < 0 \
                or not 1 <= limit <= 100:
            raise ValueError("DIRECTORY_PAGE_INVALID")
        query = urlencode({"first": offset, "max": limit + 1,
                           "briefRepresentation": "false"})
        value = self._request("GET",
            f"/admin/realms/{REALM}/groups?{query}")
        if type(value) is not list or len(value) > limit + 1:
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        managed = []
        for item in value:
            group_id = (item.get("id") if type(item) is dict else None)
            if not isinstance(group_id, str) or not group_id:
                raise KeycloakDirectoryError(
                    "KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
            # As with users, managed ownership is asserted only by the
            # canonical detail attributes.  Collection rows are identity
            # candidates, not sufficient authorization evidence.
            detail = self._request("GET",
                f"/admin/realms/{REALM}/groups/"
                f"{quote(group_id, safe='')}")
            try:
                managed.append(self._group(detail))
            except KeycloakDirectoryError as error:
                if str(error) != "DIRECTORY_GROUP_NOT_MANAGED":
                    raise
        return {"items": managed[:limit],
                "nextOffset": offset + limit if len(value) > limit else None}

    def authorization_snapshot(self) -> dict:
        """Read one bounded normalized snapshot for fixed-core reconciliation.

        Only Open EPM-managed native-user status and managed group status are
        projected. Memberships include every current Keycloak subject in a
        managed group, including identities created by the native directory.
        """
        users, offset = [], 0
        while True:
            page = self.list_users(offset=offset, limit=100)
            users.extend({"subjectId": item["subjectId"],
                          "username": item["username"],
                          "displayName": item["displayName"],
                          "status": item["status"]}
                         for item in page["items"])
            if len(users) > MAX_RECONCILE_USERS:
                raise KeycloakDirectoryError(
                    "KEYCLOAK_DIRECTORY_RECONCILIATION_LIMIT")
            if page["nextOffset"] is None:
                break
            offset = page["nextOffset"]

        groups, memberships, offset = [], [], 0
        while True:
            page = self.list_groups(offset=offset, limit=100)
            for item in page["items"]:
                groups.append({"groupId": item["groupId"],
                               "groupName": item["groupName"],
                               "displayName": item["displayName"],
                               "status": item["status"]})
                internal = item["groupId"]
                member_offset = 0
                while True:
                    query = urlencode({"first": member_offset, "max": 100,
                                       "briefRepresentation": "true"})
                    value = self._request("GET",
                        f"/admin/realms/{REALM}/groups/"
                        f"{quote(internal, safe='')}/members?{query}")
                    if type(value) is not list or len(value) > 100:
                        raise KeycloakDirectoryError(
                            "KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
                    for member in value:
                        subject_id = (member.get("id")
                                      if type(member) is dict else None)
                        if not isinstance(subject_id, str) or not subject_id:
                            raise KeycloakDirectoryError(
                                "KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
                        memberships.append({"subjectId": subject_id,
                                            "groupId": item["groupId"]})
                    if len(memberships) > MAX_RECONCILE_MEMBERSHIPS:
                        raise KeycloakDirectoryError(
                            "KEYCLOAK_DIRECTORY_RECONCILIATION_LIMIT")
                    if len(value) < 100:
                        break
                    member_offset += len(value)
            if len(groups) > MAX_RECONCILE_GROUPS:
                raise KeycloakDirectoryError(
                    "KEYCLOAK_DIRECTORY_RECONCILIATION_LIMIT")
            if page["nextOffset"] is None:
                break
            offset = page["nextOffset"]
        return {"users": sorted(users, key=lambda item: item["subjectId"]),
                "groups": sorted(groups, key=lambda item: item["groupId"]),
                "memberships": sorted(memberships, key=lambda item: (
                    item["groupId"], item["subjectId"]))}

    def create_group(self, fields: dict, *, operation_marker: str) -> dict:
        if type(fields) is not dict or set(fields) != {
                "groupId", "displayName", "shortDescription",
                "semanticDescription"}:
            raise ValueError("DIRECTORY_GROUP_CREATE_INVALID")
        operation_marker = _operation_marker(operation_marker)
        group_id = _text(fields["groupId"], 200,
                         "DIRECTORY_GROUP_CREATE_INVALID")
        if not IDENTIFIER.fullmatch(group_id):
            raise ValueError("DIRECTORY_GROUP_CREATE_INVALID")
        query = urlencode({"search": group_id, "exact": "true",
                           "briefRepresentation": "false", "max": 2})
        found = self._request("GET",
            f"/admin/realms/{REALM}/groups?{query}")
        matches = [item for item in found if type(item) is dict
                   and item.get("name") == group_id] if type(found) is list else []
        if len(matches) > 1:
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        if matches:
            if _is_replay(_attributes(matches[0].get("attributes")), operation_marker):
                return self._group(matches[0])
            raise KeycloakDirectoryError("DIRECTORY_OBJECT_CONFLICT")
        body = {"name": group_id, "attributes": {
            "openepm_kind": [MANAGED_GROUP],
            "openepm_display_name": [_text(fields["displayName"], 200,
                "DIRECTORY_GROUP_CREATE_INVALID")],
            "openepm_short_description": [_text(fields["shortDescription"],
                500, "DIRECTORY_GROUP_CREATE_INVALID", empty=True)],
            "openepm_semantic_description": [_text(
                fields["semanticDescription"], 10000,
                "DIRECTORY_GROUP_CREATE_INVALID", empty=True)],
            "openepm_status": ["Active"],
            "openepm_last_operation": [operation_marker]}}
        self._request("POST", f"/admin/realms/{REALM}/groups", body=body,
                      allowed=(201, 204))
        query = urlencode({"search": group_id, "exact": "true",
                           "briefRepresentation": "false", "max": 2})
        created = self._request("GET",
            f"/admin/realms/{REALM}/groups?{query}")
        matches = [item for item in created if type(item) is dict
                   and item.get("name") == group_id] \
            if type(created) is list else []
        if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
            raise KeycloakDirectoryError("KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
        return self.read_group(matches[0]["id"])

    def update_group(self, group_id: str, fields: dict, *,
                     operation_marker: str) -> dict:
        operation_marker = _operation_marker(operation_marker)
        internal = self._group_internal_id(group_id)
        current = self._request("GET",
            f"/admin/realms/{REALM}/groups/{quote(internal, safe='')}")
        normalized = self._group(current)
        if _is_replay(_attributes(current.get("attributes")), operation_marker):
            return normalized
        if type(fields) is not dict or set(fields) != {
                "displayName", "shortDescription", "semanticDescription"}:
            raise ValueError("DIRECTORY_GROUP_UPDATE_INVALID")
        attributes = _attributes(current.get("attributes"))
        attributes.update({
            "openepm_kind": [MANAGED_GROUP],
            "openepm_display_name": [_text(fields["displayName"], 200,
                "DIRECTORY_GROUP_UPDATE_INVALID")],
            "openepm_short_description": [_text(fields["shortDescription"],
                500, "DIRECTORY_GROUP_UPDATE_INVALID", empty=True)],
            "openepm_semantic_description": [_text(
                fields["semanticDescription"], 10000,
                "DIRECTORY_GROUP_UPDATE_INVALID", empty=True)],
            "openepm_last_operation": [operation_marker]})
        self._request("PUT",
            f"/admin/realms/{REALM}/groups/{quote(internal, safe='')}",
            body={**current, "name": current["name"],
                  "attributes": attributes},
            allowed=(204,))
        return self.read_group(group_id)

    def set_group_status(self, group_id: str, status: str, *,
                         operation_marker: str) -> dict:
        operation_marker = _operation_marker(operation_marker)
        internal = self._group_internal_id(group_id)
        current = self._request("GET",
            f"/admin/realms/{REALM}/groups/{quote(internal, safe='')}")
        normalized = self._group(current)
        if status not in ("Active", "Inactive"):
            raise ValueError("DIRECTORY_GROUP_STATUS_INVALID")
        replay = _is_replay(_attributes(current.get("attributes")),
                            operation_marker)
        if not replay:
            attributes = _attributes(current.get("attributes"))
            attributes.update({"openepm_status": [status],
                               "openepm_last_operation": [operation_marker]})
            self._request("PUT",
                f"/admin/realms/{REALM}/groups/{quote(internal, safe='')}",
                body={**current, "name": current["name"],
                      "attributes": attributes},
                allowed=(204,))
        retired = (self._retire_group_memberships(internal)
                   if status == "Inactive" else {
                       "membershipsRemoved": 0, "sessionsRevoked": 0})
        return {**self.read_group(group_id), **retired}

    def _logout_user(self, subject_id: str) -> None:
        self._request("POST",
            f"/admin/realms/{REALM}/users/{quote(subject_id, safe='')}/logout",
            allowed=(204,))

    def _retire_group_memberships(self, internal: str) -> dict:
        removed = 0
        while True:
            query = urlencode({"first": 0, "max": 100,
                               "briefRepresentation": "true"})
            value = self._request("GET",
                f"/admin/realms/{REALM}/groups/{quote(internal, safe='')}"
                f"/members?{query}")
            if type(value) is not list or len(value) > 100:
                raise KeycloakDirectoryError(
                    "KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
            if not value:
                return {"membershipsRemoved": removed,
                        "sessionsRevoked": removed}
            if removed + len(value) > MAX_GROUP_RETIREMENT_MEMBERS:
                raise KeycloakDirectoryError(
                    "KEYCLOAK_DIRECTORY_GROUP_RETIREMENT_LIMIT")
            for item in value:
                subject_id = item.get("id") if type(item) is dict else None
                if not isinstance(subject_id, str) or not subject_id:
                    raise KeycloakDirectoryError(
                        "KEYCLOAK_DIRECTORY_RESPONSE_INVALID")
                self._request("DELETE",
                    f"/admin/realms/{REALM}/users/"
                    f"{quote(subject_id, safe='')}/groups/"
                    f"{quote(internal, safe='')}", allowed=(204,))
                self._logout_user(subject_id)
                removed += 1

    def set_membership(self, subject_id: str, group_id: str,
                       action: str) -> dict:
        self.read_user(subject_id)
        if action not in ("add", "remove"):
            raise ValueError("DIRECTORY_MEMBERSHIP_ACTION_INVALID")
        group = self.read_group(group_id)
        if action == "add" and group["status"] != "Active":
            raise KeycloakDirectoryError("DIRECTORY_GROUP_INACTIVE")
        internal = group["groupId"]
        self._request("PUT" if action == "add" else "DELETE",
            f"/admin/realms/{REALM}/users/{quote(subject_id, safe='')}"
            f"/groups/{quote(internal, safe='')}", allowed=(204,))
        # Existing access tokens retain their original group claims. Force a
        # fresh Keycloak session after every membership transition rather than
        # allowing an old claim to survive a removal.
        self._logout_user(subject_id)
        return {"subjectId": subject_id, "groupId": group["groupId"],
                "membership": action == "add", "sessionsRevoked": True}
