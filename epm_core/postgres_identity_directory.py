"""Platform-operator-governed Keycloak directory application functions."""
from __future__ import annotations

from hashlib import sha256
import json

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .keycloak_directory import (
    DIRECTORY_DESCRIPTION_LIMITS, IDENTIFIER, USERNAME, KeycloakDirectory, directory_description_attributes,
    validate_temporary_password,
)
from .postgres_access import VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_platform_provision import (
    PostgresPlatformProvisioner, platform_operation_actor_digest)


USER_CREATE = "identity.native-user.create"
USER_UPDATE = "identity.native-user.update"
USER_STATUS = "identity.native-user.status.set"
USER_PASSWORD = "identity.native-user.password.set"
USER_READ = "identity.native-user.read"
USER_LIST = "identity.native-user.list"
GROUP_CREATE = "identity.group.create"
GROUP_UPDATE = "identity.group.update"
GROUP_STATUS = "identity.group.status.set"
GROUP_READ = "identity.group.read"
GROUP_LIST = "identity.group.list"
MEMBERSHIP_LIST = "identity.group.membership.list"
MEMBERSHIP_SET = "identity.group.membership.set"
DIRECTORY_RECONCILE = "identity.directory.reconcile"
SERVER_ADMINISTRATOR_ACCESS = "identity.server-administrator.access.set"
WRITE_FUNCTIONS = frozenset((USER_CREATE, USER_UPDATE, USER_STATUS,
                             USER_PASSWORD,
                             GROUP_CREATE, GROUP_UPDATE, GROUP_STATUS,
                             MEMBERSHIP_SET, DIRECTORY_RECONCILE,
                             SERVER_ADMINISTRATOR_ACCESS))
READ_FUNCTIONS = frozenset((USER_READ, USER_LIST, GROUP_READ, GROUP_LIST,
                            MEMBERSHIP_LIST))
ALL_FUNCTIONS = WRITE_FUNCTIONS | READ_FUNCTIONS


class DirectoryPasswordOutcomeUnknown(ValueError):
    code = "DIRECTORY_PASSWORD_OUTCOME_UNKNOWN"

    def __init__(self):
        super().__init__(self.code)

_DIRECTORY_GROUP_AUTHORITY_TABLES = (
    ("identity_group_directory_state", ()),
    ("identity_group_membership_state", ("subject_id",)),
)

_DESCRIPTION_ERROR = {
    USER_CREATE: "DIRECTORY_USER_CREATE_INVALID",
    USER_UPDATE: "DIRECTORY_USER_UPDATE_INVALID",
    GROUP_CREATE: "DIRECTORY_GROUP_CREATE_INVALID",
    GROUP_UPDATE: "DIRECTORY_GROUP_UPDATE_INVALID",
}


def _legacy_group_mapping(groups: list[dict], observed_ids: set[str]
                          ) -> dict[str, str]:
    """Resolve legacy names to UUIDs, refusing every ambiguous cutover."""
    immutable_ids = {item["groupId"] for item in groups}
    by_name: dict[str, str] = {}
    for item in groups:
        name = item["groupName"]
        if name in by_name:
            raise ValueError("DIRECTORY_GROUP_NAME_DUPLICATE")
        by_name[name] = item["groupId"]
    if any(name in immutable_ids and name != immutable_id
           for name, immutable_id in by_name.items()):
        raise ValueError("DIRECTORY_GROUP_NAME_ID_COLLISION")
    unknown = observed_ids - immutable_ids - set(by_name)
    if unknown:
        raise ValueError("DIRECTORY_GROUP_MAPPING_MISSING")
    mapping = {legacy: by_name[legacy]
               for legacy in observed_ids - immutable_ids}
    if len(set(mapping.values())) != len(mapping):
        raise ValueError("DIRECTORY_GROUP_TARGET_DUPLICATE")
    return mapping


def _program(program: object) -> tuple[str, dict]:
    if (type(program) is not dict
            or set(program) != {"languageVersion", "function", "arguments"}
            or type(program.get("languageVersion")) is not int
            or program.get("languageVersion") != 2
            or type(program.get("function")) is not str
            or program.get("function") not in ALL_FUNCTIONS
            or type(program.get("arguments")) is not dict):
        raise ValueError("V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED")
    function, arguments = program["function"], program["arguments"]
    shapes = {
        USER_CREATE: {"username", "displayName",
                      "shortDescription", "semanticDescription"},
        USER_UPDATE: {"subjectId", "displayName", "shortDescription",
                      "semanticDescription"},
        USER_STATUS: {"subjectId", "status"},
        USER_PASSWORD: {"subjectId", "temporaryPassword"},
        USER_READ: {"subjectId"},
        USER_LIST: {"offset", "limit"},
        GROUP_CREATE: {"groupId", "displayName", "shortDescription",
                       "semanticDescription"},
        GROUP_UPDATE: {"groupId", "displayName", "shortDescription",
                       "semanticDescription"},
        GROUP_STATUS: {"groupId", "status"},
        GROUP_READ: {"groupId"},
        GROUP_LIST: {"offset", "limit"},
        MEMBERSHIP_LIST: {"afterGroupId", "afterSubjectId", "limit"},
        MEMBERSHIP_SET: {"subjectId", "groupId", "action"},
        DIRECTORY_RECONCILE: set(),
        SERVER_ADMINISTRATOR_ACCESS: {"subjectId", "access"},
    }
    if set(arguments) != shapes[function]:
        raise ValueError("V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED")
    if (function == SERVER_ADMINISTRATOR_ACCESS
            and arguments["access"] not in ("Grant", "Revoke")):
        raise ValueError("SERVER_ADMINISTRATOR_ACCESS_INVALID")
    return function, arguments


def _require_identifier(value: object, code: str) -> None:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(code)


def _validate_write_arguments(function: str, arguments: dict) -> None:
    if function == USER_PASSWORD:
        validate_temporary_password(arguments["subjectId"], arguments["temporaryPassword"])
        return
    if function == SERVER_ADMINISTRATOR_ACCESS:
        subject_id = arguments["subjectId"]
        if not isinstance(subject_id, str) or not subject_id or "\0" in subject_id:
            raise ValueError("SERVER_ADMINISTRATOR_ACCESS_INVALID")
        return
    if function == USER_CREATE:
        username = arguments["username"]
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ValueError("DIRECTORY_USER_CREATE_INVALID")
    elif "subjectId" in arguments:
        _require_identifier(arguments["subjectId"], "DIRECTORY_SUBJECT_ID_INVALID")
    if "groupId" in arguments:
        _require_identifier(arguments["groupId"], "DIRECTORY_GROUP_CREATE_INVALID"
                            if function == GROUP_CREATE else "DIRECTORY_GROUP_ID_INVALID")
    if function in _DESCRIPTION_ERROR:
        directory_description_attributes(arguments, _DESCRIPTION_ERROR[function])
    if function in (USER_STATUS, GROUP_STATUS) and arguments["status"] not in ("Active", "Inactive"):
        raise ValueError("DIRECTORY_USER_STATUS_INVALID" if function == USER_STATUS
                         else "DIRECTORY_GROUP_STATUS_INVALID")
    if function == MEMBERSHIP_SET and arguments["action"] not in ("add", "remove"):
        raise ValueError("DIRECTORY_MEMBERSHIP_ACTION_INVALID")


def compile_directory_write(program: object) -> tuple[str, dict]:
    function, arguments = _program(program)
    if function not in WRITE_FUNCTIONS:
        raise ValueError("V2_FUNCTION_MODE_MISMATCH")
    _validate_write_arguments(function, arguments)
    return function, arguments


def compile_directory_read(program: object) -> tuple[str, dict]:
    function, arguments = _program(program)
    if function not in READ_FUNCTIONS:
        raise ValueError("V2_FUNCTION_MODE_MISMATCH")
    if function in (USER_READ, GROUP_READ):
        user = function == USER_READ
        identifier = arguments["subjectId" if user else "groupId"]
        _require_identifier(identifier, "DIRECTORY_SUBJECT_ID_INVALID" if user else "DIRECTORY_GROUP_ID_INVALID")
    elif function in (USER_LIST, GROUP_LIST):
        offset, limit = arguments["offset"], arguments["limit"]
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("DIRECTORY_PAGE_INVALID")
    else:
        after_group, after_subject, limit = (arguments["afterGroupId"], arguments["afterSubjectId"], arguments["limit"])
        if (type(limit) is not int or not 1 <= limit <= 100
                or (after_group is None) != (after_subject is None)
                or (after_group is not None and any(not isinstance(key, str) or not 1 <= len(key) <= 300
                                                   or "\0" in key for key in (after_group, after_subject)))):
            raise ValueError("DIRECTORY_MEMBERSHIP_PAGE_INVALID")
    return function, arguments


def _directory_record_fields(*, user: bool) -> dict:
    text = {"type": "string"}
    return {("subjectId" if user else "groupId"): text,
            ("username" if user else "groupName"): text,
            "displayName": text, "shortDescription": text, "semanticDescription": text,
            "status": {"enum": ["Active", "Inactive"]}}


def directory_read_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    if function not in READ_FUNCTIONS:
        raise ValueError("DIRECTORY_READ_FUNCTION_INVALID")
    identifier = {"type": "string", "pattern": rf"^{IDENTIFIER.pattern}(?![\s\S])"}
    limit = {"type": "integer", "minimum": 1, "maximum": 100}
    rules = ["This read requires current platform operator authority on the platform listener."]
    if function == MEMBERSHIP_LIST:
        key = {"type": "string", "minLength": 1, "maxLength": 300, "pattern": r"^[^\x00]+(?![\s\S])"}
        nullable_key = {"anyOf": [key, {"type": "null"}]}
        arguments = {**obj({"afterGroupId": nullable_key, "afterSubjectId": nullable_key, "limit": limit}),
                     "oneOf": [{"properties": {"afterGroupId": {"type": kind}, "afterSubjectId": {"type": kind}}}
                               for kind in ("null", "string")]}
        keys = {"groupId": key, "subjectId": key}
        membership = obj({**keys, "directoryRevision": {"type": "integer", "minimum": 1}})
        result = obj({"items": {"type": "array", "maxItems": 100, "items": membership},
                      "nextAfter": {"oneOf": [obj(keys), {"type": "null"}]}})
        examples = [
            read_example(function, {"afterGroupId": None, "afterSubjectId": None, "limit": 25},
                         name="List current memberships", binding="Use null for both fields on the first page."),
            read_example(function, {"afterGroupId": "example-group", "afterSubjectId": "example-subject", "limit": 25},
                         name="Continue the memberships list", binding="Use both keys from the exact returned nextAfter pair."),
        ]
        rules.append("Membership pages list active rows from the current directory projection. Null nextAfter ends the listing.")
    else:
        user = function in (USER_READ, USER_LIST)
        field, label = ("subjectId", "user") if user else ("groupId", "group")
        record = obj(_directory_record_fields(user=user))
        if function in (USER_LIST, GROUP_LIST):
            arguments = obj({"offset": {"type": "integer", "minimum": 0}, "limit": limit})
            result = obj({"items": {"type": "array", "maxItems": 100, "items": record},
                          "nextOffset": {"type": ["integer", "null"], "minimum": 1}})
            examples = [
                read_example(function, {"offset": 0, "limit": 25}, name=f"List managed {label}s",
                             binding="Start at offset zero."),
                read_example(function, {"offset": 25, "limit": 25}, name=f"Continue the {label} list",
                             binding="Use the returned nextOffset, even after an empty page."),
            ]
            rules.append("Offsets count provider entries before filtering. Continue until nextOffset is null.")
        else:
            arguments, result = obj({field: identifier}), record
            examples = [read_example(function, {field: f"example-{label}"}, name=f"Inspect a managed {label}",
                                     binding=f"Use the exact {field} returned by current directory discovery.")]
    contract = read_contract(function, arguments, result, owner="PostgresIdentityDirectory",
                             examples=examples, semantic_rules=rules, result_scope="result")
    contract["programContract"]["recovery"] = (
        "Use the current platform catalogue to repair a malformed request. After an interrupted read, "
        "check current authority and retry the exact read or restart the list.")
    return contract


def directory_write_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    if function not in WRITE_FUNCTIONS:
        raise ValueError("DIRECTORY_WRITE_FUNCTION_INVALID")
    identifier = {"type": "string", "pattern": rf"^{IDENTIFIER.pattern}(?![\s\S])"}
    subject, group = {"subjectId": identifier}, {"groupId": identifier}
    count = {"type": "integer", "minimum": 0}
    boolean = {"type": "boolean"}
    active = {"enum": ["Active", "Inactive"]}
    descriptions = {field: {"type": "string", "maxLength": limit}
                    for field, limit in DIRECTORY_DESCRIPTION_LIMITS.items()}
    descriptions["displayName"]["minLength"] = 1
    names = {"displayName": "Planning directory example", "shortDescription": "",
             "semanticDescription": ""}
    subject_example = {"subjectId": "example-subject"}
    group_example = {"groupId": "example-group"}
    subject_binding = "Bind subjectId to the exact managed ID returned by the current user list."
    group_binding = "Bind groupId to the immutable ID returned by the current group list or create result."
    semantic = [
        "Use this write on the platform listener under current platform operator authority.",
        "Use execute_v2_platform_program with one unused idempotency_key for the reviewed program. "
        "Pass the original program and key for exact replay.",
    ]
    examples = []

    def example(arguments, name, binding):
        examples.append(read_example(function, arguments, name=name, binding=binding))

    if function in _DESCRIPTION_ERROR:
        user = function in (USER_CREATE, USER_UPDATE)
        identity = ({"username": {"type": "string", "pattern": rf"^{USERNAME.pattern}(?![\s\S])"}}
                    if function == USER_CREATE else subject if user else group)
        arguments = {**identity, **descriptions}
        result = obj(_directory_record_fields(user=user))
        if function == USER_CREATE:
            example({"username": "planning.example", **names}, "Create a managed user",
                    "Choose an unused username. Retain subjectId from the result. Assign any temporary credential separately.")
        elif function == GROUP_CREATE:
            example({**group_example, **names}, "Create a managed group",
                    "Supply the new group name in groupId. Retain the immutable provider groupId returned in the result.")
        else:
            example({**(subject_example if user else group_example), **names},
                    "Update user descriptions" if user else "Update group descriptions",
                    subject_binding if user else group_binding)
        semantic.append("Supply descriptive values without leading or trailing whitespace or NUL characters.")
    elif function in (USER_STATUS, GROUP_STATUS):
        user = function == USER_STATUS
        arguments = {**(subject if user else group), "status": active}
        record = _directory_record_fields(user=user)
        if user:
            result = {"oneOf": [
                obj({**record, "status": {"const": "Active"}, "sessionsRevoked": {"const": False}}),
                obj({**record, "status": {"const": "Inactive"}, "sessionsRevoked": {"const": True},
                     "tokensValidAfter": count}),
            ]}
        else:
            result = obj({**record, "membershipsRemoved": count, "sessionsRevoked": count})
        for status in ("Inactive", "Active"):
            example({**(subject_example if user else group_example), "status": status},
                    f"Set {'user' if user else 'group'} status to {status}",
                    subject_binding if user else group_binding)
        semantic.append("Deactivation fences existing authority. Reactivation does not restore prior sessions or removed memberships.")
    elif function == MEMBERSHIP_SET:
        arguments = {**subject, **group, "action": {"enum": ["add", "remove"]}}
        result = obj({"subjectId": {"type": "string"}, "groupId": {"type": "string"},
                      "membership": boolean, "sessionsRevoked": {"const": True}})
        for action in ("add", "remove"):
            example({**subject_example, **group_example, "action": action},
                    f"{action.capitalize()} managed membership", f"{subject_binding} {group_binding}")
        semantic.append("Both changes fence existing sessions. Addition requires a current active group.")
    elif function == DIRECTORY_RECONCILE:
        arguments = {}
        result = obj({"issuer": {"type": "string"}, "directoryRevision": count, "userCount": count,
                      "groupCount": count, "membershipCount": count, "legacyGroupAuthorityRowsMigrated": count,
                      "snapshotDigest": {"type": "string", "pattern": r"^[0-9a-f]{64}(?![\s\S])"}})
        example({}, "Reconcile the current managed directory",
                "Review reconciliation for the configured provider. The response contains counts and a snapshot digest.")
        semantic.append("Reconciliation reads the configured provider and replaces its directory projection. It preserves the cutoff on an unchanged identity.")
    elif function == SERVER_ADMINISTRATOR_ACCESS:
        arguments = {"subjectId": {"type": "string", "minLength": 1, "pattern": r"^[^\x00]+(?![\s\S])"},
                     "access": {"enum": ["Grant", "Revoke"]}}
        result = obj({"issuer": {"type": "string"}, "subjectId": {"type": "string"},
                      "access": {"enum": ["Granted", "Revoked"]}, "changed": boolean})
        for access in ("Grant", "Revoke"):
            example({**subject_example, "access": access}, f"{access} Server Administrator access", subject_binding)
        semantic.append("Server Administrator access is separate from application and workspace grants. The core checks target activity and protects the final administrator.")
    else:
        arguments = {**subject, "temporaryPassword": {"type": "string", "format": "password", "writeOnly": True}}
        settled = {"subjectId": {"type": "string"}, "passwordChanged": {"const": True},
                   "temporary": {"const": True}, "sessionsRevoked": {"const": True}}
        result = obj({**settled, "tokensValidAfter": count}, list(settled))
        semantic.extend([
            "Bind subjectId to the managed ID of an active user. Supply a new private temporary credential at dispatch.",
            "Use 12 to 256 characters with ASCII lower and upper case letters, a digit and a non-alphanumeric character. "
            "Characters below U+0020 are refused. Keep the credential out of stored examples and recovery records.",
        ])
    contract = read_contract(function, obj(arguments), result, owner="PostgresIdentityDirectory",
                             examples=examples, semantic_rules=semantic, result_scope="result")
    recovery = (
        "After an interrupted response, use platform.operation.receipt.read with operationId set to the original "
        "idempotency key under current operator authority. A Pending receipt leaves the outcome unconfirmed.")
    if function == USER_PASSWORD:
        recovery += (" Inspect the receipt without the credential. An unresolved assignment can return "
                     "DIRECTORY_PASSWORD_OUTCOME_UNKNOWN and stops before another reset.")
    contract["programContract"]["recovery"] = recovery
    return contract


def catalog() -> dict:
    descriptions = {
        USER_CREATE: ("atomic_write", "native user without password material"),
        USER_UPDATE: ("atomic_write", "native user descriptive fields"),
        USER_STATUS: ("atomic_write", "native user active status"),
        USER_PASSWORD: ("atomic_write",
                        "temporary password replacement without retention"),
        USER_READ: ("read", "one managed native user"),
        USER_LIST: ("read", "bounded managed native-user page"),
        GROUP_CREATE: ("atomic_write", "stable group and mutable descriptions"),
        GROUP_UPDATE: ("atomic_write", "group descriptive fields"),
        GROUP_STATUS: ("atomic_write", "group active status"),
        GROUP_READ: ("read", "one managed group"),
        GROUP_LIST: ("read", "bounded managed-group page"),
        MEMBERSHIP_LIST: ("read", "current bounded group-membership page"),
        MEMBERSHIP_SET: ("atomic_write", "explicit user/group membership"),
        DIRECTORY_RECONCILE: ("atomic_write",
                              "current Keycloak authorization snapshot"),
        SERVER_ADMINISTRATOR_ACCESS: (
            "atomic_write", "audited Server Administrator authority"),
    }
    result = {}
    for name, (mode, effect) in descriptions.items():
        result[name] = {"mode": mode, "permission": "platform_operator",
                        "arguments": "strict typed V2 arguments",
                        "result": effect,
                        "previewRequired": False,
                        "idempotencyRequired": mode == "atomic_write",
                        "workClass": "short"}
        if name in READ_FUNCTIONS:
            result[name].update(directory_read_contract(name))
        else:
            result[name].update(directory_write_contract(name))
    return {"languageVersion": 2, "functions": result}


class PostgresIdentityDirectory:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 directory: KeycloakDirectory, directory_issuer: str | None = None):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("Verified identity is required")
        directory_issuer = directory_issuer or identity.issuer
        if (not isinstance(directory_issuer, str)
                or not 1 <= len(directory_issuer) <= 300
                or directory_issuer != directory_issuer.strip()
                or any(ord(character) < 32 for character in directory_issuer)):
            raise ValueError("DIRECTORY_ISSUER_INVALID")
        self.dsn, self.identity, self.directory = dsn, identity, directory
        self.directory_issuer = directory_issuer

    def _check(self) -> None:
        PostgresPlatformProvisioner(self.dsn,
                                    identity=self.identity).check()

    def read(self, program: object) -> dict:
        function, arguments = compile_directory_read(program)
        if function == MEMBERSHIP_LIST:
            return self._list_memberships(arguments)
        self._check()
        if function == USER_READ:
            result = self.directory.read_user(arguments["subjectId"])
        elif function == USER_LIST:
            result = self.directory.list_users(offset=arguments["offset"],
                                               limit=arguments["limit"])
        elif function == GROUP_READ:
            result = self.directory.read_group(arguments["groupId"])
        else:
            result = self.directory.list_groups(offset=arguments["offset"],
                                                limit=arguments["limit"])
        # Directory data is administrative security information.  A current
        # grant is required both before and after the external read.
        self._check()
        return result

    def _list_memberships(self, arguments: dict) -> dict:
        after_group = arguments["afterGroupId"]
        after_subject = arguments["afterSubjectId"]
        limit = arguments["limit"]
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresPlatformProvisioner._require_operator(db, self.identity)
                rows = db.execute("""SELECT group_id,subject_id,directory_revision
                    FROM epm.identity_group_membership_state
                    WHERE issuer=%s AND active
                      AND (%s::text IS NULL OR (group_id,subject_id)>(%s,%s))
                    ORDER BY group_id,subject_id LIMIT %s""",
                    (self.directory_issuer, after_group, after_group,
                     after_subject, limit + 1)).fetchall()
                PostgresPlatformProvisioner._require_operator(db, self.identity)
        items = [{"groupId": row["group_id"],
                  "subjectId": row["subject_id"],
                  "directoryRevision": row["directory_revision"]}
                 for row in rows[:limit]]
        next_after = (None if len(rows) <= limit else {
            "groupId": items[-1]["groupId"],
            "subjectId": items[-1]["subjectId"]})
        return {"items": items, "nextAfter": next_after}

    def execute(self, program: object, *, idempotency_key: str) -> dict:
        function, arguments = _program(program)
        if function not in WRITE_FUNCTIONS:
            raise ValueError("V2_FUNCTION_MODE_MISMATCH")
        if (not isinstance(idempotency_key, str)
                or not 1 <= len(idempotency_key) <= 135
                or any(character.isspace() for character in idempotency_key)):
            raise ValueError("Idempotency key is required")
        if function == SERVER_ADMINISTRATOR_ACCESS:
            return self._execute_server_administrator_access(
                program, arguments, idempotency_key=idempotency_key)
        digest = sha256(json.dumps(program, sort_keys=True,
            ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        actor_digest = platform_operation_actor_digest(self.identity)
        marker = idempotency_key + ":" + digest
        with connect_postgres(self.dsn, row_factory=dict_row,
                              autocommit=True) as db:
            db.execute("SELECT pg_advisory_lock(hashtextextended(%s,0))",
                       ("epm.identity-directory:" + idempotency_key,))
            password_started = False
            membership_fence = False
            try:
                with db.transaction():
                    PostgresPlatformProvisioner._require_operator(
                        db, self.identity)
                    previous = db.execute("""SELECT command_digest,actor_digest,
                        result,status FROM epm.platform_operation_receipt
                        WHERE operation_id=%s""",
                        (idempotency_key,)).fetchone()
                    if previous:
                        if (previous["command_digest"] != digest
                                or previous["actor_digest"] != actor_digest):
                            raise ValueError("IDEMPOTENCY_KEY_REUSED")
                        if previous["status"] == "Committed":
                            return previous["result"]
                        if function == USER_PASSWORD:
                            # Keycloak's reset endpoint has no operation key that
                            # can prove the original credential was left untouched.
                            raise DirectoryPasswordOutcomeUnknown()
                    # Deterministic input errors must precede receipt creation
                    # and the local session cutoff for provider-side effects.
                    _validate_write_arguments(function, arguments)
                    membership_change = function in (
                        MEMBERSHIP_SET, USER_STATUS, GROUP_STATUS, DIRECTORY_RECONCILE)
                    if membership_change:
                        # Hold through the provider request and its local projection.
                        # Assignment writers acquire the matching shared xact lock.
                        membership_fence = db.execute("""SELECT pg_try_advisory_lock(
                            hashtextextended('epm.authorization.directory-membership',0)) AS held"""
                        ).fetchone()['held']
                        if not membership_fence:
                            raise ValueError('DIRECTORY_AUTHORIZATION_CHANGE_BUSY')
                        removing = (arguments.get('status') == 'Inactive'
                                    or arguments.get('action') == 'remove')
                        if removing:
                            removal = (self.directory_issuer, arguments.get('subjectId'), arguments.get('groupId'))
                            continuity = db.execute("""SELECT
                                epm.directory_removal_preserves_assignment_admins(%s,%s,%s) AS applications,
                                epm.directory_removal_preserves_workspace_admins(%s,%s,%s) AS workspaces""",
                                (*removal, *removal)).fetchone()
                            if not continuity['applications']:
                                raise ValueError('LAST_REACHABLE_APPLICATION_ADMINISTRATOR')
                            if not continuity['workspaces']:
                                raise ValueError('LAST_WORKSPACE_ADMINISTRATOR')
                    if previous is None:
                        db.execute("""INSERT INTO epm.platform_operation_receipt
                            (operation_id,command_digest,actor_digest,
                             function_name,status,result)
                            VALUES (%s,%s,%s,%s,'Pending','{}'::jsonb)""",
                            (idempotency_key, digest, actor_digest, function))
                    self._pre_fence_session_authority(
                        db, function=function, arguments=arguments)
                password_started = function == USER_PASSWORD
                result = self._apply(function, arguments, marker)
                with db.transaction():
                    PostgresPlatformProvisioner._require_operator(
                        db, self.identity)
                    previous = db.execute("""SELECT command_digest,actor_digest,
                        result,status FROM epm.platform_operation_receipt
                        WHERE operation_id=%s""",
                        (idempotency_key,)).fetchone()
                    if previous:
                        if (previous["command_digest"] != digest
                                or previous["actor_digest"] != actor_digest):
                            raise ValueError("IDEMPOTENCY_KEY_REUSED")
                        if previous["status"] == "Committed":
                            return previous["result"]
                    committed_result = self._record_current_state(
                        db, function=function, arguments=arguments,
                        result=result)
                    db.execute("""UPDATE epm.platform_operation_receipt
                        SET status='Committed',result=%s,
                            committed_at=transaction_timestamp()
                        WHERE operation_id=%s AND status='Pending'""",
                        (Jsonb(committed_result), idempotency_key))
                    target = (committed_result.get("subjectId")
                              or committed_result.get("groupId")
                              or "directory")
                    db.execute("""INSERT INTO epm.security_audit
                        (actor_id,action,target_digest,outcome,detail)
                        VALUES (%s,%s,%s,'Accepted',%s)""",
                        (actor_digest, function,
                         sha256(target.encode()).hexdigest(),
                         Jsonb({"directory": "keycloak"})))
                return committed_result
            except Exception:
                if password_started:
                    raise DirectoryPasswordOutcomeUnknown() from None
                raise
            finally:
                if membership_fence:
                    db.execute("""SELECT pg_advisory_unlock(
                        hashtextextended('epm.authorization.directory-membership',0))""")
                db.execute("SELECT pg_advisory_unlock(hashtextextended(%s,0))",
                           ("epm.identity-directory:" + idempotency_key,))

    def _execute_server_administrator_access(
            self, program: dict, arguments: dict, *,
            idempotency_key: str) -> dict:
        """Atomically delegate or revoke the bounded platform authority.

        Unlike Keycloak directory changes, this effect is wholly PostgreSQL-
        authoritative and therefore commits with its receipt and audit.  The
        fixed SQL function independently serializes all administrators and
        rechecks the current caller, target activity, self-revocation and the
        last-administrator invariant.
        """
        digest = sha256(json.dumps(program, sort_keys=True,
            ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        actor_digest = platform_operation_actor_digest(self.identity)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresPlatformProvisioner._require_operator(
                    db, self.identity)
                db.execute("""SELECT pg_advisory_xact_lock(
                    hashtextextended('epm.platform-operation:' || %s,0))""",
                    (idempotency_key,))
                previous = db.execute("""SELECT command_digest,actor_digest,
                    result,status FROM epm.platform_operation_receipt
                    WHERE operation_id=%s""", (idempotency_key,)).fetchone()
                if previous:
                    if (previous["command_digest"] != digest
                            or previous["actor_digest"] != actor_digest):
                        raise ValueError("IDEMPOTENCY_KEY_REUSED")
                    if previous["status"] != "Committed":
                        raise ValueError("PLATFORM_OPERATION_INCOMPLETE")
                    return previous["result"]
                _validate_write_arguments(SERVER_ADMINISTRATOR_ACCESS, arguments)
                result = db.execute("""SELECT
                    epm.set_server_administrator_access(%s,%s,%s,%s,%s)
                    AS result""", (
                        self.identity.issuer, self.identity.subject_id,
                        self.directory_issuer, arguments["subjectId"],
                        arguments["access"] == "Grant",
                    )).fetchone()["result"]
                db.execute("""INSERT INTO epm.platform_operation_receipt
                    (operation_id,command_digest,actor_digest,function_name,
                     status,result,committed_at)
                    VALUES (%s,%s,%s,%s,'Committed',%s,
                            transaction_timestamp())""", (
                        idempotency_key, digest, actor_digest,
                        SERVER_ADMINISTRATOR_ACCESS, Jsonb(result),
                    ))
                db.execute("""INSERT INTO epm.security_audit
                    (actor_id,action,target_digest,outcome,detail)
                    VALUES (%s,%s,%s,'Accepted',%s)""", (
                        actor_digest, SERVER_ADMINISTRATOR_ACCESS,
                        sha256(arguments["subjectId"].encode()).hexdigest(),
                        Jsonb({"authority": "server_administrator",
                               "access": arguments["access"],
                               "changed": result["changed"]}),
                    ))
                return result

    def _pre_fence_session_authority(self, db, *, function: str,
                                     arguments: dict) -> None:
        """Revoke stale bearer authority before an external Keycloak effect.

        Keycloak session mutation and PostgreSQL projection cannot share one
        transaction.  Advancing the local epoch first makes an interruption
        fail closed: the user may need to authenticate again even when the
        external mutation fails, but an old access token can never survive a
        successful external reset/removal followed by a local commit failure.
        """
        subject_id = None
        if function == USER_PASSWORD:
            subject_id = arguments["subjectId"]
        elif function == USER_STATUS and arguments["status"] == "Inactive":
            subject_id = arguments["subjectId"]
        elif function == MEMBERSHIP_SET:
            subject_id = arguments["subjectId"]
        if subject_id is not None:
            changed = db.execute("""UPDATE epm.identity_user_directory_state
                SET tokens_valid_after=greatest(tokens_valid_after,
                    extract(epoch FROM clock_timestamp())::bigint),
                    updated_at=transaction_timestamp()
                WHERE issuer=%s AND subject_id=%s""",
                (self.directory_issuer, subject_id)).rowcount
            if changed != 1:
                raise ValueError(
                    "DIRECTORY_USER_REVOCATION_PROJECTION_UNAVAILABLE")
            return
        if function == GROUP_STATUS and arguments["status"] == "Inactive":
            db.execute("""UPDATE epm.identity_user_directory_state u
                SET tokens_valid_after=greatest(u.tokens_valid_after,
                    extract(epoch FROM clock_timestamp())::bigint),
                    updated_at=transaction_timestamp()
                WHERE u.issuer=%s AND EXISTS (SELECT 1
                  FROM epm.identity_group_membership_state m
                  WHERE m.issuer=u.issuer AND m.subject_id=u.subject_id
                    AND m.group_id=%s AND m.active)""",
                (self.directory_issuer, arguments["groupId"]))

    def _record_current_state(self, db, *, function: str,
                              arguments: dict, result: dict) -> dict:
        """Commit the Keycloak-derived revocation projection with receipt.

        This is deliberately not a writable user/group directory.  The
        external Keycloak mutation has already succeeded and ``result`` is
        its normalized response.  The projection only lets fixed-core access
        checks fence stale self-contained tokens immediately.
        """
        if function == DIRECTORY_RECONCILE:
            return self._replace_current_state(db, result)
        if function not in {USER_CREATE, USER_UPDATE, USER_STATUS, USER_PASSWORD,
                            GROUP_CREATE, GROUP_UPDATE, GROUP_STATUS,
                            MEMBERSHIP_SET}:
            return result
        revision = db.execute("""UPDATE epm.identity_directory_state
            SET revision=revision+1,updated_at=transaction_timestamp()
            WHERE singleton=true RETURNING revision""").fetchone()["revision"]
        # Directory state belongs to the configured Keycloak realm, not to
        # whichever issuer authenticated the platform operator during a
        # guarded identity-provider transition.
        issuer = self.directory_issuer
        if function in {USER_CREATE, USER_UPDATE, USER_STATUS, USER_PASSWORD}:
            subject_id = result.get("subjectId")
            status = result.get("status", "Active")
            principal_digest = sha256(
                (issuer + "\0" + subject_id).encode()).hexdigest()
            db.execute("""INSERT INTO epm.identity_user_directory_state
                (issuer,subject_id,status,directory_revision,tokens_valid_after,
                 username,display_name,principal_digest)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (issuer,subject_id) DO UPDATE SET
                    status=excluded.status,
                    directory_revision=excluded.directory_revision,
                    username=coalesce(excluded.username,
                                      epm.identity_user_directory_state.username),
                    display_name=coalesce(excluded.display_name,
                        epm.identity_user_directory_state.display_name),
                    principal_digest=excluded.principal_digest,
                    tokens_valid_after=greatest(
                      epm.identity_user_directory_state.tokens_valid_after,
                      excluded.tokens_valid_after),
                    updated_at=transaction_timestamp()""",
                (issuer, subject_id, status, revision,
                 result.get("tokensValidAfter", 0), result.get("username"),
                 result.get("displayName"), principal_digest))
            return result
        if function in {GROUP_CREATE, GROUP_UPDATE, GROUP_STATUS}:
            group_id = result.get("groupId")
            status = result.get("status", "Active")
            principal_digest = sha256(
                (issuer + "\0group\0" + group_id).encode()).hexdigest()
            db.execute("""INSERT INTO epm.identity_group_directory_state
                (issuer,group_id,status,directory_revision,group_name,
                 display_name,principal_digest)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (issuer,group_id) DO UPDATE SET
                    status=excluded.status,
                    directory_revision=excluded.directory_revision,
                    group_name=coalesce(excluded.group_name,
                        epm.identity_group_directory_state.group_name),
                    display_name=coalesce(excluded.display_name,
                        epm.identity_group_directory_state.display_name),
                    principal_digest=excluded.principal_digest,
                    updated_at=transaction_timestamp()""",
                (issuer, group_id, status, revision, result.get("groupName"),
                 result.get("displayName"), principal_digest))
            if status == "Inactive":
                db.execute("""UPDATE epm.identity_group_membership_state
                    SET active=false,directory_revision=%s,
                        updated_at=transaction_timestamp()
                    WHERE issuer=%s AND group_id=%s AND active""",
                    (revision, issuer, group_id))
            return result
        db.execute("""INSERT INTO epm.identity_group_membership_state
            (issuer,subject_id,group_id,active,directory_revision)
            VALUES (%s,%s,%s,%s,%s)
            ON CONFLICT (issuer,subject_id,group_id) DO UPDATE SET
                active=excluded.active,
                directory_revision=excluded.directory_revision,
                updated_at=transaction_timestamp()""",
            (issuer, result.get("subjectId"), result.get("groupId"),
             bool(result.get("membership")), revision))
        return result

    def _replace_current_state(self, db, snapshot: dict) -> dict:
        if type(snapshot) is not dict or set(snapshot) != {
                "users", "groups", "memberships"}:
            raise ValueError("DIRECTORY_SNAPSHOT_INVALID")
        users, groups, memberships = (snapshot["users"], snapshot["groups"],
                                      snapshot["memberships"])
        if not all(type(value) is list for value in
                   (users, groups, memberships)):
            raise ValueError("DIRECTORY_SNAPSHOT_INVALID")
        if (len(users) > 100_000 or len(groups) > 10_000
                or len(memberships) > 1_000_000):
            raise ValueError("DIRECTORY_SNAPSHOT_INVALID")
        if (any(type(item) is not dict or set(item) != {
                    "subjectId", "username", "displayName", "status"}
                or item["status"] not in ("Active", "Inactive")
                for item in users)
                or any(type(item) is not dict
                       or set(item) != {"groupId", "groupName", "displayName",
                                       "status"}
                       or item["status"] not in ("Active", "Inactive")
                       for item in groups)
                or any(type(item) is not dict
                       or set(item) != {"subjectId", "groupId"}
                       for item in memberships)):
            raise ValueError("DIRECTORY_SNAPSHOT_INVALID")
        user_ids = [item["subjectId"] for item in users]
        group_ids = [item["groupId"] for item in groups]
        membership_keys = [(item["subjectId"], item["groupId"])
                           for item in memberships]
        user_id_set, group_id_set = set(user_ids), set(group_ids)
        if (len(user_id_set) != len(user_ids)
                or len(group_id_set) != len(group_ids)
                or len(set(membership_keys)) != len(membership_keys)
                or any(not isinstance(value, str) or not value
                       for value in user_ids + group_ids
                       + [item["username"] for item in users]
                       + [item["displayName"] for item in users]
                       + [item["groupName"] for item in groups]
                       + [item["displayName"] for item in groups])
                or any(not isinstance(value, str) or not value
                       for pair in membership_keys for value in pair)
                or any(subject_id not in user_id_set
                       or group_id not in group_id_set
                       for subject_id, group_id in membership_keys)):
            raise ValueError("DIRECTORY_SNAPSHOT_INVALID")
        migrated = self._migrate_legacy_group_authority(db, groups)
        digest = sha256(json.dumps(snapshot, sort_keys=True,
            ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        revision = db.execute("""UPDATE epm.identity_directory_state
            SET revision=revision+1,updated_at=transaction_timestamp()
            WHERE singleton=true RETURNING revision""").fetchone()["revision"]
        issuer = self.directory_issuer
        db.execute("DELETE FROM epm.identity_group_membership_state WHERE issuer=%s",
                   (issuer,))
        db.execute("DELETE FROM epm.identity_group_directory_state WHERE issuer=%s",
                   (issuer,))
        # A missing provider subject loses current authority immediately, but
        # deleting its session cutoff would revive older bearer/durable authority
        # if that exact immutable subject returned. Keep only the revocation
        # identity; missing subjects must not become a historical user catalogue.
        db.execute("""UPDATE epm.identity_user_directory_state
            SET status='Inactive',
                tokens_valid_after=greatest(tokens_valid_after,
                    CASE WHEN status='Active' THEN
                        extract(epoch FROM clock_timestamp())::bigint ELSE 0 END),
                directory_revision=%s,username=NULL,display_name=NULL,
                principal_digest=NULL,updated_at=transaction_timestamp()
            WHERE issuer=%s AND NOT (subject_id=ANY(%s::text[]))
              AND (status<>'Inactive' OR username IS NOT NULL
                   OR display_name IS NOT NULL OR principal_digest IS NOT NULL)""",
            (revision, issuer, user_ids))
        if users:
            db.execute("""INSERT INTO epm.identity_user_directory_state
                (issuer,subject_id,status,directory_revision,username,
                 display_name,principal_digest,tokens_valid_after)
                SELECT %s,item.subject_id,item.status,%s,item.username,
                       item.display_name,item.principal_digest,
                       CASE WHEN item.status='Inactive' THEN
                           extract(epoch FROM clock_timestamp())::bigint ELSE 0 END
                FROM jsonb_to_recordset(%s::jsonb)
                    AS item(subject_id text,status text,username text,
                            display_name text,principal_digest text)
                ON CONFLICT (issuer,subject_id) DO UPDATE SET
                    status=excluded.status,
                    directory_revision=excluded.directory_revision,
                    username=excluded.username,display_name=excluded.display_name,
                    principal_digest=excluded.principal_digest,
                    tokens_valid_after=greatest(
                        epm.identity_user_directory_state.tokens_valid_after,
                        CASE WHEN epm.identity_user_directory_state.status='Active'
                            AND excluded.status='Inactive'
                            THEN excluded.tokens_valid_after ELSE 0 END),
                    updated_at=transaction_timestamp()""",
                (issuer, revision, Jsonb([{
                    "subject_id": item["subjectId"],
                    "status": item["status"], "username": item["username"],
                    "display_name": item["displayName"],
                    "principal_digest": sha256((issuer + "\0" +
                        item["subjectId"]).encode()).hexdigest()}
                    for item in users])))
        if groups:
            db.execute("""INSERT INTO epm.identity_group_directory_state
                (issuer,group_id,status,directory_revision,group_name,
                 display_name,principal_digest)
                SELECT %s,item.group_id,item.status,%s,item.group_name,
                       item.display_name,item.principal_digest
                FROM jsonb_to_recordset(%s::jsonb)
                    AS item(group_id text,status text,group_name text,
                            display_name text,principal_digest text)""",
                (issuer, revision, Jsonb([{
                    "group_id": item["groupId"],
                    "status": item["status"],
                    "group_name": item["groupName"],
                    "display_name": item["displayName"],
                    "principal_digest": sha256((issuer + "\0group\0" +
                        item["groupId"]).encode()).hexdigest()}
                    for item in groups])))
        if memberships:
            db.execute("""INSERT INTO epm.identity_group_membership_state
                (issuer,subject_id,group_id,active,directory_revision)
                SELECT %s,item.subject_id,item.group_id,true,%s
                FROM jsonb_to_recordset(%s::jsonb)
                    AS item(subject_id text,group_id text)""",
                (issuer, revision, Jsonb([{"subject_id": item["subjectId"],
                    "group_id": item["groupId"]} for item in memberships])))
        return {"issuer": issuer, "directoryRevision": revision,
                "userCount": len(users), "groupCount": len(groups),
                "membershipCount": len(memberships),
                "legacyGroupAuthorityRowsMigrated": migrated,
                "snapshotDigest": digest}

    def _migrate_legacy_group_authority(self, db, groups: list[dict]) -> int:
        """Atomically replace legacy name keys before projection replacement."""
        issuer = self.directory_issuer
        unions = " UNION ".join(
            f"SELECT group_id FROM epm.{table} WHERE issuer=%s"
            for table, _ in _DIRECTORY_GROUP_AUTHORITY_TABLES)
        rows = db.execute(
            unions,
            (issuer,) * len(_DIRECTORY_GROUP_AUTHORITY_TABLES),
        ).fetchall()
        observed_ids = {row["group_id"] for row in rows}
        projection_mapping = _legacy_group_mapping(groups, observed_ids)
        # The provision service cannot inspect business grant tables. Supply
        # the complete collision-checked Keycloak name/UUID catalogue to the
        # narrow SECURITY DEFINER cutover; it discovers which legacy names are
        # actually present and changes only their authority key.
        mapping = {item["groupName"]: item["groupId"] for item in groups
                   if item["groupName"] != item["groupId"]}
        payload = {"mappings": [{"legacy_group_name": old_id,
                                 "immutable_group_id": new_id}
                                for old_id, new_id in sorted(mapping.items())],
                   "immutable_group_ids": sorted(item["groupId"]
                                               for item in groups)}
        # PostgreSQL jsonb's canonical text orders object keys by length then
        # bytes.  These fixed contract keys are constructed in that order.
        payload_digest = sha256(json.dumps(payload, ensure_ascii=False,
            separators=(", ", ": ")).encode()).hexdigest()
        migrated = db.execute(
            "SELECT epm.apply_group_authority_uuid_cutover(%s,%s,%s) AS changed",
            (issuer, Jsonb(payload), payload_digest)).fetchone()["changed"]
        for old_id, new_id in sorted(projection_mapping.items()):
            for table, scope in _DIRECTORY_GROUP_AUTHORITY_TABLES:
                scope_match = " AND ".join(
                    f"target.{column}=legacy.{column}" for column in scope)
                if scope_match:
                    scope_match = " AND " + scope_match
                collision = db.execute(f"""SELECT EXISTS (
                    SELECT 1 FROM epm.{table} legacy
                    JOIN epm.{table} target
                      ON target.issuer=legacy.issuer
                     AND target.group_id=%s{scope_match}
                    WHERE legacy.issuer=%s AND legacy.group_id=%s
                ) AS collision""", (new_id, issuer, old_id)).fetchone()
                if collision["collision"]:
                    raise ValueError("DIRECTORY_GROUP_TARGET_COLLISION")
            for table, _ in _DIRECTORY_GROUP_AUTHORITY_TABLES:
                result = db.execute(f"""UPDATE epm.{table} SET group_id=%s
                    WHERE issuer=%s AND group_id=%s""",
                    (new_id, issuer, old_id))
                migrated += result.rowcount
        return migrated

    def _apply(self, function: str, arguments: dict, marker: str) -> dict:
        if function == DIRECTORY_RECONCILE:
            return self.directory.authorization_snapshot()
        if function == USER_CREATE:
            return self.directory.create_user(arguments,
                                              operation_marker=marker)
        if function == USER_UPDATE:
            fields = {key: value for key, value in arguments.items()
                      if key != "subjectId"}
            return self.directory.update_user(arguments["subjectId"], fields,
                                              operation_marker=marker)
        if function == USER_STATUS:
            return self.directory.set_user_status(
                arguments["subjectId"], arguments["status"],
                operation_marker=marker)
        if function == USER_PASSWORD:
            return self.directory.set_temporary_password(
                arguments["subjectId"], arguments["temporaryPassword"])
        if function == GROUP_CREATE:
            return self.directory.create_group(arguments,
                                               operation_marker=marker)
        if function == GROUP_UPDATE:
            fields = {key: value for key, value in arguments.items()
                      if key != "groupId"}
            return self.directory.update_group(arguments["groupId"], fields,
                                               operation_marker=marker)
        if function == GROUP_STATUS:
            return self.directory.set_group_status(
                arguments["groupId"], arguments["status"],
                operation_marker=marker)
        return self.directory.set_membership(
            arguments["subjectId"], arguments["groupId"],
            arguments["action"])
