"""Fail-closed structural review for a PostgreSQL baseline candidate.

This is deliberately not an SQL execution or activation API.  A constructor
may serialize reviewed DDL into this ordered JSON contract; this module only
checks that the packet is complete, deterministic, narrowly scoped, and free
of pg_dump/session/data-loading behaviours that must never enter a baseline.
Catalog parity and disposable restore tests remain separate required gates.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


FORMAT = "openepm-postgres-baseline-artifact-review-v1"
CATEGORIES = (
    "extension", "role", "membership", "role-setting", "schema", "type",
    "sequence", "table", "partition", "constraint", "index", "routine",
    "view", "matview", "rule", "trigger", "rls", "policy", "default-acl",
    "acl", "owner", "comment", "security-label",
)
_CATEGORY_ORDER = {name: ordinal for ordinal, name in enumerate(CATEGORIES)}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTITY = re.compile(r"[a-zA-Z0-9_.() ,\[\]\-]+")
_FORBIDDEN_OUTSIDE_LITERALS = re.compile(
    r"\b(?:COPY|INSERT|UPDATE|DELETE|MERGE|TRUNCATE|VACUUM|ANALYZE|"
    r"CREATE\s+DATABASE|ALTER\s+DATABASE|DROP\s+DATABASE|CREATE\s+TABLESPACE|"
    r"CREATE\s+(?:FOREIGN\s+DATA\s+WRAPPER|SERVER|USER\s+MAPPING)|"
    r"ALTER\s+SYSTEM|LOAD|DO|CALL|LISTEN|NOTIFY|UNLISTEN|"
    r"BEGIN|START\s+TRANSACTION|COMMIT|ROLLBACK|SAVEPOINT|PREPARE\s+TRANSACTION|"
    r"SET\s+(?:SESSION|LOCAL|ROLE|SESSION\s+AUTHORIZATION|SEARCH_PATH)|RESET)\b",
    re.IGNORECASE,
)
_EXTERNAL_ACCESS = re.compile(
    r"\b(?:PROGRAM|dblink|postgres_fdw|file_fdw|http|https|curl|aws_|s3|"
    r"lo_import|lo_export|pg_read_file|pg_write_file|pg_ls_dir)\b", re.I)
_PASSWORD = re.compile(r"\b(?:PASSWORD|ENCRYPTED\s+PASSWORD)\b", re.I)
_CATEGORY_COMMAND = {
    "role": r"CREATE\s+ROLE\s+epm_[a-z0-9_]+\b",
    "membership": r"GRANT\s+epm_[a-z0-9_]+(?:\s*,\s*epm_[a-z0-9_]+)*\s+TO\s+epm_[a-z0-9_]+\b",
    "role-setting": r"ALTER\s+ROLE\s+epm_[a-z0-9_]+\s+SET\s+[a-z_]+\s*=",
    "schema": r"CREATE\s+SCHEMA\s+epm\b",
    "type": r"CREATE\s+(?:TYPE|DOMAIN)\s+epm\.",
    "sequence": r"(?:CREATE|ALTER)\s+SEQUENCE\s+epm\.",
    "table": r"(?:CREATE|ALTER)\s+TABLE\s+(?:ONLY\s+)?epm\.",
    "partition": r"(?:CREATE\s+TABLE\s+epm\.|ALTER\s+TABLE\s+(?:ONLY\s+)?epm\.)",
    "constraint": r"ALTER\s+TABLE\s+(?:ONLY\s+)?epm\..*\bADD\s+CONSTRAINT\b",
    "index": r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+[^\s]+\s+ON\s+(?:ONLY\s+)?epm\.",
    "routine": r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+epm\.",
    "view": r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+epm\.",
    "matview": r"CREATE\s+MATERIALIZED\s+VIEW\s+epm\.",
    "rule": r"CREATE\s+RULE\s+[^\s]+\s+AS\s+ON\b",
    "trigger": r"(?:CREATE\s+(?:CONSTRAINT\s+)?TRIGGER\s+[^\s]+\b|ALTER\s+TABLE\s+(?:ONLY\s+)?epm\..*\b(?:ENABLE(?:\s+(?:ALWAYS|REPLICA))?|DISABLE)\s+TRIGGER\s+[^\s]+)",
    "rls": r"ALTER\s+TABLE\s+(?:ONLY\s+)?epm\..*\b(?:ENABLE|FORCE)\s+ROW\s+LEVEL\s+SECURITY\b",
    "policy": r"CREATE\s+POLICY\s+[^\s]+\s+ON\s+epm\.",
    "default-acl": r"ALTER\s+DEFAULT\s+PRIVILEGES\b",
    "acl": r"(?:GRANT|REVOKE)\s+.+\s+ON\s+(?:TABLE|SEQUENCE|FUNCTION|PROCEDURE|SCHEMA|TYPE)\b",
    "owner": r"ALTER\s+(?:SCHEMA|TYPE|DOMAIN|SEQUENCE|TABLE|FUNCTION|PROCEDURE|VIEW|MATERIALIZED\s+VIEW)\b.+\bOWNER\s+TO\s+epm_[a-z0-9_]+\b",
    "comment": r"COMMENT\s+ON\b",
    "security-label": r"SECURITY\s+LABEL\s+(?:FOR\s+[a-z0-9_]+\s+)?ON\b",
}


def _fail(code: str) -> None:
    raise ValueError(code)


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode()).hexdigest()


def _outside_literals(sql: str) -> str:
    """Return SQL with quoted/dollar bodies blanked; reject comments/unclosed text."""
    out: list[str] = []
    index = 0
    while index < len(sql):
        char = sql[index]
        if sql.startswith("--", index) or sql.startswith("/*", index):
            _fail("BASELINE_ARTIFACT_SQL_COMMENT_REJECTED")
        if char in "'\"":
            quote = char; out.append(" "); index += 1
            while index < len(sql):
                if sql[index] == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2; continue
                    index += 1; break
                index += 1
            else:
                _fail("BASELINE_ARTIFACT_SQL_UNTERMINATED_LITERAL")
            continue
        if char == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", sql[index:])
            if match:
                tag = match.group(0); end = sql.find(tag, index + len(tag))
                if end < 0: _fail("BASELINE_ARTIFACT_SQL_UNTERMINATED_LITERAL")
                out.append(" "); index = end + len(tag); continue
        out.append(char); index += 1
    return "".join(out)


def _review_sql(category: str, sql: str, allowed_extensions: set[str]) -> None:
    if not isinstance(sql, str) or not sql or "\x00" in sql:
        _fail("BASELINE_ARTIFACT_SQL_INVALID")
    if re.search(r"(?m)^\s*\\", sql):
        _fail("BASELINE_ARTIFACT_PSQL_META_REJECTED")
    outside = _outside_literals(sql).strip()
    # Exactly one top-level command. Semicolons inside routine bodies were blanked.
    if not outside.endswith(";") or ";" in outside[:-1]:
        _fail("BASELINE_ARTIFACT_SQL_COMMAND_COUNT_INVALID")
    command = outside[:-1].strip()
    safety_command = command
    if category == "routine":
        safety_command = re.sub(
            r"\bSET\s+search_path\s*=\s*(?:pg_catalog\s*,\s*epm|epm\s*,\s*pg_catalog)\b",
            " REVIEWED_ROUTINE_PATH ", safety_command, flags=re.I)
    if _FORBIDDEN_OUTSIDE_LITERALS.search(safety_command):
        _fail("BASELINE_ARTIFACT_UNSAFE_SQL_REJECTED")
    # Scan the original as well as the structural form: an external primitive
    # hidden inside a dollar-quoted routine body is still external access.
    if (_EXTERNAL_ACCESS.search(command) or _EXTERNAL_ACCESS.search(sql)
            or re.search(r"\b(?:SET\s+ROLE|SET\s+SESSION\s+AUTHORIZATION|set_config)\b",
                         sql, re.I)):
        _fail("BASELINE_ARTIFACT_EXTERNAL_ACCESS_REJECTED")
    if _PASSWORD.search(command):
        _fail("BASELINE_ARTIFACT_SECRET_REJECTED")
    if category == "extension":
        match = re.fullmatch(
            r"CREATE\s+EXTENSION\s+([A-Za-z_][A-Za-z0-9_]*)\s+WITH\s+SCHEMA\s+"
            r"([A-Za-z_][A-Za-z0-9_]*)\s+VERSION\s+'[A-Za-z0-9_.+\-]+';?",
            sql.strip(), re.I)
        if not match or match.group(1).lower() not in allowed_extensions:
            _fail("BASELINE_ARTIFACT_EXTENSION_REJECTED")
    elif not re.match(_CATEGORY_COMMAND[category], command, re.I | re.S):
        _fail("BASELINE_ARTIFACT_CATEGORY_COMMAND_INVALID")
    if category == "routine":
        if not re.match(r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\b",
                        command, re.I):
            _fail("BASELINE_ARTIFACT_ROUTINE_INVALID")
        if not re.search(r"\bSET\s+search_path\s*=\s*(?:pg_catalog\s*,\s*epm|epm\s*,\s*pg_catalog)\b",
                         command, re.I):
            _fail("BASELINE_ARTIFACT_ROUTINE_SEARCH_PATH_REQUIRED")


def validate_baseline_artifact(packet: dict[str, Any], *,
        expected_postgres_profile: str, expected_extensions: list[list[str]]) -> dict[str, Any]:
    """Validate a review packet without executing it or authorizing activation."""
    required = {"format", "activationAuthorized", "postgresProfile",
        "extensionProfile", "allowedSchemas", "requiredRoles", "inventory",
        "statements", "artifactSha256"}
    if not isinstance(packet, dict) or set(packet) != required:
        _fail("BASELINE_ARTIFACT_SHAPE_INVALID")
    if packet["format"] != FORMAT or packet["activationAuthorized"] is not False:
        _fail("BASELINE_ARTIFACT_BOUNDARY_INVALID")
    if (packet["postgresProfile"] != expected_postgres_profile
            or packet["extensionProfile"] != expected_extensions):
        _fail("BASELINE_ARTIFACT_PROFILE_MISMATCH")
    if (not isinstance(expected_extensions, list)
            or any(not isinstance(row, list) or len(row) != 2
                   or not all(isinstance(v, str) and v for v in row)
                   for row in expected_extensions)):
        _fail("BASELINE_ARTIFACT_EXTENSION_PROFILE_INVALID")
    schemas = packet["allowedSchemas"]
    if schemas != ["epm"]:
        _fail("BASELINE_ARTIFACT_SCHEMA_SCOPE_INVALID")
    roles = packet["requiredRoles"]
    if (not isinstance(roles, list) or roles != sorted(set(roles)) or not roles
            or any(not re.fullmatch(r"epm_[a-z0-9_]+", role) for role in roles)):
        _fail("BASELINE_ARTIFACT_ROLE_SCOPE_INVALID")
    inventory = packet["inventory"]
    if (not isinstance(inventory, dict) or tuple(inventory) != CATEGORIES
            or any(type(count) is not int or count < 0 for count in inventory.values())):
        _fail("BASELINE_ARTIFACT_INVENTORY_INVALID")
    statements = packet["statements"]
    if not isinstance(statements, list) or not statements:
        _fail("BASELINE_ARTIFACT_STATEMENTS_INVALID")
    allowed_extensions = {row[0].lower() for row in expected_extensions}
    seen: set[tuple[str, str]] = set(); previous = None
    observed = {category: 0 for category in CATEGORIES}
    for ordinal, row in enumerate(statements, 1):
        if (not isinstance(row, dict)
                or set(row) != {"ordinal", "category", "identity", "sql", "sha256"}
                or row["ordinal"] != ordinal or row["category"] not in _CATEGORY_ORDER
                or not isinstance(row["identity"], str)
                or not _IDENTITY.fullmatch(row["identity"])
                or not _DIGEST.fullmatch(str(row["sha256"]))
                or row["sha256"] != hashlib.sha256(row["sql"].encode()).hexdigest()):
            _fail("BASELINE_ARTIFACT_STATEMENT_INVALID")
        key = (row["category"], row["identity"])
        ordering = (_CATEGORY_ORDER[row["category"]], row["identity"])
        if key in seen or (previous is not None and ordering <= previous):
            _fail("BASELINE_ARTIFACT_ORDER_OR_IDENTITY_INVALID")
        seen.add(key); previous = ordering; observed[row["category"]] += 1
        referenced_roles = set(re.findall(r"\bepm_[a-z0-9_]+\b",
            _outside_literals(row["sql"]), re.I))
        if not referenced_roles.issubset(set(roles)):
            _fail("BASELINE_ARTIFACT_UNDECLARED_ROLE")
        _review_sql(row["category"], row["sql"], allowed_extensions)
    if observed != inventory:
        _fail("BASELINE_ARTIFACT_INVENTORY_MISMATCH")
    canonical = {key: packet[key] for key in required - {"artifactSha256"}}
    if packet["artifactSha256"] != _canonical_digest(canonical):
        _fail("BASELINE_ARTIFACT_DIGEST_MISMATCH")
    return {"validated": True, "activationAuthorized": False,
        "statementCount": len(statements), "artifactSha256": packet["artifactSha256"]}
