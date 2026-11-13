"""Current-only Python source and build admission contracts.

The product stores one source per program ID.  Product versions are not part
of this contract: callers replace the current source with an exact state-token
precondition, and Validation/Test/Activate/Run bind that current token plus the
source digest.  Environment identity is likewise current and token-bound;
deployment image/compiler digests remain dependency pins, not product history.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from .current_object_contract import require_state_token
from .python_source_validation import validate_python_source


PROGRAM_SAVE = "python.program.save"
PROGRAM_ACTIVATE = "python.program.activate"
PROGRAM_DEACTIVATE = "python.program.deactivate"
PROGRAM_DELETE = "python.program.delete"
PROGRAM_READ = "python.program.read"
PROGRAM_LIST = "python.program.list"
ENVIRONMENT_REGISTER = "python.environment.register"
ENVIRONMENT_READ = "python.environment.read"
ENVIRONMENT_LIST = "python.environment.list"
FORMAT = "openepm-current-python-source-v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_ENTRY_POINT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,99}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")


def _canonical_json(value: object, error: str, *, limit: int) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, UnicodeEncodeError) as failure:
        raise ValueError(error) from failure
    if len(encoded.encode("ascii")) > limit:
        raise ValueError(error)
    return encoded


def identifier(value: object, error: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(error)
    return value


def canonical_source(value: object) -> dict:
    """Validate and copy the single current authored source definition."""
    required = {"format", "programId", "sourceText", "entryPoint",
                "parameterSchema", "environmentId",
                "environmentStateToken"}
    if (type(value) is not dict or not required <= set(value)
            or set(value) - required - {"declaredOutput"} or value.get("format") != FORMAT):
        raise ValueError("PYTHON_SOURCE_DEFINITION_INVALID")
    program_id = identifier(value["programId"], "PYTHON_SOURCE_DEFINITION_INVALID")
    environment_id = identifier(value["environmentId"], "PYTHON_SOURCE_DEFINITION_INVALID")
    if (type(value["entryPoint"]) is not str
            or _ENTRY_POINT.fullmatch(value["entryPoint"]) is None):
        raise ValueError("PYTHON_SOURCE_DEFINITION_INVALID")
    require_state_token(value["environmentStateToken"],
                        error="PYTHON_ENVIRONMENT_STATE_TOKEN_INVALID")
    source_digest = validate_python_source(value["sourceText"])
    schema = json.loads(_canonical_json(value["parameterSchema"],
        "PYTHON_PARAMETER_SCHEMA_INVALID", limit=262_144))
    result = {"format": FORMAT, "programId": program_id,
        "sourceText": value["sourceText"], "entryPoint": value["entryPoint"],
        "parameterSchema": schema, "environmentId": environment_id,
        "environmentStateToken": value["environmentStateToken"]}
    if "declaredOutput" in value:
        result["declaredOutput"] = canonical_declared_output(value["declaredOutput"])
    # Recompute rather than accepting a caller-owned source/content digest.
    result["sourceDigest"] = source_digest
    result["contentDigest"] = sha256(_canonical_json(result,
        "PYTHON_SOURCE_DEFINITION_INVALID", limit=1_500_000).encode("ascii")).hexdigest()
    return result



def canonical_declared_output(value: object) -> dict:
    """Name the one business owner before authored compilation can return it."""
    if not isinstance(value, dict) or type(value.get("kind")) is not str or value["kind"] not in {
            "ApplicationRule", "CalculatedMember"}:
        raise ValueError("PYTHON_DECLARED_OUTPUT_INVALID")
    expected = {"kind", "definitionId"}
    if set(value) != expected:
        raise ValueError("PYTHON_DECLARED_OUTPUT_INVALID")
    for key in expected - {"kind"}:
        identifier(value[key], "PYTHON_DECLARED_OUTPUT_INVALID")
    if re.fullmatch(r"[A-Za-z0-9._-]{1,100}", value["definitionId"]) is None:
        raise ValueError("PYTHON_DECLARED_OUTPUT_INVALID")
    return dict(value)


def parse_program_mutation(raw: object, function: str) -> dict:
    """Parse current Save/Activate/Deactivate/Delete shapes without aliases."""
    if (type(raw) is not dict or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2 or raw.get("function") != function
            or type(raw.get("arguments")) is not dict):
        raise ValueError("CURRENT_PYTHON_PROGRAM_INVALID")
    args = raw["arguments"]
    pins = {"expectedMetadataRevision", "expectedPolicyRevision", "expectedSchemaEpoch"}
    if function == PROGRAM_SAVE:
        if not pins | {"definition"} <= set(args) or set(args) - pins - {
                "definition", "expectedStateToken", "validationParameters", "expectedOwnerStateToken"}:
            raise ValueError("CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
        definition = canonical_source(args["definition"])
        if "expectedStateToken" in args:
            require_state_token(args["expectedStateToken"],
                                error="PYTHON_PROGRAM_STATE_TOKEN_INVALID")
        if "expectedOwnerStateToken" in args:
            require_state_token(args["expectedOwnerStateToken"], error="DEFINITION_OWNER_STATE_TOKEN_INVALID")
        validation = args.get("validationParameters", {})
        _canonical_json(validation, "PYTHON_VALIDATION_PARAMETERS_INVALID",
                        limit=1_048_576)
        result = {**args, "definition": definition,
                  "validationParameters": validation}
    elif function == PROGRAM_ACTIVATE:
        allowed = pins | {"programId", "expectedStateToken", "validationBuildId"}
        if set(args) != allowed:
            raise ValueError("CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
        identifier(args["programId"], "CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
        require_state_token(args["expectedStateToken"],
                            error="PYTHON_PROGRAM_STATE_TOKEN_INVALID")
        if type(args["validationBuildId"]) is not str or _HEX32.fullmatch(
                args["validationBuildId"]) is None:
            raise ValueError("CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
        result = dict(args)
    else:
        allowed = pins | {"programId", "expectedStateToken"}
        if function not in (PROGRAM_DEACTIVATE, PROGRAM_DELETE) or set(args) != allowed:
            raise ValueError("CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
        identifier(args["programId"], "CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
        require_state_token(args["expectedStateToken"],
                            error="PYTHON_PROGRAM_STATE_TOKEN_INVALID")
        result = dict(args)
    if any(type(result[name]) is not int or result[name] < 0 for name in pins):
        raise ValueError("CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
    return result


def build_source_pin(program: dict) -> dict:
    """Return the exact current source proof stored on technical work."""
    return {"programId": program["programId"],
            "programSourceToken": require_state_token(program["sourceToken"],
                error="PYTHON_PROGRAM_SOURCE_TOKEN_INVALID"),
            "sourceDigest": program["sourceDigest"],
            "contentDigest": program["contentDigest"]}
