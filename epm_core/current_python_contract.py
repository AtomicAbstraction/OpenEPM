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

from .current_object_contract import STATE_TOKEN_BYTES, require_state_token
from .python_source_validation import validate_python_source


PROGRAM_SAVE = "python.program.save"
PROGRAM_ACTIVATE = "python.program.activate"
PROGRAM_DEACTIVATE = "python.program.deactivate"
PROGRAM_DELETE = "python.program.delete"
PROGRAM_READ = "python.program.read"
PROGRAM_LIST = "python.program.list"
PROGRAM_READS = frozenset((PROGRAM_READ, PROGRAM_LIST))
PROGRAM_MUTATIONS = frozenset((PROGRAM_SAVE, PROGRAM_ACTIVATE,
                               PROGRAM_DEACTIVATE, PROGRAM_DELETE))
ENVIRONMENT_REGISTER = "python.environment.register"
ENVIRONMENT_READ = "python.environment.read"
ENVIRONMENT_LIST = "python.environment.list"
FORMAT = "openepm-current-python-source-v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
_ENTRY_POINT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,99}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_OUTPUT_ID = re.compile(r"[A-Za-z0-9._-]{1,100}")
_OUTPUT_KINDS = frozenset(("ApplicationRule", "CalculatedMember"))
_PINS = ("expectedMetadataRevision", "expectedPolicyRevision", "expectedSchemaEpoch")


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
    if (not isinstance(value, dict) or type(value.get("kind")) is not str
            or value["kind"] not in _OUTPUT_KINDS):
        raise ValueError("PYTHON_DECLARED_OUTPUT_INVALID")
    expected = {"kind", "definitionId"}
    if set(value) != expected:
        raise ValueError("PYTHON_DECLARED_OUTPUT_INVALID")
    for key in expected - {"kind"}:
        identifier(value[key], "PYTHON_DECLARED_OUTPUT_INVALID")
    if _OUTPUT_ID.fullmatch(value["definitionId"]) is None:
        raise ValueError("PYTHON_DECLARED_OUTPUT_INVALID")
    return dict(value)


def parse_program_mutation(raw: object, function: str) -> dict:
    """Parse current Save/Activate/Deactivate/Delete shapes without aliases."""
    if (type(raw) is not dict or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2 or raw.get("function") != function
            or type(raw.get("arguments")) is not dict):
        raise ValueError("CURRENT_PYTHON_PROGRAM_INVALID")
    args = raw["arguments"]
    pins = set(_PINS)
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


def mutation_program_contract(function: str) -> dict:
    """Describe current source operations owned by the repository and parser."""
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj
    from .python_execution_contract import KEY_PATTERN

    if function not in PROGRAM_MUTATIONS:
        raise ValueError("CURRENT_PYTHON_PROGRAM_INVALID")

    def string(pattern):
        return {"type": "string", "pattern": "^(?:" + pattern + r")(?![\s\S])"}

    identifier = string(_ID.pattern)
    digest = string(f"[0-9a-f]{{{STATE_TOKEN_BYTES * 2}}}")
    build_id = string(_HEX32.pattern)
    revision = {"type": "integer", "minimum": 0}
    declared = {"kind": {"enum": sorted(_OUTPUT_KINDS)},
                "definitionId": string(_OUTPUT_ID.pattern)}
    pins = dict.fromkeys(_PINS, revision)
    args = {"programId": identifier, "expectedStateToken": digest, **pins}
    example = {"programId": "example-ordered-source", "expectedStateToken": "a" * 64,
               **dict.fromkeys(_PINS, 1)}
    status = {PROGRAM_SAVE: "Inactive", PROGRAM_ACTIVATE: "Active",
              PROGRAM_DEACTIVATE: "Inactive", PROGRAM_DELETE: "Deleted"}[function]
    result = {"operationId": string(KEY_PATTERN), "programId": identifier,
              "stateToken": digest, "sourceToken": digest, "sourceDigest": digest,
              "status": {"const": status}, "metadataRevision": revision,
              "policyRevision": revision, "schemaEpoch": revision}
    binding = ("Read the exact source state token and current application revisions. "
               "Obtain a signed operation admission for the unchanged program.")
    name = "Change the current Python source state"
    if function == PROGRAM_SAVE:
        definition = {"format": {"const": FORMAT}, "programId": identifier,
                      "sourceText": {"type": "string"}, "entryPoint": string(_ENTRY_POINT.pattern),
                      "parameterSchema": {"description": "JSON declaration bounded by encoded byte size."},
                      "environmentId": identifier, "environmentStateToken": digest}
        args = {"definition": obj({**definition, "declaredOutput": obj(declared)}, list(definition)),
                **pins, "expectedStateToken": digest, "expectedOwnerStateToken": digest,
                "validationParameters": {"type": "object"}}
        arguments = obj(args, ["definition", *_PINS])
        result["validation"] = obj({"buildId": build_id, "taskId": string("p:" + _HEX32.pattern),
                                    "purpose": {"const": "Validation"}, "status": {"const": "accepted"}})
        source = (
            "from openepm import Amount, ApplicationRule, NumericSequence\n"
            "def build(context, parameters):\n"
            "    sequence = NumericSequence().set({\"custom-axis\": \"member-b\"}, Amount(\"1\"),\n"
            "        expected_change_id=\"\")\n"
            "    return ApplicationRule(\"example-ordered-rule\").then_numeric_sequence(sequence)\n"
        )
        example = {"definition": {"format": FORMAT, "programId": example["programId"],
            "sourceText": source, "entryPoint": "build", "parameterSchema": {},
            "environmentId": "example-builder", "environmentStateToken": "b" * 64,
            "declaredOutput": {"kind": "ApplicationRule", "definitionId": "example-ordered-rule"}},
            **dict.fromkeys(_PINS, 1)}
        name = "Save source for one ordered ApplicationRule"
        binding = ("Bind an active environment and the current application revisions. Review the "
                   "full fact coordinate and first-touch change ID before authoring. The example "
                   "uses a disposable one-axis model with no prior numeric event there.")
    else:
        if function == PROGRAM_ACTIVATE:
            args["validationBuildId"] = build_id
            example["validationBuildId"] = "c" * 32
            name = "Activate the exact saved and validated source"
            binding += " Supply the exact reviewed, current build ID for this source and authority."
        arguments = obj(args)

    required_result = list(result)
    if function == PROGRAM_ACTIVATE:
        result["definition"] = obj({**declared, "stateToken": digest,
            "source": obj({"programId": identifier, "programSourceToken": digest,
                           "sourceDigest": digest, "buildId": build_id, "active": {"type": "boolean"}})})
    return read_contract(function, arguments, obj(result, required_result),
        owner="PostgresPythonPrograms",
        examples=[read_example(function, example, name=name, binding=binding)],
        semantic_rules=[
            "Save records one inactive source and queues Validation atomically. A returned accepted build still needs to finish.",
            "In group-assigned applications, rules.design can save a new or inactive declared ApplicationRule. Choose an active binding from python.environment.list. Replacing an active owner or adopting another owner is unavailable. Automatic Validation supports nested numeric sequences and batches and checks independently granted access to every cell.",
            "Replacing a source requires its current state token. Adopting an existing configuration owner requires its reviewed owner state token.",
            "A group publisher requires rules.test and rules.publish, scoped fact read and write, and their own exact, complete private ImpactTest of the current inactive rule. Numeric sequences and batches support scalar amount/ratio bindings. Re-test after a change to source, permissions, metadata, data, policy or environment.",
            "Legacy activation requires the exact current reviewed Validation or complete ImpactTest build under current authority. Activation does not run the rule.",
            "Delete requires an inactive source with no blocking references. A retained rule workflow can prevent removal even after deactivation.",
            "The repository owns source syntax and encoded-size checks, current grants, revision fences, definition lifecycle and replay.",
        ])


def source_read_program_contract(function: str) -> dict:
    from openepm.diagnostics import diagnostic_payload_schema
    from .metadata_read_contract import read_contract, read_example
    from .postgres_application_rules import _PARAMETER_TYPES
    from .postgres_numeric_catalog import obj
    from .python_program_execution import BuildStatus

    def text(pattern):
        return {"type": "string", "pattern": "^(?:" + pattern + r")(?![\s\S])"}

    def nullable(schema):
        return {"anyOf": [schema, {"type": "null"}]}

    identifier = text(_ID.pattern)
    digest = text(f"[0-9a-f]{{{STATE_TOKEN_BYTES * 2}}}")
    boolean = {"type": "boolean"}
    dimension_types = {"Member", "MemberList"}
    parameter = {"oneOf": [
        obj({"name": identifier, "type": {"enum": sorted(_PARAMETER_TYPES - dimension_types)}}),
        obj({"name": identifier, "type": {"enum": sorted(dimension_types)}, "dimensionId": identifier}),
    ]}
    kinds = sorted(_OUTPUT_KINDS)
    declared_output = {"oneOf": [
        obj({"kind": {"enum": kinds}, "definitionId": text(_OUTPUT_ID.pattern)}),
        obj({"kind": {"const": "MemberList"}, "definitionId": identifier, "dimensionId": identifier}),
    ]}

    def build_summary(purpose):
        required = {"buildId": text(_HEX32.pattern), "taskId": text("p:" + _HEX32.pattern),
                    "status": {"enum": [status.value for status in BuildStatus]},
                    "purpose": {"const": purpose}, "current": boolean}
        if purpose == "Validation":
            required["ownedByCaller"] = boolean
        return obj({**required, "errorCode": {"type": "string"}, "diagnostics": diagnostic_payload_schema(),
                    "definition": obj({"kind": {"enum": kinds}, "definitionId": text(_OUTPUT_ID.pattern),
                        "parameters": {"type": "array", "maxItems": 100, "items": parameter}})}, list(required))

    summary = {"programId": identifier, "stateToken": digest, "sourceToken": digest,
               "status": {"enum": ["Active", "Inactive", "Unavailable"]},
               "validation": nullable(build_summary("Validation")),
               "latestImpactTest": nullable(build_summary("ImpactTest")), "sourceDigest": digest,
               "declaredOutput": nullable(declared_output), "entryPoint": text(_ENTRY_POINT.pattern),
               "parameterSchema": {"type": "object"}, "environmentId": identifier, "environmentStateToken": digest}
    owner_state = {**dict.fromkeys(("defined", "valid", "active", "sourceCurrent", "executable"), boolean),
                   "resultCurrent": {"type": "null"}, "reason": {"type": ["string", "null"]},
                   "definition": obj({"kind": {"enum": [*kinds, "MemberList"]}, "definitionId": identifier})}
    if function == PROGRAM_READ:
        arguments = obj({"programId": identifier})
        opened = {**summary, "defined": {"const": True}, "sourceText": {"type": "string"},
                  "updatedAt": {"type": "string", "format": "date-time"}}
        result = {"oneOf": [obj({"programId": identifier, "defined": {"const": False}}),
                            obj({**owner_state, **opened}, list(opened))]}
        examples = [read_example(function, {"programId": "example-ordered-source"},
            name="Open the current source by program ID",
            binding="Use the exact programId from a saved source or the authorized source list.")]
    elif function == PROGRAM_LIST:
        arguments = obj({"limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 100},
                         "afterProgramId": identifier}, [])
        result = obj({"programs": {"type": "array", "maxItems": 100,
                                   "items": obj({**summary, **owner_state}, list(summary))},
                      "nextAfterProgramId": nullable(identifier)})
        result["allOf"] = [{"if": {"properties": {"programs": {"maxItems": 0}}},
                            "then": {"properties": {"nextAfterProgramId": {"type": "null"}}}}]
        examples = [read_example(function, {"limit": 1}, name="List the first page of source summaries",
                         binding="Use the selected authorized application."),
                    read_example(function, {"limit": 1, "afterProgramId": "example-ordered-source"},
                         name="Continue the current source list",
                         binding="Use the exact non-null nextAfterProgramId from the previous page.")]
    else:
        raise ValueError("CURRENT_PYTHON_PROGRAM_INVALID")

    return read_contract(function, arguments, result, owner="PostgresPythonPrograms", examples=examples,
        semantic_rules=[
            "A list contains current source summaries in program ID order. Read a specific source to obtain its text.",
            "In a group-assigned application, rules.inspect covers only declared ApplicationRule sources "
            "with a matching current rule owner. Other IDs produce defined=false. A designer can see progress of their own current automatic Validation. The latestImpactTest field summarizes the tester’s own current-scope run. The Impact section contains private before/after values for the authorized cells. Other build sections and diagnostics require separate authority.",
            "An unknown program ID returns defined=false. An empty list is a successful read under current authority.",
            "Use stateToken for a reviewed source change and sourceToken for its exact build or Test. Validation status and executable state answer different questions.",
            "Validation and latestImpactTest describe the exact current source token. An explicit Validation and any ImpactTest are visible only to their owner under current dimensional authority. The source save may expose its automatic Validation summary. Only a caller-owned current build is eligible to activate. Parameter summaries omit validation samples.",
            "A sealed validation may become stale when application revisions change. Activation and Run recheck the current source, build and authority. Refresh the catalogue and reread after PYTHON_PROGRAM_READ_AUTHORIZATION_STALE.",
        ])


def build_source_pin(program: dict) -> dict:
    """Return the exact current source proof stored on technical work."""
    return {"programId": program["programId"],
            "programSourceToken": require_state_token(program["sourceToken"],
                error="PYTHON_PROGRAM_SOURCE_TOKEN_INVALID"),
            "sourceDigest": program["sourceDigest"],
            "contentDigest": program["contentDigest"]}
