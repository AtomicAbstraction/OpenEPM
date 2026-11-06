"""Transport-neutral MCP client facade for the public SDK."""

from __future__ import annotations

import base64
import binascii
import json
from hashlib import sha256
import re
from typing import Any, Mapping, Protocol

from .model import (Application, BuildContext, JobHandle, Program,
                    MAX_OPERATIONS, PythonBuildArtifactSection,
                    _canonical_copy, _identifier)
from .functions import FunctionRegistry,generate_function_registry


_ENTRY_POINT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")
_REQUEST_KEY = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMPILER_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_ARTIFACT_PAGE_BYTES = 64 * 1024
_ARTIFACT_LIMITS = {'Plan': 4 * 1024 * 1024,
                    'SourceMap': 1024 * 1024,
                    'BuildLog': 1024 * 1024}


class Transport(Protocol):
    """Authenticated transport implemented by an MCP client adapter."""

    def call(self, tool: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]: ...


class EpmClient:
    def __init__(self, transport: Transport):
        if not hasattr(transport, "call"):
            raise ValueError("An authenticated MCP transport is required")
        self._transport = transport

    def discover(self, application: Application | None = None) -> Mapping[str, Any]:
        arguments={} if application is None else application.to_wire()
        return self._transport.call("list_v2_functions", arguments)

    def functions(self,application: Application | None = None) -> FunctionRegistry:
        """Generate wrappers only for this identity/application's discovery."""
        return generate_function_registry(self.discover(application))

    def read(self, application: Application, function: str,
             arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        program = {"languageVersion": 2, "function": _identifier(function, "function"),
                   "arguments": _canonical_copy(arguments, label="arguments")}
        return self._transport.call("read_v2_program", {
            **application.to_wire(), "program": program})

    def preview(self, application: Application, program: Program) -> Mapping[str, Any]:
        operation = self._single_operation(program)
        return self._transport.call("preview_v2_program", {
            **application.to_wire(), "program": operation})

    def submit(self, application: Application, program: Program, *,
               request_key: str, preview_token: str) -> JobHandle:
        _identifier(request_key, "request_key")
        if not isinstance(preview_token, str) or not preview_token:
            raise ValueError("preview_token is required")
        operation = self._single_operation(program)
        result = self._transport.call("submit_v2_program", {
            **application.to_wire(), "program": operation,
            "idempotency_key": request_key,
            "preview_token": preview_token})
        job_id = result.get("jobId")
        if not isinstance(job_id, str):
            raise ValueError("Transport returned no jobId")
        return JobHandle(application, job_id, request_key)

    def status(self, handle: JobHandle) -> Mapping[str, Any]:
        return self._transport.call("read_v2_job", {
            **handle.application.to_wire(), "job_id": handle.job_id})

    def cancel(self, handle: JobHandle) -> Mapping[str, Any]:
        return self._transport.call("cancel_v2_job", {
            **handle.application.to_wire(), "job_id": handle.job_id})

    def execute_cube_write_policy(self,application: Application,program: Program,
                                  *,request_key: str|None=None
                                  ) -> Mapping[str,Any]:
        """Manage a domain-neutral cube write-policy through its MCP tool."""
        operation=self._single_operation(program)
        keyed=frozenset({"cube.write.policy.publish",
                         "cube.write.policy.deactivate"})
        unkeyed=frozenset({"cube.write.policy.save",
                           "cube.write.policy.read",
                           "cube.write.policy.list"})
        self._forecast_request_key(operation["function"],request_key,keyed,unkeyed)
        return self._planning_management(application,program,
            allowed=keyed|unkeyed,
            tool="execute_v2_cube_write_policy",
            request_key=request_key)

    def execute_application_schedule(self,application: Application,
                                     program: Program,*,
                                     request_key: str|None=None
                                     )->Mapping[str,Any]:
        """Manage an exact generic application-rule schedule version."""
        operation=self._single_operation(program)
        writes=frozenset({"schedule.version.save","schedule.version.publish",
                          "schedule.version.deactivate"})
        reads=frozenset({"schedule.version.read","schedule.version.list"})
        self._forecast_request_key(operation["function"],request_key,
                                   writes,reads)
        return self._planning_management(application,program,
            allowed=writes|reads,tool="execute_v2_application_schedule",
            request_key=request_key)

    def execute_application_assignment(self,application: Application,
                                       program: Program,*,
                                       request_key: str|None=None
                                       )->Mapping[str,Any]:
        """Manage a domain-neutral assignment set through fixed core."""
        operation=self._single_operation(program)
        writes=frozenset({"application.assignment.save",
                          "application.assignment.publish",
                          "application.assignment.deactivate"})
        reads=frozenset({"application.assignment.read",
                         "application.assignment.list"})
        function=operation["function"]
        if function not in writes|reads:
            raise ValueError("APPLICATION_ASSIGNMENT_FUNCTION_INVALID")
        if function in writes and request_key is None:
            raise ValueError("APPLICATION_ASSIGNMENT_REQUEST_KEY_REQUIRED")
        if function in reads and request_key is not None:
            raise ValueError("APPLICATION_ASSIGNMENT_READ_REQUEST_KEY_FORBIDDEN")
        return self._planning_management(application,program,
            allowed=writes|reads,tool="execute_v2_application_assignment",
            request_key=request_key)

    def execute_application_workflow(self,application: Application,
                                     program: Program,* ,
                                     request_key: str|None=None
                                     )->Mapping[str,Any]:
        """Manage a domain-neutral workflow definition through fixed core."""
        operation=self._single_operation(program)
        writes=frozenset({"application.workflow.save",
                          "application.workflow.publish",
                          "application.workflow.deactivate"})
        reads=frozenset({"application.workflow.read",
                         "application.workflow.list"})
        function=operation["function"]
        if function not in writes|reads:
            raise ValueError("APPLICATION_WORKFLOW_FUNCTION_INVALID")
        if function in writes and request_key is None:
            raise ValueError("APPLICATION_WORKFLOW_REQUEST_KEY_REQUIRED")
        if function in reads and request_key is not None:
            raise ValueError("APPLICATION_WORKFLOW_READ_REQUEST_KEY_FORBIDDEN")
        return self._planning_management(application,program,
            allowed=writes|reads,tool="execute_v2_application_workflow",
            request_key=request_key)

    def execute_application_workflow_occurrence(self,application: Application,
            program: Program,*,request_key: str|None=None)->Mapping[str,Any]:
        """Operate one generic workflow occurrence through fixed core."""
        operation=self._single_operation(program)
        writes=frozenset({"application.workflow.occurrence.start",
            "application.workflow.activity.complete",
            "application.workflow.activity.return",
            "application.workflow.occurrence.cancel"})
        reads=frozenset({"application.workflow.occurrence.read",
                         "application.workflow.worklist"})
        function=operation["function"]
        if function not in writes|reads:
            raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_FUNCTION_INVALID")
        if function in writes and request_key is None:
            raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_REQUEST_KEY_REQUIRED")
        if function in reads and request_key is not None:
            raise ValueError(
                "APPLICATION_WORKFLOW_OCCURRENCE_READ_REQUEST_KEY_FORBIDDEN")
        return self._planning_management(application,program,
            allowed=writes|reads,
            tool="execute_v2_application_workflow_occurrence",
            request_key=request_key)

    def apply_cube_write_scope_transition(
            self,application: Application,program: Program,*,
            preview_token: str) -> Mapping[str,Any]:
        """Apply one server-previewed domain-neutral write-scope transition."""
        operation=self._single_operation(program)
        if operation["function"] not in {"cube.write.scope.lock",
                "cube.write.scope.submit","cube.write.scope.approve",
                "cube.write.scope.reopen"}:
            raise ValueError("CUBE_WRITE_SCOPE_TRANSITION_FUNCTION_INVALID")
        if not isinstance(preview_token,str) or not preview_token:
            raise ValueError("preview_token is required")
        return self._transport.call("apply_v2_cube_write_scope_transition",{
            **application.to_wire(),"program":operation,
            "preview_token":preview_token})

    def cube_write_scope_worklist(
            self,application: Application,*,limit: int=100,
            after_lock_id: str|None=None,
            include_resolved: bool=False) -> Mapping[str,Any]:
        """Read the current verified identity's cube write-scope work."""
        if type(limit) is not int or not 1<=limit<=100:
            raise ValueError("limit must be an integer from 1 through 100")
        if type(include_resolved) is not bool:
            raise ValueError("include_resolved must be a boolean")
        arguments:dict[str,Any]={"limit":limit}
        if include_resolved:
            arguments["includeResolved"]=True
        if after_lock_id is not None:
            arguments["afterLockId"]=_identifier(after_lock_id,"after_lock_id")
        return self.read(application,"cube.write.scope.worklist",arguments)

    def _planning_management(self,application: Application,program: Program,* ,
                             allowed: frozenset[str],tool: str,
                             request_key: str|None) -> Mapping[str,Any]:
        operation=self._single_operation(program)
        if operation["function"] not in allowed:
            raise ValueError("PLANNING_MANAGEMENT_FUNCTION_INVALID")
        arguments={**application.to_wire(),"program":operation}
        if request_key is not None:
            self._request_key(request_key);arguments["idempotency_key"]=request_key
        return self._transport.call(tool,arguments)

    @staticmethod
    def _forecast_request_key(function: str,request_key: str|None,
                              writes: frozenset[str],reads: frozenset[str])->None:
        if function in writes and request_key is None:
            raise ValueError("FORECAST_REQUEST_KEY_REQUIRED")
        if function in reads and request_key is not None:
            raise ValueError("FORECAST_READ_REQUEST_KEY_FORBIDDEN")

    def save_python_program(self, context: BuildContext, *, program_id: str,
                            version: int, source_text: str,
                            parameter_schema: Mapping[str, Any],
                            environment_id: str, environment_version: int,
                            request_key: str,
                            entry_point: str = "build") -> Mapping[str, Any]:
        """Save one immutable builder source version through the public MCP boundary."""
        if not isinstance(context, BuildContext):
            raise ValueError("context must be a BuildContext")
        if (not isinstance(source_text, str) or "\x00" in source_text
                or not 1 <= len(source_text.encode("utf-8")) <= 1024 * 1024):
            raise ValueError("source_text must contain 1 byte through 1 MiB of UTF-8 text")
        if not isinstance(entry_point, str) or not _ENTRY_POINT.fullmatch(entry_point):
            raise ValueError("entry_point must be a Python identifier of at most 100 characters")
        schema = _canonical_copy(parameter_schema, label="parameter_schema")
        if not isinstance(schema, dict):
            raise ValueError("parameter_schema must be an object")
        if len(json.dumps(schema, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":")).encode("ascii")) > 256 * 1024:
            raise ValueError("parameter_schema exceeds 256 KiB")
        arguments = {
            "programId": _identifier(program_id, "program_id"),
            "version": self._positive_integer(version, "version"),
            "sourceText": source_text,
            "entryPoint": entry_point,
            "parameterSchema": schema,
            "environmentId": _identifier(environment_id, "environment_id"),
            "environmentVersion": self._positive_integer(
                environment_version, "environment_version"),
            **self._pins(context),
        }
        return self._python_registry(context.application, "python.program.save",
                                     arguments, request_key)

    def read_python_program(self, application: Application, program_id: str, *,
                            version: int | None = None) -> Mapping[str, Any]:
        arguments: dict[str, Any] = {
            "programId": _identifier(program_id, "program_id")}
        if version is not None:
            arguments["version"] = self._positive_integer(version, "version")
        return self.read(application, "python.program.read", arguments)

    def list_python_programs(self, application: Application, *, limit: int = 100,
                             after_program_id: str | None = None
                             ) -> Mapping[str, Any]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 through 100")
        arguments: dict[str, Any] = {"limit": limit}
        if after_program_id is not None:
            arguments["afterProgramId"] = _identifier(
                after_program_id, "after_program_id")
        return self.read(application, "python.program.list", arguments)

    def publish_python_program(self, context: BuildContext, *, program_id: str,
                               version: int, request_key: str
                               ) -> Mapping[str, Any]:
        return self._python_pointer(context, "python.program.publish", program_id,
                                    version, request_key)

    def deactivate_python_program(self, context: BuildContext, *, program_id: str,
                                  version: int, request_key: str
                                  ) -> Mapping[str, Any]:
        return self._python_pointer(context, "python.program.deactivate", program_id,
                                    version, request_key)

    def build_python_program(self, context: BuildContext, *, program_id: str,
                             program_version: int,
                             parameters: Mapping[str, Any],
                             delegation_id: str, delegation_version: int,
                             schedule_id: str | None = None,
                             schedule_version: int | None = None,
                             request_key: str) -> Mapping[str, Any]:
        if not isinstance(context, BuildContext):
            raise ValueError("context must be a BuildContext")
        self._request_key(request_key)
        values = _canonical_copy(parameters, label="parameters")
        if not isinstance(values, dict):
            raise ValueError("parameters must be an object")
        delegation_id=_identifier(delegation_id,"delegation_id")
        delegation_version=self._positive_integer(
            delegation_version,"delegation_version")
        if (schedule_id is None)!=(schedule_version is None):
            raise ValueError("schedule_id and schedule_version must be supplied together")
        if schedule_id is not None:
            schedule_id=_identifier(schedule_id,"schedule_id")
            schedule_version=self._positive_integer(
                schedule_version,"schedule_version")
        return self._transport.call("execute_v2_python_program_build", {
            **context.application.to_wire(), "program": {
                "languageVersion": 2, "function": "python.program.build",
                "arguments": {"programId": _identifier(program_id, "program_id"),
                    "programVersion": self._positive_integer(
                        program_version, "program_version"),
                    "parameters": values,"delegationId":delegation_id,
                    "delegationVersion":delegation_version,
                    "scheduleId":schedule_id,"scheduleVersion":schedule_version,
                    **self._pins(context)}},
            "idempotency_key": request_key})

    def create_execution_delegation(self, context: BuildContext, *,
            delegation_id: str, version: int, issuer: str, subject_id: str,
            operation_scope: list[str], valid_from: str, valid_until: str,
            request_key: str) -> Mapping[str, Any]:
        """Create bounded unattended authority through the public MCP boundary."""
        if not isinstance(context, BuildContext):
            raise ValueError("context must be a BuildContext")
        self._request_key(request_key)
        delegation_id = _identifier(delegation_id, "delegation_id")
        version = self._positive_integer(version, "version")
        if (not isinstance(issuer, str) or not issuer or len(issuer) > 300
                or not isinstance(subject_id, str) or not subject_id
                or len(subject_id) > 300
                or any(ord(character) < 32 or ord(character) == 127
                       for value in (issuer, subject_id) for character in value)
                or not isinstance(operation_scope, list)
                or not 1 <= len(operation_scope) <= 32
                or len(set(operation_scope)) != len(operation_scope)
                or any(not isinstance(item, str)
                       or _identifier(item, "operation_scope") != item
                       for item in operation_scope)
                or not isinstance(valid_from, str) or not valid_from
                or not isinstance(valid_until, str) or not valid_until):
            raise ValueError("execution delegation is invalid")
        return self._transport.call("execute_v2_execution_delegation", {
            **context.application.to_wire(), "program": {
                "languageVersion": 2, "function": "execution.delegation.create",
                "arguments": {"delegationId": delegation_id, "version": version,
                    "issuer": issuer, "subjectId": subject_id,
                    "operationScope": list(operation_scope),
                    "validFrom": valid_from, "validUntil": valid_until,
                    "scheduleId": None, "scheduleVersion": None,
                    **self._pins(context)}}, "idempotency_key": request_key})

    def read_python_build(self, application: Application,
                          build_id: str) -> Mapping[str, Any]:
        return self._transport.call("read_v2_python_program_build", {
            **application.to_wire(), "build_id": self._build_id(build_id)})

    def read_python_build_artifact(self, application: Application, *,
                                   build_id: str, section: str,
                                   cursor: str | None = None
                                   ) -> Mapping[str, Any]:
        if section not in {'Plan', 'SourceMap', 'BuildLog'}:
            raise ValueError('section must be Plan, SourceMap, or BuildLog')
        if cursor is not None and (not isinstance(cursor, str) or not cursor):
            raise ValueError('cursor must be a non-empty string')
        return self._transport.call(
            "read_v2_python_program_build_artifact", {
                **application.to_wire(), "build_id": self._build_id(build_id),
                "section": section, "cursor": cursor})

    def inspect_python_build_artifact(self, application: Application, *,
                                      build_id: str, section: str
                                      ) -> PythonBuildArtifactSection:
        """Read and verify one complete immutable sealed-build artifact section."""
        build_id = self._build_id(build_id)
        if section not in _ARTIFACT_LIMITS:
            raise ValueError('section must be Plan, SourceMap, or BuildLog')
        maximum = _ARTIFACT_LIMITS[section]
        maximum_pages = max(1, maximum // _ARTIFACT_PAGE_BYTES)
        cursor = None
        seen: set[str] = set()
        chunks: list[bytes] = []
        expected_offset = 0
        identity = None
        total_bytes = None
        completed = False
        for page_index in range(maximum_pages):
            page = self.read_python_build_artifact(application,
                build_id=build_id, section=section, cursor=cursor)
            required = {'buildId', 'section', 'encoding', 'offset',
                'totalBytes', 'chunkBase64', 'nextCursor', 'planDigest',
                'sourceDigest', 'sectionDigest', 'compilerVersion', 'unitCount'}
            if not isinstance(page, Mapping) or not required.issubset(page):
                raise ValueError('Python build artifact page is invalid')
            current_identity = (page['buildId'], page['section'],
                page['planDigest'], page['sourceDigest'], page['sectionDigest'],
                page['compilerVersion'], page['unitCount'])
            if (page['buildId'] != build_id or page['section'] != section
                    or page['encoding'] != 'base64'
                    or any(type(value) is not str
                           or _HEX64.fullmatch(value) is None
                           for value in current_identity[2:5])
                    or type(page['compilerVersion']) is not str
                    or _COMPILER_VERSION.fullmatch(page['compilerVersion']) is None
                    or type(page['unitCount']) is not int
                    or not 1 <= page['unitCount'] <= MAX_OPERATIONS
                    or type(page['offset']) is not int
                    or page['offset'] != expected_offset
                    or type(page['totalBytes']) is not int
                    or not 0 <= page['totalBytes'] <= maximum
                    or type(page['chunkBase64']) is not str
                    or len(page['chunkBase64']) > 4 * ((_ARTIFACT_PAGE_BYTES + 2) // 3)
                    or page['nextCursor'] is not None
                    and (type(page['nextCursor']) is not str
                         or not 1 <= len(page['nextCursor']) <= 4096)):
                raise ValueError('Python build artifact page is invalid')
            if identity is None:
                identity = current_identity
                total_bytes = page['totalBytes']
            elif current_identity != identity or page['totalBytes'] != total_bytes:
                raise ValueError('Python build artifact identity changed during read')
            try:
                chunk = base64.b64decode(page['chunkBase64'], validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError('Python build artifact page is invalid') from error
            if (len(chunk) > _ARTIFACT_PAGE_BYTES
                    or expected_offset + len(chunk) > total_bytes
                    or page['nextCursor'] is not None
                    and len(chunk) != _ARTIFACT_PAGE_BYTES
                    or page['nextCursor'] is None
                    and expected_offset + len(chunk) != total_bytes):
                raise ValueError('Python build artifact page is truncated or oversized')
            chunks.append(chunk)
            expected_offset += len(chunk)
            next_cursor = page['nextCursor']
            if next_cursor is None:
                completed = True
                break
            if next_cursor in seen:
                raise ValueError('Python build artifact cursor repeated')
            seen.add(next_cursor)
            cursor = next_cursor
        else:
            raise ValueError('Python build artifact page limit exceeded')
        if identity is None or total_bytes is None or not completed:
            raise ValueError('Python build artifact is incomplete')
        raw = b''.join(chunks)
        if len(raw) != total_bytes or sha256(raw).hexdigest() != identity[4]:
            raise ValueError('Python build artifact digest mismatch')
        if section == 'BuildLog':
            try:
                content: Mapping[str, Any] | str = raw.decode('utf-8')
            except UnicodeDecodeError as error:
                raise ValueError('Python build log is not UTF-8') from error
            if '\x00' in content:
                raise ValueError('Python build log contains a NUL byte')
        else:
            try:
                content = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise ValueError('Python build artifact JSON is invalid') from error
            if not isinstance(content, dict):
                raise ValueError('Python build artifact JSON must be an object')
            canonical = json.dumps(content, ensure_ascii=True, sort_keys=True,
                separators=(',', ':'), allow_nan=False).encode('ascii')
            if canonical != raw:
                raise ValueError('Python build artifact JSON is not canonical')
            if section == 'Plan':
                units = content.get('units')
                if (content.get('format') != 'openepm-python-plan-v1'
                        or type(units) is not list
                        or len(units) != identity[6]
                        or identity[2] != identity[4]):
                    raise ValueError('Python build plan identity is invalid')
        return PythonBuildArtifactSection(build_id, section, identity[2],
            identity[3], identity[4], identity[5], identity[6], total_bytes,
            content)

    def cancel_python_build(self, application: Application,
                            build_id: str) -> Mapping[str, Any]:
        return self._transport.call("cancel_v2_python_program_build", {
            **application.to_wire(), "build_id": self._build_id(build_id)})

    def run_python_program(self, application: Application, *, build_id: str,
                           request_key: str) -> Mapping[str, Any]:
        self._request_key(request_key)
        return self._transport.call("execute_v2_python_program_run", {
            **application.to_wire(),
            "program": {"languageVersion": 2, "function": "python.program.run",
                        "arguments": {"buildId": self._build_id(build_id)}},
            "idempotency_key": request_key})

    def read_python_workflow(self, application: Application,
                             workflow_id: str) -> Mapping[str, Any]:
        return self._transport.call("read_v2_python_program_workflow", {
            **application.to_wire(), "workflow_id": self._build_id(workflow_id)})

    def cancel_python_workflow(self, application: Application,
                               workflow_id: str) -> Mapping[str, Any]:
        return self._transport.call("cancel_v2_python_program_workflow", {
            **application.to_wire(), "workflow_id": self._build_id(workflow_id)})

    def save_python_schedule(self, context: BuildContext, *, schedule_id: str,
            expected_version: int, expected_state_revision: int,
            program_id: str, program_version: int,
            parameters: Mapping[str,Any], interval_seconds: int,
            first_due_at: str, catch_up_policy: str, max_catch_up: int,
            delegation_id: str, delegation_version: int,
            request_key: str) -> Mapping[str,Any]:
        arguments={"scheduleId":_identifier(schedule_id,"schedule_id"),
            "expectedVersion":expected_version,
            "expectedStateRevision":expected_state_revision,
            "programId":_identifier(program_id,"program_id"),
            "programVersion":self._positive_integer(program_version,"program_version"),
            "parameters":_canonical_copy(parameters,label="parameters"),
            "intervalSeconds":interval_seconds,"firstDueAt":first_due_at,
            "catchUpPolicy":catch_up_policy,"maxCatchUp":max_catch_up,
            "delegationId":_identifier(delegation_id,"delegation_id"),
            "delegationVersion":self._positive_integer(delegation_version,"delegation_version"),
            **self._pins(context)}
        return self._python_registry(context.application,"python.schedule.save",
                                     arguments,request_key)

    def publish_python_schedule(self,context: BuildContext,*,schedule_id: str,
            version: int,expected_state_revision: int,request_key: str):
        return self._python_registry(context.application,"python.schedule.publish",
            {"scheduleId":_identifier(schedule_id,"schedule_id"),
             "version":self._positive_integer(version,"version"),
             "expectedStateRevision":expected_state_revision,**self._pins(context)},
            request_key)

    def deactivate_python_schedule(self,context: BuildContext,*,schedule_id: str,
            version: int,expected_state_revision: int,request_key: str):
        return self._python_registry(context.application,"python.schedule.deactivate",
            {"scheduleId":_identifier(schedule_id,"schedule_id"),
             "version":self._positive_integer(version,"version"),
             "expectedStateRevision":expected_state_revision,**self._pins(context)},
            request_key)

    def read_python_schedule(self,application: Application,schedule_id: str):
        return self.read(application,"python.schedule.read",
            {"scheduleId":_identifier(schedule_id,"schedule_id")})

    def list_python_schedules(self,application: Application,*,limit: int=100,
                              after_schedule_id: str|None=None):
        arguments={"limit":limit}
        if after_schedule_id is not None:arguments["afterScheduleId"]=_identifier(after_schedule_id,"after_schedule_id")
        return self.read(application,"python.schedule.list",arguments)

    def run_python_schedule(self,application: Application,*,schedule_id: str,
                            request_key: str):
        return self._python_registry(application,"python.schedule.run",
            {"scheduleId":_identifier(schedule_id,"schedule_id")},request_key)

    def read_python_schedule_occurrence(self,application: Application,
                                        occurrence_id: str):
        return self.read(application,"python.schedule.occurrence.read",
            {"occurrenceId":self._build_id(occurrence_id)})

    def cancel_python_schedule_occurrence(self,application: Application,*,
            occurrence_id: str,request_key: str):
        return self._python_registry(application,"python.schedule.occurrence.cancel",
            {"occurrenceId":self._build_id(occurrence_id)},request_key)

    def _python_pointer(self, context: BuildContext, function: str,
                        program_id: str, version: int,
                        request_key: str) -> Mapping[str, Any]:
        if not isinstance(context, BuildContext):
            raise ValueError("context must be a BuildContext")
        arguments = {"programId": _identifier(program_id, "program_id"),
                     "version": self._positive_integer(version, "version"),
                     **self._pins(context)}
        return self._python_registry(context.application, function, arguments,
                                     request_key)

    def _python_registry(self, application: Application, function: str,
                         arguments: Mapping[str, Any],
                         request_key: str) -> Mapping[str, Any]:
        self._request_key(request_key)
        return self._transport.call("execute_v2_python_program_registry", {
            **application.to_wire(),
            "program": {"languageVersion": 2, "function": function,
                        "arguments": _canonical_copy(arguments,
                                                     label="arguments")},
            "idempotency_key": request_key})

    @staticmethod
    def _pins(context: BuildContext) -> dict[str, int]:
        return {"expectedMetadataRevision": context.metadata_revision,
                "expectedPolicyRevision": context.policy_revision,
                "expectedSchemaEpoch": context.schema_epoch}

    @staticmethod
    def _positive_integer(value: object, label: str) -> int:
        if type(value) is not int or value < 1:
            raise ValueError(f"{label} must be a positive integer")
        return value

    @staticmethod
    def _request_key(value: object) -> str:
        if not isinstance(value, str) or not _REQUEST_KEY.fullmatch(value):
            raise ValueError("request_key must match [A-Za-z0-9._-]{8,128}")
        return value

    @staticmethod
    def _build_id(value: object) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
            raise ValueError("build_id must be 32 lowercase hexadecimal characters")
        return value

    @staticmethod
    def _single_operation(program: Program) -> Mapping[str, Any]:
        if (not isinstance(program, Program) or len(program.units) != 1
                or len(program.units[0].operations) != 1):
            raise ValueError(
                "Composite plans require the server-owned python.program.build workflow")
        return program.to_wire()["units"][0]["operations"][0]
