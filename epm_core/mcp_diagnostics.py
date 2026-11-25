"""Preserve fixed-validator diagnostics through MCP worker isolation."""
from __future__ import annotations

import json

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent

from openepm.diagnostics import SourceValidationError, validate_diagnostic_payload
from openepm.public_diagnostics import (
    CATALOG_DISCOVERY_CODES, CATALOG_DISCOVERY_FORMAT, PROGRAM_FORMAT,
    validate_catalog_discovery_diagnostic)
from .public_program_diagnostics import ProgramValidationError, validate_program_diagnostic


def validate_public_diagnostic_payload(details: dict) -> tuple[str, dict]:
    if isinstance(details, dict) and details.get('format') == PROGRAM_FORMAT:
        return ProgramValidationError.code, validate_program_diagnostic(details)
    if isinstance(details, dict) and details.get('format') == CATALOG_DISCOVERY_FORMAT:
        validated = validate_catalog_discovery_diagnostic(details)
        return validated['code'], validated
    return SourceValidationError.code, validate_diagnostic_payload(details)


class DiagnosticToolError(ToolError):
    def __init__(self, details: dict):
        self.code, self.details = validate_public_diagnostic_payload(details)
        super().__init__(self.code)

    def result(self) -> CallToolResult:
        if self.code in CATALOG_DISCOVERY_CODES:
            message = self.details['recovery']
        elif self.code == ProgramValidationError.code:
            message = "Review the program diagnostics and current authorized discovery."
        else:
            message = "Correct the source diagnostics and save again."
        payload = {"code": self.code, "message": message, "details": self.details}
        return CallToolResult(is_error=True, structured_content=payload,
            content=[TextContent(type="text", text=json.dumps(payload,
                ensure_ascii=False, separators=(",", ":")))])
