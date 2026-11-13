"""Preserve fixed-validator diagnostics through MCP worker isolation."""
from __future__ import annotations

import json

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent

from openepm.diagnostics import SourceValidationError, validate_diagnostic_payload


class DiagnosticToolError(ToolError):
    def __init__(self, details: dict):
        self.details = validate_diagnostic_payload(details)
        super().__init__(SourceValidationError.code)

    def result(self) -> CallToolResult:
        payload = {"code": SourceValidationError.code,
            "message": "Correct the source diagnostics and save again.",
            "details": self.details}
        return CallToolResult(is_error=True, structured_content=payload,
            content=[TextContent(type="text", text=json.dumps(payload,
                ensure_ascii=False, separators=(",", ":")))])
