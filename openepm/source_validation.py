"""No-execution Python syntax validation for save/build admission.

Compiling checks Python's grammar and static compiler rules; it does not import
or execute the resulting code. Semantic plan validation remains in the isolated
builder and fixed primitive validators.
"""
from __future__ import annotations

from hashlib import sha256
import warnings

from .diagnostics import Diagnostic, SourceValidationError, diagnostic_payload


MAX_SOURCE_BYTES = 1_048_576


def _column(lines: list[str], line: int, column: int) -> int:
    if not 1 <= line <= len(lines):
        return 1
    prefix = lines[line - 1][:max(0, column - 1)]
    return len(prefix.encode("utf-16-le")) // 2 + 1


def validate_python_source(source: str) -> str:
    """Return the exact source digest, or useful diagnostics; never run source."""
    if type(source) is not str:
        raise ValueError("PYTHON_SOURCE_INVALID")
    try:
        encoded = source.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("PYTHON_SOURCE_INVALID") from None
    if not 1 <= len(encoded) <= MAX_SOURCE_BYTES or "\x00" in source:
        raise ValueError("PYTHON_SOURCE_INVALID")
    digest = sha256(encoded).hexdigest()
    try:
        # Python 3.12+ can emit source-bearing SyntaxWarnings. Diagnostics own
        # the public output; do not let compiler warnings enter service logs.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            compile(source, "<openepm-program>", "exec", dont_inherit=True,
                    optimize=0)
    except SyntaxError as error:
        lines = source.splitlines()
        start_line = max(1, error.lineno or 1)
        start_column = _column(lines, start_line, error.offset or 1)
        end_line = max(start_line, error.end_lineno or start_line)
        end_column = _column(lines, end_line, error.end_offset or error.offset or 1)
        if end_line == start_line:
            end_column = max(start_column, end_column)
        # The parser's message contains the grammatical diagnosis, never its
        # separate source-text/excerpt field or a formatted traceback.
        message = " ".join(str(error.msg).split())[:400] or "Invalid Python syntax."
        code = ("PYTHON_INDENTATION_ERROR" if isinstance(error, IndentationError)
                else "PYTHON_SYNTAX_ERROR")
        diagnostic = Diagnostic(code, message, "syntax",
            (start_line, start_column, end_line, end_column),
            hint="Correct the highlighted syntax and save again.")
        raise SourceValidationError(diagnostic_payload(digest, (diagnostic,))) from None
    except (RecursionError, MemoryError, OverflowError):
        raise SourceValidationError(diagnostic_payload(digest, (Diagnostic(
            "PYTHON_SOURCE_COMPLEXITY_LIMIT", "The source exceeds the compiler's complexity limit.",
            "syntax", hint="Split excessively nested expressions into smaller expressions."),))) from None
    return digest
