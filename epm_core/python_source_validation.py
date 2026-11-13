"""Fixed-core import of the same no-execution validator used by the builder."""
from openepm.source_validation import MAX_SOURCE_BYTES, validate_python_source

__all__ = ['MAX_SOURCE_BYTES', 'validate_python_source']
