"""Root-confined, bounded repository reads for Deep Audit investigators."""

from .catalog import _catalog_digest, _regular_file_signature
from .models import (
    DEFAULT_EXCLUDED_FOLDERS,
    DEFAULT_SOURCE_EXTENSIONS,
    INVESTIGATOR_TOOL_SCHEMA_VERSION,
    AuditToolBudgetExceeded,
    AuditToolError,
    AuditToolFileChanged,
    InvestigationToolLimits,
    ToolObservation,
)
from .rendering import (
    _bounded_numbered_lines,
    _bounded_search_hits,
    _truncate_utf8,
)
from .session import AuditReadOnlyTools
from .validation import (
    _optional_positive_int,
    _positive_int,
    _reject_unknown_arguments,
    _symbol_matcher,
    _validated_relative_path_text,
)

__all__ = [
    "DEFAULT_EXCLUDED_FOLDERS",
    "DEFAULT_SOURCE_EXTENSIONS",
    "INVESTIGATOR_TOOL_SCHEMA_VERSION",
    "AuditReadOnlyTools",
    "AuditToolBudgetExceeded",
    "AuditToolError",
    "AuditToolFileChanged",
    "InvestigationToolLimits",
    "ToolObservation",
    "_bounded_numbered_lines",
    "_bounded_search_hits",
    "_catalog_digest",
    "_optional_positive_int",
    "_positive_int",
    "_regular_file_signature",
    "_reject_unknown_arguments",
    "_symbol_matcher",
    "_truncate_utf8",
    "_validated_relative_path_text",
]
