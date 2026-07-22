"""Public constants and value types for bounded investigator tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


INVESTIGATOR_TOOL_SCHEMA_VERSION = "audit-read-tools-v2"

DEFAULT_SOURCE_EXTENSIONS = (
    ".py",
    ".pyi",
    ".pyw",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".java",
    ".kt",
    ".kts",
    ".php",
    ".rb",
    ".rs",
    ".dart",
    ".cs",
    ".scala",
    ".swift",
    ".vue",
    ".svelte",
    ".sql",
    ".graphql",
    ".gql",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
)

DEFAULT_EXCLUDED_FOLDERS = (
    ".git",
    ".hg",
    ".svn",
    ".skylos",
    ".agents",
    ".claude",
    ".codex",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "target",
    "dist",
    "build",
    "coverage",
    "htmlcov",
    "__pycache__",
)


class AuditToolError(RuntimeError):
    """A bounded, content-free denial from the investigator tool layer."""


class AuditToolBudgetExceeded(AuditToolError):
    """A hard investigation limit was reached."""


class AuditToolFileChanged(AuditToolError):
    """A source file changed after the repository view was frozen."""


@dataclass(frozen=True)
class InvestigationToolLimits:
    max_tool_calls: int = 12
    max_distinct_files: int = 12
    max_catalog_files: int = 10_000
    max_file_bytes: int = 1_000_000
    max_lines_per_read: int = 240
    max_output_bytes_per_call: int = 24_000
    max_total_output_bytes: int = 96_000
    max_search_hits: int = 60
    max_search_files: int = 1_000
    max_search_scan_bytes: int = 8_000_000
    max_list_results: int = 200
    max_catalog_preview: int = 200


@dataclass(frozen=True)
class ToolObservation:
    tool: str
    content: str
    summary: dict[str, Any]

    def to_prompt_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "summary": dict(self.summary),
            "content": self.content,
        }
