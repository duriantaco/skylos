"""Stateful budget and evidence session for read-only investigator tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .catalog import CatalogMixin, build_catalog_snapshot
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
from .operations import ToolOperationsMixin
from .safety import EvidenceSafetyMixin
from .validation import _positive_int


class AuditReadOnlyTools(ToolOperationsMixin, CatalogMixin, EvidenceSafetyMixin):
    """Root-confined, bounded repository reads for an untrusted model.

    This class deliberately exposes no arbitrary callbacks, regexes, shell,
    writes, network, imports, tests, or target-code execution.
    """

    TOOL_NAMES = ("read_file", "search_code", "list_files", "find_symbol")

    def __init__(
        self,
        project_root: str | Path,
        *,
        limits: InvestigationToolLimits | None = None,
        extensions: tuple[str, ...] = DEFAULT_SOURCE_EXTENSIONS,
        exclude_folders: tuple[str, ...] = DEFAULT_EXCLUDED_FOLDERS,
        denied_paths: Iterable[str] | None = None,
        excluded_paths: Iterable[str] | None = None,
    ) -> None:
        self.project_root = Path(project_root).resolve(strict=True)
        if not self.project_root.is_dir():
            raise ValueError("Investigator project root must be a directory")
        self.limits = limits or InvestigationToolLimits()
        self._extensions = tuple(extensions)
        self._exclude_folders = tuple(exclude_folders)
        self._denied_paths = frozenset(str(path) for path in (denied_paths or ()))
        self._excluded_paths = frozenset(
            str(path).rstrip("/") for path in (excluded_paths or ()) if str(path)
        )
        snapshot = build_catalog_snapshot(
            self.project_root,
            self._extensions,
            self._exclude_folders,
            self._excluded_paths,
            max_catalog_files=self.limits.max_catalog_files,
        )
        self._discovered_count = snapshot.discovered_count
        self.catalog_truncated = snapshot.truncated
        self._catalog = snapshot.paths
        self._catalog_signatures = snapshot.signatures
        self._catalog_digest = snapshot.digest
        self.tool_calls = 0
        self.source_observation_calls = 0
        self.total_output_bytes = 0
        self._visited_hashes: dict[str, str] = {}
        self._inspected_ranges: dict[str, list[tuple[int, int]]] = {}
        self._entry_file: str | None = None
        self._source_observed_files: set[str] = set()
        self._redacted_source_files: set[str] = set()
        self._unsafe_discovery_truncations = 0
        self._sensitive_denials = 0

    @property
    def visited_files(self) -> tuple[str, ...]:
        return tuple(sorted(self._visited_hashes))

    @property
    def related_file_hashes(self) -> dict[str, str]:
        return dict(sorted(self._visited_hashes.items()))

    @property
    def related_files(self) -> list[dict[str, str]]:
        return [
            {"path": path, "sha256": file_hash}
            for path, file_hash in sorted(self._visited_hashes.items())
        ]

    @property
    def catalog_size(self) -> int:
        return len(self._catalog)

    def catalog_preview(self) -> dict[str, Any]:
        """Return a bounded path-only view for safe initial tool planning."""

        paths = sorted(self._catalog)
        visible = paths[: self.limits.max_catalog_preview]
        return {
            "file_count": len(paths),
            "files": visible,
            "truncated": len(visible) < len(paths),
        }

    @property
    def has_related_source_observation(self) -> bool:
        return any(path != self._entry_file for path in self._source_observed_files)

    def register_initial_file(
        self,
        path: str,
        *,
        visible_end_line: int | None = None,
    ) -> str:
        rel_path = self._catalog_path(path)
        source = self._read_source(rel_path)
        self._safe_source_view(rel_path, source)
        self._record_visited(rel_path, source)
        if self._entry_file is None:
            self._entry_file = rel_path
        if visible_end_line is not None and visible_end_line > 0:
            self._record_inspected_range(rel_path, 1, visible_end_line)
        return rel_path

    def execute(self, tool: str, arguments: dict[str, Any]) -> ToolObservation:
        self._consume_tool_call()
        handler = self._tool_handlers().get(tool)
        if handler is None:
            raise AuditToolError(f"unknown investigator tool: {tool}")
        observation = handler(arguments)
        observed_paths = _source_observation_paths(tool, observation.summary)
        if observed_paths:
            self.source_observation_calls += 1
            self._source_observed_files.update(observed_paths)
        self._consume_output(observation.content)
        return observation

    def validate_evidence(
        self,
        path: str,
        line: int,
        end_line: int | None = None,
    ) -> tuple[str, int, int]:
        rel_path = self._catalog_path(path)
        if rel_path not in self._visited_hashes:
            raise AuditToolError(
                f"evidence file was not inspected by the investigator: {rel_path}"
            )
        source = self._read_source(rel_path)
        self._record_visited(rel_path, source)
        lines = source.splitlines()
        if not lines:
            raise AuditToolError(f"evidence file is empty: {rel_path}")
        start = _positive_int(line, name="evidence line")
        end = (
            start if end_line is None else _positive_int(end_line, name="evidence end")
        )
        if end < start or end > len(lines):
            raise AuditToolError(f"evidence range is outside {rel_path}")
        if not self._range_was_inspected(rel_path, start, end):
            raise AuditToolError(
                f"evidence range was not exposed to the investigator: {rel_path}"
            )
        return rel_path, start, end

    def assert_visited_files_current(self) -> None:
        """Fail if any evidence-bearing file changed during the session."""

        for rel_path in self.visited_files:
            self._record_visited(rel_path, self._read_source(rel_path))

    def assert_completion_safe(self) -> None:
        if self.catalog_truncated:
            raise AuditToolBudgetExceeded(
                "repository catalog budget was truncated; completion is unsafe"
            )
        if self._sensitive_denials:
            raise AuditToolError(
                "sensitive source context was withheld during investigation"
            )
        if self._unsafe_discovery_truncations:
            raise AuditToolBudgetExceeded(
                "repository discovery result was truncated; completion is unsafe"
            )
        if self._current_catalog_digest() != self._catalog_digest:
            raise AuditToolFileChanged(
                "repository catalog changed during investigation"
            )
        self.assert_visited_files_current()

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_schema_version": INVESTIGATOR_TOOL_SCHEMA_VERSION,
            "tool_calls": self.tool_calls,
            "source_observation_calls": self.source_observation_calls,
            "source_observed_files": sorted(self._source_observed_files),
            "evidence_bytes": self.total_output_bytes,
            "visited_files": list(self.visited_files),
            "related_files": self.related_files,
            "inspected_ranges": {
                path: [[start, end] for start, end in ranges]
                for path, ranges in sorted(self._inspected_ranges.items())
            },
            "catalog_size": self.catalog_size,
            "catalog_truncated": self.catalog_truncated,
            "catalog_digest": self._catalog_digest,
            "excluded_sensitive_files": len(self._denied_paths),
            "redacted_source_files": len(self._redacted_source_files),
            "unsafe_discovery_truncations": self._unsafe_discovery_truncations,
            "configured_excluded_paths": len(self._excluded_paths),
            "sensitive_denials": self._sensitive_denials,
        }

    def _tool_handlers(self):
        return {
            "read_file": self._read_file,
            "search_code": self._search_text,
            "find_symbol": self._find_symbol,
            "list_files": self._list_files,
        }

    def _search_text(self, arguments: dict[str, Any]) -> ToolObservation:
        return self._search_code(arguments, symbol=False)

    def _find_symbol(self, arguments: dict[str, Any]) -> ToolObservation:
        return self._search_code(arguments, symbol=True)

    def _consume_tool_call(self) -> None:
        if self.tool_calls >= self.limits.max_tool_calls:
            raise AuditToolBudgetExceeded("investigator tool-call budget exhausted")
        self.tool_calls += 1

    def _consume_output(self, content: str) -> None:
        size = len(content.encode("utf-8"))
        if size > self.limits.max_output_bytes_per_call:
            raise AuditToolBudgetExceeded(
                "investigator tool output exceeded per-call budget"
            )
        if self.total_output_bytes + size > self.limits.max_total_output_bytes:
            raise AuditToolBudgetExceeded(
                "investigator total evidence budget exhausted"
            )
        self.total_output_bytes += size


def _source_observation_paths(
    tool: str,
    summary: dict[str, Any],
) -> tuple[str, ...]:
    if tool == "read_file" and _read_observation_has_source(summary):
        path = summary.get("path")
        return (path,) if isinstance(path, str) else ()
    if tool in {"search_code", "find_symbol"} and int(summary.get("matches") or 0) > 0:
        return tuple(
            path for path in summary.get("matched_files", ()) if isinstance(path, str)
        )
    return ()


def _read_observation_has_source(summary: dict[str, Any]) -> bool:
    return int(summary.get("end_line") or 0) >= int(summary.get("start_line") or 1)
