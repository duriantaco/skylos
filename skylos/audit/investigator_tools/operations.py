"""Implementations of the bounded read, search, and listing tools."""

from __future__ import annotations

import re
from typing import Any

from .models import AuditToolError, ToolObservation
from .rendering import SearchHit, _bounded_numbered_lines, _bounded_search_hits
from .rendering import _truncate_utf8
from .validation import (
    _optional_positive_int,
    _reject_unknown_arguments,
    _symbol_matcher,
)


class ToolOperationsMixin:
    def _read_file(self, arguments: dict[str, Any]) -> ToolObservation:
        _reject_unknown_arguments(arguments, {"path", "start_line", "end_line"})
        rel_path = self._catalog_path(arguments.get("path"))
        start = _optional_positive_int(arguments.get("start_line"), default=1)
        requested_end = _optional_positive_int(
            arguments.get("end_line"),
            default=start + self.limits.max_lines_per_read - 1,
        )
        if requested_end < start:
            raise AuditToolError("read_file end_line must not precede start_line")
        end = min(requested_end, start + self.limits.max_lines_per_read - 1)
        source = self._read_source(rel_path)
        visible_source = self._safe_source_view(rel_path, source)
        lines = visible_source.splitlines()
        if start > max(1, len(lines)):
            raise AuditToolError(f"read_file start_line is outside {rel_path}")
        selected = lines[start - 1 : end]
        visible_lines, content, output_truncated = _bounded_numbered_lines(
            selected,
            start=start,
            max_bytes=self.limits.max_output_bytes_per_call,
        )
        self._record_visited(rel_path, source)
        if visible_lines:
            self._record_inspected_range(
                rel_path,
                start,
                start + len(visible_lines) - 1,
            )
        return ToolObservation(
            tool="read_file",
            content=content,
            summary={
                "path": rel_path,
                "start_line": start,
                "end_line": start + len(visible_lines) - 1,
                "file_lines": len(lines),
                "truncated": (
                    requested_end > end or end < len(lines) or output_truncated
                ),
            },
        )

    def _search_code(
        self,
        arguments: dict[str, Any],
        *,
        symbol: bool,
    ) -> ToolObservation:
        query, matcher = _validated_search_terms(arguments, symbol=symbol)
        prefix = self._path_prefix(arguments.get("path_prefix"))
        candidates, search_space_truncated = self._bounded_search_candidates(prefix)
        hits, scanned_bytes = self._scan_search_candidates(
            candidates,
            query=query,
            matcher=matcher,
        )
        visible_hits, output_truncated = _bounded_search_hits(
            hits,
            self.limits.max_output_bytes_per_call,
        )
        matched_sources = self._record_search_evidence(visible_hits)
        truncated = _search_was_truncated(
            search_space_truncated=search_space_truncated,
            hit_count=len(hits),
            max_hits=self.limits.max_search_hits,
            scanned_bytes=scanned_bytes,
            max_scan_bytes=self.limits.max_search_scan_bytes,
            output_truncated=output_truncated,
        )
        if truncated:
            self._unsafe_discovery_truncations += 1
        return ToolObservation(
            tool="find_symbol" if symbol else "search_code",
            content=_render_search_content(visible_hits),
            summary={
                "query": query,
                "path_prefix": prefix or None,
                "matches": len(visible_hits),
                "matched_files": sorted(matched_sources),
                "truncated": truncated,
                "sensitive_files_withheld": self._sensitive_denials,
            },
        )

    def _bounded_search_candidates(
        self,
        prefix: str,
    ) -> tuple[list[tuple[str, Any]], bool]:
        candidates = self._catalog_items(prefix)
        truncated = len(candidates) > self.limits.max_search_files
        return candidates[: self.limits.max_search_files], truncated

    def _scan_search_candidates(
        self,
        candidates: list[tuple[str, Any]],
        *,
        query: str,
        matcher: re.Pattern[str] | None,
    ) -> tuple[list[SearchHit], int]:
        hits: list[SearchHit] = []
        scanned_bytes = 0
        for rel_path, _path in candidates:
            source = self._read_source(rel_path)
            visible_source = self._searchable_source(rel_path, source)
            if visible_source is None:
                continue
            scanned_bytes += len(visible_source.encode("utf-8"))
            if scanned_bytes > self.limits.max_search_scan_bytes:
                break
            hits.extend(
                _matching_lines(
                    rel_path,
                    source,
                    visible_source,
                    query=query,
                    matcher=matcher,
                    existing_hits=len(hits),
                    max_hits=self.limits.max_search_hits,
                )
            )
            if len(hits) >= self.limits.max_search_hits:
                break
        return hits, scanned_bytes

    def _searchable_source(self, rel_path: str, source: str) -> str | None:
        try:
            return self._safe_source_view(rel_path, source)
        except AuditToolError:
            return None

    def _record_search_evidence(
        self,
        visible_hits: list[SearchHit],
    ) -> dict[str, str]:
        matched_sources: dict[str, str] = {}
        for _text, rel_path, line_number, source in visible_hits:
            matched_sources[rel_path] = source
            self._record_inspected_range(rel_path, line_number, line_number)
        for rel_path, source in sorted(matched_sources.items()):
            self._record_visited(rel_path, source)
        return matched_sources

    def _list_files(self, arguments: dict[str, Any]) -> ToolObservation:
        _reject_unknown_arguments(arguments, {"path_prefix", "name_contains"})
        prefix = self._path_prefix(arguments.get("path_prefix"))
        contains = _validated_name_filter(arguments.get("name_contains"))
        paths = _matching_paths(self._catalog_items(prefix), contains)
        truncated = len(paths) > self.limits.max_list_results
        visible_paths = paths[: self.limits.max_list_results]
        content = _truncate_utf8(
            "\n".join(visible_paths) if visible_paths else "No matching files.",
            self.limits.max_output_bytes_per_call,
        )
        truncated = truncated or content.endswith("[TRUNCATED]")
        if truncated:
            self._unsafe_discovery_truncations += 1
        return ToolObservation(
            tool="list_files",
            content=content,
            summary={
                "path_prefix": prefix or None,
                "name_contains": contains or None,
                "matches": len(visible_paths),
                "truncated": truncated,
            },
        )


def _validated_search_terms(
    arguments: dict[str, Any],
    *,
    symbol: bool,
) -> tuple[str, re.Pattern[str] | None]:
    _reject_unknown_arguments(arguments, {"query", "path_prefix"})
    raw_query = arguments.get("query")
    if not isinstance(raw_query, str):
        raise AuditToolError("search query must be a string")
    query = raw_query.strip()
    if not query or len(query) > 128 or any(char in query for char in "\r\n\x00"):
        raise AuditToolError("search query must be 1-128 characters on one line")
    if symbol and not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_.$:]*", query):
        raise AuditToolError("find_symbol requires an identifier or qualified name")
    return query, _symbol_matcher(query) if symbol else None


def _matching_lines(
    rel_path: str,
    source: str,
    visible_source: str,
    *,
    query: str,
    matcher: re.Pattern[str] | None,
    existing_hits: int,
    max_hits: int,
) -> list[SearchHit]:
    hits: list[SearchHit] = []
    for line_number, line in enumerate(visible_source.splitlines(), start=1):
        if not _line_matches(line, query=query, matcher=matcher):
            continue
        hits.append(
            (f"{rel_path}:{line_number}: {line}", rel_path, line_number, source)
        )
        if existing_hits + len(hits) >= max_hits:
            break
    return hits


def _line_matches(
    line: str,
    *,
    query: str,
    matcher: re.Pattern[str] | None,
) -> bool:
    if matcher is not None:
        return bool(matcher.search(line))
    return query in line


def _search_was_truncated(
    *,
    search_space_truncated: bool,
    hit_count: int,
    max_hits: int,
    scanned_bytes: int,
    max_scan_bytes: int,
    output_truncated: bool,
) -> bool:
    return (
        search_space_truncated
        or hit_count >= max_hits
        or scanned_bytes > max_scan_bytes
        or output_truncated
    )


def _render_search_content(hits: list[SearchHit]) -> str:
    if not hits:
        return "No matches."
    return "\n".join(item[0] for item in hits)


def _validated_name_filter(raw_contains: Any) -> str:
    if raw_contains is not None and not isinstance(raw_contains, str):
        raise AuditToolError("name_contains must be a string")
    contains = (raw_contains or "").strip().lower()
    if len(contains) > 128 or any(char in contains for char in "\r\n\x00"):
        raise AuditToolError("name_contains must be at most 128 characters")
    return contains


def _matching_paths(
    catalog_items: list[tuple[str, Any]],
    contains: str,
) -> list[str]:
    return [
        rel_path
        for rel_path, _path in catalog_items
        if not contains or contains in rel_path.lower()
    ]
