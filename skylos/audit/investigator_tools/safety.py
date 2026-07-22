"""Evidence tracking and secret-safe source projection."""

from __future__ import annotations

import hashlib

from skylos.audit.redaction import redact_text
from skylos.rules.secrets import scan_ctx as scan_secret_context

from .models import AuditToolBudgetExceeded, AuditToolError, AuditToolFileChanged


class EvidenceSafetyMixin:
    def _record_visited(self, rel_path: str, source: str) -> None:
        source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        previous_hash = self._visited_hashes.get(rel_path)
        if previous_hash is not None and previous_hash != source_hash:
            raise AuditToolFileChanged(
                f"source file changed during investigation: {rel_path}"
            )
        if rel_path not in self._visited_hashes:
            if len(self._visited_hashes) >= self.limits.max_distinct_files:
                raise AuditToolBudgetExceeded(
                    "investigator distinct-file budget exhausted"
                )
            self._visited_hashes[rel_path] = source_hash

    def _record_inspected_range(self, rel_path: str, start: int, end: int) -> None:
        ranges = [*self._inspected_ranges.get(rel_path, ()), (start, end)]
        merged: list[tuple[int, int]] = []
        for range_start, range_end in sorted(ranges):
            if not merged or range_start > merged[-1][1] + 1:
                merged.append((range_start, range_end))
                continue
            merged[-1] = (merged[-1][0], max(merged[-1][1], range_end))
        self._inspected_ranges[rel_path] = merged

    def _range_was_inspected(self, rel_path: str, start: int, end: int) -> bool:
        return any(
            inspected_start <= start and end <= inspected_end
            for inspected_start, inspected_end in self._inspected_ranges.get(
                rel_path, ()
            )
        )

    def _safe_source_view(self, rel_path: str, source: str) -> str:
        visible_source = redact_text(source)
        if rel_path in self._denied_paths or visible_source != source:
            self._redacted_source_files.add(rel_path)
        try:
            findings = scan_secret_context(
                {
                    # Force language-agnostic secret checks to run for every
                    # extension exposed by the investigator catalog.
                    "relpath": f"{rel_path}.py",
                    "lines": visible_source.splitlines(keepends=True),
                    "tree": None,
                },
                ignore_tests=False,
            )
        except Exception as exc:
            self._sensitive_denials += 1
            raise AuditToolError(
                f"source sensitivity check failed safely: {rel_path}"
            ) from exc
        if findings:
            self._sensitive_denials += 1
            raise AuditToolError(f"source file was withheld as sensitive: {rel_path}")
        return visible_source
