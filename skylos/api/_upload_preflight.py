"""Upload pre-flight: make every finding follow the upload contract.

Findings are never dropped. See ``apply_upload_contract``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from skylos.api._upload_contract import (
    field_max_length,
    repository_scope_kind,
    repository_scope_line,
    repository_scope_rule_ids,
)
from skylos.api._upload_paths import (
    encode_upload_path,
    normalize_contract_file_path,
    resolve_upload_location,
)

__all__ = ["UploadPreflight", "apply_upload_contract", "strip_secret_snippets"]

_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")


def _project_root_path(project_root: Any) -> str | None:
    if project_root is None:
        return None
    normalized = normalize_contract_file_path(str(project_root))
    if normalized is None:
        return None
    normalized = normalized.rstrip("/")
    return normalized if normalized and normalized != "." else "."


def _is_base_directory(finding: dict[str, Any], base: str | None) -> bool:
    raw = finding.get("file_path") or finding.get("file")
    if not isinstance(raw, str) or not raw.strip():
        return False
    if raw.strip() in (".", "./"):
        return True
    if base is None or not os.path.isabs(raw):
        return False
    try:
        return os.path.realpath(raw) == os.path.realpath(base)
    except (OSError, ValueError):
        return False


def _normalize_rule_id(value: Any, max_length: int) -> str:
    if isinstance(value, str) and len(value) <= max_length and value.strip() == value:
        if value and not _CONTROL_CHARACTER_RE.search(value):
            return value
    text = _CONTROL_CHARACTER_RE.sub("", str(value if value is not None else ""))
    text = text.strip()[:max_length].strip()
    return text or "UNKNOWN"


def _normalize_line(value: Any) -> int:
    try:
        line = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(line, 0)


@dataclass(frozen=True)
class UploadPreflight:
    """What the pre-flight pass changed or found."""

    finding_count: int = 0
    repository_scoped: int = 0
    no_location: int = 0

    def no_location_message(self) -> str | None:
        if not self.no_location:
            return None
        if self.no_location == 1:
            return "1 finding has no file location; uploading it anyway."
        return (
            f"{self.no_location} findings have no file location; uploading them anyway."
        )


def _drop_absolute_file(finding: dict[str, Any]) -> None:
    """Keep the local checkout path out of the upload.

    Analyzer findings carry the absolute ``file`` beside the repo-relative
    ``file_path``; evidence built from ``file`` (for example SARIF evidence
    traces) would otherwise send the user's home directory to the server.
    """
    if "file" in finding and isinstance(finding.get("file_path"), str):
        finding["file"] = finding["file_path"]


def _is_repository_scoped(finding: dict[str, Any], scope_ids, scope_kind) -> bool:
    return finding.get("rule_id") in scope_ids and finding.get("kind") == scope_kind


def apply_upload_contract(
    findings: list[dict[str, Any]],
    project_root: Any,
    base_dir: str | os.PathLike | None = None,
) -> UploadPreflight:
    """Normalize findings in place so each one follows the upload contract.

    Findings are never dropped. Repository-level findings (the contract's
    ``repository_scope`` rules) are sent at the project root on line 1.
    Every other finding is sent with a path inside the project, relative to
    ``base_dir`` (the Git root, or the working directory without one), or
    with an empty path when it has no usable location: never a placeholder
    such as ``unknown``, an absolute machine path, or a ``..`` path.
    """
    scope_ids = repository_scope_rule_ids()
    scope_kind = repository_scope_kind()
    scope_line = repository_scope_line()
    rule_id_max = field_max_length("rule_id", 120)
    root = _project_root_path(project_root)
    base = os.fspath(base_dir) if base_dir is not None else None
    isdir_cache: dict[str, bool] = {}
    repository_scoped = 0
    no_location = 0

    for finding in findings:
        # Severity and category are left alone: in the SARIF payload they
        # become the result ``level`` and ``properties.category`` the server
        # already stores, and changing them would change Cloud gate results.
        finding["rule_id"] = _normalize_rule_id(finding.get("rule_id"), rule_id_max)

        if _is_repository_scoped(finding, scope_ids, scope_kind):
            repository_scoped += 1
            finding["line_number"] = scope_line
            if root is not None:
                finding["file_path"] = root
            elif _is_base_directory(finding, base):
                # The contract sends repository-level findings at the project
                # root, which is "." when the project is the repository root.
                # resolve_upload_location() treats the base directory itself
                # as "no location", which the server would store without a
                # location (and count as new on pull-request scans).
                finding["file_path"] = "."
            else:
                location = resolve_upload_location(
                    finding, base, root, allow_directory=True
                )
                finding["file_path"] = encode_upload_path(location) if location else ""
            # A snippet read from a manifest no longer matches the location.
            finding.pop("snippet", None)
            _drop_absolute_file(finding)
            continue

        finding["line_number"] = _normalize_line(finding.get("line_number"))
        location = resolve_upload_location(finding, base, root, isdir_cache=isdir_cache)
        if location is None:
            no_location += 1
            finding["file_path"] = ""
            finding.pop("snippet", None)
        else:
            finding["file_path"] = encode_upload_path(location)
        _drop_absolute_file(finding)

    return UploadPreflight(
        finding_count=len(findings),
        repository_scoped=repository_scoped,
        no_location=no_location,
    )


def strip_secret_snippets(payload: Any) -> None:
    """Remove any code snippet attached to a SECRET finding in an upload body.

    Normalization already drops them; this is a last check on the exact
    body before it is first sent (and therefore before it can be saved for
    ``skylos upload --retry``, which resends those bytes unchanged).
    """
    if not isinstance(payload, dict):
        return
    for run in payload.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            props = result.get("properties") or {}
            if str(props.get("category") or "").upper() != "SECRET":
                continue
            for location in result.get("locations") or []:
                physical = (location or {}).get("physicalLocation") or {}
                region = physical.get("region")
                if isinstance(region, dict):
                    region.pop("snippet", None)
    for finding in payload.get("findings") or []:
        if (
            isinstance(finding, dict)
            and str(finding.get("category") or "").upper() == "SECRET"
        ):
            finding.pop("snippet", None)
