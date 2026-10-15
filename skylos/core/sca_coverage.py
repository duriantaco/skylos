"""Validate the operational receipt for explicitly unqueried SCA sources."""

import re
from collections.abc import Mapping

NON_REGISTRY_COVERAGE_STATUS = "complete_with_non_registry_sources"
# Every supported dependency file was read and queried, but the repository
# also has dependency files Skylos does not read (composer.lock, Cargo.lock,
# pom.xml, ...). `complete` is false; `unsupported_inputs` names them. Not an
# operational failure, so it never makes a scan exit 2 on its own.
UNSUPPORTED_INPUTS_COVERAGE_STATUS = "complete_with_unsupported_inputs"


def _known_uv_source(entry: object) -> bool:
    if not isinstance(entry, Mapping):
        return False
    reason, kind = entry.get("reason"), entry.get("source_type")
    if not (
        reason == "non_registry_source"
        and kind in ("git", "path", "url")
        or reason == "non_public_registry"
        and kind == "registry"
    ):
        return False
    name = entry.get("name", entry.get("package"))
    filename = entry.get("file")
    return (
        isinstance(name, str)
        and len(name) <= 256
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is not None
        and isinstance(filename, str)
        and filename.replace("\\", "/").rsplit("/", 1)[-1] == "uv.lock"
        and type(entry.get("line")) is int
        and entry["line"] > 0
    )


def _zero_count(receipt: Mapping, key: str) -> bool:
    return type(receipt.get(key)) is int and receipt[key] == 0


def valid_non_registry_sca_receipt(coverage: object) -> bool:
    """Coverage remains limited; only inventory and public queries completed."""
    if not isinstance(coverage, Mapping):
        return False
    if (
        coverage.get("status") != NON_REGISTRY_COVERAGE_STATUS
        or coverage.get("complete") is not False
        or coverage.get("category_complete") is not False
        or coverage.get("limit_reasons")
    ):
        return False
    skipped = coverage.get("non_registry_lockfile_dependency_count")
    not_checked = coverage.get("not_checked_lockfile_dependency_count")
    if (
        type(skipped) is not int
        or type(not_checked) is not int
        or not 0 < skipped <= not_checked
    ):
        return False
    for key in ("parse_error_count", "unresolved_lockfile_dependency_count"):
        if not _zero_count(coverage, key):
            return False
    entries = coverage.get("lockfile_not_checked")
    if not isinstance(entries, list) or not 0 < len(entries) <= min(25, not_checked):
        return False
    known = [
        entry
        for entry in entries
        if isinstance(entry, Mapping)
        and entry.get("reason") in ("non_registry_source", "non_public_registry")
    ]
    if not known or len(known) > skipped or not all(map(_known_uv_source, known)):
        return False
    if coverage.get("lockfile_issues"):
        return False
    if "nuget_unresolved_count" in coverage and not _zero_count(
        coverage, "nuget_unresolved_count"
    ):
        return False
    query = coverage.get("query")
    if (
        not isinstance(query, Mapping)
        or query.get("status") != "complete"
        or query.get("complete") is not True
        or query.get("limit_reasons")
    ):
        return False
    requested = query.get("requested_batches")
    if (
        type(requested) is not int
        or requested < 0
        or not _zero_count(query, "failed_batches")
    ):
        return False
    successful = query.get("successful_batches")
    if (requested or "successful_batches" in query) and (
        type(successful) is not int or successful != requested
    ):
        return False
    queried = coverage.get("queried_dependency_count")
    if queried is not None and (
        type(queried) is not int or queried < 0 or bool(queried) != bool(requested)
    ):
        return False
    for key in ("failed_requests", "advisory_context_error_count"):
        if key in query and not _zero_count(query, key):
            return False
    details = query.get("advisory_details")
    if details is not None:
        if (
            not isinstance(details, Mapping)
            or details.get("complete") is not True
            or details.get("status") != "complete"
            or details.get("limit_reasons")
        ):
            return False
        for key in (
            "failed_count",
            "skipped_count",
            "failed_requests",
            "skipped_requests",
        ):
            if key in details and not _zero_count(details, key):
                return False
        if details.get("deadline_exceeded") or details.get("total_size_exceeded"):
            return False
        for key in ("unique_id_count", "requested_count", "successful_count"):
            if key in details and (type(details[key]) is not int or details[key] < 0):
                return False
        if (
            "requested_count" in details
            and "successful_count" in details
            and details["requested_count"] != details["successful_count"]
        ):
            return False
        if (
            "unique_id_count" in details
            and "successful_count" in details
            and details["unique_id_count"] != details["successful_count"]
        ):
            return False
    return True


def _display_dependency_file(path: object) -> str | None:
    from pathlib import Path

    if not isinstance(path, str) or not path or len(path) > 4096:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return None
    raw = Path(path)
    if raw.is_absolute():
        try:
            return raw.resolve().relative_to(Path.cwd().resolve()).as_posix()
        except (OSError, ValueError):
            return raw.name
    return raw.as_posix()


def _grouped_inputs(entries: object, limit: int) -> list[str]:
    """``files (Ecosystem: reason)`` groups, at most ``limit`` file names."""
    if not isinstance(entries, list):
        return []
    groups: dict[tuple[str, str], list[str]] = {}
    shown = 0
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        ecosystem, reason = entry.get("ecosystem"), entry.get("reason")
        label = _display_dependency_file(entry.get("file"))
        if not (isinstance(ecosystem, str) and isinstance(reason, str) and label):
            continue
        files = groups.setdefault((ecosystem, reason), [])
        if shown < limit:
            files.append(label)
            shown += 1
    return [
        f"{', '.join(files) or '…'} ({ecosystem}: {reason})"
        for (ecosystem, reason), files in groups.items()
    ]


def _count(receipt: Mapping, key: str) -> int:
    value = receipt.get(key, 0)
    return value if type(value) is int and value > 0 else 0


def unsupported_inputs_line(receipt: object, *, limit: int = 6) -> str | None:
    """One line naming the dependency files present but not read, or None."""
    if not isinstance(receipt, Mapping):
        return None
    total = _count(receipt, "unsupported_lockfile_count") + _count(
        receipt, "unsupported_manifest_count"
    )
    if not total:
        return None
    groups = _grouped_inputs(receipt.get("unsupported_inputs"), limit)
    if not groups:
        return (
            f"{total} dependency file(s) not read (see sca_coverage.unsupported_inputs)"
        )
    named = min(total, limit)
    more = (
        f"; {total - named} more in sca_coverage.unsupported_inputs"
        if total > named
        else ""
    )
    return "Dependency files not read: " + "; ".join(groups) + more


def skipped_inputs_line(receipt: object, *, limit: int = 4) -> str | None:
    """Dependency files deliberately not read because another file covers them."""
    if not isinstance(receipt, Mapping) or not _count(receipt, "skipped_input_count"):
        return None
    groups = _grouped_inputs(receipt.get("skipped_inputs"), limit)
    return "Dependency files not needed: " + "; ".join(groups) if groups else None
