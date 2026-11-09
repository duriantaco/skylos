"""Shared, data-only inventory contract for supported dependency lockfiles."""

from __future__ import annotations

from dataclasses import dataclass, field


NON_REGISTRY_REASONS = frozenset({"non_registry_source", "non_public_registry"})
_RECEIPT_SOURCE_KINDS = {
    "external": "url",
    "non_registry": "url",
    "file": "path",
    "legacy": "registry",
}


def not_checked_source(problem: dict, reason: str, source_type: str) -> dict:
    """A correctly read entry whose source has no public advisory identity."""
    if source_type == "local":
        return dict(problem, reason="local_package", source_type="local")
    kind = _RECEIPT_SOURCE_KINDS.get(source_type, source_type)
    if reason == "non_public_registry":
        kind = "registry"
    return dict(problem, reason=reason, source_type=kind)


class LockfileParseError(ValueError):
    """A lockfile cannot be interpreted as a supported inventory."""


class LockfileLimitError(LockfileParseError):
    """A lockfile exceeds the configured inventory bound."""


@dataclass
class LockfileInventory:
    """All recorded environments, not a claim about an installed environment.

    Dependencies use the existing SCA name/version/ecosystem/file/line shape.
    Local workspace packages are counted separately and never queried as public
    registry packages. Unsupported external entries remain explicit problems;
    known non-operational coverage gaps remain explicit limitations.

    ``not_checked`` lists entries that were read correctly but are the
    project's own local code, with no public registry identity to check
    (``link:``/``file:`` directories, local tarballs, workspace packages).
    They are reported and never queried. Known, validated non-registry entries
    may also appear here with ``non_registry_source`` or ``non_public_registry``
    reasons: processing succeeded, but their advisory coverage is incomplete.
    Malformed or unsupported source metadata stays in ``unresolved``.

    ``source_records`` describe Git and URL entries (see
    ``skylos.rules.sca.package_sources.source_record``) for the mutable-source
    check; they never become advisory queries. Their URLs are already
    stripped of credentials and are left out of the repr.
    """

    format_version: int
    dependencies: list[dict] = field(default_factory=list)
    package_count: int = 0
    local_package_count: int = 0
    non_registry_names: list[str] = field(default_factory=list)
    workspace_paths: list[str] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)
    limitations: list[dict] = field(default_factory=list)
    not_checked: list[dict] = field(default_factory=list)
    source_records: list[dict] = field(default_factory=list, repr=False)
