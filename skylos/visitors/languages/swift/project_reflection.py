"""Bounded positive reflection evidence across admitted Swift source files."""

from __future__ import annotations

import hashlib
from pathlib import Path

from skylos.analysis.errors import analysis_error_payload
from skylos.core.safe_cache_io import read_text_no_symlink

MAX_PROJECT_REFLECTION_FILES = 512
MAX_PROJECT_REFLECTION_BYTES = 8_000_000
MAX_SOURCE_BYTES = 2_000_000
MAX_PROJECT_REFLECTION_FACTS = 200_000
MAX_SOURCE_UNIT_ENTRIES = 1_024


def _flat_source_unit(root, source_directories):
    """Recognize only the default flat source unit, without build inference.

    SwiftPM/Xcode targets or directory partitions may own unrelated same-named
    declarations. Those contexts retain possible standard-library reflection.
    """
    if any(directory != root for directory in source_directories):
        return False
    try:
        for index, child in enumerate(root.iterdir()):
            if index >= MAX_SOURCE_UNIT_ENTRIES:
                return False
            if child.name == "Package.swift" or child.suffix in {
                ".xcodeproj",
                ".xcworkspace",
            }:
                return False
    except OSError:
        return False
    return True


def apply_project_reflection(definitions, facts_by_file, *, scan_root):
    """Credit exact stored properties observed by reachable standard reflection.

    Facts travel in the existing worker visitor. Source identity and containment
    are checked atomically before any reference changes. Returns analysis errors
    if those proofs cannot be checked, never a clean skipped verification.
    """
    if not any(facts.get("requests") for facts in facts_by_file.values()):
        return []
    errors = []
    verified = {}
    source_directories = set()
    try:
        root = Path(scan_root).resolve(strict=True)
        if root.is_file():
            root = root.parent
        if len(facts_by_file) > MAX_PROJECT_REFLECTION_FILES:
            raise ValueError("Swift project reflection file limit exceeded")
        total = 0
        fact_count = 0
        for filename, facts in facts_by_file.items():
            if facts.get("proof_version") != 2 or any(
                not {"base_reachable", "base_signals", "core_signals"} <= item.keys()
                for item in facts.get("properties", ())
            ):
                raise ValueError(
                    "Swift reflection provenance is stale; source analysis must be refreshed"
                )
            fact_count += sum(
                len(facts.get(key, ())) for key in ("requests", "properties", "types")
            )
            if fact_count > MAX_PROJECT_REFLECTION_FACTS:
                raise ValueError("Swift project reflection fact limit exceeded")
            path = Path(filename)
            if path.is_symlink():
                raise ValueError("Swift reflection source became a symlink")
            canonical = path.resolve(strict=True)
            source_directories.add(canonical.parent)
            relative = canonical.relative_to(root)
            contained = root / relative
            source = read_text_no_symlink(
                contained,
                max_bytes=MAX_SOURCE_BYTES,
                encoding="utf-8",
                errors="strict",
                newline="",
            )
            if source is None:
                raise ValueError("Swift reflection source is unreadable or over limit")
            data = source.encode("utf-8")
            total += len(data)
            if total > MAX_PROJECT_REFLECTION_BYTES:
                raise ValueError("Swift project reflection byte limit exceeded")
            if hashlib.sha256(data).hexdigest() != facts.get("source_sha256"):
                raise ValueError("Swift reflection source changed after parsing")
            verified[str(filename)] = facts
    except (OSError, ValueError, UnicodeError) as error:
        errors.append(
            analysis_error_payload(
                str(scan_root), error, kind="swift_reflection_context_error"
            )
        )
        return errors
    same_source_unit = _flat_source_unit(root, source_directories)
    by_identity = {}
    for definition in definitions.values():
        if Path(definition.filename).suffix.lower() == ".swift":
            by_identity[
                (
                    str(definition.filename),
                    definition.name,
                    definition.line,
                    definition.type,
                )
            ] = definition
    visible_types = {}
    shadow_types = set()
    for filename, facts in verified.items():
        for type_info in facts.get("types", ()):
            if not type_info["private"]:
                visible_types.setdefault(type_info["name"], []).append(filename)
                if "." not in type_info["name"]:
                    shadow_types.add(type_info["name"])
    properties = []
    properties_by_owner = {}
    for filename, facts in verified.items():
        for item in facts.get("properties", ()):
            identity = (filename, item["name"], item["line"], "variable")
            definition = by_identity.get(identity)
            if definition is not None:
                properties.append((filename, item, definition))
                if item.get("owner_reachable"):
                    properties_by_owner.setdefault(
                        (filename, item["owner"]), []
                    ).append(definition)
    evidence = set()
    checked_targets = set()
    all_properties_covered = False
    for source_file, facts in verified.items():
        for request in facts.get("requests", ()):
            if (
                same_source_unit
                and not request.get("qualified")
                and request.get("provider") in shadow_types
            ):
                # A project nominal declaration resolves an unqualified type
                # name before the implicit standard-library provider.
                continue
            if (
                same_source_unit
                and request.get("qualified")
                and "Swift" in shadow_types
            ):
                continue
            owner = request.get("owner")
            owner_file = request.get("owner_file")
            if owner is not None:
                targets = (
                    [owner_file]
                    if owner_file is not None
                    else visible_types.get(owner, [])
                )
                if not targets:
                    continue
            else:
                targets = None
            if owner is None:
                evidence.update(
                    definition
                    for _, item, definition in properties
                    if item.get("owner_reachable")
                )
                all_properties_covered = True
                break
            for target in targets:
                identity = (target, owner)
                if identity not in checked_targets:
                    checked_targets.add(identity)
                    evidence.update(properties_by_owner.get(identity, ()))
        if all_properties_covered:
            break
    # Local Core cannot see a provider declared in another file. Remove only
    # its provisional reflection contribution, preserving ordinary reachable
    # reads, runtime roots and evidence supplied outside this Core snapshot.
    for _, item, definition in properties:
        definition.references = int(item["base_reachable"])
        core_signals = set(item["core_signals"])
        definition.framework_signals = [
            s for s in definition.framework_signals if s not in core_signals
        ]
        for signal in item["base_signals"]:
            if signal not in definition.framework_signals:
                definition.framework_signals.append(signal)
    for definition in evidence:
        definition.references = max(definition.references, 1)
        reason = "source-visible project reflection may observe stored property"
        if reason not in definition.framework_signals:
            definition.framework_signals.append(reason)
    return errors


__all__ = ["apply_project_reflection"]
