"""Conservative public-symbol candidates for complete C# application scans.

Library public APIs remain exported.  A complete executable application is a
different boundary: a public declaration with no local references can be a
useful dead-code candidate, but only after retaining known dynamic entrypoints.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from pathlib import Path
from xml.etree import ElementTree

from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_project_text_no_symlink

_MAX_METADATA_BYTES = 512_000
_MAX_CONFIG_FILES = 256
_PUBLIC_APP_CONFIDENCE = 60
_DYNAMIC_BASES = {"Controller", "ControllerBase", "PageModel", "BackgroundService"}
_UNSAFE_XML_DECLARATION_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)


def demote_application_public_symbols(
    definitions,
    project_root: str | Path,
    source_files,
    *,
    analysis_scope: dict,
    analysis_errors,
    exclude_folders=None,
) -> None:
    """Reconsider synthetic public references only for complete app projects."""
    if (
        analysis_errors
        or analysis_scope.get("kind")
        not in {"repository_root", "repository_root_with_exclusions"}
        or not set(analysis_scope.get("excluded_folders", ())).issubset(
            DEFAULT_EXCLUDE_FOLDERS
        )
    ):
        return

    root = Path(project_root).resolve()
    csharp_files = [path for path in source_files if Path(path).suffix.lower() == ".cs"]
    if not csharp_files:
        return

    projects = _projects_by_directory(root, exclude_folders=exclude_folders)
    if not projects:
        return

    grouped: dict[Path, list] = defaultdict(list)
    for definition in definitions:
        if Path(definition.filename).suffix.lower() != ".cs":
            continue
        owner = _owning_project(Path(definition.filename), projects)
        if owner is not None and projects[owner] == "application":
            grouped[owner].append(definition)

    for project_file, project_definitions in grouped.items():
        config_type_names = _configured_type_names(
            root, project_file, projects, exclude_folders=exclude_folders
        )
        if config_type_names is None:
            continue
        _demote_project_symbols(project_definitions, config_type_names)


def _projects_by_directory(root: Path, *, exclude_folders=None) -> dict[Path, str]:
    project_files = discover_source_files(
        root, {".csproj"}, exclude_folders=exclude_folders
    )
    projects: dict[Path, str] = {}
    for project_file in project_files:
        kind = _project_kind(root, project_file)
        if kind is not None:
            projects[project_file] = kind
    return projects


def _project_kind(root: Path, path: Path) -> str | None:
    source = read_project_text_no_symlink(
        root, path, max_bytes=_MAX_METADATA_BYTES, encoding="utf-8"
    )
    if source is None or _UNSAFE_XML_DECLARATION_RE.search(source):
        return None
    try:
        project = ElementTree.fromstring(source)
    except ElementTree.ParseError:
        return None
    if project.tag.rsplit("}", 1)[-1] != "Project":
        return None
    if any(key.rsplit("}", 1)[-1] == "Condition" for key in project.attrib):
        return None

    output_types: set[str] = set()
    sdk_names = [project.get("Sdk", "")]
    pending = [(project, "", False)]
    while pending:
        element, parent_name, inherited_condition = pending.pop()
        name = element.tag.rsplit("}", 1)[-1]
        conditional = (
            inherited_condition
            or any(key.rsplit("}", 1)[-1] == "Condition" for key in element.attrib)
            or name in {"Choose", "When", "Otherwise"}
        )
        if name in {"OutputType", "Sdk"} and conditional:
            return None
        if name == "OutputType" and parent_name == "PropertyGroup":
            output_types.add((element.text or "").strip().lower())
        elif name == "Sdk" and parent_name == "Project":
            sdk_names.append(element.get("Name", ""))
        pending.extend((child, name, conditional) for child in element)

    if output_types:
        if output_types <= {"exe", "winexe"}:
            return "application"
        if output_types != {"library"}:
            return None
        return "library"

    if any(
        sdk.strip().split("/")[0].lower() == "microsoft.net.sdk.web"
        for value in sdk_names
        for sdk in value.split(";")
    ):
        return "application"
    return "library"


def _owning_project(path: Path, projects: dict[Path, str]) -> Path | None:
    path = path.resolve()
    candidates = [project for project in projects if project.parent in path.parents]
    if not candidates:
        return None
    deepest = max(len(project.parent.parts) for project in candidates)
    nearest = [
        project for project in candidates if len(project.parent.parts) == deepest
    ]
    return nearest[0] if len(nearest) == 1 else None


def _configured_type_names(
    root: Path, project_file: Path, projects: dict[Path, str], *, exclude_folders=None
) -> set[str] | None:
    config_files = [
        path
        for path in discover_source_files(
            project_file.parent, {".json"}, exclude_folders=exclude_folders
        )
        if _owning_project(path, projects) == project_file
    ]
    if len(config_files) > _MAX_CONFIG_FILES:
        return None

    names: set[str] = set()
    for path in config_files:
        source = read_project_text_no_symlink(
            root, path, max_bytes=_MAX_METADATA_BYTES, encoding="utf-8"
        )
        if source is None:
            # An unreadable configuration may contain dynamic type references.
            return None
        try:
            document = json.loads(source)
        except (ValueError, RecursionError):
            continue
        pending = [document]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, str):
                type_name = value.split(",", 1)[0].strip()
                if "." in type_name:
                    names.add(type_name)
    return names


def _demote_project_symbols(definitions, config_type_names: set[str]) -> None:
    types = {
        definition.name: definition
        for definition in definitions
        if definition.type == "class"
    }
    extension_owners: set[str] = set()
    for definition in definitions:
        if getattr(definition, "csharp_is_extension", False):
            extension_owners.add(definition.name.rsplit(".", 1)[0])

    protected_types = {
        name
        for name, definition in types.items()
        if name in config_type_names
        or name in extension_owners
        or getattr(definition, "csharp_has_attributes", False)
        or "partial" in getattr(definition, "csharp_modifiers", ())
        or _has_unknown_base(definition, types)
        or any(
            base.rsplit(".", 1)[-1] in _DYNAMIC_BASES
            for base in getattr(definition, "csharp_base_types", ())
        )
    }
    children_by_base: dict[str, set[str]] = defaultdict(set)
    for name, definition in types.items():
        for base in getattr(definition, "csharp_base_types", ()):
            parent = _resolve_base_type(definition, base, types)
            if parent is not None:
                children_by_base[parent.name].add(name)

    queue = deque(protected_types)
    while queue:
        for child in children_by_base.get(queue.popleft(), ()):
            if child not in protected_types:
                protected_types.add(child)
                queue.append(child)

    for definition in definitions:
        if not definition.is_exported or definition.type not in {"class", "method"}:
            continue
        if "public" not in getattr(definition, "csharp_modifiers", ()):
            continue
        if definition.type == "class":
            if definition.name in protected_types or _has_unknown_base(
                definition, types
            ):
                continue
        else:
            owner_name = definition.name.rsplit(".", 1)[0]
            owner = types.get(owner_name)
            if (
                owner is None
                or owner_name in protected_types
                or getattr(definition, "csharp_has_attributes", False)
                or getattr(definition, "csharp_is_extension", False)
                or getattr(definition, "csharp_modifiers", frozenset())
                & {"override", "abstract", "virtual", "extern"}
                or (
                    definition.simple_name == "Main"
                    and "static" in definition.csharp_modifiers
                )
                or _has_unknown_base(owner, types)
                or _implements_interface_method(definition, owner, types)
            ):
                continue

        # scan_symbols seeds one reference solely for C# public visibility.
        # Keep any real references added by the cross-file resolver.
        definition.references = max(0, definition.references - 1)
        definition.is_exported = False
        definition.confidence = min(definition.confidence, _PUBLIC_APP_CONFIDENCE)
        definition.why_unused.append(
            "no local references in a complete C# application project scan"
        )


def _resolve_base_type(definition, base: str, types: dict[str, object]):
    namespace, _, _ = definition.name.rpartition(".")
    qualified = f"{namespace}.{base}" if namespace else base
    if "." not in base and qualified in types:
        return types[qualified]
    return types.get(base) or types.get(qualified)


def _has_unknown_base(definition, types: dict[str, object]) -> bool:
    for base in getattr(definition, "csharp_base_types", ()):
        if _resolve_base_type(definition, base, types) is None:
            return True
    return False


def _implements_interface_method(definition, owner, types) -> bool:
    for base in getattr(owner, "csharp_base_types", ()):
        interface = _resolve_base_type(owner, base, types)
        if interface is not None and (
            getattr(interface, "csharp_type_kind", None) == "interface"
            and definition.simple_name in interface.csharp_interface_methods
        ):
            return True
    return False
