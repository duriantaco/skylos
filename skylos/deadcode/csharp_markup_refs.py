"""C# names used from Razor, Razor Pages/MVC views and XAML markup.

``.razor``, ``.cshtml`` and ``.xaml`` files are not C# sources, yet they call
component and service methods (``await Basket.CheckoutAsync(info)``), bind
event handlers (``Clicked="OnSaveClicked"``) and name view models
(``@model LoginViewModel``). A name written there keeps the same-named C#
method or type alive. When several types share the name and C# code already
references one of them, the markup is read as naming that one. Markup never
creates a finding.
"""

from __future__ import annotations

import re
from pathlib import Path

from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_project_text_no_symlink

_MARKUP_SUFFIXES = {".razor", ".cshtml", ".xaml", ".axaml"}
_MAX_MARKUP_FILE_BYTES = 512_000
_MAX_MARKUP_FILES = 4_000
_COMMENT_RE = re.compile(r"<!--.*?-->|@\*.*?\*@", re.DOTALL)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")


def collect_csharp_markup_names(
    project_root, source_files, *, exclude_folders=None
) -> set[str]:
    root = Path(project_root).resolve()
    if not root.is_dir():
        return set()
    if not any(Path(path).suffix.lower() == ".cs" for path in source_files):
        return set()
    markup_files = discover_source_files(
        root, _MARKUP_SUFFIXES, exclude_folders=exclude_folders
    )
    names: set[str] = set()
    for path in list(markup_files)[:_MAX_MARKUP_FILES]:
        source = read_project_text_no_symlink(
            root,
            Path(path),
            max_bytes=_MAX_MARKUP_FILE_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
        if source is None:
            continue
        names.update(_IDENTIFIER_RE.findall(_COMMENT_RE.sub(" ", source)))
    return names


def credit_csharp_markup_names(
    definitions, project_root, source_files, *, exclude_folders=None
) -> None:
    names = collect_csharp_markup_names(
        project_root, source_files, exclude_folders=exclude_folders
    )
    if not names:
        return
    types_by_name: dict[str, list] = {}
    named = []
    for definition in definitions:
        if Path(definition.filename).suffix.lower() != ".cs":
            continue
        if definition.type not in {"method", "class"}:
            continue
        if definition.simple_name not in names:
            continue
        named.append(definition)
        if definition.type == "class":
            types_by_name.setdefault(definition.simple_name, []).append(definition)
    for definition in named:
        if definition.type == "class" and _has_referenced_namesake(
            types_by_name[definition.simple_name]
        ):
            continue
        definition.references += 1
        definition.heuristic_refs["csharp_markup_reference"] = 1.0


def _has_referenced_namesake(candidates) -> bool:
    if len(candidates) < 2:
        return False
    for candidate in candidates:
        seeded = 0
        if candidate.is_exported:
            seeded = 1
        if candidate.references > seeded:
            return True
    return False
