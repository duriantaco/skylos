from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink


MAX_GO_MANIFEST_BYTES = 512 * 1024


@dataclass(frozen=True)
class GoReplacement:
    import_path: str
    directory: Path


@dataclass(frozen=True)
class GoModule:
    module_path: str
    root: Path
    scan_root: Path
    replacements: tuple[GoReplacement, ...] = ()
    unresolved_replacements: tuple[str, ...] = ()


def go_work_use_paths(text: str) -> list[str]:
    paths: list[str] = []
    in_use_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "use (":
            in_use_block = True
            continue
        if in_use_block and line == ")":
            in_use_block = False
            continue
        if line.startswith("use "):
            paths.append(_unquote(line[4:].strip()))
        elif in_use_block:
            paths.append(_unquote(line.split()[0]))
    return [path for path in paths if path]


def module_from_manifest(scan_root: Path, manifest: Path) -> GoModule | None:
    text = read_text_no_symlink(
        manifest,
        max_bytes=MAX_GO_MANIFEST_BYTES,
        encoding="utf-8",
        errors="replace",
    )
    if text is None:
        return None
    module_path = _module_path(text)
    if not module_path:
        return None
    module_root = manifest.parent.resolve()
    replacements, unresolved_replacements = _local_replacements(
        scan_root,
        module_root,
        text,
    )
    return GoModule(
        module_path=module_path,
        root=module_root,
        scan_root=scan_root,
        replacements=replacements,
        unresolved_replacements=unresolved_replacements,
    )


def _module_path(text: str) -> str | None:
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line.startswith("module "):
            continue
        value = _unquote(line[7:].strip())
        return value.split()[0] if value else None
    return None


def _local_replacements(
    scan_root: Path,
    module_root: Path,
    text: str,
) -> tuple[tuple[GoReplacement, ...], tuple[str, ...]]:
    replacements: list[GoReplacement] = []
    unresolved: set[str] = set()
    for directive in _replace_directives(text):
        left, separator, right = directive.partition("=>")
        if not separator:
            continue
        old_path = left.strip().split()[0]
        target = _unquote(right.strip().split()[0])
        if not target.startswith((".", "/")):
            continue
        directory = Path(target)
        if not directory.is_absolute():
            directory = module_root / directory
        try:
            resolved = directory.resolve(strict=False)
            resolved.relative_to(scan_root)
        except (OSError, ValueError):
            unresolved.add(old_path)
            continue
        replacements.append(GoReplacement(old_path, resolved))
    return tuple(replacements), tuple(sorted(unresolved))


def _replace_directives(text: str) -> list[str]:
    directives: list[str] = []
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if line == "replace (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("replace "):
            directives.append(line[8:].strip())
        elif in_block and line:
            directives.append(line)
    return directives


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] in {'"', "'", "`"} and value[-1] == value[0]:
        return value[1:-1]
    return value
