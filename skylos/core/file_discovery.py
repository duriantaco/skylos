from __future__ import annotations

import os
import subprocess
from fnmatch import fnmatchcase
from collections.abc import Iterable, Sequence
from pathlib import Path


def _normalize_path_text(value: str) -> str:
    return value.replace("\\", "/").rstrip("/")


def _normalized_parts(value: str) -> tuple[str, ...]:
    return tuple(part for part in value.split("/") if part and part != ".")


def _dedupe_candidates(candidates: list[str]) -> list[str]:
    seen = set()
    deduped = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            deduped.append(candidate)
    return deduped


def _absolute_exclude_candidate(exclude_folder: str, root_path: Path) -> str | None:
    exclude_path = Path(exclude_folder)
    if not exclude_path.is_absolute():
        return None

    try:
        rel = exclude_path.resolve(strict=False).relative_to(
            root_path.resolve(strict=False)
        )
    except (OSError, ValueError):
        return None

    return _normalize_path_text(str(rel))


def _root_prefixed_exclude_candidate(exclude_normalized: str, root_path: Path) -> str | None:
    if "/" not in exclude_normalized:
        return None

    exclude_parts = _normalized_parts(exclude_normalized)
    root_parts = tuple(
        part
        for part in root_path.resolve(strict=False).parts
        if part not in {"", os.sep}
    )
    max_prefix = min(len(exclude_parts), len(root_parts))
    for prefix_size in range(max_prefix, 0, -1):
        if exclude_parts[:prefix_size] == root_parts[-prefix_size:]:
            return "/".join(exclude_parts[prefix_size:]) or None
    return None


def _exclude_candidates(exclude_folder: str, root_path: Path) -> list[str]:
    exclude_normalized = _normalize_path_text(exclude_folder)
    candidates = [exclude_normalized]

    if "*" not in exclude_normalized:
        absolute_candidate = _absolute_exclude_candidate(exclude_folder, root_path)
        prefixed_candidate = _root_prefixed_exclude_candidate(
            exclude_normalized, root_path
        )
        if absolute_candidate:
            candidates.append(absolute_candidate)
        if prefixed_candidate:
            candidates.append(prefixed_candidate)

    return _dedupe_candidates(candidates)


def _glob_patterns(exclude_normalized: str) -> set[str]:
    patterns = {exclude_normalized}
    if exclude_normalized.startswith("**/"):
        patterns.add(exclude_normalized[3:])
    if exclude_normalized.endswith("/**"):
        patterns.add(exclude_normalized[:-3])
    if exclude_normalized.startswith("**/") and exclude_normalized.endswith("/**"):
        patterns.add(exclude_normalized[3:-3])
    return patterns


def _matches_glob_exclude(
    rel_path_str: str, path_parts: tuple[str, ...], exclude_normalized: str
) -> bool:
    for pattern in _glob_patterns(exclude_normalized):
        if rel_path_str == pattern or fnmatchcase(rel_path_str, pattern):
            return True
        if pattern.endswith("/**"):
            directory = pattern[:-3]
            if rel_path_str == directory or rel_path_str.startswith(directory + "/"):
                return True

    suffix = exclude_normalized.replace("*", "")
    return any(part.endswith(suffix) for part in path_parts)


def _matches_nested_exclude(rel_path_str: str, exclude_normalized: str) -> bool:
    if rel_path_str == exclude_normalized:
        return True
    if rel_path_str.startswith(exclude_normalized + "/"):
        return True
    check = "/" + rel_path_str + "/"
    return "/" + exclude_normalized + "/" in check


def _path_matches_exclude(
    rel_path_str: str, path_parts: tuple[str, ...], exclude_normalized: str
) -> bool:
    if "*" in exclude_normalized:
        return _matches_glob_exclude(rel_path_str, path_parts, exclude_normalized)

    if "/" in exclude_normalized:
        return _matches_nested_exclude(rel_path_str, exclude_normalized)

    return exclude_normalized in path_parts


def should_exclude_path(
    file_path: Path,
    root_path: Path,
    exclude_folders: Sequence[str] | None,
) -> bool:
    if not exclude_folders:
        return False

    try:
        rel_path = file_path.relative_to(root_path)
    except ValueError:
        return False

    path_parts = rel_path.parts
    rel_path_str = str(rel_path).replace("\\", "/")

    for exclude_folder in exclude_folders:
        for exclude_normalized in _exclude_candidates(exclude_folder, root_path):
            if _path_matches_exclude(rel_path_str, path_parts, exclude_normalized):
                return True

    return False


def should_include_path(
    file_path: Path,
    root_path: Path,
    include_folders: Sequence[str] | None,
) -> bool:
    return should_exclude_path(file_path, root_path, include_folders)


def find_git_root(path: str | Path) -> Path | None:
    try:
        current = Path(path).resolve()
    except Exception:
        return None

    if current.is_file():
        current = current.parent

    while True:
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


def list_git_visible_files(path: str | Path) -> list[Path] | None:
    root = find_git_root(path)
    if root is None:
        return None

    target = Path(path).resolve()
    if target.is_file():
        target = target.parent

    cmd = [
        "git",
        "-C",
        str(root),
        "ls-files",
        "-co",
        "--exclude-standard",
        "--full-name",
    ]

    if target != root:
        try:
            rel_target = target.relative_to(root)
        except ValueError:
            return None
        cmd.extend(["--", str(rel_target).replace("\\", "/")])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None

    if result.returncode != 0:
        return None

    files = []
    for line in result.stdout.splitlines():
        rel_path = line.strip()
        if not rel_path:
            continue
        files.append(root / rel_path)

    files.sort()
    return files


def _resolve_contained_source_file(file_path: Path, root_path: Path) -> Path | None:
    if file_path.is_symlink():
        return None
    try:
        resolved = file_path.resolve(strict=True)
        resolved.relative_to(root_path)
    except (OSError, ValueError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def discover_source_files(
    path: str | Path,
    extensions: Iterable[str],
    exclude_folders: Sequence[str] | None = None,
    include_folders: Sequence[str] | None = None,
    respect_gitignore: bool = True,
) -> list[Path]:
    raw_target = Path(path)
    try:
        target = raw_target.resolve(strict=True)
    except OSError:
        return []
    ext_set = {
        ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in extensions
    }

    if raw_target.is_file():
        if should_exclude_path(target, target.parent, exclude_folders):
            return []
        if target.suffix.lower() in ext_set:
            contained = _resolve_contained_source_file(raw_target, target.parent)
            return [contained] if contained is not None else []
        return []

    if respect_gitignore:
        git_files = list_git_visible_files(target)
        if git_files is not None:
            forced_includes = _collect_forced_included_files(
                target, ext_set, include_folders
            )
            files = []
            seen = set()
            for file_path in [*git_files, *forced_includes]:
                if file_path.suffix.lower() not in ext_set:
                    continue
                resolved = _resolve_contained_source_file(file_path, target)
                if resolved is None:
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                if should_include_path(file_path, target, include_folders):
                    files.append(resolved)
                    continue
                if should_exclude_path(file_path, target, exclude_folders):
                    continue
                files.append(resolved)
            files.sort()
            return files

    files: list[Path] = []
    try:
        for dirpath, dirnames, filenames in os.walk(target):
            base = Path(dirpath)
            pruned = []
            for dirname in list(dirnames):
                dir_path = base / dirname
                if should_exclude_path(dir_path, target, exclude_folders):
                    pruned.append(dirname)
            for dirname in pruned:
                try:
                    dirnames.remove(dirname)
                except ValueError:
                    pass

            if include_folders:
                keep = []
                for dirname in list(dirnames):
                    dir_path = base / dirname
                    if should_include_path(dir_path, target, include_folders):
                        keep.append(dirname)
                for dirname in keep:
                    if dirname in pruned:
                        try:
                            dirnames.append(dirname)
                        except Exception:
                            pass

            for filename in filenames:
                file_path = base / filename
                if file_path.suffix.lower() not in ext_set:
                    continue
                resolved = _resolve_contained_source_file(file_path, target)
                if resolved is None:
                    continue
                if should_include_path(file_path, target, include_folders):
                    files.append(resolved)
                    continue
                if should_exclude_path(file_path, target, exclude_folders):
                    continue
                files.append(resolved)
    except (OSError, PermissionError, TypeError):
        for ext in ext_set:
            for file_path in target.glob(f"**/*{ext}"):
                resolved = _resolve_contained_source_file(file_path, target)
                if resolved is not None:
                    files.append(resolved)

    files.sort()
    return files


def _collect_forced_included_files(
    target: Path,
    extensions: set[str],
    include_folders: Sequence[str] | None,
) -> list[Path]:
    if not include_folders:
        return []

    files = []
    seen = set()
    for pattern in include_folders:
        for match in _iter_include_matches(target, pattern):
            if match.is_symlink():
                continue
            try:
                resolved = match.resolve()
                resolved.relative_to(target)
            except OSError:
                continue
            except ValueError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            if match.is_dir():
                for file_path in match.rglob("*"):
                    if file_path.suffix.lower() not in extensions:
                        continue
                    contained = _resolve_contained_source_file(file_path, target)
                    if contained is None:
                        continue
                    files.append(contained)
            elif match.is_file() and match.suffix.lower() in extensions:
                contained = _resolve_contained_source_file(match, target)
                if contained is not None:
                    files.append(contained)
    return files


def _iter_include_matches(target: Path, pattern: str):
    normalized = pattern.replace("\\", "/").rstrip("/")
    if not normalized:
        return

    has_glob = any(char in normalized for char in "*?[")
    direct_candidates = []

    if "/" in normalized and not has_glob:
        direct_candidates.append(target / normalized)
        parts = normalized.split("/")
        if parts and parts[0] == target.name and len(parts) > 1:
            direct_candidates.append(target / "/".join(parts[1:]))

    for candidate in direct_candidates:
        if candidate.exists():
            yield candidate

    if direct_candidates:
        return

    if has_glob:
        pattern_expr = normalized
        if "/" not in pattern_expr:
            pattern_expr = f"**/{pattern_expr}"
        yield from target.glob(pattern_expr)
        return

    yield from target.rglob(normalized)
