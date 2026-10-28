"""Bounded source proof for package.json export patterns; never runs a build."""

from __future__ import annotations

import os
from pathlib import Path
import re

from .resolve import _package_target_variants, _resolve_extends_path
from .safe_glob import MAX_TYPESCRIPT_GLOB_MATCHES, safe_glob_paths
from .workspace import _load_jsonc

_SOURCE_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
_MAX_PATTERNS = 64
_MAX_EXPORT_KEYS = 128


def _target_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict) and not any(key.startswith(".") for key in value):
        for condition, target in value.items():
            yield from _target_strings(target)
            # Later conditions cannot follow an unconditional default arm.
            if condition == "default":
                break
    # Array fallback and malformed mixed maps are not publication proofs.


def _safe_relative(value):
    return (
        isinstance(value, str)
        and value.startswith("./")
        and "\\" not in value
        and not any(char in value for char in "?[]{}%")
        and not any(
            part in {".", "..", "node_modules"} for part in value.split("/")[1:]
        )
    )


def _inside(path, root):
    return Path(path).resolve().is_relative_to(root)


def _config(path, root, seen=None):
    seen = set() if seen is None else seen
    path = Path(path).resolve()
    if path in seen or len(seen) >= 8 or not path.is_relative_to(root):
        return None
    seen.add(path)
    data = _load_jsonc(path)
    if not data:
        return None
    inherited = ({}, {})
    if "extends" in data:
        parent = data["extends"]
        if not isinstance(parent, str):
            return None
        parent_path = _resolve_extends_path(str(path.parent), parent)
        if parent_path is None:
            return None
        inherited = _config(parent_path, root, seen)
        if inherited is None:
            return None
    options, selection = inherited
    options, selection = dict(options), dict(selection)
    own_options = data.get("compilerOptions", {})
    if not isinstance(own_options, dict):
        return None
    for key, value in own_options.items():
        if key in {"rootDir", "outDir", "declarationDir"}:
            if not isinstance(value, str):
                return None
            if "${" in value:
                options[key] = value
                continue
            value = (path.parent / value).resolve()
            if not value.is_relative_to(root):
                return None
        options[key] = value
    for key in ["include", "exclude", "files"]:
        if key in data:
            if not isinstance(data[key], list) or any(
                not isinstance(value, str) for value in data[key]
            ):
                return None
            selection[key] = [
                os.path.normpath(str(path.parent / value)) for value in data[key]
            ]
    return options, selection


def _glob_matches(path, pattern):
    # TypeScript **/ includes zero directory segments, unlike Path.match.
    escaped = re.escape(pattern.replace(os.sep, "/"))
    regex = (
        escaped.replace(r"\*\*/", "(?:.*/)?")
        .replace(r"\*\*", ".*")
        .replace(r"\*", "[^/]*")
        .replace(r"\?", "[^/]")
    )
    return re.fullmatch(regex, str(path).replace(os.sep, "/")) is not None


def _selected_source(path, selection):
    if any(
        part in {"node_modules", "bower_components", "jspm_packages"}
        for part in path.parts
    ):
        return False
    if any(
        _glob_matches(path, pattern) or str(path).startswith(pattern.rstrip("/") + "/")
        for pattern in selection.get("exclude", [])
    ):
        return False
    includes = selection.get("include")
    files = selection.get("files", [])
    if str(path) in files:
        return True
    if includes is not None:
        return any(_glob_matches(path, pattern) for pattern in includes)
    return "files" not in selection


def _owned_source(path, root):
    current = path.parent
    while current != root:
        if not current.is_relative_to(root) or (current / "package.json").is_file():
            return False
        current = current.parent
    return True


def _emitted_suffix(path, declaration, options):
    if declaration:
        return {
            ".ts": ".d.ts",
            ".tsx": ".d.ts",
            ".mts": ".d.mts",
            ".cts": ".d.cts",
        }.get(path.suffix)
    if options.get("emitDeclarationOnly") is True:
        return None
    if path.suffix == ".tsx" and options.get("jsx") in {"preserve", "react-native"}:
        return ".jsx"
    return {".ts": ".js", ".tsx": ".js", ".mts": ".mjs", ".cts": ".cjs"}.get(
        path.suffix
    )


def _pattern_capture(pattern, value):
    if pattern.count("*") != 1:
        return None
    before, after = pattern.split("*")
    if not value.startswith(before) or not value.endswith(after):
        return None
    end = len(value) - len(after) if after else len(value)
    capture = value[len(before) : end]
    return (
        capture
        if capture
        and "%" not in capture
        and not any(part in {".", "..", "node_modules"} for part in capture.split("/"))
        else None
    )


def _selected_key(exports, key, subpath):
    if subpath in exports:
        return key == subpath
    patterns = [
        candidate
        for candidate in exports
        if _pattern_capture(candidate, subpath) is not None
    ]
    if not patterns:
        return False
    winner = max(
        patterns, key=lambda candidate: (len(candidate.split("*")[0]), len(candidate))
    )
    return key == winner


def package_export_pattern_files(package_root, exports):
    """Return only declared, owned wildcard-interface sources with emit proof."""
    if (
        not isinstance(exports, dict)
        or len(exports) > _MAX_EXPORT_KEYS
        or any(not key.startswith(".") for key in exports)
    ):
        return set()
    root = Path(package_root).resolve()
    layouts = []
    for name in ["tsconfig.json", "tsconfig.build.json"]:
        config = _config(root / name, root)
        if (
            config is not None
            and isinstance(config[0].get("rootDir"), Path)
            and config[0].get("noEmit") is not True
            and "outFile" not in config[0]
        ):
            layouts.append(config)
    cache, result = {}, set()

    def sources(directory):
        directory = Path(directory)
        if directory not in cache:
            matches = safe_glob_paths(
                str(root),
                str(directory / "**/*"),
                allowed_suffixes=_SOURCE_SUFFIXES,
                max_matches=MAX_TYPESCRIPT_GLOB_MATCHES + 1,
            )
            cache[directory] = (
                []
                if len(matches) > MAX_TYPESCRIPT_GLOB_MATCHES
                else sorted(set(matches))
            )
        return cache[directory]

    for key in list(exports)[:_MAX_PATTERNS]:
        if not _safe_relative(key) or key.count("*") != 1:
            continue
        for target in list(_target_strings(exports[key]))[:_MAX_PATTERNS]:
            if not _safe_relative(target) or target.count("*") != 1:
                continue
            candidates = []
            direct = root / target
            prefix = str(direct).split("*")[0]
            directory = Path(prefix).parent
            if _inside(directory, root):
                candidates.extend(
                    (Path(path), "./" + Path(path).relative_to(root).as_posix())
                    for path in sources(directory)
                    if _pattern_capture(
                        target, "./" + Path(path).relative_to(root).as_posix()
                    )
                    is not None
                )
            for options, selection in layouts:
                declaration = target.endswith((".d.ts", ".d.mts", ".d.cts"))
                output = (
                    options.get("declarationDir", options.get("outDir"))
                    if declaration
                    else options.get("outDir")
                )
                if not isinstance(output, Path) or (
                    declaration
                    and options.get("declaration") is not True
                    and options.get("emitDeclarationOnly") is not True
                ):
                    continue
                for name in sources(options["rootDir"]):
                    source = Path(name)
                    if not _selected_source(source, selection):
                        continue
                    suffix = _emitted_suffix(source, declaration, options)
                    if suffix is None:
                        continue
                    relative = source.relative_to(options["rootDir"]).with_suffix(
                        suffix
                    )
                    emitted = "./" + (output / relative).relative_to(root).as_posix()
                    # Existing extension mappings remain the supported source families.
                    variants = _package_target_variants(str(source.with_suffix(suffix)))
                    if (
                        str(source) in variants
                        and _pattern_capture(target, emitted) is not None
                    ):
                        candidates.append((source, emitted))
            for source, emitted in candidates:
                if (
                    not _inside(source, root)
                    or source.is_symlink()
                    or not _owned_source(source, root)
                ):
                    continue
                captured = _pattern_capture(target, emitted)
                if captured is not None and _selected_key(
                    exports, key, key.replace("*", captured)
                ):
                    result.add(str(source.resolve()))
    return result
