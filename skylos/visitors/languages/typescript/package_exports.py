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
        if _is_types_only(exports[key]):
            # Declarations only: the modules' types are public, their values
            # are not importable (see ``types_only_pattern_files``).
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


_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
_TYPE_CONDITIONS = frozenset({"types", "typings"})


def _capturing_targets(value, condition=None):
    """``(condition, target)`` for every target with one ``*`` capture."""
    if isinstance(value, str):
        if value.count("*") == 1:
            yield condition, value
    elif isinstance(value, dict):
        for key, target in value.items():
            if isinstance(key, str) and not key.startswith("."):
                yield from _capturing_targets(target, key if condition is None else condition)
    elif isinstance(value, list):
        for item in value:
            yield from _capturing_targets(item, condition)


def _is_types_only(value):
    targets = list(_capturing_targets(value))
    return bool(targets) and all(
        condition in _TYPE_CONDITIONS or target.endswith(_DECLARATION_SUFFIXES)
        for condition, target in targets
    )


def _types_only_targets(exports):
    """Declaration targets of wildcard keys that expose types, not values.

    ``"./*": {"types": "./dist/types/*.d.ts"}`` publishes one declaration file
    per module; a runtime target that does not capture the module
    (``"default": "./dist/index.js"``) does not expose its values either.
    """
    if not isinstance(exports, dict):
        return []
    found = []
    for key in list(exports)[:_MAX_PATTERNS]:
        if not isinstance(key, str) or not key.startswith("./") or key.count("*") != 1:
            continue
        if not _is_types_only(exports[key]):
            continue
        targets = list(_capturing_targets(exports[key]))
        found.extend(
            target
            for _condition, target in targets
            if _safe_relative(target) and target.split("*")[1].endswith(_DECLARATION_SUFFIXES)
        )
    return found


def _within(path, directory):
    return path == directory or path.startswith(directory.rstrip(os.sep) + os.sep)


def _declaration_source_bases(package_root, prefix, analysed, project_root):
    """Source folders whose modules a declaration prefix (``dist/types/x/``)
    publishes: the tsconfig ``outDir``→``rootDir`` layout when the package
    states one, else the nearest existing folder named by the prefix's tail
    (``x``) beside the package or one of its parents in the project."""
    root = Path(package_root).resolve()
    project = Path(project_root).resolve()
    parts = [part for part in prefix.strip("/").split("/") if part]
    for name in ("tsconfig.build.json", "tsconfig.json"):
        config = _config(root / name, project) if (root / name).is_file() else None
        if config is None:
            continue
        options = config[0]
        out_dir, root_dir = options.get("declarationDir", options.get("outDir")), options.get("rootDir")
        if not isinstance(out_dir, Path) or not isinstance(root_dir, Path):
            continue
        emitted = root.joinpath(*parts)
        if emitted == out_dir or emitted.is_relative_to(out_dir):
            base = root_dir / emitted.relative_to(out_dir)
            if any(_within(path, str(base)) for path in analysed):
                return [str(base)]
    ancestors = [root, *(parent for parent in root.parents if parent.is_relative_to(project))]
    for start in range(len(parts) + 1):
        tail = parts[start:]
        if not tail:
            break
        for ancestor in ancestors:
            base = str(ancestor.joinpath(*tail))
            if any(_within(path, base) for path in analysed):
                return [base]
    return []


def types_only_pattern_files(package_root, exports, analysed, project_root):
    """Analysed sources published only as declarations by a wildcard export.

    Their type exports are public API; their values are not importable
    through that subpath, so value checks still apply.
    """
    targets = _types_only_targets(exports)
    if not targets:
        return set()
    result = set()
    for target in targets:
        prefix = target[2:].split("*")[0]
        directory = prefix if prefix.endswith("/") else prefix.rsplit("/", 1)[0] + "/"
        for base in _declaration_source_bases(package_root, directory, analysed, project_root):
            result.update(
                path
                for path in analysed
                if _within(path, base) and not path.endswith(_DECLARATION_SUFFIXES)
            )
    return result
