from __future__ import annotations

import json
import re
from json.decoder import scanstring
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.ai_defect.dependency_hallucination import (
    FROM_RE,
    IMPORT_RE,
    MAX_DEPENDENCY_MANIFEST_BYTES,
    RULE_ID_HALLUCINATION,
    RULE_ID_UNDECLARED,
    _is_confident_hallucination_candidate,
    _normalize_name,
    _pyproject_dependency_metadata,
    scan_diff_added_imports,
)
from skylos.rules.ai_defect.manifest_dependency_hallucination import (
    RULE_ID_DEPENDENCY_HALLUCINATION,
    RULE_ID_VERSION_HALLUCINATION,
    STATUS_MISSING_PACKAGE,
    STATUS_MISSING_VERSION,
    STATUS_UNKNOWN,
    check_dependency_version_status,
)
from skylos.rules.sca.vulnerability_scanner import (
    _PACKAGE_JSON_DEPENDENCY_SECTIONS,
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
    MAX_MANIFEST_BYTES,
    _classify_npm_registry_spec,
    _parse_package_json_text,
)

SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"

_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")

_PY_SUFFIXES = (".py", ".pyi", ".pyw")

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_REQ_PIN_RE = re.compile(r"==\s*([A-Za-z0-9!+*._-]+)")
_PEP508_SPEC_RE = re.compile(
    r"[\"']([A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)\s*([^\"',;]+)[\"',;]"
)
_POETRY_DEP_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*\"([\^~>=<!]*\d[^\"]*)\""
)
_EXACT_PY_VERSION_RE = re.compile(r"^\d[\w.!+]*$")
_PYPROJECT_KEY_BLOCKLIST = frozenset(
    {"version", "python", "requires-python", "target-version"}
)
_MAX_DIFF_PATH_CHARS = 4096
_MAX_DIFF_PATH_COMPONENTS = 256
_NEW_FILE_HUNK_RE = re.compile(r"^@@ -0,0 \+1(?:,(\d+))? @@(?: .*)?$")

_PACKAGE_JSON_DEP_RE = re.compile(
    r"^\s*\"(@?[a-z0-9][a-z0-9._/-]*)\"\s*:\s*\"([^\"]*)\""
)
_JSON_STRUCTURE_RE = re.compile(r'["{}\[\]:,]')
_GO_MOD_REQUIRE_RE = re.compile(
    r"^(?:require\s+)?([a-z0-9][\w.-]*\.[a-z]{2,}(?:/[\w.~-]+)+)\s+(v[\w.+-]+)"
)

_IMPORT_KINDS = {
    RULE_ID_HALLUCINATION: "hallucinated_import",
    RULE_ID_UNDECLARED: "undeclared_import",
}

_REGISTRY_LABELS = {
    ECOSYSTEM_PYPI: "the PyPI registry",
    ECOSYSTEM_NPM: "the npm registry",
    ECOSYSTEM_GO: "the Go module proxy",
}


class _ScopedDependencyNames(set[str]):
    """Dependency names plus their project-relative manifest directories."""

    def __init__(self, by_directory: dict[str, set[str]]) -> None:
        self.by_directory = {
            directory: frozenset(names)
            for directory, names in by_directory.items()
        }
        super().__init__(
            name for names in self.by_directory.values() for name in names
        )


def scan_diff_dependency_hallucinations(
    diff_text: str,
    repo_root,
    *,
    import_scanner=None,
    status_checker=None,
) -> dict[str, Any]:
    """Deterministic dependency-hallucination checks scoped to a unified diff.

    Checks import statements added to Python files and dependency entries added
    to manifests (requirements*.txt, pyproject.toml, package.json, go.mod)
    against the package registries. Returns {"findings": [...],
    "registry_unreachable": bool}; registry_unreachable=True means at least one
    lookup could not be completed, so a "pass" is incomplete rather than clean.
    """
    if import_scanner is None:
        import_scanner = scan_diff_added_imports
    if status_checker is None:
        status_checker = check_dependency_version_status

    added_imports: list[tuple[str, int, str]] = []
    local_roots: set[str] = set()
    manifest_specs: list[dict[str, Any]] = []

    for file_path, added_lines in _parse_added_lines(diff_text):
        if file_path.endswith(_PY_SUFFIXES):
            local_roots |= _local_roots_for_path(file_path)
            for line_no, text in added_lines:
                mod = _import_root(text)
                if mod:
                    added_imports.append((file_path, line_no, mod))
            continue
        manifest_specs.extend(_manifest_specs_for_file(file_path, added_lines))
    manifest_specs.extend(_package_json_specs_from_diff(diff_text, repo_root))

    findings: list[dict[str, Any]] = []
    registry_unreachable = False

    if added_imports:
        import_findings, unreachable = import_scanner(
            repo_root,
            added_imports,
            extra_local_modules=local_roots,
            extra_declared_deps=_added_pypi_dependency_names(
                manifest_specs,
                diff_text=diff_text,
            ),
        )
        for finding in import_findings:
            finding["kind"] = _IMPORT_KINDS.get(finding.get("rule_id"), "dependency")
        findings.extend(import_findings)
        registry_unreachable = registry_unreachable or unreachable

    manifest_findings, manifest_unreachable = _check_manifest_specs(
        manifest_specs, status_checker
    )
    findings.extend(manifest_findings)
    registry_unreachable = registry_unreachable or manifest_unreachable

    return {"findings": findings, "registry_unreachable": registry_unreachable}


def _parse_added_lines(diff_text) -> list[tuple[str, list[tuple[int, str]]]]:
    files: list[tuple[str, list[tuple[int, str]]]] = []
    current_added: list[tuple[int, str]] | None = None
    line_no = 0

    for raw_line in str(diff_text or "").splitlines():
        file_match = _DIFF_FILE_RE.match(raw_line)
        if file_match:
            current_added = []
            files.append((file_match.group(1), current_added))
            line_no = 0
            continue
        if current_added is None:
            continue
        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            line_no = int(hunk_match.group(1)) - 1
            continue
        if raw_line.startswith("+"):
            line_no += 1
            current_added.append((line_no, raw_line[1:]))
        elif not raw_line.startswith("-"):
            line_no += 1

    return files


def _import_root(text: str) -> str | None:
    match = IMPORT_RE.match(text) or FROM_RE.match(text)
    if match is None:
        return None
    return match.group(1).split(".")[0]


def _local_roots_for_path(file_path: str) -> set[str]:
    parts = PurePosixPath(file_path).parts
    roots = set()
    if len(parts) == 1:
        roots.add(PurePosixPath(file_path).stem)
    else:
        roots.update(parts[:-1])
        roots.add(PurePosixPath(parts[-1]).stem)
    return {root for root in roots if root and not root.startswith(".")}


def _manifest_specs_for_file(
    file_path: str,
    added_lines: list[tuple[int, str]],
) -> list[dict[str, Any]]:
    name = PurePosixPath(file_path).name.lower()
    if _is_requirements_file(file_path):
        return _requirement_specs(file_path, added_lines)
    if name == "pyproject.toml":
        return _pyproject_specs(file_path, added_lines)
    if name == "go.mod":
        return _go_mod_specs(file_path, added_lines)
    return []


def _is_requirements_file(file_path: str) -> bool:
    path = PurePosixPath(file_path)
    name = path.name.lower()
    if not name.endswith((".txt", ".in")):
        return False
    if "requirements" in name or "constraints" in name:
        return True
    return path.parent.name.lower() == "requirements"


def _requirement_specs(
    file_path: str,
    added_lines: list[tuple[int, str]],
) -> list[dict[str, Any]]:
    specs = []
    for line_no, text in added_lines:
        stripped = text.strip()
        if not stripped or stripped.startswith(("#", "-")) or "://" in stripped:
            continue
        name_match = _REQ_NAME_RE.match(stripped)
        if name_match is None:
            continue
        pin_match = _REQ_PIN_RE.search(stripped)
        version = pin_match.group(1) if pin_match else ""
        specs.append(
            _spec(
                ECOSYSTEM_PYPI,
                name_match.group(1),
                version,
                exact=bool(pin_match) and "*" not in version,
                file_path=file_path,
                line_no=line_no,
            )
        )
    return specs


def _pyproject_specs(
    file_path: str,
    added_lines: list[tuple[int, str]],
) -> list[dict[str, Any]]:
    specs = []
    for line_no, text in added_lines:
        stripped = text.strip()
        if not stripped or stripped.startswith("#"):
            continue

        spec_match = _PEP508_SPEC_RE.search(stripped)
        if spec_match is not None:
            name = spec_match.group(1)
            operator = spec_match.group(2)
            version = spec_match.group(3).strip()
            if name.lower() in _PYPROJECT_KEY_BLOCKLIST:
                continue
            specs.append(
                _spec(
                    ECOSYSTEM_PYPI,
                    name,
                    version,
                    exact=operator in ("==", "===") and "*" not in version,
                    file_path=file_path,
                    line_no=line_no,
                )
            )
            continue

        poetry_match = _POETRY_DEP_RE.match(stripped)
        if poetry_match is not None:
            name = poetry_match.group(1)
            version = poetry_match.group(2).strip()
            if name.lower() in _PYPROJECT_KEY_BLOCKLIST or "." not in version:
                continue
            specs.append(
                _spec(
                    ECOSYSTEM_PYPI,
                    name,
                    version.lstrip("^~=<>! "),
                    exact=_EXACT_PY_VERSION_RE.match(version) is not None,
                    file_path=file_path,
                    line_no=line_no,
                )
            )
    return specs


def _added_pyproject_dependency_names(
    diff_text: str,
) -> dict[str, set[str]]:
    names_by_directory: dict[str, set[str]] = {}
    for file_path, text in _complete_new_file_postimages(diff_text):
        if PurePosixPath(file_path).name != "pyproject.toml":
            continue
        scope = _pypi_manifest_scope(file_path)
        if scope is None:
            continue
        try:
            if len(text.encode("utf-8")) > MAX_DEPENDENCY_MANIFEST_BYTES:
                continue
            data = tomllib.loads(text)
        except (UnicodeError, tomllib.TOMLDecodeError, RecursionError, ValueError):
            continue
        names, _project_name = _pyproject_dependency_metadata(data)
        if names:
            names_by_directory.setdefault(scope, set()).update(names)
    return names_by_directory


def _complete_new_file_postimages(diff_text: str) -> list[tuple[str, str]]:
    lines = str(diff_text or "").splitlines()
    postimages = []
    index = 0

    while index < len(lines):
        if lines[index] != "--- /dev/null":
            index += 1
            continue
        if index + 2 >= len(lines):
            break

        file_match = _DIFF_FILE_RE.match(lines[index + 1])
        hunk_match = _NEW_FILE_HUNK_RE.match(lines[index + 2])
        if file_match is None or hunk_match is None:
            index += 1
            continue

        count_text = hunk_match.group(1) or "1"
        if len(count_text) > 7:
            index += 3
            continue
        expected_lines = int(count_text)
        added_lines = []
        valid = True
        index += 3

        while index < len(lines):
            raw_line = lines[index]
            if raw_line.startswith("diff --git "):
                break
            if raw_line.startswith("--- "):
                if (
                    index + 1 < len(lines)
                    and lines[index + 1].startswith("+++ ")
                ):
                    break
                valid = False
                index += 1
                continue
            if raw_line.startswith("+"):
                added_lines.append(raw_line[1:])
            elif raw_line.startswith("\\ No newline at end of file"):
                pass
            else:
                valid = False
            index += 1

        if valid and len(added_lines) == expected_lines:
            postimages.append(
                (file_match.group(1), "\n".join(added_lines))
            )

    return postimages


def _parse_new_file_lines(diff_text) -> list[tuple[str, list[tuple[str, int, str]]]]:
    files: list[tuple[str, list[tuple[str, int, str]]]] = []
    current_lines: list[tuple[str, int, str]] | None = None
    line_no = 0
    in_hunk = False

    for raw_line in str(diff_text or "").splitlines():
        file_match = _DIFF_FILE_RE.match(raw_line)
        if file_match:
            current_lines = []
            files.append((file_match.group(1), current_lines))
            line_no = 0
            in_hunk = False
            continue
        if current_lines is None:
            continue
        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            line_no = int(hunk_match.group(1)) - 1
            in_hunk = True
            current_lines.append(("hunk", line_no, ""))
            continue
        if not in_hunk:
            continue
        if raw_line.startswith("\\"):
            continue
        if raw_line.startswith("+"):
            line_no += 1
            current_lines.append(("add", line_no, raw_line[1:]))
        elif raw_line.startswith("-"):
            continue
        else:
            line_no += 1
            text = raw_line[1:] if raw_line.startswith(" ") else raw_line
            current_lines.append(("context", line_no, text))

    return files


def _package_json_specs_from_diff(
    diff_text: str,
    repo_root=None,
) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for file_path, new_lines in _parse_new_file_lines(diff_text):
        if PurePosixPath(file_path).name.lower() != "package.json":
            continue
        worktree_specs = _worktree_package_json_specs(
            repo_root,
            file_path,
            new_lines,
        )
        if worktree_specs is not None:
            specs.extend(worktree_specs)
            continue
        specs.extend(_package_json_specs(file_path, new_lines))
    return specs


def _worktree_package_json_specs(
    repo_root,
    file_path: str,
    new_lines: list[tuple[str, int, str]],
) -> list[dict[str, Any]] | None:
    """Use the parsed postimage when it matches every added diff line exactly."""
    postimage = _matching_package_json_postimage(repo_root, file_path, new_lines)
    if postimage is None:
        return None
    text, added_line_numbers = postimage
    candidates = _parse_package_json_text(
        text,
        path=Path(file_path),
        exact_only=False,
    )
    return [
        _diff_candidate(candidate, file_path)
        for candidate in candidates
        if candidate.get("line") in added_line_numbers
    ]


def _matching_package_json_postimage(
    repo_root,
    file_path: str,
    new_lines: list[tuple[str, int, str]],
) -> tuple[str, set[int]] | None:
    if repo_root is None:
        return None
    relative = _safe_diff_relative_path(file_path)
    if relative is None:
        return None
    try:
        root = Path(repo_root).resolve()
    except (OSError, TypeError):
        return None

    text = read_project_text_no_symlink(
        root,
        relative.as_posix(),
        max_bytes=MAX_MANIFEST_BYTES,
        encoding="utf-8",
        errors=None,
    )
    if text is None or not _valid_package_json_text(text):
        return None

    added_line_numbers = _matching_added_line_numbers(text, new_lines)
    if added_line_numbers is None:
        return None
    return text, added_line_numbers


def _safe_diff_relative_path(file_path: str) -> PurePosixPath | None:
    raw_path = str(file_path or "")
    if (
        not raw_path
        or raw_path != raw_path.strip()
        or len(raw_path) > _MAX_DIFF_PATH_CHARS
        or "\\" in raw_path
        or re.match(r"^[A-Za-z]:", raw_path)
    ):
        return None
    relative = PurePosixPath(raw_path)
    if (
        not relative.parts
        or relative.as_posix() != raw_path
        or len(relative.parts) > _MAX_DIFF_PATH_COMPONENTS
        or relative.is_absolute()
        or ".." in relative.parts
    ):
        return None
    return relative


def _valid_package_json_text(text: str) -> bool:
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return False
    return isinstance(data, dict)


def _matching_added_line_numbers(
    text: str,
    new_lines: list[tuple[str, int, str]],
) -> set[int] | None:
    postimage_lines = text.splitlines()
    added_lines = [
        (line_no, line) for kind, line_no, line in new_lines if kind == "add"
    ]
    if not added_lines:
        return None
    for line_no, line in added_lines:
        if line_no < 1 or line_no > len(postimage_lines):
            return None
        if postimage_lines[line_no - 1] != line:
            return None
    return {line_no for line_no, _line in added_lines}


def _diff_candidate(candidate: dict[str, Any], file_path: str) -> dict[str, Any]:
    normalized = dict(candidate)
    normalized["file"] = file_path
    return normalized


def _package_json_specs(
    file_path: str,
    new_lines: list[tuple[str, int, str]],
) -> list[dict[str, Any]]:
    specs = []
    object_stack: list[str | None] = []
    optional_names: set[str] = set()
    optional_peer_names: set[str] = set()
    for kind, line_no, text in new_lines:
        if kind == "hunk":
            object_stack.clear()
            continue

        dependency_section = _package_json_dependency_section(object_stack)
        match = (
            _PACKAGE_JSON_DEP_RE.match(text)
            if dependency_section is not None
            else None
        )
        if match is not None and dependency_section == "optionalDependencies":
            optional_names.add(match.group(1))
        spec = _added_package_json_spec(
            kind,
            line_no,
            file_path,
            dependency_section,
            match,
        )
        if spec is not None:
            specs.append(spec)

        optional_peer = _added_optional_peer_name(object_stack, text)
        if optional_peer:
            optional_peer_names.add(optional_peer)

        _update_json_object_stack(object_stack, text)

    return _effective_package_json_specs(specs, optional_names, optional_peer_names)


def _added_package_json_spec(
    kind: str,
    line_no: int,
    file_path: str,
    dependency_section: str | None,
    match: re.Match[str] | None,
) -> dict[str, Any] | None:
    if kind != "add" or match is None or dependency_section is None:
        return None
    name = match.group(1)
    version_spec = match.group(2).strip()
    classified = _classify_npm_registry_spec(version_spec)
    if classified is None:
        return None
    version, exact = classified
    return _spec(
        ECOSYSTEM_NPM,
        name,
        version,
        exact=exact,
        file_path=file_path,
        line_no=line_no,
        version_spec=version_spec,
        dependency_section=dependency_section,
        dependency_optional=_diff_dependency_optional(dependency_section),
    )


def _diff_dependency_optional(section: str) -> bool | None:
    if section == "optionalDependencies":
        return True
    if section == "peerDependencies":
        return None
    return False


def _effective_package_json_specs(
    specs: list[dict[str, Any]],
    optional_names: set[str],
    optional_peer_names: set[str],
) -> list[dict[str, Any]]:
    effective = []
    for spec in specs:
        section = spec.get("dependency_section")
        name = spec.get("name")
        if section == "dependencies" and name in optional_names:
            continue
        if section == "peerDependencies" and name in optional_peer_names:
            spec["dependency_optional"] = True
            spec["peer_dependency_optional"] = True
        effective.append(spec)
    return effective


def _added_optional_peer_name(stack: list[str | None], text: str) -> str | None:
    if len(stack) == 2 and stack[0] == "peerDependenciesMeta":
        if re.match(r'^\s*"optional"\s*:\s*true\b', text):
            return stack[1]
    if len(stack) == 1 and stack[0] == "peerDependenciesMeta":
        match = re.match(
            r'^\s*"([^"]+)"\s*:\s*\{[^{}]*"optional"\s*:\s*true\b',
            text,
        )
        if match is not None:
            return match.group(1)
    return None


def _update_json_object_stack(stack: list[str | None], text: str) -> None:
    pending_key: str | None = None
    expect_value = False
    for token, value in _json_structure_tokens(text):
        if token == '"':
            if expect_value:
                pending_key = None
                expect_value = False
            else:
                pending_key = value
            continue
        if token == ":":
            expect_value = True
            continue
        if token == ",":
            pending_key = None
            expect_value = False
            continue
        _update_json_container_stack(stack, token, pending_key, expect_value)
        pending_key = None
        expect_value = False


def _json_structure_tokens(text: str):
    pos = 0
    while True:
        match = _JSON_STRUCTURE_RE.search(text, pos)
        if match is None:
            return
        token = match.group()
        pos = match.end()
        if token != '"':
            yield token, None
            continue
        try:
            value, pos = scanstring(text, pos)
        except ValueError:
            return
        yield token, value


def _update_json_container_stack(
    stack: list[str | None],
    token: str,
    pending_key: str | None,
    expect_value: bool,
) -> None:
    if token in "{[":
        if expect_value and pending_key is not None:
            stack.append(pending_key)
        elif stack:
            stack.append(None)
    elif stack:
        stack.pop()


def _package_json_dependency_section(stack: list[str | None]) -> str | None:
    if len(stack) != 1:
        return None
    section = stack[0]
    return section if section in _PACKAGE_JSON_DEPENDENCY_SECTIONS else None


def _added_pypi_dependency_names(
    specs: list[dict[str, Any]],
    *,
    diff_text: str = "",
) -> _ScopedDependencyNames:
    names_by_directory: dict[str, set[str]] = {}
    for spec in specs:
        if spec.get("ecosystem") != ECOSYSTEM_PYPI:
            continue
        relative = _safe_diff_relative_path(spec.get("file"))
        if relative is None or relative.name.lower() == "pyproject.toml":
            continue
        normalized = _normalize_name(spec.get("name"))
        scope = _pypi_manifest_scope(relative.as_posix())
        if normalized and scope is not None:
            names_by_directory.setdefault(scope, set()).add(normalized)
    for directory, names in _added_pyproject_dependency_names(diff_text).items():
        names_by_directory.setdefault(directory, set()).update(names)
    return _ScopedDependencyNames(names_by_directory)


def _pypi_manifest_scope(file_path) -> str | None:
    relative = _safe_diff_relative_path(file_path)
    if relative is None:
        return None
    parent = relative.parent
    if parent.name.lower() == "requirements":
        parent = parent.parent
    return parent.as_posix()


def _go_mod_specs(
    file_path: str,
    added_lines: list[tuple[int, str]],
) -> list[dict[str, Any]]:
    specs = []
    for line_no, text in added_lines:
        stripped = text.strip()
        if not stripped or stripped.startswith(("//", "module ")):
            continue
        match = _GO_MOD_REQUIRE_RE.match(stripped)
        if match is None:
            continue
        specs.append(
            _spec(
                ECOSYSTEM_GO,
                match.group(1),
                match.group(2),
                exact=True,
                file_path=file_path,
                line_no=line_no,
            )
        )
    return specs


def _spec(
    ecosystem,
    name,
    version,
    *,
    exact,
    file_path,
    line_no,
    version_spec=None,
    dependency_section=None,
    dependency_optional=None,
    peer_dependency_optional=None,
) -> dict[str, Any]:
    spec = {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "exact": exact,
        "file": file_path,
        "line": line_no,
    }
    if version_spec is not None:
        spec["version_spec"] = version_spec
    if dependency_section is not None:
        spec["dependency_section"] = dependency_section
    if dependency_optional is not None:
        spec["dependency_optional"] = dependency_optional
    if peer_dependency_optional is not None:
        spec["peer_dependency_optional"] = peer_dependency_optional
    return spec


def _check_manifest_specs(
    specs: list[dict[str, Any]],
    status_checker,
) -> tuple[list[dict[str, Any]], bool]:
    findings: list[dict[str, Any]] = []
    registry_unreachable = False
    seen: set[tuple[str, str, str]] = set()

    for spec in specs:
        version_key = (
            "<package-only>"
            if spec["ecosystem"] == ECOSYSTEM_NPM and spec.get("exact") is False
            else spec["version"]
        )
        key = (spec["ecosystem"], spec["name"], version_key)
        if key in seen:
            continue
        seen.add(key)

        status = status_checker(spec["ecosystem"], spec["name"], spec["version"], {})

        if status == STATUS_UNKNOWN:
            registry_unreachable = True
            continue

        if status == STATUS_MISSING_PACKAGE and _is_confident_hallucination_candidate(
            spec["name"]
        ):
            findings.append(_missing_package_finding(spec))
        elif status == STATUS_MISSING_VERSION and spec["exact"]:
            findings.append(_missing_version_finding(spec))

    return findings, registry_unreachable


def _missing_package_finding(spec: dict[str, Any]) -> dict[str, Any]:
    registry = _REGISTRY_LABELS.get(spec["ecosystem"], "its package registry")
    return _manifest_finding(
        spec,
        rule_id=RULE_ID_DEPENDENCY_HALLUCINATION,
        kind="hallucinated_package",
        severity=SEV_CRITICAL,
        message=(
            f"Hallucinated {spec['ecosystem']} dependency '{spec['name']}'. "
            f"Package does not exist in {registry}."
        ),
    )


def _missing_version_finding(spec: dict[str, Any]) -> dict[str, Any]:
    registry = _REGISTRY_LABELS.get(spec["ecosystem"], "its package registry")
    return _manifest_finding(
        spec,
        rule_id=RULE_ID_VERSION_HALLUCINATION,
        kind="hallucinated_version",
        severity=SEV_HIGH,
        message=(
            f"Hallucinated {spec['ecosystem']} dependency version "
            f"'{spec['name']}@{spec['version']}'. "
            f"Version does not exist in {registry}."
        ),
    )


def _manifest_finding(
    spec: dict[str, Any],
    *,
    rule_id: str,
    kind: str,
    severity: str,
    message: str,
) -> dict[str, Any]:
    finding = {
        "rule_id": rule_id,
        "kind": kind,
        "severity": severity,
        "message": message,
        "file": str(spec["file"]),
        "line": int(spec["line"]),
        "col": 0,
        "symbol": spec["name"],
        "category": "ai_defect",
        "defect_type": "dependency_hallucination",
        "vibe_category": "dependency_hallucination",
        "ai_likelihood": "high",
    }
    metadata = {
        key: spec[key]
        for key in (
            "version_spec",
            "exact",
            "dependency_section",
            "dependency_optional",
            "peer_dependency_optional",
        )
        if key in spec
    }
    if metadata:
        finding["metadata"] = metadata
    return finding
