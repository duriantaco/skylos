from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from skylos.rules.ai_defect.dependency_hallucination import (
    FROM_RE,
    IMPORT_RE,
    RULE_ID_HALLUCINATION,
    RULE_ID_UNDECLARED,
    _is_confident_hallucination_candidate,
    _normalize_name,
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
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
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

_PACKAGE_JSON_DEP_RE = re.compile(r"^\s*\"(@?[a-z0-9][a-z0-9._/-]*)\"\s*:\s*\"([^\"]+)\"")
_NPM_VERSIONISH_RE = re.compile(r"^[\^~>=<]*\s*\d[\w.+-]*(?:\s*(?:\|\||-)\s*.*)?$")
_EXACT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.]+)?$")
_PACKAGE_JSON_META_KEYS = frozenset(
    {
        "name",
        "version",
        "description",
        "main",
        "module",
        "types",
        "typings",
        "type",
        "license",
        "author",
        "homepage",
        "packageManager",
        "node",
        "npm",
        "yarn",
        "pnpm",
    }
)
_PACKAGE_JSON_DEPENDENCY_SECTIONS = frozenset(
    {
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    }
)

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
    manifest_specs.extend(_package_json_specs_from_diff(diff_text))

    findings: list[dict[str, Any]] = []
    registry_unreachable = False

    if added_imports:
        import_findings, unreachable = import_scanner(
            repo_root,
            added_imports,
            extra_local_modules=local_roots,
            extra_declared_deps=_added_pypi_dependency_names(manifest_specs),
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
            files.append((file_match.group(1).strip(), current_added))
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


def _parse_new_file_lines(diff_text) -> list[tuple[str, list[tuple[str, int, str]]]]:
    files: list[tuple[str, list[tuple[str, int, str]]]] = []
    current_lines: list[tuple[str, int, str]] | None = None
    line_no = 0
    in_hunk = False

    for raw_line in str(diff_text or "").splitlines():
        file_match = _DIFF_FILE_RE.match(raw_line)
        if file_match:
            current_lines = []
            files.append((file_match.group(1).strip(), current_lines))
            line_no = 0
            in_hunk = False
            continue
        if current_lines is None:
            continue
        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            line_no = int(hunk_match.group(1)) - 1
            in_hunk = True
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


def _package_json_specs_from_diff(diff_text: str) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for file_path, new_lines in _parse_new_file_lines(diff_text):
        if PurePosixPath(file_path).name.lower() != "package.json":
            continue
        specs.extend(_package_json_specs(file_path, new_lines))
    return specs


def _package_json_specs(
    file_path: str,
    new_lines: list[tuple[str, int, str]],
) -> list[dict[str, Any]]:
    specs = []
    object_stack: list[str] = []
    for kind, line_no, text in new_lines:
        _pop_closed_json_objects(object_stack, text)

        if kind == "add" and _inside_package_dependency_section(object_stack):
            match = _PACKAGE_JSON_DEP_RE.match(text)
            if match is not None:
                name = match.group(1)
                version = match.group(2).strip()
                if name not in _PACKAGE_JSON_META_KEYS and _NPM_VERSIONISH_RE.match(
                    version
                ):
                    specs.append(
                        _spec(
                            ECOSYSTEM_NPM,
                            name,
                            version,
                            exact=_EXACT_SEMVER_RE.match(version) is not None,
                            file_path=file_path,
                            line_no=line_no,
                        )
                    )

        _push_open_json_object(object_stack, text)
    return specs


def _pop_closed_json_objects(stack: list[str], text: str) -> None:
    stripped = text.lstrip()
    while stripped.startswith(("}", "]")):
        if stack:
            stack.pop()
        stripped = stripped[1:].lstrip()
        if stripped.startswith(","):
            stripped = stripped[1:].lstrip()


def _push_open_json_object(stack: list[str], text: str) -> None:
    match = re.match(r'^\s*"([^"]+)"\s*:\s*[{[]', text)
    if match is None:
        return
    stack.append(match.group(1))


def _inside_package_dependency_section(stack: list[str]) -> bool:
    return any(section in _PACKAGE_JSON_DEPENDENCY_SECTIONS for section in stack)


def _added_pypi_dependency_names(specs: list[dict[str, Any]]) -> set[str]:
    names = set()
    for spec in specs:
        if spec.get("ecosystem") != ECOSYSTEM_PYPI:
            continue
        normalized = _normalize_name(spec.get("name"))
        if normalized:
            names.add(normalized)
    return names


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


def _spec(ecosystem, name, version, *, exact, file_path, line_no) -> dict[str, Any]:
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "exact": exact,
        "file": file_path,
        "line": line_no,
    }


def _check_manifest_specs(
    specs: list[dict[str, Any]],
    status_checker,
) -> tuple[list[dict[str, Any]], bool]:
    findings: list[dict[str, Any]] = []
    registry_unreachable = False
    seen: set[tuple[str, str, str]] = set()

    for spec in specs:
        key = (spec["ecosystem"], spec["name"], spec["version"])
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
    return {
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
