from __future__ import annotations

import fnmatch
import glob
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is a runtime dependency.
    yaml = None


@dataclass
class WorkspaceInfo:
    root: Path
    name: str
    discovered_from: set[str] = field(default_factory=set)
    is_root: bool = False
    is_internal_dependency: bool = False
    has_package_json: bool = True

    def to_dict(self, project_root: Path) -> dict:
        try:
            relative = self.root.relative_to(project_root)
            relative_path = "." if str(relative) == "." else str(relative)
        except ValueError:
            relative_path = str(self.root)

        return {
            "name": self.name,
            "path": str(self.root),
            "relative_path": relative_path,
            "discovered_from": sorted(self.discovered_from),
            "is_root": self.is_root,
            "is_internal_dependency": self.is_internal_dependency,
            "has_package_json": self.has_package_json,
        }


@dataclass
class WorkspaceDiagnostic:
    kind: str
    path: Path
    message: str

    def to_dict(self, project_root: Path) -> dict:
        try:
            relative = self.path.relative_to(project_root)
            relative_path = "." if str(relative) == "." else str(relative)
        except ValueError:
            relative_path = str(self.path)

        return {
            "kind": self.kind,
            "path": str(self.path),
            "relative_path": relative_path,
            "message": self.message,
        }


@dataclass
class WorkspaceInventory:
    root_package: WorkspaceInfo | None
    packages: list[WorkspaceInfo]
    diagnostics: list[WorkspaceDiagnostic]
    declared_patterns: list[str]
    tsconfig_references: list[str]

    @property
    def total_packages(self) -> int:
        return len(self.packages) + (1 if self.root_package else 0)

    @property
    def is_monorepo(self) -> bool:
        return bool(self.packages or self.declared_patterns or self.tsconfig_references)

    def to_dict(self, project_root: Path) -> dict:
        return {
            "is_monorepo": self.is_monorepo,
            "root_package": (
                self.root_package.to_dict(project_root) if self.root_package else None
            ),
            "packages": [pkg.to_dict(project_root) for pkg in self.packages],
            "diagnostics": [diag.to_dict(project_root) for diag in self.diagnostics],
            "declared_patterns": list(self.declared_patterns),
            "tsconfig_references": list(self.tsconfig_references),
            "package_count": len(self.packages),
            "total_packages": self.total_packages,
            "diagnostic_count": len(self.diagnostics),
        }


def _read_json_file(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _normalize_relpath(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return str(path).replace(os.sep, "/")
    rel_str = str(relative).replace(os.sep, "/")
    return "." if rel_str == "." else rel_str


def _workspace_name(path: Path, root: Path, package_data: dict) -> str:
    name = package_data.get("name")
    if isinstance(name, str) and name.strip():
        return name
    return _normalize_relpath(path, root)


def _extract_workspace_patterns(package_data: dict) -> list[str]:
    workspaces = package_data.get("workspaces")
    if isinstance(workspaces, list):
        return [item for item in workspaces if isinstance(item, str)]
    if isinstance(workspaces, dict):
        packages = workspaces.get("packages")
        if isinstance(packages, list):
            return [item for item in packages if isinstance(item, str)]
    return []


def _parse_pnpm_workspace_yaml(content: str) -> list[str]:
    if yaml is not None:
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                packages = data.get("packages")
                if isinstance(packages, list):
                    return [item for item in packages if isinstance(item, str)]
        except yaml.YAMLError:
            pass

    patterns: list[str] = []
    in_packages = False

    for line in content.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("packages:"):
            inline = trimmed[len("packages:") :].strip()
            if inline.startswith("[") and inline.endswith("]"):
                for value in inline[1:-1].split(","):
                    pattern = value.strip().strip("'").strip('"')
                    if pattern:
                        patterns.append(pattern)
                in_packages = False
            else:
                in_packages = True
            continue
        if not in_packages:
            continue
        if trimmed.startswith("- "):
            value = trimmed[2:].strip().strip("'").strip('"')
            if value:
                patterns.append(value)
            continue
        if trimmed and not trimmed.startswith("#"):
            break

    return patterns


def _extract_lerna_patterns(root: Path) -> list[str]:
    data = _read_json_file(root / "lerna.json")
    packages = data.get("packages")
    if isinstance(packages, list):
        return [item for item in packages if isinstance(item, str)]
    return []


def _extract_rush_project_roots(root: Path) -> list[Path]:
    data = _read_json_file(root / "rush.json")
    projects = data.get("projects")
    if not isinstance(projects, list):
        return []

    roots: list[Path] = []
    seen: set[Path] = set()
    for project in projects:
        if not isinstance(project, dict):
            continue
        folder = project.get("projectFolder")
        if not isinstance(folder, str) or not folder.strip():
            continue
        candidate = (root / folder).resolve()
        if candidate in seen or _should_skip_dir(candidate, root):
            continue
        seen.add(candidate)
        roots.append(candidate)
    return roots


def _strip_json_comments(text: str) -> str:
    out: list[str] = []
    in_string = False
    in_line_comment = False
    in_block_comment = False
    escaped = False
    i = 0

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(ch)
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    out: list[str] = []
    in_string = False
    escaped = False
    i = 0

    while i < len(text):
        ch = text[i]

        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == ",":
            j = i + 1
            while j < len(text) and text[j].isspace():
                j += 1
            if j < len(text) and text[j] in "]}":
                i += 1
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def _load_jsonc(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    cleaned = _strip_trailing_commas(_strip_json_comments(raw.lstrip("\ufeff")))
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return {}


def _parse_tsconfig_references(root: Path) -> tuple[list[Path], list[str]]:
    data = _load_jsonc(root / "tsconfig.json")
    refs = data.get("references")
    if not isinstance(refs, list):
        return [], []

    results: list[Path] = []
    reported_refs: list[str] = []
    seen_roots: set[Path] = set()
    seen_reported: set[str] = set()
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        ref_path = ref.get("path")
        if not isinstance(ref_path, str):
            continue
        candidate = (root / ref_path).resolve()

        resolved_root: Path | None = None
        if candidate.is_dir():
            resolved_root = candidate
        elif candidate.is_file():
            resolved_root = candidate.parent

        if resolved_root is not None and resolved_root not in seen_roots:
            results.append(resolved_root)
            seen_roots.add(resolved_root)

        if candidate.exists():
            reported_ref = _normalize_relpath(candidate, root)
            if reported_ref not in seen_reported:
                reported_refs.append(reported_ref)
                seen_reported.add(reported_ref)

    return results, reported_refs


def _collect_dependency_names(package_data: dict) -> set[str]:
    names: set[str] = set()
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        deps = package_data.get(key)
        if isinstance(deps, dict):
            names.update(name for name in deps if isinstance(name, str))
    return names


def _should_skip_dir(path: Path, root: Path) -> bool:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    if resolved_path == resolved_root:
        return False
    try:
        parts = resolved_path.relative_to(resolved_root).parts
    except ValueError:
        parts = path.parts
    for part in parts:
        if part.startswith("."):
            return True
        if part in {"node_modules", "build", "dist"}:
            return True
    return False


def _expand_workspace_patterns(
    root: Path, patterns: list[str], source_label: str
) -> dict[Path, set[str]]:
    matches: dict[Path, set[str]] = {}
    positives = [pattern for pattern in patterns if not pattern.startswith("!")]
    negatives = [pattern[1:] for pattern in patterns if pattern.startswith("!")]

    for pattern in positives:
        if pattern.endswith("/"):
            pattern = pattern + "*"

        full_pattern = str(root / pattern)
        for matched in glob.glob(full_pattern, recursive=True):
            candidate = Path(matched).resolve()
            if not candidate.is_dir():
                continue
            if _should_skip_dir(candidate, root):
                continue

            rel = _normalize_relpath(candidate, root)
            if any(fnmatch.fnmatch(rel, neg) for neg in negatives):
                continue

            pkg_json = candidate / "package.json"
            if not pkg_json.is_file():
                continue

            matches.setdefault(candidate, set()).add(source_label)

    return matches


def _discover_undeclared_packages(
    root: Path, declared_roots: set[Path]
) -> list[WorkspaceDiagnostic]:
    diagnostics: list[WorkspaceDiagnostic] = []

    top_level: list[Path] = []
    try:
        top_level = [entry for entry in root.iterdir() if entry.is_dir()]
    except OSError:
        return diagnostics

    for entry in top_level:
        if _should_skip_dir(entry, root):
            continue

        candidates = [entry]
        try:
            candidates.extend(child for child in entry.iterdir() if child.is_dir())
        except OSError:
            pass

        for candidate in candidates:
            if _should_skip_dir(candidate, root):
                continue
            pkg_json = candidate / "package.json"
            if not pkg_json.is_file():
                continue
            resolved = candidate.resolve()
            if resolved == root or resolved in declared_roots:
                continue
            diagnostics.append(
                WorkspaceDiagnostic(
                    kind="undeclared_workspace_package",
                    path=resolved,
                    message=(
                        f"Directory '{_normalize_relpath(resolved, root)}' contains "
                        "package.json but is not declared as a workspace"
                    ),
                )
            )

    diagnostics.sort(key=lambda item: str(item.path))
    return diagnostics


def discover_workspace_inventory(project_root: Path) -> WorkspaceInventory:
    root = project_root.resolve()

    root_package_json = root / "package.json"
    root_package_data = _read_json_file(root_package_json)
    root_package = None
    if root_package_json.is_file():
        root_package = WorkspaceInfo(
            root=root,
            name=_workspace_name(root, root, root_package_data),
            discovered_from={"root-package"},
            is_root=True,
            has_package_json=True,
        )

    package_json_patterns = _extract_workspace_patterns(root_package_data)
    patterns = list(package_json_patterns)
    pattern_sources: list[tuple[list[str], str]] = []
    if package_json_patterns:
        pattern_sources.append((package_json_patterns, "package.json:workspaces"))

    pnpm_workspace = root / "pnpm-workspace.yaml"
    if pnpm_workspace.is_file():
        try:
            pnpm_patterns = _parse_pnpm_workspace_yaml(
                pnpm_workspace.read_text(encoding="utf-8")
            )
            patterns.extend(pnpm_patterns)
            if pnpm_patterns:
                pattern_sources.append((pnpm_patterns, "pnpm-workspace.yaml"))
        except OSError:
            pass

    lerna_patterns = _extract_lerna_patterns(root)
    if lerna_patterns:
        patterns.extend(lerna_patterns)
        pattern_sources.append((lerna_patterns, "lerna.json:packages"))

    workspace_sources: dict[Path, set[str]] = {}
    for source_patterns, source_label in pattern_sources:
        for pkg_root, sources in _expand_workspace_patterns(
            root, source_patterns, source_label
        ).items():
            workspace_sources.setdefault(pkg_root, set()).update(sources)
    tsconfig_reference_roots, tsconfig_reference_paths = _parse_tsconfig_references(
        root
    )
    for ref_path in tsconfig_reference_roots:
        workspace_sources.setdefault(ref_path, set()).add("tsconfig.json:references")

    for rush_root in _extract_rush_project_roots(root):
        workspace_sources.setdefault(rush_root, set()).add("rush.json:projects")

    packages: list[WorkspaceInfo] = []
    package_data_by_root: dict[Path, dict] = {}
    for pkg_root in sorted(workspace_sources, key=lambda item: str(item)):
        pkg_json = pkg_root / "package.json"
        pkg_data = _read_json_file(pkg_json)
        has_package_json = pkg_json.is_file()
        package_data_by_root[pkg_root] = pkg_data
        packages.append(
            WorkspaceInfo(
                root=pkg_root,
                name=_workspace_name(pkg_root, root, pkg_data),
                discovered_from=set(workspace_sources[pkg_root]),
                has_package_json=has_package_json,
            )
        )

    name_to_workspace: dict[str, WorkspaceInfo] = {}
    all_packages_for_deps = list(packages)
    if root_package is not None:
        all_packages_for_deps = [root_package, *all_packages_for_deps]
        package_data_by_root[root] = root_package_data

    for workspace in all_packages_for_deps:
        name_to_workspace[workspace.name] = workspace

    for workspace in all_packages_for_deps:
        pkg_data = package_data_by_root.get(workspace.root, {})
        for dep_name in _collect_dependency_names(pkg_data):
            target = name_to_workspace.get(dep_name)
            if target and target.root != workspace.root:
                target.is_internal_dependency = True

    diagnostics: list[WorkspaceDiagnostic] = []
    if workspace_sources:
        diagnostics = _discover_undeclared_packages(
            root, {pkg.root.resolve() for pkg in packages}
        )

    return WorkspaceInventory(
        root_package=root_package,
        packages=packages,
        diagnostics=diagnostics,
        declared_patterns=patterns,
        tsconfig_references=tsconfig_reference_paths,
    )
