from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


ENTRYPOINT_BASENAMES = {
    "__main__.py",
    "app.py",
    "asgi.py",
    "cli.py",
    "conftest.py",
    "main.py",
    "manage.py",
    "server.py",
    "setup.py",
    "tasks.py",
    "wsgi.py",
}

REGISTRATION_TOKENS = (
    "route",
    "router",
    "command",
    "group",
    "callback",
    "task",
    "fixture",
    "hook",
    "receiver",
    "signal",
    "scheduler",
    "job",
    "consumer",
    "listener",
)

HIGH_SIGNAL_PATH_TOKENS = (
    "admin",
    "auth",
    "billing",
    "crypto",
    "database",
    "db",
    "login",
    "oauth",
    "password",
    "payment",
    "query",
    "secret",
    "session",
    "sql",
    "token",
    "upload",
)

SECURITY_TOKENS = {
    "eval(": "dynamic code execution",
    "exec(": "dynamic code execution",
    "subprocess.": "subprocess usage",
    "os.system(": "shell execution",
    ".execute(": "query execution",
    "yaml.load(": "unsafe deserialization",
    "pickle.loads(": "unsafe deserialization",
    "requests.": "network boundary",
}


def _norm_path(path: str | Path) -> str:
    try:
        return str(Path(path).resolve())
    except Exception:
        return str(path)


def _module_name(project_root: Path, file_path: Path) -> str:
    try:
        rel = file_path.resolve().relative_to(project_root.resolve())
    except ValueError:
        rel = Path(file_path.name)
    parts = list(rel.parts)
    if not parts:
        return file_path.stem
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = Path(parts[-1]).stem
    return ".".join(p for p in parts if p)


def _dotted_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _is_main_guard(test) -> bool:
    if not isinstance(test, ast.Compare):
        return False
    if not isinstance(test.left, ast.Name) or test.left.id != "__name__":
        return False
    if not test.comparators:
        return False
    comp = test.comparators[0]
    return isinstance(comp, ast.Constant) and comp.value == "__main__"


def _branch_count(node) -> int:
    count = 0
    for child in ast.walk(node):
        if isinstance(
            child,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Try,
                ast.ExceptHandler,
                ast.With,
                ast.AsyncWith,
                ast.Match,
            ),
        ):
            count += 1
        elif isinstance(child, ast.BoolOp):
            count += max(0, len(child.values) - 1)
    return count


@dataclass
class FileActivation:
    path: str
    module: str
    imports: set[str] = field(default_factory=set)
    imported_by: set[str] = field(default_factory=set)
    entrypoint_reasons: list[str] = field(default_factory=list)
    registration_hints: list[str] = field(default_factory=list)
    security_hints: list[str] = field(default_factory=list)
    hotspot_hints: list[str] = field(default_factory=list)
    related_tests: list[str] = field(default_factory=list)
    static_reasons: list[str] = field(default_factory=list)
    source_lines: int = 0
    total_defs: int = 0
    total_branches: int = 0
    review_score: int = 0
    prefer_full_file_review: bool = False

    def context_block(self) -> str:
        parts = [
            f"- review_score={self.review_score}",
        ]

        if self.entrypoint_reasons:
            parts.append("- entrypoints: " + "; ".join(self.entrypoint_reasons[:3]))
        if self.imported_by:
            importers = sorted(Path(p).name for p in self.imported_by)
            parts.append("- imported_by: " + ", ".join(importers[:4]))
        if self.registration_hints:
            parts.append(
                "- runtime registrations: " + "; ".join(self.registration_hints[:3])
            )
        if self.related_tests:
            tests = [Path(p).name for p in self.related_tests[:4]]
            parts.append("- related tests: " + ", ".join(tests))
        if self.static_reasons:
            parts.append("- static signals: " + "; ".join(self.static_reasons[:3]))
        if self.security_hints:
            parts.append("- security surfaces: " + "; ".join(self.security_hints[:3]))
        if self.hotspot_hints:
            parts.append("- hotspot signals: " + "; ".join(self.hotspot_hints[:3]))
        parts.append(
            f"- module stats: defs={self.total_defs}, branches={self.total_branches}, lines={self.source_lines}"
        )
        return "\n".join(parts)


class RepoActivationIndex:
    def __init__(self, project_root: Path, files: list[Path], static_findings=None):
        self.project_root = project_root.resolve()
        self.files = [
            Path(f).resolve() for f in files if Path(f).suffix.lower() == ".py"
        ]
        self.static_findings = static_findings or {}
        self.by_path: dict[str, FileActivation] = {}

    def build(self) -> "RepoActivationIndex":
        if not self.files:
            return self

        module_by_path = {
            _norm_path(file_path): _module_name(self.project_root, file_path)
            for file_path in self.files
        }
        path_by_module = {
            module: path for path, module in module_by_path.items() if module
        }

        tests: list[tuple[str, str]] = []

        for file_path in self.files:
            norm = _norm_path(file_path)
            module = module_by_path[norm]
            meta = FileActivation(path=norm, module=module)
            self.by_path[norm] = meta

            try:
                source = file_path.read_text(encoding="utf-8")
            except Exception:
                continue

            meta.source_lines = len(source.splitlines())

            basename = file_path.name.lower()
            normalized_path = norm.replace("\\", "/").lower()
            if basename in ENTRYPOINT_BASENAMES:
                meta.entrypoint_reasons.append(f"conventional entry file `{basename}`")
            if (
                basename.startswith("test_")
                or basename.endswith("_test.py")
                or "tests" in file_path.parts
            ):
                tests.append((norm, source))
                meta.entrypoint_reasons.append("test module")
            if any(token in normalized_path for token in HIGH_SIGNAL_PATH_TOKENS):
                meta.security_hints.append("path suggests a security-sensitive surface")

            for token, label in SECURITY_TOKENS.items():
                if token in source:
                    meta.security_hints.append(label)

            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.If) and _is_main_guard(node.test):
                    meta.entrypoint_reasons.append("module has __main__ guard")

                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    meta.total_defs += 1
                    branches = _branch_count(node)
                    meta.total_branches += branches

                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if branches >= 5:
                            meta.hotspot_hints.append(
                                f"{node.name} is branch-heavy ({branches} control-flow points)"
                            )
                        arg_count = len(getattr(node.args, "args", [])) + len(
                            getattr(node.args, "kwonlyargs", [])
                        )
                        if arg_count >= 5:
                            meta.hotspot_hints.append(
                                f"{node.name} has a wide parameter surface ({arg_count} parameters)"
                            )
                        if getattr(node, "end_lineno", node.lineno) - node.lineno >= 35:
                            meta.hotspot_hints.append(
                                f"{node.name} is long enough to deserve review"
                            )

                    for decorator in getattr(node, "decorator_list", []):
                        name = _dotted_name(decorator)
                        if name and any(
                            token in name.lower() for token in REGISTRATION_TOKENS
                        ):
                            meta.registration_hints.append(
                                f"decorator `{name}` activates runtime behavior"
                            )

                if isinstance(node, ast.Import):
                    for alias in node.names:
                        target = alias.name
                        for i in range(len(target.split(".")), 0, -1):
                            prefix = ".".join(target.split(".")[:i])
                            imported_path = path_by_module.get(prefix)
                            if imported_path:
                                meta.imports.add(imported_path)
                                break
                elif isinstance(node, ast.ImportFrom):
                    module_name = node.module or ""
                    if node.level:
                        base_parts = module.split(".")
                        keep = max(0, len(base_parts) - node.level)
                        prefix = ".".join(base_parts[:keep])
                        module_name = (
                            f"{prefix}.{module_name}".strip(".")
                            if module_name
                            else prefix
                        )
                    for i in range(len(module_name.split(".")), 0, -1):
                        prefix = ".".join(module_name.split(".")[:i])
                        imported_path = path_by_module.get(prefix)
                        if imported_path:
                            meta.imports.add(imported_path)
                            break

            if meta.total_defs >= 8:
                meta.hotspot_hints.append(
                    f"module contains many definitions ({meta.total_defs})"
                )

        for meta in self.by_path.values():
            for imported in meta.imports:
                target = self.by_path.get(imported)
                if target:
                    target.imported_by.add(meta.path)

        for test_path, test_source in tests:
            lowered = test_source.lower()
            for meta in self.by_path.values():
                if meta.path == test_path:
                    continue
                file_stem = Path(meta.path).stem.lower()
                module_tokens = [file_stem]
                if meta.module:
                    module_tokens.append(meta.module.split(".")[-1].lower())
                if any(
                    token
                    and (
                        f"import {token}" in lowered
                        or f"from {token}" in lowered
                        or token in Path(test_path).stem.lower()
                    )
                    for token in module_tokens
                ):
                    meta.related_tests.append(test_path)

        self._apply_static_signals()
        self._score()
        return self

    def _apply_static_signals(self) -> None:
        weights = {"security": 100, "secrets": 100, "quality": 45}
        for category, weight in weights.items():
            for finding in self.static_findings.get(category, []) or []:
                file_path = _norm_path(finding.get("file", ""))
                meta = self.by_path.get(file_path)
                if not meta:
                    continue
                message = (finding.get("message") or category).strip()
                meta.static_reasons.append(f"{category}: {message}")
                meta.review_score += weight

    def _score(self) -> None:
        for meta in self.by_path.values():
            meta.review_score += min(90, 30 * len(meta.entrypoint_reasons))
            meta.review_score += min(60, 20 * len(meta.imported_by))
            meta.review_score += min(40, 10 * len(meta.registration_hints))
            meta.review_score += min(25, 5 * len(meta.related_tests))
            meta.review_score += min(35, 10 * len(meta.security_hints))
            meta.review_score += min(45, 10 * len(meta.hotspot_hints))
            if meta.source_lines >= 200:
                meta.review_score += 10
            if meta.total_branches >= 15:
                meta.review_score += 10

            meta.prefer_full_file_review = bool(
                meta.entrypoint_reasons
                or len(meta.imported_by) >= 2
                or meta.security_hints
                or meta.hotspot_hints
                or meta.review_score >= 120
            )

    def rank_files(
        self,
        *,
        changed_files=None,
        force_include_files=False,
        max_files=12,
    ) -> list[Path]:
        if changed_files:
            changed_norm = {_norm_path(f) for f in changed_files}
            return [Path(path) for path in self.by_path if path in changed_norm]

        ranked = sorted(
            self.by_path.values(),
            key=lambda item: (-item.review_score, item.path),
        )
        if force_include_files:
            return [Path(item.path) for item in ranked[:max_files]]
        return [Path(item.path) for item in ranked if item.review_score > 0][:max_files]

    def context_map_for(self, files) -> dict[str, str]:
        context = {}
        for file_path in files:
            norm = _norm_path(file_path)
            meta = self.by_path.get(norm)
            if meta:
                context[norm] = meta.context_block()
        return context

    def force_full_file_paths_for(self, files, *, limit=4) -> set[str]:
        preferred = []
        for file_path in files:
            meta = self.by_path.get(_norm_path(file_path))
            if meta and meta.prefer_full_file_review:
                preferred.append(meta)
        preferred.sort(key=lambda item: (-item.review_score, item.path))
        return {item.path for item in preferred[:limit]}


def build_repo_activation_index(
    python_files,
    *,
    project_root: str | Path | None = None,
    static_findings=None,
) -> RepoActivationIndex:
    files = [Path(f) for f in python_files if Path(f).suffix.lower() == ".py"]
    if not files:
        project_root = Path(project_root) if project_root is not None else Path.cwd()
        index = RepoActivationIndex(project_root, [], static_findings=static_findings)
        return index.build()

    if project_root is None:
        project_root = Path(files[0]).parent
    else:
        project_root = Path(project_root)
        try:
            first_file = files[0].resolve()
            root_resolved = project_root.resolve()
            if first_file != root_resolved and root_resolved not in first_file.parents:
                project_root = Path(Path.commonpath([str(f.resolve()) for f in files]))
        except Exception:
            project_root = Path(files[0]).parent

    index = RepoActivationIndex(
        Path(project_root), files, static_findings=static_findings
    )
    return index.build()
