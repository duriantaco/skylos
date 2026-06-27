from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from skylos.core.python_api_surface import cache_python_api_surface
from skylos.core.safe_cache_io import read_text_no_symlink


RULE_ID_API_SIGNATURE = "SKY-D224"
SEV_HIGH = "HIGH"
DEFAULT_API_SIGNATURE_ALLOWLIST = ("requests", "pandas", "boto3", "openai")
VIBE_CATEGORY = "api_signature_hallucination"
AI_LIKELIHOOD = "high"
MAX_PYTHON_API_SIGNATURE_SOURCE_BYTES = 1_000_000

SurfaceLoader = Callable[[str | Path, str], dict[str, Any] | None]


@dataclass(frozen=True)
class _CallTarget:
    module_name: str
    label: str
    entry: dict[str, Any] | None
    missing_kind: str


class _ApiSignatureChecker(ast.NodeVisitor):
    def __init__(
        self,
        project_root: Path,
        file_path: Path,
        allowed_roots: set[str],
        local_modules: set[str],
        surfaces: dict[str, dict[str, Any] | None],
        surface_loader: SurfaceLoader,
        findings: list[dict[str, Any]],
    ) -> None:
        self.project_root = project_root
        self.file_path = file_path
        self.allowed_roots = allowed_roots
        self.local_modules = local_modules
        self.surfaces = surfaces
        self.surface_loader = surface_loader
        self.findings = findings
        self.module_aliases: dict[str, str] = {}
        self.function_aliases: dict[str, tuple[str, str]] = {}
        self.class_aliases: dict[str, tuple[str, str]] = {}
        self.instance_stack: list[dict[str, tuple[str, str]]] = [{}]

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module_name = _safe_module_name(alias.name)
            if module_name is None:
                continue
            if not self._allowed_module(module_name):
                continue

            local_name = _import_alias_name(alias, module_name)
            self.module_aliases[local_name] = module_name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module_name = _safe_module_name(node.module)
        if module_name is None:
            self.generic_visit(node)
            return
        if not self._allowed_module(module_name):
            self.generic_visit(node)
            return

        for alias in node.names:
            imported_name = _safe_member_name(alias.name)
            if imported_name is None:
                continue

            local_name = _member_alias_name(alias, imported_name)
            member = self._module_member(module_name, imported_name)
            if _entry_kind(member) == "class":
                self.class_aliases[local_name] = (module_name, imported_name)
                continue
            if member is not None:
                self.function_aliases[local_name] = (module_name, imported_name)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.instance_stack.append({})
        self.generic_visit(node)
        self.instance_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.instance_stack.append({})
        self.generic_visit(node)
        self.instance_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        constructed = self._constructed_class(node.value)
        if constructed is not None:
            for target in node.targets:
                for name in _assigned_names(target):
                    self._current_instances()[name] = constructed
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        target = self._call_target(node)
        if target is not None:
            self._check_call_target(node, target)
        self.generic_visit(node)

    def _allowed_module(self, module_name: str) -> bool:
        root = _module_root(module_name)
        if root in self.local_modules:
            return False
        return root in self.allowed_roots

    def _current_instances(self) -> dict[str, tuple[str, str]]:
        return self.instance_stack[-1]

    def _instance_type(self, name: str) -> tuple[str, str] | None:
        for instances in reversed(self.instance_stack):
            instance_type = instances.get(name)
            if instance_type is not None:
                return instance_type
        return None

    def _surface(self, module_name: str) -> dict[str, Any] | None:
        if module_name not in self.surfaces:
            self.surfaces[module_name] = self.surface_loader(
                self.project_root,
                module_name,
            )
        return self.surfaces[module_name]

    def _module_member(
        self,
        module_name: str,
        member_name: str,
    ) -> dict[str, Any] | None:
        surface = self._surface(module_name)
        if surface is None:
            return None

        members = surface.get("members")
        if not isinstance(members, dict):
            return None

        member = members.get(member_name)
        if isinstance(member, dict):
            return member
        return None

    def _constructed_class(self, value: ast.AST) -> tuple[str, str] | None:
        if not isinstance(value, ast.Call):
            return None

        target = self._call_target(value)
        if target is None:
            return None
        if target.entry is None:
            return None
        if _entry_kind(target.entry) != "class":
            return None

        parts = target.label.split(".")
        if len(parts) < 2:
            return None
        class_name = parts[-1]
        return target.module_name, class_name

    def _call_target(self, node: ast.Call) -> _CallTarget | None:
        func = node.func
        if isinstance(func, ast.Name):
            return self._name_call_target(func.id)
        if isinstance(func, ast.Attribute):
            return self._attribute_call_target(func)
        return None

    def _name_call_target(self, name: str) -> _CallTarget | None:
        function_alias = self.function_aliases.get(name)
        if function_alias is not None:
            module_name, member_name = function_alias
            entry = self._module_member(module_name, member_name)
            return _CallTarget(module_name, f"{module_name}.{member_name}", entry, "")

        class_alias = self.class_aliases.get(name)
        if class_alias is not None:
            module_name, class_name = class_alias
            entry = self._module_member(module_name, class_name)
            return _CallTarget(module_name, f"{module_name}.{class_name}", entry, "")

        return None

    def _attribute_call_target(self, func: ast.Attribute) -> _CallTarget | None:
        value = func.value
        resource_target = self._instance_resource_method_target(func)
        if resource_target is not None:
            return resource_target

        if isinstance(value, ast.Name):
            module_target = self._module_attribute_target(value.id, func.attr)
            if module_target is not None:
                return module_target

            instance_target = self._instance_method_target(value.id, func.attr)
            if instance_target is not None:
                return instance_target

        return None

    def _instance_resource_method_target(
        self,
        func: ast.Attribute,
    ) -> _CallTarget | None:
        chain = _flatten_attribute_chain(func)
        if chain is None:
            return None
        if len(chain) < 3:
            return None

        instance_type = self._instance_type(chain[0])
        if instance_type is None:
            return None

        module_name, class_name = instance_type
        current_entry = self._module_member(module_name, class_name)
        if current_entry is None:
            return None

        for property_name in chain[1:-1]:
            properties = _entry_properties(current_entry)
            property_entry = properties.get(property_name)
            if not isinstance(property_entry, dict):
                label = f"{module_name}.{class_name}.{'.'.join(chain[1:])}"
                return _CallTarget(module_name, label, None, "method")
            current_entry = property_entry

        method_name = chain[-1]
        methods = _entry_methods(current_entry)
        method = methods.get(method_name)
        label = f"{module_name}.{class_name}.{'.'.join(chain[1:])}"
        if not isinstance(method, dict):
            return _CallTarget(module_name, label, None, "method")
        return _CallTarget(module_name, label, method, "")

    def _module_attribute_target(
        self,
        alias_name: str,
        member_name: str,
    ) -> _CallTarget | None:
        module_name = self.module_aliases.get(alias_name)
        if module_name is None:
            return None

        entry = self._module_member(module_name, member_name)
        label = f"{module_name}.{member_name}"
        if entry is None:
            return _CallTarget(module_name, label, None, "module_member")
        return _CallTarget(module_name, label, entry, "")

    def _instance_method_target(
        self,
        instance_name: str,
        method_name: str,
    ) -> _CallTarget | None:
        instance_type = self._instance_type(instance_name)
        if instance_type is None:
            return None

        module_name, class_name = instance_type
        class_entry = self._module_member(module_name, class_name)
        methods = _entry_methods(class_entry)
        method = methods.get(method_name)
        label = f"{module_name}.{class_name}.{method_name}"
        if not isinstance(method, dict):
            return _CallTarget(module_name, label, None, "method")
        return _CallTarget(module_name, label, method, "")

    def _check_call_target(self, node: ast.Call, target: _CallTarget) -> None:
        if target.entry is None:
            self._add_missing_finding(node, target)
            return

        for keyword in node.keywords:
            if keyword.arg is None:
                continue
            if _keyword_accepted(target.entry, keyword.arg):
                continue
            self._add_keyword_finding(node, target, keyword.arg)

    def _add_missing_finding(self, node: ast.AST, target: _CallTarget) -> None:
        if target.missing_kind == "method":
            message = f"Installed API '{target.label}' does not expose this method."
        else:
            message = (
                f"Installed package '{target.module_name}' does not expose "
                f"callable API '{target.label}'."
            )
        self.findings.append(_finding(self.file_path, node, target.label, message))

    def _add_keyword_finding(
        self,
        node: ast.AST,
        target: _CallTarget,
        keyword: str,
    ) -> None:
        message = (
            f"Installed API '{target.label}' does not accept keyword "
            f"argument '{keyword}'."
        )
        self.findings.append(_finding(self.file_path, node, target.label, message))


def scan_python_api_signature_hallucinations(
    repo_root: str | Path | None,
    py_files: list[Path],
    *,
    allowed_modules: tuple[str, ...] | None = None,
    surface_loader: SurfaceLoader | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    root = _repo_root(repo_root)
    if root is None:
        return findings

    allowed_roots = _allowed_roots(allowed_modules)
    if not allowed_roots:
        return findings

    loader = _surface_loader(surface_loader)
    local_modules = _local_module_roots(root, py_files)
    surfaces: dict[str, dict[str, Any] | None] = {}

    for file_path in py_files:
        tree = _parse_python_file(root, file_path)
        if tree is None:
            continue

        checker = _ApiSignatureChecker(
            root,
            file_path,
            allowed_roots,
            local_modules,
            surfaces,
            loader,
            findings,
        )
        checker.visit(tree)

    return findings


def _repo_root(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    try:
        return Path(value).resolve()
    except OSError:
        return Path(value)


def _surface_loader(surface_loader: SurfaceLoader | None) -> SurfaceLoader:
    if surface_loader is not None:
        return surface_loader
    return cache_python_api_surface


def _allowed_roots(allowed_modules: tuple[str, ...] | None) -> set[str]:
    source = allowed_modules
    if source is None:
        source = DEFAULT_API_SIGNATURE_ALLOWLIST

    roots: set[str] = set()
    for module_name in source:
        safe_name = _safe_module_name(module_name)
        if safe_name is None:
            continue
        roots.add(_module_root(safe_name))
    return roots


def _parse_python_file(root: Path, file_path: Path) -> ast.AST | None:
    try:
        resolved = Path(file_path).resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None

    if not resolved.is_file():
        return None

    source = read_text_no_symlink(
        resolved,
        max_bytes=MAX_PYTHON_API_SIGNATURE_SOURCE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if source is None:
        return None

    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _safe_module_name(value: Any) -> str | None:
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    parts = raw.split(".")
    for part in parts:
        if not part:
            return None
        if not part.isidentifier():
            return None
    return raw


def _safe_member_name(value: Any) -> str | None:
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None
    if not raw.isidentifier():
        return None
    return raw


def _module_root(module_name: str) -> str:
    parts = module_name.split(".")
    return parts[0]


def _import_alias_name(alias: ast.alias, module_name: str) -> str:
    if alias.asname:
        return alias.asname
    return _module_root(module_name)


def _member_alias_name(alias: ast.alias, imported_name: str) -> str:
    if alias.asname:
        return alias.asname
    return imported_name


def _assigned_names(target: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
        return names
    if isinstance(target, (ast.Tuple, ast.List)):
        for item in target.elts:
            names.extend(_assigned_names(item))
    return names


def _flatten_attribute_chain(expr: ast.AST) -> list[str] | None:
    parts: list[str] = []
    current = expr

    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value

    if not isinstance(current, ast.Name):
        return None

    parts.append(current.id)
    parts.reverse()
    return parts


def _local_module_roots(project_root: Path, py_files: list[Path]) -> set[str]:
    roots: set[str] = set()
    for root_name in _top_level_python_modules(project_root):
        roots.add(root_name)

    for file_path in py_files:
        relative = _relative_path(project_root, file_path)
        if relative is None:
            continue

        root = _module_root_for_relative_path(relative)
        if root is not None:
            roots.add(root)
    return roots


def _top_level_python_modules(project_root: Path) -> set[str]:
    modules: set[str] = set()
    try:
        children = list(project_root.iterdir())
    except OSError:
        return modules

    for child in children:
        if child.name.startswith("."):
            continue
        if child.is_symlink():
            continue

        module_name = _top_level_file_module(child)
        if module_name is not None:
            modules.add(module_name)
            continue

        module_name = _top_level_package_module(child)
        if module_name is not None:
            modules.add(module_name)
    return modules


def _module_root_for_relative_path(relative: Path) -> str | None:
    if not relative.parts:
        return None
    if len(relative.parts) > 1:
        return relative.parts[0]
    if relative.stem == "__init__":
        return None
    return relative.stem


def _top_level_file_module(path: Path) -> str | None:
    if not path.is_file():
        return None
    if path.suffix != ".py":
        return None
    if path.stem == "__init__":
        return None
    return path.stem


def _top_level_package_module(path: Path) -> str | None:
    if not path.is_dir():
        return None
    init_file = path / "__init__.py"
    if not init_file.exists():
        return None
    return path.name


def _relative_path(project_root: Path, file_path: Path) -> Path | None:
    try:
        return file_path.resolve().relative_to(project_root)
    except (OSError, ValueError):
        return None


def _entry_kind(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return ""

    kind = entry.get("kind")
    if isinstance(kind, str):
        return kind
    return ""


def _entry_methods(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}

    methods = entry.get("methods")
    if isinstance(methods, dict):
        return methods
    return {}


def _entry_properties(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}

    properties = entry.get("properties")
    if isinstance(properties, dict):
        return properties
    return {}


def _keyword_accepted(entry: dict[str, Any], keyword: str) -> bool:
    parameters = entry.get("parameters")
    if not isinstance(parameters, list):
        return True
    if not parameters:
        return True

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue

        kind = str(parameter.get("kind"))
        if kind == "VAR_KEYWORD":
            return True

        name = parameter.get("name")
        if name != keyword:
            continue
        if kind == "POSITIONAL_OR_KEYWORD":
            return True
        if kind == "KEYWORD_ONLY":
            return True

    return False


def _finding(
    file_path: Path,
    node: ast.AST,
    symbol: str,
    message: str,
) -> dict[str, Any]:
    line = getattr(node, "lineno", 1)
    col = getattr(node, "col_offset", 0)
    return {
        "rule_id": RULE_ID_API_SIGNATURE,
        "severity": SEV_HIGH,
        "message": message,
        "file": str(file_path),
        "line": line,
        "col": col,
        "symbol": symbol,
        "category": "ai_defect",
        "defect_type": VIBE_CATEGORY,
        "vibe_category": VIBE_CATEGORY,
        "ai_likelihood": AI_LIKELIHOOD,
        "confidence": 88,
    }
