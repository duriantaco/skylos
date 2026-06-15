from __future__ import annotations

import ast
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from skylos.deadcode.plugin_registry import find_literal_plugin_registry_targets
from skylos.deadcode.python_ast import ParsedPythonFile, parse_python_files


SENTINEL_CALLER = "<skylos.deadcode.liveness>"
DOC_EXTS = {".md", ".rst", ".txt"}
DOC_NAMES = {"README", "FAQ"}
REGISTRATION_WORDS = (
    "callback",
    "command",
    "decorator",
    "handler",
    "hook",
    "listener",
    "processor",
    "receiver",
    "register",
    "route",
    "signal",
    "subscriber",
)
REGISTRATION_MUTATORS = {"add", "append", "extend", "insert", "register", "setdefault"}
PROTOCOL_METHODS_BY_BASE = {
    "Handler": {"emit"},
    "logging.Handler": {"emit"},
    "Formatter": {"format", "formatException", "formatMessage", "formatTime"},
    "logging.Formatter": {"format", "formatException", "formatMessage", "formatTime"},
}
COMMON_UNTYPED_ATTR_CALLS = {
    "add",
    "append",
    "clear",
    "close",
    "copy",
    "extend",
    "format",
    "get",
    "items",
    "keys",
    "pop",
    "read",
    "remove",
    "render",
    "setdefault",
    "update",
    "values",
    "write",
}
FRAMEWORK_PROXY_NAMES = {"current_app"}
_DISABLE_VALUES = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class LivenessRescue:
    name: str
    reason: str
    file: str
    line: int


@dataclass
class LivenessReport:
    rescued: list[LivenessRescue] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        rescued_items: list[dict[str, Any]] = []
        for rescue in self.rescued:
            rescued_items.append(
                {
                    "name": rescue.name,
                    "reason": rescue.reason,
                    "file": rescue.file,
                    "line": rescue.line,
                }
            )
        return {
            "rescued_count": len(self.rescued),
            "rescued": rescued_items,
        }


@dataclass(frozen=True)
class _AttrCall:
    attr: str
    base_name: str
    file: Path
    line: int


def apply_dead_code_liveness(
    definitions: dict[str, Any],
    refs: Iterable[tuple[str, Any]],
    project_root: str | Path,
    files: Iterable[str | Path] | None = None,
) -> LivenessReport:

    report = LivenessReport()
    if os.getenv("SKYLOS_DEAD_CODE_LIVENESS", "1").lower() in _DISABLE_VALUES:
        return report

    root = Path(project_root).resolve()
    py_files = _python_files(root, files)
    parsed_files = parse_python_files(py_files)
    docs_text = _read_public_docs(root)
    attr_calls = _collect_attr_calls(parsed_files)

    classes: dict[str, Any] = {}
    class_methods: dict[str, list[Any]] = defaultdict(list)
    for defn in definitions.values():
        if getattr(defn, "type", None) == "class":
            classes[getattr(defn, "name", "")] = defn
        elif getattr(defn, "type", None) == "method" and "." in getattr(
            defn, "name", ""
        ):
            class_methods[defn.name.rsplit(".", 1)[0]].append(defn)

    _rescue_optional_import_fallbacks(definitions, refs, report)
    _rescue_protocol_overrides(classes, class_methods, report)
    _rescue_registration_methods(classes, class_methods, report)
    for target in find_literal_plugin_registry_targets(definitions, parsed_files):
        _mark(target, "literal_plugin_registry", report)
    _rescue_documented_public_methods(classes, class_methods, docs_text, report)
    _rescue_unique_external_attr_calls(classes, class_methods, attr_calls, report)
    return report


def _mark(defn: Any, reason: str, report: LivenessReport) -> None:
    if getattr(defn, "references", 0) <= 0:
        defn.references += 1
    refs = getattr(defn, "heuristic_refs", None)
    if refs is not None:
        refs[f"dead_code_liveness:{reason}"] = 1.0
    signals = getattr(defn, "framework_signals", None)
    if signals is not None and reason not in signals:
        signals.append(reason)
    called_by = getattr(defn, "called_by", None)
    if called_by is not None:
        called_by.add(SENTINEL_CALLER)
    report.rescued.append(
        LivenessRescue(
            name=str(getattr(defn, "name", "")),
            reason=reason,
            file=str(getattr(defn, "filename", "")),
            line=int(getattr(defn, "line", 0) or 0),
        )
    )


def _is_live_class(defn: Any) -> bool:
    if getattr(defn, "references", 0) > 0:
        return True
    if getattr(defn, "is_exported", False):
        return True
    if _is_public_name(getattr(defn, "simple_name", "")):
        return True
    return False


def _is_public_name(name: str) -> bool:
    return bool(name and not name.startswith("_"))


def _owner_live(classes: dict[str, Any], owner: str) -> bool:
    class_def = classes.get(owner)
    if not class_def:
        return False
    return _is_live_class(class_def)


def _is_support_file(defn: Any) -> bool:
    try:
        path_parts = Path(getattr(defn, "filename", "")).parts
    except TypeError:
        return False
    for part in path_parts:
        if part.lower() in {"test", "tests", "docs", "examples"}:
            return True
    return False


def _python_files(root: Path, files: Iterable[str | Path] | None) -> list[Path]:
    if files is not None:
        explicit_files: list[Path] = []
        for file in files:
            path = Path(file)
            if path.suffix == ".py":
                explicit_files.append(path)
        return explicit_files
    if not root.exists():
        return []
    ignored = {".git", ".venv", "venv", "__pycache__"}
    python_files: list[Path] = []
    for path in root.rglob("*.py"):
        if _path_has_ignored_part(path, ignored):
            continue
        python_files.append(path)
    return python_files


def _path_has_ignored_part(path: Path, ignored: set[str]) -> bool:
    for part in path.parts:
        if part in ignored:
            return True
    return False


def _read_public_docs(root: Path) -> str:
    if not root.exists() or not root.is_dir():
        return ""

    ignored = {".git", ".venv", "venv", "__pycache__"}
    parts: list[str] = []
    seen_bytes = 0
    for path in root.rglob("*"):
        if not path.is_file() or _path_has_ignored_part(path, ignored):
            continue
        if path.suffix.lower() not in DOC_EXTS and path.stem.upper() not in DOC_NAMES:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > 300_000:
            continue
        if seen_bytes + size > 2_000_000:
            break
        try:
            parts.append(path.read_text(encoding="utf-8", errors="ignore"))
            seen_bytes += size
        except OSError:
            continue
    return "\n".join(parts)


def _collect_attr_calls(files: Iterable[ParsedPythonFile]) -> list[_AttrCall]:
    calls: list[_AttrCall] = []
    for parsed in files:
        for node in ast.walk(parsed.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                calls.append(
                    _AttrCall(
                        node.func.attr,
                        _attr_call_base_name(node.func),
                        parsed.path,
                        getattr(node, "lineno", 0),
                    )
                )
    return calls


def _attr_call_base_name(func: ast.Attribute) -> str:
    value = func.value
    if isinstance(value, ast.Name):
        return value.id
    while isinstance(value, ast.Attribute):
        value = value.value
    if isinstance(value, ast.Name):
        return value.id
    return ""


def _rescue_optional_import_fallbacks(
    definitions: dict[str, Any],
    refs: Iterable[tuple[str, Any]],
    report: LivenessReport,
) -> None:
    conditional_imports = []
    for defn in definitions.values():
        if getattr(defn, "type", None) != "import":
            continue
        if not getattr(defn, "conditional_import", False):
            continue
        conditional_imports.append(defn)
    if not conditional_imports:
        return

    referenced_simples: set[str] = set()
    for ref, _ref_file in refs:
        referenced_simples.add(str(ref).rsplit(".", 1)[-1])

    conditional_by_file: dict[tuple[str, str], bool] = {}
    for imp in conditional_imports:
        simple = getattr(imp, "simple_name", "")
        if simple:
            conditional_by_file[(str(Path(imp.filename).resolve()), simple)] = True

    for defn in definitions.values():
        if getattr(defn, "type", None) not in {"class", "function"}:
            continue
        simple = getattr(defn, "simple_name", "")
        if simple not in referenced_simples:
            continue
        key = (str(Path(defn.filename).resolve()), simple)
        if key in conditional_by_file:
            _mark(defn, "optional_import_fallback", report)


def _rescue_protocol_overrides(
    classes: dict[str, Any],
    class_methods: dict[str, list[Any]],
    report: LivenessReport,
) -> None:
    for owner, methods in class_methods.items():
        class_def = classes.get(owner)
        if not class_def:
            continue
        base_names = _base_names_for_class(class_def)
        live_methods: set[str] = set()
        for base in base_names:
            live_methods.update(PROTOCOL_METHODS_BY_BASE.get(base, set()))
        for method in methods:
            if getattr(method, "simple_name", "") in live_methods:
                _mark(method, "protocol_override", report)


def _rescue_registration_methods(
    classes: dict[str, Any],
    class_methods: dict[str, list[Any]],
    report: LivenessReport,
) -> None:
    for owner, methods in class_methods.items():
        if not _owner_live(classes, owner):
            continue
        for method in methods:
            if _is_support_file(method):
                continue
            name = getattr(method, "simple_name", "")
            if not _is_public_name(name):
                continue
            decorators = _decorator_leaf_names(method)
            if not _looks_registered_method(name, decorators):
                continue
            if not _stores_and_returns_callable(method):
                continue
            _mark(method, "registration_api", report)


def _base_names_for_class(class_def: Any) -> set[str]:
    base_names: set[str] = set()
    for base in getattr(class_def, "base_classes", []):
        if not isinstance(base, str):
            continue
        base_names.add(base)
        base_names.add(base.rsplit(".", 1)[-1])
    return base_names


def _decorator_leaf_names(method: Any) -> set[str]:
    decorators: set[str] = set()
    for decorator in getattr(method, "decorators", []):
        decorators.add(str(decorator).rsplit(".", 1)[-1].lower())
    return decorators


def _looks_registered_method(name: str, decorators: set[str]) -> bool:
    lowered_name = name.lower()
    for word in REGISTRATION_WORDS:
        if word in lowered_name:
            return True
    for decorator in decorators:
        if decorator in {"setupmethod", "route", "command", "receiver"}:
            return True
    return False


def _stores_and_returns_callable(method: Any) -> bool:
    node = getattr(method, "node", None)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    params: list[str] = []
    for arg in node.args.args:
        params.append(arg.arg)
    if params and params[0] in {"self", "cls"}:
        params = params[1:]
    if not params:
        return False
    first_param = params[0]
    stores_param = False
    returns_param = False
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if _call_stores_param_on_self_or_cls(child, first_param):
                stores_param = True
        elif isinstance(child, ast.Return):
            if isinstance(child.value, ast.Name) and child.value.id == first_param:
                returns_param = True
    return stores_param and returns_param


def _call_stores_param_on_self_or_cls(call: ast.Call, param_name: str) -> bool:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in REGISTRATION_MUTATORS:
        return False
    if not isinstance(func.value, ast.Attribute):
        return False
    receiver = func.value.value
    if not isinstance(receiver, ast.Name):
        return False
    if receiver.id not in {"self", "cls"}:
        return False
    return _call_has_arg_name(call, param_name)


def _call_has_arg_name(call: ast.Call, name: str) -> bool:
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id == name:
            return True
    return False


def _rescue_documented_public_methods(
    classes: dict[str, Any],
    class_methods: dict[str, list[Any]],
    docs_text: str,
    report: LivenessReport,
) -> None:
    if not docs_text:
        return
    for owner, methods in class_methods.items():
        if not _owner_live(classes, owner):
            continue
        class_name = owner.rsplit(".", 1)[-1]
        for method in methods:
            if _is_support_file(method):
                continue
            name = getattr(method, "simple_name", "")
            if _is_public_name(name) and _docs_reference_method(
                docs_text, class_name, name
            ):
                _mark(method, "documented_public_api", report)


def _docs_reference_method(text: str, class_name: str, method_name: str) -> bool:
    escaped_class = re.escape(class_name)
    escaped_method = re.escape(method_name)
    patterns = [
        rf"\b{escaped_class}\.{escaped_method}\b",
        rf":meth:`[^`]*{escaped_class}\.{escaped_method}`",
        rf":meth:`[^`]*{escaped_method}`",
    ]
    if "_" in method_name and len(method_name) >= 10:
        patterns.append(rf"\.[ \t]*{escaped_method}\(")
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False


def _rescue_unique_external_attr_calls(
    classes: dict[str, Any],
    class_methods: dict[str, list[Any]],
    attr_calls: list[_AttrCall],
    report: LivenessReport,
) -> None:
    if not attr_calls:
        return

    method_by_simple: dict[str, list[tuple[str, Any]]] = defaultdict(list)
    for owner, methods in class_methods.items():
        if not _owner_live(classes, owner):
            continue
        for method in methods:
            if _is_support_file(method):
                continue
            name = getattr(method, "simple_name", "")
            if _is_public_name(name):
                method_by_simple[name].append((owner, method))

    call_count: Counter[str] = Counter()
    calls_by_attr: dict[str, list[_AttrCall]] = defaultdict(list)
    for call in attr_calls:
        call_count[call.attr] += 1
        calls_by_attr[call.attr].append(call)

    for method_name, owner_methods in method_by_simple.items():
        if len(owner_methods) != 1:
            continue
        if method_name in COMMON_UNTYPED_ATTR_CALLS:
            continue
        if call_count.get(method_name, 0) == 0:
            continue
        _owner, method = owner_methods[0]
        method_file = Path(getattr(method, "filename", "")).resolve()
        if _has_external_framework_proxy_call(calls_by_attr[method_name], method_file):
            _mark(method, "unique_external_attr_call", report)


def _has_external_framework_proxy_call(
    calls: list[_AttrCall],
    method_file: Path,
) -> bool:
    for call in calls:
        if call.file.resolve() == method_file:
            continue
        if call.base_name not in FRAMEWORK_PROXY_NAMES:
            continue
        return True
    return False
