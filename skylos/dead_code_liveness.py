from __future__ import annotations

import ast
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SENTINEL_CALLER = "<skylos.dead_code_liveness>"
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
        return {
            "rescued_count": len(self.rescued),
            "rescued": [
                {
                    "name": rescue.name,
                    "reason": rescue.reason,
                    "file": rescue.file,
                    "line": rescue.line,
                }
                for rescue in self.rescued
            ],
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
    docs_text = _read_public_docs(root)
    attr_calls = _collect_attr_calls(py_files)

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
    return bool(
        getattr(defn, "references", 0) > 0
        or getattr(defn, "is_exported", False)
        or _is_public_name(getattr(defn, "simple_name", ""))
    )


def _is_public_name(name: str) -> bool:
    return bool(name and not name.startswith("_"))


def _owner_live(classes: dict[str, Any], owner: str) -> bool:
    class_def = classes.get(owner)
    return bool(class_def and _is_live_class(class_def))


def _is_support_file(defn: Any) -> bool:
    try:
        parts = {part.lower() for part in Path(getattr(defn, "filename", "")).parts}
    except TypeError:
        return False
    return bool(parts & {"test", "tests", "docs", "examples"})


def _python_files(root: Path, files: Iterable[str | Path] | None) -> list[Path]:
    if files is not None:
        return [Path(f) for f in files if Path(f).suffix == ".py"]
    if not root.exists():
        return []
    ignored = {".git", ".venv", "venv", "__pycache__"}
    return [path for path in root.rglob("*.py") if not any(p in ignored for p in path.parts)]


def _read_public_docs(root: Path) -> str:
    if not root.exists() or not root.is_dir():
        return ""

    ignored = {".git", ".venv", "venv", "__pycache__"}
    parts: list[str] = []
    seen_bytes = 0
    for path in root.rglob("*"):
        if not path.is_file() or any(part in ignored for part in path.parts):
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


def _collect_attr_calls(files: Iterable[Path]) -> list[_AttrCall]:
    calls: list[_AttrCall] = []
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                calls.append(
                    _AttrCall(
                        node.func.attr,
                        _attr_call_base_name(node.func),
                        path,
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
    conditional_imports = [
        defn
        for defn in definitions.values()
        if getattr(defn, "type", None) == "import"
        and getattr(defn, "conditional_import", False)
    ]
    if not conditional_imports:
        return

    referenced_simples = {str(ref).rsplit(".", 1)[-1] for ref, _ref_file in refs}
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
        base_names = {
            base
            for base in getattr(class_def, "base_classes", [])
            if isinstance(base, str)
        }
        base_names.update(base.rsplit(".", 1)[-1] for base in list(base_names))
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
            decorators = {
                str(deco).rsplit(".", 1)[-1].lower()
                for deco in getattr(method, "decorators", [])
            }
            looks_registered = (
                any(word in name.lower() for word in REGISTRATION_WORDS)
                or bool(decorators & {"setupmethod", "route", "command", "receiver"})
            )
            if looks_registered and _stores_and_returns_callable(method):
                _mark(method, "registration_api", report)


def _stores_and_returns_callable(method: Any) -> bool:
    node = getattr(method, "node", None)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    params = [arg.arg for arg in node.args.args]
    if params and params[0] in {"self", "cls"}:
        params = params[1:]
    if not params:
        return False
    first_param = params[0]
    stores_param = False
    returns_param = False
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in REGISTRATION_MUTATORS
                and isinstance(func.value, ast.Attribute)
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id in {"self", "cls"}
                and any(isinstance(arg, ast.Name) and arg.id == first_param for arg in child.args)
            ):
                stores_param = True
        elif isinstance(child, ast.Return):
            if isinstance(child.value, ast.Name) and child.value.id == first_param:
                returns_param = True
    return stores_param and returns_param


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
            if _is_public_name(name) and _docs_reference_method(docs_text, class_name, name):
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
    return any(re.search(pattern, text) for pattern in patterns)


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

    call_count = Counter(call.attr for call in attr_calls)
    calls_by_attr: dict[str, list[_AttrCall]] = defaultdict(list)
    for call in attr_calls:
        calls_by_attr[call.attr].append(call)

    for method_name, owner_methods in method_by_simple.items():
        if len(owner_methods) != 1:
            continue
        if method_name in COMMON_UNTYPED_ATTR_CALLS or call_count.get(method_name, 0) == 0:
            continue
        _owner, method = owner_methods[0]
        method_file = Path(getattr(method, "filename", "")).resolve()
        external_calls = [
            call
            for call in calls_by_attr[method_name]
            if call.file.resolve() != method_file
            and call.base_name in FRAMEWORK_PROXY_NAMES
        ]
        if external_calls:
            _mark(method, "unique_external_attr_call", report)

