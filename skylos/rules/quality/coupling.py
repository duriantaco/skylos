import ast
from pathlib import Path
from typing import Any, Optional

from skylos.rules.base import SkylosRule

BUILTIN_TYPES = frozenset({
    "int", "str", "float", "bool", "bytes", "list", "dict", "set", "tuple",
    "frozenset", "type", "object", "None", "complex", "bytearray",
    "memoryview", "range", "slice", "property", "classmethod", "staticmethod",
    "Exception", "BaseException", "ValueError", "TypeError", "KeyError",
    "IndexError", "AttributeError", "RuntimeError", "StopIteration",
    "OSError", "IOError", "FileNotFoundError", "NotImplementedError",
})

TYPING_WRAPPERS = frozenset({
    "Optional", "Union", "List", "Dict", "Set", "Tuple", "FrozenSet",
    "Type", "ClassVar", "Final", "Literal", "Annotated", "Callable",
    "Iterator", "Iterable", "Generator", "AsyncIterator", "AsyncIterable",
    "Awaitable", "Coroutine", "Sequence", "MutableSequence", "Mapping",
    "MutableMapping", "Any",
})

FRAMEWORK_EXPECTED_COUPLING = frozenset({
    "models.Model", "models.Manager", "admin.ModelAdmin",
    "forms.ModelForm", "forms.Form", "views.View",
    "serializers.ModelSerializer", "serializers.Serializer",
    "viewsets.ModelViewSet", "viewsets.ViewSet",
    "permissions.BasePermission", "TestCase", "SimpleTestCase",
})


def _extract_type_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    if node is None:
        return names

    if isinstance(node, ast.Name):
        if node.id not in BUILTIN_TYPES and node.id not in TYPING_WRAPPERS:
            names.add(node.id)

    elif isinstance(node, ast.Attribute):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        full = ".".join(reversed(parts))
        names.add(full)

    elif isinstance(node, ast.Subscript):
        names.update(_extract_type_names(node.value))
        names.update(_extract_type_names(node.slice))

    elif isinstance(node, ast.Tuple):
        for elt in node.elts:
            names.update(_extract_type_names(elt))

    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        names.update(_extract_type_names(node.left))
        names.update(_extract_type_names(node.right))

    elif isinstance(node, ast.Constant) and node.value is None:
        pass

    elif isinstance(node, ast.List):
        for elt in node.elts:
            names.update(_extract_type_names(elt))

    return names


class _ClassInfo:
    __slots__ = (
        "name", "lineno", "col_offset", "bases", "decorators",
        "type_deps", "instantiation_deps", "attribute_deps",
        "import_deps", "decorator_deps", "protocol_abc_deps",
        "is_protocol", "is_abc", "is_dataclass", "methods",
    )

    def __init__(self, name: str, lineno: int, col_offset: int):
        self.name = name
        self.lineno = lineno
        self.col_offset = col_offset
        self.bases: set[str] = set()
        self.decorators: set[str] = set()
        self.type_deps: set[str] = set()
        self.instantiation_deps: set[str] = set()
        self.attribute_deps: set[str] = set()
        self.import_deps: set[str] = set()
        self.decorator_deps: set[str] = set()
        self.protocol_abc_deps: set[str] = set()
        self.is_protocol = False
        self.is_abc = False
        self.is_dataclass = False
        self.methods: list[str] = []


def _get_decorator_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return None


def analyze_coupling(tree: ast.AST, filename: str) -> dict[str, Any]:
    classes: dict[str, _ClassInfo] = {}
    module_imports: dict[str, str] = {}
    known_classes: set[str] = set()

    # first pass, collect all class definitions and imports
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            info = _ClassInfo(node.name, node.lineno, node.col_offset)
            known_classes.add(node.name)

            for base in node.bases:
                for name in _extract_type_names(base):
                    info.bases.add(name)

            for dec in node.decorator_list:
                dec_name = _get_decorator_name(dec)
                if dec_name:
                    info.decorators.add(dec_name)
                    if dec_name in ("dataclass", "dataclasses.dataclass"):
                        info.is_dataclass = True

            for base in node.bases:
                if isinstance(base, ast.Name):
                    if base.id == "Protocol":
                        info.is_protocol = True
                    elif base.id in ("ABC", "ABCMeta"):
                        info.is_abc = True
                elif isinstance(base, ast.Attribute):
                    if base.attr == "Protocol":
                        info.is_protocol = True
                    elif base.attr in ("ABC", "ABCMeta"):
                        info.is_abc = True

            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    info.methods.append(item.name)

            classes[node.name] = info

        elif isinstance(node, ast.Import):
            for alias in node.names:
                module_imports[alias.asname or alias.name] = alias.name

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for alias in node.names:
                    module_imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    # second pass analyze coupling for each class
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if node.name not in classes:
            continue

        info = classes[node.name]

        for child in ast.walk(node):
            if isinstance(child, ast.AnnAssign) and child.annotation:
                for name in _extract_type_names(child.annotation):
                    if name != node.name and name not in BUILTIN_TYPES:
                        info.type_deps.add(name)

            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.returns:
                    for name in _extract_type_names(child.returns):
                        if name != node.name and name not in BUILTIN_TYPES:
                            info.type_deps.add(name)

                for arg in child.args.args + child.args.kwonlyargs:
                    if arg.annotation:
                        for name in _extract_type_names(arg.annotation):
                            if name != node.name and name not in BUILTIN_TYPES:
                                info.type_deps.add(name)

                for dec in child.decorator_list:
                    dec_name = _get_decorator_name(dec)
                    if dec_name and dec_name in known_classes and dec_name != node.name:
                        info.decorator_deps.add(dec_name)

            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    callee = child.func.id
                    if callee in known_classes and callee != node.name:
                        info.instantiation_deps.add(callee)
                elif isinstance(child.func, ast.Attribute):
                    attr_name = child.func.attr
                    if attr_name in known_classes and attr_name != node.name:
                        info.instantiation_deps.add(attr_name)

            if isinstance(child, ast.Attribute):
                if isinstance(child.value, ast.Name):
                    obj_name = child.value.id
                    if (
                        obj_name in known_classes
                        and obj_name != node.name
                        and obj_name != "self"
                        and obj_name != "cls"
                    ):
                        info.attribute_deps.add(obj_name)

    coupling_graph: dict[str, dict[str, set[str]]] = {}

    for class_name, info in classes.items():
        all_efferent: set[str] = set()
        dep_breakdown: dict[str, set[str]] = {
            "inheritance": info.bases & known_classes,
            "type_hints": info.type_deps & known_classes,
            "instantiation": info.instantiation_deps,
            "attribute_access": info.attribute_deps,
            "decorator": info.decorator_deps,
            "protocol_abc": set(),
        }

        for other_name, other_info in classes.items():
            if other_name == class_name:
                continue
            shared_bases = info.bases & other_info.bases
            shared_protocols = {
                b for b in shared_bases
                if any(
                    classes.get(b, _ClassInfo("", 0, 0)).is_protocol
                    or classes.get(b, _ClassInfo("", 0, 0)).is_abc
                    for _ in [None]
                )
            }
            if shared_protocols:
                dep_breakdown["protocol_abc"].add(other_name)

        for deps in dep_breakdown.values():
            all_efferent.update(deps)

        coupling_graph[class_name] = dep_breakdown

    afferent: dict[str, set[str]] = {name: set() for name in classes}
    for class_name, breakdown in coupling_graph.items():
        for dep_type, deps in breakdown.items():
            for dep in deps:
                if dep in afferent:
                    afferent[dep].add(class_name)

    result_classes: dict[str, dict[str, Any]] = {}
    for class_name, info in classes.items():
        breakdown = coupling_graph.get(class_name, {})
        all_efferent = set()
        for deps in breakdown.values():
            all_efferent.update(deps)

        ce = len(all_efferent)
        ca = len(afferent.get(class_name, set()))
        total = ce + ca

        result_classes[class_name] = {}

        result_classes[class_name]["efferent_coupling"] = ce
        result_classes[class_name]["afferent_coupling"] = ca
        result_classes[class_name]["total_coupling"] = total

        result_classes[class_name]["efferent_classes"] = sorted(all_efferent)

        incoming = afferent.get(class_name)
        if incoming is None:
            incoming = set()
        result_classes[class_name]["afferent_classes"] = sorted(incoming)

        breakdown_sorted = {}
        for k, v in breakdown.items():
            breakdown_sorted[k] = sorted(v)
        result_classes[class_name]["breakdown"] = breakdown_sorted

        denom = ca + ce
        if denom > 0:
            instability = ce / denom
        else:
            instability = 0.0
        result_classes[class_name]["instability"] = instability

        result_classes[class_name]["is_protocol"] = info.is_protocol
        result_classes[class_name]["is_abc"] = info.is_abc
        result_classes[class_name]["is_dataclass"] = info.is_dataclass
        result_classes[class_name]["line"] = info.lineno
        result_classes[class_name]["methods"] = info.methods

        coupling_graph_out = {}
        for name, bd in coupling_graph.items():
            combined = set()
            for values in bd.values():
                combined.update(values)
            coupling_graph_out[name] = sorted(combined)

        return {
            "classes": result_classes,
            "coupling_graph": coupling_graph_out,
        }


class CBORule(SkylosRule):
    rule_id = "SKY-Q701"
    name = "Coupling Between Objects"

    def __init__(self, low_threshold=4, high_threshold=8):
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold
        self._file_cache: dict[str, dict] = {}

    def _get_file_analysis(self, context: dict) -> dict:
        filename = context.get("filename", "")
        if filename not in self._file_cache:
            self._file_cache[filename] = {}
        return self._file_cache[filename]

    def visit_node(
        self, node: ast.AST, context: dict[str, Any]
    ) -> Optional[list[dict[str, Any]]]:
        if not isinstance(node, ast.ClassDef):
            return None

        filename = context.get("filename", "")

        if filename not in self._file_cache:
            self._file_cache[filename] = {"_analyzed": False}

        file_data = self._file_cache[filename]
        if not file_data.get("_analyzed"):
            file_data["_analyzed"] = True
            try:
                source = Path(filename).read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)
                result = analyze_coupling(tree, filename)
                file_data.update(result)
            except Exception:
                return None

        class_data = file_data.get("classes", {}).get(node.name)
        if not class_data:
            return None

        ce = class_data["efferent_coupling"]

        if ce <= self.low_threshold:
            return None

        if ce > self.high_threshold:
            severity = "HIGH"
        elif ce > self.low_threshold:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        breakdown_parts = []
        for dep_type, deps in class_data["breakdown"].items():
            if deps:
                breakdown_parts.append(f"{dep_type}={len(deps)}")
        if breakdown_parts:
            breakdown_str = ", ".join(breakdown_parts)
        else:
            breakdown_str = "none"

        return [
            {
                "rule_id": self.rule_id,
                "kind": "quality",
                "severity": severity,
                "type": "class",
                "name": node.name,
                "simple_name": node.name,
                "value": ce,
                "threshold": self.low_threshold,
                "efferent_coupling": ce,
                "afferent_coupling": class_data["afferent_coupling"],
                "instability": round(class_data["instability"], 3),
                "coupling_breakdown": breakdown_str,
                "message": (
                    f"Class '{node.name}' has high coupling (Ce={ce}, Ca={class_data['afferent_coupling']}). "
                    f"Breakdown: {breakdown_str}. Consider reducing dependencies."
                ),
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
