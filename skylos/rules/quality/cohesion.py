import ast
from pathlib import Path
from typing import Any, Optional

from skylos.rules.base import SkylosRule

DATACLASS_DECORATORS = frozenset(
    {
        "dataclass",
        "dataclasses.dataclass",
        "attrs",
        "attr.s",
        "attr.attrs",
        "define",
        "attrs.define",
    }
)

DATACLASS_BASES = frozenset(
    {
        "BaseModel",
        "BaseSettings",
        "TypedDict",
        "NamedTuple",
    }
)

INIT_METHODS = frozenset({"__init__", "__post_init__", "__init_subclass__"})

INTERFACE_DUNDERS = frozenset(
    {
        "__str__",
        "__repr__",
        "__format__",
        "__bytes__",
        "__eq__",
        "__ne__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__hash__",
        "__bool__",
        "__len__",
        "__iter__",
        "__next__",
        "__contains__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__enter__",
        "__exit__",
        "__aenter__",
        "__aexit__",
        "__call__",
        "__add__",
        "__sub__",
        "__mul__",
    }
)


class _UnionFind:
    __slots__ = ("parent", "rank")

    def __init__(self):
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def make_set(self, x: str):
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0

    def find(self, x: str) -> str:
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: str, y: str):
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1

    def components(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for x in self.parent:
            root = self.find(x)
            groups.setdefault(root, []).append(x)
        return groups


class _MethodInfo:
    __slots__ = (
        "name",
        "lineno",
        "is_static",
        "is_classmethod",
        "is_property",
        "is_init",
        "is_dunder",
        "self_attrs",
        "cls_attrs",
        "self_calls",
        "property_backing",
    )

    def __init__(self, name: str, lineno: int):
        self.name = name
        self.lineno = lineno
        self.is_static = False
        self.is_classmethod = False
        self.is_property = False
        self.is_init = False
        self.is_dunder = name.startswith("__") and name.endswith("__")
        self.self_attrs: set[str] = set()
        self.cls_attrs: set[str] = set()
        self.self_calls: set[str] = set()
        self.property_backing: str | None = None


def _get_decorator_names(decorators: list[ast.expr]) -> set[str]:
    names = set()
    for dec in decorators:
        if isinstance(dec, ast.Name):
            names.add(dec.id)
        elif isinstance(dec, ast.Attribute):
            names.add(dec.attr)
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                names.add(dec.func.id)
            elif isinstance(dec.func, ast.Attribute):
                names.add(dec.func.attr)
    return names


def _is_dataclass_or_container(node: ast.ClassDef) -> bool:
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id in DATACLASS_DECORATORS:
            return True
        if isinstance(dec, ast.Attribute):
            full = f"{getattr(dec.value, 'id', '')}.{dec.attr}"
            if full in DATACLASS_DECORATORS:
                return True
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name) and func.id in DATACLASS_DECORATORS:
                return True
            if isinstance(func, ast.Attribute):
                full = f"{getattr(func.value, 'id', '')}.{func.attr}"
                if full in DATACLASS_DECORATORS:
                    return True

    for base in node.bases:
        if isinstance(base, ast.Name) and base.id in DATACLASS_BASES:
            return True
        if isinstance(base, ast.Attribute) and base.attr in DATACLASS_BASES:
            return True

    return False


def _extract_method_info(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> _MethodInfo:
    info = _MethodInfo(func_node.name, func_node.lineno)

    dec_names = _get_decorator_names(func_node.decorator_list)
    info.is_static = "staticmethod" in dec_names
    info.is_classmethod = "classmethod" in dec_names
    info.is_property = "property" in dec_names
    info.is_init = func_node.name in INIT_METHODS

    if info.is_static:
        return info

    self_param = "self"
    if info.is_classmethod:
        self_param = "cls"
    if func_node.args.args:
        self_param = func_node.args.args[0].arg

    for child in ast.walk(func_node):
        if isinstance(child, ast.Attribute):
            if isinstance(child.value, ast.Name) and child.value.id == self_param:
                attr_name = child.attr

                if info.is_classmethod:
                    info.cls_attrs.add(attr_name)
                else:
                    info.self_attrs.add(attr_name)

        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Attribute):
                if (
                    isinstance(child.func.value, ast.Name)
                    and child.func.value.id == self_param
                ):
                    info.self_calls.add(child.func.attr)

    if info.is_property:
        private_attrs = {a for a in info.self_attrs if a.startswith("_")}
        if len(private_attrs) == 1:
            info.property_backing = private_attrs.pop()

    return info


def analyze_cohesion(class_node: ast.ClassDef) -> dict[str, Any] | None:
    methods: list[_MethodInfo] = []

    for item in class_node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info = _extract_method_info(item)
            if not info.is_static:
                methods.append(info)

    if len(methods) < 2:
        return None

    property_map: dict[str, str] = {}
    for m in methods:
        if m.property_backing:
            property_map[m.property_backing] = m.name

    def normalize_attr(attr: str) -> str:
        if attr in property_map:
            return property_map[attr]
        return attr

    method_attrs: dict[str, set[str]] = {}
    for m in methods:
        attrs = set()
        for a in m.self_attrs:
            attrs.add(normalize_attr(a))
        for a in m.cls_attrs:
            attrs.add(normalize_attr(a))
        method_attrs[m.name] = attrs

    all_attrs: set[str] = set()
    for attrs in method_attrs.values():
        all_attrs.update(attrs)

    method_names = []
    for m in methods:
        method_names.append(m.name)

    n = len(method_names)
    pairs_no_share = 0
    pairs_share = 0

    for i in range(n):
        for j in range(i + 1, n):
            a_attrs = method_attrs[method_names[i]]
            b_attrs = method_attrs[method_names[j]]
            if a_attrs & b_attrs:
                pairs_share += 1
            else:
                pairs_no_share += 1

    lcom1 = max(0, pairs_no_share - pairs_share)

    uf = _UnionFind()
    for m in methods:
        uf.make_set(m.name)

    attr_to_methods: dict[str, list[str]] = {}
    for m_name, attrs in method_attrs.items():
        for attr in attrs:
            attr_to_methods.setdefault(attr, []).append(m_name)

    for attr, m_names in attr_to_methods.items():
        for i in range(1, len(m_names)):
            uf.union(m_names[0], m_names[i])

    method_name_set = set()
    for m in methods:
        method_name_set.add(m.name)

    for m in methods:
        for call_target in m.self_calls:
            if call_target in method_name_set:
                uf.union(m.name, call_target)

    init_methods = []
    for m in methods:
        if m.is_init:
            init_methods.append(m.name)

    for i in range(1, len(init_methods)):
        uf.union(init_methods[0], init_methods[i])

    if init_methods:
        init_attrs = set()
        for im in init_methods:
            init_attrs.update(method_attrs.get(im, set()))
        for m in methods:
            if m.is_dunder and m.name in INTERFACE_DUNDERS:
                if method_attrs[m.name] & init_attrs:
                    uf.union(init_methods[0], m.name)

    components = uf.components()
    lcom4 = len(components)
    m_count = len(methods)
    a_count = len(all_attrs)

    if a_count > 0 and m_count > 1:
        sum_methods_using_attr = 0
        for ms in attr_to_methods.values():
            sum_methods_using_attr += len(ms)

        lcom5 = ((sum_methods_using_attr / a_count) - m_count) / (1 - m_count)

        if lcom5 < 0.0:
            lcom5 = 0.0
        elif lcom5 > 1.0:
            lcom5 = 1.0
    else:
        lcom5 = 0.0

    cohesion_groups = []
    for root, members in sorted(components.items(), key=lambda x: -len(x[1])):
        group_attrs = set()
        for member in members:
            group_attrs.update(method_attrs.get(member, set()))
        cohesion_groups.append(
            {
                "methods": sorted(members),
                "shared_attributes": sorted(group_attrs),
                "size": len(members),
            }
        )

    return {
        "lcom1": lcom1,
        "lcom4": lcom4,
        "lcom5": round(lcom5, 3),
        "method_count": m_count,
        "attribute_count": a_count,
        "cohesion_groups": cohesion_groups,
        "is_dataclass": _is_dataclass_or_container(class_node),
    }


class LCOMRule(SkylosRule):
    rule_id = "SKY-Q702"
    name = "Lack of Cohesion of Methods"

    def __init__(self, low_threshold=2, high_threshold=4):
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold

    def visit_node(
        self, node: ast.AST, context: dict[str, Any]
    ) -> Optional[list[dict[str, Any]]]:
        if not isinstance(node, ast.ClassDef):
            return None

        result = analyze_cohesion(node)
        if result is None:
            return None

        lcom4 = result["lcom4"]

        if result["is_dataclass"] and lcom4 <= self.high_threshold + 2:
            return None

        if lcom4 <= self.low_threshold:
            return None

        if lcom4 > self.high_threshold:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        groups = result["cohesion_groups"]
        group_descs = []
        for i, g in enumerate(groups[:4], 1):
            methods = ", ".join(g["methods"][:5])
            if len(g["methods"]) > 5:
                methods += f" (+{len(g['methods']) - 5} more)"
            group_descs.append(f"Group {i}: [{methods}]")
        groups_str = "; ".join(group_descs)

        filename = context.get("filename", "")

        return [
            {
                "rule_id": self.rule_id,
                "kind": "quality",
                "severity": severity,
                "type": "class",
                "name": node.name,
                "simple_name": node.name,
                "value": lcom4,
                "threshold": self.low_threshold,
                "lcom1": result["lcom1"],
                "lcom4": lcom4,
                "lcom5": result["lcom5"],
                "method_count": result["method_count"],
                "attribute_count": result["attribute_count"],
                "cohesion_groups": groups_str,
                "message": (
                    f"Class '{node.name}' has low cohesion (LCOM4={lcom4}, LCOM5={result['lcom5']:.2f}). "
                    f"{len(groups)} disconnected method groups found. "
                    f"Consider splitting: {groups_str}"
                ),
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
