from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from collections import defaultdict
from skylos.control_flow import evaluate_static_condition, extract_constant_string
from skylos.implicit_refs import pattern_tracker
from typing import Any, Optional, Union

PYTHON_BUILTINS = {
    "print",
    "len",
    "str",
    "int",
    "float",
    "list",
    "dict",
    "set",
    "tuple",
    "range",
    "open",
    "reversed",
    "super",
    "object",
    "type",
    "enumerate",
    "zip",
    "map",
    "filter",
    "sorted",
    "sum",
    "min",
    "next",
    "iter",
    "bytes",
    "bytearray",
    "format",
    "round",
    "abs",
    "complex",
    "hash",
    "id",
    "bool",
    "callable",
    "getattr",
    "max",
    "all",
    "any",
    "setattr",
    "hasattr",
    "isinstance",
    "globals",
    "locals",
    "vars",
    "dir",
    "property",
    "classmethod",
    "staticmethod",
}

DYNAMIC_PATTERNS = {"getattr", "globals", "eval", "exec"}

IMPLICIT_DUNDERS = {
    "__init__",
    "__new__",
    "__del__",
    "__init_subclass__",
    "__repr__",
    "__str__",
    "__bytes__",
    "__format__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__hash__",
    "__getattr__",
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "__dir__",
    "__get__",
    "__set__",
    "__delete__",
    "__set_name__",
    "__len__",
    "__length_hint__",
    "__getitem__",
    "__setitem__",
    "__delitem__",
    "__missing__",
    "__iter__",
    "__reversed__",
    "__contains__",
    "__add__",
    "__sub__",
    "__mul__",
    "__matmul__",
    "__truediv__",
    "__floordiv__",
    "__mod__",
    "__divmod__",
    "__pow__",
    "__lshift__",
    "__rshift__",
    "__and__",
    "__xor__",
    "__or__",
    "__neg__",
    "__pos__",
    "__abs__",
    "__invert__",
    "__complex__",
    "__int__",
    "__float__",
    "__index__",
    "__round__",
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rmatmul__",
    "__rtruediv__",
    "__rfloordiv__",
    "__rmod__",
    "__rdivmod__",
    "__rpow__",
    "__rlshift__",
    "__rrshift__",
    "__rand__",
    "__rxor__",
    "__ror__",
    "__iadd__",
    "__isub__",
    "__imul__",
    "__imatmul__",
    "__itruediv__",
    "__ifloordiv__",
    "__imod__",
    "__ipow__",
    "__ilshift__",
    "__irshift__",
    "__iand__",
    "__ixor__",
    "__ior__",
    "__enter__",
    "__exit__",
    "__aenter__",
    "__aexit__",
    "__call__",
    "__await__",
    "__aiter__",
    "__anext__",
    "__prepare__",
    "__class_getitem__",
    "__reduce__",
    "__reduce_ex__",
    "__getstate__",
    "__setstate__",
    "__getnewargs__",
    "__getnewargs_ex__",
    "__copy__",
    "__deepcopy__",
    "__bool__",
}

METACLASS_BASES = {"ABCMeta", "EnumMeta", "type"}


class Definition:
    __slots__ = (
        "name",
        "type",
        "filename",
        "line",
        "simple_name",
        "confidence",
        "references",
        "is_exported",
        "in_init",
        "node",
        "calls",
        "called_by",
        "closes_over",
        "return_type",
        "is_closure",
        "is_lambda",
        "is_descriptor",
        "is_dunder",
        "decorators",
        "complexity",
        "skip_reason",
        "base_classes",
    )

    def __init__(
        self,
        name: str,
        t: str,
        filename: Union[Path, str],
        line: int,
        node: Optional[ast.AST] = None,
    ) -> None:
        self.name = name
        self.type = t
        self.filename = filename
        self.line = line
        self.simple_name = name.split(".")[-1]
        self.confidence = 100
        self.references = 0
        self.is_exported = False
        self.in_init = "__init__.py" in str(filename)

        self.node = node
        self.calls = set()
        self.called_by = set()
        self.closes_over = set()
        self.return_type = None
        self.is_closure = False
        self.is_lambda = False
        self.is_descriptor = False
        self.is_dunder = False
        self.decorators = []
        self.complexity = 1
        self.base_classes = []

    def to_dict(self) -> dict[str, Any]:
        if self.type == "method" and "." in self.name:
            parts = self.name.split(".")
            if len(parts) >= 3:
                output_name = ".".join(parts[-2:])
            else:
                output_name = self.name
        else:
            output_name = self.simple_name

        result = {
            "name": output_name,
            "full_name": self.name,
            "simple_name": self.simple_name,
            "type": self.type,
            "file": str(self.filename),
            "basename": Path(self.filename).name,
            "line": self.line,
            "confidence": self.confidence,
            "references": self.references,
        }

        if self.calls:
            result["calls"] = list(self.calls)
        if self.called_by:
            result["called_by"] = list(self.called_by)
        if self.closes_over:
            result["closes_over"] = list(self.closes_over)
        if self.return_type:
            result["return_type"] = self.return_type
        if self.is_lambda:
            result["is_lambda"] = True
        if self.is_closure:
            result["is_closure"] = True
        if self.is_descriptor:
            result["is_descriptor"] = True
        if self.decorators:
            result["decorators"] = self.decorators

        return result


class Visitor(ast.NodeVisitor):
    def __init__(self, mod: str, file: Union[Path, str]) -> None:
        self.mod = mod
        self.file = file
        self.defs = []
        self.refs = []
        self.cls = None
        self.alias = {}
        self.dyn = set()
        self.exports = set()
        self.current_function_scope = []
        self.current_function_params = []
        self.local_var_maps = []
        self.in_cst_class = 0
        self.local_type_maps = []
        self._dataclass_stack = []
        self.dataclass_fields = set()
        self.first_read_lineno = {}
        self.instance_attr_types = {}
        self.local_constants = []
        self.pattern_tracker = pattern_tracker
        self._param_stack = []
        self._typed_dict_stack = []
        self._shadowed_module_aliases = {}
        self._in_protocol_class = False
        self.protocol_classes = set()
        self._in_overload = False
        self._in_abstractmethod = False
        self.namedtuple_classes = set()
        self.enum_classes = set()
        self.attrs_classes = set()
        self.orm_model_classes = set()
        self.type_alias_names = set()
        self.all_exports = set()
        self.abc_classes = set()
        self.abstract_methods = {}
        self.abc_implementers = {}
        self.protocol_implementers = {}
        self.protocol_method_names = {}

        self.call_graph = defaultdict(set)
        self.reverse_call_graph = defaultdict(set)

        self._current_function_qname = None

        self._nonlocal_names = set()
        self._free_vars = defaultdict(set)
        self._lambda_counter = 0
        self._comprehension_scope_stack = []
        self.inferred_types = {}
        self.metaclass_classes = set()
        self.descriptor_classes = set()
        self._string_ref_patterns = []
        self._complexity_stack = [0]
        self.class_bases = {}
        self._mro_cache = {}
        self.slotted_classes = set()
        self.property_chains = defaultdict(dict)
        self.version_conditional_lines = set()
        self._used_attr_names = set()

    def add_def(
        self, name: str, t: str, line: int, node: Optional[ast.AST] = None, **extra: Any
    ) -> None:
        found = False
        for d in self.defs:
            if d.name == name:
                found = True
                if node is not None:
                    d.node = node
                for k, v in extra.items():
                    if hasattr(d, k):
                        setattr(d, k, v)
                break
        if not found:
            defn = Definition(name, t, self.file, line, node=node)
            for k, v in extra.items():
                if hasattr(defn, k):
                    setattr(defn, k, v)
            self.defs.append(defn)

            if defn.simple_name.startswith("__") and defn.simple_name.endswith("__"):
                defn.is_dunder = True
                if defn.simple_name in IMPLICIT_DUNDERS:
                    defn.references += 1

    def add_ref(self, name: str) -> None:
        self.refs.append((sys.intern(str(name)), self.file))

        if self._current_function_qname:
            self.call_graph[self._current_function_qname].add(name)
            self.reverse_call_graph[name].add(self._current_function_qname)

    def qual(self, name: str) -> str:
        if name in self.alias:
            if self.mod:
                local_name = f"{self.mod}.{name}"
                if any(d.name == local_name for d in self.defs):
                    return local_name
            else:
                if any(d.name == name for d in self.defs):
                    return name
            return self.alias[name]

        if name in PYTHON_BUILTINS:
            if self.mod:
                mod_candidate = f"{self.mod}.{name}"
            else:
                mod_candidate = name
            if any(d.name == mod_candidate for d in self.defs):
                return mod_candidate

        if self.mod:
            return f"{self.mod}.{name}"
        else:
            return name

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            full = a.name
            if a.asname:
                alias_name = a.asname
                target = full
            else:
                head = full.split(".", 1)[0]
                alias_name = head
                target = head

            self.alias[alias_name] = target
            self.add_def(target, "import", node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module

        mod_str = self.mod or ""
        is_init = Path(str(self.file)).name == "__init__.py"
        cur_pkg = (
            mod_str
            if is_init
            else (mod_str.rsplit(".", 1)[0] if "." in mod_str else mod_str)
        )

        if node.level and node.level > 0:
            if cur_pkg:
                parts = cur_pkg.split(".")
            else:
                parts = []
            up = node.level - 1

            if up > len(parts):
                base = ""
            else:
                base = ".".join(parts[: len(parts) - up])

            if module:
                base = f"{base}.{module}" if base else module
        else:
            base = module or ""

        for a in node.names:
            if a.name == "*":
                root = (base.split(".")[0] if base else "") or (
                    module.split(".")[0] if module else ""
                )
                self.dyn.add(root)
                continue

            if a.asname:
                alias_name = a.asname
            else:
                alias_name = a.name

            if base:
                full = f"{base}.{a.name}"
            else:
                full = a.name

            self.alias[alias_name] = full
            self.add_def(full, "import", node.lineno)

    def visit_If(self, node: ast.If) -> None:
        from skylos.control_flow import (
            _is_sys_version_info_node,
            _extract_version_tuple,
        )

        condition = evaluate_static_condition(node.test, file_path=self.file)
        self.visit(node.test)
        self._complexity_stack[-1] += 1

        is_version_conditional = False
        if isinstance(node.test, ast.Compare):
            if _is_sys_version_info_node(node.test.left):
                version_tuple = (
                    _extract_version_tuple(node.test.comparators[0])
                    if node.test.comparators
                    else None
                )
                is_version_conditional = version_tuple is not None
            elif node.test.comparators and _is_sys_version_info_node(
                node.test.comparators[0]
            ):
                version_tuple = _extract_version_tuple(node.test.left)
                is_version_conditional = version_tuple is not None

        if condition is True:
            for statement in node.body:
                self.visit(statement)
        elif condition is False:
            for statement in node.orelse:
                self.visit(statement)
        else:
            for statement in node.body:
                if is_version_conditional:
                    self._mark_version_conditional(statement)
                self.visit(statement)
            for statement in node.orelse:
                if is_version_conditional:
                    self._mark_version_conditional(statement)
                self.visit(statement)

    def _mark_version_conditional(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if hasattr(child, "lineno"):
                self.version_conditional_lines.add(child.lineno)

    def visit_For(self, node: ast.For) -> None:
        self._complexity_stack[-1] += 1

        self.visit(node.iter)
        self._bind_target(node.target, node.lineno)

        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._complexity_stack[-1] += 1

        self.visit(node.iter)
        self._bind_target(node.target, node.lineno)

        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_While(self, node: ast.While) -> None:
        self._complexity_stack[-1] += 1

        self.visit(node.test)
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Try(self, node: ast.Try) -> None:
        self._complexity_stack[-1] += len(node.handlers)

        is_import_error_handler = any(
            isinstance(h.type, ast.Name)
            and h.type.id in ("ImportError", "ModuleNotFoundError")
            for h in node.handlers
        )

        if is_import_error_handler:
            has_flag = False
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name) and (
                            t.id.startswith("HAS_") or t.id.startswith("HAVE_")
                        ):
                            has_flag = True
                            break

            if has_flag:
                for stmt in node.body:
                    if isinstance(stmt, ast.Import):
                        for alias in stmt.names:
                            target = (
                                alias.asname
                                if alias.asname
                                else alias.name.split(".", 1)[0]
                            )
                            self.add_ref(target)
                    elif isinstance(stmt, ast.ImportFrom) and stmt.module:
                        for alias in stmt.names:
                            if alias.name == "*":
                                continue
                            full_name = f"{stmt.module}.{alias.name}"
                            self.add_ref(full_name)

        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._bind_target(item.optional_vars, node.lineno)

                if isinstance(item.context_expr, ast.Call):
                    type_name = self._get_call_type(item.context_expr)
                    if type_name and isinstance(item.optional_vars, ast.Name):
                        var_qname = self._compute_variable_name(item.optional_vars.id)
                        self.inferred_types[var_qname] = type_name

        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncWith = visit_With

    def _get_decorator_name(self, deco: ast.expr) -> Optional[str]:
        if isinstance(deco, ast.Name):
            return deco.id
        elif isinstance(deco, ast.Attribute):
            parent = self._get_decorator_name(deco.value)
            if parent:
                return f"{parent}.{deco.attr}"
            return deco.attr
        elif isinstance(deco, ast.Call):
            return self._get_decorator_name(deco.func)
        return None

    def _analyze_decorator_args(self, deco: ast.expr) -> None:
        if not isinstance(deco, ast.Call):
            return

        for arg in deco.args:
            self.visit(arg)
        for kw in deco.keywords:
            self.visit(kw.value)

            if kw.arg in ("default", "factory", "validator", "converter"):
                if isinstance(kw.value, ast.Name):
                    self.add_ref(self.qual(kw.value.id))

    def visit_FunctionDef(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> None:
        outer_scope_prefix = (
            ".".join(self.current_function_scope) + "."
            if self.current_function_scope
            else ""
        )

        if self.cls:
            name_parts = [self.mod, self.cls, outer_scope_prefix + node.name]
        else:
            name_parts = [self.mod, outer_scope_prefix + node.name]

        qualified_name = ".".join(filter(None, name_parts))
        if self.cls:
            def_type = "method"
        else:
            def_type = "function"

        decorator_names = []
        for d in node.decorator_list:
            deco_name = self._get_decorator_name(d)
            if deco_name:
                decorator_names.append(deco_name)

        is_descriptor = node.name in (
            "__get__",
            "__set__",
            "__delete__",
            "__set_name__",
        )
        if is_descriptor and self.cls:
            self.descriptor_classes.add(
                f"{self.mod}.{self.cls}" if self.mod else self.cls
            )

        self.add_def(
            qualified_name,
            def_type,
            node.lineno,
            node=node,
            decorators=decorator_names,
            is_descriptor=is_descriptor,
        )

        for d in node.decorator_list:
            self.visit(d)
            self._analyze_decorator_args(d)

        FRAMEWORK_DECORATORS = {
            "fixture",
            "pytest",
            "task",
            "celery",
            "register",
            "subscriber",
            "listener",
            "handler",
            "receiver",
            "command",
            "route",
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "api",
            "endpoint",
            "hook",
            "signal",
            "event",
            "job",
            "worker",
            "consumer",
            "producer",
        }

        is_abstract_or_overload = False
        for deco in node.decorator_list:
            deco_name = self._get_decorator_name(deco)
            if deco_name in (
                "abstractmethod",
                "abc.abstractmethod",
                "overload",
                "typing.overload",
                "typing_extensions.overload",
            ):
                is_abstract_or_overload = True
                break

        if self.cls and self.cls in self.abc_classes and is_abstract_or_overload:
            if self.cls not in self.abstract_methods:
                self.abstract_methods[self.cls] = set()
            self.abstract_methods[self.cls].add(node.name)

        if self.cls and self._in_protocol_class:
            if self.cls not in self.protocol_method_names:
                self.protocol_method_names[self.cls] = set()
            self.protocol_method_names[self.cls].add(node.name)

        prev_abstract_overload = getattr(self, "_in_abstract_or_overload", False)
        self._in_abstract_or_overload = is_abstract_or_overload

        for deco in node.decorator_list:
            deco_name = self._get_decorator_name(deco)
            if deco_name:
                if deco_name in (
                    "property",
                    "cached_property",
                    "functools.cached_property",
                ):
                    self.add_ref(qualified_name)
                    if self.cls:
                        self.property_chains[
                            f"{self.mod}.{self.cls}" if self.mod else self.cls
                        ][node.name] = {"getter": qualified_name}
                elif deco_name.endswith((".setter", ".deleter")):
                    self.add_ref(qualified_name)
                    if self.cls:
                        prop_name = deco_name.rsplit(".", 1)[0]
                        class_key = f"{self.mod}.{self.cls}" if self.mod else self.cls
                        if prop_name not in self.property_chains[class_key]:
                            self.property_chains[class_key][prop_name] = {}
                        chain_type = (
                            "setter" if deco_name.endswith(".setter") else "deleter"
                        )
                        self.property_chains[class_key][prop_name][chain_type] = (
                            qualified_name
                        )
                elif any(
                    keyword in deco_name.lower() for keyword in FRAMEWORK_DECORATORS
                ):
                    self.add_ref(qualified_name)

        if self.current_function_scope and self.local_var_maps:
            self.local_var_maps[-1][node.name] = qualified_name

        prev_function_qname = self._current_function_qname
        self._current_function_qname = qualified_name

        self._complexity_stack.append(1)

        self.current_function_scope.append(node.name)
        self.local_var_maps.append({})
        self.local_type_maps.append({})
        self.local_constants.append({})

        old_params = self.current_function_params
        self._param_stack.append(old_params)
        self.current_function_params = []

        prev_nonlocals = self._nonlocal_names
        self._nonlocal_names = set()

        all_args = []
        all_args.extend(node.args.posonlyargs)
        all_args.extend(node.args.args)
        all_args.extend(node.args.kwonlyargs)

        skip_params = self._in_protocol_class or getattr(
            self, "_in_abstract_or_overload", False
        )

        for arg in all_args:
            param_name = f"{qualified_name}.{arg.arg}"
            if not skip_params:
                self.add_def(
                    param_name, "parameter", getattr(arg, "lineno", node.lineno)
                )
            self.current_function_params.append((arg.arg, param_name))

            if arg.annotation:
                type_str = self._annotation_to_string(arg.annotation)
                if type_str:
                    self.inferred_types[param_name] = type_str

        if node.args.vararg:
            va = node.args.vararg
            param_name = f"{qualified_name}.{va.arg}"
            if not skip_params:
                self.add_def(
                    param_name, "parameter", getattr(va, "lineno", node.lineno)
                )
            self.current_function_params.append((va.arg, param_name))

        if node.args.kwarg:
            ka = node.args.kwarg
            param_name = f"{qualified_name}.{ka.arg}"
            if not skip_params:
                self.add_def(
                    param_name, "parameter", getattr(ka, "lineno", node.lineno)
                )
            self.current_function_params.append((ka.arg, param_name))

        self.visit_arguments(node.args)
        self.visit_annotation(node.returns)

        if node.returns:
            return_type = self._annotation_to_string(node.returns)
            if return_type:
                for d in self.defs:
                    if d.name == qualified_name:
                        d.return_type = return_type
                        break

        for stmt in node.body:
            self.visit(stmt)

        complexity = self._complexity_stack.pop()
        for d in self.defs:
            if d.name == qualified_name:
                d.complexity = complexity
                break

        if self._nonlocal_names or (
            prev_function_qname and self._free_vars.get(qualified_name)
        ):
            for d in self.defs:
                if d.name == qualified_name:
                    d.is_closure = True
                    d.closes_over = self._free_vars.get(qualified_name, set())
                    break

        self.current_function_scope.pop()
        self.current_function_params = self._param_stack.pop()
        self.local_var_maps.pop()
        self.local_type_maps.pop()
        self.local_constants.pop()

        self._current_function_qname = prev_function_qname
        self._nonlocal_names = prev_nonlocals
        self._in_abstract_or_overload = prev_abstract_overload

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._lambda_counter += 1

        scope_parts = [self.mod]
        if self.cls:
            scope_parts.append(self.cls)
        if self.current_function_scope:
            scope_parts.extend(self.current_function_scope)

        lambda_name = f"<lambda_{self._lambda_counter}>"
        qualified_name = ".".join(filter(None, scope_parts + [lambda_name]))

        self.add_def(qualified_name, "lambda", node.lineno, node=node, is_lambda=True)
        self.visit_arguments(node.args)
        self.visit(node.body)

    def _visit_comprehension_scope(
        self,
        node: Union[ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp],
        comp_type: str,
    ) -> None:
        self._comprehension_scope_stack.append({})

        for generator in node.generators:
            self.visit(generator.iter)

            self._bind_comprehension_target(generator.target, node.lineno)

            for if_clause in generator.ifs:
                self.visit(if_clause)

        if hasattr(node, "elt"):
            self.visit(node.elt)
        elif hasattr(node, "key"):
            self.visit(node.key)
            self.visit(node.value)

        self._comprehension_scope_stack.pop()

    def _bind_comprehension_target(self, target: ast.expr, lineno: int) -> None:
        if isinstance(target, ast.Name):
            if self._comprehension_scope_stack:
                self._comprehension_scope_stack[-1][target.id] = True
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind_comprehension_target(elt, lineno)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension_scope(node, "listcomp")

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension_scope(node, "setcomp")

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension_scope(node, "dictcomp")

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension_scope(node, "genexp")

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)

        for case in node.cases:
            self._visit_match_case(case)

    def _visit_match_case(self, case: ast.match_case) -> None:
        self._complexity_stack[-1] += 1

        self._visit_pattern(case.pattern)

        if case.guard:
            self.visit(case.guard)

        for stmt in case.body:
            self.visit(stmt)

    def _visit_pattern(self, pattern: ast.pattern) -> None:
        pattern_type = type(pattern).__name__

        if pattern_type == "MatchValue":
            self.visit(pattern.value)

        elif pattern_type == "MatchSingleton":
            pass

        elif pattern_type == "MatchSequence":
            for p in pattern.patterns:
                self._visit_pattern(p)

        elif pattern_type == "MatchMapping":
            for key in pattern.keys:
                self.visit(key)
            for p in pattern.patterns:
                self._visit_pattern(p)
            if pattern.rest:
                self._bind_target(
                    ast.Name(id=pattern.rest, ctx=ast.Store()),
                    getattr(pattern, "lineno", 0),
                )

        elif pattern_type == "MatchClass":
            self.visit(pattern.cls)
            for p in pattern.patterns:
                self._visit_pattern(p)
            for p in pattern.kwd_patterns:
                self._visit_pattern(p)

        elif pattern_type == "MatchStar":
            if pattern.name:
                self._bind_target(
                    ast.Name(id=pattern.name, ctx=ast.Store()),
                    getattr(pattern, "lineno", 0),
                )

        elif pattern_type == "MatchAs":
            if pattern.pattern:
                self._visit_pattern(pattern.pattern)
            if pattern.name:
                self._bind_target(
                    ast.Name(id=pattern.name, ctx=ast.Store()),
                    getattr(pattern, "lineno", 0),
                )

        elif pattern_type == "MatchOr":
            for p in pattern.patterns:
                self._visit_pattern(p)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        cname = f"{self.mod}.{node.name}"
        self.add_def(cname, "class", node.lineno, node=node)

        is_protocol = False
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == "Protocol":
                is_protocol = True
            elif isinstance(base, ast.Attribute) and base.attr == "Protocol":
                is_protocol = True

        if is_protocol:
            self.protocol_classes.add(node.name)

        base_qnames = []

        for base in node.bases:
            base_name = None
            if isinstance(base, ast.Name):
                base_name = base.id
                base_qnames.append(self.alias.get(base_name, self.qual(base_name)))
            elif isinstance(base, ast.Attribute):
                base_name = base.attr
                base_qnames.append(self._get_attr_chain(base))

            if not base_name:
                continue

            if base_name == "ABC":
                self.abc_classes.add(node.name)

            elif base_name in self.abc_classes:
                if node.name not in self.abc_implementers:
                    self.abc_implementers[node.name] = []
                self.abc_implementers[node.name].append(base_name)

            elif base_name in self.protocol_classes:
                if node.name not in self.protocol_implementers:
                    self.protocol_implementers[node.name] = []
                self.protocol_implementers[node.name].append(base_name)

            if base_name in METACLASS_BASES:
                self.metaclass_classes.add(node.name)

        self.class_bases[cname] = base_qnames

        for d in self.defs:
            if d.name == cname and d.type == "class":
                d.base_classes = base_qnames
                break

        is_namedtuple = False
        is_enum = False
        is_orm_model = False

        for base in node.bases:
            base_name = ""
            if isinstance(base, ast.Name):
                base_name = base.id
            elif isinstance(base, ast.Attribute):
                base_name = base.attr

            if base_name == "NamedTuple":
                is_namedtuple = True
            if (
                base_name in ("Enum", "IntEnum", "StrEnum", "Flag", "IntFlag")
                or base_name in self.enum_classes
            ):
                is_enum = True
            if base_name in (
                "Base",
                "Model",
                "DeclarativeBase",
                "SQLModel",
                "Document",
            ):
                is_orm_model = True

        if is_namedtuple:
            self.namedtuple_classes.add(node.name)
        if is_enum:
            self.enum_classes.add(node.name)
        if is_orm_model:
            self.orm_model_classes.add(node.name)

        for keyword in node.keywords:
            if keyword.arg == "metaclass":
                self.metaclass_classes.add(node.name)
                self.visit(keyword.value)
            else:
                self.visit(keyword.value)

        for deco in node.decorator_list:
            deco_name = self._get_decorator_name(deco)
            if deco_name in (
                "attr.s",
                "attr.attrs",
                "attrs",
                "define",
                "attr.define",
                "frozen",
                "attr.frozen",
            ):
                self.attrs_classes.add(node.name)
            self.visit(deco)

        prev_in_protocol = self._in_protocol_class
        self._in_protocol_class = is_protocol

        is_typed_dict = False
        for base in node.bases:
            base_path = ""
            if isinstance(base, ast.Name):
                base_path = base.id
            elif isinstance(base, ast.Attribute):
                base_path = self._get_decorator_name(base) or ""
            if base_path:
                last = base_path.split(".")[-1]
                if last == "TypedDict":
                    is_typed_dict = True
                    break

        self._typed_dict_stack.append(is_typed_dict)

        is_cst = False
        is_dc = False

        for base in node.bases:
            base_name = ""
            if isinstance(base, ast.Attribute):
                base_name = base.attr
            elif isinstance(base, ast.Name):
                base_name = base.id

            self.visit(base)

            if base_name in {"CSTTransformer", "CSTVisitor"}:
                is_cst = True

        for decorator in node.decorator_list:

            def _is_dc(dec):
                if isinstance(dec, ast.Call):
                    target = dec.func
                else:
                    target = dec
                if isinstance(target, ast.Name):
                    return target.id == "dataclass"
                if isinstance(target, ast.Attribute):
                    return target.attr == "dataclass"
                return False

            if _is_dc(decorator):
                is_dc = True

        prev = self.cls
        if is_cst:
            self.in_cst_class += 1

        self.cls = node.name
        self._dataclass_stack.append(is_dc)

        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == "__slots__":
                        self.slotted_classes.add(cname)

        for b in node.body:
            self.visit(b)

        self.cls = prev
        self._dataclass_stack.pop()
        self._typed_dict_stack.pop()

        if is_cst:
            self.in_cst_class -= 1

        self._in_protocol_class = prev_in_protocol

    def visit_Global(self, node: ast.Global) -> None:
        if self.current_function_scope and self.local_var_maps:
            for name in node.names:
                self.local_var_maps[-1][name] = f"{self.mod}.{name}"

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self._nonlocal_names.update(node.names)

        if self._current_function_qname:
            self._free_vars[self._current_function_qname].update(node.names)

        for name in node.names:
            outer_qname = None
            for outer_params in reversed(self._param_stack):
                for param_name, param_full_name in outer_params:
                    if name == param_name:
                        outer_qname = param_full_name
                        break
                if outer_qname:
                    break
            if not outer_qname and self.local_var_maps:
                for scope_map in reversed(self.local_var_maps[:-1]):
                    if name in scope_map:
                        outer_qname = scope_map[name]
                        break
            if not outer_qname:
                outer_qname = self.qual(name)

            self.add_ref(outer_qname)
            if self.current_function_scope and self.local_var_maps:
                self.local_var_maps[-1][name] = outer_qname

    def _bind_target(self, target: ast.expr, lineno: int) -> None:
        if isinstance(target, ast.Name):
            name_simple = target.id
            var_name = self._compute_variable_name(name_simple)

            if not self._should_skip_variable_def(name_simple):
                self.add_def(var_name, "variable", lineno)

            if self.current_function_scope and self.local_var_maps:
                self.local_var_maps[-1][name_simple] = var_name

        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind_target(elt, lineno)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, lineno)

    def _compute_variable_name(self, name_simple: str) -> str:
        scope_parts = [self.mod]
        if self.cls:
            scope_parts.append(self.cls)
        if self.current_function_scope:
            scope_parts.extend(self.current_function_scope)

        if (
            self.current_function_scope
            and self.local_var_maps
            and name_simple in self.local_var_maps[-1]
        ):
            return self.local_var_maps[-1][name_simple]

        prefix = ".".join(filter(None, scope_parts))
        if prefix:
            return f"{prefix}.{name_simple}"
        return name_simple

    def _should_skip_variable_def(self, name_simple: str) -> bool:
        if (
            name_simple == "METADATA_DEPENDENCIES"
            and self.cls
            and self.in_cst_class > 0
        ):
            return True
        if (
            name_simple == "__all__"
            and not self.current_function_scope
            and not self.cls
        ):
            return True
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        const_val = extract_constant_string(node.value)
        if const_val is not None:
            if len(self.local_constants) > 0:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.local_constants[-1][t.id] = const_val

        if isinstance(node.value, ast.JoinedStr):
            pattern = self._extract_fstring_pattern(node.value)
            if pattern:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.pattern_tracker.f_string_patterns[t.id] = pattern

        for target in node.targets:
            self._process_target_for_def(target)

        if isinstance(node.value, ast.Dict):
            self._track_dict_dispatch(node)

        self._process_dunder_all_exports(node)
        self._try_infer_types_from_call(node)
        self._process_textual_bindings(node)
        self._extract_string_refs(node.value)
        self.generic_visit(node)
        self._track_instance_attr_types(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit_annotation(node.annotation)

        if isinstance(node.target, ast.Name):
            ann = node.annotation
            is_type_alias = False
            if isinstance(ann, ast.Name) and ann.id == "TypeAlias":
                is_type_alias = True
            elif isinstance(ann, ast.Attribute) and ann.attr == "TypeAlias":
                is_type_alias = True
            elif isinstance(ann, ast.Subscript):
                if (
                    isinstance(ann.value, ast.Attribute)
                    and ann.value.attr == "TypeAlias"
                ):
                    is_type_alias = True

            if is_type_alias:
                self.type_alias_names.add(node.target.id)

        if node.value:
            self.visit(node.value)
            self._extract_string_refs(node.value)

        def _define(t):
            if isinstance(t, ast.Name):
                name_simple = t.id
                var_name = self._compute_variable_name(name_simple)

                in_typeddict = bool(
                    self._typed_dict_stack and self._typed_dict_stack[-1]
                )
                is_class_body = bool(self.cls and not self.current_function_scope)
                is_annotation_only = node.value is None

                if in_typeddict and is_class_body and is_annotation_only:
                    return

                self.add_def(var_name, "variable", t.lineno)

                if (
                    self._dataclass_stack
                    and self._dataclass_stack[-1]
                    and self.cls
                    and not self.current_function_scope
                ):
                    self.dataclass_fields.add(var_name)

                if self.current_function_scope and self.local_var_maps:
                    self.local_var_maps[-1][name_simple] = var_name

                type_str = self._annotation_to_string(node.annotation)
                if type_str:
                    self.inferred_types[var_name] = type_str

            elif isinstance(t, (ast.Tuple, ast.List)):
                for elt in t.elts:
                    _define(elt)

        _define(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            nm = node.target.id
            if (
                self.current_function_scope
                and self.local_var_maps
                and nm in self.local_var_maps[-1]
            ):
                fq = self.local_var_maps[-1][nm]
                self.add_ref(fq)
                var_name = fq
            else:
                self.add_ref(self.qual(nm))
                var_name = self._compute_variable_name(nm)

            self.add_def(var_name, "variable", node.lineno)
            if self.current_function_scope and self.local_var_maps:
                self.local_var_maps[-1][nm] = var_name
        else:
            self.visit(node.target)
        self.visit(node.value)

    def _process_target_for_def(
        self, target_node: ast.expr, _in_tuple_unpack: bool = False
    ) -> None:
        if isinstance(target_node, ast.Name):
            name_simple = target_node.id

            if self._should_skip_variable_def(name_simple):
                return

            if (
                _in_tuple_unpack
                and name_simple.startswith("_")
                and not name_simple.startswith("__")
            ):
                return

            var_name = self._compute_variable_name(name_simple)
            self.add_def(var_name, "variable", target_node.lineno)

            if self.current_function_scope and self.local_var_maps:
                self.local_var_maps[-1][name_simple] = var_name

            if (
                (not self.current_function_scope)
                and (not self.cls)
                and (name_simple in self.alias)
            ):
                self._shadowed_module_aliases[name_simple] = var_name

        elif isinstance(target_node, (ast.Tuple, ast.List)):
            for elt in target_node.elts:
                self._process_target_for_def(elt, _in_tuple_unpack=True)

    def _process_dunder_all_exports(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id != "__all__":
                continue
            if not isinstance(node.value, (ast.List, ast.Tuple)):
                continue

            for elt in node.value.elts:
                value = self._extract_string_value(elt)
                if value is None:
                    continue

                self.all_exports.add(value)
                self.exports.add(value)

                if self.mod:
                    export_name = f"{self.mod}.{value}"
                else:
                    export_name = value

                self.add_ref(export_name)
                self.add_ref(value)

    def _extract_string_value(self, elt: ast.expr) -> Optional[str]:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            return elt.value
        if hasattr(elt, "s") and isinstance(elt.s, str):
            return elt.s
        return None

    def _extract_string_refs(self, node: ast.expr) -> None:
        if isinstance(node, ast.JoinedStr):
            pattern = self._extract_fstring_pattern(node)
            if pattern:
                self._string_ref_patterns.append(pattern)

        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                fmt = node.left.value
                pattern = re.sub(r"%[sdirfx]", "*", fmt)
                if "*" in pattern:
                    self._string_ref_patterns.append(pattern)

        elif isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
            ):
                fmt = node.func.value.value
                pattern = re.sub(r"\{[^}]*\}", "*", fmt)
                if "*" in pattern:
                    self._string_ref_patterns.append(pattern)

    def _extract_fstring_pattern(self, node: ast.JoinedStr) -> Optional[str]:
        parts = []
        has_var = False
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                parts.append("*")
                has_var = True
        return "".join(parts) if has_var else None

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)

        if isinstance(node.func, ast.Name) and node.func.id == "NewType":
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                self.type_alias_names.add(node.args[0].value)

        if (
            isinstance(node.func, ast.Name)
            and node.func.id in ("getattr", "hasattr", "setattr", "delattr")
            and len(node.args) >= 2
        ):
            attr_name = None

            if isinstance(node.args[1], ast.Name) and self.local_constants:
                attr_name = self.local_constants[-1].get(node.args[1].id)

            if not attr_name:
                attr_name = extract_constant_string(node.args[1])

            if attr_name:
                self.add_ref(attr_name)

                if isinstance(node.args[0], ast.Name):
                    module_name = node.args[0].id
                    if module_name != "self":
                        qualified_name = f"{self.qual(module_name)}.{attr_name}"
                        self.add_ref(qualified_name)

            else:
                fstring_pattern = None
                if isinstance(node.args[1], ast.JoinedStr):
                    fstring_pattern = self._extract_fstring_pattern(node.args[1])
                elif isinstance(node.args[1], ast.BinOp) and isinstance(
                    node.args[1].op, ast.Add
                ):
                    if isinstance(node.args[1].left, ast.Constant) and isinstance(
                        node.args[1].left.value, str
                    ):
                        fstring_pattern = node.args[1].left.value + "*"
                elif isinstance(node.args[1], ast.Name):
                    var_name = node.args[1].id
                    fstring_pattern = self.pattern_tracker.f_string_patterns.get(
                        var_name
                    )
                    if not fstring_pattern and self.local_constants:
                        val = self.local_constants[-1].get(var_name)
                        if val:
                            self.pattern_tracker.known_refs.add(val)

                if fstring_pattern:
                    self.pattern_tracker.add_pattern_ref(
                        fstring_pattern, 70, source_module=self.mod
                    )
                    if self._current_function_qname:
                        self.pattern_tracker.known_refs.add(
                            self._current_function_qname.split(".")[-1]
                        )

        elif isinstance(node.func, ast.Name) and node.func.id == "globals":
            parent = getattr(node, "parent", None)
            if isinstance(parent, ast.Subscript):
                if isinstance(parent.slice, ast.Constant) and isinstance(
                    parent.slice.value, str
                ):
                    func_name = parent.slice.value
                    self.add_ref(func_name)
                    self.add_ref(f"{self.mod}.{func_name}")
                elif isinstance(parent.slice, ast.JoinedStr):
                    pattern = self._extract_fstring_pattern(parent.slice)
                    if pattern:
                        self.pattern_tracker.add_pattern_ref(
                            pattern, 70, source_module=self.mod
                        )
                        if self._current_function_qname:
                            self.pattern_tracker.known_refs.add(
                                self._current_function_qname.split(".")[-1]
                            )

        elif isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            root_mod = ""
            if self.mod:
                root_mod = self.mod.split(".")[0]
            self.dyn.add(root_mod)

        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in ("importlib", "__import__")
        ):
            if node.args:
                arg = node.args[0]
                mod_name = extract_constant_string(arg)
                if mod_name:
                    root = mod_name.split(".")[0]
                    self.dyn.add(root)
                elif isinstance(arg, ast.JoinedStr):
                    pattern = self._extract_fstring_pattern(arg)
                    if pattern:
                        static_prefix = pattern.split("*")[0]
                        if static_prefix and "." in static_prefix:
                            root = static_prefix.split(".")[0]
                            self.dyn.add(root)
                        self.pattern_tracker.add_pattern_ref(
                            pattern, 60, source_module=self.mod
                        )

        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id == "super"
        ):
            method_name = node.func.attr
            if self.cls:
                owner = f"{self.mod}.{self.cls}" if self.mod else self.cls
                self.add_ref(f"{owner}.{method_name}")

                class_qname = f"{self.mod}.{self.cls}" if self.mod else self.cls
                for base_qname in self.class_bases.get(class_qname, []):
                    self.add_ref(f"{base_qname}.{method_name}")

    def _get_call_type(self, call_node: ast.Call) -> Optional[str]:
        if isinstance(call_node.func, ast.Name):
            name = call_node.func.id
            if name and name[0].isupper():
                return self.alias.get(name, self.qual(name))
        elif isinstance(call_node.func, ast.Attribute):
            attr = call_node.func.attr
            if attr and attr[0].isupper():
                return self._get_attr_chain(call_node.func)
        return None

    def _try_infer_types_from_call(self, node: ast.Assign) -> None:
        if not isinstance(node.value, ast.Call):
            return
        if not self.current_function_scope:
            return
        if not self.local_type_maps:
            return

        call_node = node.value
        if not hasattr(call_node, "func"):
            return

        callee = call_node.func
        fqname = self._resolve_callee_fqname(callee)

        if not fqname:
            return

        for target in node.targets:
            self._mark_target_type(target, fqname)

    def _resolve_callee_fqname(self, callee: ast.expr) -> Optional[str]:
        if isinstance(callee, ast.Name):
            return self.alias.get(callee.id, self.qual(callee.id))
        if isinstance(callee, ast.Attribute):
            parts = []
            cur = callee
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                head = self.alias.get(cur.id, self.qual(cur.id))
                if head:
                    return ".".join([head] + list(reversed(parts)))
        return None

    def _mark_target_type(self, target: ast.expr, fqname: str) -> None:
        if isinstance(target, ast.Name):
            self.local_type_maps[-1][target.id] = fqname
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_target_type(elt, fqname)

    def _track_instance_attr_types(self, node: ast.Assign) -> None:
        if not self.cls:
            return
        if not isinstance(node.value, ast.Call):
            return

        for target in node.targets:
            if not isinstance(target, ast.Attribute):
                continue
            if not isinstance(target.value, ast.Name):
                continue
            if target.value.id != "self":
                continue

            call_func = node.value.func
            class_name = None
            qualified_class = None

            if isinstance(call_func, ast.Name):
                class_name = call_func.id
                if class_name and class_name[0].isupper():
                    qualified_class = self.alias.get(class_name, self.qual(class_name))
            elif isinstance(call_func, ast.Attribute):
                class_name = call_func.attr
                if class_name and class_name[0].isupper():
                    if isinstance(call_func.value, ast.Name):
                        base = call_func.value.id
                        base_resolved = self.alias.get(base, base)
                        qualified_class = f"{base_resolved}.{class_name}"
                    else:
                        qualified_class = self.alias.get(
                            class_name, self.qual(class_name)
                        )

            if qualified_class:
                owner = f"{self.mod}.{self.cls}" if self.mod else self.cls
                attr_key = f"{owner}.{target.attr}"
                self.instance_attr_types[attr_key] = qualified_class

    def _track_dict_dispatch(self, node: ast.Assign) -> None:
        dict_node = node.value
        for val in dict_node.values:
            if val is None:
                continue
            if isinstance(val, ast.Name):
                self.add_ref(self.qual(val.id))
            elif isinstance(val, ast.Attribute):
                chain = self._get_attr_chain(val)
                if chain:
                    self.add_ref(chain)
            elif isinstance(val, (ast.List, ast.Tuple)):
                for elt in val.elts:
                    if isinstance(elt, ast.Name):
                        self.add_ref(self.qual(elt.id))
                    elif isinstance(elt, ast.Attribute):
                        chain = self._get_attr_chain(elt)
                        if chain:
                            self.add_ref(chain)

    def _process_textual_bindings(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id != "BINDINGS":
                continue
            if not isinstance(node.value, (ast.List, ast.Tuple)):
                continue

            for elt in node.value.elts:
                action_name = None

                if isinstance(elt, ast.Call):
                    if len(elt.args) >= 2:
                        arg = elt.args[1]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            action_name = arg.value
                elif isinstance(elt, (ast.Tuple, ast.List)):
                    if len(elt.elts) >= 2:
                        arg = elt.elts[1]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            action_name = arg.value

                if action_name:
                    method_name = f"action_{action_name}"
                    if self.cls:
                        qualified = f"{self.mod}.{self.cls}.{method_name}"
                    else:
                        qualified = f"{self.mod}.{method_name}"
                    self.add_ref(qualified)
                    self.add_ref(method_name)

    def visit_Name(self, node: ast.Name) -> None:
        if not isinstance(node.ctx, ast.Load):
            return

        if self._comprehension_scope_stack:
            for scope in reversed(self._comprehension_scope_stack):
                if node.id in scope:
                    return

        if self.current_function_params:
            for param_name, param_full_name in self.current_function_params:
                if node.id == param_name:
                    self.first_read_lineno.setdefault(param_full_name, node.lineno)
                    self.add_ref(param_full_name)
                    return

        if self._param_stack:
            for outer_params in reversed(self._param_stack):
                for param_name, param_full_name in outer_params:
                    if node.id == param_name:
                        self.first_read_lineno.setdefault(param_full_name, node.lineno)
                        self.add_ref(param_full_name)

                        if self._current_function_qname:
                            self._free_vars[self._current_function_qname].add(node.id)
                        return

        if self.current_function_scope and self.local_var_maps:
            for scope_map in reversed(self.local_var_maps):
                if node.id in scope_map:
                    fq = scope_map[node.id]
                    self.first_read_lineno.setdefault(fq, node.lineno)
                    self.add_ref(fq)
                    return

        shadowed = self._shadowed_module_aliases.get(node.id)
        if shadowed:
            self.first_read_lineno.setdefault(shadowed, node.lineno)
            self.add_ref(shadowed)
            aliased = self.alias.get(node.id)
            if aliased:
                self.first_read_lineno.setdefault(aliased, node.lineno)
                self.add_ref(aliased)
            return

        qualified = self.qual(node.id)
        self.first_read_lineno.setdefault(qualified, node.lineno)
        self.add_ref(qualified)

        if node.id in DYNAMIC_PATTERNS:
            self.dyn.add(self.mod.split(".")[0])

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.generic_visit(node)

        if not isinstance(node.ctx, ast.Load):
            return

        self._used_attr_names.add(node.attr)

        if isinstance(node.value, ast.Name):
            base = node.value.id

            param_hit = None
            for param_name, param_full in self.current_function_params:
                if base == param_name:
                    param_hit = (param_name, param_full)
                    break

            if not param_hit and self._param_stack:
                for outer_params in reversed(self._param_stack):
                    for param_name, param_full in outer_params:
                        if base == param_name:
                            param_hit = (param_name, param_full)
                            break
                    if param_hit:
                        break

            if param_hit:
                self.add_ref(param_hit[1])

                param_qname = param_hit[1]
                if param_qname in self.inferred_types:
                    type_name = self.inferred_types[param_qname]
                    self.add_ref(f"{type_name}.{node.attr}")

            if self.cls and base in {"self", "cls"}:
                owner = f"{self.mod}.{self.cls}" if self.mod else self.cls
                self.add_ref(f"{owner}.{node.attr}")
                return

            if (
                self.current_function_scope
                and self.local_type_maps
                and self.local_type_maps[-1].get(base)
            ):
                self.add_ref(f"{self.local_type_maps[-1][base]}.{node.attr}")
                return

            self.add_ref(f"{self.qual(base)}.{node.attr}")

        elif isinstance(node.value, ast.Call):
            qualified_class = self._get_call_type(node.value)

            if qualified_class:
                self.add_ref(f"{qualified_class}.{node.attr}")

        elif isinstance(node.value, ast.Attribute):
            inner = node.value
            if (
                isinstance(inner.value, ast.Name)
                and inner.value.id == "self"
                and self.cls
            ):
                owner = f"{self.mod}.{self.cls}" if self.mod else self.cls
                attr_key = f"{owner}.{inner.attr}"
                if attr_key in self.instance_attr_types:
                    type_name = self.instance_attr_types[attr_key]
                    self.add_ref(f"{type_name}.{node.attr}")

    def visit_annotation(self, node: Optional[ast.expr]) -> None:
        if node is not None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.visit_string_annotation(node.value)
            elif hasattr(node, "s") and isinstance(node.s, str):
                self.visit_string_annotation(node.s)
            else:
                self.visit(node)

    def visit_string_annotation(self, annotation_str: str) -> None:
        if not isinstance(annotation_str, str):
            return

        try:
            parsed = ast.parse(annotation_str, mode="eval")
            self.visit(parsed.body)
        except SyntaxError:
            IGNORE_ANN_TOKENS = {
                "Any",
                "Optional",
                "Union",
                "Literal",
                "Callable",
                "Iterable",
                "Iterator",
                "Sequence",
                "Mapping",
                "MutableMapping",
                "Dict",
                "List",
                "Set",
                "Tuple",
                "Type",
                "Protocol",
                "TypedDict",
                "Self",
                "Final",
                "ClassVar",
                "Annotated",
                "Never",
                "NoReturn",
                "Required",
                "NotRequired",
                "int",
                "str",
                "float",
                "bool",
                "bytes",
                "object",
            }

            for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", annotation_str):
                if tok in IGNORE_ANN_TOKENS:
                    continue
                self.add_ref(self.qual(tok))

    def visit_arguments(self, args: ast.arguments) -> None:
        for arg in args.args:
            self.visit_annotation(arg.annotation)
        for arg in args.posonlyargs:
            self.visit_annotation(arg.annotation)
        for arg in args.kwonlyargs:
            self.visit_annotation(arg.annotation)
        if args.vararg:
            self.visit_annotation(args.vararg.annotation)
        if args.kwarg:
            self.visit_annotation(args.kwarg.annotation)
        for default in args.defaults:
            self.visit(default)
        for default in args.kw_defaults:
            if default:
                self.visit(default)

    def _annotation_to_string(self, node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value
            return str(node.value)
        elif isinstance(node, ast.Attribute):
            return self._get_attr_chain(node)
        elif isinstance(node, ast.Subscript):
            base = self._annotation_to_string(node.value)
            return base
        return None

    def _get_attr_chain(self, node: ast.expr) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.AST):
            node.value.parent = node
        if isinstance(node.slice, ast.AST):
            node.slice.parent = node

        self.visit(node.value)
        self.visit(node.slice)

    def visit_Slice(self, node: ast.Slice) -> None:
        if node.lower and isinstance(node.lower, ast.AST):
            node.lower.parent = node
            self.visit(node.lower)
        if node.upper and isinstance(node.upper, ast.AST):
            node.upper.parent = node
            self.visit(node.upper)
        if node.step and isinstance(node.step, ast.AST):
            node.step.parent = node
            self.visit(node.step)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            nm = node.target.id
            var_name = self._compute_variable_name(nm)

            self.add_def(var_name, "variable", node.lineno)
            if self.current_function_scope and self.local_var_maps:
                self.local_var_maps[-1][nm] = var_name
            self.add_ref(var_name)

    def visit_keyword(self, node: ast.keyword) -> None:
        self.visit(node.value)

    def visit_withitem(self, node: ast.withitem) -> None:
        self.visit(node.context_expr)
        if node.optional_vars:
            self.visit(node.optional_vars)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type:
            self.visit(node.type)

        if node.name:
            var_name = self._compute_variable_name(node.name)
            self.add_def(var_name, "variable", node.lineno)
            if self.current_function_scope and self.local_var_maps:
                self.local_var_maps[-1][node.name] = var_name

        for stmt in node.body:
            self.visit(stmt)

    def generic_visit(self, node: ast.AST) -> None:
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        item.parent = node
                        self.visit(item)
            elif isinstance(value, ast.AST):
                value.parent = node
                self.visit(value)

    def finalize(self) -> None:
        for defn in self.defs:
            if defn.name in self.call_graph:
                defn.calls = self.call_graph[defn.name]
            if defn.name in self.reverse_call_graph:
                defn.called_by = self.reverse_call_graph[defn.name]

        for class_qname in self.descriptor_classes:
            for defn in self.defs:
                if defn.name == class_qname:
                    defn.is_descriptor = True

        self._apply_string_patterns()

    def _apply_string_patterns(self) -> None:
        for pattern in self._string_ref_patterns:
            regex_pattern = pattern.replace("*", ".*")
            try:
                regex = re.compile(f"^{regex_pattern}$")
            except re.error:
                continue

            for defn in self.defs:
                if regex.match(defn.simple_name):
                    defn.references += 1
                    self.pattern_tracker.known_refs.add(defn.simple_name)

    def get_call_graph(self) -> dict[str, set[str]]:
        return dict(self.call_graph)

    def get_reverse_call_graph(self) -> dict[str, set[str]]:
        return dict(self.reverse_call_graph)

    def get_unreachable_from_entries(self, entry_points: set[str]) -> set[str]:
        reachable = set()
        stack = list(entry_points)

        while stack:
            current = stack.pop()
            if current in reachable:
                continue
            reachable.add(current)

            for callee in self.call_graph.get(current, []):
                if callee not in reachable:
                    stack.append(callee)

        all_defs = {d.name for d in self.defs if d.type in ("function", "method")}
        return all_defs - reachable
