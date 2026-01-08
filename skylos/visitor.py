#!/usr/bin/env python3
import ast
from pathlib import Path
import re
from skylos.control_flow import evaluate_static_condition, extract_constant_string
from skylos.implicit_refs import pattern_tracker

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

## "🥚" hi :)


class Definition:
    def __init__(self, name, t, filename, line):
        self.name = name
        self.type = t
        self.filename = filename
        self.line = line
        self.simple_name = name.split(".")[-1]
        self.confidence = 100
        self.references = 0
        self.is_exported = False
        self.in_init = "__init__.py" in str(filename)

    def to_dict(self):
        if self.type == "method" and "." in self.name:
            parts = self.name.split(".")
            if len(parts) >= 3:
                output_name = ".".join(parts[-2:])
            else:
                output_name = self.name
        else:
            output_name = self.simple_name

        return {
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


class Visitor(ast.NodeVisitor):
    def __init__(self, mod, file):
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

    def add_def(self, name, t, line):
        found = False
        for d in self.defs:
            if d.name == name:
                found = True
                break
        if not found:
            self.defs.append(Definition(name, t, self.file, line))

    def add_ref(self, name):
        self.refs.append((name, self.file))

    def qual(self, name):
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

    def visit_Global(self, node):
        if self.current_function_scope and self.local_var_maps:
            for name in node.names:
                self.local_var_maps[-1][name] = f"{self.mod}.{name}"
        return

    def visit_annotation(self, node):
        if node is not None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.visit_string_annotation(node.value)
            elif hasattr(node, "s") and isinstance(node.s, str):
                self.visit_string_annotation(node.s)
            else:
                self.visit(node)

    def visit_string_annotation(self, annotation_str):
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

    def visit_Import(self, node):
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

    def visit_ImportFrom(self, node):
        if node.module is None:
            return

        for a in node.names:
            if a.name == "*":
                continue

            base = node.module
            if node.level:
                parts = self.mod.split(".")
                base = ".".join(parts[: -node.level]) + (
                    f".{node.module}" if node.module else ""
                )

            full = f"{base}.{a.name}"
            if a.asname:
                self.alias[a.asname] = full
                self.add_def(full, "import", node.lineno)
            else:
                self.alias[a.name] = full
                self.add_def(full, "import", node.lineno)

    def visit_If(self, node):
        condition = evaluate_static_condition(node.test)

        self.visit(node.test)

        if condition is True:
            for statement in node.body:
                self.visit(statement)
        elif condition is False:
            for statement in node.orelse:
                self.visit(statement)
        else:
            for statement in node.body:
                self.visit(statement)
            for statement in node.orelse:
                self.visit(statement)

    def visit_arguments(self, args):
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
    
    def _process_textual_bindings(self, node):
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

    def _get_decorator_name(self, deco):
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

    def visit_FunctionDef(self, node):
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
        self.add_def(qualified_name, def_type, node.lineno)

        for d in node.decorator_list:
            self.visit(d)

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
        }

        is_abstract_or_overload = False
        for deco in node.decorator_list:
            deco_name = self._get_decorator_name(deco)
            if deco_name in ("abstractmethod", "abc.abstractmethod", "overload", "typing.overload", "typing_extensions.overload"):
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
        
        prev_abstract_overload = getattr(self, '_in_abstract_or_overload', False)

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
                elif deco_name.endswith((".setter", ".deleter")):
                    self.add_ref(qualified_name)
                elif any(
                    keyword in deco_name.lower() for keyword in FRAMEWORK_DECORATORS
                ):
                    self.add_ref(qualified_name)

            elif deco_name and deco_name.endswith((".setter", ".deleter")):
                self.add_ref(qualified_name)

        if self.current_function_scope and self.local_var_maps:
            self.local_var_maps[-1][node.name] = qualified_name

        self.current_function_scope.append(node.name)
        self.local_var_maps.append({})
        self.local_type_maps.append({})
        self.local_constants.append({})

        old_params = self.current_function_params
        self._param_stack.append(old_params)
        self.current_function_params = []

        all_args = []
        all_args.extend(node.args.posonlyargs)
        all_args.extend(node.args.args)
        all_args.extend(node.args.kwonlyargs)

        skip_params = self._in_protocol_class or getattr(self, '_in_abstract_or_overload', False)
        
        for arg in all_args:
            param_name = f"{qualified_name}.{arg.arg}"
            if not skip_params:
                self.add_def(param_name, "parameter", getattr(arg, "lineno", node.lineno))
            self.current_function_params.append((arg.arg, param_name))

        if node.args.vararg:
            va = node.args.vararg
            param_name = f"{qualified_name}.{va.arg}"
            if not skip_params:
                self.add_def(param_name, "parameter", getattr(va, "lineno", node.lineno))
            self.current_function_params.append((va.arg, param_name))

        if node.args.kwarg:
            ka = node.args.kwarg
            param_name = f"{qualified_name}.{ka.arg}"
            if not skip_params:
                self.add_def(param_name, "parameter", getattr(ka, "lineno", node.lineno))
            self.current_function_params.append((ka.arg, param_name))

        self.visit_arguments(node.args)
        self.visit_annotation(node.returns)

        for stmt in node.body:
            self.visit(stmt)

        self.current_function_scope.pop()
        self.current_function_params = self._param_stack.pop()
        self.local_var_maps.pop()
        self.local_type_maps.pop()
        self.local_constants.pop()

        self._in_abstract_or_overload = prev_abstract_overload

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        cname = f"{self.mod}.{node.name}"
        self.add_def(cname, "class", node.lineno)

        is_protocol = False
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == "Protocol":
                is_protocol = True
            elif isinstance(base, ast.Attribute) and base.attr == "Protocol":
                is_protocol = True
        
        if is_protocol:
            self.protocol_classes.add(node.name)

        is_abc_class = False
        for base in node.bases:
            base_name = None
            if isinstance(base, ast.Name):
                base_name = base.id
            elif isinstance(base, ast.Attribute):
                base_name = base.attr
            
            if not base_name:
                continue
            
            if base_name == "ABC":
                is_abc_class = True
                self.abc_classes.add(node.name)
            
            elif base_name in self.abc_classes:
                if node.name not in self.abc_implementers:
                    self.abc_implementers[node.name] = []
                self.abc_implementers[node.name].append(base_name)
            
            elif base_name in self.protocol_classes:
                if node.name not in self.protocol_implementers:
                    self.protocol_implementers[node.name] = []
                self.protocol_implementers[node.name].append(base_name)

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
            if base_name in ("Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"):
                is_enum = True
            if base_name in ("Base", "Model", "DeclarativeBase", "SQLModel", "Document"):
                is_orm_model = True
        
        if is_namedtuple:
            self.namedtuple_classes.add(node.name)
        if is_enum:
            self.enum_classes.add(node.name)
        if is_orm_model:
            self.orm_model_classes.add(node.name)
        
        for deco in node.decorator_list:
            deco_name = self._get_decorator_name(deco)
            if deco_name in ("attr.s", "attr.attrs", "attrs", "define", "attr.define", "frozen", "attr.frozen"):
                self.attrs_classes.add(node.name)
                break
        
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

        for keyword in node.keywords:
            self.visit(keyword.value)

        for decorator in node.decorator_list:

            def _is_dc(dec):
                target = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(target, ast.Name):
                    return target.id == "dataclass"
                if isinstance(target, ast.Attribute):
                    return target.attr == "dataclass"
                return False

            if _is_dc(decorator):
                is_dc = True
            self.visit(decorator)

        prev = self.cls
        if is_cst:
            self.in_cst_class += 1
        
        self.cls = node.name
        self._dataclass_stack.append(is_dc)

        for b in node.body:
            self.visit(b)

        self.cls = prev
        self._dataclass_stack.pop()
        self._typed_dict_stack.pop()

        if is_cst:
            self.in_cst_class -= 1

        self._in_protocol_class = prev_in_protocol

    def visit_AnnAssign(self, node):
        self.visit_annotation(node.annotation)

        if isinstance(node.target, ast.Name):
            ann = node.annotation
            is_type_alias = False
            if isinstance(ann, ast.Name) and ann.id == "TypeAlias":
                is_type_alias = True
            elif isinstance(ann, ast.Attribute) and ann.attr == "TypeAlias":
                is_type_alias = True
            elif isinstance(ann, ast.Subscript):
                if isinstance(ann.value, ast.Attribute) and ann.value.attr == "TypeAlias":
                    is_type_alias = True
            
            if is_type_alias:
                self.type_alias_names.add(node.target.id)
        
        if node.value:
            self.visit(node.value)

        if node.value:
            self.visit(node.value)

        def _define(t):
            if isinstance(t, ast.Name):
                name_simple = t.id
                scope_parts = [self.mod]
                if self.cls:
                    scope_parts.append(self.cls)

                if self.current_function_scope:
                    scope_parts.extend(self.current_function_scope)
                prefix = ".".join(filter(None, scope_parts))
                if prefix:
                    var_name = f"{prefix}.{name_simple}"
                else:
                    var_name = name_simple

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

            elif isinstance(t, (ast.Tuple, ast.List)):
                for elt in t.elts:
                    _define(elt)

        _define(node.target)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            nm = node.target.id
            if (
                self.current_function_scope
                and self.local_var_maps
                and self.local_var_maps
                and nm in self.local_var_maps[-1]
            ):
                # self.add_ref(self.local_var_maps[-1][nm])
                fq = self.local_var_maps[-1][nm]
                self.add_ref(fq)
                var_name = fq

            else:
                self.add_ref(self.qual(nm))
                scope_parts = [self.mod]
                if self.cls:
                    scope_parts.append(self.cls)

                if self.current_function_scope:
                    scope_parts.extend(self.current_function_scope)
                prefix = ".".join(filter(None, scope_parts))
                if prefix:
                    var_name = f"{prefix}.{nm}"
                else:
                    var_name = nm

            self.add_def(var_name, "variable", node.lineno)
            if self.current_function_scope and self.local_var_maps:
                self.local_var_maps[-1][nm] = var_name
        else:
            self.visit(node.target)
        self.visit(node.value)

    def visit_Subscript(self, node):

        if isinstance(node.value, ast.AST):
            node.value.parent = node
        if isinstance(node.slice, ast.AST):
            node.slice.parent = node

        self.visit(node.value)
        self.visit(node.slice)

    def visit_Slice(self, node):
        if node.lower and isinstance(node.lower, ast.AST):
            node.lower.parent = node
            self.visit(node.lower)
        if node.upper and isinstance(node.upper, ast.AST):
            node.upper.parent = node
            self.visit(node.upper)
        if node.step and isinstance(node.step, ast.AST):
            node.step.parent = node
            self.visit(node.step)

    def _should_skip_variable_def(self, name_simple):
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

    def _compute_variable_name(self, name_simple):
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

    def _process_target_for_def(self, target_node):
        if isinstance(target_node, ast.Name):
            name_simple = target_node.id

            if self._should_skip_variable_def(name_simple):
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
                self._process_target_for_def(elt)

    def _extract_string_value(self, elt):
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            return elt.value
        if hasattr(elt, "s") and isinstance(elt.s, str):
            return elt.s
        return None

    def _process_dunder_all_exports(self, node):
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

    def _resolve_callee_fqname_from_name(self, callee):
        return self.alias.get(callee.id, self.qual(callee.id))

    def _resolve_callee_fqname_from_attribute(self, callee):
        parts = []
        cur = callee

        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value

        if not isinstance(cur, ast.Name):
            return None

        head = self.alias.get(cur.id, self.qual(cur.id))
        if not head:
            return None

        return ".".join([head] + list(reversed(parts)))

    def _resolve_callee_fqname(self, callee):
        if isinstance(callee, ast.Name):
            return self._resolve_callee_fqname_from_name(callee)

        if isinstance(callee, ast.Attribute):
            return self._resolve_callee_fqname_from_attribute(callee)

        return None

    def _mark_target_type(self, target, fqname):
        if isinstance(target, ast.Name):
            self.local_type_maps[-1][target.id] = fqname
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_target_type(elt, fqname)

    def _try_infer_types_from_call(self, node):
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

    def _extract_class_name_from_call(self, call_func):
        if isinstance(call_func, ast.Name):
            return call_func.id
        if isinstance(call_func, ast.Attribute):
            return call_func.attr
        return None

    def _track_instance_attr_types(self, node):
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
            class_name = self._extract_class_name_from_call(call_func)

            if not class_name:
                continue
            if not class_name[0].isupper():
                continue

            owner = f"{self.mod}.{self.cls}" if self.mod else self.cls
            attr_key = f"{owner}.{target.attr}"
            qualified_class = self.alias.get(class_name, self.qual(class_name))
            self.instance_attr_types[attr_key] = qualified_class

    def visit_Assign(self, node):
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

        self._process_dunder_all_exports(node)
        self._try_infer_types_from_call(node)
        self._process_textual_bindings(node)
        self.generic_visit(node)
        self._track_instance_attr_types(node)

    def _extract_fstring_pattern(self, node: ast.JoinedStr):
        """Convert f'handle_{x}' to 'handle_*'"""
        parts = []
        has_var = False
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                parts.append("*")
                has_var = True
        return "".join(parts) if has_var else None

    def visit_Call(self, node):
        self.generic_visit(node)

        if isinstance(node.func, ast.Name) and node.func.id == "NewType":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.type_alias_names.add(node.args[0].value)

        if (
            isinstance(node.func, ast.Name)
            and node.func.id in ("getattr", "hasattr")
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

            elif isinstance(node.args[0], ast.Name):
                target_name = node.args[0].id
                if target_name != "self":
                    if isinstance(node.args[1], ast.Name):
                        var_name = node.args[1].id
                        if var_name in self.pattern_tracker.f_string_patterns:
                            pattern = self.pattern_tracker.f_string_patterns[var_name]
                            self.pattern_tracker.pattern_refs.append((pattern, 70))
                        elif (
                            self.local_constants
                            and var_name in self.local_constants[-1]
                        ):
                            val = self.local_constants[-1][var_name]
                            self.pattern_tracker.known_refs.add(val)

        elif isinstance(node.func, ast.Name) and node.func.id == "globals":
            parent = getattr(node, "parent", None)
            if (
                isinstance(parent, ast.Subscript)
                and isinstance(parent.slice, ast.Constant)
                and isinstance(parent.slice.value, str)
            ):
                func_name = parent.slice.value
                self.add_ref(func_name)
                self.add_ref(f"{self.mod}.{func_name}")

        elif isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            root_mod = ""
            if self.mod:
                root_mod = self.mod.split(".")[0]
            self.dyn.add(root_mod)

        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id == "super"
        ):
            method_name = node.func.attr
            if self.cls:
                if self.mod:
                    owner = f"{self.mod}.{self.cls}"
                else:
                    owner = self.cls
                self.add_ref(f"{owner}.{method_name}")

    def visit_Name(self, node):
        if not isinstance(node.ctx, ast.Load):
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

    def visit_Attribute(self, node):
        self.generic_visit(node)

        if not isinstance(node.ctx, ast.Load):
            return

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

            if self.cls and base in {"self", "cls"}:
                if self.mod:
                    owner = f"{self.mod}.{self.cls}"
                else:
                    owner = self.cls

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

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            nm = node.target.id
            scope_parts = [self.mod]

            if self.cls:
                scope_parts.append(self.cls)

            if self.current_function_scope:
                scope_parts.extend(self.current_function_scope)

            prefix = ".".join(filter(None, scope_parts))
            var_name = f"{prefix}.{nm}" if prefix else nm

            self.add_def(var_name, "variable", node.lineno)
            if self.current_function_scope and self.local_var_maps:
                self.local_var_maps[-1][nm] = var_name
            self.add_ref(var_name)

    def visit_keyword(self, node):
        self.visit(node.value)

    def visit_withitem(self, node):
        self.visit(node.context_expr)
        if node.optional_vars:
            self.visit(node.optional_vars)

    def visit_ExceptHandler(self, node):
        if node.type:
            self.visit(node.type)
        for stmt in node.body:
            self.visit(stmt)

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        item.parent = node
                        self.visit(item)
            elif isinstance(value, ast.AST):
                value.parent = node
                self.visit(value)
