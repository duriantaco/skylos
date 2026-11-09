"""Bounded checks for concrete Python security configuration and input gaps.

Unknown values are not treated as attacker input. API checks require an import
binding; dynamic imports additionally require the existing source evidence.
"""

from __future__ import annotations

import ast
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from .untrusted_sources import (
    UntrustedSourceIndex,
    _scope_bindings,
    _unsafe_import_roots,
)
from .module_namespace import attribute_write_names, module_name_for, module_rebinding

_HTTP_CALLS = {
    f"{module}.{method}"
    for module in ("requests", "httpx")
    for method in (
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
    )
} | {"urllib.request.urlopen", "urllib.request.Request"}
_GRADIO_FACTORIES = {"gradio.Blocks", "gradio.Interface", "gradio.ChatInterface"}
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_UNKNOWN = object()


@dataclass(frozen=True)
class _Alternatives:
    values: tuple


class _Checker(ast.NodeVisitor):
    def __init__(self, tree, file_path, findings, project_root=None):
        self.file_path = str(file_path)
        self.findings = findings
        self.bindings: dict[str, str | ast.AST | None] = {}
        self.container_values: dict[str, ast.AST] = {}
        self.path_arguments: dict[str, ast.AST] = {}
        self.flask_apps: set[str] = set()
        self.flask_config_keys: set[str] = set()
        self.flask_instances: dict[str, int] = {}
        self.flask_config_instances: dict[str, int] = {}
        self.functions: list[ast.AST] = []
        self.symbols = ["<module>"]
        self.sources = None
        self.provider_sources = UntrustedSourceIndex(tree)
        self.provider_scopes = {id(tree): _scope_bindings(tree)}
        self.written_attributes, self.computed_attributes = attribute_write_names(tree)
        self.dynamic_namespace, self.rebound_globals = module_rebinding(
            tree, module_name_for(file_path)
        )
        self.unsafe_import_roots, self.unknown_global_write = _unsafe_import_roots(tree)
        self.imported_roots: dict[str, str] = {}
        self.cached_functions: set[int] = set()
        self.tree = tree
        self.project_root = project_root
        self.project_sources = None

    def _name(self, node, depth=0):
        if depth > 12:
            return None
        if isinstance(node, ast.Name):
            value = self.bindings.get(node.id)
            if isinstance(value, str):
                if node.id in self.imported_roots:
                    bindings = dict(self.provider_scopes[id(self.tree)])
                    for function in self.functions:
                        if id(function) not in self.provider_scopes:
                            self.provider_scopes[id(function)] = _scope_bindings(
                                function
                            )
                        bindings.update(self.provider_scopes[id(function)])
                    loader = value in {
                        "importlib",
                        "importlib.import_module",
                        "builtins",
                        "builtins.__import__",
                    }
                    if (
                        (
                            self.dynamic_namespace
                            and not (loader and not self.unknown_global_write)
                        )
                        or node.id in self.rebound_globals
                        or (loader and node.id in self.unsafe_import_roots)
                        or bindings.get(node.id) != self.imported_roots[node.id]
                    ):
                        return None
                    if (
                        self.computed_attributes
                        or value.rsplit(".", 1)[-1] in self.written_attributes
                    ):
                        return None
                return value
            if isinstance(value, ast.AST):
                return self._name(value, depth + 1)
        if isinstance(node, ast.Attribute):
            base = self._name(node.value, depth + 1)
            if base:
                name = f"{base}.{node.attr}"
                if self.computed_attributes or node.attr in self.written_attributes:
                    return None
                if name in self.bindings:
                    return (
                        self.bindings[name]
                        if isinstance(self.bindings[name], str)
                        else None
                    )
                return name
        if isinstance(node, ast.Call):
            name = self._name(node.func, depth + 1)
            if name in _GRADIO_FACTORIES or name == "pathlib.Path":
                return name
        return None

    def _literal(self, node, depth=0):
        if depth > 12:
            return _UNKNOWN
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            value = self.bindings.get(node.id)
            if isinstance(value, ast.AST):
                return self._literal(value, depth + 1)
        if isinstance(node, ast.Subscript):
            value = self.container_values.get(ast.dump(node, include_attributes=False))
            if value is not None:
                return self._literal(value, depth + 1)
        if (
            isinstance(node, ast.Call)
            and self._name(node.func) in {"os.path.abspath", "os.path.normpath"}
            and node.args
        ):
            value = self._literal(node.args[0], depth + 1)
            if isinstance(value, str) and value.startswith("/"):
                # The absolute literal is already fixed; never interpret a
                # relative path using the scanner's working directory.
                return value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = (
                self._literal(node.left, depth + 1),
                self._literal(node.right, depth + 1),
            )
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        return _UNKNOWN

    def _choices(self, node, depth=0):
        if depth > 12:
            return [None]
        if isinstance(node, ast.Name):
            return self._choices(self.bindings.get(node.id), depth + 1)
        if isinstance(node, _Alternatives):
            values = []
            for value in node.values:
                values.extend(self._choices(value, depth + 1))
            return values[:16]
        return [node] if isinstance(node, ast.AST) else [None]

    def _url_prefix(self, node, depth=0):
        """A fixed URL prefix; stop before the first unknown formatted value."""
        if depth > 12:
            return ""
        if isinstance(node, ast.Name):
            return self._url_prefix(self.bindings.get(node.id), depth + 1)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            prefix = ""
            for part in node.values:
                if not isinstance(part, ast.Constant) or not isinstance(
                    part.value, str
                ):
                    break
                prefix += part.value
            return prefix
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._literal(node.left)
            prefix = self._url_prefix(node.left, depth + 1)
            if isinstance(left, str):
                prefix += self._url_prefix(node.right, depth + 1)
            return prefix
        return ""

    def _emit(self, node, rule, severity, message, evidence=None):
        finding = {
            "rule_id": rule,
            "severity": severity,
            "message": message,
            "file": self.file_path,
            "line": node.lineno,
            "col": node.col_offset,
            "symbol": self.symbols[-1],
        }
        if evidence:
            finding["security_evidence"] = evidence
        self.findings.append(finding)

    def visit_Import(self, node):
        for alias in node.names:
            self.bindings[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )
            self.imported_roots[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )

    def visit_ImportFrom(self, node):
        if node.level or not node.module:
            return
        for alias in node.names:
            if alias.name != "*":
                self.bindings[alias.asname or alias.name] = (
                    f"{node.module}.{alias.name}"
                )
                self.imported_roots[alias.asname or alias.name] = (
                    f"{node.module}.{alias.name}"
                )

    def _bind(self, target, value):
        if isinstance(target, ast.Name):
            # Capture aliases at assignment time; later rebinding the original
            # name must not change the callable that was already captured.
            self.bindings[target.id] = (
                self._mapping(value) or self._name(value) or value
            )
            self.path_arguments.pop(target.id, None)
            self.flask_apps.discard(target.id)
            self.flask_instances.pop(target.id, None)
            if isinstance(value, ast.Call) and self._name(value.func) == "flask.Flask":
                self.flask_apps.add(target.id)
                self.flask_instances[target.id] = id(value)
            elif isinstance(value, ast.Name) and value.id in self.flask_instances:
                self.flask_apps.add(target.id)
                self.flask_instances[target.id] = self.flask_instances[value.id]
            if (
                isinstance(value, ast.Call)
                and self._name(value.func) == "pathlib.Path"
                and value.args
            ):
                self.path_arguments[target.id] = value.args[0]
        elif isinstance(target, ast.Attribute):
            name = self._name(target)
            if name:
                self.bindings[name] = None
        elif isinstance(target, ast.Subscript) and value is not None:
            if isinstance(target.value, ast.Name):
                self._invalidate_mapping(target.value)
            key = ast.dump(target, include_attributes=False)
            # Store and load contexts differ but identify the same container.
            self.container_values[key.replace("ctx=Store()", "ctx=Load()")] = value
            if (
                isinstance(target.value, ast.Attribute)
                and target.value.attr == "config"
                and isinstance(target.value.value, ast.Name)
                and target.value.value.id in self.flask_apps
            ):
                self.flask_config_keys.add(key.replace("ctx=Store()", "ctx=Load()"))
                self.flask_config_instances[
                    key.replace("ctx=Store()", "ctx=Load()")
                ] = self.flask_instances[target.value.value.id]
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, None)

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self._bind(target, node.value)

    def visit_AnnAssign(self, node):
        if node.value:
            self.visit(node.value)
        self._bind(node.target, node.value)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._bind(item.optional_vars, item.context_expr)
        for child in node.body:
            self.visit(child)

    visit_AsyncWith = visit_With

    def visit_For(self, node):
        self.visit(node.iter)
        self._bind(node.target, None)
        sequences = self._choices(node.iter)
        if isinstance(node.target, ast.Name) and all(
            isinstance(value, (ast.List, ast.Tuple)) for value in sequences
        ):
            elements = [element for sequence in sequences for element in sequence.elts]
            if elements and len(elements) <= 16:
                self.bindings[node.target.id] = _Alternatives(tuple(elements))
        for child in [*node.body, *node.orelse]:
            self.visit(child)

    visit_AsyncFor = visit_For

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bindings[node.name] = None
        for child in node.body:
            self.visit(child)

    def _mapping(self, expression):
        for _ in range(12):
            if not isinstance(expression, ast.Name):
                break
            expression = self.bindings.get(expression.id)
        return expression if isinstance(expression, ast.Dict) else None

    def _invalidate_mapping(self, expression):
        mappings = {
            id(value)
            for value in self._choices(expression)
            if isinstance(value, ast.Dict)
        }
        if mappings:
            aliases = [
                name
                for name in self.bindings
                if any(
                    id(value) in mappings for value in self._choices(ast.Name(id=name))
                )
            ]
            for name in aliases:
                self.bindings[name] = None

    def _append_sequence(self, expression, value):
        replacements = {
            id(sequence): ast.List(elts=[*sequence.elts, value])
            for sequence in self._choices(expression)
            if isinstance(sequence, ast.List) and len(sequence.elts) < 16
        }
        for name in list(self.bindings):
            values = self._choices(ast.Name(id=name))
            if any(id(item) in replacements for item in values):
                self.bindings[name] = _Alternatives(
                    tuple(replacements.get(id(item), item) for item in values)
                )

    def _invalidate_sequence(self, expression):
        ids = {
            id(value)
            for value in self._choices(expression)
            if isinstance(value, ast.List)
        }
        for name in list(self.bindings):
            if any(id(value) in ids for value in self._choices(ast.Name(id=name))):
                self.bindings[name] = None

    def visit_FunctionDef(self, node):
        if any(
            self._name(d.func if isinstance(d, ast.Call) else d)
            in {"functools.cached_property", "functools.lru_cache", "functools.cache"}
            for d in node.decorator_list
        ):
            self.cached_functions.add(id(node))
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.bindings[node.name] = None
        outer = self.bindings.copy()
        outer_containers = self.container_values.copy()
        outer_paths = self.path_arguments.copy()
        outer_flask_apps = self.flask_apps.copy()
        outer_flask_instances = self.flask_instances.copy()
        for arg in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
            node.args.vararg,
            node.args.kwarg,
        ]:
            if arg:
                self.bindings[arg.arg] = None
        # A local assignment shadows an outer import throughout the function.
        stack = list(node.body)
        while stack:
            child = stack.pop()
            if isinstance(child, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
                self.bindings[getattr(child, "name", "")] = None
                continue
            if isinstance(child, ast.Name) and isinstance(
                child.ctx, (ast.Store, ast.Del)
            ):
                self.bindings[child.id] = None
            stack.extend(ast.iter_child_nodes(child))
        self.functions.append(node)
        self.symbols.append(node.name)
        for child in node.body:
            self.visit(child)
        self.symbols.pop()
        self.functions.pop()
        self.bindings = outer
        self.container_values = outer_containers
        self.path_arguments = outer_paths
        self.flask_apps = outer_flask_apps
        self.flask_instances = outer_flask_instances

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.bindings[node.name] = None
        outer = self.bindings.copy()
        self._index_cached_helpers(node)
        self.symbols.append(node.name)
        for child in node.body:
            self.visit(child)
        self.symbols.pop()
        self.bindings = outer

    def _index_cached_helpers(self, cls):
        methods = {
            child.name: child for child in cls.body if isinstance(child, _FUNCTIONS)
        }
        pending = [
            method
            for method in methods.values()
            if any(
                self._name(d.func if isinstance(d, ast.Call) else d)
                in {
                    "functools.cached_property",
                    "functools.lru_cache",
                    "functools.cache",
                }
                for d in method.decorator_list
            )
        ]
        rounds = 0
        while pending and rounds < 64:
            method = pending.pop()
            if id(method) in self.cached_functions:
                continue
            rounds += 1
            self.cached_functions.add(id(method))
            for child in ast.walk(method):
                # A cached render can invoke callbacks returned by a helper.
                if isinstance(child, _FUNCTIONS):
                    self.cached_functions.add(id(child))
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id in {"self", "cls"}
                ):
                    target = methods.get(child.func.attr)
                    if target and id(target) not in self.cached_functions:
                        pending.append(target)

    def visit_If(self, node):
        self.visit(node.test)
        before = self.bindings.copy()
        before_containers = self.container_values.copy()
        before_paths = self.path_arguments.copy()
        for child in node.body:
            self.visit(child)
        body = self.bindings
        body_containers = self.container_values
        body_paths = self.path_arguments
        self.bindings = before.copy()
        self.container_values = before_containers.copy()
        self.path_arguments = before_paths.copy()
        for child in node.orelse:
            self.visit(child)
        other = self.bindings
        changed = {
            name
            for name in body.keys() | other.keys()
            if body.get(name) != other.get(name)
        }
        self.container_values = {
            key: value
            for key, value in body_containers.items()
            if self.container_values.get(key) is value
        }
        self.path_arguments = {
            key: value
            for key, value in body_paths.items()
            if self.path_arguments.get(key) is value
        }
        self.bindings = {
            name: (
                None
                if name in changed and len(changed) > 1
                else self._join_binding(body.get(name), other.get(name))
            )
            for name in body.keys() | other.keys()
        }

    @staticmethod
    def _join_binding(left, right):
        if left == right:
            return left
        values = []
        for value in (left, right):
            values.extend(value.values if isinstance(value, _Alternatives) else [value])
        if len(values) <= 16 and all(
            value is None
            or isinstance(value, (ast.Dict, ast.List, ast.Tuple, ast.Constant))
            for value in values
        ):
            return _Alternatives(tuple(values))
        return None

    def _keywords(self, call):
        values = {}
        unknown = False
        for keyword in call.keywords:
            if keyword.arg is not None:
                values[keyword.arg] = keyword.value
                continue
            mapping = keyword.value
            for _ in range(12):
                if not isinstance(mapping, ast.Name):
                    break
                mapping = self.bindings.get(mapping.id)
            if not isinstance(mapping, ast.Dict) or any(
                not isinstance(key, ast.Constant) or not isinstance(key.value, str)
                for key in mapping.keys
            ):
                unknown = True
                continue
            values.update(
                {key.value: value for key, value in zip(mapping.keys, mapping.values)}
            )
        return values, unknown

    def _keyword_variants(self, call):
        variants = [({}, False)]
        for keyword in call.keywords:
            if keyword.arg is not None:
                for values, _ in variants:
                    values[keyword.arg] = keyword.value
                continue
            merged = []
            for choice in self._choices(keyword.value):
                known = isinstance(choice, ast.Dict) and all(
                    isinstance(key, ast.Constant) and isinstance(key.value, str)
                    for key in choice.keys
                )
                for values, unknown in variants:
                    updated = values.copy()
                    if known:
                        updated.update(
                            {
                                key.value: value
                                for key, value in zip(choice.keys, choice.values)
                            }
                        )
                    merged.append((updated, unknown or not known))
            if len(merged) > 16:
                return [({}, True)]
            variants = merged
        return variants

    def visit_Call(self, node):
        name = self._name(node.func)
        kwargs, unpacked = self._keywords(node)
        if (
            name
            in {
                "subprocess.Popen",
                "subprocess.run",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
            }
            and self.project_root is not None
            and not unpacked
            and ("shell" not in kwargs or self._literal(kwargs["shell"]) is False)
        ):
            imports = _scope_bindings(self.tree)
            if "shlex.split" in imports.values() or "shlex" in imports.values():
                from .project_security_sources import ProjectSources

                if self.project_sources is None:
                    self.project_sources = ProjectSources(self.project_root)
                evidence = self.project_sources.command_evidence(self.file_path, node)
                if evidence:
                    self._emit(
                        node,
                        "SKY-D212",
                        "HIGH",
                        "Untrusted input expands into command arguments without a proven option boundary; use a fixed argument allowlist or an option terminator.",
                        evidence,
                    )
        if name in {
            "jinja2.Environment",
            "jinja2.SandboxedEnvironment",
            "jinja2.sandbox.SandboxedEnvironment",
        }:
            autoescape = kwargs.get(
                "autoescape", node.args[16] if len(node.args) > 16 else None
            )
            if (
                autoescape is None
                and not unpacked
                and not any(isinstance(arg, ast.Starred) for arg in node.args)
            ) or (
                autoescape is not None and self._literal(autoescape) in (False, None)
            ):
                self._emit(
                    node,
                    "SKY-D355",
                    "HIGH",
                    "Jinja environment disables HTML autoescaping; enable autoescape or select_autoescape for HTML templates.",
                )
        if name in _HTTP_CALLS:
            position = 1 if name in {"requests.request", "httpx.request"} else 0
            url = (
                node.args[position]
                if len(node.args) > position
                else kwargs.get("url", kwargs.get("fullurl"))
            )
            value = self._literal(url)
            prefix = value if isinstance(value, str) else self._url_prefix(url)
            if prefix.lower().startswith("http://"):
                try:
                    host = urlsplit(prefix).hostname
                except ValueError:
                    host = None
                    prefix = ""
                authority_complete = isinstance(value, str) or any(
                    char in prefix[7:] for char in "/?#"
                )
                loopback = authority_complete and host == "localhost"
                try:
                    loopback = loopback or (
                        authority_complete
                        and ipaddress.ip_address(host or "").is_loopback
                    )
                except ValueError:
                    pass
                if prefix and (host or not isinstance(value, str)) and not loopback:
                    self._emit(
                        node,
                        "SKY-D356",
                        "MEDIUM",
                        "Outbound request URL has an explicit cleartext HTTP scheme; use HTTPS to protect data in transit.",
                    )
        if name in {"importlib.import_module", "builtins.__import__"} or (
            isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
            and "__import__" not in self.bindings
            and not self.unknown_global_write
            and "__import__" not in self.unsafe_import_roots
        ):
            if self.sources is None:
                self.sources = UntrustedSourceIndex(self.tree, follow_local_calls=True)
            arg = node.args[0] if node.args else kwargs.get("name")
            evidence = self.sources.evidence(
                self.functions[-1] if self.functions else None,
                arg,
                sink="dynamic Python import",
                missing_guard="select a module from a fixed allowlist",
                evidence_kind="python_dynamic_import_taint",
            )
            if evidence is None and self.functions:
                evidence = self._module_import_source(self.functions[-1], arg)
            if evidence is None and self.project_root is not None:
                from .project_security_sources import ProjectSources

                if self.project_sources is None:
                    self.project_sources = ProjectSources(self.project_root)
                evidence = self.project_sources.import_evidence(self.file_path, node)
            if evidence:
                self._emit(
                    node,
                    "SKY-D357",
                    "HIGH",
                    "Untrusted input selects a Python module to import; use a fixed module allowlist.",
                    evidence,
                )
        if (
            name
            and name.removesuffix(".launch") in _GRADIO_FACTORIES
            and name.endswith(".launch")
        ):
            for options, unknown in self._keyword_variants(node):
                hosts = [
                    self._literal(choice)
                    for choice in self._choices(options.get("server_name"))
                ]
                public = [host for host in hosts if host in {"0.0.0.0", "::", "[::]"}]
                if (
                    public
                    and not unknown
                    and (
                        "auth" not in options or self._literal(options["auth"]) is None
                    )
                    and (
                        "auth_dependency" not in options
                        or self._literal(options["auth_dependency"]) is None
                    )
                ):
                    evidence = {
                        "evidence_kind": "python_public_launch_branch",
                        "source": "visible launch configuration",
                        "sink": "Gradio launch",
                        "path": [
                            f"server_name can be {public[0]!r}",
                            "a visible expanded option branch has no configured auth",
                            "reaches launch()",
                        ],
                        "analysis_complete": False,
                    }
                    self._emit(
                        node,
                        "SKY-D358",
                        "HIGH",
                        "A visible Gradio launch branch binds to all interfaces without configured authentication; configure auth or restrict the bind address.",
                        evidence,
                    )
                    break
        if (
            name in {"flask.url_for", "flask.helpers.url_for"}
            and self._literal(kwargs.get("_external")) is True
            and any(id(fn) in self.cached_functions for fn in self.functions)
            and not self._fixed_flask_host()
        ):
            self._emit(
                node,
                "SKY-D359",
                "MEDIUM",
                "External Flask URL is generated while building cached content; if Host comes from clients, validate it or configure SERVER_NAME before caching absolute links.",
            )
        if name in {"os.makedirs", "pathlib.Path.mkdir"}:
            path = (
                node.args[0]
                if name == "os.makedirs" and node.args
                else kwargs.get("name")
            )
            if (
                name == "pathlib.Path.mkdir"
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Call)
            ):
                path = node.func.value.args[0] if node.func.value.args else None
            elif (
                name == "pathlib.Path.mkdir"
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
            ):
                path = self.path_arguments.get(node.func.value.id)
            value = self._literal(path)
            if (
                isinstance(value, str)
                and value.startswith(("/tmp/", "/var/tmp/"))
                and self._literal(kwargs.get("exist_ok")) is True
            ):
                self._emit(
                    node,
                    "SKY-D348",
                    "HIGH",
                    "Predictable shared temporary directory accepts an existing path; use tempfile.mkdtemp or TemporaryDirectory to create a private directory.",
                )
        self.generic_visit(node)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            and len(node.args) == 1
            and not node.keywords
        ):
            self._append_sequence(node.func.value, node.args[0])
        for argument in node.args:
            self._invalidate_mapping(argument)
            self._invalidate_sequence(argument)
        for keyword in node.keywords:
            if keyword.arg is not None:
                self._invalidate_mapping(keyword.value)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.attr
            in {"update", "setdefault", "pop", "popitem", "clear", "__setitem__"}
        ):
            self._invalidate_mapping(node.func.value)
            self.bindings[node.func.value.id] = None

    def _module_import_source(self, function, expression):
        if not isinstance(expression, ast.Name):
            return None
        if any(
            isinstance(node, ast.Name)
            and node.id == expression.id
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(function)
        ):
            return None
        definitions = [
            node
            for node in self.tree.body
            if isinstance(node, _FUNCTIONS) and node.name == function.name
        ]
        if definitions != [function]:
            return None
        parameters = [*function.args.posonlyargs, *function.args.args]
        position = next(
            (
                index
                for index, param in enumerate(parameters)
                if param.arg == expression.id
            ),
            None,
        )
        if position is None:
            return None
        pending = list(self.tree.body)
        module_nodes = []
        while pending:
            node = pending.pop()
            if isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
                continue
            module_nodes.append(node)
            pending.extend(ast.iter_child_nodes(node))
        for node in module_nodes:
            if (
                isinstance(node, ast.Name)
                and node.id == function.name
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return None
        for node in module_nodes:
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == function.name
            ):
                argument = (
                    node.args[position]
                    if len(node.args) > position
                    else next(
                        (kw.value for kw in node.keywords if kw.arg == expression.id),
                        None,
                    )
                )
                evidence = self.sources.evidence(
                    None,
                    argument,
                    sink="dynamic Python import",
                    missing_guard="select a module from a fixed allowlist",
                    evidence_kind="python_dynamic_import_taint",
                )
                if evidence:
                    evidence["path"].insert(
                        -1, f"passed as `{expression.id}` to `{function.name}`"
                    )
                    return evidence
        return None

    def _fixed_flask_host(self):
        if len(set(self.flask_instances.values())) != 1:
            return False
        constructors = 0
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            parts = []
            while isinstance(target, ast.Attribute):
                parts.append(target.attr)
                target = target.value
            if isinstance(target, ast.Name):
                parts.append(target.id)
                qualified = self.provider_sources.resolved_import(
                    None, ".".join(reversed(parts))
                )
                constructors += qualified == "flask.Flask"
        if constructors != 1:
            return False
        for key, value in self.container_values.items():
            if key not in self.flask_config_keys:
                continue
            if (
                self.flask_config_instances.get(key)
                not in self.flask_instances.values()
            ):
                continue
            if "value='SERVER_NAME'" in key:
                literal = self._literal(value)
                if isinstance(literal, str) and literal:
                    return True
            if (
                "value='TRUSTED_HOSTS'" in key
                and isinstance(value, (ast.List, ast.Tuple))
                and len(value.elts) == 1
            ):
                host = self._literal(value.elts[0])
                if (
                    isinstance(host, str)
                    and host
                    and not host.startswith(".")
                    and "*" not in host
                ):
                    return True
        return False


def scan(tree, file_path, findings, *, project_root=None):
    _Checker(tree, file_path, findings, project_root=project_root).visit(tree)
