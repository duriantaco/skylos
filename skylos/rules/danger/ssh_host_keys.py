"""Detect Paramiko clients configured to accept unknown SSH host keys."""

from __future__ import annotations

import ast
import builtins
from functools import lru_cache
from pathlib import Path

from skylos.rules.quality._test_code import is_python_test_file

from .callable_bindings import _CallableFlow, _CallableIndex
from .danger_fs.path_provenance import _Project, _ResolutionLimit, _Unit
from .import_proof import provider_is_unshadowed
from .module_namespace import attribute_write_names
from .project_source import project_source_snapshot

_METHOD = "set_missing_host_key_policy"
_CLIENT = "paramiko.SSHClient"
_CLIENT_INSTANCE = "@paramiko.SSHClient"
_SETTER = f"{_CLIENT_INSTANCE}.{_METHOD}"
_UNSAFE_POLICIES = frozenset({"paramiko.AutoAddPolicy", "paramiko.WarningPolicy"})
_MODULES = frozenset({"paramiko", "paramiko.client"})
_CLASS_NAMES = frozenset({_CLIENT, *_UNSAFE_POLICIES})
_NATIVE_NAMES = _MODULES | _CLASS_NAMES
_UNKNOWN = frozenset({"?"})
_UNBOUND = frozenset({"@unbound"})
_LITERAL_TRUTH = {
    "@literal:false": False,
    "@literal:true": True,
    "@text:empty": False,
    "@text:blank": True,
    "@text:nonblank": True,
}
_STRIPPED_TRUTH = {
    "@text:empty": False,
    "@text:blank": False,
    "@text:nonblank": True,
}
_PACKAGE_IMPORTS = frozenset(
    {"paramiko.client", "paramiko.pkey", "paramiko.ssh_exception", "paramiko.transport"}
)
_MODULE_SUFFIXES = frozenset({".py", ".pyi", ".pyc", ".pyo", ".so", ".pyd"})
_DEFAULT_ATTRIBUTES = frozenset({"__defaults__", "__kwdefaults__"})
_NATIVE_WRITES = frozenset(
    {
        _METHOD,
        "SSHClient",
        "AutoAddPolicy",
        "WarningPolicy",
        "missing_host_key",
        "__class__",
        "__enter__",
    }
)


def _literal_labels(value):
    if isinstance(value, str):
        if not value:
            return frozenset({"@text:empty"})
        return frozenset({"@text:nonblank" if value.strip() else "@text:blank"})
    return frozenset({"@literal:true" if value else "@literal:false"})


def _known_truth(labels, truth_by_label):
    if not labels or not labels <= truth_by_label.keys():
        return None
    outcomes = {truth_by_label[label] for label in labels}
    return outcomes.pop() if len(outcomes) == 1 else None


def _policy_argument(call):
    if not isinstance(call.func, ast.Attribute) or call.func.attr != _METHOD:
        return None
    if len(call.args) == 1 and not call.keywords:
        argument = call.args[0]
        return None if isinstance(argument, ast.Starred) else argument
    if not call.args and len(call.keywords) == 1 and call.keywords[0].arg == "policy":
        return call.keywords[0].value
    return None


def _optional_package_names(module):
    return {
        name
        for block in module.body
        if isinstance(block, ast.Try)
        and any(
            isinstance(handler.type, ast.Name)
            and handler.type.id in {"ImportError", "ModuleNotFoundError"}
            for handler in block.handlers
        )
        for statement in block.body
        if isinstance(statement, ast.Import)
        for imported in statement.names
        if imported.name in _MODULES | _PACKAGE_IMPORTS
        if (name := imported.asname or imported.name.split(".", 1)[0])
        not in vars(builtins)
    }


def _same_named_source_package_import(tree, filename, project_root):
    """A plain backend module cannot supply an absolute package submodule."""
    if project_root is None or any(
        isinstance(node, ast.Name)
        and node.id == "__path__"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(tree)
    ):
        return None
    package_import = next(
        (
            statement
            for statement in tree.body
            if isinstance(statement, ast.Import)
            and any(alias.name in _PACKAGE_IMPORTS for alias in statement.names)
            or isinstance(statement, ast.ImportFrom)
            and not statement.level
            and statement.module in _PACKAGE_IMPORTS
        ),
        None,
    )
    if package_import is None:
        return None
    try:
        source = Path(filename).resolve()
        root = Path(project_root).resolve()
        if (
            source.name != "paramiko.py"
            or not source.is_relative_to(root)
            or source.parent == root
            or not source.is_file()
        ):
            return None
        directory = source.parent
        for _ in range(64):
            if (directory / "paramiko").exists() or any(
                candidate != source and candidate.suffix in _MODULE_SUFFIXES
                for candidate in directory.glob("paramiko.*")
            ):
                return None
            if directory == root:
                return package_import
            directory = directory.parent
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return None


class _SSHFlow(_CallableFlow):
    def __init__(self, scope, owner, outer, max_steps):
        self.client_inputs = frozenset()
        self.literal_inputs = {}
        self.track_client_escapes = owner.caller is not None
        super().__init__(scope, owner, outer, max_steps)

    def _block(self, statements):
        if statements is self.scope.body:
            for name in self.client_inputs:
                self._bind(name, {_CLIENT_INSTANCE})
            for name, labels in self.literal_inputs.items():
                self._bind(name, labels)
        return super()._block(statements)

    def _test_truth(self, node):
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.Name):
            return _known_truth(self.value(node), _LITERAL_TRUTH)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self._test_truth(node.operand)
            return None if value is None else not value
        if isinstance(node, ast.BoolOp):
            values = [self._test_truth(part) for part in node.values]
            decisive = isinstance(node.op, ast.Or)
            if decisive in values:
                return decisive
            return None if None in values else not decisive
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "strip"
            and isinstance(node.func.value, ast.Name)
            and not node.args
            and not node.keywords
        ):
            return _known_truth(self.value(node.func.value), _STRIPPED_TRUTH)
        return None

    def _if(self, node):
        # A later operand may read a value assigned by an earlier operand.
        # Let the general flow visit those effects before considering branches.
        if any(isinstance(part, ast.NamedExpr) for part in ast.walk(node.test)):
            return super()._if(node)
        truth = self._test_truth(node.test)
        if truth is None:
            return super()._if(node)
        self._effects(node.test)
        return self._block(node.body if truth else node.orelse)

    def _absent(self, name):
        if self.scope is self.owner.module and name in self.owner.optional_packages:
            return _UNBOUND
        return super()._absent(name)

    def value(self, node):
        if isinstance(
            node,
            (ast.Subscript, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            return _UNKNOWN
        labels = super().value(node)
        if (
            isinstance(node, ast.Name)
            and (
                node.id not in self._locals or node.id in self.owner.uncertain_literals
            )
            and labels & _LITERAL_TRUTH.keys()
        ):
            return labels.difference(_LITERAL_TRUTH) | _UNKNOWN
        return labels

    def _expression(self, node, value):
        if isinstance(node, ast.Constant):
            return _literal_labels(node.value)
        if isinstance(node, ast.Attribute):
            labels = set()
            # An absent optional import raises on member access. Keep other
            # alternatives, including an explicitly assigned stand-in.
            for receiver in value(node.value) - _UNBOUND:
                if receiver == _CLIENT_INSTANCE and node.attr == _METHOD:
                    labels.add(_SETTER)
                elif receiver in _MODULES:
                    # A write to a `client` attribute can affect package-member
                    # lookups. Direct imports from `paramiko.client` resolve the
                    # submodule, and top-level exports do not use that lookup.
                    if self.owner.client_attribute_written and (
                        receiver == "paramiko.client" or node.attr == "client"
                    ):
                        labels.add("?")
                        continue
                    name = f"{receiver}.{node.attr}"
                    if name.startswith("paramiko.client."):
                        name = "paramiko." + node.attr
                    labels.add(name if name in _NATIVE_NAMES else "?")
                else:
                    labels.add("?")
            return labels
        if isinstance(node, ast.Call) and not node.args and not node.keywords:
            labels = set()
            for constructor in value(node.func):
                if constructor == _CLIENT:
                    labels.add(_CLIENT_INSTANCE)
                else:
                    labels.add(constructor if constructor in _UNSAFE_POLICIES else "?")
            return labels
        return _UNKNOWN

    def _statement(self, node):
        if (
            isinstance(node, ast.ImportFrom)
            and not node.level
            and node.module == "paramiko.client"
        ):
            for alias in node.names:
                if alias.name != "*":
                    name = "paramiko." + alias.name
                    self._bind(
                        alias.asname or alias.name,
                        {name} if name in _CLASS_NAMES else _UNKNOWN,
                    )
            return True
        return super()._statement(node)

    def _client_reference(self, node):
        if self.value(node) & {_CLIENT_INSTANCE, _SETTER}:
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Starred)):
            return any(
                self._client_reference(child)
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
            )
        return False

    def _forget_clients(self):
        for name, labels in self.state.names.items():
            if labels & {_CLIENT_INSTANCE, _SETTER}:
                self.state.names[name] = labels | _UNKNOWN

    def _assign(self, target, labels, value_node=None):
        if (
            self.track_client_escapes
            and (
                isinstance(target, (ast.Attribute, ast.Subscript))
                or isinstance(value_node, (ast.List, ast.Tuple, ast.Set, ast.Dict))
            )
            and self._client_reference(value_node)
        ):
            self._forget_clients()
            labels |= _UNKNOWN
        super()._assign(target, labels, value_node)

    def _call_mutation(self, node):
        if self.track_client_escapes:
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            if self.owner.caller is node:
                for argument in arguments:
                    # A later argument may have exposed or replaced a client
                    # that was evaluated before it.
                    self._record(argument)
            if any(self._client_reference(argument) for argument in arguments):
                self._forget_clients()
        # Native client methods update client state but leave its identity intact.
        if isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            if self.value(receiver) == {_CLIENT_INSTANCE}:
                return
            while isinstance(receiver, ast.Attribute):
                receiver = receiver.value
            if isinstance(receiver, ast.Name):
                providers = self.value(receiver) - _UNBOUND
                if providers and providers <= _MODULES:
                    # A call on the package's own API cannot store its
                    # arguments in the lexical import binding.
                    return
        super()._call_mutation(node)

    def _context_value(self, expression, *, is_async):
        # Paramiko's SSHClient inherits ClosingContextManager, which returns self.
        labels = self.value(expression)
        if not is_async and labels == {_CLIENT_INSTANCE}:
            return labels
        return labels | self.top


class _SSHBindings(_CallableIndex):
    flow_type = _SSHFlow

    def __init__(self, module, *, client_attribute_written=False, caller=None):
        self.client_attribute_written = client_attribute_written
        self.optional_packages = _optional_package_names(module)
        self.caller = caller
        super().__init__(module)
        self.uncertain_literals = set(self.mutable_outer)
        if not self.complete:
            return
        for node in ast.walk(module):
            # Class bodies can mutate an enclosing cell. Assignment expressions
            # can bind conditionally, including in assertions disabled by -O.
            if isinstance(node, ast.Nonlocal):
                self.uncertain_literals.update(node.names)
            elif isinstance(node, ast.NamedExpr):
                self.uncertain_literals.add(node.target.id)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                parent = self.parents[id(node)]
                # Shared flow walks unpacking targets in order, while Python
                # evaluates the whole right-hand side before any stores.
                if isinstance(parent, (ast.List, ast.Tuple, ast.Starred)):
                    self.uncertain_literals.add(node.id)

    def watched_expressions(self, node):
        policy = _policy_argument(node)
        return (node.func, policy) if policy is not None else ()


@lru_cache(maxsize=2)
def _ssh_project(root, snapshot):
    project = _Project(root, True)
    stable_defaults = True
    for path, tree in snapshot:
        unit = _Unit(
            path,
            path.relative_to(root).as_posix(),
            tree,
            is_python_test_file(path, root),
        )
        project.units.append(unit)
        project.by_path[path] = unit
        unit.module_names = project._module_names(unit)
        for name in unit.module_names:
            project.modules.setdefault(name, []).append(unit)
        if stable_defaults and any(
            isinstance(node, ast.Attribute)
            and node.attr in _DEFAULT_ATTRIBUTES
            or isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in _DEFAULT_ATTRIBUTES
            for node in ast.walk(tree)
        ):
            # A defaults tuple can be replaced. A keyword-default dictionary
            # can also be passed or mutated through an attribute read.
            stable_defaults = False
    project._index()
    return project, stable_defaults


def _plain_arguments(function, call):
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    if len(call.args) > len(positional) or any(
        isinstance(arg, ast.Starred) for arg in call.args
    ):
        return None
    keywords = {arg.arg for arg in [*args.args, *args.kwonlyargs]}
    bound = {arg.arg: value for arg, value in zip(positional, call.args)}
    for option in call.keywords:
        if option.arg not in keywords or option.arg in bound:
            return None
        bound[option.arg] = option.value
    first_default = len(positional) - len(args.defaults)
    defaults = {
        arg.arg: default
        for arg, default in zip(positional[first_default:], args.defaults)
    }
    defaults.update(
        (arg.arg, default)
        for arg, default in zip(args.kwonlyargs, args.kw_defaults)
        if default is not None
    )
    if any(
        arg.arg not in bound and arg.arg not in defaults
        for arg in (*positional, *args.kwonlyargs)
    ):
        return None
    literals = {
        name: _literal_labels(value.value)
        for name, value in (defaults | bound).items()
        if isinstance(value, ast.Constant)
    }
    return bound, literals


def _source_call_inputs(project, site, function, *, stable_defaults):
    unit, call = site.unit, site.call
    if (
        unit.is_test
        or not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Name)
        or site.skip_first
        or list(call.args) != site.args
        or list(call.keywords) != site.keywords
    ):
        return None
    binding = unit.lookup(site.scope, call.func.id)
    if binding is None:
        return None
    owner, choices = binding
    if len(choices) != 1:
        return None
    definition = choices[0]
    if (
        definition.kind not in {"import", "def"}
        or definition.node not in owner.node.body
        or definition.node.end_lineno >= call.lineno
    ):
        return None
    values = project.values(unit, site.scope, call.func)
    if not values or any(
        value.kind != "fn" or value.node is not function for value in values
    ):
        return None
    binding = _plain_arguments(function, call)
    if binding is None or not provider_is_unshadowed(
        "paramiko", unit.path, project.root
    ):
        return None
    arguments, literals = binding
    if not arguments:
        return None
    if not stable_defaults:
        literals = {
            name: value for name, value in literals.items() if name in arguments
        }
    writes, computed = attribute_write_names(unit.tree)
    if computed or writes & (_NATIVE_WRITES | {function.name}):
        return None
    index = _SSHBindings(
        unit.tree, client_attribute_written="client" in writes, caller=call
    )
    if not index.complete or index.dynamic:
        return None
    scope = index.scope(call)
    index.watched.setdefault(id(scope), []).extend(arguments.values())
    flow = index.flow(scope)
    if flow is None:
        return None
    engine, labels = flow
    for name, argument in arguments.items():
        # Facts belong to this particular call and are read at argument
        # evaluation, before another invocation can use a different value.
        if (
            isinstance(argument, ast.Name)
            and argument.id in engine._locals
            and argument.id not in index.uncertain_literals
            and (facts := labels.get(id(argument)))
            and facts <= _LITERAL_TRUTH.keys()
        ):
            literals[name] = facts
    clients = {
        name
        for name, value in arguments.items()
        if labels.get(id(value)) == {_CLIENT_INSTANCE}
    }
    if not clients:
        return None
    return clients, literals


def _prove_parameter_receiver(
    index, engine, scope, call, policy, file_path, project_root
):
    if (
        project_root is None
        or not isinstance(scope, ast.FunctionDef)
        or scope.decorator_list
    ):
        return False
    if index.parents.get(id(scope)) is not index.module:
        return False
    root = Path(project_root).resolve()
    snapshot, complete = project_source_snapshot(root)
    if not complete:
        return False
    try:
        project, stable_defaults = _ssh_project(root, tuple(snapshot.items()))
        unit = project.by_path.get(Path(file_path).resolve())
        if unit is None or unit.is_test:
            return False
        function = next(
            (
                node
                for node in unit.tree.body
                if isinstance(node, ast.FunctionDef)
                and node.name == scope.name
                and node.lineno == scope.lineno
            ),
            None,
        )
        if function is None or ast.dump(function) != ast.dump(scope):
            return False
        parameters = unit.function_scopes[id(function)].binds
        for site in project.call_sites(unit, function).resolved[:32]:
            inputs = _source_call_inputs(
                project, site, function, stable_defaults=stable_defaults
            )
            if inputs is None:
                continue
            clients, literals = inputs
            scoped = _SSHFlow(scope, index, engine._outer, 10000)
            scoped.client_inputs = clients
            scoped.track_client_escapes = True
            scoped.literal_inputs = {
                key: value
                for key, value in literals.items()
                if len(parameters.get(key, ())) == 1
                and key not in index.uncertain_literals
            }
            checked = scoped.run((call.func, policy)) or {}
            labels = checked.get(id(policy), frozenset())
            if (
                checked.get(id(call.func)) == {_SETTER}
                and labels
                and labels <= _UNSAFE_POLICIES
            ):
                return True
    except (OSError, RuntimeError, TypeError, ValueError, _ResolutionLimit):
        return False
    return False


def scan(tree, file_path, findings, *, project_root=None):
    if not isinstance(tree, ast.Module):
        return
    candidates = [
        (call, policy)
        for call in ast.walk(tree)
        if isinstance(call, ast.Call) and (policy := _policy_argument(call)) is not None
    ]
    if not candidates:
        return
    package_import = None
    if not provider_is_unshadowed("paramiko", file_path, project_root):
        package_import = _same_named_source_package_import(
            tree, file_path, project_root
        )
        if package_import is None:
            return
    written, computed = attribute_write_names(tree)
    if computed or written & _NATIVE_WRITES:
        return
    index = _SSHBindings(tree, client_attribute_written="client" in written)
    if not index.complete or index.dynamic:
        return
    for call, policy in candidates:
        if package_import is not None:
            statement = call
            while index.parents.get(id(statement)) is not tree:
                statement = index.parents[id(statement)]
            if statement.lineno <= package_import.end_lineno:
                continue
        scope = index.scope(call)
        flow = index.flow(scope)
        if flow is None or not index.complete:
            continue
        engine, labels = flow
        policies = labels.get(id(policy), frozenset())
        if not policies or not policies <= _UNSAFE_POLICIES:
            continue
        if labels.get(id(call.func)) != {_SETTER} and not _prove_parameter_receiver(
            index, engine, scope, call, policy, file_path, project_root
        ):
            continue
        names = " or ".join(sorted(name.rsplit(".", 1)[-1] for name in policies))
        findings.append(
            {
                "rule_id": "SKY-D380",
                "severity": "HIGH",
                "message": (
                    f"Paramiko {names} accepts unknown SSH host keys. Load trusted "
                    "host keys and keep the default RejectPolicy."
                ),
                "file": str(file_path),
                "line": call.lineno,
                "col": call.col_offset,
                "symbol": getattr(scope, "name", "<module>"),
            }
        )
