"""Bounded, source-only comparison of a small Python effect language.

This is deliberately not a Python equivalence prover.  Supported functions are
interpreted over symbolic arguments, and local helpers are inlined.  Every
opaque call is allowed an arbitrary return value or BaseException.  The result
compares those model traces, including call outcomes and exception propagation.
Unsupported syntax is an incomplete result even when the source is identical.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import Mapping

from skylos.verification.explanations import explain_difference


_ASSUMPTIONS = [
    "Comparison concerns the selected synchronous function after module initialization; module import and initialization effects are excluded.",
    "Names resolve to their declared source/import bindings after successful module initialization and remain stable during invocation; import hooks, initialization-time rebinding, monkey-patching, and namespace mutation are excluded.",
    "Opaque calls are modeled as arbitrary stateful operations that may return any value or raise any BaseException; modeled differences may be infeasible for a fixed external API.",
    "The selected function's declared parameter names and parameter kinds are a preservation obligation, including positional-only names.",
    "Observable behavior is ordered opaque calls (including argument and keyword order and active exception context), returned symbolic values, and propagated exceptions.",
    "Stack frames, tracebacks, function identity, tracing/profiling, timing, memory use, reference counts, finalizers, and interpreter resource failures are outside the model.",
]


class _Unknown(Exception):
    pass


@dataclass
class _Module:
    path: str
    name: str
    tree: ast.Module
    bindings: dict[str, list[tuple]] = field(default_factory=dict)


@dataclass
class _Frame:
    module: _Module
    function: ast.FunctionDef
    local_names: set[str]
    stack: tuple[tuple[str, str], ...]


@dataclass
class _State:
    env: dict[str, tuple]
    events: tuple = ()
    control: str = "running"
    value: tuple | None = None
    active_exception: tuple | None = None


def _constant(value):
    if type(value) not in (type(None), bool, int, float, complex, str, bytes):
        raise _Unknown("Unsupported literal value")
    return ("constant", type(value).__name__, repr(value))


_NONE = _constant(None)


def _module_name(path):
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _range(node):
    if node is None:
        return None
    return {"start_line": node.lineno, "end_line": node.end_lineno}


class _Program:
    def __init__(self, sources, known_modules, max_paths, max_depth):
        self.sources = sources
        self.known_modules = known_modules
        self.max_paths = max_paths
        self.max_depth = max_depth
        self.modules = {}
        self.by_name = {}
        self.steps = 0
        self.max_steps = max_paths * max_depth * 512
        for path in sources:
            self.by_name.setdefault(_module_name(path), []).append(path)

    def _tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise _Unknown("Symbolic evaluation work budget exhausted")

    def _bounded(self, states):
        if len(states) > self.max_paths:
            raise _Unknown(
                f"Symbolic path budget exhausted (max_paths={self.max_paths})"
            )
        return states

    def module(self, path):
        if path in self.modules:
            return self.modules[path]
        if path not in self.sources:
            raise _Unknown(f"Source unavailable for repository module {path}")
        try:
            tree = ast.parse(self.sources[path], filename=path)
            # Compilation performs syntax/scope validation only. Never execute
            # or import this code object (e.g. duplicate arguments evade parse).
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                compile(tree, path, "exec", dont_inherit=True)
        except (SyntaxError, ValueError, TypeError, RecursionError) as exc:
            raise _Unknown(
                f"Invalid Python source in {path}: {type(exc).__name__}"
            ) from exc
        module = _Module(path, _module_name(path), tree)
        self.modules[path] = module

        def bind(name, value):
            module.bindings.setdefault(name, []).append(value)

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._validate_header(node)
                bind(node.name, ("function", path, node.name))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    bind(
                        alias.asname or alias.name.split(".")[0],
                        (
                            "module",
                            alias.name if alias.asname else alias.name.split(".")[0],
                        ),
                    )
            elif isinstance(node, ast.ImportFrom):
                if any(alias.name == "*" for alias in node.names):
                    raise _Unknown(
                        f"Wildcard import makes bindings ambiguous in {path}"
                    )
                imported = self._import_module(module, node)
                for alias in node.names:
                    bind(alias.asname or alias.name, ("import", imported, alias.name))
            elif (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                continue
            elif isinstance(node, ast.Pass):
                continue
            else:
                raise _Unknown(
                    f"Unsupported module-level {type(node).__name__} in {path}; stable bindings cannot be established"
                )
        return module

    def _import_module(self, module, node):
        if not node.level:
            return node.module or ""
        if not module.name:
            raise _Unknown(
                f"Relative import has no established package identity in {module.path}"
            )
        package = module.name.split(".")
        if PurePosixPath(module.path).name != "__init__.py":
            package = package[:-1]
        if node.level > len(package):
            raise _Unknown(f"Unresolved relative import in {module.path}")
        package = package[: len(package) - node.level + 1]
        if node.module:
            package.extend(node.module.split("."))
        return ".".join(package)

    def _module_path(self, name):
        if not name or name.startswith("."):
            raise _Unknown(
                f"Import has no established absolute module identity: {name!r}"
            )
        for known in self.known_modules:
            pieces = known.split(".")
            if any(
                ".".join(pieces[index:]).casefold() == name.casefold()
                or ".".join(pieces[index:]).casefold().startswith(name.casefold() + ".")
                for index in range(1, len(pieces))
            ):
                raise _Unknown(
                    f"Repository import {name} may use an undeclared source root"
                )
        paths = self.by_name.get(name, [])
        if len(paths) > 1:
            raise _Unknown(f"Ambiguous repository module {name}")
        if paths:
            return paths[0]
        if name in self.known_modules:
            raise _Unknown(f"Repository module {name} is unavailable in this revision")
        if any(known.casefold() == name.casefold() for known in self.known_modules):
            raise _Unknown(f"Case-ambiguous repository import {name}")
        return None

    def _binding(self, module, name, seen=()):
        key = (module.path, name)
        if key in seen:
            raise _Unknown(f"Cyclic import binding for {name} in {module.path}")
        values = module.bindings.get(name, [])
        if len(values) != 1:
            raise _Unknown(f"Unresolved or ambiguous global {name} in {module.path}")
        value = values[0]
        if value[0] == "import":
            return self._imported(value[1], value[2], seen + (key,))
        return value

    def _imported(self, name, member, seen=()):
        pieces = name.split(".")
        for index in range(1, len(pieces)):
            parent = self._module_path(".".join(pieces[:index]))
            if parent:
                self.module(parent)
        path = self._module_path(name)
        if path:
            module = self.module(path)
            submodule = f"{name}.{member}"
            if member in module.bindings:
                if self._module_path(submodule):
                    raise _Unknown(
                        f"Package binding conflicts with a source child module: {submodule}"
                    )
                return self._binding(module, member, seen)
            if self._module_path(submodule):
                return ("module", submodule)
            raise _Unknown(f"Unresolved repository import {name}.{member}")
        # A namespace package can have source children without an __init__.py.
        submodule = f"{name}.{member}"
        if self._module_path(submodule):
            return ("module", submodule)
        if any(known.startswith(name + ".") for known in self.known_modules):
            raise _Unknown(f"Unresolved member of repository namespace {name}.{member}")
        return ("external", f"{name}.{member}")

    @staticmethod
    def _validate_header(node):
        name = node.name
        if node.decorator_list or node.returns or getattr(node, "type_params", []):
            raise _Unknown(
                f"Decorators, annotations, and type parameters are unsupported: {name}"
            )
        args = node.args
        if (
            args.defaults
            or any(value is not None for value in args.kw_defaults)
            or args.vararg
            or args.kwarg
        ):
            raise _Unknown(
                f"Default, variadic, and keyword-variadic parameters are unsupported: {name}"
            )
        if any(
            arg.annotation for arg in args.posonlyargs + args.args + args.kwonlyargs
        ):
            raise _Unknown(f"Parameter annotations are unsupported: {name}")

    def function(self, path, name):
        module = self.module(path)
        binding = self._binding(module, name)
        if binding != ("function", path, name):
            raise _Unknown(
                f"Selected symbol {name} is not a local module-level function"
            )
        nodes = [
            node
            for node in module.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]
        if len(nodes) != 1 or not isinstance(nodes[0], ast.FunctionDef):
            raise _Unknown(
                f"Only synchronous module-level functions are supported: {name}"
            )
        node = nodes[0]
        allowed_statements = (
            ast.Return,
            ast.Assign,
            ast.Expr,
            ast.Pass,
            ast.Try,
            ast.Raise,
        )
        allowed_expressions = (ast.Name, ast.Constant, ast.Call, ast.Attribute)
        for statement in node.body:
            for child in ast.walk(statement):
                if isinstance(child, ast.stmt) and not isinstance(
                    child, allowed_statements
                ):
                    raise _Unknown(
                        f"Unsupported {type(child).__name__} in {path}:{child.lineno}"
                    )
                if isinstance(child, ast.expr) and not isinstance(
                    child, allowed_expressions
                ):
                    raise _Unknown(
                        f"Unsupported {type(child).__name__} in {path}:{child.lineno}"
                    )
                if isinstance(child, ast.Assign) and (
                    len(child.targets) != 1
                    or not isinstance(child.targets[0], ast.Name)
                ):
                    raise _Unknown(
                        f"Only single local-name assignment is supported in {name}"
                    )
                if isinstance(child, ast.Call) and any(
                    keyword.arg is None for keyword in child.keywords
                ):
                    raise _Unknown(
                        f"Expanded keyword arguments are unsupported in {name}"
                    )
                if isinstance(child, ast.Raise) and child.cause is not None:
                    raise _Unknown(
                        f"Explicit exception causes are unsupported in {name}"
                    )
        return module, node

    @staticmethod
    def signature(node):
        return tuple(
            (kind, arg.arg)
            for kind, args in (
                ("positional_only", node.args.posonlyargs),
                ("positional_or_keyword", node.args.args),
                ("keyword_only", node.args.kwonlyargs),
            )
            for arg in args
        )

    def _frame(self, module, function, stack):
        key = (module.path, function.name)
        if key in stack:
            raise _Unknown(f"Recursive helper call: {module.path}:{function.name}")
        if len(stack) >= self.max_depth:
            raise _Unknown(
                f"Helper depth budget exhausted (max_depth={self.max_depth})"
            )
        local = {name for _, name in self.signature(function)}
        for statement in function.body:
            for node in ast.walk(statement):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    local.add(node.id)
                elif isinstance(node, ast.ExceptHandler) and node.name:
                    local.add(node.name)
        return _Frame(module, function, local, stack + (key,))

    def analyze(self, path, name):
        module, function = self.function(path, name)
        frame = self._frame(module, function, ())
        env = {name: ("parameter", name) for _, name in self.signature(function)}
        states = self._block(function.body, [_State(env)], frame)
        traces = set()
        for state in states:
            value = _NONE if state.control == "running" else state.value
            if value and value[0] in ("function", "module", "external"):
                raise _Unknown(
                    "A local or imported callable/module escapes as the selected function's return value"
                )
            traces.add(
                (state.events, "raise" if state.control == "raise" else "return", value)
            )
        return traces

    def _name(self, name, state, frame):
        if name in state.env:
            return state.env[name]
        if name in frame.local_names:
            raise _Unknown(
                f"Local {name} may be read before assignment in {frame.function.name}"
            )
        return self._binding(frame.module, name)

    def _eval(self, node, state, frame):
        self._tick()
        if state.control != "running":
            return [(state, None)]
        if isinstance(node, ast.Constant):
            return [(state, _constant(node.value))]
        if isinstance(node, ast.Name):
            return [(state, self._name(node.id, state, frame))]
        if isinstance(node, ast.Attribute):
            results = []
            for branch, owner in self._eval(node.value, state, frame):
                if branch.control != "running":
                    results.append((branch, None))
                elif owner[0] != "module":
                    raise _Unknown(
                        f"Dynamic attribute access is unsupported at {frame.module.path}:{node.lineno}"
                    )
                else:
                    results.append((branch, self._imported(owner[1], node.attr)))
            return results
        if isinstance(node, ast.Call):
            outcomes = []
            for initial, target in self._eval(node.func, state, frame):
                branches = [(initial, (), ())]
                for argument in node.args:
                    expanded = []
                    for branch, args, keywords in branches:
                        for evaluated, value in self._eval(argument, branch, frame):
                            expanded.append((evaluated, args + (value,), keywords))
                    branches = self._bounded(expanded)
                for keyword in node.keywords:
                    expanded = []
                    for branch, args, keywords in branches:
                        for evaluated, value in self._eval(
                            keyword.value, branch, frame
                        ):
                            expanded.append(
                                (evaluated, args, keywords + ((keyword.arg, value),))
                            )
                    branches = self._bounded(expanded)
                for branch, args, keywords in branches:
                    if branch.control != "running":
                        outcomes.append((branch, None))
                    elif target[0] == "function":
                        outcomes.extend(
                            self._invoke(target, args, keywords, branch, frame)
                        )
                    elif target[0] in ("parameter", "external", "result"):
                        if any(
                            value[0] in ("function", "module", "external")
                            for value in args + tuple(value for _, value in keywords)
                        ):
                            raise _Unknown(
                                "A source-defined or imported callable/module escapes into an opaque call"
                            )
                        index = len(branch.events)
                        event = ("call", target, args, keywords)
                        outcomes.append(
                            (
                                replace(
                                    branch,
                                    events=branch.events
                                    + (event + ("return", branch.active_exception),),
                                ),
                                ("result", index),
                            )
                        )
                        outcomes.append(
                            (
                                replace(
                                    branch,
                                    events=branch.events
                                    + (event + ("raise", branch.active_exception),),
                                    control="raise",
                                    value=("exception", index, branch.active_exception),
                                ),
                                None,
                            )
                        )
                    else:
                        raise _Unknown(
                            f"Unsupported call target at {frame.module.path}:{node.lineno}"
                        )
                self._bounded(outcomes)
            return outcomes
        raise _Unknown(f"Unsupported expression {type(node).__name__}")

    def _invoke(self, target, args, keywords, state, caller):
        module, function = self.function(target[1], target[2])
        frame = self._frame(module, function, caller.stack)
        positional = function.args.posonlyargs + function.args.args
        if len(args) > len(positional):
            raise _Unknown(f"Invalid argument binding for helper {function.name}")
        env = {argument.arg: value for argument, value in zip(positional, args)}
        keyword_names = {
            argument.arg for argument in function.args.args + function.args.kwonlyargs
        }
        for name, value in keywords:
            if name not in keyword_names or name in env:
                raise _Unknown(f"Invalid keyword binding for helper {function.name}")
            env[name] = value
        if set(env) != {name for _, name in self.signature(function)}:
            raise _Unknown(f"Missing argument for helper {function.name}")
        entered = replace(state, env=env)
        outcomes = []
        for result in self._block(function.body, [entered], frame):
            if result.control == "raise":
                outcomes.append(
                    (
                        replace(
                            result,
                            env=state.env,
                            active_exception=state.active_exception,
                        ),
                        None,
                    )
                )
            else:
                value = result.value if result.control == "return" else _NONE
                outcomes.append(
                    (
                        replace(
                            result,
                            env=state.env,
                            control="running",
                            value=None,
                            active_exception=state.active_exception,
                        ),
                        value,
                    )
                )
        return self._bounded(outcomes)

    def _block(self, statements, states, frame):
        for node in statements:
            following = []
            for state in states:
                self._tick()
                if state.control != "running":
                    following.append(state)
                else:
                    following.extend(self._statement(node, state, frame))
                self._bounded(following)
            states = following
        return states

    def _statement(self, node, state, frame):
        if isinstance(node, ast.Pass):
            return [state]
        if isinstance(node, ast.Expr):
            return [branch for branch, _ in self._eval(node.value, state, frame)]
        if isinstance(node, ast.Assign):
            results = []
            for branch, value in self._eval(node.value, state, frame):
                if branch.control == "running":
                    branch = replace(
                        branch, env={**branch.env, node.targets[0].id: value}
                    )
                results.append(branch)
            return results
        if isinstance(node, ast.Return):
            if node.value is None:
                return [replace(state, control="return", value=_NONE)]
            return [
                replace(branch, control="return", value=value)
                if branch.control == "running"
                else branch
                for branch, value in self._eval(node.value, state, frame)
            ]
        if isinstance(node, ast.Raise):
            if node.exc is None:
                if state.active_exception is None:
                    raise _Unknown("Bare raise without a modeled active exception")
                return [replace(state, control="raise", value=state.active_exception)]
            results = []
            for branch, value in self._eval(node.exc, state, frame):
                if branch.control != "running":
                    results.append(branch)
                elif value[0] == "exception" and value == branch.active_exception:
                    results.append(replace(branch, control="raise", value=value))
                else:
                    raise _Unknown(
                        "Only re-raising the current modeled exception is supported"
                    )
            return results
        if isinstance(node, ast.Try):
            return self._try(node, state, frame)
        raise _Unknown(f"Unsupported statement {type(node).__name__}")

    def _try(self, node, state, frame):
        if len(node.handlers) > 1:
            raise _Unknown("Multiple or typed exception handlers are unsupported")
        handler = node.handlers[0] if node.handlers else None
        if handler is not None and handler.type is not None:
            if (
                not isinstance(handler.type, ast.Name)
                or handler.type.id != "BaseException"
            ):
                raise _Unknown(
                    "Typed exception matching is unsupported; only bare except or unshadowed BaseException is modeled"
                )
            if (
                "BaseException" in frame.local_names
                or "BaseException" in frame.module.bindings
            ):
                raise _Unknown(
                    "BaseException is shadowed; catch-all behavior cannot be established"
                )
        outcomes = []
        for body in self._block(node.body, [state], frame):
            if body.control == "raise" and handler is not None:
                env = dict(body.env)
                if handler.name:
                    env[handler.name] = body.value
                entered = replace(
                    body,
                    env=env,
                    control="running",
                    active_exception=body.value,
                    value=None,
                )
                handled = self._block(handler.body, [entered], frame)
                for result in handled:
                    env = dict(result.env)
                    if handler.name:
                        env.pop(handler.name, None)
                    outcomes.append(
                        replace(
                            result, env=env, active_exception=state.active_exception
                        )
                    )
            elif body.control == "running":
                outcomes.extend(self._block(node.orelse, [body], frame))
            else:
                outcomes.append(body)
            self._bounded(outcomes)
        if not node.finalbody:
            return outcomes
        finalized = []
        for pending in outcomes:
            entered = replace(
                pending,
                control="running",
                value=None,
                active_exception=pending.value
                if pending.control == "raise"
                else pending.active_exception,
            )
            for result in self._block(node.finalbody, [entered], frame):
                if result.control == "running":
                    result = replace(
                        result, control=pending.control, value=pending.value
                    )
                finalized.append(
                    replace(result, active_exception=pending.active_exception)
                )
            self._bounded(finalized)
        return finalized


def _public_trace(trace):
    events, outcome, value = trace
    return {
        "calls": [
            {
                "target": event[1],
                "args": event[2],
                "kwargs": event[3],
                "outcome": event[4],
                "active_exception": event[5],
            }
            for event in events
        ],
        "outcome": outcome,
        "value": value,
    }


def compare_python_behavior(
    before_sources: Mapping[str, str],
    after_sources: Mapping[str, str],
    *,
    file: str,
    symbol: str,
    max_paths: int = 64,
    max_depth: int = 8,
) -> dict:
    """Compare modeled invocation behavior; no target source is executed.

    ``equivalent`` means equal complete traces in this restricted model.
    ``different`` means a model mismatch, not an executed regression witness.
    ``unknown`` means an unsupported construct, unresolved dependency, or bound
    prevented comparison. Source keys are repository-relative POSIX .py paths.
    """
    result = {
        "status": "unknown",
        "file": file,
        "symbol": symbol,
        "before_range": None,
        "after_range": None,
        "differences": [],
        "reasons": [],
        "assumptions": list(_ASSUMPTIONS),
        "model_version": 1,
    }
    try:
        if (
            type(max_paths) is not int
            or max_paths < 1
            or type(max_depth) is not int
            or max_depth < 1
        ):
            raise _Unknown("max_paths and max_depth must be positive integers")
        if (
            not isinstance(file, str)
            or not file.endswith(".py")
            or PurePosixPath(file).is_absolute()
            or ".." in PurePosixPath(file).parts
        ):
            raise _Unknown("file must be a repository-relative POSIX Python path")
        if not isinstance(symbol, str) or not symbol.isidentifier():
            raise _Unknown("symbol must name a module-level Python function")
        for sources in (before_sources, after_sources):
            if not isinstance(sources, Mapping) or any(
                not isinstance(path, str)
                or not path.endswith(".py")
                or not isinstance(source, str)
                for path, source in sources.items()
            ):
                raise _Unknown(
                    "Sources must map repository-relative Python paths to source text"
                )
        known = {
            _module_name(path) for path in set(before_sources) | set(after_sources)
        }
        programs = [
            _Program(sources, known, max_paths, max_depth)
            for sources in (before_sources, after_sources)
        ]
        functions = []
        errors = []
        for side, program in zip(("before", "after"), programs):
            try:
                _, function = program.function(file, symbol)
                result[f"{side}_range"] = _range(function)
                functions.append(function)
            except _Unknown as exc:
                errors.append(f"{side}: {exc}")
        if errors:
            result["reasons"] = errors
            return result
        signatures = [
            program.signature(function)
            for program, function in zip(programs, functions)
        ]
        if signatures[0] != signatures[1]:
            result["status"] = "different"
            result["differences"] = [
                {
                    "kind": "signature",
                    "message": "The selected function's parameter names or parameter kinds changed",
                    "before": signatures[0],
                    "after": signatures[1],
                    "evidence": "modeled_counterexample",
                    "runtime_witness": False,
                }
            ]
            for difference in result["differences"]:
                difference["explanation"] = explain_difference(difference)
            return result
        traces = []
        for side, program in zip(("before", "after"), programs):
            try:
                traces.append(program.analyze(file, symbol))
            except _Unknown as exc:
                errors.append(f"{side}: {exc}")
        if errors:
            result["reasons"] = errors
            return result
        if traces[0] == traces[1]:
            result["status"] = "equivalent"
            return result
        result["status"] = "different"
        removed = sorted(traces[0] - traces[1], key=repr)
        added = sorted(traces[1] - traces[0], key=repr)
        result["differences"] = [
            {
                "kind": "behavior_trace",
                "message": "Ordered calls, forwarded values, return behavior, or exception propagation differ in the bounded model",
                "before": _public_trace(removed[0]) if removed else None,
                "after": _public_trace(added[0]) if added else None,
                "before_only_paths": len(removed),
                "after_only_paths": len(added),
                "evidence": "modeled_counterexample",
                "runtime_witness": False,
            }
        ]
        for difference in result["differences"]:
            difference["explanation"] = explain_difference(difference)
    except _Unknown as exc:
        result["reasons"] = [str(exc)]
    except (RecursionError, MemoryError) as exc:
        result["reasons"] = [f"Static analysis resource limit: {type(exc).__name__}"]
    return result
