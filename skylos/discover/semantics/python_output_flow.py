"""Bounded, local evidence for uses of Python LLM outputs.

This pass follows values in one lexical scope. It intentionally does not claim
that an arbitrary helper, branch guard, or parser makes data safe for a
security-sensitive sink. Unsupported control flow becomes UNKNOWN evidence.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skylos.discover.semantics.vocabulary import FlowStatus, OutputFlowEvidence

_MAX_BRANCH_DEPTH = 8
_MAX_STATES = 32
_MAX_EVIDENCE_PER_SOURCE = 64
_MAX_PATH_LENGTH = 12
_TRUSTED_IMPORT_ROOTS = frozenset(
    {"json", "ast", "pydantic", "subprocess", "os", "shutil", "builtins"}
)

_DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "os.system",
    "os.popen",
    "os.execvp",
    "os.execve",
    "shutil.rmtree",
}


@dataclass(frozen=True)
class _Value:
    source: int
    stage: str
    path: tuple[str, ...]
    validation_location: str = ""
    validation_kind: str = ""

    def at(self, location: str, *, stage: str | None = None) -> _Value:
        path = self.path
        if location and (not path or path[-1] != location):
            path = (*path[-(_MAX_PATH_LENGTH - 1) :], location)
        return _Value(
            source=self.source,
            stage=stage or self.stage,
            path=path,
            validation_location=self.validation_location,
            validation_kind=self.validation_kind,
        )


@dataclass
class _State:
    bindings: dict[str, frozenset[_Value]] = field(default_factory=dict)
    callables: dict[str, str] = field(default_factory=dict)
    containers: set[str] = field(default_factory=set)
    singleton_containers: set[str] = field(default_factory=set)
    active: bool = True

    def copy(self) -> _State:
        return _State(
            dict(self.bindings),
            dict(self.callables),
            set(self.containers),
            set(self.singleton_containers),
            self.active,
        )


def attach_python_output_flow(
    tree: ast.AST,
    raw_calls: list[dict[str, Any]],
    integrations: list[Any],
    filepath: str,
    project_root: Path,
    source_file: Path,
) -> None:
    """Attach per-call facts without changing legacy discovery signals."""
    source_nodes = {
        id(call["ast_node"]): index
        for index, call in enumerate(raw_calls)
        if isinstance(call.get("ast_node"), ast.Call)
    }
    if not source_nodes:
        return

    analyzer = _OutputFlowAnalyzer(
        tree,
        source_nodes=source_nodes,
        source_locations=[call["location"] for call in raw_calls],
        filepath=filepath,
        shadowed_modules=_local_shadowed_modules(project_root, source_file),
    )
    analyzer.run()
    for index, integration in enumerate(integrations[: len(raw_calls)]):
        evidence = sorted(analyzer.evidence.get(index, []), key=_evidence_sort_key)
        if not evidence:
            location = raw_calls[index]["location"]
            evidence = [
                OutputFlowEvidence(
                    source_location=location,
                    use_location="",
                    status=FlowStatus.UNKNOWN,
                    path=(location,),
                    reason="No downstream use of this response was resolved",
                )
            ]
        integration.output_flow_evidence = evidence
        statuses = {item.status for item in evidence}
        if FlowStatus.UNVALIDATED in statuses:
            integration.output_flow_status = FlowStatus.UNVALIDATED
        elif FlowStatus.UNKNOWN in statuses:
            integration.output_flow_status = FlowStatus.UNKNOWN
        else:
            integration.output_flow_status = FlowStatus.VALIDATED


class _OutputFlowAnalyzer:
    def __init__(
        self,
        tree: ast.AST,
        *,
        source_nodes: dict[int, int],
        source_locations: list[str],
        filepath: str,
        shadowed_modules: set[str],
    ) -> None:
        self.tree = tree
        self.source_nodes = source_nodes
        self.source_locations = source_locations
        self.filepath = filepath
        self.shadowed_modules = shadowed_modules
        self.evidence: dict[int, list[OutputFlowEvidence]] = defaultdict(list)
        self._seen: set[OutputFlowEvidence] = set()
        body = getattr(tree, "body", [])
        self.mutated_import_roots = _mutated_attribute_roots(tree)
        self.module_imports = _imports_in(body)
        self.module_imports = {
            name: target
            for name, target in self.module_imports.items()
            if name not in _assigned_names(body)
            and name not in self.mutated_import_roots
            and target.split(".", 1)[0] not in self.shadowed_modules
        }
        self.model_classes = _pydantic_models(body, self.module_imports)
        self.model_classes.difference_update(self.mutated_import_roots)
        self.model_classes.difference_update(_assigned_names(body))
        self.active_models = set(self.model_classes)
        self.captured_names: set[str] = set()

    def run(self) -> None:
        self._visit_scope(self.tree)

    def _visit_scope(self, scope: ast.AST) -> None:
        body = getattr(scope, "body", [])
        if not isinstance(body, list):
            return
        direct_sources = _direct_sources(body, self.source_nodes)
        if direct_sources:
            imports = dict(self.module_imports)
            imports.update(_imports_in(body))
            imports = {
                name: target
                for name, target in imports.items()
                if target.split(".", 1)[0] not in self.shadowed_modules
            }
            shadowed = _assigned_names(body)
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                shadowed.update(arg.arg for arg in scope.args.posonlyargs)
                shadowed.update(arg.arg for arg in scope.args.args)
                shadowed.update(arg.arg for arg in scope.args.kwonlyargs)
                if scope.args.vararg:
                    shadowed.add(scope.args.vararg.arg)
                if scope.args.kwarg:
                    shadowed.add(scope.args.kwarg.arg)
                shadowed.update(
                    item.name
                    for item in body
                    if isinstance(
                        item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    )
                )
            for name in shadowed:
                imports.pop(name, None)
            for name in self.mutated_import_roots:
                imports.pop(name, None)
            previous_models = self.active_models
            previous_captures = self.captured_names
            self.active_models = self.model_classes - shadowed - set(imports)
            self.captured_names = _captured_names(body)
            self._process_block(body, [_State()], imports, depth=0)
            self.active_models = previous_models
            self.captured_names = previous_captures

        for statement in body:
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                self._visit_scope(statement)

    def _process_block(
        self,
        statements: list[ast.stmt],
        states: list[_State],
        imports: dict[str, str],
        *,
        depth: int,
    ) -> list[_State]:
        for statement in statements:
            next_states: list[_State] = []
            for state in states:
                if not state.active:
                    next_states.append(state)
                elif isinstance(statement, ast.If):
                    next_states.extend(
                        self._process_if(statement, state, imports, depth)
                    )
                else:
                    next_states.append(
                        self._process_statement(statement, state, imports)
                    )
            states = next_states
            if len(states) > _MAX_STATES:
                states = [self._collapse(states, statement)]
        return states

    def _process_if(
        self, node: ast.If, state: _State, imports: dict[str, str], depth: int
    ) -> list[_State]:
        if depth >= _MAX_BRANCH_DEPTH:
            self._mark_unknown(node, state, "Branch depth exceeded")
            return [self._collapse([state], node)]
        condition_values = self._eval(node.test, state, imports, consumed=True)
        self._record_use(condition_values, self._location(node.test), "condition")
        if isinstance(node.test, ast.Constant) and isinstance(node.test.value, bool):
            selected = node.body if node.test.value else node.orelse
            return self._process_block(selected, [state], imports, depth=depth + 1)
        yes = self._process_block(node.body, [state.copy()], imports, depth=depth + 1)
        no = self._process_block(node.orelse, [state.copy()], imports, depth=depth + 1)
        return yes + no

    def _process_statement(
        self, node: ast.stmt, state: _State, imports: dict[str, str]
    ) -> _State:
        if isinstance(node, ast.Assign):
            values = self._eval(node.value, state, imports)
            callable_target = self._callable_alias(node.value, state, imports)
            container = self._is_container_expr(node.value, state)
            singleton = self._is_singleton_expr(node.value, state)
            for target in node.targets:
                self._bind_assignment(target, node.value, values, state, imports)
                for name in _target_names(target):
                    if callable_target:
                        state.callables[name] = callable_target
                    else:
                        state.callables.pop(name, None)
                    if isinstance(target, ast.Name) and container:
                        state.containers.add(name)
                    else:
                        state.containers.discard(name)
                    if isinstance(target, ast.Name) and singleton:
                        state.singleton_containers.add(name)
                    else:
                        state.singleton_containers.discard(name)
            return state
        if isinstance(node, ast.AnnAssign):
            values = (
                self._eval(node.value, state, imports) if node.value else frozenset()
            )
            container = self._is_container_expr(node.value, state)
            singleton = self._is_singleton_expr(node.value, state)
            self._bind(node.target, values, state)
            callable_target = self._callable_alias(node.value, state, imports)
            for name in _target_names(node.target):
                if callable_target:
                    state.callables[name] = callable_target
                else:
                    state.callables.pop(name, None)
                if container:
                    state.containers.add(name)
                else:
                    state.containers.discard(name)
                if singleton:
                    state.singleton_containers.add(name)
                else:
                    state.singleton_containers.discard(name)
            return state
        if isinstance(node, ast.AugAssign):
            previous = self._eval(node.target, state, imports)
            values = self._eval(node.value, state, imports)
            self._bind(node.target, previous | values, state)
            for name in _target_names(node.target):
                state.callables.pop(name, None)
                state.containers.discard(name)
                state.singleton_containers.discard(name)
            return state
        if isinstance(node, ast.Expr):
            self._eval(node.value, state, imports, consumed=True)
            return state
        if isinstance(node, ast.Return):
            values = (
                self._eval(node.value, state, imports) if node.value else frozenset()
            )
            self._record_use(values, self._location(node), "return")
            state.active = False
            return state
        if isinstance(node, ast.Delete):
            for target in node.targets:
                for name in _target_names(target):
                    state.bindings.pop(name, None)
                    state.callables.pop(name, None)
                    state.containers.discard(name)
                    state.singleton_containers.discard(name)
            return state
        if isinstance(node, ast.Raise):
            if node.exc:
                self._record_use(
                    self._eval(node.exc, state, imports), self._location(node), "raise"
                )
            state.active = False
            return state
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Pass)):
            return state
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definition_inputs: list[ast.expr] = list(node.decorator_list)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definition_inputs.extend(node.args.defaults)
                definition_inputs.extend(
                    item for item in node.args.kw_defaults if item is not None
                )
            else:
                definition_inputs.extend(node.bases)
                definition_inputs.extend(item.value for item in node.keywords)
            for expression in definition_inputs:
                values = self._eval(expression, state, imports, consumed=True)
                self._record_use(values, self._location(expression), "definition")
            self._mark_nested_capture(node, state)
            return state
        self._mark_unknown(node, state, "Unsupported control flow or statement")
        for name in _assigned_names([node]):
            current = state.bindings.get(name, frozenset())
            state.bindings[name] = frozenset(
                value.at(self._location(node), stage="unknown") for value in current
            )
            state.callables[name] = "__unknown_callable__"
            state.containers.add(name)
            state.singleton_containers.discard(name)
        return state

    def _bind_assignment(
        self,
        target: ast.expr,
        expression: ast.expr,
        values: frozenset[_Value],
        state: _State,
        imports: dict[str, str],
    ) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(expression, (ast.Tuple, ast.List)) and len(
                target.elts
            ) == len(expression.elts):
                for child_target, child_expression in zip(target.elts, expression.elts):
                    child_values = self._eval(child_expression, state, imports)
                    self._bind_assignment(
                        child_target, child_expression, child_values, state, imports
                    )
                return
            values = frozenset(
                value.at(self._location(target), stage="unknown") for value in values
            )
        self._bind(target, values, state)

    def _is_container_expr(self, node: ast.AST | None, state: _State) -> bool:
        return isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Dict)) or (
            isinstance(node, ast.Name) and node.id in state.containers
        )

    def _is_singleton_expr(self, node: ast.AST | None, state: _State) -> bool:
        if isinstance(node, (ast.Tuple, ast.List)):
            return len(node.elts) == 1 and not self._is_container_expr(
                node.elts[0], state
            )
        return isinstance(node, ast.Name) and node.id in state.singleton_containers

    def _bind(self, target: ast.expr, values: frozenset[_Value], state: _State) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, values, state)
        elif isinstance(target, ast.Name):
            state.bindings[target.id] = frozenset(
                value.at(self._location(target)) for value in values
            )
            if values and target.id in self.captured_names:
                for value in sorted(values, key=_value_sort_key):
                    location = self._location(target)
                    self._add_evidence(
                        value.source,
                        OutputFlowEvidence(
                            source_location=self.source_locations[value.source],
                            use_location=location,
                            status=FlowStatus.UNKNOWN,
                            validation_location=value.validation_location,
                            validation_kind=value.validation_kind,
                            path=value.at(location).path,
                            reason="A nested scope may read this captured value",
                        ),
                    )
        else:
            self._record_use(values, self._location(target), "store")

    def _eval(
        self,
        node: ast.AST | None,
        state: _State,
        imports: dict[str, str],
        *,
        consumed: bool = False,
    ) -> frozenset[_Value]:
        if node is None:
            return frozenset()
        if isinstance(node, ast.Name):
            return state.bindings.get(node.id, frozenset())
        if isinstance(node, ast.Subscript):
            index_values = self._eval(node.slice, state, imports, consumed=True)
            self._record_use(index_values, self._location(node.slice), "index")
            values = self._eval(node.value, state, imports)
            unambiguous_singleton = self._is_singleton_expr(
                node.value, state
            ) and _singleton_index(node.slice)
            if len(values) > 1 or (
                self._is_container_expr(node.value, state) and not unambiguous_singleton
            ):
                # The flattened container summary cannot identify which member
                # an index selects. Do not turn every member into a proved use.
                return frozenset(
                    value.at(self._location(node), stage="unknown") for value in values
                )
            return values
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            values = self._eval(node.value, state, imports)
            self._record_use(values, self._location(node), "yield")
            return values
        if isinstance(node, (ast.Attribute, ast.Await, ast.Starred)):
            return self._eval(node.value, state, imports)
        if isinstance(node, ast.Call):
            operands = self._call_operands(node, state, imports)
            source = self.source_nodes.get(id(node))
            if source is not None:
                if operands:
                    self._record_use(operands, self._location(node), "LLM request")
                return frozenset(
                    {_Value(source, "raw", (self.source_locations[source],))}
                )
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and type(node.args[0].value) is str
                and not node.keywords
            ):
                receiver_values = self._eval(node.func.value, state, imports)
                if receiver_values and all(
                    value.stage == "parsed" for value in receiver_values
                ):
                    return frozenset(
                        value.at(self._location(node)) for value in receiver_values
                    )
            kind = self._validator_kind(node, state, imports)
            if kind and node.args:
                input_values = self._eval(node.args[0], state, imports)
                if input_values:
                    location = self._location(node)
                    return frozenset(
                        _Value(
                            source=value.source,
                            stage=kind if value.stage != "unknown" else "unknown",
                            path=value.at(location).path,
                            validation_location=location,
                            validation_kind=kind,
                        )
                        for value in input_values
                    )
            sink = self._dangerous_call(node, state, imports)
            if operands:
                self._record_use(
                    operands,
                    self._location(node),
                    sink or ("call" if consumed else "unresolved call"),
                )
            return frozenset(
                value.at(self._location(node), stage="unknown") for value in operands
            )
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return _union(self._eval(item, state, imports) for item in node.elts)
        if isinstance(node, ast.Dict):
            return _union(
                self._eval(item, state, imports)
                for item in (*node.keys, *node.values)
                if item is not None
            )
        if isinstance(node, ast.IfExp):
            test_values = self._eval(node.test, state, imports, consumed=True)
            self._record_use(test_values, self._location(node.test), "condition")
            return self._eval(node.body, state, imports) | self._eval(
                node.orelse, state, imports
            )
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            parts = []
            for generator in node.generators:
                iterator = self._eval(generator.iter, state, imports, consumed=True)
                self._record_use(
                    iterator, self._location(generator.iter), "comprehension"
                )
                parts.append(iterator)
                for condition in generator.ifs:
                    checked = self._eval(condition, state, imports, consumed=True)
                    self._record_use(checked, self._location(condition), "condition")
                    parts.append(checked)
            if isinstance(node, ast.DictComp):
                parts.extend(
                    (
                        self._eval(node.key, state, imports),
                        self._eval(node.value, state, imports),
                    )
                )
            else:
                parts.append(self._eval(node.elt, state, imports))
            values = _union(parts)
            self._record_use(values, self._location(node), "unresolved call")
            return frozenset(
                value.at(self._location(node), stage="unknown") for value in values
            )
        if isinstance(node, ast.NamedExpr):
            values = self._eval(node.value, state, imports)
            self._bind(node.target, values, state)
            return values
        if isinstance(node, ast.Constant):
            return frozenset()
        children = (
            child for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)
        )
        values = _union(self._eval(child, state, imports) for child in children)
        if isinstance(node, ast.Lambda):
            return frozenset(
                value.at(self._location(node), stage="unknown") for value in values
            )
        return values

    def _call_operands(
        self, node: ast.Call, state: _State, imports: dict[str, str]
    ) -> frozenset[_Value]:
        operands = []
        if isinstance(node.func, ast.Attribute):
            operands.append(self._eval(node.func.value, state, imports))
        operands.extend(self._eval(arg, state, imports) for arg in node.args)
        operands.extend(self._eval(kw.value, state, imports) for kw in node.keywords)
        return _union(operands)

    def _callable_alias(
        self, node: ast.AST | None, state: _State, imports: dict[str, str]
    ) -> str:
        if node is None:
            return ""
        if isinstance(node, ast.Name) and node.id in state.callables:
            return state.callables[node.id]
        canonical = _canonical_name(node, imports)
        if canonical in _DANGEROUS_CALLS or canonical in {
            "json.loads",
            "ast.literal_eval",
        }:
            return canonical
        if any(
            (
                (state.callables.get(child.id) or _canonical_name(child, imports))
                if isinstance(child, ast.Name)
                else _canonical_name(child, imports)
            )
            in _DANGEROUS_CALLS
            | {"json.loads", "ast.literal_eval", "__unknown_callable__"}
            for child in ast.walk(node)
            if isinstance(child, (ast.Name, ast.Attribute))
        ):
            return "__unknown_callable__"
        return ""

    def _resolved_call(
        self, node: ast.AST, state: _State, imports: dict[str, str]
    ) -> str:
        if isinstance(node, ast.Name) and node.id in state.callables:
            return state.callables[node.id]
        return _canonical_name(node, imports)

    def _validator_kind(
        self, node: ast.Call, state: _State, imports: dict[str, str]
    ) -> str:
        # Custom decoder, parser and context hooks can alter the validation
        # guarantee. Only the ordinary one-argument contract is modeled.
        if len(node.args) != 1 or node.keywords:
            return ""
        canonical = self._resolved_call(node.func, state, imports)
        if canonical in {"json.loads", "ast.literal_eval"}:
            return "parsed"
        if canonical in {"pydantic.parse_obj", "pydantic.parse_raw"}:
            return "schema_checked"
        if isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            method = node.func.attr
            if isinstance(receiver, ast.Name) and receiver.id in self.active_models:
                if method in {
                    "model_validate",
                    "model_validate_json",
                    "parse_obj",
                    "parse_raw",
                }:
                    return "schema_checked"
            if (
                isinstance(receiver, ast.Call)
                and _canonical_name(receiver.func, imports) == "pydantic.TypeAdapter"
            ):
                if (
                    method in {"validate_python", "validate_json"}
                    and len(receiver.args) == 1
                    and not receiver.keywords
                    and isinstance(receiver.args[0], ast.Name)
                    and receiver.args[0].id in self.active_models
                ):
                    return "schema_checked"
        return ""

    def _dangerous_call(
        self, node: ast.Call, state: _State, imports: dict[str, str]
    ) -> str:
        canonical = self._resolved_call(node.func, state, imports)
        if canonical == "__unknown_callable__":
            return canonical
        return canonical if canonical in _DANGEROUS_CALLS else ""

    def _record_use(
        self, values: frozenset[_Value], location: str, use_kind: str
    ) -> None:
        for value in sorted(values, key=_value_sort_key):
            if use_kind == "__unknown_callable__":
                status = FlowStatus.UNKNOWN
                reason = "The called function's identity could not be resolved"
            elif use_kind in _DANGEROUS_CALLS:
                status = (
                    FlowStatus.UNKNOWN
                    if value.stage == "unknown"
                    else FlowStatus.UNVALIDATED
                )
                reason = (
                    f"Parsing or schema validation does not establish safety for {use_kind}"
                    if value.stage in {"parsed", "schema_checked"}
                    else f"LLM output may reach {use_kind} without a sink-specific guard"
                )
            elif use_kind == "unresolved call":
                status = FlowStatus.UNKNOWN
                reason = (
                    "An unresolved call receives this value before the result is used"
                )
            elif value.stage in {"parsed", "schema_checked"}:
                status = FlowStatus.VALIDATED
                reason = "The used value is the parser or schema validator result"
            elif value.stage == "raw":
                status = FlowStatus.UNVALIDATED
                reason = "Raw LLM output is used without validation"
            else:
                status = FlowStatus.UNKNOWN
                reason = (
                    "An unresolved transformation may change or validate this value"
                )
            evidence = OutputFlowEvidence(
                source_location=self.source_locations[value.source],
                use_location=location,
                status=status,
                validation_location=value.validation_location,
                validation_kind=value.validation_kind,
                path=value.at(location).path,
                reason=reason,
            )
            self._add_evidence(value.source, evidence)

    def _mark_unknown(self, node: ast.AST, state: _State, reason: str) -> None:
        values = set()
        for child in _walk_without_nested_scopes(node):
            if isinstance(child, ast.Name):
                values.update(state.bindings.get(child.id, ()))
            elif isinstance(child, ast.Call):
                source = self.source_nodes.get(id(child))
                if source is not None:
                    values.add(
                        _Value(source, "unknown", (self.source_locations[source],))
                    )
        for value in sorted(values, key=_value_sort_key):
            location = self._location(node)
            self._add_evidence(
                value.source,
                OutputFlowEvidence(
                    source_location=self.source_locations[value.source],
                    use_location=location,
                    status=FlowStatus.UNKNOWN,
                    validation_location=value.validation_location,
                    validation_kind=value.validation_kind,
                    path=value.at(location).path,
                    reason=reason,
                ),
            )

    def _mark_nested_capture(self, node: ast.AST, state: _State) -> None:
        for child in ast.walk(node):
            if isinstance(child, (ast.Nonlocal, ast.Global)):
                for name in child.names:
                    state.callables[name] = "__unknown_callable__"
                    if name in state.bindings:
                        state.bindings[name] = frozenset(
                            value.at(self._location(node), stage="unknown")
                            for value in state.bindings[name]
                        )
        for name in sorted(_captures_for_nested_scope(node)):
            for value in sorted(state.bindings.get(name, ()), key=_value_sort_key):
                location = self._location(node)
                self._add_evidence(
                    value.source,
                    OutputFlowEvidence(
                        source_location=self.source_locations[value.source],
                        use_location=location,
                        status=FlowStatus.UNKNOWN,
                        validation_location=value.validation_location,
                        validation_kind=value.validation_kind,
                        path=value.at(location).path,
                        reason="A nested scope may read this captured value",
                    ),
                )

    def _collapse(self, states: list[_State], node: ast.AST) -> _State:
        merged: dict[str, set[_Value]] = defaultdict(set)
        aliases: dict[str, str] = {}
        containers: set[str] = set()
        singleton_containers: set[str] = (
            set.intersection(*(set(state.singleton_containers) for state in states))
            if states
            else set()
        )
        for state in states:
            for name, values in state.bindings.items():
                merged[name].update(
                    value.at(self._location(node), stage="unknown") for value in values
                )
        for name in set().union(*(set(state.callables) for state in states)):
            targets = {state.callables.get(name) for state in states}
            aliases[name] = (
                targets.pop() if len(targets) == 1 else "__unknown_callable__"
            )
        for state in states:
            containers.update(state.containers)
        result = _State(
            {name: frozenset(values) for name, values in merged.items()},
            aliases,
            containers,
            singleton_containers,
            active=any(state.active for state in states),
        )
        self._mark_unknown(node, result, "Analysis path limit exceeded")
        return result

    def _add_evidence(self, source: int, evidence: OutputFlowEvidence) -> None:
        if evidence in self._seen:
            return
        bucket = self.evidence[source]
        if len(bucket) >= _MAX_EVIDENCE_PER_SOURCE:
            if not any(item.reason == "Evidence limit exceeded" for item in bucket):
                bucket[-1] = OutputFlowEvidence(
                    source_location=self.source_locations[source],
                    use_location="",
                    status=FlowStatus.UNKNOWN,
                    path=(self.source_locations[source],),
                    reason="Evidence limit exceeded",
                )
            return
        self._seen.add(evidence)
        bucket.append(evidence)

    def _location(self, node: ast.AST) -> str:
        return f"{self.filepath}:{getattr(node, 'lineno', 0)}"


def _union(groups: Any) -> frozenset[_Value]:
    values: set[_Value] = set()
    for group in groups:
        values.update(group)
    return frozenset(values)


def _value_sort_key(value: _Value) -> tuple:
    return (
        value.source,
        value.stage,
        value.path,
        value.validation_location,
        value.validation_kind,
    )


def _evidence_sort_key(evidence: OutputFlowEvidence) -> tuple:
    return (
        evidence.source_location,
        evidence.use_location,
        evidence.status.value,
        evidence.validation_location,
        evidence.validation_kind,
        evidence.path,
        evidence.reason,
    )


def _singleton_index(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return type(node.value) is int and node.value == 0
    return (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and type(node.operand.value) is int
        and node.operand.value == 1
    )


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _canonical_name(node: ast.AST, imports: dict[str, str]) -> str:
    dotted = _dotted(node)
    if not dotted:
        return ""
    head, _, tail = dotted.partition(".")
    if head in imports:
        return imports[head] + (f".{tail}" if tail else "")
    return dotted if head in {"eval", "exec", "compile"} else ""


def _imports_in(statements: list[ast.stmt]) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in statements:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return imports


def _walk_without_nested_scopes(node: ast.AST):
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(
            child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        yield from _walk_without_nested_scopes(child)


def _assigned_names(statements: list[ast.stmt]) -> set[str]:
    result: set[str] = set()
    for statement in statements:
        for child in _walk_without_nested_scopes(statement):
            if isinstance(child, ast.Name) and isinstance(
                child.ctx, (ast.Store, ast.Del)
            ):
                result.add(child.id)
    return result


def _target_names(node: ast.AST) -> set[str]:
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
    }


def _direct_sources(
    statements: list[ast.stmt], source_nodes: dict[int, int]
) -> set[int]:
    return {
        source_nodes[id(child)]
        for statement in statements
        for child in _walk_without_nested_scopes(statement)
        if id(child) in source_nodes
    }


def _pydantic_models(statements: list[ast.stmt], imports: dict[str, str]) -> set[str]:
    result = set()
    for statement in statements:
        if not isinstance(statement, ast.ClassDef):
            continue
        if (
            len(statement.bases) == 1
            and _canonical_name(statement.bases[0], imports) == "pydantic.BaseModel"
            and not statement.decorator_list
            and not statement.keywords
        ):
            overrides = {
                item.name
                for item in statement.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            overrides.update(_assigned_names(statement.body))
            if not overrides.intersection(
                {"model_validate", "model_validate_json", "parse_obj", "parse_raw"}
            ):
                result.add(statement.name)
    return result


def _local_shadowed_modules(project_root: Path, source_file: Path) -> set[str]:
    """Do not trust imports that could resolve to a module in the scanned tree."""
    locations = {project_root, project_root / "src", source_file.parent}
    parent = source_file.parent
    while parent != project_root and project_root in parent.parents:
        locations.add(parent)
        parent = parent.parent
    return {
        name
        for name in _TRUSTED_IMPORT_ROOTS
        if any(
            (folder / f"{name}.py").is_file()
            or (folder / name / "__init__.py").is_file()
            for folder in locations
        )
    }


def _mutated_attribute_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = node.value.id
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.value, ast.Name)
            and isinstance(node.target, ast.Name)
        ):
            aliases[node.target.id] = node.value.id
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            roots.add(node.args[0].id)
        if not isinstance(node, (ast.Attribute, ast.Subscript)):
            continue
        if not isinstance(node.ctx, (ast.Store, ast.Del)):
            continue
        base = node.value
        while isinstance(base, (ast.Attribute, ast.Subscript)):
            base = base.value
        if isinstance(base, ast.Name):
            roots.add(base.id)
    pending = list(roots)
    while pending:
        origin = aliases.get(pending.pop())
        if origin and origin not in roots:
            roots.add(origin)
            pending.append(origin)
    return roots


def _captures_for_nested_scope(node: ast.AST) -> set[str]:
    body = getattr(node, "body", [])
    if not isinstance(body, list):
        return set()
    bound = _assigned_names(body)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        bound.update(arg.arg for arg in node.args.posonlyargs)
        bound.update(arg.arg for arg in node.args.args)
        bound.update(arg.arg for arg in node.args.kwonlyargs)
        if node.args.vararg:
            bound.add(node.args.vararg.arg)
        if node.args.kwarg:
            bound.add(node.args.kwarg.arg)
    return {
        item.id
        for statement in body
        for item in _walk_without_nested_scopes(statement)
        if isinstance(item, ast.Name)
        and isinstance(item.ctx, ast.Load)
        and item.id not in bound
    }


def _captured_names(statements: list[ast.stmt]) -> set[str]:
    names: set[str] = set()
    for statement in statements:
        for item in _walk_without_nested_scopes(statement):
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.update(_captures_for_nested_scope(item))
    return names
