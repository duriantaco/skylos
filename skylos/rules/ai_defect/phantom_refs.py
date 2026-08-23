from __future__ import annotations

import ast
import builtins
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

from skylos.analysis.control_flow import _parse_requires_python
from skylos.rules.quality._protocols import (
    type_checking_context,
    type_checking_guard_branches,
)
from skylos.rules.vibe_dictionary import DEFAULT_VIBE_DICTIONARY


PYTHON_SOURCE_SUFFIXES = (".py", ".pyi", ".pyw")

# Stable attributes supplied by the import system or inherited by module
# objects. Version-specific attributes belong in target-aware analysis.
_STANDARD_MODULE_ATTRIBUTES = frozenset(
    {
        "__annotations__",
        "__cached__",
        "__class__",
        "__dict__",
        "__doc__",
        "__file__",
        "__loader__",
        "__name__",
        "__package__",
        "__spec__",
    }
)

# ``__annotate__`` exists only on Python 3.14+ (PEP 749). It is exempted only
# when the scanned project declares a version floor of >= 3.14.
ANNOTATE_MIN_VERSION = (3, 14)
ANNOTATE_ATTRIBUTE = "__annotate__"


def _module_dunder_attributes(project_root) -> frozenset[str]:
    """Module dunders exempt from phantom checks for this project.

    ``__annotate__`` is exempt only when pyproject.toml declares
    ``requires-python >= 3.14`` (PEP 749). Without that declaration the
    attribute is treated as a phantom reference.
    """
    attributes = set(_STANDARD_MODULE_ATTRIBUTES)
    min_version, _ = _parse_requires_python(str(project_root))
    if min_version is not None and min_version >= ANNOTATE_MIN_VERSION:
        attributes.add(ANNOTATE_ATTRIBUTE)
    return frozenset(attributes)


@dataclass
class _ScopeInfo:
    shadowed_names: set[str]
    bound_names: set[str]
    local_imports: dict[str, list[tuple[int, str]]]
    imported_module_paths: dict[str, list[tuple[int, str]]]


@dataclass
class _ModuleFactState:
    members: set[str]
    exported_modules: dict[str, str]
    has_dynamic_getattr: bool = False
    has_wildcard_reexport: bool = False

    def copy(self) -> _ModuleFactState:
        return _ModuleFactState(
            members=set(self.members),
            exported_modules=dict(self.exported_modules),
            has_dynamic_getattr=self.has_dynamic_getattr,
            has_wildcard_reexport=self.has_wildcard_reexport,
        )


@dataclass
class _ModuleFacts:
    members: set[str]
    type_checking_members: set[str]
    exported_modules: dict[str, str]
    type_checking_exported_modules: dict[str, str]
    has_dynamic_getattr: bool
    has_type_checking_dynamic_getattr: bool
    type_checking_node_ids: set[int]


def scan_repo_phantom_security_references(
    project_root, py_files, target_files=None, vibe_dictionary=None
):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    root = Path(project_root).resolve()
    module_dunder_attributes = _module_dunder_attributes(root)
    files = [
        Path(f).resolve() for f in py_files if Path(f).suffix in PYTHON_SOURCE_SUFFIXES
    ]
    target_paths = {
        Path(f).resolve()
        for f in (target_files or files)
        if Path(f).suffix in PYTHON_SOURCE_SUFFIXES
    }

    module_to_file = {}
    file_to_module = {}
    module_members = {}
    module_type_checking_members = {}
    module_alias_exports = {}
    module_type_checking_alias_exports = {}
    dynamic_modules = set()
    type_checking_dynamic_modules = set()
    module_type_checking_node_ids = {}
    parse_failures = set()

    for file_path in files:
        try:
            file_path.relative_to(root)
        except ValueError:
            continue
        module_name = _module_name(root, file_path)
        if not module_name:
            continue
        module_to_file[module_name] = file_path
        file_to_module[file_path] = module_name

    local_modules = set(module_to_file)
    package_modules = {
        module_name
        for module_name, file_path in module_to_file.items()
        if _is_package_module_file(file_path)
    }
    if not local_modules:
        return []

    builtin_names = set(dir(builtins))

    def _store_module_facts(
        module_name,
        tree,
        *,
        source_has_type_checking=None,
        include_reference_context=False,
    ):
        facts = _collect_module_facts(
            tree,
            module_name,
            local_modules,
            source_has_type_checking=source_has_type_checking,
            include_reference_context=include_reference_context,
        )
        module_members[module_name] = facts.members
        module_type_checking_members[module_name] = facts.type_checking_members
        module_alias_exports[module_name] = {
            alias: target
            for alias, target in facts.exported_modules.items()
            if target in local_modules
        }
        module_type_checking_alias_exports[module_name] = {
            alias: target
            for alias, target in facts.type_checking_exported_modules.items()
            if target in local_modules
        }
        module_type_checking_node_ids[module_name] = facts.type_checking_node_ids
        dynamic_modules.discard(module_name)
        type_checking_dynamic_modules.discard(module_name)
        if facts.has_dynamic_getattr:
            dynamic_modules.add(module_name)
        if facts.has_type_checking_dynamic_getattr:
            type_checking_dynamic_modules.add(module_name)

    def _ensure_module_loaded(module_name):
        if module_name in module_members:
            return True
        if module_name in parse_failures:
            return False

        file_path = module_to_file.get(module_name)
        if not file_path:
            parse_failures.add(module_name)
            return False

        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            parse_failures.add(module_name)
            return False

        _store_module_facts(
            module_name,
            tree,
            source_has_type_checking="TYPE_CHECKING" in source,
        )
        return True

    findings = []

    for file_path, current_module in file_to_module.items():
        _ensure_module_loaded(current_module)

    repo_member_names = _repo_member_names(module_members)

    for file_path, current_module in file_to_module.items():
        if target_paths and file_path not in target_paths:
            continue
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue

        _store_module_facts(
            current_module,
            tree,
            source_has_type_checking="TYPE_CHECKING" in source,
            include_reference_context=True,
        )
        parent_map = _build_parent_map(tree)
        scope_infos = _build_scope_infos(tree, current_module, local_modules)
        type_checking_node_ids = module_type_checking_node_ids.get(
            current_module, set()
        )

        def _active_module_surface(
            node,
            current_type_checking_node_ids=type_checking_node_ids,
        ):
            if id(node) in current_type_checking_node_ids:
                return (
                    module_type_checking_members,
                    module_type_checking_alias_exports,
                    type_checking_dynamic_modules,
                )
            return module_members, module_alias_exports, dynamic_modules

        findings.extend(
            _direct_local_import_findings(
                file_path,
                current_module,
                tree,
                local_modules,
                module_members,
                module_type_checking_members,
                dynamic_modules,
                type_checking_dynamic_modules,
                type_checking_node_ids,
                package_modules,
                _ensure_module_loaded,
                module_dunder_attributes,
            )
        )

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                if _attribute_is_call_target(node, parent_map):
                    continue
                if _attribute_is_decorator_target(node, parent_map):
                    continue
                if _attribute_is_nested_prefix(node, parent_map):
                    continue
                active_members, active_aliases, active_dynamic = _active_module_surface(
                    node
                )
                resolved = _resolve_local_module_member(
                    expr=node,
                    node=node,
                    tree=tree,
                    parent_map=parent_map,
                    scope_infos=scope_infos,
                    module_alias_exports=active_aliases,
                    local_modules=local_modules,
                    ensure_module_loaded=_ensure_module_loaded,
                )
                if not resolved:
                    continue
                target_module, member_name, expr_text = resolved
                if not _ensure_module_loaded(target_module):
                    continue
                if target_module in active_dynamic:
                    continue
                if _module_has_member(
                    target_module,
                    member_name,
                    active_members,
                    package_modules,
                    module_dunder_attributes,
                ):
                    continue
                findings.append(
                    _build_reference_finding(
                        file_path,
                        node,
                        expr_text,
                        target_module,
                        member_name,
                    )
                )
                continue

            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    bare_finding = _bare_call_finding(
                        file_path=file_path,
                        node=node.func,
                        tree=tree,
                        parent_map=parent_map,
                        scope_infos=scope_infos,
                        repo_member_names=repo_member_names,
                        builtin_names=builtin_names,
                        phantom_security_names=vibe_dictionary.phantom_security_names,
                    )
                    if bare_finding is not None:
                        findings.append(bare_finding)
                    continue

                active_members, active_aliases, active_dynamic = _active_module_surface(
                    node
                )
                resolved = _resolve_local_module_member(
                    expr=node.func,
                    node=node,
                    tree=tree,
                    parent_map=parent_map,
                    scope_infos=scope_infos,
                    module_alias_exports=active_aliases,
                    local_modules=local_modules,
                    ensure_module_loaded=_ensure_module_loaded,
                )
                if not resolved:
                    continue

                target_module, member_name, expr_text = resolved
                if not _ensure_module_loaded(target_module):
                    continue
                if target_module in active_dynamic:
                    continue
                if _module_has_member(
                    target_module,
                    member_name,
                    active_members,
                    package_modules,
                    module_dunder_attributes,
                ):
                    continue

                findings.append(
                    _build_call_finding(
                        file_path=file_path,
                        node=node.func,
                        expr_text=expr_text,
                        target_module=target_module,
                        member_name=member_name,
                    )
                )
                continue

            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue

            for deco in node.decorator_list:
                deco_target = _decorator_target(deco)
                active_members, active_aliases, active_dynamic = _active_module_surface(
                    deco_target
                )
                resolved = _resolve_local_module_member(
                    expr=deco_target,
                    node=deco_target,
                    tree=tree,
                    parent_map=parent_map,
                    scope_infos=scope_infos,
                    module_alias_exports=active_aliases,
                    local_modules=local_modules,
                    ensure_module_loaded=_ensure_module_loaded,
                )
                if not resolved:
                    continue

                target_module, member_name, expr_text = resolved
                if not _ensure_module_loaded(target_module):
                    continue
                if target_module in active_dynamic:
                    continue
                if _module_has_member(
                    target_module,
                    member_name,
                    active_members,
                    package_modules,
                    module_dunder_attributes,
                ):
                    continue

                findings.append(
                    _build_decorator_finding(
                        file_path=file_path,
                        node=deco_target,
                        expr_text=expr_text,
                        target_module=target_module,
                        member_name=member_name,
                    )
                )

    return findings


def _direct_local_import_findings(
    file_path,
    current_module,
    tree,
    local_modules,
    module_members,
    module_type_checking_members,
    dynamic_modules,
    type_checking_dynamic_modules,
    type_checking_node_ids,
    package_modules,
    ensure_module_loaded,
    module_dunder_attributes: frozenset[str] = _STANDARD_MODULE_ATTRIBUTES,
):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        base = _resolve_import_from_base(current_module, node)
        if base not in local_modules:
            continue
        if id(node) in type_checking_node_ids:
            active_members = module_type_checking_members
            active_dynamic = type_checking_dynamic_modules
        else:
            active_members = module_members
            active_dynamic = dynamic_modules
        if not ensure_module_loaded(base) or base in active_dynamic:
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            full_module = f"{base}.{alias.name}"
            if full_module in local_modules:
                continue
            if _module_has_member(
                base,
                alias.name,
                active_members,
                package_modules,
                module_dunder_attributes,
            ):
                continue
            if base in package_modules:
                continue
            findings.append(
                _build_import_finding(
                    file_path,
                    node,
                    base,
                    alias.name,
                )
            )
    return findings


def _is_package_module_file(file_path):
    return file_path.name in {"__init__.py", "__init__.pyi", "__init__.pyw"}


def _module_has_member(
    module_name,
    member_name,
    module_members,
    package_modules,
    module_dunder_attributes: frozenset[str] = _STANDARD_MODULE_ATTRIBUTES,
):
    if member_name in module_members.get(module_name, set()):
        return True
    if member_name in module_dunder_attributes:
        return True
    return member_name == "__path__" and module_name in package_modules


def _repo_member_names(module_members):
    names = set()
    for members in module_members.values():
        names.update(members)
    return names


def _bare_call_finding(
    file_path,
    node,
    tree,
    parent_map,
    scope_infos,
    repo_member_names,
    builtin_names,
    phantom_security_names,
):
    name = node.id
    if name in builtin_names:
        return None
    if name in phantom_security_names:
        return None
    if _bare_name_is_bound(name, node, tree, parent_map, scope_infos):
        return None
    if not _resembles_local_symbol(name, repo_member_names):
        return None
    return _build_bare_call_finding(file_path, node, name)


def _bare_name_is_bound(name, node, tree, parent_map, scope_infos):
    for scope in _enclosing_scopes(node, tree, parent_map):
        info = scope_infos.get(scope)
        if not info:
            continue
        if name in info.bound_names:
            return True
    return False


def _resembles_local_symbol(name, repo_member_names):
    for candidate in repo_member_names:
        if candidate == name:
            continue
        if _shared_suffix_token(name, candidate):
            return True
        similarity = SequenceMatcher(None, name, candidate).ratio()
        if similarity >= 0.82:
            return True
    return False


def _shared_suffix_token(left, right):
    left_parts = left.split("_")
    right_parts = right.split("_")
    if len(left_parts) < 2:
        return False
    if len(right_parts) < 2:
        return False
    return left_parts[-1] == right_parts[-1]


def _decorator_target(decorator):
    if isinstance(decorator, ast.Call):
        return decorator.func
    return decorator


def _module_name(root: Path, file_path: Path) -> str:
    parts = list(file_path.relative_to(root).parts)

    if "src" in parts:
        src_idx = parts.index("src")
        src_path = root / "/".join(parts[: src_idx + 1])
        if not (src_path / "__init__.py").exists():
            parts = parts[src_idx + 1 :]

    if not parts:
        return ""

    for suffix in PYTHON_SOURCE_SUFFIXES:
        if parts[-1].endswith(suffix):
            parts[-1] = parts[-1][: -len(suffix)]
            break
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _collect_module_facts(
    tree,
    current_module,
    local_modules,
    *,
    source_has_type_checking=None,
    include_reference_context=False,
):
    if not isinstance(tree, ast.Module):
        return _ModuleFacts(
            members=set(),
            type_checking_members=set(),
            exported_modules={},
            type_checking_exported_modules={},
            has_dynamic_getattr=False,
            has_type_checking_dynamic_getattr=False,
            type_checking_node_ids=set(),
        )

    if source_has_type_checking is False:
        type_checking_guards = {}
        type_checking_node_ids = set()
    elif include_reference_context:
        type_checking_guards, type_checking_node_ids = type_checking_context(tree)
    else:
        type_checking_guards = type_checking_guard_branches(tree)
        type_checking_node_ids = set()
    if include_reference_context:
        type_checking_node_ids.update(_postponed_annotation_node_ids(tree))
    runtime = _collect_module_fact_state(
        tree.body,
        current_module,
        local_modules,
        type_checking_guards,
        type_checking_mode=False,
    )
    if type_checking_guards:
        type_checking = _collect_module_fact_state(
            tree.body,
            current_module,
            local_modules,
            type_checking_guards,
            type_checking_mode=True,
        )
    else:
        type_checking = runtime.copy()
    return _ModuleFacts(
        members=runtime.members,
        type_checking_members=type_checking.members,
        exported_modules=runtime.exported_modules,
        type_checking_exported_modules=type_checking.exported_modules,
        has_dynamic_getattr=(
            runtime.has_dynamic_getattr or runtime.has_wildcard_reexport
        ),
        has_type_checking_dynamic_getattr=(
            type_checking.has_dynamic_getattr or type_checking.has_wildcard_reexport
        ),
        type_checking_node_ids=type_checking_node_ids,
    )


def _collect_module_fact_state(
    statements,
    current_module,
    local_modules,
    type_checking_guards,
    *,
    type_checking_mode,
    initial=None,
):
    state = initial.copy() if initial is not None else _ModuleFactState(set(), {})

    for stmt in statements:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _invalidate_interruptible_module_facts(state, [stmt])
            _bind_plain_module_names(state, {stmt.name})
            if stmt.name == "__getattr__":
                state.has_dynamic_getattr = True
        elif isinstance(stmt, ast.ClassDef):
            _invalidate_interruptible_module_facts(state, [stmt])
            _bind_plain_module_names(state, {stmt.name})
        elif isinstance(stmt, ast.Assign):
            _apply_expression_rebindings(state, stmt.value)
            names = set()
            for target in stmt.targets:
                names.update(_extract_target_names(target))
            _bind_plain_module_names(state, names)
        elif isinstance(stmt, ast.AnnAssign):
            names = _extract_target_names(stmt.target)
            state.members.update(names)
            if stmt.value is not None:
                _apply_expression_rebindings(state, stmt.value)
                _clear_module_aliases(state, names)
        elif isinstance(stmt, ast.AugAssign):
            _apply_expression_rebindings(state, stmt.value)
            _bind_plain_module_names(state, _extract_target_names(stmt.target))
        elif _is_type_alias_statement(stmt):
            _bind_plain_module_names(state, _extract_target_names(stmt.name))
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                _bind_plain_module_names(state, {bound_name})
                if alias.asname and alias.name in local_modules:
                    state.exported_modules[bound_name] = alias.name
                elif not alias.asname:
                    head = alias.name.split(".", 1)[0]
                    if head in local_modules:
                        state.exported_modules[head] = head
        elif isinstance(stmt, ast.ImportFrom):
            base = _resolve_import_from_base(current_module, stmt)
            for alias in stmt.names:
                if alias.name == "*":
                    if base in local_modules:
                        state.has_wildcard_reexport = True
                    continue
                bound_name = alias.asname or alias.name
                _bind_plain_module_names(state, {bound_name})
                if base:
                    full_name = f"{base}.{alias.name}"
                else:
                    full_name = alias.name
                if full_name in local_modules:
                    state.exported_modules[bound_name] = full_name
        elif isinstance(stmt, ast.Delete):
            names = set()
            for target in stmt.targets:
                names.update(_extract_target_names(target))
            _delete_module_names(state, names)
        elif isinstance(stmt, ast.If):
            _apply_expression_rebindings(state, stmt.test)
            type_checking_branch = type_checking_guards.get(id(stmt))
            if type_checking_branch is not None:
                select_body = (
                    type_checking_branch
                    if type_checking_mode
                    else not type_checking_branch
                )
                selected = stmt.body if select_body else stmt.orelse
                state = _collect_module_fact_state(
                    selected,
                    current_module,
                    local_modules,
                    type_checking_guards,
                    type_checking_mode=type_checking_mode,
                    initial=state,
                )
                continue

            condition = _static_truth_value(stmt.test)
            if condition is not None:
                selected = stmt.body if condition else stmt.orelse
                state = _collect_module_fact_state(
                    selected,
                    current_module,
                    local_modules,
                    type_checking_guards,
                    type_checking_mode=type_checking_mode,
                    initial=state,
                )
                continue

            body_state = _collect_module_fact_state(
                stmt.body,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=state,
            )
            else_state = _collect_module_fact_state(
                stmt.orelse,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=state,
            )
            state = _intersect_module_fact_states([body_state, else_state])
        elif _is_try_statement(stmt):
            handler_entry_state = state.copy()
            _invalidate_interruptible_module_facts(
                handler_entry_state,
                stmt.body,
            )
            _invalidate_interruptible_module_facts(
                handler_entry_state,
                [handler.type for handler in stmt.handlers if handler.type],
            )
            normal_state = _collect_module_fact_state(
                stmt.body,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=state,
            )
            normal_state = _collect_module_fact_state(
                stmt.orelse,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=normal_state,
            )
            paths = [normal_state]
            for handler in stmt.handlers:
                handler_state = handler_entry_state.copy()
                if handler.name:
                    _bind_plain_module_names(handler_state, {handler.name})
                handler_state = _collect_module_fact_state(
                    handler.body,
                    current_module,
                    local_modules,
                    type_checking_guards,
                    type_checking_mode=type_checking_mode,
                    initial=handler_state,
                )
                if handler.name:
                    _delete_module_names(handler_state, {handler.name})
                paths.append(handler_state)
            state = _intersect_module_fact_states(paths)
            state = _collect_module_fact_state(
                stmt.finalbody,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=state,
            )
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            entry_state = state.copy()
            early_exit_states = []
            if stmt.items:
                first_item = stmt.items[0]
                _apply_expression_rebindings(
                    entry_state,
                    first_item.context_expr,
                )
                if first_item.optional_vars is not None:
                    if not isinstance(first_item.optional_vars, ast.Name):
                        suppressed_target_state = entry_state.copy()
                        _invalidate_interruptible_module_facts(
                            suppressed_target_state,
                            [first_item.optional_vars],
                        )
                        early_exit_states.append(suppressed_target_state)
                    _bind_plain_module_names(
                        entry_state,
                        _extract_target_names(first_item.optional_vars),
                    )

            body_entry_state = entry_state.copy()
            for item in stmt.items[1:]:
                _apply_expression_rebindings(
                    body_entry_state,
                    item.context_expr,
                )
                if item.optional_vars is not None:
                    _bind_plain_module_names(
                        body_entry_state,
                        _extract_target_names(item.optional_vars),
                    )

            interrupted_state = entry_state.copy()
            interruptible_nodes = []
            for item in stmt.items[1:]:
                interruptible_nodes.append(item.context_expr)
                if item.optional_vars is not None:
                    interruptible_nodes.append(item.optional_vars)
            interruptible_nodes.extend(stmt.body)
            _invalidate_interruptible_module_facts(
                interrupted_state,
                interruptible_nodes,
            )
            body_state = _collect_module_fact_state(
                stmt.body,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=body_entry_state,
            )
            state = _intersect_module_fact_states(
                [*early_exit_states, interrupted_state, body_state]
            )
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            _apply_expression_rebindings(state, stmt.iter)
            if _is_statically_empty_iterable(stmt.iter):
                state = _collect_module_fact_state(
                    stmt.orelse,
                    current_module,
                    local_modules,
                    type_checking_guards,
                    type_checking_mode=type_checking_mode,
                    initial=state,
                )
                continue
            body_start = state.copy()
            _bind_plain_module_names(
                body_start,
                _extract_target_names(stmt.target),
            )
            body_state = _collect_module_fact_state(
                stmt.body,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=body_start,
            )
            loop_state = _intersect_module_fact_states([state, body_state])
            else_state = _collect_module_fact_state(
                stmt.orelse,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=loop_state,
            )
            state = _intersect_module_fact_states([loop_state, else_state])
        elif isinstance(stmt, ast.While):
            _apply_expression_rebindings(state, stmt.test)
            if _static_truth_value(stmt.test) is False:
                state = _collect_module_fact_state(
                    stmt.orelse,
                    current_module,
                    local_modules,
                    type_checking_guards,
                    type_checking_mode=type_checking_mode,
                    initial=state,
                )
                continue
            body_state = _collect_module_fact_state(
                stmt.body,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=state,
            )
            loop_state = _intersect_module_fact_states([state, body_state])
            else_state = _collect_module_fact_state(
                stmt.orelse,
                current_module,
                local_modules,
                type_checking_guards,
                type_checking_mode=type_checking_mode,
                initial=loop_state,
            )
            state = _intersect_module_fact_states([loop_state, else_state])
        elif isinstance(stmt, ast.Match):
            _apply_expression_rebindings(state, stmt.subject)
            _invalidate_interruptible_module_facts(
                state,
                [case.guard for case in stmt.cases if case.guard],
            )
            exhaustive = bool(stmt.cases) and _is_irrefutable_match_case(stmt.cases[-1])
            paths = [] if exhaustive else [state.copy()]
            for case in stmt.cases:
                case_state = state.copy()
                _bind_plain_module_names(
                    case_state,
                    _extract_match_pattern_names(case.pattern),
                )
                case_state = _collect_module_fact_state(
                    case.body,
                    current_module,
                    local_modules,
                    type_checking_guards,
                    type_checking_mode=type_checking_mode,
                    initial=case_state,
                )
                paths.append(case_state)
            state = _intersect_module_fact_states(paths)
        elif isinstance(stmt, ast.Expr):
            _apply_expression_rebindings(state, stmt.value)
        elif isinstance(stmt, ast.Assert):
            _invalidate_interruptible_module_facts(
                state,
                [expression for expression in (stmt.test, stmt.msg) if expression],
            )

    return state


def _invalidate_interruptible_module_facts(state, statements):
    class MutationCollector(ast.NodeVisitor):
        def __init__(self):
            self.rebound_names = set()
            self.deleted_names = set()
            self.clears_dynamic_getattr = False

        def _record_names(self, names, *, deleted=False):
            self.rebound_names.update(names)
            if deleted:
                self.deleted_names.update(names)
            if "__getattr__" in names:
                self.clears_dynamic_getattr = True

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Store):
                self._record_names({node.id})
            elif isinstance(node.ctx, ast.Del):
                self._record_names({node.id}, deleted=True)

        def visit_Import(self, node):
            self._record_names(
                {
                    imported.asname or imported.name.split(".", 1)[0]
                    for imported in node.names
                }
            )

        def visit_ImportFrom(self, node):
            self._record_names(
                {
                    imported.asname or imported.name
                    for imported in node.names
                    if imported.name != "*"
                }
            )

        def visit_FunctionDef(self, node):
            self.rebound_names.add(node.name)
            self._visit_function_header(node)

        def visit_AsyncFunctionDef(self, node):
            self.rebound_names.add(node.name)
            self._visit_function_header(node)

        def _visit_function_header(self, node):
            for decorator in node.decorator_list:
                self.visit(decorator)
            for default in node.args.defaults:
                self.visit(default)
            for default in node.args.kw_defaults:
                if default is not None:
                    self.visit(default)
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            ):
                if argument.annotation is not None:
                    self.visit(argument.annotation)
            for argument in (node.args.vararg, node.args.kwarg):
                if argument is not None and argument.annotation is not None:
                    self.visit(argument.annotation)
            if node.returns is not None:
                self.visit(node.returns)
            for type_parameter in getattr(node, "type_params", []):
                self.visit(type_parameter)

        def visit_ClassDef(self, node):
            self._record_names({node.name})
            for decorator in node.decorator_list:
                self.visit(decorator)
            for base in node.bases:
                self.visit(base)
            for keyword in node.keywords:
                self.visit(keyword.value)
            for type_parameter in getattr(node, "type_params", []):
                self.visit(type_parameter)

        def visit_Lambda(self, node):
            for default in node.args.defaults:
                self.visit(default)
            for default in node.args.kw_defaults:
                if default is not None:
                    self.visit(default)

        def visit_ExceptHandler(self, node):
            if node.type is not None:
                self.visit(node.type)
            if node.name:
                self._record_names({node.name}, deleted=True)
            for child in node.body:
                self.visit(child)

        def visit_MatchAs(self, node):
            if node.name:
                self._record_names({node.name})
            if node.pattern is not None:
                self.visit(node.pattern)

        def visit_MatchStar(self, node):
            if node.name:
                self._record_names({node.name})

        def visit_MatchMapping(self, node):
            if node.rest:
                self._record_names({node.rest})
            self.generic_visit(node)

    collector = MutationCollector()
    for stmt in statements:
        collector.visit(stmt)

    state.members.difference_update(collector.deleted_names)
    for name in collector.rebound_names:
        state.exported_modules.pop(name, None)
    if collector.clears_dynamic_getattr:
        state.has_dynamic_getattr = False


def _bind_plain_module_names(state, names):
    state.members.update(names)
    _clear_module_aliases(state, names)


def _clear_module_aliases(state, names):
    for name in names:
        state.exported_modules.pop(name, None)
        if name == "__getattr__":
            state.has_dynamic_getattr = False


def _delete_module_names(state, names):
    state.members.difference_update(names)
    _clear_module_aliases(state, names)


def _apply_expression_rebindings(state, expression):
    possible_names = {
        name
        for node in ast.walk(expression)
        if isinstance(node, ast.NamedExpr)
        for name in _extract_target_names(node.target)
    }
    _clear_module_aliases(state, possible_names)

    current = expression
    while isinstance(current, ast.NamedExpr):
        state.members.update(_extract_target_names(current.target))
        current = current.value


def _intersect_module_fact_states(states):
    if not states:
        return _ModuleFactState(set(), {})

    members = set(states[0].members)
    for state in states[1:]:
        members.intersection_update(state.members)

    exported_modules = {
        name: target
        for name, target in states[0].exported_modules.items()
        if name in members
        and all(state.exported_modules.get(name) == target for state in states[1:])
    }
    return _ModuleFactState(
        members=members,
        exported_modules=exported_modules,
        has_dynamic_getattr=all(state.has_dynamic_getattr for state in states),
        has_wildcard_reexport=all(state.has_wildcard_reexport for state in states),
    )


def _static_truth_value(test):
    if isinstance(test, ast.NamedExpr):
        return _static_truth_value(test.value)
    if isinstance(test, ast.Constant):
        return bool(test.value)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        value = _static_truth_value(test.operand)
        return None if value is None else not value
    return None


def _is_try_statement(stmt):
    return isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar"


def _is_type_alias_statement(stmt):
    type_alias_node = getattr(ast, "TypeAlias", None)
    return type_alias_node is not None and isinstance(stmt, type_alias_node)


def _extract_match_pattern_names(pattern):
    names = set()
    for node in ast.walk(pattern):
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.add(node.rest)
    return names


def _is_statically_empty_iterable(expression):
    return (
        isinstance(expression, (ast.List, ast.Set, ast.Tuple)) and not expression.elts
    )


def _is_irrefutable_match_case(case):
    pattern = case.pattern
    return (
        case.guard is None
        and isinstance(pattern, ast.MatchAs)
        and pattern.pattern is None
    )


def _postponed_annotation_node_ids(tree):
    if not _uses_future_annotations(tree):
        return set()

    annotation_roots = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            annotation_roots.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns is not None:
                annotation_roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            annotation_roots.append(node.annotation)

    return {
        id(node) for annotation in annotation_roots for node in ast.walk(annotation)
    }


def _uses_future_annotations(tree):
    return any(
        isinstance(stmt, ast.ImportFrom)
        and stmt.module == "__future__"
        and any(imported.name == "annotations" for imported in stmt.names)
        for stmt in tree.body
    )


def _build_parent_map(tree):
    parent_map = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent
    return parent_map


def _build_scope_infos(tree, current_module, local_modules):
    scope_infos = {tree: _collect_scope_info(tree, current_module, local_modules)}
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            scope_infos[node] = _collect_scope_info(node, current_module, local_modules)
    return scope_infos


def _collect_scope_info(scope_node, current_module, local_modules):
    shadowed = set()
    bound = set()
    local_imports = defaultdict(list)
    imported_module_paths = defaultdict(list)

    if isinstance(scope_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arg_names = _extract_args_names(scope_node.args)
        shadowed.update(arg_names)
        bound.update(arg_names)

    class ScopeCollector(ast.NodeVisitor):
        def generic_visit(self, node):
            for child in ast.iter_child_nodes(node):
                self.visit(child)

        def visit_Import(self, node):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                bound.add(bound_name)
                if alias.asname:
                    full_name = alias.name
                else:
                    full_name = alias.name.split(".", 1)[0]
                if full_name in local_modules:
                    local_imports[bound_name].append((node.lineno, full_name))
                if (
                    not alias.asname
                    and "." in alias.name
                    and alias.name in local_modules
                ):
                    imported_module_paths[bound_name].append(
                        (node.lineno, alias.name)
                    )

        def visit_ImportFrom(self, node):
            base = _resolve_import_from_base(current_module, node)
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound.add(alias.asname or alias.name)
                if base:
                    full_name = f"{base}.{alias.name}"
                else:
                    full_name = alias.name
                if full_name in local_modules:
                    local_imports[alias.asname or alias.name].append(
                        (node.lineno, full_name)
                    )

        def visit_Assign(self, node):
            for target in node.targets:
                names = _extract_target_names(target)
                shadowed.update(names)
                bound.update(names)
            self.generic_visit(node.value)

        def visit_AnnAssign(self, node):
            names = _extract_target_names(node.target)
            shadowed.update(names)
            bound.update(names)
            if node.value:
                self.generic_visit(node.value)

        def visit_AugAssign(self, node):
            names = _extract_target_names(node.target)
            shadowed.update(names)
            bound.update(names)
            self.generic_visit(node.value)

        def visit_NamedExpr(self, node):
            names = _extract_target_names(node.target)
            shadowed.update(names)
            bound.update(names)
            self.generic_visit(node.value)

        def visit_For(self, node):
            names = _extract_target_names(node.target)
            shadowed.update(names)
            bound.update(names)
            self.generic_visit(node.iter)
            for stmt in node.body:
                self.visit(stmt)
            for stmt in node.orelse:
                self.visit(stmt)

        visit_AsyncFor = visit_For

        def visit_With(self, node):
            for item in node.items:
                if item.optional_vars is not None:
                    names = _extract_target_names(item.optional_vars)
                    shadowed.update(names)
                    bound.update(names)
                self.visit(item.context_expr)
            for stmt in node.body:
                self.visit(stmt)

        visit_AsyncWith = visit_With

        def visit_ExceptHandler(self, node):
            if node.name:
                shadowed.add(node.name)
                bound.add(node.name)
            if node.type:
                self.visit(node.type)
            for stmt in node.body:
                self.visit(stmt)

        def visit_FunctionDef(self, node):
            shadowed.add(node.name)
            bound.add(node.name)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            shadowed.add(node.name)
            bound.add(node.name)

        def visit_Lambda(self, node):
            return

    collector = ScopeCollector()
    if isinstance(scope_node, ast.Module):
        for stmt in scope_node.body:
            collector.visit(stmt)
    elif isinstance(scope_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        for stmt in scope_node.body:
            collector.visit(stmt)
    elif isinstance(scope_node, ast.Lambda):
        collector.visit(scope_node.body)

    return _ScopeInfo(
        shadowed_names=shadowed,
        bound_names=bound,
        local_imports={k: sorted(v) for k, v in local_imports.items()},
        imported_module_paths={
            k: sorted(v) for k, v in imported_module_paths.items()
        },
    )


def _resolve_local_module_member(
    expr,
    node,
    tree,
    parent_map,
    scope_infos,
    module_alias_exports,
    local_modules,
    ensure_module_loaded,
):
    chain = _flatten_attribute_chain(expr)
    if not chain or len(chain) < 2:
        return None

    base_module = _resolve_visible_alias(
        base_name=chain[0],
        node=node,
        tree=tree,
        parent_map=parent_map,
        scope_infos=scope_infos,
    )
    if not base_module:
        return None

    if _is_explicitly_imported_module_reference(
        chain=chain,
        node=node,
        tree=tree,
        parent_map=parent_map,
        scope_infos=scope_infos,
    ):
        return None

    current_module = base_module
    for segment in chain[1:-1]:
        direct_module = f"{current_module}.{segment}"
        if direct_module in local_modules:
            current_module = direct_module
            continue

        if not ensure_module_loaded(current_module):
            return None
        exported_module = module_alias_exports.get(current_module, {}).get(segment)
        if exported_module:
            current_module = exported_module
            continue

        return None

    return current_module, chain[-1], ".".join(chain)


def _resolve_visible_alias(base_name, node, tree, parent_map, scope_infos):
    visible_module = None
    for scope in _enclosing_scopes(node, tree, parent_map):
        info = scope_infos.get(scope)
        if not info:
            continue

        if base_name in info.shadowed_names:
            return None

        imports = info.local_imports.get(base_name, [])
        if not imports:
            continue

        matching = [module_name for line, module_name in imports if line <= node.lineno]
        if not matching:
            return None
        visible_module = matching[-1]

    return visible_module


def _is_explicitly_imported_module_reference(
    chain,
    node,
    tree,
    parent_map,
    scope_infos,
):
    expression = ".".join(chain)
    base_name = chain[0]

    for scope in _enclosing_scopes(node, tree, parent_map):
        info = scope_infos.get(scope)
        if not info:
            continue
        imports = info.imported_module_paths.get(base_name, [])
        for line, module_name in imports:
            if line > node.lineno:
                continue
            if module_name == expression or module_name.startswith(f"{expression}."):
                return True

    return False


def _enclosing_scopes(node, tree, parent_map):
    scopes = [tree]
    cur = parent_map.get(node)
    child = node
    nested_scopes = []
    function_barrier = False

    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if _is_decorator_expression(child, cur):
                child = cur
                cur = parent_map.get(cur)
                continue
            nested_scopes.append(cur)
            function_barrier = True
        elif isinstance(cur, ast.ClassDef) and not function_barrier:
            nested_scopes.append(cur)

        child = cur
        cur = parent_map.get(cur)

    scopes.extend(reversed(nested_scopes))
    return scopes


def _is_decorator_expression(child, parent):
    decorator_list = getattr(parent, "decorator_list", None)
    return bool(decorator_list) and child in decorator_list


def _attribute_is_call_target(node, parent_map):
    parent = parent_map.get(node)
    return isinstance(parent, ast.Call) and parent.func is node


def _attribute_is_decorator_target(node, parent_map):
    child = node
    current = parent_map.get(node)
    while current is not None:
        if isinstance(current, ast.Call) and current.func is child:
            child = current
            current = parent_map.get(current)
            continue
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return child in current.decorator_list
        if isinstance(current, ast.Attribute) and current.value is child:
            child = current
            current = parent_map.get(current)
            continue
        break
    return False


def _attribute_is_nested_prefix(node, parent_map):
    parent = parent_map.get(node)
    return isinstance(parent, ast.Attribute) and parent.value is node


def _resolve_import_from_base(current_module, node):
    module = node.module or ""
    if "." in current_module:
        cur_pkg = current_module.rsplit(".", 1)[0]
    else:
        cur_pkg = current_module

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
            if base:
                base = f"{base}.{module}"
            else:
                base = module
        return base

    return module


def _flatten_attribute_chain(expr):
    parts = []
    current = expr

    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value

    if not isinstance(current, ast.Name):
        return None

    parts.append(current.id)
    parts.reverse()
    return parts


def _extract_target_names(target):
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names = set()
        for elt in target.elts:
            names.update(_extract_target_names(elt))
        return names
    if isinstance(target, ast.Starred):
        return _extract_target_names(target.value)
    return set()


def _extract_args_names(args):
    names = {
        arg.arg
        for arg in (list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs))
    }
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _build_call_finding(file_path, node, expr_text, target_module, member_name):
    return {
        "rule_id": "SKY-L012",
        "kind": "logic",
        "severity": "CRITICAL",
        "type": "call",
        "name": expr_text,
        "simple_name": member_name,
        "value": "phantom",
        "threshold": 0,
        "message": (
            f"Call to '{expr_text}()' resolves to local module '{target_module}', "
            f"but '{member_name}' is not defined or re-exported there. "
            f"AI-generated code often hallucinates security helpers on local modules."
        ),
        "file": str(file_path),
        "basename": file_path.name,
        "line": node.lineno,
        "col": node.col_offset,
        "category": "ai_defect",
        "defect_type": "hallucinated_reference",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
    }


def _build_bare_call_finding(file_path, node, name):
    return {
        "rule_id": "SKY-L012",
        "kind": "logic",
        "severity": "CRITICAL",
        "type": "call",
        "name": name,
        "simple_name": name,
        "value": "phantom",
        "threshold": 0,
        "message": (
            f"Call to '{name}()' is not defined or imported, but it resembles "
            "another local project symbol. AI-generated code often leaves stale "
            "function names after partial refactors."
        ),
        "file": str(file_path),
        "basename": file_path.name,
        "line": node.lineno,
        "col": node.col_offset,
        "category": "ai_defect",
        "defect_type": "hallucinated_reference",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
    }


def _build_decorator_finding(file_path, node, expr_text, target_module, member_name):
    return {
        "rule_id": "SKY-L023",
        "kind": "logic",
        "severity": "CRITICAL",
        "type": "decorator",
        "name": expr_text,
        "simple_name": member_name,
        "value": "phantom",
        "threshold": 0,
        "message": (
            f"Decorator '@{expr_text}' resolves to local module '{target_module}', "
            f"but '{member_name}' is not defined or re-exported there. "
            f"AI-generated code often hallucinates security decorators on local modules."
        ),
        "file": str(file_path),
        "basename": file_path.name,
        "line": node.lineno,
        "col": node.col_offset,
        "category": "ai_defect",
        "defect_type": "hallucinated_reference",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
    }


def _build_reference_finding(
    file_path,
    node,
    expr_text,
    target_module,
    member_name,
):
    return {
        "rule_id": "SKY-L012",
        "kind": "logic",
        "severity": "CRITICAL",
        "type": "module_member",
        "name": expr_text,
        "simple_name": member_name,
        "value": "phantom",
        "threshold": 0,
        "message": (
            f"Reference '{expr_text}' resolves to local module '{target_module}', "
            f"but '{member_name}' is not defined or re-exported there."
        ),
        "file": str(file_path),
        "basename": file_path.name,
        "line": node.lineno,
        "col": node.col_offset,
        "category": "ai_defect",
        "defect_type": "hallucinated_reference",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
    }


def _build_import_finding(file_path, node, target_module, member_name):
    return {
        "rule_id": "SKY-L012",
        "kind": "logic",
        "severity": "CRITICAL",
        "type": "from_import",
        "name": member_name,
        "simple_name": member_name,
        "value": "phantom",
        "threshold": 0,
        "message": (
            f"Import from local module '{target_module}' requests '{member_name}', "
            "but that name is not defined or re-exported there."
        ),
        "file": str(file_path),
        "basename": file_path.name,
        "line": node.lineno,
        "col": node.col_offset,
        "category": "ai_defect",
        "defect_type": "hallucinated_reference",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
    }
