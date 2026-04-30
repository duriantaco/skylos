from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from skylos.rules.vibe_dictionary import DEFAULT_VIBE_DICTIONARY


@dataclass
class _ScopeInfo:
    shadowed_names: set[str]
    local_imports: dict[str, list[tuple[int, str]]]


def scan_repo_phantom_security_references(
    project_root, py_files, target_files=None, vibe_dictionary=None
):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    root = Path(project_root).resolve()
    files = [Path(f).resolve() for f in py_files if Path(f).suffix == ".py"]
    target_paths = {
        Path(f).resolve() for f in (target_files or files) if Path(f).suffix == ".py"
    }

    module_to_file = {}
    file_to_module = {}
    module_members = {}
    module_alias_exports = {}
    dynamic_modules = set()
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
    if not local_modules:
        return []

    def _store_module_facts(module_name, tree):
        members, has_dynamic_getattr, exported_modules = _collect_module_facts(
            tree, module_name, local_modules
        )
        module_members[module_name] = members
        module_alias_exports[module_name] = {
            alias: target
            for alias, target in exported_modules.items()
            if target in local_modules
        }
        if has_dynamic_getattr:
            dynamic_modules.add(module_name)

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
            tree = ast.parse(file_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            parse_failures.add(module_name)
            return False

        _store_module_facts(module_name, tree)
        return True

    findings = []

    for file_path, current_module in file_to_module.items():
        if target_paths and file_path not in target_paths:
            continue
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue

        _store_module_facts(current_module, tree)
        parent_map = _build_parent_map(tree)
        scope_infos = _build_scope_infos(tree, current_module, local_modules)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                resolved = _resolve_local_module_member(
                    expr=node.func,
                    node=node,
                    tree=tree,
                    parent_map=parent_map,
                    scope_infos=scope_infos,
                    module_alias_exports=module_alias_exports,
                    local_modules=local_modules,
                    ensure_module_loaded=_ensure_module_loaded,
                )
                if not resolved:
                    continue

                target_module, member_name, expr_text = resolved
                if member_name not in vibe_dictionary.phantom_security_names:
                    continue
                if not _ensure_module_loaded(target_module):
                    continue
                if target_module in dynamic_modules:
                    continue
                if member_name in module_members.get(target_module, set()):
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
                deco_target = deco.func if isinstance(deco, ast.Call) else deco
                resolved = _resolve_local_module_member(
                    expr=deco_target,
                    node=deco_target,
                    tree=tree,
                    parent_map=parent_map,
                    scope_infos=scope_infos,
                    module_alias_exports=module_alias_exports,
                    local_modules=local_modules,
                    ensure_module_loaded=_ensure_module_loaded,
                )
                if not resolved:
                    continue

                target_module, member_name, expr_text = resolved
                if member_name not in vibe_dictionary.phantom_security_decorators:
                    continue
                if not _ensure_module_loaded(target_module):
                    continue
                if target_module in dynamic_modules:
                    continue
                if member_name in module_members.get(target_module, set()):
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


def _module_name(root: Path, file_path: Path) -> str:
    parts = list(file_path.relative_to(root).parts)

    if "src" in parts:
        src_idx = parts.index("src")
        src_path = root / "/".join(parts[: src_idx + 1])
        if not (src_path / "__init__.py").exists():
            parts = parts[src_idx + 1 :]

    if not parts:
        return ""

    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _collect_module_facts(tree, current_module, local_modules):
    members = set()
    exported_modules = {}
    has_dynamic_getattr = False

    if not isinstance(tree, ast.Module):
        return members, has_dynamic_getattr, exported_modules

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            members.add(stmt.name)
            if stmt.name == "__getattr__":
                has_dynamic_getattr = True
        elif isinstance(stmt, ast.ClassDef):
            members.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                members.update(_extract_target_names(target))
        elif isinstance(stmt, ast.AnnAssign):
            members.update(_extract_target_names(stmt.target))
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                members.add(bound_name)
                if alias.asname and alias.name in local_modules:
                    exported_modules[bound_name] = alias.name
                elif not alias.asname:
                    head = alias.name.split(".", 1)[0]
                    if head in local_modules:
                        exported_modules[head] = head
        elif isinstance(stmt, ast.ImportFrom):
            base = _resolve_import_from_base(current_module, stmt)
            for alias in stmt.names:
                if alias.name == "*":
                    if base in local_modules:
                        has_dynamic_getattr = True
                    continue
                bound_name = alias.asname or alias.name
                members.add(bound_name)
                full_name = f"{base}.{alias.name}" if base else alias.name
                if full_name in local_modules:
                    exported_modules[bound_name] = full_name

    return members, has_dynamic_getattr, exported_modules


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
    local_imports = defaultdict(list)

    if isinstance(scope_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        shadowed.update(_extract_args_names(scope_node.args))

    class ScopeCollector(ast.NodeVisitor):
        def generic_visit(self, node):
            for child in ast.iter_child_nodes(node):
                self.visit(child)

        def visit_Import(self, node):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                full_name = alias.name if alias.asname else alias.name.split(".", 1)[0]
                if full_name in local_modules:
                    local_imports[bound_name].append((node.lineno, full_name))

        def visit_ImportFrom(self, node):
            base = _resolve_import_from_base(current_module, node)
            for alias in node.names:
                if alias.name == "*":
                    continue
                full_name = f"{base}.{alias.name}" if base else alias.name
                if full_name in local_modules:
                    local_imports[alias.asname or alias.name].append(
                        (node.lineno, full_name)
                    )

        def visit_Assign(self, node):
            for target in node.targets:
                shadowed.update(_extract_target_names(target))
            self.generic_visit(node.value)

        def visit_AnnAssign(self, node):
            shadowed.update(_extract_target_names(node.target))
            if node.value:
                self.generic_visit(node.value)

        def visit_AugAssign(self, node):
            shadowed.update(_extract_target_names(node.target))
            self.generic_visit(node.value)

        def visit_NamedExpr(self, node):
            shadowed.update(_extract_target_names(node.target))
            self.generic_visit(node.value)

        def visit_For(self, node):
            shadowed.update(_extract_target_names(node.target))
            self.generic_visit(node.iter)
            for stmt in node.body:
                self.visit(stmt)
            for stmt in node.orelse:
                self.visit(stmt)

        visit_AsyncFor = visit_For

        def visit_With(self, node):
            for item in node.items:
                if item.optional_vars is not None:
                    shadowed.update(_extract_target_names(item.optional_vars))
                self.visit(item.context_expr)
            for stmt in node.body:
                self.visit(stmt)

        visit_AsyncWith = visit_With

        def visit_ExceptHandler(self, node):
            if node.name:
                shadowed.add(node.name)
            if node.type:
                self.visit(node.type)
            for stmt in node.body:
                self.visit(stmt)

        def visit_FunctionDef(self, node):
            shadowed.add(node.name)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            shadowed.add(node.name)

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
        local_imports={k: sorted(v) for k, v in local_imports.items()},
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


def _resolve_import_from_base(current_module, node):
    module = node.module or ""
    cur_pkg = (
        current_module.rsplit(".", 1)[0] if "." in current_module else current_module
    )

    if node.level and node.level > 0:
        parts = cur_pkg.split(".") if cur_pkg else []
        up = node.level - 1

        if up > len(parts):
            base = ""
        else:
            base = ".".join(parts[: len(parts) - up])

        if module:
            base = f"{base}.{module}" if base else module
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
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
    }
