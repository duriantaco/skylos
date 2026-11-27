"""Link a request handler to an explicitly resolved reqwest helper in its crate."""

from collections import defaultdict
from dataclasses import dataclass

from . import reqwest
from .danger import (
    _INERT_ATTRIBUTES,
    _dedupe_findings,
    _ScopeAttributes,
    analyze_security_flow,
    is_async_function,
)


def _module_api(path):
    return "::".join(("@crate", *path))


def _reqwest_return(value):
    # A helper can return a future with effects deferred until its caller polls it.
    while value is not None and value.kind == "rust_helper_future":
        if any(not reqwest.has_dispatch(via) for via, _ in value.pending_http):
            return False
        value = value.awaited
    return True


@dataclass
class SiblingBindings:
    roots: dict
    helpers: dict


def _ordinary_items(root):
    """Unconditional source items with no attribute that can replace the item."""
    reader = _ScopeAttributes(root.text)
    for node, conditional, _, _ in reader.scope_entries(root):
        if conditional:
            continue
        prev = node.prev_named_sibling
        while prev and prev.type in {"attribute_item", "line_comment", "block_comment"}:
            if prev.type == "attribute_item":
                attr = next(iter(prev.named_children), None)
                name = (
                    next(iter(attr.named_children), None) if attr is not None else None
                )
                if reader.text(name) not in _INERT_ATTRIBUTES:
                    break
            prev = prev.prev_named_sibling
        else:
            yield node


def _conditional_root(root):
    for child in root.named_children:
        if child.type == "inner_attribute_item" and child.named_children:
            attr = child.named_children[0]
            if attr.named_children and attr.named_children[0].text in {
                b"cfg_attr",
                b"cfg",
            }:
                return True
    return False


def _module_bindings(project, selected):
    """Use only ordinary mod declarations and already scanned Cargo sources."""
    roots = {}
    exports = {}
    pending = [crate.root for crate in project.crates if crate.kind in {"lib", "bin"}]
    while pending:
        module = pending.pop()
        if (
            module is None
            or project.files[module.file] not in selected
            or module in roots
        ):
            continue
        root = project.source_tree(module.file)
        if (
            root is None
            or root.has_error
            or module.opaque
            or _conditional_root(root)
            or len(project.modules_by_file[module.file]) != 1
        ):
            continue
        bases = {"crate": "@crate", "self": _module_api(module.path)}
        if module.parent:
            bases["super"] = _module_api(module.parent.path)
        roots[module] = bases
        may_use_reqwest = b"reqwest" in root.text
        for node in _ordinary_items(root):
            if node.type not in {"function_item", "mod_item"}:
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            name = name_node.text.decode()
            items = module.items.get(name, ())
            if len(items) != 1:
                continue
            item = items[0]
            if node.type == "mod_item" and node.child_by_field_name("body") is None:
                target = item.target
                possible = {
                    module.directory / f"{name}.rs",
                    module.directory / name / "mod.rs",
                }
                if target is not None and {
                    p for p in possible if p in project.files
                } == {target.file}:
                    bases[name] = _module_api(target.path)
                    pending.append(target)
            elif node.type == "function_item" and may_use_reqwest:
                visibility = next(
                    (c for c in node.named_children if c.type == "visibility_modifier"),
                    None,
                )
                if visibility and b"".join(visibility.text.split()) in {
                    b"pub",
                    b"pub(crate)",
                    b"pub(super)",
                }:
                    exports[item] = node
    return roots, exports


def sibling_http_findings(project, selected):
    if project is None or not project.complete:
        return []
    roots, exports = _module_bindings(project, selected)
    if not exports:
        return []

    names = {item.name for item in exports}
    targets = defaultdict(set)
    references = (
        (
            (item.module, item.path, None)
            for item in project.uses
            if item.kind == "use" and not item.cfg
        ),
        ((ref.module, ref.segments, ref.local) for ref in project.path_refs),
    )
    for group in references:
        for caller, segments, local in group:
            if caller not in roots or not segments or segments[-1] not in names:
                continue
            resolved = project.resolve(caller, segments, local=local)
            if len(resolved) != 1 or resolved[0][0] != "item":
                continue
            target = resolved[0][1]
            if (
                target in exports
                and caller.file != target.file
                and target.module.parent in (caller, caller.parent)
                and caller.crate is target.module.crate
            ):
                targets[caller].add(target)

    summaries = {}
    for target in set().union(*targets.values()):
        if target.file not in summaries:
            tree = project.source_tree(target.file)
            flow = analyze_security_flow(
                tree,
                project.files[target.file],
                tree.text,
                siblings=SiblingBindings({}, {}),
            )
            summaries[target.file] = flow.http_returns, flow.summaries

    findings = []
    for caller, items in targets.items():
        helpers = {}
        for item in items:
            key = exports[item].start_byte
            returns, effects = summaries[item.file]
            sinks = {
                i: {
                    (rule, via)
                    for rule, via in entries
                    if rule == "SKY-D216" and reqwest.has_dispatch(via)
                }
                for i, entries in effects.get(key, {}).items()
            }
            returned = returns.get(key)
            if not _reqwest_return(returned):
                returned = None
            if not any(sinks.values()) and returned is None:
                continue
            path = (*item.module.path, item.name)
            helpers[_module_api(path)] = (
                "::".join(path),
                key,
                sinks,
                returned,
                is_async_function(exports[item]),
            )
        if helpers:
            tree = project.source_tree(caller.file)
            flow = analyze_security_flow(
                tree,
                project.files[caller.file],
                tree.text,
                siblings=SiblingBindings(roots[caller], helpers),
            )
            findings.extend(
                row for row in flow.findings if row["rule_id"] == "SKY-D216"
            )
    return _dedupe_findings(findings)
