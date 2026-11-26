"""Static references from Rust source pasted by the built-in include! macro."""

import json
import re
from collections import defaultdict
from pathlib import Path

from skylos.core.file_discovery import (
    find_git_root,
    list_git_visible_files,
    should_exclude_path,
)
from skylos.core.safe_cache_io import read_project_text_no_symlink

from .core import RustCore

_MAX_INCLUDES = 128
_MAX_FILE_BYTES = 256_000
_MAX_TOTAL_BYTES = 2_000_000
_MAX_DEPTH = 12
UNRESOLVED_METHOD = "Rust include! method receiver could not be resolved"
UNRESOLVED_INCLUDE = "Rust include! source could not be resolved within the scan"


def _literal_path(tree):
    args = [n for n in tree.named_children if not n.type.endswith("comment")]
    if len(args) != 1:
        return None
    literal = args[0]
    value = literal.text.decode("utf-8")
    if literal.type == "raw_string_literal":
        match = re.fullmatch(r'r(#*)"(.*)"\1', value, re.DOTALL)
        return match[2] if match else None
    if literal.type == "string_literal":
        try:
            return json.loads(value)
        except ValueError:  # Non-JSON Rust escapes require compiler interpretation.
            return None
    return None


def _local_path(root, source, literal):
    if not literal or "\x00" in literal:
        return None
    path = Path(literal)
    base = source.parent
    parts = list(path.parts)
    # Leading parent components step out of the already admitted source's
    # directory. Never collapse an unverified directory followed by '..'.
    while parts and parts[0] == "..":
        base = base.parent
        parts.pop(0)
    if ".." in parts:
        return None
    path = base.joinpath(*parts)
    if not path.is_relative_to(root) or any(
        part.casefold() == ".git" for part in path.relative_to(root).parts
    ):
        return None
    return path


def _sites(node, module):
    pending = [(node, module)]
    while pending:
        current, scope = pending.pop()
        if current.type == "mod_item":
            name = current.child_by_field_name("name")
            if name is not None:
                for item in scope.items.get(name.text.decode("utf-8"), ()):
                    if item.kind == "mod" and item.target is not None:
                        scope = item.target
                        break
        if current.type == "macro_invocation":
            name = current.child_by_field_name("macro")
            macro = name.text.replace(b" ", b"") if name is not None else b""
            if macro in {
                b"include",
                b"std::include",
                b"core::include",
                b"::std::include",
                b"::core::include",
            }:
                # A user-defined macro may have the same name.
                if macro == b"include" and any(
                    i.kind == "macro" for i in scope.items.get("include", ())
                ):
                    continue
                tree = next(
                    (n for n in current.named_children if n.type == "token_tree"), None
                )
                yield scope, _literal_path(tree) if tree is not None else None
        elif current.type == "token_tree":
            # Nested macros in another macro's arguments are token trees, not
            # ordinary macro_invocation nodes.
            tokens = [
                child
                for child in current.children
                if not child.type.endswith("comment")
            ]
            for index, token in enumerate(tokens):
                if token.type != "identifier" or token.text != b"include":
                    continue
                if index and tokens[index - 1].type == "::":
                    if index < 2 or tokens[index - 2].text not in {b"std", b"core"}:
                        continue
                elif any(
                    item.kind == "macro" for item in scope.items.get("include", ())
                ):
                    continue
                args = tokens[index + 1 : index + 3]
                if (
                    len(args) == 2
                    and args[0].type == "!"
                    and args[1].type == "token_tree"
                ):
                    yield scope, _literal_path(args[1])
        pending.extend((child, scope) for child in current.named_children)


def _fragment(source):
    # Use the root namespace: a fragment's filename does not name a Rust module.
    visitor = RustCore("src/main.rs", source)
    if visitor.root_node.has_error:
        # An expression such as include!("value.in") need not be a complete item.
        visitor = RustCore(
            "src/main.rs", b"fn __skylos_fragment() { let _ = " + source + b"; }"
        )
    return None if visitor.root_node.has_error else visitor


def _references(visitor, project, methods, opaque):
    """Read paths in code, ignoring declaration names, bindings and string text."""
    pending = [visitor.root_node]
    while pending:
        node = pending.pop()
        if node.type in {"mod_item", "macro_definition"}:
            # Declarations pasted by include! are absent from RustProject's
            # module and macro tables. Resolving children in the surrounding
            # module would give an incorrect meaning to `self` and `super`.
            opaque.add(node.type)
            continue
        if node.type in {"scoped_identifier", "scoped_type_identifier"}:
            segments = project._segments(visitor.source, node)
            if segments:
                yield segments
                continue
        elif node.type == "identifier":
            if visitor._is_reference_identifier(
                node
            ) and not visitor._is_local_value_reference(node):
                yield (node.text.decode("utf-8").removeprefix("r#"),)
        elif node.type == "type_identifier" and not visitor._is_definition_name(node):
            yield (node.text.decode("utf-8"),)
        elif node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is not None and callee.type == "generic_function":
                callee = callee.child_by_field_name("function")
            if callee is not None and callee.type == "field_expression":
                receiver = callee.child_by_field_name("value")
                member = callee.child_by_field_name("field")
                if receiver is not None and member is not None:
                    owner = visitor._receiver_type(receiver, None)
                    if (
                        owner is None
                        and receiver.type == "identifier"
                        and not visitor._is_local_value_reference(receiver)
                    ):
                        owner = receiver.text.decode("utf-8")
                    methods.add((owner, member.text.decode("utf-8")))
        elif node.type == "use_declaration":
            for _name, path, glob in project._use_leaves(
                visitor.source, node.child_by_field_name("argument")
            ):
                if glob:
                    opaque.add("use_glob")
                yield path
            continue
        pending.extend(node.named_children)


def _credit_fragment(liveness, module, visitor, uncertain_methods):
    project = liveness.project
    methods = set()
    used = set()
    items = set()
    opaque = set()

    def collect(target):
        if target[0] == "item":
            items.add(target[1])
        elif target[0] == "member":
            items.update(project.methods_of(target[1], target[2]))

    for segments in set(_references(visitor, project, methods, opaque)):
        for target in project.resolve(module, segments, used):
            collect(target)
    for owner, name in methods:
        matches = set()
        if owner:
            for target in project.resolve(module, (*owner.split("."), name), used):
                if target[0] == "member":
                    matches.update(project.methods_of(target[1], target[2]))
        if matches:
            items.update(matches)
        else:
            uncertain_methods[module.crate].add(name)
    for item in items | used:
        for definition in liveness.definitions_of(item):
            # This source is outside the ordinary visitor's caller graph. An
            # independent edge must survive even if a local cycle already
            # contributed one or more references.
            definition.references += 1
    return not opaque


def apply_include_liveness(liveness, exclude_folders):
    project = liveness.project
    root = project.root.resolve()
    # One module lookup per literal include site, only in files that mention include.
    pending = []
    uncertain = set()
    uncertain_methods = defaultdict(set)

    def enqueue(module, path, literal, ancestors):
        if len(pending) < _MAX_INCLUDES:
            pending.append((module, path, literal, ancestors))
        else:
            uncertain.add(module.crate)

    for path, modules in project.modules_by_file.items():
        parsed = project._parse(path)
        if parsed is None or b"include" not in parsed[0]:
            continue
        for module in modules:
            for scope, literal in _sites(parsed[1], module):
                enqueue(scope, path, literal, ())
    if not pending and not uncertain:
        return

    visible_paths = list_git_visible_files(root)
    visible = set(visible_paths) if visible_paths is not None else None
    if visible is None and find_git_root(root) is not None:
        # A failed Git listing cannot authorize reading an ignored source.
        visible = set()
    cache = {}
    visited = set()
    total_bytes = 0
    while pending:
        module, source, literal, ancestors = pending.pop()
        path = _local_path(root, source, literal)
        if path is None or len(ancestors) >= _MAX_DEPTH or path in ancestors:
            uncertain.add(module.crate)
            continue
        site = (module, path)
        if site in visited:
            continue
        if len(visited) >= _MAX_INCLUDES:
            uncertain.add(module.crate)
            continue
        visited.add(site)
        if path not in cache:
            text = None
            remaining = min(_MAX_FILE_BYTES, _MAX_TOTAL_BYTES - total_bytes)
            if (
                remaining > 0
                and (visible is None or path in visible)
                and not should_exclude_path(path, root, exclude_folders)
            ):
                text = read_project_text_no_symlink(root, path, max_bytes=remaining)
            visitor = None
            if text is not None:
                data = text.encode("utf-8")
                total_bytes += len(data)
                visitor = _fragment(data)
            cache[path] = visitor
        visitor = cache[path]
        if visitor is None:
            uncertain.add(module.crate)
            continue
        try:
            if not _credit_fragment(liveness, module, visitor, uncertain_methods):
                uncertain.add(module.crate)
        except RecursionError:
            # The grammar permits deeper nested paths and expressions than
            # the bounded Python resolver can follow.
            uncertain.add(module.crate)
            continue
        if b"include" in visitor.source:
            for scope, nested in _sites(visitor.root_node, module):
                enqueue(scope, path, nested, (*ancestors, path))

    # Missing generated source can reference other modules in the same crate.
    # Expose the uncertainty in the report without inventing a caller.
    if uncertain or uncertain_methods:
        for (file, _line, name), definitions in liveness.by_location.items():
            crates = {module.crate for module in project.modules_by_file.get(file, ())}
            for definition in definitions:
                if crates & uncertain:
                    reason = UNRESOLVED_INCLUDE
                elif definition.type == "method" and any(
                    name in uncertain_methods.get(c, ()) for c in crates
                ):
                    reason = UNRESOLVED_METHOD
                else:
                    continue
                if reason not in definition.why_confidence_reduced:
                    definition.why_confidence_reduced.append(reason)
