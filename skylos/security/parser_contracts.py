"""Finite dependency attestation for native argparse/operator producers.

This establishes provider behavior, not the origin of actual argv/environment
contents. Callers must separately prove the parser shape and process context.
No scanned module or installed provider is executed to build this proof.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.rules.danger.import_proof import (
    _effects,
    import_environment_is_stable,
    provider_is_unshadowed,
)
from skylos.rules.danger.project_imports import project_import_context

_SCALARS = frozenset(
    {
        "builtins.str",
        "builtins.int",
        "builtins.float",
        "builtins.bool",
        "builtins.ValueError",
        "builtins.TypeError",
        "math.isfinite",
        "argparse.ArgumentTypeError",
    }
)
_ENVIRONMENT = frozenset(
    {
        "os.getenv",
        "os.environ",
        "os.environ.get",
        "os._Environ",
        "collections.abc.Mapping",
        "_collections_abc.Mapping",
        "collections.abc.MutableMapping",
        "_collections_abc.MutableMapping",
    }
)
_DELEGATE_MODULES = frozenset({"argparse", "re", "builtins"})


def _environment_text_projection(tree, effects):
    """Remove only native literal-key value reads from the capability audit.

    The original project AST remains the snapshot authority. Provider/mapping
    writes and whole-object escapes stay in this local audit copy, and the
    mapping/getter dependencies are attested together before accepting it.
    """
    locations = {
        (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        for node in effects.nodes
        if isinstance(node, ast.Subscript)
        and isinstance(node.ctx, ast.Load)
        and isinstance(node.slice, ast.Constant)
        and type(node.slice.value) is str
        and effects.refs(node.value) == {"os.environ"}
        and effects.canonical_reference(node.value)
    }
    if not locations:
        return tree

    class Project(ast.NodeTransformer):
        def visit_Subscript(self, node):
            location = (
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            )
            if location in locations and isinstance(node.ctx, ast.Load):
                return ast.copy_location(
                    ast.Constant(value="native environment text"), node
                )
            return self.generic_visit(node)

    def clone(node):
        if isinstance(node, ast.AST):
            fields = {field: clone(value) for field, value in ast.iter_fields(node)}
            attributes = {
                attribute: getattr(node, attribute)
                for attribute in node._attributes
                if hasattr(node, attribute)
            }
            return type(node)(**fields, **attributes)
        if isinstance(node, list):
            return [clone(item) for item in node]
        return node

    try:
        return Project().visit(clone(tree))
    except (RecursionError, TypeError, ValueError):
        return None


def _audit(effects, names, delegated):
    ancestors = {
        ".".join(name.split(".")[:index])
        for name in names
        for index in range(1, len(name.split(".")) + 1)
    }
    roots = {name.split(".", 1)[0] for name in names}

    def sensitive(name):
        return (
            name in ancestors
            or any(name.startswith(value + ".") for value in names)
            or any(name.startswith(root + ".__") for root in roots)
        )

    # All mutations/escapes of a delegated module prefix are inspected. Native
    # canonical calls remain calls; a literal list of wrapper function names
    # cannot cover mutable re._compiler/argparse action implementations.
    callable_names = set(names)
    for node in effects.nodes:
        if isinstance(node, ast.Call) and effects.canonical_reference(node.func):
            callable_names.update(
                name
                for name in effects.refs(node.func)
                if name.split(".", 1)[0] in delegated
            )
    return effects.stable(
        sensitive,
        key=("parser-dependencies", tuple(sorted(names))),
        callable_names=callable_names,
    )


def native_environment_reader_is_intact(tree, filename, project_root=None):
    """Native literal environment text reads, independent of parser behavior."""
    return native_parser_producer_is_intact(
        "os.environ.__getitem__", tree, filename, project_root
    )


_PARSER = frozenset(
    {
        "argparse.ArgumentParser",
        "argparse._ActionsContainer",
        "argparse._ArgumentGroup",
        "argparse._MutuallyExclusiveGroup",
        "argparse.Namespace",
        "argparse._AttributeHolder",
        "argparse.Action",
        "argparse._StoreAction",
        "argparse._StoreConstAction",
        "argparse._StoreTrueAction",
        "argparse._StoreFalseAction",
        "argparse._AppendAction",
        "argparse._AppendConstAction",
        "argparse._CountAction",
        "argparse._HelpAction",
        "argparse._VersionAction",
        "argparse._SubParsersAction",
        "argparse._ExtendAction",
        "argparse.BooleanOptionalAction",
        "argparse._copy_items",
        "argparse.SUPPRESS",
        "argparse.OPTIONAL",
        "argparse.ZERO_OR_MORE",
        "argparse.ONE_OR_MORE",
        "argparse.REMAINDER",
        "argparse.PARSER",
        "argparse._UNRECOGNIZED_ARGS_ATTR",
        "argparse._sys",
        "argparse._os",
        "argparse._re",
        "sys.argv",
        "builtins.setattr",
        "builtins.getattr",
        "builtins.hasattr",
        "builtins.delattr",
        "builtins.isinstance",
        "builtins.issubclass",
        "builtins.callable",
        "builtins.str",
        "builtins.list",
        "builtins.tuple",
        "builtins.dict",
        "builtins.set",
        "builtins.len",
        "builtins.enumerate",
        "builtins.range",
        "re.compile",
        "re.match",
        "re._compile",
    }
)


def native_parser_producer_is_intact(qualified, tree, filename, project_root=None):
    """Attest one supported producer and the finite dependencies it uses.

    An unchanged ``getenv`` function does not certify its mutable mapping, and
    an unchanged ArgumentParser class does not certify inherited configuration
    or the default Action classes. Unknown producers remain unproved.
    """
    environment = qualified in {
        "os.getenv",
        "os.environ.get",
        "os.environ.__getitem__",
        "os.environ",
    }
    if environment:
        dependencies = _ENVIRONMENT
    elif qualified in {
        "argparse.ArgumentParser",
        "argparse._ActionsContainer.add_argument",
    }:
        dependencies = _PARSER | _DELEGATE_MODULES | {qualified}
    elif qualified in _SCALARS:
        dependencies = frozenset({qualified})
    else:
        return False

    try:
        source_exists = filename is not None and Path(filename).is_file()
        context = (
            project_import_context(tree, filename, project_root)
            if source_exists
            else None
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    if context is None and (source_exists or project_root is not None):
        return False
    entries = context.entries if context is not None else [(filename, tree)]
    cache_key = ("native-parser-producer-v2", tuple(sorted(dependencies)), environment)
    if context is not None and cache_key in context.provider_results:
        return context.provider_results[cache_key] and all(
            (effects := _effects(parsed)) is not None and effects.complete
            for _, parsed in entries
        )

    roots = {name.split(".", 1)[0] for name in dependencies}
    if context is not None and roots & context.modules.keys():
        return False
    if any(not provider_is_unshadowed(root, filename, project_root) for root in roots):
        return False
    names = set(dependencies)
    audited = []
    if context is not None:
        for dependency in dependencies:
            names.update(context.qualified_names(dependency))
    for path, parsed in entries:
        effects = _effects(parsed)
        if effects is None or not effects.complete:
            return False
        audit_tree = (
            _environment_text_projection(parsed, effects) if environment else parsed
        )
        audit_effects = _effects(audit_tree)
        if (
            audit_effects is None
            or not audit_effects.complete
            or not import_environment_is_stable(audit_tree)
        ):
            return False
        generic, global_names = audit_effects.native_generic_dependencies()
        for dependency in generic:
            if not provider_is_unshadowed(dependency, path, project_root):
                return False
            names.update(
                context.qualified_names(dependency)
                if context is not None
                else {dependency}
            )
        if context is not None:
            for local in global_names:
                for module in context.names.get(path, ()):
                    if module:
                        names.add(module + "." + local)
            for (scope, local), references in effects.aliases.items():
                if scope is None and any(
                    reference == dependency or dependency.startswith(reference + ".")
                    for reference in references
                    for dependency in dependencies
                ):
                    names.update(
                        module + "." + local
                        for module in context.names.get(path, ())
                        if module
                    )
        audited.append(audit_effects)
    delegated = roots & _DELEGATE_MODULES
    result = all(_audit(effects, names, delegated) for effects in audited)
    if context is not None:
        context.provider_results[cache_key] = result
    return result
