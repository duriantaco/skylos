"""Bounded source evidence for optional annotation-coverage advice.

An ordinary public-looking name is not evidence of an API boundary. This
module recognises explicit exports and import-proven interface declarations;
it does not import a project, resolve its dependency graph or infer callbacks
from their names. Supplied contracts apply only to optional coverage advice,
never to an explicit requirement to annotate the implementation itself.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import os
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.quality._overload_groups import _mutated_names, overload_groups
from skylos.rules.quality._receivers import (
    _scope_bindings,
    method_receiver,
    resolve_method_kinds,
)
from skylos.rules.quality._typing import comment_contract, parameters


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_PROVIDERS = {"abc", "typing", "typing_extensions"}
_MAX_STUB_BYTES = 1_000_000


@dataclass(frozen=True)
class AnnotationContractEvidence:
    boundary_ids: frozenset[int]
    supplied_ids: frozenset[int]


def _provider_available(name, project_root, source_reader):
    """Do not treat a local typing.py/abc.py as a standard provider."""
    if not project_root:
        return True
    root = Path(os.path.abspath(project_root))
    for base in (Path(), Path("src")):
        for relative in (base / f"{name}.py", base / name / "__init__.py"):
            if source_reader is not None:
                try:
                    source_reader(relative)
                except FileNotFoundError:
                    continue
                except (OSError, ValueError, UnicodeError):
                    return False
                # None means unavailable in a historical snapshot, not absent.
                return False
            try:
                (root / relative).lstat()
            except FileNotFoundError:
                continue
            except OSError:
                return False
            return False
    return True


def _provider_aliases(module, project_root, source_reader):
    bindings = _scope_bindings(module)
    mutated = _mutated_names(module)
    if "*" in bindings.names or "*" in mutated:
        return {}
    mutated_providers = {
        alias.name
        for statement in module.body
        if isinstance(statement, ast.Import)
        for alias in statement.names
        if (alias.asname or alias.name) in mutated
    }
    aliases = {}
    available = {}
    for statement in module.body:
        if not isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(statement, ast.ImportFrom) and statement.level:
            continue
        for alias in statement.names:
            provider = (
                alias.name if isinstance(statement, ast.Import) else statement.module
            )
            if provider not in _PROVIDERS:
                continue
            if provider in mutated_providers:
                continue
            if provider not in available:
                available[provider] = _provider_available(
                    provider, project_root, source_reader
                )
            name = alias.asname or alias.name
            if (
                available[provider]
                and bindings.counts[name] == 1
                and name not in mutated
            ):
                aliases[name] = (
                    provider
                    if isinstance(statement, ast.Import)
                    else f"{provider}.{alias.name}",
                    statement.lineno,
                )
    return aliases


def _qualified(expression, aliases):
    if isinstance(expression, ast.Name):
        binding = aliases.get(expression.id)
        if binding and binding[1] < expression.lineno:
            return binding[0]
    if isinstance(expression, ast.Attribute):
        owner = _qualified(expression.value, aliases)
        return f"{owner}.{expression.attr}" if owner else None
    if isinstance(expression, ast.Subscript):
        return _qualified(expression.value, aliases)
    return None


def _top_definitions(module):
    """Only direct, stable definitions can establish an exported surface."""
    bindings = _scope_bindings(module)
    mutated = _mutated_names(module)
    if "*" in bindings.names or "*" in mutated:
        return {}
    candidates = {}
    for statement in module.body:
        if isinstance(statement, (*_FUNCTIONS, ast.ClassDef)):
            candidates.setdefault(statement.name, []).append(statement)
    return {
        name: definitions
        for name, definitions in candidates.items()
        if bindings.counts[name] == len(definitions) and name not in mutated
    }


def _complete(function, lines, receiver=None):
    commented, return_comment = comment_contract(function, lines, receiver)
    return (function.returns is not None or return_comment) and all(
        argument.arg == receiver
        or argument.annotation is not None
        or argument.arg in commented
        for argument in parameters(function)
    )


def _binding_decorators(function):
    return tuple(
        decorator.id
        for decorator in function.decorator_list
        if isinstance(decorator, ast.Name)
        and decorator.id in {"classmethod", "staticmethod"}
    )


def _parameter_shape(function, receiver=None):
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaulted = {
        argument.arg
        for argument in positional[-len(args.defaults) :]
    } if args.defaults else set()
    defaulted.update(
        argument.arg
        for argument, value in zip(args.kwonlyargs, args.kw_defaults)
        if value is not None
    )
    kinds = {
        id(argument): kind
        for kind, arguments in (
            ("posonly", args.posonlyargs),
            ("positional", args.args),
            ("keyword", args.kwonlyargs),
            ("vararg", [args.vararg] if args.vararg else []),
            ("kwarg", [args.kwarg] if args.kwarg else []),
        )
        for argument in arguments
    }
    return tuple(
        (kinds[id(argument)], argument.arg, argument.arg in defaulted)
        for argument in parameters(function)
        if argument.arg != receiver
    )


def _direct_functions(module):
    result = {}
    for name, definitions in _top_definitions(module).items():
        if len(definitions) != 1:
            continue
        definition = definitions[0]
        if isinstance(definition, _FUNCTIONS):
            result[(name,)] = definition
        else:
            # A decorator may replace the class and its entire callable
            # surface. The original methods cannot establish its contract.
            if definition.decorator_list:
                continue
            bindings = _scope_bindings(definition)
            for method in definition.body:
                if isinstance(method, _FUNCTIONS) and bindings.counts[method.name] == 1:
                    result[(name, method.name)] = method
    return result


def _stub_source(filename, project_root, source_reader):
    if not filename or not project_root or str(filename).endswith(".pyi"):
        return None
    root = Path(os.path.abspath(project_root))
    filename = Path(filename)
    path = filename if filename.is_absolute() else root / filename
    try:
        relative = Path(os.path.abspath(path)).relative_to(root).with_suffix(".pyi")
    except ValueError:
        return None
    if source_reader is None:
        return read_project_text_no_symlink(
            root, root / relative, max_bytes=_MAX_STUB_BYTES
        )
    try:
        text = source_reader(relative)
    except (OSError, ValueError, UnicodeError):
        return None
    if not isinstance(text, str) or len(text.encode("utf-8")) > _MAX_STUB_BYTES:
        return None
    return text


def annotation_contract_evidence(
    module,
    *,
    filename="",
    source_lines=(),
    method_kinds=None,
    project_root=None,
    source_reader=None,
    exported_names=None,
):
    """Return proven boundary IDs and optional-coverage contract exemptions.

    ``exported_names`` must come from a complete, mutation-checked literal
    ``__all__`` parser; None establishes no export evidence. This helper does
    not infer an API merely because a function lacks a leading underscore.
    Sidecar stubs are deliberately limited to exact direct function/method
    signatures; imported/re-exported stubs and overload sidecars stay unknown.
    """
    if method_kinds is None:
        method_kinds = resolve_method_kinds(
            module,
            filename=filename,
            project_root=project_root,
            source_reader=source_reader,
        )
    aliases = _provider_aliases(module, project_root, source_reader)
    mutated = _mutated_names(module)
    owners = {
        id(method): cls
        for cls in ast.walk(module)
        if isinstance(cls, ast.ClassDef)
        for method in cls.body
        if isinstance(method, _FUNCTIONS)
    }
    overload_receivers = {}

    def receiver(function):
        if id(function) in overload_receivers:
            return overload_receivers[id(function)]
        if id(function) not in owners:
            return None
        return method_receiver(function, kinds=method_kinds)

    groups = overload_groups(module, filename=filename)
    supplied = set()
    for group in groups:
        if group.implementation is None or len(group.signatures) < 2:
            continue
        if "*" in mutated or group.implementation.name in mutated:
            continue
        if id(group.implementation) in owners:
            owner = owners[id(group.implementation)]
            if owner.decorator_list or owner.name in mutated:
                continue
            implementation_kind = method_kinds.get(group.implementation)
            if implementation_kind not in {"instance", "class", "static"}:
                continue
            if any(
                _binding_decorators(signature)
                != _binding_decorators(group.implementation)
                for signature in group.signatures
            ):
                continue
            overload_receivers.update(
                (
                    id(signature),
                    method_receiver(signature, kinds={signature: implementation_kind}),
                )
                for signature in group.signatures
            )
        if all(
            any(
                _qualified(decorator, aliases)
                in {"typing.overload", "typing_extensions.overload"}
                for decorator in signature.decorator_list
            )
            and _complete(signature, source_lines, receiver(signature))
            for signature in group.signatures
        ):
            supplied.update(id(member) for member in group.members)

    boundaries = set()
    for name, definitions in _top_definitions(module).items():
        if len(definitions) == 1 and isinstance(definitions[0], ast.ClassDef):
            cls = definitions[0]
            # Even a Protocol or abstract declaration can be replaced by an
            # unknown class decorator. No decorator-name exemption is guessed.
            if cls.decorator_list:
                continue
            interface = any(
                _qualified(base, aliases)
                in {"typing.Protocol", "typing_extensions.Protocol"}
                for base in cls.bases
            )
            class_aliases = {
                key: value
                for key, value in aliases.items()
                if key not in _scope_bindings(cls).names
            }
            class_bindings = _scope_bindings(cls)
            methods_by_name = {}
            for method in cls.body:
                if isinstance(method, _FUNCTIONS):
                    methods_by_name.setdefault(method.name, []).append(method)
            for method in cls.body:
                if not isinstance(method, _FUNCTIONS) or method.name.startswith("_"):
                    continue
                definitions = methods_by_name[method.name]
                if class_bindings.counts[method.name] != len(definitions) or (
                    len(definitions) > 1 and not any(
                        {id(definition) for definition in definitions}
                        == {id(member) for member in group.members}
                        for group in groups
                    )
                ):
                    continue
                abstract = any(
                    _qualified(decorator, class_aliases) == "abc.abstractmethod"
                    for decorator in method.decorator_list
                )
                if (
                    interface or abstract or name in (exported_names or ())
                ) and method_kinds.get(method) in {"instance", "class", "static"}:
                    boundaries.add(id(method))
        elif name in (exported_names or ()) and (
            len(definitions) == 1
            or any(
                {id(definition) for definition in definitions}
                == {id(member) for member in group.members}
                for group in groups
            )
        ):
            for function in definitions:
                if isinstance(function, _FUNCTIONS) and (
                    not function.decorator_list or id(function) in supplied
                ):
                    boundaries.add(id(function))

    stub_text = _stub_source(filename, project_root, source_reader)
    if stub_text is not None:
        try:
            stub = ast.parse(stub_text, type_comments=True)
        except (SyntaxError, ValueError, RecursionError):
            stub = None
        if stub is not None:
            stub_kinds = resolve_method_kinds(
                stub,
                filename=str(Path(filename).with_suffix(".pyi")),
                project_root=project_root,
                source_reader=source_reader,
            )
            declarations = _direct_functions(stub)
            for key, function in _direct_functions(module).items():
                declaration = declarations.get(key)
                if declaration is None or type(function) is not type(declaration):
                    continue
                if len(key) == 1 and (function.decorator_list or declaration.decorator_list):
                    continue
                if len(key) == 2 and (
                    method_kinds.get(function) not in {"instance", "class", "static"}
                    or stub_kinds.get(declaration) not in {"instance", "class", "static"}
                    or method_kinds.get(function) != stub_kinds.get(declaration)
                ):
                    continue
                stub_receiver = (
                    method_receiver(declaration, kinds=stub_kinds)
                    if len(key) == 2 else None
                )
                if _complete(
                    declaration, stub_text.splitlines(keepends=True), stub_receiver
                ) and _parameter_shape(function, receiver(function)) == _parameter_shape(
                    declaration, stub_receiver
                ):
                    supplied.add(id(function))

    return AnnotationContractEvidence(frozenset(boundaries), frozenset(supplied))
