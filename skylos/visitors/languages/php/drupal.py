"""Drupal classes and methods the framework calls without a PHP reference.

Drupal wires most extension code from outside PHP: the service container
builds the classes named in ``*.services.yml``, routes name controllers and
forms in ``*.routing.yml``, and other YAML files (menu links, permissions,
Drush services) name classes and callbacks the same way. Plugin managers
discover classes under ``src/Plugin/`` and ``src/Entity/`` by their attribute
or docblock annotation, Drush 12+ discovers ``src/Drush/Commands/``, and OOP
hooks are methods (or invokable classes) carrying a ``#[Hook]`` attribute.
Classes in ``src/ProxyClass/`` (generated for lazy services) and
``src/Install/Requirements/`` are loaded by convention, as are
``src/<Module>ServiceProvider.php`` and the ``FooValidator`` next to each
``Foo`` constraint (Symfony's ``validatedBy()`` default). The update system
calls every function of ``*.post_update.php`` and Drush every function of
``*.deploy.php``; ``*.api.php`` files only document hooks.

The rules apply only inside a Drupal extension, a directory holding a
``<name>.info.yml`` file, and read only that extension's own YAML files. The
framework calls these classes through their public surface (``build``,
``submitForm``, plugin interface methods, event callbacks), so their public
methods are roots; private helpers stay live only when one of them calls the
helper.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

_MAX_YAML_BYTES = 1_000_000
_MAX_YAML_FILES = 2_000
_SKIPPED_DIRS = {".git", "node_modules", "vendor"}
_DISCOVERY_DIRS = ("src/Plugin/", "src/Entity/", "src/Drush/Commands/")
_CONVENTION_DIRS = ("src/ProxyClass/", "src/Install/Requirements/")
_ALL_FUNCTIONS_SUFFIXES = (".api.php", ".post_update.php", ".deploy.php")
_HOOK_ATTRIBUTES = {"Hook", "LegacyHook"}
_INFO_SUFFIX = ".info.yml"

# A class in YAML: Drupal\module\Name, optionally ::method (routes, callbacks)
# or :method (controller service notation). Double-quoted YAML doubles the
# backslashes; a leading backslash is allowed.
_YAML_CLASS_RE = re.compile(
    r"\\?(Drupal(?:\\[A-Za-z_][A-Za-z0-9_]*)+)(?:::?([A-Za-z_][A-Za-z0-9_]*))?"
)
_ANNOTATION_RE = re.compile(r"@[A-Z][A-Za-z0-9_\\]*\s*\(")


@lru_cache(maxsize=4096)
def _machine_names(directory: str) -> tuple[str, ...]:
    try:
        return tuple(
            name[: -len(_INFO_SUFFIX)]
            for name in os.listdir(directory)
            if name.endswith(_INFO_SUFFIX)
        )
    except OSError:
        return ()


def _service_provider_names(directory: str) -> set[str]:
    # ContainerBuilder::camelize(): search_api -> SearchApiServiceProvider.
    return {
        "".join(part.capitalize() for part in name.split("_")) + "ServiceProvider"
        for name in _machine_names(directory)
    }


def _is_convention_class(root: str, relative: str, name: str) -> bool:
    if relative.startswith(_CONVENTION_DIRS):
        return True
    if relative == f"src/{name}.php" and name in _service_provider_names(root):
        return True
    constraint = name[: -len("Validator")] if name.endswith("Validator") else ""
    return bool(constraint) and os.path.isfile(
        os.path.join(root, os.path.dirname(relative), f"{constraint}.php")
    )


def _extension_root_and_path(file_path: str) -> tuple[str, str] | None:
    absolute = os.path.abspath(file_path)
    directory = os.path.dirname(absolute)
    while True:
        if _machine_names(directory):
            relative = os.path.relpath(absolute, directory).replace(os.sep, "/")
            return directory, relative
        parent = os.path.dirname(directory)
        if parent == directory:
            return None
        directory = parent


def _yaml_files(root: str):
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = sorted(d for d in subdirectories if d not in _SKIPPED_DIRS)
        yield from (
            os.path.join(directory, name)
            for name in sorted(files)
            if name.endswith(".yml")
        )


def _read_yaml(path: str) -> str:
    try:
        data = Path(path).read_bytes()[
            :_MAX_YAML_BYTES
        ]  # skylos: ignore[SKY-D215] analyzer reads the scanned extension's YAML
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


@lru_cache(maxsize=256)
def _yaml_references(root: str) -> frozenset[str]:
    """Dotted classes, and ``Class.method`` callbacks, the extension's YAML names."""
    names: set[str] = set()
    for count, path in enumerate(_yaml_files(root)):
        if count >= _MAX_YAML_FILES:
            break
        for match in _YAML_CLASS_RE.finditer(_read_yaml(path).replace("\\\\", "\\")):
            dotted = match.group(1).replace("\\", ".")
            names.add(dotted)
            if match.group(2):
                names.add(f"{dotted}.{match.group(2)}")
    return frozenset(names)


def _text(node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _descendants(node, node_type: str):
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == node_type:
            yield current
        else:
            stack.extend(current.children)


def _attribute_names(node, source: bytes) -> set[str]:
    names: set[str] = set()
    for attribute_list in (c for c in node.children if c.type == "attribute_list"):
        for attribute in _descendants(attribute_list, "attribute"):
            name = next(
                (c for c in attribute.children if c.type in {"name", "qualified_name"}),
                None,
            )
            if name is not None:
                names.add(_text(name, source).rpartition("\\")[2])
    return names


def _has_annotation(node, source: bytes) -> bool:
    previous = node.prev_named_sibling
    if previous is None or previous.type != "comment":
        return False
    text = _text(previous, source)
    return text.startswith("/**") and bool(_ANNOTATION_RE.search(text))


def _name_line(node) -> int | None:
    name = next((c for c in node.children if c.type == "name"), None)
    return name.start_point[0] + 1 if name is not None else None


def _hook_method_lines(class_node, source: bytes) -> set[int]:
    body = next((c for c in class_node.children if c.type == "declaration_list"), None)
    methods = (
        (c for c in body.children if c.type == "method_declaration") if body else ()
    )
    return {
        line
        for method in methods
        if _attribute_names(method, source) & _HOOK_ATTRIBUTES
        and (line := _name_line(method)) is not None
    }


def _is_discovered(class_node, source: bytes, relative: str) -> bool:
    """A class a plugin manager, Drush or the hook system finds on its own."""
    attributes = _attribute_names(class_node, source)
    if attributes & _HOOK_ATTRIBUTES:
        return True
    if not relative.startswith(_DISCOVERY_DIRS):
        return False
    return (
        bool(attributes)
        or relative.startswith("src/Drush/")
        or _has_annotation(class_node, source)
    )


def _attribute_root_lines(root_node, source: bytes, relative: str):
    """``(lines of discovered classes, lines of #[Hook] methods)``."""
    classes: set[int] = set()
    hooks: set[int] = set()
    for node in _descendants(root_node, "class_declaration"):
        line = _name_line(node)
        if line is None:
            continue
        methods = _hook_method_lines(node, source)
        hooks |= methods
        if methods or _is_discovered(node, source, relative):
            classes.add(line)
    return classes, hooks


def _root_classes(defs, class_lines, yaml_names, root: str, relative: str):
    """``{qualified name: line}`` of the classes Drupal builds or discovers."""
    return {
        d.name: d.line
        for d in defs
        if d.type == "class"
        and (
            d.line in class_lines
            or d.name in yaml_names
            or _is_convention_class(root, relative, d.simple_name)
        )
    }


def _root_method_lines(defs, classes, yaml_names) -> set[int]:
    """Callbacks the YAML names, and the public methods of root classes."""
    return {
        d.line
        for d in defs
        if d.type == "method"
        and (
            d.name in yaml_names
            or (d.is_exported and d.name.rpartition(".")[0] in classes)
        )
    }


def drupal_entrypoint_lines(file_path: str, defs, root_node, source: bytes) -> set[int]:
    """Lines of the definitions in ``defs`` that Drupal itself calls."""
    located = _extension_root_and_path(file_path)
    if located is None:
        return set()
    root, relative = located
    # Hook documentation, post-update and deploy functions: called by name.
    if relative.endswith(_ALL_FUNCTIONS_SUFFIXES):
        return {d.line for d in defs if d.type == "function"}
    if root_node is None:
        return set()

    yaml_names = _yaml_references(root)
    class_lines, lines = _attribute_root_lines(root_node, source, relative)
    classes = _root_classes(defs, class_lines, yaml_names, root, relative)
    return lines | set(classes.values()) | _root_method_lines(defs, classes, yaml_names)
