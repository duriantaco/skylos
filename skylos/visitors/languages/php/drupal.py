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
``*.deploy.php``; ``*.api.php`` files only document hooks. In the procedural
files (``.module``, ``.install``, ``.inc``, ``.theme``, ``.profile``,
``.engine``) the hook system calls functions by name: every function named
after one of the extension's machine names (``mymodule_form_alter``,
``mymodule_update_10001``) or ``template_preprocess_*`` is a root. Functions
starting with an underscore are private helpers by convention, so they still
need a caller.

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

import yaml

from .core import PhpCore

_MAX_YAML_BYTES = 1_000_000
_MAX_YAML_FILES = 2_000
_SKIPPED_DIRS = {".git", "node_modules", "vendor"}
_DISCOVERY_DIRS = ("src/Plugin/", "src/Entity/", "src/Drush/Commands/")
_CONVENTION_DIRS = ("src/ProxyClass/", "src/Install/Requirements/")
_ALL_FUNCTIONS_SUFFIXES = (".api.php", ".post_update.php", ".deploy.php")
_HOOK_ATTRIBUTES = {"Hook", "LegacyHook"}
_PROCEDURAL_SUFFIXES = (".module", ".install", ".inc", ".theme", ".profile", ".engine")
_INFO_SUFFIX = ".info.yml"

# A class in YAML: Drupal\module\Name, optionally ::method (routes, callbacks)
# or :method (controller service notation). Double-quoted YAML doubles the
# backslashes; a leading backslash is allowed.
_YAML_CLASS_RE = re.compile(
    r"\\?(Drupal(?:\\[A-Za-z_][A-Za-z0-9_]*)+)(?:::?([A-Za-z_][A-Za-z0-9_]*))?"
)
_ANNOTATION_RE = re.compile(r"@([A-Z\\][A-Za-z0-9_\\]*)\s*\(")
_PLUGIN_METADATA_BASES = {
    "Drupal.Component.Plugin.Attribute.AttributeBase",
    "Drupal.Component.Plugin.Attribute.AttributeInterface",
    "Drupal.Component.Plugin.Attribute.Plugin",
    "Drupal.Component.Plugin.Attribute.PluginID",
    "Drupal.Component.Annotation.AnnotationInterface",
    "Drupal.Component.Annotation.Plugin",
}


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
    constraint = ""
    if name.endswith("Validator"):
        constraint = name[: -len("Validator")]
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
        with (
            open(path, "rb") as handle
        ):  # skylos: ignore[SKY-D215] analyzer reads the scanned extension's metadata
            data = handle.read(_MAX_YAML_BYTES + 1)
    except OSError:
        return ""
    if len(data) > _MAX_YAML_BYTES:
        return ""
    return data.decode("utf-8", errors="replace")


def _yaml_scalars(text: str):
    # Compose nodes rather than constructing Python objects. A visited set
    # bounds recursive aliases and avoids expanding aliases into a large tree.
    try:
        document = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError):
        return
    pending = []
    if document is not None:
        pending.append(document)
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.ScalarNode) and node.tag == "tag:yaml.org,2002:str":
            yield node.value
        elif isinstance(node, yaml.MappingNode):
            pending.extend(child for pair in node.value for child in pair)
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)


@lru_cache(maxsize=256)
def _yaml_references(root: str) -> frozenset[str]:
    """Dotted classes, and ``Class.method`` callbacks, the extension's YAML names."""
    names: set[str] = set()
    for count, path in enumerate(_yaml_files(root)):
        if count >= _MAX_YAML_FILES:
            break
        for value in _yaml_scalars(_read_yaml(path)):
            match = _YAML_CLASS_RE.fullmatch(value.strip())
            if match is None:
                continue
            dotted = match.group(1).replace("\\", ".")
            names.add(dotted)
            if match.group(2):
                names.add(f"{dotted}.{match.group(2)}")
    return frozenset(names)


def clear_drupal_cache() -> None:
    """Discard project metadata between analyzer runs."""
    _machine_names.cache_clear()
    _yaml_references.cache_clear()
    _local_metadata_classes.cache_clear()


@lru_cache(maxsize=2048)
def _local_metadata_classes(path: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Immutable local class inheritance summaries, reused within one scan."""
    core = PhpCore(path, _read_yaml(path).encode("utf-8"))
    core.scan()
    return tuple(
        (definition.name, tuple(getattr(definition, "base_classes", ())))
        for definition in core.defs
        if definition.type == "class"
    )


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
                (
                    c
                    for c in attribute.children
                    if c.type in {"name", "qualified_name", "relative_name"}
                ),
                None,
            )
            if name is not None:
                names.add(_text(name, source))
    return names


def _annotation_names(node, source: bytes) -> set[str]:
    previous = node.prev_named_sibling
    if previous is None or previous.type != "comment":
        return set()
    text = _text(previous, source)
    if text.startswith("/**"):
        return set(_ANNOTATION_RE.findall(text))
    return set()


def _class_aliases(class_node, source: bytes) -> dict[str, str]:
    """Class imports in this namespace, including grouped use declarations."""
    scope = class_node.parent
    while scope is not None and scope.type not in {"program", "compound_statement"}:
        scope = scope.parent
    if scope is None:
        return {}
    siblings = scope.named_children
    if scope.type == "program":
        # Semicolon namespaces share the program node but never their imports.
        boundaries = [
            index
            for index, child in enumerate(siblings)
            if child.type == "namespace_definition"
        ]
        start = max(
            (
                index
                for index in boundaries
                if siblings[index].start_byte < class_node.start_byte
            ),
            default=-1,
        )
        end = next((index for index in boundaries if index > start), len(siblings))
        siblings = siblings[start + 1 : end]
    aliases: dict[str, str] = {}
    for declaration in siblings:
        if declaration.type != "namespace_use_declaration":
            continue
        declaration_kind = declaration.child_by_field_name("type")
        if declaration_kind is not None:
            continue
        prefix_node = next(
            (child for child in declaration.children if child.type == "namespace_name"),
            None,
        )
        prefix = ""
        if prefix_node is not None:
            prefix = _text(prefix_node, source) + "\\"
        for clause in _descendants(declaration, "namespace_use_clause"):
            if clause.child_by_field_name("type") is not None:
                continue
            target_node = clause.child_by_field_name("name") or next(
                (
                    child
                    for child in clause.children
                    if child.type in {"qualified_name", "name"}
                ),
                None,
            )
            if target_node is None:
                continue
            target = prefix + _text(target_node, source)
            alias_node = clause.child_by_field_name("alias")
            if alias_node is not None:
                alias = _text(alias_node, source)
            else:
                alias = target.rpartition("\\")[2]
            aliases[alias.casefold()] = target.lstrip("\\").replace("\\", ".")
    return aliases


def _resolve_metadata(name: str, aliases: dict[str, str], namespace: str) -> str | None:
    if name.startswith("\\"):
        return name.lstrip("\\").replace("\\", ".")
    first, _, rest = name.partition("\\")
    if first == "namespace":
        return ".".join(part for part in (namespace, rest.replace("\\", ".")) if part)
    if first.casefold() in aliases:
        return ".".join(
            part
            for part in (aliases[first.casefold()], rest.replace("\\", "."))
            if part
        )
    if "\\" in name:
        return ".".join(part for part in (namespace, name.replace("\\", ".")) if part)
    return None


def _is_plugin_type(qualified: str, root: str, seen: set[str] | None = None) -> bool:
    if qualified in _PLUGIN_METADATA_BASES:
        return True
    parts = qualified.split(".")
    if len(parts) < 3 or parts[0] != "Drupal":
        return False
    metadata_namespace = bool({"Attribute", "Annotation"}.intersection(parts[2:-1]))
    if parts[1] not in _machine_names(root):
        # The provider's source is outside this extension (core or contrib).
        return metadata_namespace
    if seen is None and not metadata_namespace:
        return False
    path = Path(root, "src", *parts[2:]).with_suffix(".php")
    if not path.is_file():
        return False
    if seen is None:
        seen = set()
    if qualified in seen or len(seen) >= 16:
        return False
    seen.add(qualified)
    bases = dict(_local_metadata_classes(str(path))).get(qualified)
    if bases is None:
        return False
    return any(_is_plugin_type(base, root, seen) for base in bases)


def _is_plugin_metadata(
    name: str,
    aliases: dict[str, str],
    root: str,
    relative: str,
    kind: str,
    namespace: str,
    local_classes: dict,
) -> bool:
    qualified = _resolve_metadata(name, aliases, namespace)
    local_name = qualified
    if local_name is None:
        local_name = ".".join(part for part in (namespace, name) if part)
    if local_name in local_classes:
        return _is_local_plugin_type(local_name, local_classes, root, set())
    if qualified is not None:
        return _is_plugin_type(qualified, root)
    # Legacy annotations omit use statements: their manager supplies the
    # provider namespace. Prefer a local definition when it is available.
    for machine in _machine_names(root):
        path = Path(root, "src", kind, f"{name}.php")
        if path.is_file():
            return _is_plugin_type(f"Drupal.{machine}.{kind}.{name}", root)
    # Preserve the conventional short spellings used without imported core
    # metadata, but a generic annotation is never discovery evidence.
    if relative.startswith("src/Entity/"):
        return name in {"EntityType", "ContentEntityType", "ConfigEntityType"}
    parts = [
        re.sub(r"[_-]", "", part).casefold()
        for part in relative.removeprefix("src/Plugin/").split("/")[:-1]
    ]
    normalized_name = re.sub(r"[_-]", "", name).casefold()
    for start in range(len(parts)):
        joined = ""
        for part in parts[start:]:
            joined += part
            if normalized_name in {joined, joined + "plugin"}:
                return True
    return False


def _is_local_plugin_type(
    qualified: str, local_classes: dict, root: str, seen: set[str]
) -> bool:
    """Honor actual class bindings before applying short metadata conventions."""
    bases = local_classes.get(qualified)
    if bases is None:
        return _is_plugin_type(qualified, root, seen)
    if qualified in seen or len(seen) >= 16:
        return False
    seen.add(qualified)
    return any(_is_local_plugin_type(base, local_classes, root, seen) for base in bases)


def _hook_attributes(
    node,
    source: bytes,
    aliases: dict[str, str],
    namespace: str,
    local_classes: dict,
    root: str,
) -> bool:
    hook_types = {
        f"Drupal.Core.Hook.Attribute.{attribute}" for attribute in _HOOK_ATTRIBUTES
    }
    for name in _attribute_names(node, source):
        qualified = _resolve_metadata(name, aliases, namespace)
        local_name = qualified
        if local_name is None:
            local_name = ".".join(part for part in (namespace, name) if part)
        binding = _local_hook_binding(local_name, local_classes, root, set())
        if binding is not None:
            if binding:
                return True
            continue
        if qualified in hook_types:
            return True
        if name in _HOOK_ATTRIBUTES and name.casefold() not in aliases:
            return True
    return False


def _local_hook_binding(
    qualified: str, local_classes: dict, root: str, seen: set[str]
) -> bool | None:
    """Return an actual local Hook inheritance proof, or None without source."""
    if qualified in seen or len(seen) >= 16:
        return False
    bases = local_classes.get(qualified)
    if bases is None:
        if qualified == "Drupal.Core.Hook.Attribute.Hook":
            return True
        parts = qualified.split(".")
        if (
            len(parts) < 3
            or parts[0] != "Drupal"
            or parts[1] not in _machine_names(root)
        ):
            return None
        path = Path(root, "src", *parts[2:]).with_suffix(".php")
        if not path.is_file():
            return None
        definitions = dict(_local_metadata_classes(str(path)))
        bases = definitions.get(qualified)
        if bases is None:
            return False
        local_classes = {**local_classes, **definitions}
    seen.add(qualified)
    return any(
        _local_hook_binding(base, local_classes, root, seen) is True for base in bases
    )


def _name_line(node) -> int | None:
    name = next((c for c in node.children if c.type == "name"), None)
    if name is None:
        return None
    return name.start_point[0] + 1


def _hook_method_lines(
    class_node,
    source: bytes,
    aliases: dict[str, str],
    namespace: str,
    local_classes: dict,
    root: str,
) -> set[int]:
    body = next((c for c in class_node.children if c.type == "declaration_list"), None)
    if body is None:
        return set()
    methods = (c for c in body.children if c.type == "method_declaration")
    return {
        line
        for method in methods
        if _hook_attributes(method, source, aliases, namespace, local_classes, root)
        and (line := _name_line(method)) is not None
    }


def _is_discovered(
    class_node,
    source: bytes,
    relative: str,
    root: str,
    aliases: dict[str, str],
    namespace: str,
    local_classes: dict,
) -> bool:
    """A class a plugin manager, Drush or the hook system finds on its own."""
    attributes = _attribute_names(class_node, source)
    if _hook_attributes(class_node, source, aliases, namespace, local_classes, root):
        return True
    if not relative.startswith(_DISCOVERY_DIRS):
        return False
    return (
        relative.startswith("src/Drush/")
        or any(
            _is_plugin_metadata(
                name, aliases, root, relative, "Attribute", namespace, local_classes
            )
            for name in attributes
        )
        or any(
            _is_plugin_metadata(
                name, aliases, root, relative, "Annotation", namespace, local_classes
            )
            for name in _annotation_names(class_node, source)
        )
    )


def _attribute_root_lines(root_node, source: bytes, relative: str, root: str, defs):
    """``(lines of discovered classes, lines of #[Hook] methods)``."""
    classes: set[int] = set()
    hooks: set[int] = set()
    class_names = {d.line: d.name for d in defs if d.type == "class"}
    local_classes = {
        d.name: tuple(getattr(d, "base_classes", ())) for d in defs if d.type == "class"
    }
    for node in _descendants(root_node, "class_declaration"):
        line = _name_line(node)
        if line is None:
            continue
        aliases = _class_aliases(node, source)
        namespace = class_names.get(line, "").rpartition(".")[0]
        methods = _hook_method_lines(
            node, source, aliases, namespace, local_classes, root
        )
        hooks |= methods
        if methods or _is_discovered(
            node, source, relative, root, aliases, namespace, local_classes
        ):
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
    hook_lines = set()
    if relative.endswith(_PROCEDURAL_SUFFIXES):
        prefixes = (
            *(f"{name}_" for name in _machine_names(root)),
            "template_preprocess_",
        )
        hook_lines = {
            d.line
            for d in defs
            if d.type == "function" and d.simple_name.startswith(prefixes)
        }
    if root_node is None:
        return hook_lines

    yaml_names = _yaml_references(root)
    class_lines, lines = _attribute_root_lines(root_node, source, relative, root, defs)
    classes = _root_classes(defs, class_lines, yaml_names, root, relative)
    return (
        hook_lines
        | lines
        | set(classes.values())
        | _root_method_lines(defs, classes, yaml_names)
    )
