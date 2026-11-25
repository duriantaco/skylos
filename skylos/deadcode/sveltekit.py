"""Source-proven entry points for a bounded subset of SvelteKit 2 apps."""

from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from skylos.core.file_discovery import exclusion_matcher
from skylos.core.js_ast import (
    is_type_only,
    iter_import_clause_bindings,
)
from skylos.core.js_ast import node_text as _text
from skylos.core.safe_cache_io import read_project_text_no_symlink

_CONFIG_LIMIT = 65_536
_SOURCE_LIMIT = 1_000_000
_MAX_ROUTE_DIRECTORIES = 4096
_MODULE_SUFFIXES = (".js", ".ts")
_CONFIG_SUFFIXES = frozenset({".js", ".mjs", ".ts", ".mts", ".cjs", ".cts"})
_V2_VERSION = re.compile(r"([~^]?)2\.(\d+)\.(\d+)")
_DIRECT_DEPENDENCY = re.compile(r"(?:@[\w.-]+/)?[\w.-]+", re.ASCII)
_SIMPLE_VERSION = re.compile(r"[~^]?\d+\.\d+\.\d+")
_DIRECTORY = re.compile(r"(?:\./)?[\w.-]+(?:/[\w.-]+)*", re.ASCII)
_LAYOUT = frozenset({"load", "prerender", "ssr", "csr", "trailingSlash", "config"})
_PAGE = _LAYOUT | {"entries"}
_ROUTES = {
    "+page": _PAGE,
    "+page.server": _PAGE | {"actions"},
    "+layout": _LAYOUT,
    "+layout.server": _LAYOUT,
    "+server": frozenset(
        {
            "GET",
            "POST",
            "PATCH",
            "PUT",
            "DELETE",
            "OPTIONS",
            "HEAD",
            "fallback",
            "prerender",
            "trailingSlash",
            "config",
            "entries",
        }
    ),
}
_HOOKS = {
    "hooks": frozenset({"reroute", "transport"}),
    "hooks.server": frozenset({"handle", "handleFetch", "handleError", "init"}),
    "hooks.client": frozenset({"handleError", "init"}),
}


@dataclass
class SvelteKitEntries:
    module_exports: dict[str, frozenset[str]] = field(default_factory=dict)
    export_bindings: dict[str, frozenset[tuple[str, int]]] = field(default_factory=dict)
    reexport_reads: dict[str, frozenset[str]] = field(default_factory=dict)
    components: frozenset[str] = frozenset()
    lib_directories: dict[str, str] = field(default_factory=dict)
    configured_packages: set[str] = field(default_factory=set)


def _parse(root, path, limit):
    from skylos.visitors.languages.typescript.analysis import (
        _entry_parser_for_path,
        _parse_entry_source,
    )

    source = read_project_text_no_symlink(root, path, max_bytes=limit)
    parser = _entry_parser_for_path(str(path))
    if source is None or parser is None:
        raise ValueError("unreadable SvelteKit source")
    raw = source.encode("utf-8")
    node = _parse_entry_source(parser, raw, path).root_node
    if node.has_error:
        raise ValueError("invalid SvelteKit source")
    return raw, node


def _children(node):
    return [child for child in node.named_children if child.type != "comment"]


def _string(source, node):
    if node is None or node.type != "string":
        return None
    if any(child.type != "string_fragment" for child in node.named_children):
        return None
    return _text(source, node)[1:-1]


def _properties(source, node):
    if node is None or node.type != "object":
        raise ValueError("expected a literal config object")
    properties = {}
    for pair in _children(node):
        key = pair.child_by_field_name("key")
        if pair.type != "pair" or key is None:
            raise ValueError("unsupported config property")
        name = (
            _text(source, key)
            if key.type == "property_identifier"
            else _string(source, key)
        )
        if not name or name == "__proto__" or name in properties:
            raise ValueError("unsupported config key")
        properties[name] = pair.child_by_field_name("value")
    return properties


def _config(root, path, dependencies):
    source, program = _parse(root, path, _CONFIG_LIMIT)
    imports = {}
    binding = None
    value = None
    for statement in _children(program):
        if statement.type == "import_statement":
            specifier = _string(source, statement.child_by_field_name("source"))
            if specifier not in dependencies | {"vite", "@sveltejs/kit/vite"}:
                raise ValueError("unproven config import")
            clause = next(
                (
                    child
                    for child in _children(statement)
                    if child.type == "import_clause"
                ),
                None,
            )
            if clause is None or is_type_only(statement):
                raise ValueError("unsupported config import")
            for imported in iter_import_clause_bindings(source, clause):
                if imported.local in imports or imported.type_only:
                    raise ValueError("ambiguous config import")
                imports[imported.local] = (specifier, imported.imported)
        elif (
            statement.type == "lexical_declaration"
            and statement.children[0].type == "const"
        ):
            declarations = _children(statement)
            if binding is not None or len(declarations) != 1:
                raise ValueError("unproven config initialization")
            declaration = declarations[0]
            name = declaration.child_by_field_name("name")
            if name is None or name.type != "identifier":
                raise ValueError("unsupported config binding")
            binding = (_text(source, name), declaration.child_by_field_name("value"))
        elif statement.type == "export_statement" and any(
            child.type == "default" for child in statement.children
        ):
            if value is not None:
                raise ValueError("ambiguous config export")
            value = statement.child_by_field_name("value")
        else:
            raise ValueError("unsupported config statement")
    if binding is not None:
        if (
            value is None
            or value.type != "identifier"
            or _text(source, value) != binding[0]
            or binding[0] in imports
        ):
            raise ValueError("unproven config binding")
        value = binding[1]
    if value is not None and value.type == "call_expression":
        factory, arguments = _call(source, value, imports)
        if factory != ("vite", "defineConfig") or len(arguments) != 1:
            raise ValueError("unsupported config factory")
        value = arguments[0]
    return source, imports, _properties(source, value)


def _call(source, node, imports):
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or function.type != "identifier" or arguments is None:
        raise ValueError("unsupported config call")
    return imports.get(_text(source, function)), _children(arguments)


def _literal_config(source, node, imports):
    if (
        node.type in {"true", "false", "null", "number"}
        or _string(source, node) is not None
    ):
        return
    if node.type == "object":
        values = _properties(source, node).values()
    elif node.type == "array":
        values = _children(node)
    elif node.type == "identifier" and _text(source, node) in imports:
        return
    elif node.type == "call_expression":
        factory, values = _call(source, node, imports)
        if factory is None or not (
            factory == ("mdsvex", "mdsvex")
            or (factory[0].startswith("@sveltejs/adapter-") and factory[1] == "default")
            or (factory == ("@sveltejs/vite-plugin-svelte", "vitePreprocess"))
        ):
            raise ValueError("unproven config expression")
    else:
        raise ValueError("unproven config expression")
    for value in values:
        _literal_config(source, value, imports)


def _directory(path, source, option, default):
    value = _string(source, option) if option is not None else default
    if value is None or not _DIRECTORY.fullmatch(value) or ".." in Path(value).parts:
        raise ValueError("unproven framework directory")
    directory = path / value
    if directory.resolve() != directory:
        raise ValueError("linked framework directory")
    return directory


def _read_manifest(root, path):
    manifest_text = read_project_text_no_symlink(root, path, max_bytes=_CONFIG_LIMIT)
    manifest = json.loads(manifest_text) if manifest_text is not None else None
    return manifest if isinstance(manifest, dict) else None


def _safe_overrides(manifest, providers):
    for overrides in (
        manifest.get("overrides", {}),
        manifest.get("resolutions", {}),
        manifest.get("pnpm", {}).get("overrides", {}),
    ):
        if not isinstance(overrides, dict):
            return False
        if any(
            name in providers
            or not _DIRECT_DEPENDENCY.fullmatch(name)
            or not isinstance(version, str)
            or not _SIMPLE_VERSION.fullmatch(version)
            for name, version in overrides.items()
        ):
            return False
    return True


def _installed_kit_matches(root, owner, declared):
    for directory in (owner, *owner.parents):
        package = directory / "node_modules" / "@sveltejs" / "kit"
        if package.exists() or package.is_symlink():
            metadata = (package / "package.json").resolve(strict=True)
            installed = _read_manifest(root, metadata)
            version = installed.get("version") if installed else None
            actual = (
                _V2_VERSION.fullmatch(version) if isinstance(version, str) else None
            )
            if not actual or actual[1] or installed.get("name") != "@sveltejs/kit":
                return False
            have = (int(actual[2]), int(actual[3]))
            want = (int(declared[2]), int(declared[3]))
            if declared[1] == "^":
                return have >= want
            if declared[1] == "~":
                return have[0] == want[0] and have >= want
            return have == want
        if directory == root:
            break
    return True


def _package_config(root, owner):
    manifest = _read_manifest(root, owner / "package.json")
    if manifest is None:
        return None
    runtime = manifest.get("dependencies", {})
    tooling = manifest.get("devDependencies", {})
    dependencies = runtime | tooling
    version = dependencies.get("@sveltejs/kit")
    match = _V2_VERSION.fullmatch(version) if isinstance(version, str) else None
    if (
        match is None
        or int(match[2]) < 11
        or runtime.get("@sveltejs/kit", version) != version
    ):
        return None
    providers = dependencies.keys() | {"svelte", "vite", "@sveltejs/vite-plugin-svelte"}
    if not _safe_overrides(manifest, providers) or not _installed_kit_matches(
        root, owner, match
    ):
        return None
    for ancestor in owner.parents:
        if not ancestor.is_relative_to(root):
            break
        marker = ancestor / "package.json"
        if marker.exists() or marker.is_symlink():
            parent = _read_manifest(root, marker)
            if parent is None or not _safe_overrides(parent, providers):
                return None
    if any(
        re.search(r"(?:\s|^)(?:--config\b|-c(?:\s|=))", command)
        for command in manifest.get("scripts", {}).values()
    ):
        return None

    vite_configs = [
        path for path in owner.glob("vite.config.*") if path.suffix in _CONFIG_SUFFIXES
    ]
    svelte_configs = [
        path
        for path in owner.glob("svelte.config.*")
        if path.suffix in _CONFIG_SUFFIXES
    ]
    if len(vite_configs) != 1 or svelte_configs != [owner / "svelte.config.js"]:
        return None
    source, imports, vite = _config(root, vite_configs[0], dependencies.keys())
    if {"root", "configFile"} & vite.keys():
        return None
    plugins = vite.get("plugins")
    if plugins is None or plugins.type != "array":
        return None
    plugins = _children(plugins)
    if len(plugins) != 1 or plugins[0].type != "call_expression":
        return None
    factory, arguments = _call(source, plugins[0], imports)
    if factory != ("@sveltejs/kit/vite", "sveltekit") or arguments:
        return None
    for name, option in vite.items():
        if name != "plugins":
            _literal_config(source, option, imports)

    source, imports, svelte = _config(root, svelte_configs[0], dependencies.keys())
    for option in svelte.values():
        _literal_config(source, option, imports)
    kit = _properties(source, svelte["kit"]) if "kit" in svelte else {}
    if {"moduleExtensions", "router"} & kit.keys():
        return None
    files = _properties(source, kit["files"]) if "files" in kit else {}
    if files.keys() - {"routes", "lib"}:
        return None
    routes = _directory(owner, source, files.get("routes"), "src/routes")
    lib = _directory(owner, source, files.get("lib"), "src/lib")
    if "resolve" in vite or "alias" in kit:
        lib = None
    extensions = (".svelte",)
    if "extensions" in svelte:
        option = svelte["extensions"]
        if option.type != "array":
            return None
        extensions = tuple(_string(source, value) for value in _children(option))
        if any(
            not ext or not re.fullmatch(r"\.[a-zA-Z0-9]+", ext) for ext in extensions
        ):
            return None
        if set(extensions) & set(_MODULE_SUFFIXES):
            return None
    return routes, lib, extensions


def _configured_package(package_root: str):
    owner = Path(package_root)
    if not (owner / "svelte.config.js").is_file():
        return None
    root = owner
    for parent in owner.parents:
        if (root / ".git").exists():
            break
        if (parent / "package.json").is_file():
            root = parent
        if (parent / ".git").exists():
            break
    try:
        config = _package_config(root, owner)
    except (OSError, AttributeError, RuntimeError, TypeError, ValueError):
        return None
    return config


def _legacy_files_override(package_root: str, key: str, default: str) -> Path | None:
    owner = Path(package_root)
    # With no Vite config, a Kit 2 app's literal legacy setting is enough
    # to rule out the old default, even without full entry discovery.
    if not (owner / "svelte.config.js").is_file() or any(owner.glob("vite.config.*")):
        return None
    try:
        manifest = _read_manifest(owner, owner / "package.json")
        if manifest is None:
            return None
        dependencies = manifest.get("dependencies", {}) | manifest.get("devDependencies", {})
        version = dependencies.get("@sveltejs/kit")
        if not isinstance(version, str) or _V2_VERSION.fullmatch(version) is None:
            return None
        source, imports, config = _config(
            owner, owner / "svelte.config.js", dependencies.keys()
        )
        for option in config.values():
            _literal_config(source, option, imports)
        kit = _properties(source, config.get("kit"))
        files = _properties(source, kit.get("files"))
        if key in files:
            return _directory(owner, source, files[key], default)
    except (OSError, AttributeError, RuntimeError, TypeError, ValueError):
        return None
    return None


def supersedes_default_entry(package_root: str, relative: str) -> bool:
    """Whether exact Kit configuration supersedes a table entry."""
    path = Path(relative)
    is_route = path.is_relative_to("src/routes")
    is_hook = path.parent == Path("src") and path.stem in _HOOKS
    if not is_route and not is_hook:
        return False
    config = _configured_package(package_root)
    if config is None:
        override = (
            _legacy_files_override(package_root, "routes", "src/routes")
            if is_route else None
        )
        return override is not None and not (Path(package_root) / path).is_relative_to(override)
    routes, _, _ = config
    if is_route and not (Path(package_root) / path).is_relative_to(routes):
        return True
    return path.suffix in _MODULE_SUFFIXES and (is_hook or path.stem in _ROUTES)


def supersedes_default_library(package_root: str) -> bool:
    """Whether the legacy alias would bypass established configuration."""
    if _configured_package(package_root) is not None:
        return True
    override = _legacy_files_override(package_root, "lib", "src/lib")
    return override is not None and override != Path(package_root) / "src/lib"


def _package_owner(path, root, cache):
    visited = []
    for directory in (path.parent, *path.parent.parents):
        if directory in cache:
            owner = cache[directory]
            break
        visited.append(directory)
        marker = directory / "package.json"
        if marker.exists() or marker.is_symlink():
            owner = directory
            break
        if directory == root:
            owner = None
            break
    for directory in visited:
        cache[directory] = owner
    return owner


_VALUE_DECLARATIONS = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "class_declaration",
        "enum_declaration",
    }
)


def _value_bindings(source, statement):
    if statement.type in {"lexical_declaration", "variable_declaration"}:
        candidates = _children(statement)
    elif statement.type in _VALUE_DECLARATIONS:
        candidates = (statement,)
    else:
        return ()
    names = [candidate.child_by_field_name("name") for candidate in candidates]
    return tuple(
        (_text(source, node), node.start_point[0] + 1)
        for node in names
        if node and node.type in {"identifier", "type_identifier"}
    )


def _unique_binding_lines(source, program, bindings):
    if not bindings:
        return bindings
    rows = {line - 1 for _, line in bindings}
    counts = Counter()
    declaration_types = _VALUE_DECLARATIONS | {
        "variable_declarator",
        "type_alias_declaration",
        "interface_declaration",
        "method_definition",
    }
    nodes = [program]
    while nodes:
        node = nodes.pop()
        if not any(node.start_point[0] <= row <= node.end_point[0] for row in rows):
            continue
        if node.type in declaration_types:
            name = node.child_by_field_name("name")
            if name is not None:
                binding = (_text(source, name), name.start_point[0] + 1)
                if binding in bindings:
                    counts[binding] += 1
        nodes.extend(node.named_children)
    return frozenset(binding for binding in bindings if counts[binding] == 1)


def _export_bindings(root, path, roles):
    source, program = _parse(root, path, _SOURCE_LIMIT)
    locals_by_name = defaultdict(set)
    exposed = set()
    reexports = set()
    for statement in _children(program):
        if statement.type != "export_statement":
            for name, line in _value_bindings(source, statement):
                locals_by_name[name].add(line)
            continue
        if any(child.type in {"default", "type", "="} for child in statement.children):
            continue
        has_source = statement.child_by_field_name("source") is not None
        declaration = statement.child_by_field_name("declaration")
        if declaration is not None:
            for name, line in _value_bindings(source, declaration):
                locals_by_name[name].add(line)
                if name in roles:
                    exposed.add(name)
        for clause in _children(statement):
            if clause.type != "export_clause":
                continue
            for specifier in _children(clause):
                if specifier.type != "export_specifier" or is_type_only(specifier):
                    continue
                name = specifier.child_by_field_name("name")
                alias = specifier.child_by_field_name("alias") or name
                exported = _string(source, alias) or _text(source, alias)
                if exported not in roles:
                    continue
                if has_source:
                    reexports.add(exported)
                else:
                    exposed.add(_text(source, name))
    bindings = frozenset(
        (name, next(iter(lines)))
        for name in exposed
        if len(lines := locals_by_name[name]) == 1
    )
    return _unique_binding_lines(source, program, bindings), frozenset(reexports)


def _inside(root, path):
    return path.is_relative_to(root) and path.resolve(strict=True) == path


def _route_files(routes, extensions, excluded):
    """Walk only the proven route tree to find files and their parent layouts."""
    records = {}
    leaves = set()
    named_layouts = set()
    for directory, directories, filenames in os.walk(routes):
        path = Path(directory)
        directories[:] = [name for name in directories if not excluded(path / name)]
        if len(records) >= _MAX_ROUTE_DIRECTORIES:
            raise ValueError("SvelteKit route tree too large")
        files = {}
        for name in filenames:
            suffix = Path(name).suffix
            role = name.removesuffix(suffix)
            candidate = path / name
            if not (suffix in extensions or suffix in _MODULE_SUFFIXES):
                continue
            if candidate.is_symlink() or excluded(candidate):
                continue
            if suffix in extensions and role.startswith(("+page@", "+layout@")):
                if role.startswith("+layout@"):
                    named_layouts.add(path)
                continue
            if suffix in extensions and role == "+page":
                leaves.add(path)
            if suffix in _MODULE_SUFFIXES and role in _ROUTES:
                if role in {"+page", "+page.server"}:
                    leaves.add(path)
                files.setdefault(role, []).append(candidate)
            elif suffix in extensions and role in {"+page", "+layout", "+error"}:
                files.setdefault(role + ".component", []).append(candidate)
        if path in leaves and any(
            name.startswith("+page@") and Path(name).suffix in extensions
            for name in filenames
        ):
            leaves.discard(path)
        records[path] = files

    attached = set()
    for leaf in leaves:
        for directory in (leaf, *leaf.parents):
            if directory in named_layouts:
                break
            attached.add(directory)
            if directory == routes:
                break
    return records, attached


def discover_sveltekit_entries(
    project_root, files, *, exclude_folders=None
) -> SvelteKitEntries:
    """Collect exact positive framework evidence without running project config."""
    result = SvelteKitEntries()
    root = Path(project_root).resolve()
    excluded = exclusion_matcher(root, exclude_folders)
    selected = set()
    packages = set()
    owners = {}
    for value in files:
        path = Path(value).absolute()
        if path.suffix not in _CONFIG_SUFFIXES or not path.is_relative_to(root):
            continue
        selected.add(path)
        owner = _package_owner(path, root, owners)
        if owner is not None:
            packages.add(owner)

    components = set()
    for owner in sorted(packages):
        try:
            if not _inside(root, owner) or excluded(owner):
                continue
            config = _package_config(root, owner)
            if config is None:
                continue
            routes, lib, extensions = config
            result.configured_packages.add(str(owner))
            uses_default_resolver = (
                lib is not None
                and not excluded(lib)
                and _package_owner(lib / "module", root, owners) == owner
            )
            records, attached = ({}, set())
            if (
                not excluded(routes)
                and _package_owner(routes / "route", root, owners) == owner
            ):
                records, attached = _route_files(routes, extensions, excluded)
            modules = {}
            for directory, candidates in records.items():
                for role, paths in candidates.items():
                    if len(paths) != 1:
                        continue
                    path = paths[0]
                    if excluded(path) or not _inside(root, path):
                        continue
                    if (
                        role
                        in {
                            "+layout",
                            "+layout.server",
                            "+layout.component",
                            "+error.component",
                        }
                        and directory not in attached
                    ):
                        continue
                    if (
                        uses_default_resolver
                        and role.endswith(".component")
                        and path.suffix == ".svelte"
                    ):
                        components.add(str(path))
                    elif path in selected and role in _ROUTES:
                        modules[path] = _ROUTES[role]
            for role, names in _HOOKS.items():
                base = owner / "src" / role
                candidates = [Path(str(base) + suffix) for suffix in _MODULE_SUFFIXES]
                existing = [
                    path for path in candidates if path.exists() or path.is_symlink()
                ]
                if len(existing) == 1 and not base.exists() and not base.is_symlink():
                    path = existing[0]
                    if (
                        path in selected
                        and not excluded(path)
                        and _inside(root, path)
                        and _package_owner(path, root, owners) == owner
                    ):
                        modules[path] = names
            for path, roles in modules.items():
                try:
                    bindings, reexports = _export_bindings(root, path, roles)
                except (OSError, RuntimeError, ValueError):
                    continue
                result.module_exports[str(path)] = roles
                result.export_bindings[str(path)] = bindings
                result.reexport_reads[str(path)] = reexports
            if uses_default_resolver:
                result.lib_directories[str(owner)] = str(lib)
        except (OSError, AttributeError, RuntimeError, TypeError, ValueError):
            continue
    result.components = frozenset(components)
    return result
