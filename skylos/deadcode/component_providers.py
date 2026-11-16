"""Source evidence for generated component consumers outside the static graph."""

from collections import Counter
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink


_ROUTE_PROVIDERS = frozenset({"vue-router/auto-routes", "virtual:generated-pages", "virtual:generated-layouts", "~pages"})
_FACTORIES = {
    "unplugin-auto-import/vite": "unresolved_auto_import_provider",
    "unplugin-vue-components/vite": "unresolved_auto_component_provider",
}
_MAX_CONFIG_FILES = 64
_MAX_CONFIG_BYTES = 8_000_000


def generated_component_provider_limits(project_root, source_files, raw_imports):
    """Identify unsupported generated consumers; this never grants liveness."""
    from skylos.core.js_ast import iter_import_clause_bindings
    from skylos.visitors.languages.typescript.core import TypeScriptCore
    from skylos.visitors.languages.typescript.namespace_references import _pattern_names

    root = Path(project_root).resolve()
    selected = {str(Path(file).absolute()) for file in source_files}
    limits = []
    seen_routes = set()
    for importer, entries in raw_imports.items():
        if str(Path(importer).absolute()) not in selected or str(importer).lower().endswith((".d.ts", ".d.mts", ".d.cts")):
            continue
        for entry in entries:
            identity = (str(importer), entry.get("source"))
            if entry.get("source") in _ROUTE_PROVIDERS and identity not in seen_routes:
                seen_routes.add(identity)
                limits.append({"file": str(importer), "reason": "unresolved_generated_route_provider", "source": entry["source"]})
    config_count, config_bytes = 0, 0
    for filename in sorted(selected):
        path = Path(filename)
        if not path.name.startswith("vite.config."):
            continue
        config_count += 1
        if config_count > _MAX_CONFIG_FILES:
            limits.append({"file": filename, "reason": "component_provider_config_limit"})
            break
        source_text = read_project_text_no_symlink(root, path, max_bytes=1_000_000)
        if source_text is None:
            continue
        config_bytes += len(source_text.encode("utf-8"))
        if config_bytes > _MAX_CONFIG_BYTES:
            limits.append({"file": filename, "reason": "component_provider_byte_limit"})
            break
        core = TypeScriptCore(filename, source_text.encode("utf-8"))
        tree, source = core.root_node, core.source
        if tree is None or tree.has_error:
            continue

        def text(node):
            return source[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

        factories, config_functions, names = {}, set(), Counter()
        for statement in tree.named_children:
            if statement.type != "import_statement":
                continue
            provider = text(statement.child_by_field_name("source")).strip("'\"")
            clause = next((child for child in statement.named_children if child.type == "import_clause"), None)
            if clause is None:
                continue
            for binding in iter_import_clause_bindings(source, clause):
                names[binding.local] += 1
                if binding.type_only:
                    continue
                if provider in _FACTORIES and binding.kind == "default":
                    factories[binding.local] = (provider, _FACTORIES[provider])
                if provider in {"vite", "vitest/config"} and binding.imported == "defineConfig":
                    config_functions.add(binding.local)
        protected = set(factories) | config_functions
        if not factories or any(names[name] != 1 for name in protected):
            continue
        rebound = False
        for node in core._iter_nodes(tree):
            if node.type in {"variable_declarator", "function_declaration", "class_declaration"}:
                pattern = node.child_by_field_name("name")
            elif node.type in {"formal_parameters", "required_parameter", "optional_parameter"}:
                pattern = node
            elif node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
                pattern = node.child_by_field_name("left") or node.child_by_field_name("argument")
            else:
                continue
            if any(text(name) in protected for name in _pattern_names(pattern)):
                rebound = True
        if rebound:
            continue
        for statement in tree.named_children:
            if statement.type != "export_statement" or not any(child.type == "default" for child in statement.children):
                continue
            config = next((child for child in statement.named_children if child.type in {"object", "call_expression"}), None)
            if config is not None and config.type == "call_expression":
                arguments = config.child_by_field_name("arguments")
                if text(config.child_by_field_name("function")) not in config_functions or arguments is None or len(arguments.named_children) != 1:
                    continue
                config = arguments.named_children[0]
            if config is None or config.type != "object":
                continue
            pairs = [child for child in config.named_children if child.type == "pair" and text(child.child_by_field_name("key")).strip("'\"") == "plugins"]
            if len(pairs) != 1:
                continue
            plugins = pairs[0].child_by_field_name("value")
            if plugins is None or plugins.type != "array":
                continue
            for plugin in plugins.named_children:
                if plugin.type != "call_expression":
                    continue
                factory = text(plugin.child_by_field_name("function"))
                if factory not in factories:
                    continue
                provider, reason = factories[factory]
                if reason == "unresolved_auto_import_provider":
                    arguments = plugin.child_by_field_name("arguments")
                    options = next(iter(arguments.named_children), None) if arguments is not None else None
                    if options is None:
                        continue
                    if options.type == "object" and all(child.type in {"pair", "comment"} for child in options.named_children) and not any(child.type == "pair" and text(child.child_by_field_name("key")).strip("'\"") == "dirs" for child in options.named_children):
                        continue
                limits.append({"file": filename, "reason": reason, "source": provider})
    return limits
