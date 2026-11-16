"""Bounded npm dependency usage from source, package scripts and tool configs.

No package code or package-manager commands are executed. Missing source,
dynamic loaders and unknown command providers prevent an absence claim for
the owning package; they never make a dependency look unused.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from collections import defaultdict
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink

RULE_UNUSED = "SKY-U005"
RULE_UNLISTED = "SKY-Q408"
RULE_BINARY = "SKY-Q409"
MAX_FILES = 20_000
MAX_WALK_ENTRIES = 100_000
MAX_BYTES = 2_000_000
MAX_TOTAL_BYTES = 32_000_000
MAX_NODES = 50_000
SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
COMPONENT_SUFFIXES = {".vue", ".svelte", ".astro", ".mdx", ".marko"}
OPAQUE_SOURCE_SUFFIXES = {".css", ".scss", ".sass", ".less"}
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "dist", "build", "coverage", ".next", ".nuxt"}
DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
JSON_CONFIGS = {".eslintrc", ".eslintrc.json", ".babelrc", ".babelrc.json", "babel.config.json", ".prettierrc", ".prettierrc.json"}
OPAQUE_CONFIGS = {".eslintrc.js", ".eslintrc.cjs", ".eslintrc.yml", ".eslintrc.yaml", "babel.config.js", "babel.config.cjs", ".babelrc.js", ".babelrc.cjs", "postcss.config.json", ".postcssrc", ".postcssrc.json", "prettier.config.js", "prettier.config.cjs", ".prettierrc.js", ".prettierrc.cjs", ".prettierrc.yml", ".prettierrc.yaml"}
OPAQUE_CONFIGS |= {f"postcss.config.{extension}" for extension in ("js", "mjs", "cjs", "ts", "mts", "cts")}
_OPAQUE_MANIFEST_CONFIGS = {"jest", "postcss", "ava", "mocha", "nyc", "lint-staged", "commitlint", "release", "stylelint", "xo"}
# These commands have non-identical package names. Other commands require
# a matching dependency name or an installed package's literal bin metadata.
BINARY_PROVIDERS = {
    "tsc": "typescript", "tsserver": "typescript", "babel": "@babel/cli",
    "ng": "@angular/cli", "nest": "@nestjs/cli", "webpack": "webpack-cli",
    "playwright": "@playwright/test", "eslint": "eslint", "vite": "vite",
    "vitest": "vitest", "jest": "jest", "prettier": "prettier", "tsx": "tsx",
    "ts-node": "ts-node", "rollup": "rollup", "esbuild": "esbuild",
    "next": "next", "nuxt": "nuxt", "astro": "astro", "storybook": "storybook",
}
SYSTEM_COMMANDS = {"node", "nodejs", "bun", "deno", "echo", "printf", "true", "false", "test", "mkdir", "rm", "cp", "mv", "cat", "ls", "pwd", "cd", "touch", "git", "exit", "sleep", "which", "command", "export", "unset", "[", "]"}
_PACKAGE = re.compile(r"^(?:@[a-zA-Z0-9._~-]+/)?[a-zA-Z0-9._~-]+$")
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _package_name(specifier):
    if not isinstance(specifier, str) or specifier.startswith((".", "/", "#")) or _URL.match(specifier):
        return None
    from skylos.rules.ai_defect.js_api_hallucination import _NODE_BUILTINS

    if specifier in _NODE_BUILTINS or specifier.split("/", 1)[0] in _NODE_BUILTINS:
        return None
    parts = specifier.split("/")
    name = "/".join(parts[:2]) if specifier.startswith("@") else parts[0]
    return name if _PACKAGE.fullmatch(name) else None


def _nodes(root):
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.named_children))


def _text(source, node):
    return source[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""


def _literal(source, node):
    if node is None or node.type not in {"string", "template_string"}:
        return None
    if any(child.type == "template_substitution" for child in node.named_children):
        return None
    raw = _text(source, node)
    # Escaped specifiers are valid but need JavaScript string evaluation.
    return raw[1:-1] if len(raw) >= 2 and "\\" not in raw else None


def _source_imports(path, text):
    from skylos.visitors.languages.typescript.core import TypeScriptCore

    core = TypeScriptCore(str(path), text.encode("utf-8"))
    if core.root_node is None or core.root_node.has_error:
        return [], [{"kind": "source_parse_error", "file": str(path)}]
    source = core.source
    imports, unknown = [], []
    nodes = []
    for node in _nodes(core.root_node):
        nodes.append(node)
        if len(nodes) > MAX_NODES:
            return [], [{"kind": "source_node_budget", "file": str(path)}]
    # A local require binding cannot prove that a package is loaded. Decline
    # absence analysis instead of treating a lookalike function as a provider.
    shadowed_require = any(
        node.type == "identifier" and _text(source, node) == "require"
        and node.parent is not None and node.parent.type in {
            "formal_parameters", "required_parameter", "optional_parameter",
            "variable_declarator", "function_declaration", "import_clause", "import_specifier",
        }
        for node in nodes
    )
    for node in nodes:
        if node.type == "comment" and re.match(r"///\s*<reference\b[^>]*\btypes\s*=", _text(source, node)):
            unknown.append({"kind": "typescript_reference_provider", "file": str(path)})
        if node.type == "identifier" and _text(source, node) == "require":
            parent = node.parent
            if parent is not None and parent.type not in {"call_expression", "member_expression"}:
                unknown.append({"kind": "escaped_module_loader", "file": str(path)})
        if node.type in {"import_statement", "export_statement"}:
            literal = node.child_by_field_name("source")
            if literal is not None:
                value = _literal(source, literal)
                if value is None:
                    unknown.append({"kind": "escaped_module_specifier", "file": str(path)})
                else:
                    imports.append((value, literal.start_point[0] + 1))
                    if value in {"module", "node:module"}:
                        unknown.append({"kind": "module_loader_capability", "file": str(path)})
            continue
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        name = _text(source, function)
        args = node.child_by_field_name("arguments")
        if name in {"eval", "createRequire"} or name.endswith(".createRequire"):
            unknown.append({"kind": "dynamic_module_loader", "file": str(path)})
        if name not in {"import", "require", "require.resolve", "import.meta.resolve"}:
            continue
        if name.startswith("require") and shadowed_require:
            unknown.append({"kind": "shadowed_require", "file": str(path)})
            continue
        arg = args.named_children[0] if args is not None and args.named_children else None
        value = _literal(source, arg)
        if value is not None:
            imports.append((value, node.start_point[0] + 1))
            if value in {"module", "node:module"}:
                unknown.append({"kind": "module_loader_capability", "file": str(path)})
        elif arg is not None and arg.type == "template_string" and _text(source, arg).startswith(("`./", "`../")):
            continue
        else:
            unknown.append({"kind": "dynamic_module_specifier", "file": str(path)})
    core.raw_imports = []
    core._raw_import_seen = set()
    core._scan_jsdoc_raw_imports()
    imports.extend((item["source"], item["line"]) for item in core.raw_imports)
    return imports, unknown


def _line(text, name):
    match = re.search(r'"' + re.escape(name) + r'"\s*:', text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _finding(rule, name, path, line, message, **metadata):
    return {
        "rule_id": rule, "kind": "quality", "severity": "MEDIUM",
        "type": "dependency" if rule != RULE_BINARY else "binary",
        "name": name, "simple_name": name, "value": "unused" if rule == RULE_UNUSED else "unlisted",
        "message": message, "file": str(path), "basename": Path(path).name,
        "line": line, "col": 0, "metadata": {"ecosystem": "npm", **metadata},
    }


def _script_commands(script, script_names=()):
    """Return simple command heads only; decline shell expansion/compound syntax."""
    if not isinstance(script, str) or any(char in script for char in ("$", "`", "\n", "(", ")", "<", ">")):
        return [], True
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return [], True
    segments, segment = [], []
    for token in tokens:
        if token in {";", "&&", "||", "|", "&"}:
            if segment:
                segments.append(segment)
            segment = []
        else:
            segment.append(token)
    if segment:
        segments.append(segment)
    commands, unknown = [], False
    for tokens in segments:
        while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
            tokens = tokens[1:]
        if not tokens:
            continue
        command, rest = tokens[0], tokens[1:]
        if command in {"npm", "pnpm", "yarn"}:
            if rest and rest[0] in {"run", "run-script", "test", "start", "stop", "restart"}:
                continue  # Every declared script is inspected independently.
            if rest and rest[0] in {"install", "i", "add", "remove", "update", "publish", "pack", "version", "audit", "ci", "prune", "dedupe", "outdated"}:
                continue
            if rest and rest[0] in {"exec", "dlx"}:
                if rest[0] == "dlx":
                    continue  # An explicit transient provider, not a local dependency.
                rest = [token for token in rest[1:] if token != "--"]
                if rest and not rest[0].startswith("-"):
                    commands.append(rest[0])
                else:
                    unknown = True
            elif command in {"pnpm", "yarn"} and rest and not rest[0].startswith("-"):
                if rest[0] not in script_names:
                    commands.append(rest[0])
            else:
                unknown = True
        elif command == "npx":
            # npx may fetch the requested package; it does not establish a
            # missing locally declared provider. Preserve dependencies because
            # flags and installed-provider preference affect actual selection.
            unknown = True
        elif command in {"env", "cross-env", "cross-env-shell", "sh", "bash", "cmd", "powershell", "concurrently", "npm-run-all", "run-s", "run-p"}:
            commands.append(command)
            unknown = True
        elif command.startswith(("./", "../", "/")):
            unknown = True
        elif command in {"node", "nodejs", "bun", "deno"}:
            commands.append(command)
            if any(value in {"-e", "--eval", "-p", "--print"} or value.startswith(("--eval=", "--print=", "../", "/")) for value in rest):
                unknown = True
        else:
            commands.append(command)
    return commands, unknown


def _script_preloads(script):
    if not isinstance(script, str):
        return set()
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return set()
    names, segments, segment = set(), [], []
    for token in tokens:
        if token in {";", "&&", "||", "|", "&"}:
            segments.append(segment)
            segment = []
        else:
            segment.append(token)
    segments.append(segment)
    flags = {"-r", "--require", "--import", "--loader", "--experimental-loader"}
    for tokens in segments:
        while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
            tokens = tokens[1:]
        if not tokens or tokens[0] not in {"node", "nodejs", "bun"}:
            continue
        for index, token in enumerate(tokens):
            if token in flags and index + 1 < len(tokens):
                value = tokens[index + 1]
            elif any(token.startswith(flag + "=") for flag in flags):
                value = token.split("=", 1)[1]
            else:
                continue
            name = _package_name(value)
            if name:
                names.add(name)
    return names


def _plugin_names(data):
    names, unknown = set(), False
    prettier = data.get("prettier")
    if isinstance(prettier, str):
        name = _package_name(prettier)
        if name:
            names.add(name)
        else:
            unknown = True
    if isinstance(prettier, dict):
        plugins = prettier.get("plugins", [])
        if not isinstance(plugins, list):
            unknown = True
        else:
            for plugin in plugins:
                if isinstance(plugin, str) and _package_name(plugin):
                    names.add(_package_name(plugin))
                else:
                    unknown = True
    babel = data.get("babel")
    if isinstance(babel, dict):
        unknown |= bool({"extends", "env", "overrides"} & babel.keys())
        for key, prefix in (("plugins", "babel-plugin-"), ("presets", "babel-preset-")):
            values = babel.get(key, [])
            if not isinstance(values, list):
                unknown = True
                continue
            for value in values:
                value = value[0] if isinstance(value, list) and value else value
                if not isinstance(value, str):
                    unknown = True
                elif value.startswith((".", "/")):
                    unknown = True
                elif value.startswith("@babel/"):
                    names.add(value if value.rsplit("/", 1)[-1].startswith(("plugin-", "preset-")) else value.replace("@babel/", "@babel/" + prefix.removeprefix("babel-")))
                else:
                    names.add(value if value.startswith(prefix) or value.startswith("@") else prefix + value)
    eslint = data.get("eslintConfig")
    if isinstance(eslint, dict):
        unknown |= "overrides" in eslint
        plugins = eslint.get("plugins", [])
        if not isinstance(plugins, list):
            unknown = True
            plugins = []
        for plugin in plugins:
            if not isinstance(plugin, str):
                unknown = True
            elif plugin.startswith("@"):
                names.add(plugin if "/" in plugin else plugin + "/eslint-plugin")
            else:
                names.add(plugin if plugin.startswith("eslint-plugin-") else "eslint-plugin-" + plugin)
        parser = eslint.get("parser")
        if isinstance(parser, str):
            names.add(parser)
        extends = eslint.get("extends", [])
        extends = [extends] if isinstance(extends, str) else extends
        if isinstance(extends, list):
            for value in extends:
                if not isinstance(value, str):
                    unknown = True
                elif value.startswith("eslint:"):
                    continue
                elif value.startswith("plugin:"):
                    plugin = value[7:].rsplit("/", 1)[0]
                    names.add(plugin + "/eslint-plugin" if plugin.startswith("@") and "/" not in plugin else plugin if plugin.startswith("@") else "eslint-plugin-" + plugin)
                elif value.startswith((".", "/")):
                    unknown = True
                elif value.startswith("@"):
                    unknown = True  # Scoped config shorthand is not ordinary npm identity.
                else:
                    names.add(value if value.startswith("eslint-config-") else "eslint-config-" + value)
        else:
            unknown = True
    return names, unknown


def _configured_package_targets(value):
    """Package import/export conditions can name a dependency without source syntax."""
    names, pending, count = set(), [value], 0
    while pending:
        current = pending.pop()
        count += 1
        if count > MAX_NODES:
            return None
        if isinstance(current, str):
            name = _package_name(current)
            if name:
                names.add(name)
        elif isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return names


def _configured_virtual_modules(root, package, data):
    """Virtual CSS requires an actual stable UnoCSS plugin in Vite's config."""
    from skylos.core.js_ast import iter_import_clause_bindings
    from skylos.visitors.languages.typescript.core import TypeScriptCore
    from skylos.visitors.languages.typescript.namespace_references import _pattern_names

    if not any(isinstance(data.get(field), dict) and "unocss" in data[field] for field in DEPENDENCY_FIELDS):
        return set()
    for extension in ("ts", "mts", "cts", "js", "mjs", "cjs"):
        path = package / f"vite.config.{extension}"
        text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
        if text is None:
            continue
        core = TypeScriptCore(str(path), text.encode("utf-8"))
        tree, source = core.root_node, core.source
        if tree is None or tree.has_error:
            continue
        factories, config_functions, import_names = set(), set(), defaultdict(int)
        for statement in tree.named_children:
            if statement.type != "import_statement":
                continue
            provider = _literal(source, statement.child_by_field_name("source"))
            clause = next((part for part in statement.named_children if part.type == "import_clause"), None)
            if clause is None:
                continue
            for binding in iter_import_clause_bindings(source, clause):
                import_names[binding.local] += 1
                if binding.type_only:
                    continue
                if provider == "unocss/vite" and binding.kind == "default":
                    factories.add(binding.local)
                if provider in {"vite", "vitest/config"} and binding.imported == "defineConfig":
                    config_functions.add(binding.local)
        protected = factories | config_functions
        if not factories:
            continue
        rebound = any(import_names[name] != 1 for name in protected)
        for node in _nodes(tree):
            if node.type in {"variable_declarator", "function_declaration", "class_declaration", "enum_declaration"}:
                if any(_text(source, name) in protected for name in _pattern_names(node.child_by_field_name("name"))):
                    rebound = True
            if node.type in {"formal_parameters", "required_parameter", "optional_parameter"}:
                if any(_text(source, name) in protected for name in _pattern_names(node)):
                    rebound = True
            if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
                target = node.child_by_field_name("left") or node.child_by_field_name("argument")
                if target is not None and _text(source, target) in protected:
                    rebound = True
        if rebound:
            continue
        for statement in tree.named_children:
            if statement.type != "export_statement" or not any(part.type == "default" for part in statement.children):
                continue
            config = next((part for part in statement.named_children if part.type in {"object", "call_expression"}), None)
            if config is not None and config.type == "call_expression":
                function = config.child_by_field_name("function")
                args = config.child_by_field_name("arguments")
                if _text(source, function) not in config_functions or args is None or len(args.named_children) != 1:
                    continue
                config = args.named_children[0]
            if config is None or config.type != "object":
                continue
            # Spreads or duplicate keys can replace the visible plugin list.
            if any(part.type != "pair" and part.type != "comment" for part in config.named_children):
                continue
            plugin_pairs = [part for part in config.named_children if part.type == "pair" and _text(source, part.child_by_field_name("key")).strip("'\"") == "plugins"]
            if len(plugin_pairs) != 1:
                continue
            plugins = plugin_pairs[0].child_by_field_name("value")
            if plugins is None or plugins.type != "array":
                continue
            for plugin in plugins.named_children:
                if plugin.type != "call_expression":
                    continue
                function = plugin.child_by_field_name("function")
                if function is not None and function.type == "identifier" and _text(source, function) in factories:
                    return {"uno.css"}
    return set()


def scan_npm_dependencies(project_root, files, *, workspace_inventory=None, coverage=None, complete_scope=True):
    """Return quality findings for proven npm usage within package ownership.

    Only source files included by the caller may provide import evidence. An
    on-disk source missing from that inventory blocks unused checks, preserving
    correctness for changed-file, excluded and component-only scans.
    """
    root = Path(project_root).resolve()
    receipt = coverage if coverage is not None else {}
    receipt.update(status="complete", complete=True, reasons=[], packages=[], abstained_dependencies=[])
    observed, total, walked, walk_error = [], 0, 0, False
    opaque_inventory = []
    def walk_failed(error):
        opaque_inventory.append({"kind": "unreadable_source_directory", "file": str(error.filename)})

    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_failed):
        walked += 1 + len(dirs) + len(names)
        if walked > MAX_WALK_ENTRIES:
            walk_error = True
            break
        for name in dirs:
            if name not in SKIP_DIRS and (Path(directory) / name).is_symlink():
                opaque_inventory.append({"kind": "symlink_source_directory", "file": str(Path(directory) / name)})
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            command_config = name in {"Makefile", "Procfile", "Dockerfile", "Containerfile", ".gitlab-ci.yml"} or (".github" in path.parts and "workflows" in path.parts and path.suffix in {".yml", ".yaml"})
            if command_config:
                opaque_inventory.append({"kind": "unmodelled_command_file", "file": str(path)})
            if name == "package.json" or (name.startswith("tsconfig") and name.endswith(".json")) or name in JSON_CONFIGS | OPAQUE_CONFIGS or path.suffix in SOURCE_SUFFIXES | COMPONENT_SUFFIXES | OPAQUE_SOURCE_SUFFIXES:
                observed.append(path)
                total += 1
                if total > MAX_FILES:
                    walk_error = True
                    break
        if walk_error:
            break
    if walk_error:
        opaque_inventory.append({"kind": "source_inventory_budget"})
    manifests, source_text = {}, {}
    for path in observed:
        if path.name != "package.json":
            continue
        text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
        try:
            data = json.loads(text) if text is not None else None
        except (ValueError, TypeError, RecursionError):
            data = None
        if not isinstance(data, dict):
            opaque_inventory.append({"kind": "unreadable_manifest", "file": str(path)})
            continue
        manifests[path.parent] = data
        source_text[path.parent] = text
    if not manifests:
        receipt.update(status="not_run", complete=False, reasons=opaque_inventory)
        return []
    roots = sorted(manifests, key=lambda path: len(path.parts), reverse=True)

    def owner(path):
        return next((package for package in roots if path.is_relative_to(package)), None)

    unknown = defaultdict(list)
    for package in roots:
        unknown[package].extend(opaque_inventory)
    used = defaultdict(set)
    imports = defaultdict(list)
    selected = {Path(path).absolute() for path in files}
    package_names = {data.get("name") for data in manifests.values() if isinstance(data.get("name"), str)}
    from skylos.visitors.languages.typescript.resolve import MonorepoResolver

    resolver = MonorepoResolver(str(root))
    virtual_modules = {package: _configured_virtual_modules(root, package, data) for package, data in manifests.items()}
    bytes_read = 0
    for path in observed:
        if path.name == "package.json":
            continue
        package = owner(path)
        if package is None:
            continue
        if path.name in OPAQUE_CONFIGS:
            unknown[package].append({"kind": "unresolved_plugin_config", "file": str(path)})
            continue
        if path.name.startswith("tsconfig") and path.name.endswith(".json"):
            from skylos.visitors.languages.typescript.workspace import _strip_json_comments, _strip_trailing_commas

            config_text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
            try:
                config_data = json.loads(_strip_trailing_commas(_strip_json_comments(config_text))) if config_text is not None else None
            except (TypeError, ValueError):
                config_data = None
            if not isinstance(config_data, dict):
                unknown[package].append({"kind": "unreadable_typescript_config", "file": str(path)})
                continue
            parents = config_data.get("extends", [])
            parents = [parents] if isinstance(parents, str) else parents
            if not isinstance(parents, list):
                parents = []
                unknown[package].append({"kind": "unresolved_typescript_config", "file": str(path)})
            options = config_data.get("compilerOptions", {})
            plugins = options.get("plugins", []) if isinstance(options, dict) else None
            if not isinstance(plugins, list):
                unknown[package].append({"kind": "unresolved_typescript_plugins", "file": str(path)})
                plugins = []
            for value in parents + [plugin.get("name") if isinstance(plugin, dict) else None for plugin in plugins]:
                name = _package_name(value)
                if name:
                    used[package].add(name)
                    imports[package].append((name, path, 1))
                else:
                    unknown[package].append({"kind": "unresolved_typescript_config_provider", "file": str(path)})
            continue
        if path.name in JSON_CONFIGS:
            config_text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
            try:
                config_data = json.loads(config_text) if config_text is not None else None
            except ValueError:
                config_data = None
            if not isinstance(config_data, dict):
                unknown[package].append({"kind": "unreadable_plugin_config", "file": str(path)})
                continue
            field = "eslintConfig" if path.name.startswith(".eslintrc") else "prettier" if path.name.startswith(".prettierrc") else "babel"
            configured, config_unknown = _plugin_names({field: config_data})
            used[package].update(configured)
            imports[package].extend((name, path, 1) for name in configured)
            if config_unknown:
                unknown[package].append({"kind": "unresolved_plugin_config", "file": str(path)})
            continue
        if path.suffix in COMPONENT_SUFFIXES | OPAQUE_SOURCE_SUFFIXES or path not in selected:
            unknown[package].append({"kind": "unanalysed_source", "file": str(path)})
            continue
        text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
        if text is None or bytes_read + len(text.encode("utf-8")) > MAX_TOTAL_BYTES:
            unknown[package].append({"kind": "unreadable_source", "file": str(path)})
            continue
        bytes_read += len(text.encode("utf-8"))
        items, limitations = _source_imports(path, text)
        unknown[package].extend(limitations)
        for specifier, line in items:
            if specifier in virtual_modules[package]:
                continue
            name = _package_name(specifier)
            if name is None:
                continue
            if name == manifests[package].get("name"):
                continue
            if name not in package_names and resolver.claims_local_source(specifier, str(path)):
                continue
            imports[package].append((name, path, line))
            used[package].add(name)
    findings = []
    # Children supply source evidence for shared ancestor tooling before the
    # ancestor's absence check is evaluated.
    for package in roots:
        data, manifest = manifests[package], package / "package.json"
        declared, sections = set(), {}
        for field in DEPENDENCY_FIELDS:
            values = data.get(field, {})
            if not isinstance(values, dict):
                unknown[package].append({"kind": "invalid_dependency_map", "field": field})
                continue
            for name in values:
                declared.add(name)
                sections.setdefault(name, field)
        configured, config_unknown = _plugin_names(data)
        for field in ("imports", "exports", "browser"):
            targets = _configured_package_targets(data.get(field))
            if targets is None:
                config_unknown = True
            else:
                configured.update(targets)
        used[package].update(configured)
        if _OPAQUE_MANIFEST_CONFIGS & data.keys():
            unknown[package].append({"kind": "unmodelled_tool_config"})
        if config_unknown:
            unknown[package].append({"kind": "unresolved_plugin_config"})
        for name in configured:
            imports[package].append((name, manifest, _line(source_text[package], "eslintConfig")))
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            scripts = {}
            unknown[package].append({"kind": "invalid_scripts"})
        available = set(declared)
        for ancestor in roots:
            if ancestor != package and package.is_relative_to(ancestor):
                for field in DEPENDENCY_FIELDS:
                    values = manifests[ancestor].get(field, {})
                    if isinstance(values, dict):
                        available.update(values)
        providers = dict(BINARY_PROVIDERS)
        for name in available:
            # Exact name equality establishes a plausible CLI identity only
            # for retaining usage; unknown commands never prove absence.
            providers.setdefault(name, name)
            meta = read_project_text_no_symlink(root, package / "node_modules" / name / "package.json", max_bytes=MAX_BYTES)
            try:
                installed = json.loads(meta) if meta else {}
            except ValueError:
                installed = {}
            bins = installed.get("bin", {}) if isinstance(installed, dict) else {}
            if isinstance(bins, dict):
                for binary in bins:
                    if providers.get(binary) in available and providers[binary] != name:
                        unknown[package].append({"kind": "ambiguous_binary_provider", "binary": binary})
                    providers[binary] = name
            elif isinstance(bins, str):
                providers[name.rsplit("/", 1)[-1]] = name
        for script_name, script in scripts.items():
            preloads = _script_preloads(script)
            used[package].update(preloads)
            imports[package].extend((name, manifest, _line(source_text[package], script_name)) for name in preloads)
            commands, dynamic = _script_commands(script, scripts)
            if dynamic:
                unknown[package].append({"kind": "unresolved_script", "script": script_name})
            for command in commands:
                if command in SYSTEM_COMMANDS and command not in providers:
                    continue
                provider = providers.get(command)
                if provider is None:
                    unknown[package].append({"kind": "unknown_binary_provider", "binary": command})
                    continue
                if provider in available:
                    # Root tooling used by a workspace is evidence for the
                    # root declaration, without crediting sibling manifests.
                    for declaration_owner in roots:
                        if package.is_relative_to(declaration_owner) and any(isinstance(manifests[declaration_owner].get(field), dict) and provider in manifests[declaration_owner][field] for field in DEPENDENCY_FIELDS):
                            used[declaration_owner].add(provider)
                elif not dynamic:
                    findings.append(_finding(RULE_BINARY, command, manifest, _line(source_text[package], script_name), f"Package script '{script_name}' invokes '{command}' without a declared npm provider ('{provider}').", package_name=provider, package_manifest=str(manifest), script=script_name))
        seen = set()
        for name, path, line in imports[package]:
            key = name, str(path), line
            if name not in declared and key not in seen:
                findings.append(_finding(RULE_UNLISTED, name, path, line, f"Package '{name}' is used but is not declared by this package's package.json.", package_name=name, package_manifest=str(manifest)))
                seen.add(key)
        # Peer dependencies are published consumer contracts, not unused
        # implementation dependencies. Type packages can be implicitly loaded.
        candidates = {name for name in declared - used[package] if sections[name] != "peerDependencies" and not name.startswith("@types/")}
        if walk_error or not complete_scope:
            unknown[package].append({"kind": "incomplete_source_scope"})
        if unknown[package]:
            receipt["abstained_dependencies"].extend({"package_manifest": str(manifest), "name": name} for name in sorted(candidates))
            receipt["reasons"].extend({"package_manifest": str(manifest), **reason} for reason in unknown[package])
            for ancestor in roots:
                if ancestor != package and package.is_relative_to(ancestor):
                    unknown[ancestor].append({"kind": "unresolved_workspace_consumer", "package_manifest": str(manifest)})
        else:
            for name in sorted(candidates):
                findings.append(_finding(RULE_UNUSED, name, manifest, _line(source_text[package], name), f"Declared npm dependency '{name}' has no source import, package-script command or supported tool-config use in this package.", package_name=name, package_manifest=str(manifest), dependency_section=sections[name]))
        receipt["packages"].append(str(manifest))
    receipt["abstained_count"] = len(receipt["abstained_dependencies"])
    if receipt["reasons"]:
        receipt.update(status="incomplete", complete=False)
    return findings
