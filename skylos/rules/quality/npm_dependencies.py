"""Bounded npm dependency usage from source, package scripts and tool configs.

No package code or package-manager commands are executed. Missing source and
dynamic loaders prevent an absence claim for the owning package. An unknown
script command only holds back the declared dependencies that could plausibly
provide it; it never makes a dependency look unused.
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.quality.npm_commands import (
    _ASSIGNMENT,
    _BIN_NAME,
    _GHA_EXPRESSION,
    _PACKAGE,
    _URL,
    MAX_COMMAND_FILE_DEPTH,
    SYSTEM_COMMANDS,
    _command_file_lines,
    _command_lines,
    _script_commands,
    _segments,
    _shell_script,
    _tokens,
    _unknown_words,
    _yaml_documents,
)
from skylos.rules.quality.npm_lockfiles import lockfile_facts
from skylos.visitors.languages.typescript.plugin_facts import (
    config_file_names as _plugin_config_file_names,
)
from skylos.visitors.languages.typescript.plugin_facts import (
    is_plugin_config_path as _is_plugin_config_path,
)
from skylos.visitors.languages.typescript.plugin_facts import (
    text_fixture_directories as _text_fixture_directories,
)
from skylos.visitors.languages.typescript.static_config import (
    parse_data_config as _parse_data_config,
)

RULE_UNUSED = "SKY-U005"
RULE_UNLISTED = "SKY-Q408"
RULE_BINARY = "SKY-Q409"
RULE_CATALOG_UNUSED = "SKY-Q411"
RULE_CATALOG_UNRESOLVED = "SKY-Q412"
RULE_OPTIONAL_PEER = "SKY-Q413"
MAX_FILES = 20_000
MAX_WALK_ENTRIES = 100_000
MAX_BYTES = 2_000_000
MAX_TOTAL_BYTES = 32_000_000
MAX_NODES = 50_000
SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
TYPESCRIPT_SUFFIXES = {".ts", ".tsx", ".mts", ".cts"}
# Component and stylesheet files are read as text: script/ESM blocks are
# parsed as TypeScript and stylesheet at-rules are matched literally.
COMPONENT_SUFFIXES = {".vue", ".svelte", ".astro"}
MDX_SUFFIXES = {".mdx"}
STYLESHEET_SUFFIXES = {".css", ".scss", ".sass", ".less", ".pcss", ".postcss"}
OPAQUE_SOURCE_SUFFIXES = {".marko"}
NPM_ASSET_SUFFIXES = frozenset(COMPONENT_SUFFIXES | MDX_SUFFIXES | STYLESHEET_SUFFIXES)
# A compiled single-file component imports its framework runtime.
COMPONENT_RUNTIMES = {".vue": "vue", ".svelte": "svelte", ".astro": "astro"}
# Bundlers compile preprocessor stylesheets with whichever of these is installed.
STYLESHEET_COMPILERS = {
    "scss": ("sass", "sass-embedded", "node-sass"), "sass": ("sass", "sass-embedded", "node-sass"),
    "less": ("less",), "stylus": ("stylus",), "styl": ("stylus",),
}
# CLI flags that load an optional package of the same tool. The flag may
# reach the tool through a script alias (``yarn test --ui``).
RUNNER_FLAG_PLUGINS = {
    "vitest": {"--ui": ("@vitest/ui",), "--coverage": ("@vitest/coverage-v8", "@vitest/coverage-istanbul"), "--browser": ("@vitest/browser",)},
    "expo": {"--web": ("react-native-web", "react-dom", "@expo/metro-runtime")},
}
# CLI subcommands that load a separate package (``astro check``).
RUNNER_SUBCOMMAND_PLUGINS = {
    "astro": {"check": ("@astrojs/check", "typescript")},
    "nuxt": {"typecheck": ("vue-tsc", "typescript")}, "nuxi": {"typecheck": ("vue-tsc", "typescript")},
}
# Framework workspace configs that name builders, polyfills and plugins as
# strings (``"builder": "@angular/build:application"``).
DATA_CONFIGS = {"angular.json", "project.json", "workspace.json", "app.json", "app.config.json", "nest-cli.json"}
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "dist", "build", "coverage", ".next", ".nuxt"}
VCS_DIRS = {".git", ".hg", ".svn"}
DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
JSON_CONFIGS = {".eslintrc", ".eslintrc.json", ".babelrc", ".babelrc.json", "babel.config.json", ".prettierrc", ".prettierrc.json"}
OPAQUE_CONFIGS = {".eslintrc.js", ".eslintrc.cjs", ".eslintrc.yml", ".eslintrc.yaml", "babel.config.js", "babel.config.cjs", ".babelrc.js", ".babelrc.cjs", "prettier.config.js", "prettier.config.cjs", ".prettierrc.js", ".prettierrc.cjs", ".prettierrc.yml", ".prettierrc.yaml"}
# PostCSS plugin maps name packages by string keys, not imports. Literal
# object/array configs are read statically; anything else stays opaque.
POSTCSS_DATA_CONFIGS = {".postcssrc", ".postcssrc.json", "postcss.config.json", ".postcssrc.yml", ".postcssrc.yaml"}
POSTCSS_SCRIPT_CONFIGS = {f"{stem}.{extension}" for stem in ("postcss.config", ".postcssrc") for extension in ("js", "mjs", "cjs", "ts", "mts", "cts")}
_OPAQUE_MANIFEST_CONFIGS = {"jest", "ava", "mocha", "nyc", "lint-staged", "commitlint", "release", "stylelint", "xo"}
# Well-known CLIs whose package name differs from the command. Commands not
# listed here resolve through installed or workspace bin metadata, or by the
# command naming a declared package.
BINARY_PROVIDERS = {
    "tsc": ("typescript",), "tsserver": ("typescript",), "babel": ("@babel/cli",),
    "babel-node": ("@babel/node",), "ng": ("@angular/cli",), "nest": ("@nestjs/cli",),
    "webpack": ("webpack-cli", "webpack"), "webpack-dev-server": ("webpack-dev-server",),
    "playwright": ("@playwright/test", "playwright"), "changeset": ("@changesets/cli",),
    "biome": ("@biomejs/biome",), "run-s": ("npm-run-all", "npm-run-all2"),
    "run-p": ("npm-run-all", "npm-run-all2"), "npm-run-all": ("npm-run-all", "npm-run-all2"),
    "firebase": ("firebase-tools",), "netlify": ("netlify-cli",), "ntl": ("netlify-cli",),
    "eas": ("eas-cli",), "cz": ("commitizen",), "git-cz": ("commitizen",),
    "gql-gen": ("@graphql-codegen/cli",), "graphql-codegen": ("@graphql-codegen/cli",),
    "graphql-code-generator": ("@graphql-codegen/cli",), "lessc": ("less",),
    "vue-cli-service": ("@vue/cli-service",), "vue": ("@vue/cli",),
    "svelte-kit": ("@sveltejs/kit",), "remix": ("@remix-run/dev",),
    "react-router": ("@react-router/dev",), "docusaurus": ("@docusaurus/core",),
    "nuxi": ("nuxi", "nuxt", "@nuxt/cli"), "nuxt": ("nuxt", "nuxi"), "sb": ("storybook",),
    "start-storybook": ("@storybook/cli", "storybook"), "build-storybook": ("@storybook/cli", "storybook"),
    "tailwindcss": ("tailwindcss", "@tailwindcss/cli"), "tailwind": ("tailwindcss", "@tailwindcss/cli"),
    "lhci": ("@lhci/cli",), "cap": ("@capacitor/cli",), "ionic": ("@ionic/cli",),
    "api-extractor": ("@microsoft/api-extractor",), "api-documenter": ("@microsoft/api-documenter",),
    "rush": ("@microsoft/rush",), "heft": ("@rushstack/heft",), "swc": ("@swc/cli",),
    "spack": ("@swc/cli",), "rspack": ("@rspack/cli",), "rsbuild": ("@rsbuild/core",),
    "rslib": ("@rslib/core",), "commitlint": ("@commitlint/cli",), "wrangler": ("wrangler",),
    "vercel": ("vercel",), "cdk": ("aws-cdk",), "sls": ("serverless",), "serverless": ("serverless",),
    "amplify": ("@aws-amplify/cli",), "attw": ("@arethetypeswrong/cli",), "ncu": ("npm-check-updates",),
    "tsnd": ("ts-node-dev",), "ts-node-esm": ("ts-node",), "ts-node-script": ("ts-node",),
    "server-test": ("start-server-and-test",), "start-test": ("start-server-and-test",),
    "vsce": ("@vscode/vsce", "vsce"), "vscode-test": ("@vscode/test-cli",),
    "wdio": ("@wdio/cli",), "percy": ("@percy/cli",), "electron-forge": ("@electron-forge/cli",),
    "mikro-orm": ("@mikro-orm/cli",), "openapi-generator-cli": ("@openapitools/openapi-generator-cli",),
    "orval": ("orval",), "buf": ("@bufbuild/buf",), "grpc_tools_node_protoc": ("grpc-tools",),
    "prisma": ("prisma",), "drizzle-kit": ("drizzle-kit",), "sequelize": ("sequelize-cli",),
    "typeorm": ("typeorm",), "knex": ("knex",), "jest": ("jest",), "vitest": ("vitest",),
    "vite": ("vite",), "eslint": ("eslint",), "prettier": ("prettier",), "tsx": ("tsx",),
    "ts-node": ("ts-node",), "rollup": ("rollup",), "esbuild": ("esbuild",), "next": ("next",),
    "astro": ("astro",), "storybook": ("storybook",), "expo": ("expo", "expo-cli"),
    "react-native": ("react-native", "@react-native-community/cli"),
    "react-scripts": ("react-scripts",), "craco": ("@craco/craco",), "lerna": ("lerna",),
    "nx": ("nx",), "turbo": ("turbo",), "manypkg": ("@manypkg/cli",), "syncpack": ("syncpack",),
    "postcss": ("postcss-cli",), "sass": ("sass", "sass-embedded"), "node-sass": ("node-sass",),
    "stylus": ("stylus",), "dotenv": ("dotenv-cli",), "env-cmd": ("env-cmd",),
    "cross-env": ("cross-env",), "cross-env-shell": ("cross-env",), "concurrently": ("concurrently",),
    "chokidar": ("chokidar-cli",), "markdownlint": ("markdownlint-cli",),
    "markdownlint-cli2": ("markdownlint-cli2",), "c8": ("c8",), "nyc": ("nyc",),
    "mocha": ("mocha",), "_mocha": ("mocha",), "ava": ("ava",), "tap": ("tap",),
    "cypress": ("cypress",), "ng-packagr": ("ng-packagr",), "parcel": ("parcel", "parcel-bundler"),
    "microbundle": ("microbundle",), "tsup": ("tsup",), "tsdown": ("tsdown",), "unbuild": ("unbuild",),
    "pkgroll": ("pkgroll",), "typedoc": ("typedoc",), "husky": ("husky",),
    "lint-staged": ("lint-staged",), "semantic-release": ("semantic-release",),
    "release-it": ("release-it",), "standard-version": ("standard-version",),
    "rimraf": ("rimraf",), "del-cli": ("del-cli",), "shx": ("shx",),
    "copyfiles": ("copyfiles",), "cpy": ("cpy-cli",), "mkdirp": ("mkdirp",),
    "nodemon": ("nodemon",), "pm2": ("pm2",), "serve": ("serve",), "http-server": ("http-server",),
    "patch-package": ("patch-package",), "vue-tsc": ("vue-tsc",), "svelte-check": ("svelte-check",),
    "tsc-alias": ("tsc-alias",), "oxlint": ("oxlint",), "stylelint": ("stylelint",),
    "electron": ("electron",), "electron-builder": ("electron-builder",), "jiti": ("jiti",),
    "vite-node": ("vite-node",), "zx": ("zx",), "size-limit": ("size-limit",),
    "publint": ("publint",), "knip": ("knip",), "cspell": ("cspell",), "dprint": ("dprint",),
    "relay-compiler": ("relay-compiler",), "apollo": ("apollo",), "gatsby": ("gatsby",),
    "vuepress": ("vuepress",), "vitepress": ("vitepress",), "nodemon-webpack-plugin": ("nodemon-webpack-plugin",),
    # Compilers and framework CLIs whose binary is named after the tool, not
    # the package that ships it.
    "ngc": ("@angular/compiler-cli",), "ngcc": ("@angular/compiler-cli",),
    "ng-xi18n": ("@angular/compiler-cli",), "svelte-package": ("@sveltejs/package",),
    "svelte-migrate": ("svelte-migrate",), "vue-demi-switch": ("vue-demi",), "vue-demi-fix": ("vue-demi",),
    "tsgo": ("@typescript/native-preview",), "ttsc": ("ttypescript",), "stencil": ("@stencil/core",),
    "glint": ("@glint/core",), "qwik": ("@builder.io/qwik",), "ncc": ("@vercel/ncc",),
    "napi": ("@napi-rs/cli",), "tauri": ("@tauri-apps/cli",), "svgr": ("@svgr/cli",),
    "lingui": ("@lingui/cli",), "gulp": ("gulp", "gulp-cli"), "grunt": ("grunt-cli", "grunt"),
    "ember": ("ember-cli",), "tsgolint": ("oxlint-tsgolint",), "lefthook": ("lefthook", "@evilmartians/lefthook"),
    "jscodeshift": ("jscodeshift",), "premove": ("premove",), "sherif": ("sherif",),
}
# A dependency used by a framework is also used through the peers that the
# framework requires at runtime, even when no source imports them directly.
# Installed package manifests add their literal peerDependencies to this.
KNOWN_PEER_CONTRACTS = {
    "next": ("react", "react-dom"), "react-dom": ("react",), "react-native": ("react",),
    "@next/mdx": ("@mdx-js/loader", "@mdx-js/react"), "@remix-run/react": ("react", "react-dom"),
    "gatsby": ("react", "react-dom"), "@docusaurus/core": ("react", "react-dom", "@mdx-js/react"),
    "@docusaurus/tsconfig": ("@docusaurus/module-type-aliases", "@docusaurus/theme-classic"),
    "@tsconfig/docusaurus": ("@docusaurus/module-type-aliases", "@docusaurus/theme-classic"),
    "@testing-library/react": ("react-dom", "@testing-library/dom"), "react-router-dom": ("react", "react-dom"),
    "@vitejs/plugin-react": ("vite",), "@vitejs/plugin-vue": ("vite", "vue"), "ts-jest": ("jest", "typescript"),
    # Angular packages require their framework peers; zone.js is the
    # change-detection peer of @angular/core.
    "@angular/core": ("rxjs", "zone.js"), "@angular/common": ("@angular/core", "rxjs"),
    "@angular/platform-browser": ("@angular/common", "@angular/core"),
    "@angular/platform-browser-dynamic": ("@angular/common", "@angular/compiler", "@angular/core", "@angular/platform-browser"),
    "@angular/platform-server": ("@angular/common", "@angular/compiler", "@angular/core", "@angular/platform-browser"),
    "@angular/router": ("@angular/common", "@angular/core", "@angular/platform-browser", "rxjs"),
    "@angular/forms": ("@angular/common", "@angular/core", "@angular/platform-browser", "rxjs"),
    "@angular/ssr": ("@angular/common", "@angular/core", "@angular/platform-server", "@angular/router"),
    "@angular/build": ("@angular/compiler", "@angular/compiler-cli", "typescript"),
    "@angular-devkit/build-angular": ("@angular/compiler-cli", "typescript"),
    "@angular/compiler-cli": ("@angular/compiler", "typescript"),
    "@analogjs/vite-plugin-angular": ("@angular/build", "@angular/compiler-cli"),
    "@testing-library/angular": ("@angular/common", "@angular/core", "@angular/platform-browser", "@angular/router", "@testing-library/dom"),
    "graphql-request": ("graphql",), "@apollo/client": ("graphql",),
    "@react-navigation/native": ("react-native-safe-area-context", "react-native-screens"),
    "@react-navigation/stack": ("@react-navigation/native", "react-native-gesture-handler", "react-native-safe-area-context", "react-native-screens"),
    "nuxt": ("vue", "vue-router"), "babel-loader": ("@babel/core", "webpack"),
}
_GENERIC_NAME_TOKENS = {"cli", "core", "js", "node", "bin", "tool", "tools", "dev", "run", "plugin", "config", "app", "the", "npm", "env"}
# Shareable configs, plugins, presets and type packages extend a tool; none
# of them ships the tool's own binary (eslint-config-x never provides eslint).
_NON_BINARY_TOKENS = {"config", "configs", "plugin", "plugins", "preset", "presets"}
_CATALOG_SCRIPT_REFERENCE = re.compile(r"((?:@[\w.~-]+/)?[\w.~-]+)@catalog:([\w.~-]*)")


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


def _type_only_statement(source, node):
    """Report whether an import/export-from statement is erased at runtime."""
    from skylos.core.js_ast import is_type_only, iter_import_clause_bindings

    if is_type_only(node):
        return True
    clause = next((part for part in node.named_children if part.type == "import_clause"), None)
    if clause is not None:
        bindings = list(iter_import_clause_bindings(source, clause))
        return bool(bindings) and all(binding.type_only for binding in bindings)
    exports = next((part for part in node.named_children if part.type == "export_clause"), None)
    if exports is not None:
        specifiers = [part for part in exports.named_children if part.type == "export_specifier"]
        return bool(specifiers) and all(is_type_only(part) for part in specifiers)
    return False


_REFERENCE_TYPES = re.compile(r"///\s*<reference\b[^>]*\btypes\s*=\s*(?:\"([^\"]+)\"|'([^']+)')")
# Calls that always return an absolute path or file URL: a module loaded by
# such a specifier is a local file, never an npm package.
_ABSOLUTE_PATH_CALLS = {"path.resolve", "resolve", "path.posix.resolve", "path.win32.resolve", "fileURLToPath", "url.fileURLToPath", "process.cwd", "pathToFileURL", "url.pathToFileURL"}
_JOIN_PATH_CALLS = {"path.join", "join", "path.posix.join", "path.normalize", "path.dirname", "dirname"}
_PATH_GLOBALS = {"__dirname", "__filename"}


def _call_argument(args):
    """The first argument of a call, skipping bundler magic comments."""
    if args is None:
        return None
    return next((child for child in args.named_children if child.type != "comment"), None)


def _static_string(source, node, depth=0):
    """Evaluate literal string expressions (``"a" + "b"``, ``["fs"].join()``)."""
    if node is None or depth > 8:
        return None
    if node.type in {"string", "template_string"}:
        return _literal(source, node)
    if node.type == "parenthesized_expression" and node.named_children:
        return _static_string(source, node.named_children[0], depth + 1)
    if node.type == "binary_expression" and _text(source, node.child_by_field_name("operator")) == "+":
        left = _static_string(source, node.child_by_field_name("left"), depth + 1)
        right = _static_string(source, node.child_by_field_name("right"), depth + 1)
        return left + right if left is not None and right is not None else None
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if function is None or function.type != "member_expression" or _text(source, function.child_by_field_name("property")) != "join":
            return None
        array = function.child_by_field_name("object")
        if array is None or array.type != "array":
            return None
        parts = [_static_string(source, item, depth + 1) for item in array.named_children if item.type != "comment"]
        arguments = [child for child in (args.named_children if args is not None else []) if child.type != "comment"]
        separator = "," if not arguments else _static_string(source, arguments[0], depth + 1)
        if separator is None or len(arguments) > 1 or any(part is None for part in parts):
            return None
        return separator.join(parts)
    return None


class _PathFacts:
    """Single-assignment bindings used to prove a computed specifier is a path."""

    def __init__(self, source, nodes):
        self.source = source
        self.values, self.functions, counts = {}, {}, defaultdict(int)
        for node in nodes:
            if node.type == "variable_declarator":
                name = node.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    key = _text(source, name)
                    counts[key] += 1
                    value = node.child_by_field_name("value")
                    if value is not None and value.type in {"arrow_function", "function_expression", "function"}:
                        self.functions[key] = value
                    else:
                        self.values[key] = value
            elif node.type == "function_declaration":
                name = node.child_by_field_name("name")
                if name is not None:
                    key = _text(source, name)
                    counts[key] += 1
                    self.functions[key] = node
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                if left is not None and left.type == "identifier":
                    counts[_text(source, left)] += 2  # Reassigned: not a single value.
        ambiguous = {name for name, count in counts.items() if count != 1}
        for name in ambiguous:
            self.values.pop(name, None)
            self.functions.pop(name, None)

    def returns(self, function):
        body = function.child_by_field_name("body")
        if body is None:
            return []
        if body.type != "statement_block":
            return [body]
        found, pending = [], list(body.named_children)
        while pending:
            node = pending.pop()
            if node.type == "return_statement":
                found.append(node.named_children[0] if node.named_children else None)
            elif node.type not in {"function_declaration", "arrow_function", "function_expression", "function", "class_declaration", "method_definition"}:
                pending.extend(node.named_children)
        return found

    def path_like(self, node, depth=0):
        """Whether ``node`` evaluates to an absolute path or file URL."""
        source = self.source
        if node is None or depth > 6:
            return False
        kind = node.type
        if kind in {"parenthesized_expression", "await_expression", "as_expression", "satisfies_expression", "non_null_expression"}:
            return bool(node.named_children) and self.path_like(node.named_children[0], depth + 1)
        if kind == "identifier":
            name = _text(source, node)
            if name in _PATH_GLOBALS:
                return True
            return name in self.values and self.path_like(self.values[name], depth + 1)
        if kind == "member_expression":
            text = _text(source, node)
            if text in {"import.meta.dirname", "import.meta.filename", "import.meta.url"}:
                return True
            # ``pathToFileURL(x).href`` and ``new URL(x, base).href``.
            return _text(source, node.child_by_field_name("property")) in {"href", "pathname"} and self.path_like(node.child_by_field_name("object"), depth + 1)
        if kind in {"string", "template_string"}:
            literal = _literal(source, node)
            if literal is not None:
                return literal.startswith(("/", "file:"))
            if kind == "template_string":
                parts = [child for child in node.named_children if child.type != "string_fragment"]
                first = node.named_children[0] if node.named_children else None
                if first is not None and first.type == "template_substitution" and parts:
                    inner = first.named_children[0] if first.named_children else None
                    return self.path_like(inner, depth + 1)
            return False
        if kind == "binary_expression" and _text(source, node.child_by_field_name("operator")) == "+":
            return self.path_like(node.child_by_field_name("left"), depth + 1)
        if kind == "new_expression":
            constructor = node.child_by_field_name("constructor")
            args = node.child_by_field_name("arguments")
            arguments = [child for child in (args.named_children if args is not None else []) if child.type != "comment"]
            return constructor is not None and _text(source, constructor) == "URL" and len(arguments) == 2 and self.path_like(arguments[1], depth + 1)
        if kind == "call_expression":
            function = node.child_by_field_name("function")
            name = _text(source, function)
            args = node.child_by_field_name("arguments")
            arguments = [child for child in (args.named_children if args is not None else []) if child.type != "comment"]
            if name in _ABSOLUTE_PATH_CALLS:
                return True
            if name in _JOIN_PATH_CALLS:
                return bool(arguments) and self.path_like(arguments[0], depth + 1)
            if function is not None and function.type == "identifier" and name in self.functions:
                results = self.returns(self.functions[name])
                return bool(results) and all(self.path_like(result, depth + 1) for result in results)
        return False


def _source_imports(path, text):
    """Return ``(specifier, line, kind)`` records and analysis limitations.

    ``kind`` is ``static`` for a runtime import/export-from declaration,
    ``type`` for erased type-only syntax, ``dynamic`` for loader calls,
    ``jsdoc`` for a JSDoc ``import()`` type and ``reference`` for a
    ``/// <reference types>`` directive.
    """
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
    facts = None
    for node in nodes:
        if node.type == "comment":
            reference = _REFERENCE_TYPES.match(_text(source, node))
            if reference:
                imports.append((reference.group(1) or reference.group(2), node.start_point[0] + 1, "reference"))
        if node.type == "identifier" and _text(source, node) == "require":
            parent = node.parent
            if parent is not None and parent.type not in {"call_expression", "member_expression"} and not (parent.type == "unary_expression" and _text(source, parent).startswith("typeof")):
                unknown.append({"kind": "escaped_module_loader", "file": str(path)})
        if node.type in {"import_statement", "export_statement"}:
            literal = node.child_by_field_name("source")
            if literal is not None:
                value = _literal(source, literal)
                if value is None:
                    unknown.append({"kind": "escaped_module_specifier", "file": str(path)})
                else:
                    kind = "type" if _type_only_statement(source, node) else "static"
                    imports.append((value, literal.start_point[0] + 1, kind))
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
        arg = _call_argument(args)
        value = _static_string(source, arg)
        if value is None and arg is not None and arg.type == "identifier":
            if facts is None:
                facts = _PathFacts(source, nodes)
            bound = facts.values.get(_text(source, arg))
            value = _static_string(source, bound) if bound is not None else None
        if value is not None:
            imports.append((value, node.start_point[0] + 1, "dynamic"))
            if value in {"module", "node:module"}:
                unknown.append({"kind": "module_loader_capability", "file": str(path)})
            continue
        if arg is not None and arg.type == "template_string" and _text(source, arg).startswith(("`./", "`../", "`/")):
            continue
        if facts is None:
            facts = _PathFacts(source, nodes)
        if arg is not None and facts.path_like(arg):
            continue  # An absolute path or file URL loads a local file.
        unknown.append({"kind": "dynamic_module_specifier", "file": str(path)})
    core.raw_imports = []
    core._raw_import_seen = set()
    core._scan_jsdoc_raw_imports()
    imports.extend((item["source"], item["line"], "jsdoc") for item in core.raw_imports)
    return imports, unknown


def _component_imports(path, text):
    """Read imports from Vue/Svelte/Astro script and style blocks as text."""
    from skylos.deadcode.component_imports import (
        _SCRIPT_LANGUAGES,
        _SCRIPT_TYPES,
        component_blocks,
    )

    scripts, styles, complete = component_blocks(text, path.suffix.lower())
    imports, unknown, stylesheet = [], [], []
    if not complete:
        unknown.append({"kind": "unclosed_component_block", "file": str(path)})
    for attrs, start_line, body in scripts:
        lang = (attrs.get("lang") or "").lower()
        if (attrs.get("type") or "").lower() not in _SCRIPT_TYPES:
            continue  # JSON and other data blocks do not import executable code.
        if lang not in _SCRIPT_LANGUAGES:
            unknown.append({"kind": "unsupported_script_language", "file": str(path), "language": lang})
            continue
        if attrs.get("src"):
            imports.append((attrs["src"], start_line, "static"))
            continue
        suffix = ".tsx" if lang in {"tsx", "jsx"} else ".ts"
        found, limitations = _source_imports(Path(str(path) + suffix), "\n" * (start_line - 1) + body)
        imports.extend(found)
        unknown.extend({**item, "file": str(path)} for item in limitations)
    for attrs, start_line, body in styles:
        lang = (attrs.get("lang") or "css").lower()
        stylesheet.extend((compiler, start_line, False) for compiler in STYLESHEET_COMPILERS.get(lang, ()))
        if lang == "stylus" or lang == "styl":
            if re.search(r"@(?:import|require)\b", body):
                unknown.append({"kind": "unsupported_style_language", "file": str(path), "language": lang})
            continue
        found, limitations = _stylesheet_imports(path, "\n" * (start_line - 1) + body, "." + lang)
        stylesheet.extend(found)
        unknown.extend(limitations)
    return imports, stylesheet, unknown


_MDX_ESM = re.compile(r"(?:import|export)(?=[\s{*\"'])")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# Lines after which a new flow construct starts instead of a paragraph
# continuation: headings, thematic breaks and a JSX element on its own line.
_MDX_FLOW_END = re.compile(r"^ {0,3}(?:#{1,6}(?:[ \t].*)?|(?:[-*_][ \t]*){3,}|<.*>[ \t]*)$")


def _mdx_imports(path, text):
    """Parse top-level MDX ESM blocks; fenced code and prose are ignored."""
    lines = text.splitlines()
    imports, unknown = [], []
    index = 0
    if lines and lines[0].strip() == "---":
        closing = next((number for number in range(1, len(lines)) if lines[number].strip() == "---"), None)
        if closing is None:
            return [], [{"kind": "unclosed_mdx_frontmatter", "file": str(path)}]
        index = closing + 1
    fence = None
    # MDX ESM cannot interrupt a paragraph: an import/export line that
    # continues prose is text, exactly as the MDX compiler reads it.
    flow_start = True
    while index < len(lines):
        line = lines[index]
        marker = _FENCE.match(line)
        if fence is not None:
            if marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence) and not line.strip().strip(fence[0]):
                fence = None
                flow_start = True
            index += 1
            continue
        if marker:
            fence = marker.group(1)
            index += 1
            continue
        if not (flow_start and _MDX_ESM.match(line)):
            flow_start = not line.strip() or bool(_MDX_FLOW_END.match(line))
            index += 1
            continue
        start = index
        while index < len(lines) and lines[index].strip():
            index += 1
        block = "\n" * start + "\n".join(lines[start:index])
        found, limitations = _source_imports(Path(str(path) + ".tsx"), block)
        imports.extend(found)
        for item in limitations:
            kind = "mdx_esm_parse_error" if item["kind"] == "source_parse_error" else item["kind"]
            unknown.append({**item, "kind": kind, "file": str(path)})
        flow_start = True
    if fence is not None:
        unknown.append({"kind": "unclosed_mdx_code_fence", "file": str(path)})
    return imports, unknown


_STYLE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STYLE_LINE_COMMENT = re.compile(r"(^|[\s;{}])//[^\n]*")
_STYLE_AT_RULE = re.compile(r"(?:^|(?<=[;{}]))[ \t]*@(import|use|forward|plugin|config|reference)\b((?:[#@]\{[^}\n]*\}|[^;{}\n])*)", re.MULTILINE)
_STYLE_STRING = re.compile(r"\"([^\"\n]*)\"|'([^'\n]*)'")
_STYLE_PARENS = re.compile(r"\([^()]*\)")
_STYLE_TILDE_URL = re.compile(r"url\(\s*[\"']?~([^\"')\s]+)")
_STYLE_COMPOSES = re.compile(r"composes\s*:[^;{}]*?\bfrom\s+(?:\"([^\"\n]+)\"|'([^'\n]+)')")


def _stylesheet_imports(path, text, suffix):
    """Return ``(package, line, reportable)`` uses from stylesheet at-rules.

    Only Sass ``pkg:`` URLs and Tailwind ``@plugin`` names are unambiguous
    package references. Other bare specifiers may name a local file or a
    load-path entry, so they are usage evidence but never an undeclared
    package claim. Relative paths, URLs and ``url(...)`` arguments are local.
    """
    def blank(match):
        return re.sub(r"[^\n]", " ", match.group(0))

    text = _STYLE_BLOCK_COMMENT.sub(blank, text)
    if suffix in {".scss", ".sass", ".less"}:
        text = _STYLE_LINE_COMMENT.sub(lambda match: match.group(1) + " " * (len(match.group(0)) - len(match.group(1))), text)
    found, unknown = [], []

    def add(specifier, offset, *, rule):
        line = text.count("\n", 0, offset) + 1
        if any(marker in specifier for marker in ("#{", "@{", "$")):
            unknown.append({"kind": "dynamic_stylesheet_import", "file": str(path)})
            return
        reportable = False
        if specifier.startswith("pkg:"):
            specifier, reportable = specifier[4:], True
        elif specifier.startswith("~"):
            specifier = specifier[1:]
        elif rule == "plugin" and suffix in {".css", ".pcss", ".postcss"}:
            # Tailwind resolves a bare @plugin as a module; Less plugins differ.
            reportable = not re.search(r"\.[cm]?[jt]s$", specifier)
        name = _package_name(specifier)
        if name is not None:
            found.append((name, line, reportable))

    for match in _STYLE_AT_RULE.finditer(text):
        rule, params = match.group(1), match.group(2)
        params = params.strip()
        while _STYLE_PARENS.search(params):
            params = _STYLE_PARENS.sub(" ", params)
        params = re.sub(r"\burl\b", " ", params)
        strings = [first or second for first, second in _STYLE_STRING.findall(params)]
        if not strings and suffix == ".sass" and rule in {"import", "use", "forward"} and params:
            strings = [params.split()[0].rstrip(",")]
        for specifier in strings:
            add(specifier, match.start(), rule=rule)
    for match in _STYLE_TILDE_URL.finditer(text):
        add("~" + match.group(1), match.start(), rule="url")
    for match in _STYLE_COMPOSES.finditer(text):
        add(match.group(1) or match.group(2), match.start(), rule="composes")
    return found, unknown


def _object_key(source, node):
    if node is None:
        return None
    if node.type in {"property_identifier", "identifier", "shorthand_property_identifier"}:
        return _text(source, node)
    if node.type == "string":
        return _literal(source, node)
    return None


def _postcss_plugins_value(value):
    """Plugin names from a JSON/YAML PostCSS ``plugins`` value, or None."""
    if isinstance(value, dict):
        return [name for name in value if isinstance(name, str)] if all(isinstance(name, str) for name in value) else None
    if isinstance(value, list):
        names = []
        for item in value:
            item = item[0] if isinstance(item, list) and item else item
            if not isinstance(item, str):
                return None
            names.append(item)
        return names
    return [] if value is None else None


def _postcss_data_plugins(data):
    if not isinstance(data, dict):
        return None
    names = _postcss_plugins_value(data.get("plugins"))
    if names is None:
        return None
    for key in ("parser", "syntax", "stringifier"):
        if isinstance(data.get(key), str):
            names.append(data[key])
    return {name for name in map(_package_name, names) if name}


def _postcss_script_plugins(path, text):
    """Plugin names from a literal PostCSS config module, or None if opaque."""
    from skylos.visitors.languages.typescript.core import TypeScriptCore

    core = TypeScriptCore(str(path), text.encode("utf-8"))
    tree, source = core.root_node, core.source
    if tree is None or tree.has_error:
        return None
    exported, declarations = [], {}
    for statement in tree.named_children:
        if statement.type == "export_statement" and any(part.type == "default" for part in statement.children):
            value = next((part for part in statement.named_children if part.type not in {"comment", "decorator"}), None)
            exported.append(value)
        elif statement.type == "expression_statement":
            expression = statement.named_children[0] if statement.named_children else None
            if expression is not None and expression.type == "assignment_expression":
                left = expression.child_by_field_name("left")
                if _text(source, left) in {"module.exports", "exports.default"}:
                    exported.append(expression.child_by_field_name("right"))
        elif statement.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in statement.named_children:
                if declarator.type == "variable_declarator":
                    name = _text(source, declarator.child_by_field_name("name"))
                    declarations[name] = None if name in declarations else declarator.child_by_field_name("value")
    if len(exported) != 1:
        return None
    config = exported[0]
    while config is not None and config.type in {"parenthesized_expression", "satisfies_expression", "as_expression"}:
        config = config.named_children[0] if config.named_children else None
    if config is not None and config.type == "identifier":
        config = declarations.get(_text(source, config))
        while config is not None and config.type in {"parenthesized_expression", "satisfies_expression", "as_expression"}:
            config = config.named_children[0] if config.named_children else None
    if config is None or config.type != "object":
        return None
    names = []
    plugin_values = []
    for part in config.named_children:
        if part.type == "comment":
            continue
        if part.type != "pair":
            return None  # Spreads and methods can replace the visible plugins.
        key = _object_key(source, part.child_by_field_name("key"))
        value = part.child_by_field_name("value")
        if key is None:
            return None
        if key == "plugins":
            plugin_values.append(value)
        elif key in {"parser", "syntax", "stringifier"} and value is not None and value.type == "string":
            names.append(_literal(source, value) or "")
    if len(plugin_values) > 1:
        return None
    for value in plugin_values:
        if value.type == "object":
            for entry in value.named_children:
                if entry.type == "comment":
                    continue
                if entry.type == "pair":
                    key = _object_key(source, entry.child_by_field_name("key"))
                elif entry.type == "shorthand_property_identifier":
                    key = _text(source, entry)
                else:
                    return None
                if key is None:
                    return None
                names.append(key)
        elif value.type == "array":
            for entry in value.named_children:
                if entry.type == "comment":
                    continue
                if entry.type == "string":
                    names.append(_literal(source, entry) or "")
                elif entry.type not in {"call_expression", "identifier", "member_expression"}:
                    return None
                # Calls and bindings come from imports/requires read separately.
        else:
            return None
    return {name for name in map(_package_name, names) if name}


class _NotLiteral(Exception):
    """A config value that is computed rather than written literally."""


def _literal_value(source, node, declarations, depth=0):
    """Evaluate a literal config value; ``require("x")`` evaluates to ``"x"``."""
    if node is None or depth > 32:
        raise _NotLiteral
    kind = node.type
    if kind in {"parenthesized_expression", "satisfies_expression", "as_expression"}:
        return _literal_value(source, node.named_children[0] if node.named_children else None, declarations, depth + 1)
    if kind in {"string", "template_string"}:
        value = _literal(source, node)
        if value is None:
            raise _NotLiteral
        return value
    if kind == "number":
        return _text(source, node)
    if kind in {"true", "false", "null", "undefined"}:
        return {"true": True, "false": False}.get(kind)
    if kind == "array":
        values = []
        for item in node.named_children:
            if item.type == "comment":
                continue
            values.append(_literal_value(source, item, declarations, depth + 1))
        return values
    if kind == "object":
        values = {}
        for part in node.named_children:
            if part.type == "comment":
                continue
            if part.type == "pair":
                key_node = part.child_by_field_name("key")
                key = _object_key(source, key_node) if key_node is None or key_node.type != "number" else _text(source, key_node)
                if key is None:
                    raise _NotLiteral
                values[key] = _literal_value(source, part.child_by_field_name("value"), declarations, depth + 1)
            elif part.type == "shorthand_property_identifier":
                name = _text(source, part)
                values[name] = _literal_value(source, declarations.get(name), declarations, depth + 1)
            else:
                raise _NotLiteral  # Spreads and methods can add any value.
        return values
    if kind == "identifier":
        name = _text(source, node)
        if name not in declarations:
            raise _NotLiteral
        return _literal_value(source, declarations[name], declarations, depth + 1)
    if kind == "call_expression":
        function = _text(source, node.child_by_field_name("function"))
        argument = _call_argument(node.child_by_field_name("arguments"))
        if function in {"require", "require.resolve"}:
            value = _static_string(source, argument)
            if value is None:
                raise _NotLiteral
            return value
        if function in _ABSOLUTE_PATH_CALLS | _JOIN_PATH_CALLS:
            return "./local"  # A path: a local file, never a package name.
    raise _NotLiteral


def _literal_config(path, text):
    """The exported value of a JS config module when it is written literally.

    Returns None when the module computes its configuration (functions,
    spreads, unknown bindings); the caller then cannot list what it loads.
    """
    from skylos.visitors.languages.typescript.core import TypeScriptCore

    core = TypeScriptCore(str(path), text.encode("utf-8"))
    tree, source = core.root_node, core.source
    if tree is None or tree.has_error:
        return None
    exported, declarations = [], {}
    for statement in tree.named_children:
        if statement.type == "export_statement" and any(part.type == "default" for part in statement.children):
            exported.append(next((part for part in statement.named_children if part.type not in {"comment", "decorator"}), None))
        elif statement.type == "expression_statement":
            expression = statement.named_children[0] if statement.named_children else None
            if expression is not None and expression.type == "assignment_expression" and _text(source, expression.child_by_field_name("left")) in {"module.exports", "exports.default"}:
                exported.append(expression.child_by_field_name("right"))
        elif statement.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in statement.named_children:
                if declarator.type == "variable_declarator":
                    name = _text(source, declarator.child_by_field_name("name"))
                    declarations[name] = None if name in declarations else declarator.child_by_field_name("value")
    if len(exported) != 1:
        return None
    try:
        value = _literal_value(source, exported[0], declarations)
    except _NotLiteral:
        return None
    return value if isinstance(value, dict) else None


# Tool and framework configs often name packages by string (Nuxt modules,
# Gatsby/Docusaurus plugins, Storybook addons, Jest presets). In these files a
# string literal naming a declared dependency is usage evidence only.
_CONFIG_FILE = re.compile(r"(?:^|[.-])(?:config|rc|main)\.[cm]?[jt]s$|^gatsby-(?:config|node|browser|ssr)\.[cm]?[jt]sx?$")
_CONFIG_SHORTHANDS = {
    "docusaurus": ("@docusaurus/{type}-{name}", "docusaurus-{type}-{name}"),
    "jest": ("jest-environment-{name}", "jest-runner-{name}", "jest-preset-{name}"),
    # ``coverage: {provider: "istanbul"}`` and ``browser: {provider: ...}``.
    "vitest": ("@vitest/coverage-{name}", "@vitest/browser-{name}"),
}


def _config_file_kind(path):
    """``docusaurus``/``jest``/``generic`` for a tool config module, else None."""
    name = path.name
    if not (_CONFIG_FILE.search(name) or ".storybook" in path.parts or (path.parent.name.startswith(".") and path.stem == "config")):
        return None
    if name.startswith("docusaurus.config."):
        return "docusaurus"
    if name.startswith("jest.config."):
        return "jest"
    if name.startswith(("vite.config.", "vitest.config.", "vitest.workspace.", "vitest.projects.")):
        return "vitest"
    return "generic"


def _config_string_candidates(path, text, kind):
    """Package names that string literals in a config module could denote."""
    from skylos.visitors.languages.typescript.core import TypeScriptCore

    core = TypeScriptCore(str(path), text.encode("utf-8"))
    if core.root_node is None:
        return set()
    names, count = set(), 0
    for node in _nodes(core.root_node):
        count += 1
        if count > MAX_NODES:
            break
        if node.type not in {"string", "template_string"}:
            continue
        value = _literal(core.source, node)
        if not value or len(value) > 214 or any(char.isspace() for char in value):
            continue
        name = _package_name(value)
        if name:
            names.add(name)
        if kind == "docusaurus":
            for module_type in ("preset", "theme", "plugin"):
                if value.startswith("@") and "/" not in value:
                    names.add(f"{value}/docusaurus-{module_type}")
                elif value.startswith("@"):
                    scope, rest = value.split("/", 1)
                    names.add(f"{scope}/docusaurus-{module_type}-{rest}")
                elif _PACKAGE.fullmatch(value):
                    names.update(pattern.format(type=module_type, name=value) for pattern in _CONFIG_SHORTHANDS["docusaurus"])
        elif kind in {"jest", "vitest"} and _PACKAGE.fullmatch(value) and not value.startswith("@"):
            names.update(pattern.format(name=value) for pattern in _CONFIG_SHORTHANDS[kind])
    return names


def _line(text, name):
    match = re.search(r'"' + re.escape(name) + r'"\s*:', text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _section_line(text, field, name):
    """Line of ``name`` inside the ``field`` object of a manifest."""
    section = re.search(r'"' + re.escape(field) + r'"\s*:\s*\{', text)
    if section:
        match = re.compile(r'"' + re.escape(name) + r'"\s*:').search(text, section.end())
        if match:
            return text.count("\n", 0, match.start()) + 1
    return _line(text, name)


_FINDING_TYPES = {RULE_BINARY: "binary", RULE_CATALOG_UNUSED: "catalog_entry", RULE_CATALOG_UNRESOLVED: "catalog_reference"}
_FINDING_VALUES = {RULE_UNUSED: "unused", RULE_CATALOG_UNUSED: "unused", RULE_CATALOG_UNRESOLVED: "unresolved", RULE_OPTIONAL_PEER: "optional_peer"}


def _finding(rule, name, path, line, message, *, severity="MEDIUM", **metadata):
    return {
        "rule_id": rule, "kind": "quality", "severity": severity,
        "type": _FINDING_TYPES.get(rule, "dependency"),
        "name": name, "simple_name": name, "value": _FINDING_VALUES.get(rule, "unlisted"),
        "message": message, "file": str(path), "basename": Path(path).name,
        "line": line, "col": 0, "metadata": {"ecosystem": "npm", **metadata},
    }


def _script_preloads(script):
    if not isinstance(script, str):
        return set()
    tokens = _tokens(script)
    if tokens is None:
        return set()
    names = set()
    flags = {"-r", "--require", "--import", "--loader", "--experimental-loader"}
    for segment in _segments(tokens):
        while segment and _ASSIGNMENT.fullmatch(segment[0]):
            segment = segment[1:]
        if not segment or segment[0] not in {"node", "nodejs", "bun"}:
            continue
        for index, token in enumerate(segment):
            if token in flags and index + 1 < len(segment):
                value = segment[index + 1]
            elif any(token.startswith(flag + "=") for flag in flags):
                value = token.split("=", 1)[1]
            else:
                continue
            name = _package_name(value)
            if name:
                names.add(name)
    return names


def _never_provides_binary(dependency):
    """Configs, plugins, presets and type packages never ship a tool binary."""
    dependency = dependency.lower()
    tokens = set(re.split(r"[-_.@/]+", dependency))
    return dependency.startswith("@types/") or bool(tokens & _NON_BINARY_TOKENS)


def _name_related(command, dependency):
    """Whether an uninstalled dependency could plausibly provide ``command``."""
    command, dependency = command.lower(), dependency.lower()
    if _never_provides_binary(dependency) and not set(re.split(r"[-_.@/]+", command)) & _NON_BINARY_TOKENS:
        return False
    scope, base = ("", dependency)
    if dependency.startswith("@") and "/" in dependency:
        scope, base = dependency[1:].split("/", 1)
    if dependency in {command + "-cli", "@" + command + "/cli"}:
        return True
    for name in filter(None, (base, scope)):
        if name.startswith(command):  # Includes equality and "<command>-..." names.
            return True
        if len(name) >= 2 and command.startswith(name):
            return True
    command_tokens = {token for token in re.split(r"[-_.@/]+", command) if len(token) >= 3} - _GENERIC_NAME_TOKENS
    dependency_tokens = {token for token in re.split(r"[-_.@/]+", dependency) if len(token) >= 3} - _GENERIC_NAME_TOKENS
    return bool(command_tokens & dependency_tokens)


def _eslint_plugin_packages(plugin):
    """``(package, alternates)`` an ESLint plugin reference resolves to."""
    if plugin.startswith("@"):
        scope, _, rest = plugin.partition("/")
        if not rest:
            return scope + "/eslint-plugin", set()
        rest = rest.split("/", 1)[0]
        if rest == "eslint-plugin" or rest.startswith("eslint-plugin-"):
            return scope + "/" + rest, set()
        return scope + "/eslint-plugin-" + rest, {scope + "/" + rest, scope + "/eslint-plugin"}
    plugin = plugin.split("/", 1)[0]
    return (plugin if plugin.startswith("eslint-plugin-") else "eslint-plugin-" + plugin), set()


def _eslint_config_packages(value):
    """``(packages, alternates)`` an ESLint ``extends`` entry resolves to, or None if local."""
    if value.startswith("eslint:"):
        return set(), set()
    if value.startswith("plugin:"):
        plugin = value[7:].rsplit("/", 1)[0] if "/" in value[7:] else value[7:]
        package, alternates = _eslint_plugin_packages(plugin)
        return {package}, alternates
    if value.startswith((".", "/")) or _URL.match(value):
        return None
    if value.startswith("@"):
        scope, _, rest = value.partition("/")
        if not rest:
            return {scope + "/eslint-config"}, set()
        rest = rest.split("/", 1)[0]
        if rest == "eslint-config" or rest.startswith("eslint-config-"):
            return {scope + "/" + rest}, set()
        return {scope + "/eslint-config-" + rest}, {scope + "/" + rest}
    name = _package_name(value)
    if name is None:
        return None
    if name.startswith("eslint-config-"):
        return {name}, set()
    return {"eslint-config-" + name}, {name}


def _plugin_names(data, shareable=None, hints=None):
    """``(packages, unknown_tools)`` named by literal tool configuration.

    ``unknown_tools`` lists the tools (``eslint``, ``babel``, ``prettier``,
    ``postcss``) whose configuration also loads something not read here, such
    as a local config. Only dependencies of that tool family stay unresolved.
    Shareable ESLint configs are added to ``shareable``: they load their own
    plugins and peers, which only their installed manifest lists. ``hints``
    receives names that are usage evidence only: alternate shorthand
    resolutions and plugins inferred from rule prefixes (``import/order``),
    which a shareable config may provide.
    """
    names, unknown = set(), set()
    shareable = shareable if shareable is not None else set()
    hints = hints if hints is not None else set()
    prettier = data.get("prettier")
    if isinstance(prettier, str):
        name = _package_name(prettier)
        if name:
            names.add(name)
        else:
            unknown.add("prettier")
    if isinstance(prettier, dict):
        plugins = prettier.get("plugins", [])
        if not isinstance(plugins, list):
            unknown.add("prettier")
        else:
            for plugin in plugins:
                if isinstance(plugin, str) and _package_name(plugin):
                    names.add(_package_name(plugin))
                else:
                    unknown.add("prettier")
    babel = data.get("babel")
    if isinstance(babel, dict):
        if {"extends", "env", "overrides"} & babel.keys():
            unknown.add("babel")
        for key, prefix in (("plugins", "babel-plugin-"), ("presets", "babel-preset-")):
            values = babel.get(key, [])
            if not isinstance(values, list):
                unknown.add("babel")
                continue
            for value in values:
                value = value[0] if isinstance(value, list) and value else value
                if not isinstance(value, str) or value.startswith((".", "/")):
                    unknown.add("babel")
                elif value.startswith("@babel/"):
                    names.add(_package_name(value if value.rsplit("/", 1)[-1].startswith(("plugin-", "preset-")) else value.replace("@babel/", "@babel/" + prefix.removeprefix("babel-"))) or value)
                else:
                    name = _package_name(value if value.startswith((prefix, "@")) else prefix + value)
                    if name is None:
                        unknown.add("babel")
                    else:
                        names.add(name)
    eslint = data.get("eslintConfig")
    if isinstance(eslint, dict):
        if "overrides" in eslint:
            unknown.add("eslint")
        plugins = eslint.get("plugins", [])
        if not isinstance(plugins, list):
            unknown.add("eslint")
            plugins = []
        for plugin in plugins:
            if not isinstance(plugin, str):
                unknown.add("eslint")
            else:
                package, alternates = _eslint_plugin_packages(plugin)
                names.add(package)
                hints.update(alternates)
        parser = eslint.get("parser")
        if isinstance(parser, str) and _package_name(parser):
            names.add(_package_name(parser))
        rules = eslint.get("rules")
        if isinstance(rules, dict):
            # ``import/order`` configures eslint-plugin-import.
            for rule in rules:
                if isinstance(rule, str) and "/" in rule:
                    package, alternates = _eslint_plugin_packages(rule.rsplit("/", 1)[0])
                    hints.update({package, *alternates})
        extends = eslint.get("extends", [])
        extends = [extends] if isinstance(extends, str) else extends
        if isinstance(extends, list):
            for value in extends:
                resolved = _eslint_config_packages(value) if isinstance(value, str) else None
                if resolved is None:
                    unknown.add("eslint")
                    continue
                packages, alternates = resolved
                names.update(packages)
                hints.update(alternates)
                if packages and not value.startswith(("eslint:", "plugin:")):
                    shareable.add(frozenset(packages | alternates))
        else:
            unknown.add("eslint")
    if "postcss" in data:
        postcss = _postcss_data_plugins(data["postcss"])
        if postcss is None:
            unknown.add("postcss")
        else:
            names.update(postcss)
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
            if node.type in {"variable_declarator", "function_declaration", "class_declaration", "enum_declaration"} and any(_text(source, name) in protected for name in _pattern_names(node.child_by_field_name("name"))):
                rebound = True
            if node.type in {"formal_parameters", "required_parameter", "optional_parameter"} and any(_text(source, name) in protected for name in _pattern_names(node)):
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


def _typescript_option_packages(options):
    """Packages named by compiler options without an import declaration."""
    names = set()
    if not isinstance(options, dict):
        return names
    types = options.get("types")
    if isinstance(types, list):
        names.update(name for name in map(_package_name, (value for value in types if isinstance(value, str))) if name)
    if options.get("importHelpers") is True:
        names.add("tslib")
    source = options.get("jsxImportSource")
    if isinstance(source, str) and _package_name(source):
        names.add(_package_name(source))
    elif isinstance(options.get("jsx"), str) and options["jsx"].lower() in {"react-jsx", "react-jsxdev", "react"}:
        names.add("react")
    return names


def _load_workspace_yaml(text):
    """Load pnpm-workspace.yaml with YAML 1.2 scalars and key line marks."""
    import yaml

    from skylos.rules.sca.pnpm_lockfile import (
        LockfileLimitError,
        LockfileParseError,
        _LockLoader,
    )

    loader = _LockLoader(text)
    try:
        return loader.get_single_data()
    except (yaml.YAMLError, LockfileParseError, LockfileLimitError, RecursionError, ValueError):
        return False
    finally:
        loader.dispose()


def _catalog_entries(data):
    """Return ``{(catalog, package): line}`` or None when catalogs are malformed."""
    entries = {}
    catalog = data.get("catalog")
    if catalog is not None:
        if not isinstance(catalog, dict):
            return None
        for name in catalog:
            entries[("default", name)] = getattr(catalog, "lines", {}).get(name, 1)
    catalogs = data.get("catalogs")
    if catalogs is not None:
        if not isinstance(catalogs, dict):
            return None
        for catalog_name, values in catalogs.items():
            if not isinstance(values, dict):
                return None
            for name in values:
                entries[(catalog_name, name)] = getattr(values, "lines", {}).get(name, 1)
    return entries


def _catalog_reference(name, version):
    if isinstance(version, str) and version.startswith("catalog:"):
        return (version[len("catalog:"):].strip() or "default", name)
    return None


def _override_target(selector):
    """Package name an override selector applies to, e.g. ``a>b@<2`` -> ``b``."""
    if not isinstance(selector, str):
        return None
    target = re.split(r"(?<=[^ |@])>", selector)[-1].strip()
    if target.startswith("@"):
        scope, _, rest = target.partition("/")
        target = scope + "/" + rest.split("@", 1)[0]
    else:
        target = target.split("@", 1)[0]
    return target if _PACKAGE.fullmatch(target) else None


def _manifest_catalog_references(data):
    """``(references, unknown)`` for every catalog protocol use in a manifest."""
    references, unknown = [], False
    for field in (*DEPENDENCY_FIELDS, "resolutions", "overrides"):
        values = data.get(field)
        if not isinstance(values, dict):
            continue
        for name, version in values.items():
            if field in {"resolutions", "overrides"}:
                if isinstance(version, dict):
                    unknown |= "catalog:" in json.dumps(version)
                    continue
                target = _override_target(name)
                reference = _catalog_reference(target, version) if target else None
                unknown |= reference is None and isinstance(version, str) and version.startswith("catalog:")
            else:
                reference = _catalog_reference(name, version)
            if reference is not None:
                references.append((*reference, field))
    pnpm = data.get("pnpm")
    if isinstance(pnpm, dict) and isinstance(pnpm.get("overrides"), dict):
        for selector, version in pnpm["overrides"].items():
            target = _override_target(selector)
            reference = _catalog_reference(target, version) if target else None
            if reference is not None:
                references.append((*reference, "pnpm.overrides"))
            elif isinstance(version, str) and version.startswith("catalog:"):
                unknown = True
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for script in scripts.values():
            if isinstance(script, str) and "catalog:" in script:
                matches = _CATALOG_SCRIPT_REFERENCE.findall(script)
                unknown |= not matches
                references.extend((catalog or "default", name, "scripts") for name, catalog in matches)
    return references, unknown


def _glob_regex(pattern):
    pattern = pattern.strip()
    while pattern.startswith("./"):
        pattern = pattern[2:]
    pattern = pattern.rstrip("/") or "."
    if pattern == ".":
        return re.compile(r"")
    out, index = [], 0
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index):
            out.append(r"(?:.*/)?")
            index += 3
            continue
        if pattern.startswith("**", index):
            out.append(r".*")
            index += 2
            continue
        if char == "*":
            out.append(r"[^/]*")
        elif char == "?":
            out.append(r"[^/]")
        elif char == "{" and "}" in pattern[index:]:
            end = pattern.index("}", index)
            out.append("(?:" + "|".join(re.escape(part) for part in pattern[index + 1:end].split(",")) + ")")
            index = end
        else:
            out.append(re.escape(char))
        index += 1
    return re.compile("".join(out))


def _workspace_member(relative, patterns):
    """pnpm membership for a manifest directory relative to the workspace root."""
    if relative == "":
        return True
    included = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        if _glob_regex(pattern[1:] if negated else pattern).fullmatch(relative):
            included = not negated
    return included


def _workspace_manifest_paths(base, limitations):
    """Every package.json below ``base`` except installed and VCS copies."""
    walked, members = 0, []

    def walk_failed(error):
        limitations.append({"kind": "unreadable_workspace_directory", "file": str(error.filename)})

    for directory, dirs, names in os.walk(base, followlinks=False, onerror=walk_failed):
        walked += 1 + len(dirs) + len(names)
        if walked > MAX_WALK_ENTRIES:
            limitations.append({"kind": "workspace_walk_budget"})
            break
        for name in dirs:
            if name not in VCS_DIRS | {"node_modules"} and (Path(directory) / name).is_symlink():
                limitations.append({"kind": "symlink_workspace_directory", "file": str(Path(directory) / name)})
        dirs[:] = sorted(name for name in dirs if name not in VCS_DIRS | {"node_modules"} and not (Path(directory) / name).is_symlink())
        if "package.json" in names:
            members.append(Path(directory) / "package.json")
    return members


def _catalog_findings(root, workspace_files, manifests, source_text, analyses):
    findings = []
    nearest = {}
    workspace_dirs = sorted((path.parent for path in workspace_files), key=lambda path: len(path.parts), reverse=True)
    for manifest_dir in manifests:
        nearest[manifest_dir] = next((directory for directory in workspace_dirs if manifest_dir.is_relative_to(directory)), None)
    for workspace_file in sorted(workspace_files):
        base = workspace_file.parent
        analysis = {"workspace_file": str(workspace_file), "status": "complete", "limitations": [], "entries": 0, "references": 0}
        analyses.append(analysis)
        text = read_project_text_no_symlink(root, workspace_file, max_bytes=MAX_BYTES)
        data = _load_workspace_yaml(text) if text is not None else False
        if data is None:
            data = {}
        if not isinstance(data, dict):
            analysis.update(status="not_run", limitations=[{"kind": "unreadable_workspace_file"}])
            continue
        entries = _catalog_entries(data)
        if entries is None:
            analysis.update(status="not_run", limitations=[{"kind": "malformed_catalog"}])
            continue
        analysis["entries"] = len(entries)
        limitations = analysis["limitations"]
        referenced, unknown_catalogs = set(), set()
        overrides = data.get("overrides")
        if isinstance(overrides, dict):
            for selector, version in overrides.items():
                target = _override_target(selector)
                reference = _catalog_reference(target, version) if target else None
                if reference is not None:
                    referenced.add(reference)
                elif isinstance(version, str) and version.startswith("catalog:"):
                    unknown_catalogs.add(version[len("catalog:"):].strip() or "default")
        for hook in (".pnpmfile.cjs", ".pnpmfile.mjs", ".pnpmfile.js"):
            if (base / hook).exists():
                limitations.append({"kind": "unmodelled_pnpmfile_hook", "file": str(base / hook)})
        root_manifest = manifests.get(base, {})
        workspaces = root_manifest.get("workspaces")
        if any(key in root_manifest for key in ("catalog", "catalogs")) or (isinstance(workspaces, dict) and {"catalog", "catalogs"} & workspaces.keys()) or (base / ".yarnrc.yml").exists():
            limitations.append({"kind": "competing_catalog_source"})
        # Every package.json under the workspace can reference an entry, even in
        # directories the dependency scan skips. More references only remove
        # unused-entry claims, so this inventory is a deliberate superset.
        members = _workspace_manifest_paths(base, limitations) if entries else []
        for manifest_path in members:
            data_text = read_project_text_no_symlink(root, manifest_path, max_bytes=MAX_BYTES)
            try:
                manifest = json.loads(data_text) if data_text is not None else None
            except (ValueError, TypeError, RecursionError):
                manifest = None
            if not isinstance(manifest, dict):
                limitations.append({"kind": "unreadable_workspace_manifest", "file": str(manifest_path)})
                continue
            references, unknown = _manifest_catalog_references(manifest)
            if unknown:
                limitations.append({"kind": "unresolved_catalog_reference_syntax", "file": str(manifest_path)})
            referenced.update((catalog, name) for catalog, name, _field in references)
            analysis["references"] += len(references)
        if not limitations:
            for (catalog, name), line in sorted(entries.items()):
                if (catalog, name) in referenced or catalog in unknown_catalogs:
                    continue
                label = "default catalog" if catalog == "default" else f"catalog '{catalog}'"
                findings.append(_finding(RULE_CATALOG_UNUSED, name, workspace_file, line, f"pnpm catalog entry '{name}' ({label}) is not referenced by any workspace package.json.", severity="LOW", package_name=name, catalog=catalog, workspace_file=str(workspace_file)))
        else:
            analysis["status"] = "incomplete"
        patterns = data.get("packages", [])
        if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
            limitations.append({"kind": "unresolved_workspace_packages"})
            patterns = []
        if any(item["kind"] in {"competing_catalog_source", "unmodelled_pnpmfile_hook"} for item in limitations):
            continue
        for manifest_dir, manifest in manifests.items():
            if nearest.get(manifest_dir) != base:
                continue
            relative = manifest_dir.relative_to(base).as_posix()
            if not _workspace_member("" if relative == "." else relative, patterns):
                continue
            references, _unknown = _manifest_catalog_references(manifest)
            for catalog, name, field in references:
                if field not in DEPENDENCY_FIELDS or (catalog, name) in entries:
                    continue
                label = "default catalog" if catalog == "default" else f"catalog '{catalog}'"
                manifest_path = manifest_dir / "package.json"
                findings.append(_finding(RULE_CATALOG_UNRESOLVED, name, manifest_path, _line(source_text[manifest_dir], name), f"Dependency '{name}' uses the catalog: protocol, but the {label} in {workspace_file.name} has no '{name}' entry.", package_name=name, catalog=catalog, dependency_section=field, workspace_file=str(workspace_file), package_manifest=str(manifest_path)))
    return findings


# Module aliases a framework provides at build time, not npm packages.
FRAMEWORK_ALIAS_SCOPES = {
    "@docusaurus/core": ("@theme", "@theme-original", "@theme-init", "@site", "@generated"),
}
FRAMEWORK_ALIAS_MODULES = {
    "@docusaurus/core": ("@docusaurus/router", "@docusaurus/constants"),
}


def _framework_alias(name, available):
    """Whether an undeclared specifier is a framework alias or not an npm name."""
    if name.startswith("@") and name != name.lower():
        return True  # Scoped npm package names are always lowercase.
    for framework, scopes in FRAMEWORK_ALIAS_SCOPES.items():
        if framework in available and (name.split("/", 1)[0] in scopes or name in FRAMEWORK_ALIAS_MODULES.get(framework, ())):
            return True
    return False


def _has_subpath_entries(data):
    exports = data.get("exports")
    if not isinstance(exports, dict):
        return False
    return any(isinstance(key, str) and key.startswith("./") and key not in {"./package.json"} for key in exports)


# Codemod and transform harnesses read these files as text (jscodeshift
# ``__testfixtures__``, Babel/ESLint testers' ``__fixtures__``, and
# ``fixtures/**/input.*``/``output.*`` pairs); their imports never execute.
_FIXTURE_TEXT_DIRS = _text_fixture_directories()
_FIXTURE_DIRS = {"fixtures", "fixture"}
_FIXTURE_TEXT_STEMS = {"input", "output"}
# Package files that never ship to consumers of a published package: tests
# and their setup, tool configs, scripts, stories, examples and benchmarks.
_TOOLING_TOP_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "e2e", "scripts", "script", "tools", "examples",
    "example", "demo", "demos", "bench", "benchmark", "benchmarks", "stories", "storybook", ".storybook",
    "docs", "playground", "fixtures", "cypress", "playwright",
}
_TOOLING_ANY_DIRS = {"__tests__", "__mocks__", "__fixtures__", "__testfixtures__", "__snapshots__", "__stories__", ".storybook", "cypress", "e2e"}
_TOOLING_NAME = re.compile(
    r"[.\-_](?:test|spec|e2e|bench|stories|story|cy|test-d|spec-d)\.[cm]?[jt]sx?$"
    r"|\.config(?:\.[\w-]+)?\.[cm]?[jt]sx?$|^\.[\w-]+rc\.[cm]?[jt]s$|^vitest\.workspace\.[cm]?[jt]s$"
    r"|^(?:setup[-_.]?tests?|tests?[-_.]?setup|(?:jest|vitest|playwright|cypress)[-_.]setup)(?:[.-][A-Za-z0-9]+)*\.[cm]?[jt]sx?$",
    re.IGNORECASE,
)
_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
# Kinds of import evidence that only the type checker reads.
_TYPE_KINDS = {"type", "jsdoc", "reference", "tsconfig"}
# Opaque tool config files and the tool family whose packages they can load.
_OPAQUE_CONFIG_TOOLS = {"eslintrc": "eslint", "babel": "babel", "babelrc": "babel", "prettier": "prettier", "prettierrc": "prettier"}
# Manifest tool sections read as data: every string value can name a package;
# the tool may also resolve shorthand names of its own family.
_MANIFEST_TOOL_FAMILIES = {
    "jest": {"jest"}, "ava": {"ava"}, "mocha": {"mocha"}, "nyc": {"nyc", "istanbul"},
    "commitlint": {"commitlint"}, "release": {"semantic"}, "stylelint": {"stylelint"}, "xo": {"xo", "eslint"},
}
_TOOL_FAMILY_TOKENS = {"eslint": {"eslint"}, "babel": {"babel"}, "prettier": {"prettier"}, "postcss": {"postcss"}}
# size-limit loads every installed ``@size-limit/*`` plugin.
_SIZE_LIMIT_CONFIGS = tuple(f".size-limit.{extension}" for extension in ("json", "js", "cjs", "mjs", "ts", "cts", "mts"))
_NODE_API = re.compile(r"\b(?:process|Buffer|__dirname|__filename|NodeJS|setImmediate)\b")
MAX_SCRIPT_FILES = 64


def _fixture_text(parts):
    """Whether a file (path parts relative to the project) is fixture text."""
    dirs = [part.lower() for part in parts[:-1]]
    if any(part in _FIXTURE_TEXT_DIRS for part in dirs):
        return True
    if any(part in _FIXTURE_DIRS for part in dirs):
        pieces = parts[-1].lower().split(".")
        return pieces[0] in _FIXTURE_TEXT_STEMS or (len(pieces) > 2 and pieces[-2] in _FIXTURE_TEXT_STEMS)
    return False


def _tooling_file(parts):
    """Test, setup, config, script, story, example or benchmark file.

    ``parts`` are relative to the owning package directory.
    """
    dirs = [part.lower() for part in parts[:-1]]
    if _TOOLING_NAME.search(parts[-1]) or any(part in _TOOLING_ANY_DIRS for part in dirs):
        return True
    return bool(dirs) and dirs[0] in _TOOLING_TOP_DIRS


def _types_package(name):
    """DefinitelyTyped package for ``name`` (``@scope/x`` -> ``@types/scope__x``)."""
    return "@types/" + (name[1:].replace("/", "__", 1) if name.startswith("@") else name)


def _types_target(name):
    """Package an ``@types/*`` package describes (``@types/scope__x`` -> ``@scope/x``)."""
    base = name[len("@types/"):]
    return "@" + base.replace("__", "/", 1) if "__" in base else base


def _node_builtin(specifier):
    from skylos.rules.ai_defect.js_api_hallucination import _NODE_BUILTINS

    if not isinstance(specifier, str):
        return False
    return specifier.startswith("node:") or specifier in _NODE_BUILTINS or specifier.split("/", 1)[0] in _NODE_BUILTINS


def _tool_related(tokens, name):
    return bool(set(re.split(r"[-_.@/]+", name.lower())) & tokens)


def _string_leaves(value, limit=MAX_NODES):
    found, pending = [], [value]
    while pending and len(found) < limit:
        current = pending.pop()
        if isinstance(current, str):
            found.append(current)
        elif isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return found


def _string_values(value, limit=MAX_NODES):
    """String values (not keys) of a parsed data config."""
    found, pending = [], [value]
    while pending and len(found) < limit:
        current = pending.pop()
        if isinstance(current, str):
            found.append(current)
        elif isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return found


def _tsconfig_chain(root, path, limit=8):
    """``(configs, unknown, generated)``: a tsconfig and the local configs it extends.

    ``configs`` is ``[(path, data, text)]`` child first; package ``extends``
    names are returned as data for the caller. A missing local parent is
    unknown, except one in a dot-directory that a framework generates
    (``.svelte-kit/tsconfig.json``), reported as ``generated``.
    """
    from skylos.visitors.languages.typescript.workspace import (
        _strip_json_comments,
        _strip_trailing_commas,
    )

    chain, pending, seen, unknown, generated = [], [path], set(), False, False
    while pending and len(chain) < limit:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        text = read_project_text_no_symlink(root, current, max_bytes=MAX_BYTES)
        try:
            data = json.loads(_strip_trailing_commas(_strip_json_comments(text))) if text is not None else None
        except (TypeError, ValueError):
            data = None
        if not isinstance(data, dict):
            unknown = True
            continue
        chain.append((current, data, text))
        parents = data.get("extends", [])
        for parent in [parents] if isinstance(parents, str) else parents if isinstance(parents, list) else []:
            if not isinstance(parent, str) or not parent.startswith((".", "/")):
                continue
            candidate = (current.parent / parent).resolve()
            options = [candidate, candidate.with_name(candidate.name + ".json"), candidate / "tsconfig.json"]
            found = next((option for option in options if option.is_file() and option.is_relative_to(root)), None)
            if found is not None:
                pending.append(found)
            elif any(part.startswith(".") and part not in {".", ".."} for part in Path(parent).parts):
                generated = True  # Written by the framework (.svelte-kit, .nuxt): not on disk.
            else:
                unknown = True
    return chain, unknown, generated


def _type_reference_name(entry):
    """``(package, types_package)`` named by a ``types`` entry or reference."""
    if not isinstance(entry, str):
        return None, None
    if _node_builtin(entry) or entry == "node":
        return None, "@types/node"
    name = _package_name(entry)
    if name is None:
        return None, None
    return name, _types_package(name)


def scan_npm_dependencies(project_root, files, *, workspace_inventory=None, coverage=None, complete_scope=True, strict=False):
    """Return quality findings for proven npm usage within package ownership.

    Only files included by the caller may provide import evidence: JS/TS
    sources plus Vue/Svelte/Astro components, MDX and stylesheets. An on-disk
    source missing from that inventory blocks unused checks, preserving
    correctness for changed-file, excluded and component-only scans.

    Node resolves a bare import from the importing file's directory upward,
    so an ancestor workspace's declaration satisfies tests, setup files,
    configs, scripts, stories, examples, type-only inputs and every file of a
    private package. By default an ancestor's declaration also satisfies the
    production source of a published package; ``strict=True``
    (``strict_dependencies = true``) reports it, because consumers install
    only that package's dependencies.
    """
    root = Path(project_root).resolve()
    receipt = coverage if coverage is not None else {}
    receipt.update(status="complete", complete=True, reasons=[], packages=[], abstained_dependencies=[], limitations_by_package={}, strict=bool(strict), ancestor_declared_production_imports=0)
    observed, total, walked, walk_error = [], 0, 0, False
    # Data configs of the tools in the plugin table (``.mocharc.yml``,
    # ``nest-cli.json``, ``netlify.toml``): their strings may name packages.
    plugin_data_configs = _plugin_config_file_names()[0]
    workspace_files, command_files = [], []
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
            if name in {"Makefile", "Procfile", "Dockerfile", "Containerfile", ".gitlab-ci.yml"} or (".github" in path.parts and "workflows" in path.parts and path.suffix in {".yml", ".yaml"}):
                command_files.append(path)
            if name == "pnpm-workspace.yaml":
                workspace_files.append(path)
            if name == "package.json" or (name.startswith("tsconfig") and name.endswith(".json")) or name in JSON_CONFIGS | OPAQUE_CONFIGS | POSTCSS_DATA_CONFIGS | POSTCSS_SCRIPT_CONFIGS | DATA_CONFIGS | plugin_data_configs or path.suffix in SOURCE_SUFFIXES | NPM_ASSET_SUFFIXES | OPAQUE_SOURCE_SUFFIXES:
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
    from skylos.visitors.languages.typescript.workspace import is_marker_manifest

    # A nested ``{"type": "commonjs"}`` marker declares nothing; its files
    # belong to the enclosing package (see ``is_marker_manifest``).
    manifests = {package: data for package, data in manifests.items() if not (is_marker_manifest(data) and any(other != package and package.is_relative_to(other) for other in manifests))}
    roots = sorted(manifests, key=lambda path: len(path.parts), reverse=True)
    root_prefixes = [(package, str(package).rstrip(os.sep) + os.sep) for package in roots]
    owner_cache, ancestor_cache = {}, {}

    def owner(path):
        directory = path if path in manifests else path.parent
        if directory not in owner_cache:
            text = str(directory).rstrip(os.sep) + os.sep
            owner_cache[directory] = next((package for package, prefix in root_prefixes if text.startswith(prefix)), None)
        return owner_cache[directory]

    def ancestors_of(package):
        if package not in ancestor_cache:
            text = str(package).rstrip(os.sep) + os.sep
            ancestor_cache[package] = [ancestor for ancestor, prefix in root_prefixes if ancestor != package and text.startswith(prefix)]
        return list(ancestor_cache[package])

    declared_by = {}
    for package, data in manifests.items():
        declared_by[package] = {name for field in DEPENDENCY_FIELDS if isinstance(data.get(field), dict) for name in data[field]}

    def declaring_ancestor(package, *names):
        """Nearest ancestor package that declares one of ``names``."""
        for ancestor in ancestors_of(package):
            for name in names:
                if name in declared_by[ancestor]:
                    return ancestor, name
        return None, None

    unknown = defaultdict(list)
    for package in roots:
        unknown[package].extend(opaque_inventory)
    scoped = defaultdict(list)
    held = defaultdict(lambda: defaultdict(list))
    used = defaultdict(set)
    imports = defaultdict(list)
    static_imports = defaultdict(list)
    config_strings = defaultdict(set)
    node_usage = set()
    selected = {Path(path).absolute() for path in files}
    package_names = {data.get("name") for data in manifests.values() if isinstance(data.get("name"), str)}
    workspace_manifests = {data["name"]: data for data in manifests.values() if isinstance(data.get("name"), str)}
    workspace_dirs = {data["name"]: package for package, data in manifests.items() if isinstance(data.get("name"), str)}
    # Ambient type packages (``@types/chrome``) are used through a global of
    # the same name; those identifiers are looked up in every source text.
    ambient = {}
    for names in declared_by.values():
        for name in names:
            if name.startswith("@types/"):
                identifier = _types_target(name).split(".", 1)[0]
                if re.fullmatch(r"[A-Za-z_$][\w$]*", identifier):
                    ambient[identifier] = name
    ambient_pattern = re.compile(r"\b(" + "|".join(sorted(map(re.escape, ambient))) + r")\s*[.(]") if ambient else None
    ambient_seen = set()
    from skylos.visitors.languages.typescript.resolve import MonorepoResolver

    resolver = MonorepoResolver(str(root))
    virtual_modules = {package: _configured_virtual_modules(root, package, data) for package, data in manifests.items()}
    bytes_read = 0
    alias_scopes = []
    file_names = {}
    # Source files a tsconfig outside their package compiles (``include`` or
    # ``files``): the including package uses their imports, and that
    # config's ``paths`` can map their workspace specifiers.
    tsconfig_inputs = []
    including_configs = defaultdict(list)

    def workspace_alias(specifier, path):
        """A tsconfig ``paths`` entry or readable bundler alias maps the specifier to source."""
        from fnmatch import fnmatchcase

        from skylos.visitors.languages.typescript.resolve import _parse_tsconfig_paths

        context = resolver._get_tsconfig_context(str(path))
        if context is not None and any(pattern != "*" and fnmatchcase(specifier, pattern) for pattern in context[1]):
            return True
        for config in including_configs.get(path, ()):
            if any(pattern != "*" and fnmatchcase(specifier, pattern) for pattern in _parse_tsconfig_paths(str(config))[1]):
                return True
        if not alias_scopes:
            from skylos.visitors.languages.typescript.unresolved_imports import (
                _discover_alias_scopes,
            )

            alias_scopes.append(_discover_alias_scopes(str(root), None))
        for scope in alias_scopes[0]:
            if not path.is_relative_to(scope.directory):
                continue
            for key in scope.keys:
                key = key.rstrip("/")
                if key and (specifier == key or specifier.startswith(key + "/")):
                    return True
        return False

    installed_cache = {}

    def installed_manifest(package, name):
        """An installed package manifest, read as data from node_modules."""
        for directory in [package, *ancestors_of(package)]:
            key = directory, name
            if key not in installed_cache:
                meta = read_project_text_no_symlink(root, directory / "node_modules" / name / "package.json", max_bytes=MAX_BYTES)
                try:
                    installed_cache[key] = json.loads(meta) if meta else None
                except (ValueError, RecursionError):
                    installed_cache[key] = None
            if isinstance(installed_cache[key], dict):
                return installed_cache[key]
        return None

    def bins_of(package, name):
        """Binary names a declared dependency provides, or None when unknown."""
        metadata = workspace_manifests.get(name) or installed_manifest(package, name)
        if not isinstance(metadata, dict):
            return set() if _never_provides_binary(name) else None
        bins = metadata.get("bin")
        if isinstance(bins, dict):
            return {binary for binary in bins if isinstance(binary, str)}
        if isinstance(bins, str):
            return {name.rsplit("/", 1)[-1]}
        return set()

    def tooling_file(package, path):
        try:
            relative = path.relative_to(package).parts
        except ValueError:
            relative = (path.name,)
        return manifests[package].get("private") is True or _tooling_file(relative)

    def record(package, path, items):
        data = manifests[package]
        names_here = file_names.setdefault(path, set())
        try:
            fixture = _fixture_text(path.relative_to(root).parts)
        except ValueError:
            fixture = False
        declaration = path.name.endswith(_DECLARATION_SUFFIXES)
        tooling = tooling_file(package, path)
        for specifier, line, kind in items:
            if specifier in virtual_modules[package]:
                continue
            if kind in {"reference", "tsconfig"}:
                name, types = _type_reference_name(specifier)
                if types == "@types/node":
                    node_usage.add(package)
                if types:
                    used[package].add(types)
                if name is None:
                    continue
            else:
                name = _package_name(specifier)
                if name is None:
                    if _node_builtin(specifier):
                        node_usage.add(package)
                    continue
            if name == data.get("name"):
                continue
            if name not in package_names and resolver.claims_local_source(specifier, str(path)):
                continue
            used[package].add(name)
            names_here.add(name)
            if kind == "static" and not declaration:
                static_imports[package].append((name, path, line))
            if fixture:
                continue  # Read as text by a test harness: usage evidence only.
            if declaration or kind in {"reference", "tsconfig"}:
                role = "compile_time"  # Declaration inputs are not emitted.
            elif tooling:
                role = "tooling"
            else:
                role = "production"
            if kind == "jsdoc" and role != "production":
                continue  # A JSDoc type annotation loads nothing at runtime.
            imports[package].append((name, path, line, kind, role, specifier))

    def read_selected(package, path):
        nonlocal bytes_read
        if path not in selected:
            unknown[package].append({"kind": "unanalysed_source", "file": str(path)})
            return None
        text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
        if text is None or bytes_read + len(text.encode("utf-8")) > MAX_TOTAL_BYTES:
            unknown[package].append({"kind": "unreadable_source", "file": str(path)})
            return None
        bytes_read += len(text.encode("utf-8"))
        if _NODE_API.search(text):
            node_usage.add(package)
        if ambient_pattern is not None:
            ambient_seen.update(match.group(1) for match in ambient_pattern.finditer(text))
        return text

    def configured_tools(package, path, field, config_data):
        """Literal ESLint/Prettier/Babel config: named packages and scoped unknowns."""
        shareable, hints = set(), set()
        configured, config_unknown = _plugin_names({field: config_data}, shareable, hints)
        used[package].update(configured | hints)
        imports[package].extend((name, path, 1, "static", "tooling") for name in configured)
        # An uninstalled shareable config loads plugins and peers that only
        # its own manifest lists; an installed one contributes its peers.
        if any(not any(installed_manifest(package, name) for name in group) for group in shareable):
            config_unknown.add("eslint")
        for tool in sorted(config_unknown):
            scoped[package].append((_TOOL_FAMILY_TOKENS.get(tool, {tool}), {"kind": "unresolved_plugin_config", "file": str(path), "tool": tool}))

    def read_tsconfig(package, path):
        chain, chain_unknown, generated = _tsconfig_chain(root, path)
        if not chain:
            unknown[package].append({"kind": "unreadable_typescript_config", "file": str(path)})
            return
        if chain_unknown:
            unknown[package].append({"kind": "unresolved_typescript_config", "file": str(path)})
        if generated:
            # A generated config can list ambient type packages.
            scoped[package].append(({"types"}, {"kind": "generated_typescript_config", "file": str(path)}))
        for index, (config_path, config_data, config_text) in enumerate(chain):
            own = index == 0
            parents = config_data.get("extends", [])
            parents = [parents] if isinstance(parents, str) else parents
            if not isinstance(parents, list):
                parents = []
                unknown[package].append({"kind": "unresolved_typescript_config", "file": str(config_path)})
            options = config_data.get("compilerOptions", {})
            plugins = options.get("plugins", []) if isinstance(options, dict) else None
            if not isinstance(plugins, list):
                unknown[package].append({"kind": "unresolved_typescript_plugins", "file": str(config_path)})
                plugins = []
            for value in [parent for parent in parents if not (isinstance(parent, str) and parent.startswith((".", "/")))] + [plugin.get("name") if isinstance(plugin, dict) else None for plugin in plugins]:
                name = _package_name(value)
                if name is None:
                    unknown[package].append({"kind": "unresolved_typescript_config_provider", "file": str(config_path)})
                elif own:
                    record(package, path, [(value, 1, "tsconfig")])
                else:
                    used[package].add(name)
            for entry in [*(config_data.get("files") or []), *(config_data.get("include") or [])] if isinstance(config_data.get("files", []), list) and isinstance(config_data.get("include", []), list) else []:
                if not isinstance(entry, str):
                    continue
                prefix = re.split(r"[*?{\[]", entry, maxsplit=1)[0]
                target = (config_path.parent / prefix).resolve() if prefix else config_path.parent.resolve()
                if target.is_relative_to(root) and not target.is_relative_to(package):
                    tsconfig_inputs.append((package, target, prefix != entry or target.is_dir(), path))
            # Ambient types, helper imports and the JSX runtime are usage
            # evidence; an own ``types`` entry also names a package to declare.
            used[package].update(_typescript_option_packages(options))
            types = options.get("types") if isinstance(options, dict) else None
            for entry in types if isinstance(types, list) else []:
                name, types_name = _type_reference_name(entry)
                if types_name:
                    used[package].add(types_name)
                if own and isinstance(entry, str):
                    match = re.search(r'"' + re.escape(entry) + r'"', config_text)
                    record(package, path, [(entry, config_text.count("\n", 0, match.start()) + 1 if match else 1, "tsconfig")])

    for path in observed:
        if path.name == "package.json":
            continue
        package = owner(path)
        if package is None:
            continue
        suffix = path.suffix.lower()
        if suffix in COMPONENT_RUNTIMES:
            used[package].add(COMPONENT_RUNTIMES[suffix])
        used[package].update(STYLESHEET_COMPILERS.get(suffix.lstrip("."), ()))
        if suffix in TYPESCRIPT_SUFFIXES or (path.name.startswith("tsconfig") and path.name.endswith(".json")):
            # The compiler is used by any TypeScript package, even without a
            # tsc script (editors, bundlers and type-check tools load it).
            used[package].add("typescript")
        if path.name in OPAQUE_CONFIGS:
            stem = path.name.lstrip(".").split(".", 1)[0]
            tool = _OPAQUE_CONFIG_TOOLS.get(stem, stem)
            reason = {"kind": "unresolved_plugin_config", "file": str(path), "tool": tool}
            if suffix in {".yml", ".yaml"}:
                config_text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
                documents = _yaml_documents(config_text) if config_text is not None else None
                config_data = documents[0] if documents and len(documents) == 1 else None
                if isinstance(config_data, dict):
                    field = "eslintConfig" if tool == "eslint" else "prettier"
                    configured_tools(package, path, field, config_data)
                    continue
                scoped[package].append((_TOOL_FAMILY_TOKENS.get(tool, {tool}), reason))
                continue
            # A JavaScript config is read as source. A literal export is read
            # like its JSON form; a computed one can still name packages of
            # its own tool family.
            text = read_selected(package, path)
            if text is None:
                continue
            items, limitations = _source_imports(path, text)
            unknown[package].extend(limitations)
            config_strings[package].update(_config_string_candidates(path, text, "generic"))
            record(package, path, items)
            literal = _literal_config(path, text)
            if literal is None:
                scoped[package].append((_TOOL_FAMILY_TOKENS.get(tool, {tool}), reason))
            else:
                configured_tools(package, path, {"eslint": "eslintConfig"}.get(tool, tool), literal)
            continue
        if path.name in POSTCSS_DATA_CONFIGS:
            config_text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
            config_data = None
            if config_text is not None:
                try:
                    config_data = json.loads(config_text)
                except ValueError:
                    import yaml

                    try:
                        config_data = yaml.safe_load(config_text) if path.suffix != ".json" else None
                    except yaml.YAMLError:
                        config_data = None
            configured = _postcss_data_plugins(config_data)
            if configured is None:
                unknown[package].append({"kind": "unresolved_plugin_config", "file": str(path)})
            else:
                used[package].update(configured)
                imports[package].extend((name, path, 1, "static", "tooling") for name in configured)
            continue
        if path.name.startswith("tsconfig") and path.name.endswith(".json"):
            read_tsconfig(package, path)
            continue
        if path.name in plugin_data_configs and path.name not in DATA_CONFIGS | JSON_CONFIGS | POSTCSS_DATA_CONFIGS and suffix not in SOURCE_SUFFIXES:
            if not _is_plugin_config_path(path.relative_to(package).as_posix()):
                continue
            config_text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
            config_data = _parse_data_config(str(path), config_text) if config_text is not None else None
            for value in _string_values(config_data if isinstance(config_data, (dict, list)) else None):
                for candidate in {value, value.split(":", 1)[0]}:
                    name = _package_name(candidate) if len(candidate) <= 214 and not any(char.isspace() for char in candidate) else None
                    if name:
                        config_strings[package].add(name)
            continue
        if path.name in DATA_CONFIGS:
            config_text = read_project_text_no_symlink(root, path, max_bytes=MAX_BYTES)
            try:
                config_data = json.loads(config_text) if config_text is not None else None
            except (ValueError, RecursionError):
                config_data = None
            for value in _string_leaves(config_data):
                for candidate in {value, value.split(":", 1)[0]}:
                    name = _package_name(candidate) if len(candidate) <= 214 and not any(char.isspace() for char in candidate) else None
                    if name:
                        config_strings[package].add(name)
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
            configured_tools(package, path, field, config_data)
            continue
        if suffix in OPAQUE_SOURCE_SUFFIXES:
            unknown[package].append({"kind": "unanalysed_source", "file": str(path)})
            continue
        text = read_selected(package, path)
        if text is None:
            continue
        if suffix in STYLESHEET_SUFFIXES:
            found, limitations = _stylesheet_imports(path, text, suffix)
            unknown[package].extend(limitations)
            for name, line, reportable in found:
                used[package].add(name)
                if reportable and name != manifests[package].get("name"):
                    imports[package].append((name, path, line, "static", "tooling" if tooling_file(package, path) else "production"))
            continue
        if suffix in COMPONENT_SUFFIXES:
            items, stylesheet, limitations = _component_imports(path, text)
            for name, line, reportable in stylesheet:
                used[package].add(name)
                if reportable and name != manifests[package].get("name"):
                    imports[package].append((name, path, line, "static", "tooling" if tooling_file(package, path) else "production"))
        elif suffix in MDX_SUFFIXES:
            items, limitations = _mdx_imports(path, text)
        else:
            items, limitations = _source_imports(path, text)
            config_kind = _config_file_kind(path)
            if config_kind is None and path.name in _plugin_config_file_names()[1] and _is_plugin_config_path(path.relative_to(package).as_posix()):
                config_kind = "generic"  # a config file of a tool in the plugin table
            if config_kind is not None:
                config_strings[package].update(_config_string_candidates(path, text, config_kind))
            if path.name in POSTCSS_SCRIPT_CONFIGS:
                configured = _postcss_script_plugins(path, text)
                if configured is None:
                    limitations = [*limitations, {"kind": "unresolved_plugin_config", "file": str(path)}]
                else:
                    used[package].update(configured)
                    imports[package].extend((name, path, 1, "static", "tooling") for name in configured)
        unknown[package].extend(limitations)
        record(package, path, items)

    for package, target, pattern, config in tsconfig_inputs:
        if not pattern:
            including_configs[target].append(config)
            used[package].update(file_names.get(target, ()))
            continue
        prefix = str(target).rstrip(os.sep) + os.sep
        for path, names in file_names.items():
            if str(path).startswith(prefix):
                used[package].update(names)

    lock_cache = {}

    def lock_of(package):
        """Bins and peers from the nearest lockfile (package or ancestor)."""
        if package not in lock_cache:
            lock_cache[package] = next((facts for facts in (lockfile_facts(directory) for directory in [package, *ancestors_of(package), root]) if facts is not None), None)
        return lock_cache[package]

    def providers_in(package, names, command):
        """Declared ``names`` of ``package`` that provide ``command``."""
        known = BINARY_PROVIDERS.get(command, ())
        lock = lock_of(package) if package is not None else None
        locked = lock.providers(command) if lock is not None else set()
        return {name for name in names if command in (bins_of(package, name) or ()) or name in known or name == command or name in locked}

    def lineage_declarations(package):
        declaring = defaultdict(list)
        for directory in [package, *ancestors_of(package)]:
            for name in sorted(declared_by[directory]):
                declaring[name].append(directory)
        return declaring

    def resolve_target(base, target):
        """Package directory a package-manager target selects, or None."""
        kind, value = target
        if kind == "workspace" and value in workspace_dirs:
            return workspace_dirs[value]
        if kind == "cwd" or value.startswith((".", "/")):
            try:
                directory = (base / value).resolve()
            except (OSError, RuntimeError):
                return None
            return directory if directory in manifests else None
        return None

    def scripts_of(package):
        scripts = manifests[package].get("scripts")
        return scripts if isinstance(scripts, dict) else {}

    def follow_script(package, base, script):
        """Credit packages a runtime-loaded script file and its local imports load.

        Returns False when the script cannot be read but might load packages.
        """
        parts = Path(script).parts
        if "node_modules" in parts:
            # ``node ../../node_modules/typescript/lib/tsc.js`` runs that package.
            rest = parts[parts.index("node_modules") + 1:]
            name = _package_name("/".join(rest[:2])) if rest else None
            if name:
                used[package].add(name)
                return True
            return False
        start = (base / script)
        try:
            start = start.resolve()
        except (OSError, RuntimeError):
            return False
        candidates = [start] + [start.with_name(start.name + extension) for extension in (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")] + [start / "index.js"]
        first = next((candidate for candidate in candidates if candidate.is_file()), None)
        if first is None or not first.is_relative_to(root):
            # Build output (``node dist/server.js``) is generated from this
            # package's own source; a missing file elsewhere is unknown.
            return start.is_relative_to(package)
        pending, seen, complete = [first], set(), True
        while pending and len(seen) < MAX_SCRIPT_FILES:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            text = read_project_text_no_symlink(root, current, max_bytes=MAX_BYTES)
            if text is None:
                complete = False
                continue
            items, limitations = _source_imports(current, text)
            if limitations and not current.is_relative_to(package):
                complete = False
            # A script that spawns a tool names it by string (``spawn("tsx")``).
            used[package].update(_config_string_candidates(current, text, "generic") & set(lineage_declarations(package)))
            for specifier, _line_number, _kind in items:
                if specifier.startswith("."):
                    target = (current.parent / specifier).resolve()
                    options = [target] + [target.with_name(target.name + extension) for extension in (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".json")] + [target / "index.js"]
                    found = next((option for option in options if option.is_file() and option.suffix in SOURCE_SUFFIXES and option.is_relative_to(root)), None)
                    if found is not None:
                        pending.append(found)
                    continue
                name = _package_name(specifier)
                if name:
                    used[package].add(name)
        return complete

    # CI, container and task files run commands with the same parser as
    # package scripts. A command credits every declaration that provides it
    # (the working directory can change); an unknown command holds back only
    # the dependencies that could plausibly provide it.
    shell_files = set()
    pending_files = [(path, 0) for path in sorted(command_files)]
    while pending_files:
        command_path, file_depth = pending_files.pop(0)
        if file_depth:
            text = read_project_text_no_symlink(root, command_path, max_bytes=MAX_BYTES)
            lines = None if text is None else [(line, command_path.parent) for line in _command_lines(text)]
        else:
            lines = _command_file_lines(root, command_path)
        if lines is None:
            for package in roots:
                unknown[package].append({"kind": "unmodelled_command_file", "file": str(command_path)})
            continue
        for text, cwd in lines:
            if text is None:
                for package in roots:
                    unknown[package].append({"kind": "unmodelled_command_file", "file": str(command_path)})
                continue
            text = _GHA_EXPRESSION.sub("$GHA", text)
            context = owner(cwd) if cwd is not None and cwd.is_relative_to(root) else owner(root)
            names = scripts_of(context) if context is not None else {}
            for line in _command_lines(text):
                commands, dynamic = _script_commands(line, names, lenient=True)
                if dynamic:
                    # Only dependencies named like a word of the declined
                    # segment can be what it runs.
                    words = _unknown_words(line, names)
                    if words is None:
                        for package in roots:
                            unknown[package].append({"kind": "unresolved_command", "file": str(command_path)})
                        continue
                    reason = {"kind": "unresolved_command", "file": str(command_path), "words": sorted(words)[:20]}
                    for package in roots:
                        for name in declared_by[package]:
                            if any(_name_related(word, name) for word in words):
                                held[package][name].append(reason)
                for item in commands:
                    base = cwd if cwd is not None else root
                    target_package = context
                    if item.target is not None:
                        target_package = resolve_target(base, item.target)
                        if target_package is None:
                            continue
                        if item.name in scripts_of(target_package) or (item.name is not None and not _BIN_NAME.fullmatch(item.name)):
                            continue
                        base = target_package
                    if item.name is None and item.script:
                        script_path = (base / item.script).resolve()
                        if script_path.is_file() and script_path.is_relative_to(root) and script_path not in shell_files and file_depth < MAX_COMMAND_FILE_DEPTH and _shell_script(root, script_path):
                            shell_files.add(script_path)
                            pending_files.append((script_path, file_depth + 1))
                        continue
                    if item.name is None:
                        continue
                    if item.script and target_package is not None:
                        follow_script(target_package, base, item.script)
                    found = False
                    for package in roots:
                        for provider in providers_in(package, declared_by[package], item.name):
                            used[package].add(provider)
                            found = True
                    if found or item.name in SYSTEM_COMMANDS:
                        continue
                    reason = {"kind": "unknown_binary_provider", "binary": item.name, "file": str(command_path)}
                    for package in roots:
                        for name in declared_by[package]:
                            if bins_of(package, name) is None and _name_related(item.name, name):
                                held[package][name].append(reason)

    findings = []
    optional_peer_limitations = []
    # Children supply source evidence for shared ancestor tooling before the
    # ancestor's absence check is evaluated.
    for package in roots:
        data, manifest = manifests[package], package / "package.json"
        declared, sections = set(), defaultdict(list)
        for field in DEPENDENCY_FIELDS:
            values = data.get(field, {})
            if not isinstance(values, dict):
                unknown[package].append({"kind": "invalid_dependency_map", "field": field})
                continue
            for name in values:
                declared.add(name)
                sections[name].append(field)
        shareable = set()
        lineage = [package, *ancestors_of(package)]
        declaring = lineage_declarations(package)
        available = set(declaring)
        hints = set()
        configured, config_unknown = _plugin_names(data, shareable, hints)
        used[package].update(hints)
        for group in shareable:
            if not any(installed_manifest(package, name) for name in group):
                config_unknown.add("eslint")
        for field in ("imports", "exports", "browser"):
            targets = _configured_package_targets(data.get(field))
            if targets is None:
                unknown[package].append({"kind": "unresolved_plugin_config"})
            else:
                configured.update(targets)
        used[package].update(configured)
        for tool in sorted(config_unknown):
            scoped[package].append((_TOOL_FAMILY_TOKENS.get(tool, {tool}), {"kind": "unresolved_plugin_config", "tool": tool}))
        for key in sorted(_OPAQUE_MANIFEST_CONFIGS & data.keys()):
            if key == "lint-staged":
                # Values are commands run on staged files.
                for value in _string_leaves(data[key]):
                    commands, dynamic = _script_commands(value, scripts_of(package))
                    if dynamic:
                        unknown[package].append({"kind": "unresolved_script", "script": key})
                    for item in commands:
                        if item.name:
                            for provider in providers_in(package, available, item.name):
                                for declaration_owner in declaring[provider]:
                                    used[declaration_owner].add(provider)
                continue
            leaves = _string_leaves(data[key])
            names = {name for name in map(_package_name, leaves) if name}
            if key == "jest":
                names.update(pattern.format(name=value) for value in leaves if _PACKAGE.fullmatch(value) and not value.startswith("@") for pattern in _CONFIG_SHORTHANDS["jest"])
            used[package].update(names & declared)
            config_strings[package].update(names)
            scoped[package].append((_MANIFEST_TOOL_FAMILIES[key], {"kind": "unmodelled_tool_config", "tool": key}))
        for name in configured:
            imports[package].append((name, manifest, _line(source_text[package], "eslintConfig"), "static", "tooling"))
        if any((package / config).is_file() for config in _SIZE_LIMIT_CONFIGS) or "size-limit" in data:
            used[package].update(name for name in declared if name.startswith("@size-limit/"))
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            scripts = {}
            unknown[package].append({"kind": "invalid_scripts"})
        for tokens, reason in scoped[package]:
            for directory in lineage:
                for name in declared_by[directory]:
                    if _tool_related(tokens, name):
                        held[directory][name].append(reason)
        own_bins = set()
        if isinstance(data.get("bin"), str) and isinstance(data.get("name"), str):
            own_bins.add(data["name"].rsplit("/", 1)[-1])
        elif isinstance(data.get("bin"), dict):
            own_bins.update(binary for binary in data["bin"] if isinstance(binary, str))
        for script_name, script in scripts.items():
            preloads = _script_preloads(script)
            used[package].update(preloads)
            imports[package].extend((name, manifest, _line(source_text[package], script_name), "static", "tooling") for name in preloads)
            commands, dynamic = _script_commands(script, scripts)
            if dynamic:
                unknown[package].append({"kind": "unresolved_script", "script": script_name})
            for item in commands:
                context, context_declaring, context_available, base = package, declaring, available, package
                if item.target is not None:
                    context = resolve_target(package, item.target)
                    if context is None:
                        unknown[package].append({"kind": "unresolved_script_target", "script": script_name})
                        continue
                    if item.name in scripts_of(context):
                        continue  # That package's script is inspected there.
                    if item.name is not None and not _BIN_NAME.fullmatch(item.name):
                        unknown[package].append({"kind": "unresolved_script_target", "script": script_name})
                        continue
                    context_declaring = lineage_declarations(context)
                    context_available = set(context_declaring)
                    base = context
                if item.script and not follow_script(context, base, item.script):
                    unknown[package].append({"kind": "unresolved_script", "script": script_name, "file": item.script})
                if item.name is None:
                    continue
                command, origin = item.name, item.origin
                providers = providers_in(context, context_available, command)
                known = BINARY_PROVIDERS.get(command, ())
                if providers:
                    # Root tooling used by a workspace is evidence for the
                    # root declaration, without crediting sibling manifests.
                    for provider in providers:
                        for declaration_owner in context_declaring[provider]:
                            used[declaration_owner].add(provider)
                    continue
                if command in own_bins or (command in SYSTEM_COMMANDS and not known):
                    continue
                plausible = sorted(name for name in context_available if bins_of(context, name) is None and _name_related(command, name))
                if plausible:
                    reason = {"kind": "unknown_binary_provider", "binary": command, "script": script_name}
                    for name in plausible:
                        for declaration_owner in context_declaring[name]:
                            held[declaration_owner][name].append(reason)
                    continue
                if dynamic or origin == "npx" or (origin == "package_manager" and not known):
                    continue  # A fetching runner or unmodelled shorthand is not proof.
                provider = known[0] if known else command
                evidence = "known_binary_map" if known else "command_name"
                findings.append(_finding(RULE_BINARY, command, manifest, _line(source_text[package], script_name), f"Package script '{script_name}' invokes '{command}' without a declared npm provider ('{provider}').", package_name=provider, package_manifest=str(manifest), script=script_name, provider_evidence=evidence))
        script_words = [script.split() for script in scripts.values() if isinstance(script, str)]
        flag_words = {word.split("=", 1)[0].split(".", 1)[0] for words in script_words for word in words}
        for runner, flags in RUNNER_FLAG_PLUGINS.items():
            if runner in available or any(runner in words for words in script_words):
                for flag, plugins in flags.items():
                    if flag in flag_words:
                        used[package].update(plugins)
        for words in script_words:
            for index, word in enumerate(words[:-1]):
                used[package].update(RUNNER_SUBCOMMAND_PLUGINS.get(word, {}).get(words[index + 1], ()))
        seen = set()
        for name, path, line, kind, role, *rest in imports[package]:
            key = name, str(path), line
            if key in seen:
                continue
            if rest and name in package_names and role != "production" and workspace_alias(rest[0], path):
                continue  # Resolved to workspace source by a tsconfig or bundler alias.
            names = (name, _types_package(name)) if kind in _TYPE_KINDS else (name,)
            if any(candidate in declared for candidate in names) or _framework_alias(name, available):
                continue
            compilers = [owner(config) for config in including_configs.get(path, ())]
            compiled_by = next((compiler for compiler in compilers if compiler is not None and any(candidate in lineage_declarations(compiler) for candidate in names)), None)
            if compiled_by is not None and role != "production":
                continue  # A tsconfig of the package that declares it compiles this file.
            ancestor, declared_name = declaring_ancestor(package, *names)
            if ancestor is not None:
                # Resolution walks up to the ancestor's node_modules.
                used[ancestor].add(declared_name)
                if role != "production":
                    continue
                if not strict:
                    # Published source that relies on an ancestor declaration
                    # resolves in the repository; only strict mode reports it.
                    receipt["ancestor_declared_production_imports"] += 1
                    seen.add(key)
                    continue
            message = f"Package '{name}' is used but is not declared by this package's package.json."
            if ancestor is not None:
                message = f"Package '{name}' is used by published source but is declared only by an ancestor package.json; consumers of this package will not install it."
            findings.append(_finding(RULE_UNLISTED, name, path, line, message, package_name=name, package_manifest=str(manifest), **({"ancestor_manifest": str(ancestor / "package.json")} if ancestor is not None else {})))
            seen.add(key)
        # Optional peers are allowed to be absent; a runtime import that does
        # not handle that absence breaks consumers who skip the peer.
        peers = data.get("peerDependencies") if isinstance(data.get("peerDependencies"), dict) else {}
        peer_meta = data.get("peerDependenciesMeta") if isinstance(data.get("peerDependenciesMeta"), dict) else {}
        optional_peers = {
            name for name in peers
            if isinstance(peer_meta.get(name), dict) and peer_meta[name].get("optional") is True
            and not any(isinstance(data.get(field), dict) and name in data[field] for field in ("dependencies", "devDependencies"))
        }
        if optional_peers and _has_subpath_entries(data):
            optional_peer_limitations.append({"package_manifest": str(manifest), "kind": "subpath_entry_points"})
        elif optional_peers:
            reported = set()
            for name, path, line in sorted(static_imports[package], key=lambda item: (str(item[1]), item[2])):
                if name in optional_peers and name not in reported:
                    reported.add(name)
                    count = sum(1 for item in static_imports[package] if item[0] == name)
                    findings.append(_finding(RULE_OPTIONAL_PEER, name, path, line, f"Optional peer dependency '{name}' is imported statically; consumers that omit the optional peer cannot load this module.", severity="LOW", package_name=name, package_manifest=str(manifest), import_count=count))
        used[package].update(config_strings[package] & available)
        # A framework used by this package also uses its required peers.
        pending = sorted(used[package] & available)
        visited = set()
        while pending:
            host = pending.pop()
            if host in visited:
                continue
            visited.add(host)
            metadata = installed_manifest(package, host) or workspace_manifests.get(host)
            contract = set(KNOWN_PEER_CONTRACTS.get(host, ()))
            if isinstance(metadata, dict) and isinstance(metadata.get("peerDependencies"), dict):
                contract.update(name for name in metadata["peerDependencies"] if isinstance(name, str))
            lock = lock_of(package)
            if lock is not None:
                # The lockfile records the host's peers without node_modules.
                contract.update(lock.peers.get(host, ()))
            for peer in sorted((contract & available) - used[package]):
                used[package].add(peer)
                pending.append(peer)
        # What this package uses but an ancestor declares is the ancestor's use.
        for name in sorted(used[package] - declared):
            ancestor, _name = declaring_ancestor(package, name)
            if ancestor is not None:
                used[ancestor].add(name)
        # Peer dependencies are published consumer contracts, not unused
        # implementation dependencies. A type package stays while the package
        # it describes is used anywhere, a tsconfig/reference names it, or its
        # ambient global is referenced.
        used_anywhere = set().union(*used.values())

        def types_used(name, used_anywhere=used_anywhere):
            target = _types_target(name)
            if name in used_anywhere or target in used_anywhere:
                return True
            if target == "node" or _node_builtin(target):
                return bool(node_usage)
            return target.split(".", 1)[0] in ambient_seen

        candidates = {name for name in declared - used[package] if sections[name][0] != "peerDependencies" and not (name.startswith("@types/") and types_used(name))}
        if walk_error or not complete_scope:
            unknown[package].append({"kind": "incomplete_source_scope"})
        held_candidates = candidates & held[package].keys()
        limitation_kinds = sorted({reason["kind"] for reason in unknown[package]} | {reason["kind"] for name in held_candidates for reason in held[package][name]})
        if limitation_kinds:
            receipt["limitations_by_package"][str(manifest)] = limitation_kinds
        if unknown[package]:
            receipt["abstained_dependencies"].extend({"package_manifest": str(manifest), "name": name} for name in sorted(candidates))
            receipt["reasons"].extend({"package_manifest": str(manifest), **reason} for reason in unknown[package])
            # This package's unresolved use can only reach an ancestor's
            # declaration that resolution walks up to: one that neither this
            # package nor a nearer ancestor declares itself.
            shadowed = set(declared)
            reason = {"kind": "unresolved_workspace_consumer", "consumer_manifest": str(manifest)}
            for ancestor in ancestors_of(package):
                for name in declared_by[ancestor] - shadowed:
                    held[ancestor][name].append(reason)
                shadowed |= declared_by[ancestor]
        else:
            for name in sorted(candidates):
                if name in held[package]:
                    reasons = held[package][name]
                    entry = {"package_manifest": str(manifest), "name": name}
                    binaries = sorted({reason["binary"] for reason in reasons if "binary" in reason})
                    if binaries:
                        entry["binaries"] = binaries
                    others = sorted({reason["kind"] for reason in reasons if "binary" not in reason})
                    if others:
                        entry["limitations"] = others
                    receipt["abstained_dependencies"].append(entry)
                    continue
                # Each declaration of the package is unused, in every section.
                for section in sections[name]:
                    if section == "peerDependencies":
                        continue
                    findings.append(_finding(RULE_UNUSED, name, manifest, _section_line(source_text[package], section, name), f"Declared npm dependency '{name}' has no source import, package-script command or supported tool-config use in this package.", package_name=name, package_manifest=str(manifest), dependency_section=section))
        for name in sorted(held_candidates):
            for reason in held[package][name]:
                receipt["reasons"].append({"package_manifest": str(manifest), "dependency": name, **reason})
        receipt["packages"].append(str(manifest))
    catalog_analyses = []
    if workspace_files:
        findings.extend(_catalog_findings(root, workspace_files, manifests, source_text, catalog_analyses))
    receipt["catalog_analysis"] = catalog_analyses
    receipt["optional_peer_limitations"] = optional_peer_limitations
    receipt["abstained_count"] = len(receipt["abstained_dependencies"])
    if receipt["reasons"]:
        receipt.update(status="incomplete", complete=False)
    return findings
