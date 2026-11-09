from __future__ import annotations

import json
import os
import re
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from skylos.core.js_api_surface_utils import (
    MAX_JS_API_SURFACE_SOURCE_BYTES,
    read_package_json,
)
from skylos.core.safe_cache_io import read_project_text_no_symlink, read_text_no_symlink
from skylos.rules.ai_defect.dependency_hallucination import (
    RULE_ID_HALLUCINATION,
    RULE_ID_UNDECLARED,
    _is_confident_hallucination_candidate,
)
from skylos.rules.ai_defect.js_api_hallucination import (
    _NODE_BUILTINS,
    JS_SOURCE_SUFFIXES,
    _browser_remaps_source,
    _package_name_for_source,
)
from skylos.rules.ai_defect.manifest_dependency_hallucination import (
    STATUS_MISSING_PACKAGE,
    STATUS_UNKNOWN,
)
from skylos.rules.sca.vulnerability_scanner import ECOSYSTEM_NPM
from skylos.visitors.languages.typescript import is_minified_js_source
from skylos.visitors.languages.typescript.resolve import (
    MonorepoResolver,
    _parse_tsconfig_paths,
)
from skylos.visitors.languages.typescript.workspace import _load_jsonc

try:
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Parser

    _TS_LANGUAGE: Language | None = Language(_tsts.language_typescript())
    _TSX_LANGUAGE: Language | None = Language(_tsts.language_tsx())
except (ImportError, OSError, TypeError, ValueError):  # pragma: no cover
    _TS_LANGUAGE = None
    _TSX_LANGUAGE = None

_TS_GRAMMAR_SUFFIXES = (".ts", ".mts", ".cts")
_FIXTURE_DIR_NAMES = frozenset({"__testfixtures__", "__fixtures__", "fixtures"})
_FIXTURE_STEM_SUFFIXES = (".input", ".output")
_SPECIFIER_STATEMENTS = frozenset(
    {"import_statement", "export_statement", "import_require_clause"}
)
_NPM_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_MAX_NPM_PACKAGE_CHARS = 214
_LOCAL_SPECIFIER_PREFIXES = ("~", "$", "@/", "@~", "\\")
_STYLE_SUFFIXES = (".css", ".scss", ".sass", ".less", ".styl", ".stylus", ".pcss")
_DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)
_DEFAULT_NPM_REGISTRY_HOSTS = frozenset(
    {"registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com"}
)
_REGISTRY_ENV_VARS = (
    "npm_config_registry",
    "NPM_CONFIG_REGISTRY",
    "YARN_NPM_REGISTRY_SERVER",
    "YARN_REGISTRY",
)
_ALIAS_CONFIG_RE = re.compile(
    r"^(?:(?:vite|vitest|webpack|rollup|rspack|rsbuild|babel|jest|next|nuxt|"
    r"svelte|astro|craco|metro|tsup|esbuild|parcel|snowpack|remix|quasar|vue|"
    r"electron\.vite|react-router|storybook|modern|umi|ice|rolldown|tsdown|"
    r"build|docusaurus|farm|rspress)\.config"
    r"(?:\.[\w-]+)*\.(?:[cm]?[jt]s|json)|\.babelrc(?:\.json|\.js|\.cjs)?|"
    r"deno(?:\.[\w-]+)*\.jsonc?|import[_-]map(?:\.[\w-]+)*\.json|\.parcelrc|"
    r"angular\.json)$"
)
_PACKAGE_JSON_ALIAS_KEYS = ("alias", "jest", "babel", "imports")
_FRAMEWORK_ALIASES = {
    "@docusaurus/core": (
        "@docusaurus/",
        "@site/",
        "@theme/",
        "@theme-original/",
        "@theme-init/",
        "@generated/",
    ),
    "vite": ("@vite/",),
    "vitepress": ("@theme/",),
}
_RUNTIME_MODULES = frozenset({"bun"})
_HOST_ENGINE_MODULES = {"vscode": "vscode"}
_WORKSPACE_MANIFESTS = ("deno.json", "deno.jsonc", "jsr.json")
_DECLARE_MODULE_RE = re.compile(r"""\bdeclare\s+module\s+(['"])([^'"\r\n]+)\1""")
_DECLARATION_DIR_NAMES = frozenset({"types", "typings", "@types", "typedefs"})
_SKIPPED_WALK_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        "dist",
        "build",
        "out",
        "coverage",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".turbo",
        ".cache",
        "vendor",
        ".venv",
        "venv",
        "__pycache__",
    }
)
_MAX_WALK_DIRS = 20_000
_MAX_SCANNED_FILES = 40_000
_USAGE_SUFFIXES = (*JS_SOURCE_SUFFIXES, ".vue", ".svelte", ".astro", ".mdx")
_KEY_FILE_RE = re.compile(
    r"^(?:package|tsconfig(?:\.[\w-]+)*|jsconfig(?:\.[\w-]+)*|deno(?:\.[\w-]+)*|"
    r"import[_-]map(?:\.[\w-]+)*|jsr|\.babelrc|[\w.-]+\.config)\.jsonc?$"
)
_MAX_CONFIG_BYTES = 1_000_000
_MAX_REGISTRY_LOOKUPS = 50

SEV_CRITICAL = "CRITICAL"
SEV_MEDIUM = "MEDIUM"


def scan_diff_js_added_imports(
    repo_root: str | Path,
    added_files: list[tuple[str, list[tuple[int, str]]]],
    *,
    status_checker,
) -> dict[str, Any]:
    """Check package imports added to JavaScript/TypeScript files.

    A bare specifier is looked up on the npm registry only when no package.json
    in the importer's folder chain declares it, no node_modules folder holds it,
    and no workspace package, tsconfig/jsconfig path, bundler alias or ambient
    module declaration (outside the change itself) claims it. A configured
    private registry makes the public registry's answer meaningless, so those
    imports are left unchecked. Returns findings, whether a lookup could not be
    completed, and the files whose imports could not be checked.
    """
    root = _safe_root(repo_root)
    unchecked: list[str] = []
    if root is None:
        return {
            "findings": [],
            "registry_unreachable": False,
            "unchecked_files": [path for path, _ in added_files],
        }
    project = _Project(root, added_files, status_checker)
    candidates: list[tuple[str, int, str, str, list[Path]]] = []
    for file_path, added_lines in added_files:
        imports = _added_imports(root, file_path, added_lines)
        if imports is None:
            unchecked.append(file_path)
            continue
        seen: set[str] = set()
        for specifier, line_no in imports:
            candidate = project.candidate(file_path, specifier)
            if candidate is None or candidate[0] in seen:
                continue
            package, chain = candidate
            seen.add(package)
            candidates.append((file_path, line_no, specifier, package, chain))
    findings: list[dict[str, Any]] = []
    if candidates:
        evidence = _walk_project(
            root, project.added, frozenset(_tokens(c[3]) for c in candidates)
        )
        for file_path, line_no, specifier, package, chain in candidates:
            verdict = project.resolve(evidence, specifier, package, chain)
            if verdict == "private" and file_path not in unchecked:
                unchecked.append(file_path)
            elif verdict == "missing":
                findings.append(_finding(file_path, line_no, package, specifier, True))
            elif verdict == "undeclared":
                findings.append(_finding(file_path, line_no, package, specifier, False))
    return {
        "findings": findings,
        "registry_unreachable": project.unreachable,
        "unchecked_files": unchecked,
    }


def _safe_root(repo_root: str | Path) -> Path | None:
    try:
        root = Path(repo_root).resolve()
    except (OSError, RuntimeError):
        return None
    if not root.is_dir():
        return None
    return root


def _language_for(file_path: str):
    if file_path.endswith(_TS_GRAMMAR_SUFFIXES):
        return _TS_LANGUAGE
    return _TSX_LANGUAGE


def _added_imports(
    root: Path,
    file_path: str,
    added_lines: list[tuple[int, str]],
) -> list[tuple[str, int]] | None:
    language = _language_for(file_path)
    if language is None or _is_transform_fixture(file_path):
        return None
    text = read_project_text_no_symlink(
        root,
        file_path,
        max_bytes=MAX_JS_API_SURFACE_SOURCE_BYTES,
        encoding="utf-8",
        errors="replace",
    )
    if text is None:
        return None
    source = text.encode("utf-8", "replace")
    if is_minified_js_source(file_path, source):
        return None
    file_lines = text.splitlines()
    added: set[int] = set()
    for line_no, line_text in added_lines:
        if line_no < 1 or line_no > len(file_lines):
            return None
        if file_lines[line_no - 1].rstrip("\r") != line_text.rstrip("\r"):
            return None
        added.add(line_no)
    tree = Parser(language).parse(source)
    if tree.root_node.has_error:
        return None
    found: list[tuple[str, int]] = []
    for node in _module_specifier_nodes(tree.root_node, source):
        line_no = node.start_point[0] + 1
        if line_no not in added:
            continue
        value = _string_value(node, source)
        if value:
            found.append((value, line_no))
    return sorted(found, key=lambda item: item[1])


def _is_transform_fixture(file_path: str) -> bool:
    path = PurePosixPath(file_path)
    if _FIXTURE_DIR_NAMES & set(path.parts[:-1]):
        return True
    stem = path.name.split(".", 1)[0]
    rest = path.name[len(stem) :]
    return rest.startswith(_FIXTURE_STEM_SUFFIXES)


def _module_specifier_nodes(root_node: Any, source: bytes):
    stack = [root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)
        if node.type in _SPECIFIER_STATEMENTS:
            specifier = node.child_by_field_name("source")
            if specifier is not None and specifier.type == "string":
                yield specifier
        elif node.type == "call_expression":
            specifier = _loader_argument(node, source)
            if specifier is not None:
                yield specifier


def _loader_argument(node: Any, source: bytes) -> Any | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or not arguments.named_children:
        return None
    first = arguments.named_children[0]
    if first.type != "string":
        return None
    if function.type == "import":
        return first
    if function.type != "identifier":
        return None
    if source[function.start_byte : function.end_byte] != b"require":
        return None
    return first


def _string_value(node: Any, source: bytes) -> str | None:
    parts: list[str] = []
    for child in node.named_children:
        if child.type != "string_fragment":
            return None
        parts.append(
            source[child.start_byte : child.end_byte].decode("utf-8", "replace")
        )
    return "".join(parts) or None


def _package_for(specifier: str) -> str | None:
    if specifier.startswith(_LOCAL_SPECIFIER_PREFIXES) or any(
        char.isspace() for char in specifier
    ):
        return None
    package = _package_name_for_source(specifier)
    if package is None or package.startswith("@/"):
        return None
    if package.endswith(_STYLE_SUFFIXES):
        return None
    if len(package) > _MAX_NPM_PACKAGE_CHARS or not _NPM_PACKAGE_RE.match(package):
        return None
    return package


def _types_package(package: str) -> str:
    if package.startswith("@"):
        return "@types/" + package[1:].replace("/", "__")
    return f"@types/{package}"


def _chain(root: Path, importer: Path) -> list[Path]:
    folders: list[Path] = []
    current = importer.parent
    while True:
        folders.append(current)
        if current == root or current.parent == current:
            return folders
        current = current.parent


class _Project:
    def __init__(
        self,
        root: Path,
        added_files: list[tuple[str, list[tuple[int, str]]]],
        status_checker,
    ) -> None:
        self.root = root
        self.added = {path: {line for line, _ in lines} for path, lines in added_files}
        self.status_checker = status_checker
        self.resolver = MonorepoResolver(str(root))
        self.unreachable = False
        self.lookups: dict[str, str] = {}
        self._registry_cache: dict[Path, tuple[bool, frozenset[str]]] = {}
        self._home_registry: tuple[bool, frozenset[str]] | None = None

    def candidate(
        self, file_path: str, specifier: str
    ) -> tuple[str, list[Path]] | None:
        package = _package_for(specifier)
        if package is None:
            return None
        if specifier in _NODE_BUILTINS or package in _NODE_BUILTINS:
            return None
        if package in _RUNTIME_MODULES:
            return None
        importer = self.root / file_path
        try:
            importer.relative_to(self.root)
        except ValueError:
            return None
        chain = _chain(self.root, importer)
        if self._claimed_locally(importer, chain, specifier, package):
            return None
        if self._declared(chain, package):
            return None
        if self._framework_provided(chain, specifier, package):
            return None
        if self._installed(chain, package):
            return None
        if self._aliased(chain, package):
            return None
        return package, chain

    def resolve(
        self,
        evidence: _Evidence,
        specifier: str,
        package: str,
        chain: list[Path],
    ) -> str:
        if evidence.claims(specifier, package):
            return "local"
        if not evidence.complete:
            return "skipped"
        if self._private_registry(chain, package):
            return "private"
        status = self._lookup(package)
        if status == STATUS_UNKNOWN:
            self.unreachable = True
            return "unknown"
        if status == STATUS_MISSING_PACKAGE:
            if _is_confident_hallucination_candidate(package):
                return "missing"
            return "skipped"
        return "undeclared"

    def _claimed_locally(
        self,
        importer: Path,
        chain: list[Path],
        specifier: str,
        package: str,
    ) -> bool:
        if self.resolver.claims_local_source(specifier, str(importer)):
            return True
        if _browser_remaps_source(self.root, importer, specifier):
            return True
        first = package.split("/", 1)[0]
        for folder in chain:
            if _module_exists(folder, first) or _module_exists(folder / "src", first):
                return True
            config = folder / "jsconfig.json"
            if config.is_file() and _jsconfig_claims(config, specifier, first):
                return True
        return False

    def _declared(self, chain: list[Path], package: str) -> bool:
        names = {package, _types_package(package)}
        for folder in chain:
            data = read_package_json(folder / "package.json")
            if data.get("name") == package:
                return True
            for section in _DEPENDENCY_SECTIONS:
                dependencies = data.get(section)
                if isinstance(dependencies, dict) and names & set(dependencies):
                    return True
            for key in ("bundledDependencies", "bundleDependencies"):
                bundled = data.get(key)
                if isinstance(bundled, list) and package in bundled:
                    return True
        return False

    def _framework_provided(
        self, chain: list[Path], specifier: str, package: str
    ) -> bool:
        for folder in chain:
            data = read_package_json(folder / "package.json")
            engines = data.get("engines")
            if (
                isinstance(engines, dict)
                and _HOST_ENGINE_MODULES.get(package) in engines
            ):
                return True
            declared = {data.get("name")}
            for section in _DEPENDENCY_SECTIONS:
                dependencies = data.get(section)
                if isinstance(dependencies, dict):
                    declared.update(dependencies)
            for framework, prefixes in _FRAMEWORK_ALIASES.items():
                if framework in declared and specifier.startswith(prefixes):
                    return True
        return False

    def _installed(self, chain: list[Path], package: str) -> bool:
        for folder in chain:
            modules = folder / "node_modules"
            for name in (package, _types_package(package)):
                if os.path.lexists(modules / name):
                    return True
        return False

    def _aliased(self, chain: list[Path], package: str) -> bool:
        names = "|".join(re.escape(name) for name in sorted(_tokens(package)))
        token = re.compile(r"(?<![A-Za-z0-9_@.-])(?:" + names + r")(?![A-Za-z0-9_.-])")
        for folder in chain:
            data = read_package_json(folder / "package.json")
            for key in _PACKAGE_JSON_ALIAS_KEYS:
                if key in data and token.search(json.dumps(data[key])):
                    return True
            try:
                entries = sorted(os.listdir(folder))
            except OSError:
                continue
            for name in entries:
                if not _ALIAS_CONFIG_RE.match(name):
                    continue
                text = read_text_no_symlink(
                    folder / name,
                    max_bytes=_MAX_CONFIG_BYTES,
                    encoding="utf-8",
                    errors="replace",
                )
                if text is None or token.search(text):
                    return True
        return False

    def _private_registry(self, chain: list[Path], package: str) -> bool:
        for custom, scopes in [
            self._home_config(),
            *(self._folder_config(f) for f in chain),
        ]:
            if custom:
                return True
            if package.startswith("@") and package.split("/", 1)[0] in scopes:
                return True
        return False

    def _home_config(self) -> tuple[bool, frozenset[str]]:
        if self._home_registry is None:
            custom = any(
                not _default_registry(os.environ.get(name, ""))
                for name in _REGISTRY_ENV_VARS
                if os.environ.get(name, "").strip()
            )
            home_custom, scopes = _registry_config(Path.home())
            self._home_registry = (custom or home_custom, scopes)
        return self._home_registry

    def _folder_config(self, folder: Path) -> tuple[bool, frozenset[str]]:
        if folder not in self._registry_cache:
            self._registry_cache[folder] = _registry_config(folder)
        return self._registry_cache[folder]

    def _lookup(self, package: str) -> str:
        if package in self.lookups:
            return self.lookups[package]
        if self.unreachable or len(self.lookups) >= _MAX_REGISTRY_LOOKUPS:
            return STATUS_UNKNOWN
        status = self.status_checker(ECOSYSTEM_NPM, package, "*", {})
        self.lookups[package] = status
        return status


def _jsconfig_claims(config: Path, specifier: str, first: str) -> bool:
    base_url, paths = _parse_tsconfig_paths(str(config))
    if any(pattern != "*" and fnmatchcase(specifier, pattern) for pattern in paths):
        return True
    return bool(base_url) and _module_exists(Path(base_url), first)


def _module_exists(folder: Path, name: str) -> bool:
    if os.path.lexists(folder / name):
        return True
    return any(
        os.path.lexists(folder / f"{name}{suffix}")
        for suffix in (*JS_SOURCE_SUFFIXES, ".d.ts", ".json")
    )


def _tokens(package: str) -> frozenset[str]:
    if package.startswith("@"):
        return frozenset({package, package.split("/", 1)[0]})
    return frozenset({package})


class _Evidence:
    def __init__(self) -> None:
        self.names: set[str] = set()
        self.ambient: set[str] = set()
        self.used: set[str] = set()
        self.keyed: set[str] = set()
        self.complete = True

    def claims(self, specifier: str, package: str) -> bool:
        tokens = _tokens(package)
        if package in self.names or tokens & (self.used | self.keyed):
            return True
        return any(
            fnmatchcase(specifier, pattern) or fnmatchcase(package, pattern)
            for pattern in self.ambient
        )


def _walk_project(
    root: Path, added: dict[str, set[int]], token_sets: frozenset[frozenset[str]]
) -> _Evidence:
    evidence = _Evidence()
    tokens = sorted({token for group in token_sets for token in group})
    names = "|".join(re.escape(token) for token in tokens)
    usage = re.compile(
        r"""(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s+)["'`]("""
        + names
        + r""")(?=["'`/])"""
    )
    key = re.compile(
        r"""["'`]\^?(""" + names + r""")(?=["'`/(\\$*])[^"'`\r\n]{0,200}["'`]\s*:"""
    )
    folders = 0
    scanned = 0
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        folders += 1
        if folders > _MAX_WALK_DIRS:
            evidence.complete = False
            return evidence
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIPPED_WALK_DIRS)
        folder = Path(current)
        for filename in filenames:
            path = folder / filename
            if filename == "package.json":
                name = read_package_json(path).get("name")
                if isinstance(name, str) and name.strip():
                    evidence.names.add(name.strip())
            elif filename in _WORKSPACE_MANIFESTS:
                name = _load_jsonc(path).get("name")
                if isinstance(name, str) and name.strip():
                    evidence.names.add(name.strip())
            reads_usage = filename.endswith(_USAGE_SUFFIXES)
            reads_keys = reads_usage or bool(_KEY_FILE_RE.match(filename))
            declares = _declares_modules(folder, filename)
            if not (reads_keys or declares):
                continue
            scanned += 1
            if scanned > _MAX_SCANNED_FILES:
                evidence.complete = False
                return evidence
            text = read_text_no_symlink(
                path, max_bytes=_MAX_CONFIG_BYTES, encoding="utf-8", errors="replace"
            )
            if text is None:
                continue
            own = added.get(path.relative_to(root).as_posix(), set())
            if declares:
                evidence.ambient.update(_ambient_modules(text, own))
            if not any(token in text for token in tokens):
                continue
            if reads_usage:
                evidence.used.update(_unchanged_matches(usage, text, own))
            if reads_keys:
                evidence.keyed.update(_unchanged_matches(key, text, set()))
    return evidence


def _unchanged_matches(pattern: re.Pattern[str], text: str, own: set[int]) -> set[str]:
    found: set[str] = set()
    for match in pattern.finditer(text):
        if own and text.count("\n", 0, match.start()) + 1 in own:
            continue
        found.add(match.group(1))
    return found


def _declares_modules(folder: Path, filename: str) -> bool:
    if filename.endswith((".d.ts", ".d.mts", ".d.cts")):
        return True
    if not filename.endswith((".ts", ".tsx", ".mts", ".cts")):
        return False
    return folder.name in _DECLARATION_DIR_NAMES


def _ambient_modules(text: str, added_lines: set[int]) -> set[str]:
    modules: set[str] = set()
    for match in _DECLARE_MODULE_RE.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        if line_no in added_lines:
            continue
        modules.add(match.group(2))
    return modules


def _default_registry(url: str) -> bool:
    value = url.strip().strip("\"'")
    if not value:
        return True
    host = urlsplit(value).hostname
    return host in _DEFAULT_NPM_REGISTRY_HOSTS


def _registry_config(folder: Path) -> tuple[bool, frozenset[str]]:
    custom = False
    scopes: set[str] = set()
    for name in (".npmrc", ".yarnrc"):
        text = read_text_no_symlink(
            folder / name,
            max_bytes=_MAX_CONFIG_BYTES,
            encoding="utf-8",
            errors="replace",
        )
        if text is None:
            continue
        for key, value in _rc_entries(text):
            if key == "registry" and not _default_registry(value):
                custom = True
            elif (
                key.startswith("@")
                and key.endswith(":registry")
                and not _default_registry(value)
            ):
                scopes.add(key[: -len(":registry")])
    yarn_custom, yarn_scopes = _yarnrc_yml_config(folder / ".yarnrc.yml")
    return custom or yarn_custom, frozenset(scopes | yarn_scopes)


def _rc_entries(text: str):
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
        else:
            key, _, value = line.partition(" ")
        yield key.strip().strip("\"'"), value.strip()


def _yarnrc_yml_config(path: Path) -> tuple[bool, set[str]]:
    text = read_text_no_symlink(
        path, max_bytes=_MAX_CONFIG_BYTES, encoding="utf-8", errors="replace"
    )
    if text is None:
        return False, set()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return True, set()
    if not isinstance(data, dict):
        return False, set()
    server = data.get("npmRegistryServer")
    custom = isinstance(server, str) and not _default_registry(server)
    scopes: set[str] = set()
    npm_scopes = data.get("npmScopes")
    if isinstance(npm_scopes, dict):
        for scope, settings in npm_scopes.items():
            scope_server = ""
            if isinstance(settings, dict):
                scope_server = str(settings.get("npmRegistryServer") or "")
            if scope_server and _default_registry(scope_server):
                continue
            scopes.add("@" + str(scope).lstrip("@"))
    return custom, scopes


def _finding(
    file_path: str,
    line_no: int,
    package: str,
    specifier: str,
    missing: bool,
) -> dict[str, Any]:
    if missing:
        rule_id = RULE_ID_HALLUCINATION
        kind = "hallucinated_import"
        severity = SEV_CRITICAL
        message = (
            f"Hallucinated npm import '{package}'. Package does not exist in the "
            "npm registry, and nothing in this project provides it."
        )
    else:
        rule_id = RULE_ID_UNDECLARED
        kind = "undeclared_import"
        severity = SEV_MEDIUM
        message = (
            f"Undeclared npm import '{package}'. No package.json declares it and "
            "no node_modules folder installs it."
        )
    return {
        "rule_id": rule_id,
        "kind": kind,
        "severity": severity,
        "message": message,
        "file": file_path,
        "line": line_no,
        "col": 0,
        "symbol": package,
        "category": "ai_defect",
        "defect_type": "dependency_hallucination",
        "vibe_category": "dependency_hallucination",
        "ai_likelihood": "high",
        "metadata": {"ecosystem": ECOSYSTEM_NPM, "specifier": specifier},
    }
