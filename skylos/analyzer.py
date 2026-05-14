#!/usr/bin/env python3
import ast
import sys
import json
import logging
import os
import traceback
from pathlib import Path
from collections import Counter, defaultdict

try:
    from skylos_fast import discover_files as _fast_discover
except ImportError:
    _fast_discover = None

from skylos.visitors.base import Visitor

from skylos.analysis.circular_deps import CircularDependencyRule, _resolve_from_import_targets

from skylos.constants import AUTO_CALLED, MARKREFS_TICK_DEFAULT

from skylos.visitors.framework_aware import FrameworkAwareVisitor
from skylos.visitors.test_aware import TestAwareVisitor
from skylos.visitors.languages.php import scan_php_file
from skylos.visitors.languages.dart import scan_dart_file
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.analysis import (
    build_ts_import_graph,
    demote_unconsumed_ts_exports,
    find_dead_ts_files,
    find_unused_ts_exports,
)
from skylos.visitors.languages.go import scan_go_file, clear_go_cache
from skylos.visitors.languages.java import scan_java_file
from skylos.visitors.languages.rust import scan_rust_file

from skylos.rules.secrets import scan_ctx as _secrets_scan_ctx

from skylos.rules.danger.calls import DangerousCallsRule


from skylos.config import get_all_ignore_lines, load_config
from skylos.core.file_discovery import (
    discover_source_files,
    find_git_root,
    should_exclude_path,
)

from skylos.core.linter import LinterVisitor

from skylos.rules.quality.complexity import ComplexityRule, CognitiveComplexityRule
from skylos.rules.quality.nesting import NestingRule
from skylos.rules.quality.structure import ArgCountRule, FunctionLengthRule
from skylos.rules.quality.logic import (
    MutableDefaultRule,
    BareExceptRule,
    DangerousComparisonRule,
    DuplicateBranchRule,
    TryBlockPatternsRule,
    UnusedExceptVarRule,
    ReturnConsistencyRule,
    EmptyErrorHandlerRule,
    MissingResourceCleanupRule,
    DebugLeftoverRule,
    SecurityTodoRule,
    DisabledSecurityRule,
    PhantomCallRule,
    InsecureRandomRule,
    HardcodedCredentialRule,
    MockPlaceholderDataRule,
    ErrorDisclosureRule,
    BroadFilePermissionsRule,
    PhantomDecoratorRule,
    UnfinishedGenerationRule,
    UndefinedConfigRule,
    StaleMockRule,
    DuplicateStringLiteralRule,
    TooManyReturnsRule,
    BooleanTrapRule,
    BroadExceptionRule,
    MissingNetworkTimeoutRule,
    NoEffectStatementRule,
)
from skylos.rules.quality.practices import (
    FrameworkPracticeRule,
    TypeAnnotationPracticeRule,
)
from skylos.rules.quality.policy import analyze_repo_policy
from skylos.rules.quality.phantom_refs import scan_repo_phantom_security_references
from skylos.rules.vibe_dictionary import build_vibe_dictionary
from skylos.rules.quality.performance import PerformanceRule
from skylos.rules.quality.unreachable import UnreachableCodeRule
from skylos.rules.quality.async_blocking import AsyncBlockingRule
from skylos.rules.quality.class_size import GodClassRule, GodFileRule
from skylos.rules.quality.coupling import CBORule
from skylos.rules.quality.cohesion import LCOMRule
from skylos.rules.quality.clones import (
    CloneConfig,
    GroupingMode,
    CloneType,
    extract_fragments,
    detect_pairs,
    group_pairs,
)

from skylos.analysis.penalties import apply_penalties

from skylos.scale.parallel_static import run_proc_file_parallel
from skylos.rules.custom import load_custom_rules, load_community_rules

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("Skylos")

_SECRET_CONFIG_SUFFIXES = {
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
}

_TS_JS_SOURCE_EXTS = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
)
_PHP_SOURCE_EXTS = (".php",)
_RUST_SOURCE_EXTS = (".rs",)
_DART_SOURCE_EXTS = (".dart",)

_TRY_NODE_TYPES = (ast.Try, getattr(ast, "TryStar", ast.Try))


def _entrypoint_module_name(qname: str) -> str | None:
    if not isinstance(qname, str) or "." not in qname:
        return None
    module_name, _symbol = qname.rsplit(".", 1)
    return module_name or None


def _architecture_iad_strict(architecture_cfg) -> bool:
    if not isinstance(architecture_cfg, dict):
        return False
    for key in ("enforce_iad", "strict_iad"):
        if key in architecture_cfg:
            return bool(architecture_cfg.get(key))
    return False


def _expand_reexported_entrypoint_modules(
    entrypoint_qnames: set[str],
    entrypoint_modules: set[str],
    raw_imports_by_file: dict[Path, list],
    modmap: dict[Path, str],
    module_files: dict[str, str],
) -> set[str]:
    modules = set(entrypoint_modules)
    known_modules = set(module_files)

    for qname in entrypoint_qnames:
        if "." not in qname:
            continue

        entry_module, entry_symbol = qname.rsplit(".", 1)
        for file_path, raw_imports in raw_imports_by_file.items():
            if modmap.get(file_path) != entry_module:
                continue

            for import_module, _line, import_type, imported_names in raw_imports:
                if import_type != "from_import":
                    continue
                if entry_symbol not in imported_names:
                    continue
                if import_module in known_modules:
                    modules.add(import_module)

    return modules


def _find_package_boundary_modules(
    raw_imports_by_file: dict[Path, list],
    modmap: dict[Path, str],
    module_files: dict[str, str],
) -> set[str]:
    modules: set[str] = set()
    known_modules = set(module_files)

    for file_path, raw_imports in raw_imports_by_file.items():
        package_module = modmap.get(file_path)
        if not package_module or Path(file_path).name != "__init__.py":
            continue

        for import_module, _line, import_type, imported_names in raw_imports:
            if import_type != "from_import":
                continue

            targets = _resolve_from_import_targets(
                import_module,
                imported_names,
                known_modules,
            )
            for target in targets:
                if target != package_module and target.startswith(
                    package_module + "."
                ):
                    modules.add(target)

    return modules


_LINTER_RULE_NODE_TYPES = {
    ComplexityRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    CognitiveComplexityRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    NestingRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    AsyncBlockingRule: (
        ast.Import,
        ast.ImportFrom,
        ast.AsyncFunctionDef,
        ast.FunctionDef,
        ast.Lambda,
        ast.Call,
    ),
    ArgCountRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    FunctionLengthRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    MutableDefaultRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    BareExceptRule: (ast.ExceptHandler,),
    DangerousComparisonRule: (ast.Compare,),
    DuplicateBranchRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    TryBlockPatternsRule: (ast.Try,),
    UnusedExceptVarRule: (ast.ExceptHandler,),
    ReturnConsistencyRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    EmptyErrorHandlerRule: (ast.ExceptHandler, ast.With),
    MissingResourceCleanupRule: (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef),
    DebugLeftoverRule: (ast.Call,),
    SecurityTodoRule: (ast.Module,),
    DisabledSecurityRule: (ast.Call, ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign),
    PhantomCallRule: (ast.Module, ast.Call),
    InsecureRandomRule: (ast.Assign,),
    HardcodedCredentialRule: (ast.Assign, ast.FunctionDef, ast.AsyncFunctionDef),
    ErrorDisclosureRule: (ast.ExceptHandler,),
    BroadFilePermissionsRule: (ast.Call,),
    UndefinedConfigRule: (ast.Module, ast.Call),
    StaleMockRule: (ast.Module, ast.Call),
    PhantomDecoratorRule: (
        ast.Module,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
    ),
    UnfinishedGenerationRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    DuplicateStringLiteralRule: (ast.Module,),
    TooManyReturnsRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    BooleanTrapRule: (ast.FunctionDef, ast.AsyncFunctionDef),
    BroadExceptionRule: (ast.ExceptHandler,),
    MissingNetworkTimeoutRule: (ast.Call,),
    NoEffectStatementRule: (ast.Expr,),
    GodFileRule: (ast.Module,),
    GodClassRule: (ast.ClassDef,),
    CBORule: (ast.ClassDef,),
    LCOMRule: (ast.ClassDef,),
    UnreachableCodeRule: (
        ast.Module,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.With,
        ast.AsyncWith,
        *_TRY_NODE_TYPES,
    ),
    PerformanceRule: (ast.Call, ast.For),
    TypeAnnotationPracticeRule: (ast.Module,),
    FrameworkPracticeRule: (ast.Module,),
    DangerousCallsRule: (ast.Module, ast.Import, ast.ImportFrom, ast.Assign, ast.Call),
}


def _set_linter_node_types(rules):
    for rule in rules:
        node_types = _LINTER_RULE_NODE_TYPES.get(type(rule))
        if node_types:
            rule.node_types = node_types


def _is_secret_config_candidate(path: Path) -> bool:
    name = path.name.lower()
    if name == ".env" or name.startswith(".env."):
        return True
    return path.suffix.lower() in _SECRET_CONFIG_SUFFIXES


_GREP_VERIFY_TYPE_PRIORITY = {
    "method": 0,
    "function": 1,
    "class": 2,
    "import": 3,
    "parameter": 4,
    "variable": 5,
    "lambda": 6,
}

_heuristic_weights = {"same_file_attr": 1.0, "same_pkg_attr": 0.3, "global_attr": 0.1}
try:
    from skylos.llm.feedback import get_tuned_weights

    _heuristic_weights = get_tuned_weights()
except (ImportError, OSError, ValueError):
    pass


def _definition_module_and_class(defn):
    if getattr(defn, "type", None) != "method" or "." not in defn.name:
        return "", ""

    parts = defn.name.split(".")
    if len(parts) < 3:
        return "", ""
    return ".".join(parts[:-2]), parts[-2]


def _resolve_analysis_root(path_like: Path) -> Path:
    current = path_like.resolve()
    if not current.is_dir():
        current = current.parent

    start = current
    home = Path.home().resolve()
    probe = current
    for _ in range(20):
        if (probe / "pyproject.toml").exists():
            if probe == home and start != home:
                break
            return probe
        if (probe / "setup.py").exists():
            if probe == home and start != home:
                break
            return probe
        if (probe / ".git").exists():
            if probe == home and start != home:
                break
            return probe
        if probe.parent == probe:
            break
        probe = probe.parent

    try:
        git_root = find_git_root(current)
        if git_root:
            resolved_git_root = Path(git_root).resolve()
            if not (resolved_git_root == home and current != home):
                return resolved_git_root
    except Exception:
        pass

    return current


def _grep_verify_rescue_priority(candidate: dict) -> tuple:
    """Budget grep verification toward candidates most worth rescuing first."""
    return (
        int(candidate.get("confidence", 0)),
        _GREP_VERIFY_TYPE_PRIORITY.get(candidate.get("type", ""), 99),
        str(candidate.get("file", "")),
        int(candidate.get("line", 0)),
        str(candidate.get("full_name", candidate.get("name", ""))),
    )


class Skylos:
    def __init__(self):
        self.defs = {}
        self.refs = []
        self.dynamic = set()
        self.exports = defaultdict(set)

    def _module(self, root, f):
        p = list(f.relative_to(root).parts)

        if "src" in p:
            src_idx = p.index("src")
            src_path = root / "/".join(p[: src_idx + 1])
            if not (src_path / "__init__.py").exists():
                p = p[src_idx + 1 :]

        if p[-1].endswith(".py"):
            p[-1] = p[-1][:-3]
        if p[-1] == "__init__":
            p.pop()
        return ".".join(p)

    def _should_exclude_file(self, file_path, root_path, exclude_folders):
        return should_exclude_path(file_path, root_path, exclude_folders)

    _LANG_MAP = {
        ".py": "Python",
        ".go": "Go",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".mts": "TypeScript",
        ".cts": "TypeScript",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".mjs": "JavaScript",
        ".cjs": "JavaScript",
        ".java": "Java",
        ".php": "PHP",
        ".rs": "Rust",
        ".dart": "Dart",
    }

    def _count_languages(self, files) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in files:
            ext = Path(f).suffix.lower()
            lang = self._LANG_MAP.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
        return counts

    def _get_python_files(self, path, exclude_folders=None):
        p = Path(path).resolve()

        if p.is_file():
            if p.suffix == ".pyi":
                return [], p.parent
            return [p], p.parent

        root = p
        exts = {
            ".py",
            ".go",
            *(_TS_JS_SOURCE_EXTS),
            ".java",
            *(_PHP_SOURCE_EXTS),
            *(_RUST_SOURCE_EXTS),
            *(_DART_SOURCE_EXTS),
        }
        ext_list = [
            "py",
            "go",
            "ts",
            "tsx",
            "js",
            "jsx",
            "mts",
            "cts",
            "mjs",
            "cjs",
            "java",
            "php",
            "rs",
            "dart",
        ]

        # use rust file discovery when avail
        if _fast_discover is not None and os.path.isdir(str(p)):
            simple_excludes = [
                "__pycache__",
                ".git",
                ".tox",
                "dist",
                "build",
                ".mypy_cache",
                ".pytest_cache",
                "node_modules",
                ".venv",
                "venv",
                ".eggs",
                "*.egg-info",
            ]
            if exclude_folders:
                for ef in exclude_folders:
                    name = ef.replace("\\", "/").rstrip("/")
                    # only simple dir names go to rust.. complex patterns stay in py
                    if "/" not in name and "*" not in name:
                        if name not in simple_excludes:
                            simple_excludes.append(name)

            try:
                rust_files = _fast_discover(str(p), ext_list, simple_excludes)
                all_files = [
                    Path(f)
                    for f in rust_files
                    if not should_exclude_path(Path(f), root, exclude_folders)
                ]
            except Exception:
                all_files = discover_source_files(
                    p, exts, exclude_folders=exclude_folders
                )
        else:
            all_files = discover_source_files(p, exts, exclude_folders=exclude_folders)

        return all_files, root

    def _walk_python_files_py(self, p, exts, exclude_folders=None, root=None):
        all_files = []
        try:
            for dirpath, dirnames, filenames in os.walk(p):
                if exclude_folders and root:
                    pruned = []
                    for d in list(dirnames):
                        d_path = Path(dirpath) / d
                        try:
                            if self._should_exclude_file(d_path, root, exclude_folders):
                                pruned.append(d)
                        except (OSError, ValueError):
                            pass
                    if pruned:
                        for d in pruned:
                            try:
                                dirnames.remove(d)
                            except ValueError:
                                pass

                for fname in filenames:
                    fpath = Path(dirpath) / fname
                    if fpath.suffix.lower() in exts:
                        all_files.append(fpath)
        except (OSError, PermissionError, TypeError):
            for ext in exts:
                all_files.extend(p.glob(f"**/*{ext}"))
        return all_files

    def _mark_exports(self):
        for name, definition in self.defs.items():
            if definition.in_init and not definition.simple_name.startswith("_"):
                definition.is_exported = True

        all_exported_names = set()
        for mod, export_names in self.exports.items():
            all_exported_names.update(export_names)

        for def_name, def_obj in self.defs.items():
            if str(def_obj.filename).endswith(_TS_JS_SOURCE_EXTS):
                continue
            if def_obj.simple_name in all_exported_names:
                def_obj.is_exported = True
                def_obj.references += 1

        for mod, export_names in self.exports.items():
            for name in export_names:
                for def_name, def_obj in self.defs.items():
                    if (
                        def_name.startswith(f"{mod}.")
                        and def_obj.simple_name == name
                        and def_obj.type != "import"
                    ):
                        def_obj.is_exported = True

        non_import_by_simple = defaultdict(list)
        for k, d in self.defs.items():
            if d.type != "import":
                non_import_by_simple[d.simple_name].append(d)

        for def_key, def_obj in self.defs.items():
            if def_obj.type != "import":
                continue
            if not def_obj.in_init:
                continue
            # e.g. "requests.api.get"
            target_name = def_obj.name
            if target_name:
                simple = target_name.split(".")[-1]
            else:
                simple = ""
            if not simple:
                continue
            if target_name in self.defs and self.defs[target_name].type != "import":
                self.defs[target_name].references += 1
                self.defs[target_name].is_exported = True
                continue
            for candidate in non_import_by_simple.get(simple, []):
                candidate.references += 1
                candidate.is_exported = True

        # propogate exports to methods of exported classes
        exported_classes = set()
        for def_name, def_obj in self.defs.items():
            if def_obj.type == "class" and def_obj.is_exported:
                exported_classes.add(def_obj.name)

        if exported_classes:
            for def_name, def_obj in self.defs.items():
                if def_obj.type not in ("function", "method"):
                    continue
                if str(def_obj.filename).endswith(".java"):
                    continue
                if "." not in def_obj.name:
                    continue
                parent = def_obj.name.rsplit(".", 1)[0]
                if parent in exported_classes and not def_obj.simple_name.startswith(
                    "_"
                ):
                    def_obj.is_exported = True
                    def_obj.references = max(def_obj.references, 1)

        if exported_classes and hasattr(self, "_global_type_map"):
            # reverse lookup: simple class name -> set of qualified def names
            class_by_simple: dict[str, set[str]] = defaultdict(set)
            for def_name, def_obj in self.defs.items():
                if def_obj.type == "class":
                    class_by_simple[def_obj.simple_name].add(def_obj.name)

            queue = list(exported_classes)
            visited = set(exported_classes)
            transitive_classes: set[str] = set()

            while queue:
                cls_name = queue.pop()
                prefix = cls_name + "."
                for attr_key, type_name in self._global_type_map.items():
                    if not attr_key.startswith(prefix):
                        continue
                    candidates = class_by_simple.get(type_name, set())
                    for candidate in candidates:
                        if candidate not in visited:
                            visited.add(candidate)
                            transitive_classes.add(candidate)
                            queue.append(candidate)

            if transitive_classes:
                for def_name, def_obj in self.defs.items():
                    if def_obj.type == "class" and def_obj.name in transitive_classes:
                        def_obj.is_exported = True
                        def_obj.references = max(def_obj.references, 1)
                    elif def_obj.type in ("function", "method") and "." in def_obj.name:
                        if str(def_obj.filename).endswith(".java"):
                            continue
                        parent = def_obj.name.rsplit(".", 1)[0]
                        if (
                            parent in transitive_classes
                            and not def_obj.simple_name.startswith("_")
                        ):
                            def_obj.is_exported = True
                            def_obj.references = max(def_obj.references, 1)

    def _build_ts_import_graph(self, ts_raw_imports: dict, monorepo_resolver=None):
        (
            self.ts_consumed_exports,
            self._ts_wildcard_edges,
            self._ts_importers_of,
        ) = build_ts_import_graph(ts_raw_imports, self.defs, monorepo_resolver)

    def _demote_unconsumed_ts_exports(self):
        if not hasattr(self, "ts_consumed_exports"):
            return
        self._ts_demoted_exports = demote_unconsumed_ts_exports(
            self.defs, self.ts_consumed_exports
        )

    def _find_dead_ts_files(self, files, exclude_folders, workspace_inventory=None):
        if not hasattr(self, "ts_consumed_exports"):
            return []
        return find_dead_ts_files(
            files,
            exclude_folders,
            getattr(self, "_ts_importers_of", {}),
            getattr(self, "_ts_wildcard_edges", {}),
            project_root=str(self._project_root),
            workspace_inventory=workspace_inventory,
        )

    def _find_unused_ts_exports(self, files, exclude_folders, workspace_inventory=None):
        if not hasattr(self, "_ts_demoted_exports"):
            return []
        return find_unused_ts_exports(
            self._ts_demoted_exports,
            getattr(self, "_ts_wildcard_edges", {}),
            files=files,
            exclude_folders=exclude_folders,
            project_root=str(self._project_root),
            workspace_inventory=workspace_inventory,
        )

    def _propagate_transitive_dead(self):
        dead_set = set()
        dead_classes = set()
        defs_by_name_file = defaultdict(list)
        class_key_by_name_file = {}
        for key, defn in self.defs.items():
            filename = str(Path(defn.filename).resolve())
            defs_by_name_file[(defn.name, filename)].append(key)
            if defn.type in ("class", "type"):
                class_key_by_name_file[(defn.name, filename)] = key

        defs_by_name = defaultdict(list)
        for key, defn in self.defs.items():
            defs_by_name[defn.name].append(key)

        def key_for_caller(caller: str, callee_defn) -> str | None:
            if caller in self.defs:
                return caller
            filename = str(Path(callee_defn.filename).resolve())
            same_file = defs_by_name_file.get((caller, filename), [])
            if len(same_file) == 1:
                return same_file[0]
            candidates = defs_by_name.get(caller, [])
            if len(candidates) == 1:
                return candidates[0]
            return None

        for key, defn in self.defs.items():
            if (
                defn.type in ("function", "method")
                and defn.references == 0
                and not defn.is_exported
            ):
                dead_set.add(key)
            elif (
                defn.type in ("class", "type")
                and defn.references == 0
                and not defn.is_exported
            ):
                dead_set.add(key)
                dead_classes.add(key)

        def is_dead_caller(caller: str, callee_defn) -> bool:
            caller_key = key_for_caller(caller, callee_defn)
            if caller_key in dead_set:
                return True
            if "." not in caller:
                return False
            filename = str(Path(callee_defn.filename).resolve())
            owner = caller.rsplit(".", 1)[0]
            owner_key = class_key_by_name_file.get((owner, filename))
            return owner_key in dead_classes

        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for key, defn in self.defs.items():
                if key in dead_set:
                    continue

                if defn.type not in ("function", "method", "class", "type"):
                    continue
                if defn.references == 0:
                    continue
                if defn.is_exported:
                    continue

                if not defn.called_by:
                    continue

                all_callers_dead = True
                for caller in defn.called_by:
                    if not is_dead_caller(caller, defn):
                        all_callers_dead = False
                        break

                if all_callers_dead:
                    dead_callers = len(
                        [c for c in defn.called_by if is_dead_caller(c, defn)]
                    )
                    if defn.references <= dead_callers:
                        dead_set.add(key)
                        defn.references = 0
                        if defn.type in ("class", "type"):
                            dead_classes.add(key)
                        changed = True

        logger.info(
            f"Transitive dead code propagation: {iterations} iterations, "
            f"{len(dead_set)} total dead definitions"
        )

        for key, defn in self.defs.items():
            if key in dead_set:
                continue
            if defn.type not in ("function", "method"):
                continue
            if defn.references == 0 or defn.is_exported:
                continue
            if not defn.called_by:
                continue

            attr_count = getattr(defn, "_attr_name_ref_count", 0)
            if attr_count <= 0:
                continue

            dead_callers = len([c for c in defn.called_by if is_dead_caller(c, defn)])

            effective_refs = defn.references - attr_count
            if effective_refs <= dead_callers and dead_callers > 0:
                why_reduced = getattr(defn, "why_confidence_reduced", None)
                if why_reduced is not None:
                    why_reduced.append("survived_propagation_via_attr_heuristic")
                defn.confidence = min(defn.confidence, 40)

    def _class_declares_attr(self, defn, attr_name: str) -> bool:
        node = getattr(defn, "node", None)
        if not isinstance(node, ast.ClassDef):
            return False

        for item in node.body:
            targets = []
            if isinstance(item, ast.Assign):
                targets.extend(item.targets)
            elif isinstance(item, ast.AnnAssign):
                targets.append(item.target)
            else:
                continue

            for target in targets:
                if isinstance(target, ast.Name) and target.id == attr_name:
                    return True
        return False

    def _suppress_standalone_orm_models(self) -> None:
        concrete_by_file = defaultdict(list)
        for defn in self.defs.values():
            if defn.type != "class":
                continue
            if not self._class_declares_attr(defn, "__tablename__"):
                continue
            concrete_by_file[str(Path(defn.filename).resolve())].append(defn)

        for model_defs in concrete_by_file.values():
            has_live_model = any(
                defn.references > 0 or defn.is_exported for defn in model_defs
            )
            if has_live_model:
                continue

            for defn in model_defs:
                if defn.references == 0 and not defn.is_exported:
                    defn.confidence = 0
                    defn.skip_reason = "standalone ORM model module"

    def _grep_verify(self):
        """Post-pass: use grep strategies to rescue false-positive dead code."""
        from skylos.core.grep_cache import GrepCache
        from skylos.core.grep_verify import grep_verify_findings

        candidates = []
        candidate_defs = {}
        for name, defn in self.defs.items():
            if defn.references == 0 and not defn.is_exported and defn.confidence > 0:
                d = defn.to_dict()
                candidates.append(d)
                candidate_defs[d.get("full_name", d.get("name", ""))] = defn

        if not candidates:
            return

        candidates.sort(key=_grep_verify_rescue_priority)

        project_root = str(getattr(self, "_project_root", ""))
        if not project_root:
            return

        grep_root = find_git_root(project_root) or Path(project_root)
        grep_cache = GrepCache()
        grep_cache.load(grep_root)
        try:
            grep_budget = float(os.getenv("SKYLOS_GREP_BUDGET", "30"))
            verdicts = grep_verify_findings(
                candidates,
                project_root,
                cache=grep_cache,
                time_budget=grep_budget,
            )
        finally:
            grep_cache.save(grep_root)

        rescued = 0
        for full_name, verdict in verdicts.items():
            defn = candidate_defs.get(full_name)
            if not defn:
                continue
            if verdict.alive:
                defn.references += 1
                defn.heuristic_refs["grep_verify"] = 1.0
                if verdict.suppression_code:
                    defn.suppression_code = verdict.suppression_code
                rescued += 1

        if rescued:
            logger.info(f"Grep verify: rescued {rescued} findings from dead code")

    def _apply_dead_code_liveness(self, files):
        try:
            from skylos.deadcode.liveness import apply_dead_code_liveness

            report = apply_dead_code_liveness(
                self.defs,
                self.refs,
                getattr(self, "_project_root", Path(".")),
                files,
            )
            self._dead_code_liveness_report = report
            if report.rescued:
                logger.info(
                    "Dead-code liveness rescued %d definitions",
                    len(report.rescued),
                )
        except Exception:
            self._dead_code_liveness_report = None
            if os.getenv("SKYLOS_DEBUG"):
                logger.error(traceback.format_exc())

    def _mark_refs(self, progress_callback=None):
        total_refs = len(self.refs)
        if progress_callback:
            progress_callback(0, total_refs or 1, Path("PHASE: mark refs"))

        import_to_original = {}

        non_import_defs = {k: v for k, v in self.defs.items() if v.type != "import"}

        type_def_lookup = defaultdict(list)
        for k, d in non_import_defs.items():
            if d.type in ("method", "variable") and "." in d.name:
                parts = d.name.rsplit(".", 1)
                type_def_lookup[parts[0]].append((parts[1], d))

        simple_to_keys = defaultdict(list)
        for k, d in non_import_defs.items():
            simple_to_keys[d.simple_name].append(k)

        import_by_simple = defaultdict(list)
        for k, d in self.defs.items():
            if d.type == "import":
                import_by_simple[d.simple_name].append(k)

        def _resolve_import_target(import_def_key: str, import_def_obj) -> str | None:
            target_fqn = import_def_obj.name
            if not target_fqn:
                return None

            if target_fqn in non_import_defs:
                return target_fqn

            simple = target_fqn.split(".")[-1]
            cands = simple_to_keys.get(simple, [])
            if len(cands) == 1:
                return cands[0]

            return None

        for def_key, def_obj in self.defs.items():
            if def_obj.type != "import":
                continue
            resolved = _resolve_import_target(def_key, def_obj)
            if resolved and resolved != def_key:
                import_to_original[def_key] = resolved
                self.defs[resolved].references += 1

        simple_name_lookup = defaultdict(list)
        for definition in self.defs.values():
            simple_name_lookup[definition.simple_name].append(definition)

        _methods_by_file_and_name = defaultdict(list)
        for d in self.defs.values():
            if d.type == "method":
                _methods_by_file_and_name[(str(d.filename), d.simple_name)].append(d)

        total_refs = len(self.refs)
        tick_every = int(os.getenv("SKYLOS_MARKREFS_TICK", str(MARKREFS_TICK_DEFAULT)))

        for i, (ref, ref_file) in enumerate(self.refs, 1):
            if progress_callback and (i == 1 or i % tick_every == 0 or i == total_refs):
                progress_callback(i, total_refs or 1, Path("PHASE: mark refs"))
            file_key = f"{ref_file}:{ref}"

            if file_key in self.defs:
                self.defs[file_key].references += 1
                if file_key in import_to_original:
                    original = import_to_original[file_key]
                    if original in self.defs:
                        self.defs[original].references += 1
                continue

            if ref in self.defs:
                self.defs[ref].references += 1
                if ref in import_to_original:
                    original = import_to_original[ref]
                    self.defs[original].references += 1
                continue

            if "." in ref:
                ref_mod, simple = ref.rsplit(".", 1)
            else:
                ref_mod, simple = "", ref
            candidates = simple_name_lookup.get(simple, [])

            if ref_mod:
                if ref_mod in ("cls", "self"):
                    cls_candidates = []
                    for d in candidates:
                        if d.type == "variable" and "." in d.name:
                            cls_candidates.append(d)

                    if cls_candidates:
                        for d in cls_candidates:
                            d.references += 1
                        continue

                else:
                    filtered = []
                    for d in candidates:
                        if d.name.startswith(ref_mod + ".") and d.type != "import":
                            filtered.append(d)
                    candidates = filtered
            else:
                filtered = []
                for d in candidates:
                    if d.type != "import":
                        filtered.append(d)
                candidates = filtered

            if len(candidates) > 1:
                same_file = []
                for d in candidates:
                    if str(d.filename) == str(ref_file):
                        same_file.append(d)
                if len(same_file) == 1:
                    candidates = same_file

            if len(candidates) == 1:
                candidates[0].references += 1
                continue

            if len(candidates) > 1:
                if ref_mod in ("self", "cls"):
                    same_file_cands = [
                        d for d in candidates if str(d.filename) == str(ref_file)
                    ]
                    if same_file_cands:
                        for d in same_file_cands:
                            d.references += 1
                    continue
                if not ref_mod:
                    continue

            # when ref_mod is a type we know about ..look up members of that type directly
            if ref_mod and ref_mod not in ("self", "cls") and len(candidates) != 1:
                type_members = type_def_lookup.get(ref_mod)
                if type_members:
                    for member_name, member_def in type_members:
                        if member_name == simple:
                            member_def.references += 1
                    continue

                resolved_type = self._global_type_map.get(ref_mod)
                if resolved_type:
                    type_members = type_def_lookup.get(resolved_type)
                    if type_members:
                        for member_name, member_def in type_members:
                            if member_name == simple:
                                member_def.references += 1
                        continue

            non_import_defs_fallback = []
            for d in simple_name_lookup.get(simple, []):
                if d.type != "import":
                    non_import_defs_fallback.append(d)

            if len(non_import_defs_fallback) == 1:
                non_import_defs_fallback[0].references += 1
                continue

            if "." in ref:
                ref_simple = ref.split(".")[-1]
                same_file_methods = _methods_by_file_and_name.get(
                    (str(ref_file), ref_simple), []
                )

                if same_file_methods and ref_mod in {"self", "cls"}:
                    for m in same_file_methods:
                        m.references += 1
                    continue

                if non_import_defs_fallback and not ref_mod:
                    for d in non_import_defs_fallback:
                        d.references += 1
                    continue

        from skylos.analysis.implicit_refs import pattern_tracker as global_tracker

        if (
            global_tracker.traced_calls
            or global_tracker.coverage_hits
            or global_tracker.known_refs
            or global_tracker._compiled_patterns
            or getattr(global_tracker, "known_qualified_refs", None)
        ):
            for def_obj in self.defs.values():
                should_mark, _, reason = global_tracker.should_mark_as_used(def_obj)
                if should_mark:
                    def_obj.references += 1

        used_attr_names = getattr(self, "_all_used_attr_names", set())
        used_attr_context = getattr(self, "_all_used_attr_context", set())
        same_class_private_attr_uses = set()
        if used_attr_context:
            for attr_name, mod, cls_ctx, _line_no in used_attr_context:
                if cls_ctx and attr_name.startswith("_"):
                    same_class_private_attr_uses.add((mod, cls_ctx, attr_name))

        if used_attr_names:
            for defn in self.defs.values():
                if defn.references > 0:
                    continue
                if defn.type == "method":
                    continue
                if defn.type == "function":
                    pass
                elif defn.type == "variable" and "." in defn.name:
                    pass
                else:
                    continue
                if defn.type == "method" and defn.simple_name.startswith("_"):
                    defn_mod, defn_cls = _definition_module_and_class(defn)
                    if (defn_mod, defn_cls, defn.simple_name) in same_class_private_attr_uses:
                        continue
                if defn.simple_name in used_attr_names:
                    defn.references += 1
                    defn._attr_name_ref_count += 1

        if used_attr_context:
            context_by_attr = defaultdict(list)
            for attr_name, mod, cls_ctx, line_no in used_attr_context:
                context_by_attr[attr_name].append((mod, cls_ctx, line_no))

            for defn in self.defs.values():
                if defn.type in ("method", "function"):
                    pass
                elif defn.type == "variable" and "." in defn.name:
                    pass
                else:
                    continue

                contexts = context_by_attr.get(defn.simple_name)
                if not contexts:
                    continue

                if "." in defn.name:
                    defn_mod = defn.name.rsplit(".")[0]
                else:
                    defn_mod = ""

                if defn_mod:
                    defn_pkg = defn_mod.split(".")[0]
                else:
                    defn_pkg = ""

                for ctx_mod, ctx_cls, ctx_line in contexts:
                    ctx_pkg = ctx_mod.split(".")[0] if ctx_mod else ""

                    if ctx_mod == defn_mod:
                        defn.heuristic_refs["same_file_attr"] = defn.heuristic_refs.get(
                            "same_file_attr", 0.0
                        ) + _heuristic_weights.get("same_file_attr", 1.0)
                    elif ctx_pkg and defn_pkg and ctx_pkg == defn_pkg:
                        defn.heuristic_refs["same_pkg_attr"] = defn.heuristic_refs.get(
                            "same_pkg_attr", 0.0
                        ) + _heuristic_weights.get("same_pkg_attr", 0.3)
                    else:
                        defn.heuristic_refs["global_attr"] = defn.heuristic_refs.get(
                            "global_attr", 0.0
                        ) + _heuristic_weights.get("global_attr", 0.1)

    def _mark_call_arg_method_refs(self):
        param_method_refs = getattr(self, "_param_method_refs", {})
        call_arg_types = getattr(self, "_call_arg_types", {})
        if not param_method_refs or not call_arg_types:
            return

        for callee, arg_types in call_arg_types.items():
            method_refs = param_method_refs.get(callee)
            if not method_refs:
                continue

            typed_call_args = []
            for arg_ref in arg_types:
                if len(arg_ref) == 3:
                    caller, position, type_name = arg_ref
                elif len(arg_ref) == 2:
                    position, type_name = arg_ref
                    caller = ""
                else:
                    continue
                if isinstance(position, (int, str)) and isinstance(type_name, str):
                    typed_call_args.append((str(caller or ""), position, type_name))

            for position, _param_type, method_name in method_refs:
                for caller, arg_position, arg_type in typed_call_args:
                    if arg_position != position:
                        continue
                    target = f"{arg_type}.{method_name}"
                    defn = self.defs.get(target)
                    if defn is None or defn.type != "method":
                        continue
                    defn.references += 1
                    defn.called_by.add(caller or callee)

    def _get_base_classes(self, class_name):
        if class_name not in self.defs:
            return []

        class_def = self.defs[class_name]

        if hasattr(class_def, "base_classes"):
            return class_def.base_classes

        return []

    def _apply_heuristics(self):
        class_methods = defaultdict(list)
        for definition in self.defs.values():
            if definition.type in ("method", "function") and "." in definition.name:
                cls = definition.name.rsplit(".", 1)[0]
                if cls in self.defs and self.defs[cls].type == "class":
                    class_methods[cls].append(definition)

        for cls, methods in class_methods.items():
            if self.defs[cls].references > 0:
                for method in methods:
                    if method.simple_name in AUTO_CALLED:
                        method.references += 1

                    if (
                        method.simple_name.startswith("visit_")
                        or method.simple_name.startswith("leave_")
                        or method.simple_name.startswith("transform_")
                    ):
                        method.references += 1

                    if method.simple_name == "format" and cls.endswith("Formatter"):
                        method.references += 1

        registry_bases = set()
        for name, defn in self.defs.items():
            if defn.type == "method" and defn.simple_name == "__init_subclass__":
                parent_cls = name.rsplit(".", 1)[0]
                registry_bases.add(parent_cls)

        if registry_bases:
            registry_simple_names = {b.split(".")[-1] for b in registry_bases}

            parents_of: dict[str, list[str]] = {}
            for n, d in self.defs.items():
                if d.type == "class":
                    parents_of[n] = getattr(d, "base_classes", [])

            suffix_to_qname: dict[str, str] = {}
            for n in parents_of:
                parts = n.split(".")
                for i in range(len(parts)):
                    suffix = ".".join(parts[i:])
                    if suffix not in suffix_to_qname:
                        suffix_to_qname[suffix] = n

            def _resolve(name: str) -> str:
                if name in parents_of:
                    return name
                return suffix_to_qname.get(name, name)

            def _has_registry_ancestor(cls_name: str) -> bool:
                visited: set[str] = set()
                stack = [_resolve(b) for b in parents_of.get(cls_name, [])]
                while stack:
                    ancestor = stack.pop()
                    if ancestor in visited:
                        continue
                    visited.add(ancestor)
                    if ancestor in registry_bases:
                        return True
                    stack.extend(_resolve(b) for b in parents_of.get(ancestor, []))
                return False

            for name, defn in self.defs.items():
                if defn.type == "class":
                    if _has_registry_ancestor(name):
                        defn.references += 1

                if defn.type == "function" and defn.return_type:
                    if defn.return_type in registry_simple_names:
                        defn.references += 1

    def _resolve_hierarchy_refs(self):
        children_of = defaultdict(set)
        for name, defn in self.defs.items():
            if defn.type != "class":
                continue
            for base_qname in getattr(defn, "base_classes", []):
                children_of[base_qname].add(name)

        if not children_of:
            return

        class_methods = defaultdict(dict)
        for name, defn in self.defs.items():
            if defn.type == "method" and "." in defn.name:
                parts = defn.name.rsplit(".", 1)
                class_methods[parts[0]][parts[1]] = defn

        for class_qname, methods in class_methods.items():
            if class_qname not in children_of:
                continue

            for method_name, method_def in methods.items():
                if method_def.references == 0:
                    continue

                stack = list(children_of[class_qname])
                visited = set()
                while stack:
                    child = stack.pop()
                    if child in visited:
                        continue
                    visited.add(child)

                    child_methods = class_methods.get(child, {})
                    if method_name in child_methods:
                        child_methods[method_name].references += 1

                    stack.extend(children_of.get(child, set()))

    def _apply_entry_reachability(self):
        call_graph = defaultdict(set)
        for defn in self.defs.values():
            calls = getattr(defn, "calls", None)
            if calls and isinstance(calls, (set, list, frozenset)):
                call_graph[defn.name].update(calls)

        entry_points = set()
        for name, defn in self.defs.items():
            if str(defn.filename).endswith("__main__.py"):
                entry_points.add(defn.name)
                continue

            if defn.type == "function" and defn.is_exported:
                entry_points.add(defn.name)
                continue

            if defn.references > 0 and defn.type in ("function", "method"):
                entry_points.add(defn.name)
                continue

            if defn.simple_name.startswith("test_"):
                entry_points.add(defn.name)
                continue

            if defn.type == "function" and defn.simple_name in (
                "main",
                "cli",
                "run",
                "app",
                "create_app",
            ):
                entry_points.add(defn.name)
                continue

        if not entry_points:
            return

        reachable = set()
        stack = list(entry_points)
        while stack:
            current = stack.pop()
            if current in reachable:
                continue
            reachable.add(current)
            for callee in call_graph.get(current, []):
                if callee not in reachable:
                    stack.append(callee)

        for name, defn in self.defs.items():
            if defn.type not in ("function", "method"):
                continue
            if defn.references > 0:
                continue
            if defn.is_exported:
                continue

            if name in reachable:
                defn.references += 1

    def _discover_files(self, path, exclude_folders):
        """Discover and deduplicate files to analyze, return (files, root) or None."""
        if isinstance(path, (list, tuple)):
            all_files = []
            seen = set()
            roots = []
            for p in path:
                f, r = self._get_python_files(p, exclude_folders)
                for fp in f:
                    resolved = fp.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        all_files.append(fp)
                roots.append(r)
            files = all_files
            if roots:
                root = Path(os.path.commonpath(roots))
            else:
                root = Path(".").resolve()
        else:
            files, root = self._get_python_files(path, exclude_folders)

        return files, root

    def _build_result(
        self,
        files,
        thr,
        exclude_folders,
        enable_secrets,
        enable_danger,
        enable_quality,
        enable_sca,
        all_secrets,
        all_dangers,
        all_quality,
        all_sca,
        all_suppressed,
        empty_files,
        modmap,
        all_raw_imports,
        path,
        unused_ts_exports=None,
        workspace_inventory=None,
        architecture_abstractness=None,
        architecture_loc=None,
        architecture_main_guard_modules=None,
        pyproject_entrypoint_qnames=None,
        pyproject_entrypoint_modules=None,
    ):
        """Assemble the final result dict from analysis outputs."""
        architecture_main_guard_modules = set(architecture_main_guard_modules or ())
        pyproject_entrypoint_qnames = set(pyproject_entrypoint_qnames or ())
        pyproject_entrypoint_modules = set(pyproject_entrypoint_modules or ())
        unused = []
        dead_class_keys = {
            key
            for key, definition in self.defs.items()
            if definition.type in ("class", "type")
            and definition.references == 0
            and not definition.is_exported
            and definition.confidence > 0
            and definition.confidence >= thr
        }
        class_key_by_name_file = {}
        for key, definition in self.defs.items():
            if definition.type in ("class", "type"):
                class_key_by_name_file[
                    (definition.name, str(Path(definition.filename).resolve()))
                ] = key

        for definition in self.defs.values():
            if (
                definition.references == 0
                and not definition.is_exported
                and definition.confidence > 0
                and definition.confidence >= thr
            ):
                if definition.type == "method" and "." in definition.name:
                    owner = definition.name.rsplit(".", 1)[0]
                    owner_key = class_key_by_name_file.get(
                        (owner, str(Path(definition.filename).resolve()))
                    )
                    if owner_key in dead_class_keys:
                        continue
                unused.append(definition.to_dict())

        context_map = {}
        for name, d in self.defs.items():
            if d.type in ("class", "function", "method") and not name.startswith("_"):
                loc = 1
                node = getattr(d, "node", None)
                if node is not None:
                    start = getattr(node, "lineno", None)
                    end = getattr(node, "end_lineno", None)
                    if start is not None and end is not None:
                        loc = max(1, end - start + 1)

                is_dead = (
                    d.references == 0
                    and not d.is_exported
                    and d.confidence > 0
                    and d.confidence >= thr
                )

                context_map[name] = {
                    "name": d.name,
                    "file": str(d.filename),
                    "line": d.line,
                    "type": d.type,
                    "loc": loc,
                    "complexity": getattr(d, "complexity", 1),
                    "calls": sorted(d.calls) if d.calls else [],
                    "called_by": sorted(d.called_by) if d.called_by else [],
                    "dead": is_dead,
                }

        whitelisted = []
        for d in self.defs.values():
            reason = getattr(d, "skip_reason", None)
            if reason:
                entry = {
                    "name": d.simple_name,
                    "file": str(d.filename),
                    "line": d.line,
                    "reason": d.skip_reason,
                    "category": "dead_code",
                    "suppression_code": getattr(d, "suppression_code", None),
                    "folder_role": getattr(d, "folder_role", None),
                }
                whitelisted.append(entry)
                if reason == "inline ignore comment":
                    all_suppressed.append(entry)

        result = {
            "definitions": context_map,
            "unused_functions": [],
            "unused_imports": [],
            "unused_classes": [],
            "unused_variables": [],
            "unused_parameters": [],
            "unused_files": [],
            "whitelisted": whitelisted,
            "suppressed": all_suppressed,
            "analysis_summary": {
                "total_files": len(files),
                "excluded_folders": exclude_folders or [],
                "languages": self._count_languages(files),
            },
        }

        liveness_report = getattr(self, "_dead_code_liveness_report", None)
        if liveness_report is not None:
            result["analysis_summary"]["dead_code_liveness"] = (
                liveness_report.to_dict()
            )

        if workspace_inventory is not None:
            project_root = (
                self._project_root
                if hasattr(self, "_project_root")
                else Path(
                    path[0] if isinstance(path, (list, tuple)) else path
                ).resolve()
            )
            result["workspaces"] = workspace_inventory.to_dict(project_root)
            result["analysis_summary"]["monorepo_detected"] = (
                workspace_inventory.is_monorepo
            )
            result["analysis_summary"]["workspace_count"] = len(
                workspace_inventory.packages
            )
            result["analysis_summary"]["workspace_total_packages"] = (
                workspace_inventory.total_packages
            )
            result["analysis_summary"]["workspace_diagnostic_count"] = len(
                workspace_inventory.diagnostics
            )

        if enable_secrets and all_secrets:
            result["secrets"] = all_secrets
            result["analysis_summary"]["secrets_count"] = len(all_secrets)

        if enable_danger and all_dangers:
            result["danger"] = all_dangers
            result["analysis_summary"]["danger_count"] = len(all_dangers)

        if enable_sca:
            result["dependency_vulnerabilities"] = all_sca
            result["analysis_summary"]["sca_count"] = len(all_sca)

        if enable_quality and all_quality:
            custom_hits = []
            core_quality = []

            for f in all_quality:
                rid = str(f.get("rule_id", ""))
                if rid.startswith("CUSTOM-"):
                    custom_hits.append(f)
                else:
                    core_quality.append(f)

            if core_quality:
                from skylos.rules.quality.standards import enrich_finding

                for f in core_quality:
                    enrich_finding(f)
                result["quality"] = core_quality
                result["analysis_summary"]["quality_count"] = len(core_quality)

            if custom_hits:
                result["custom_rules"] = custom_hits
                result["analysis_summary"]["custom_rules_count"] = len(custom_hits)

        if empty_files:
            result["unused_files"] = empty_files
            result["analysis_summary"]["unused_files_count"] = len(empty_files)

        if enable_danger and result.get("danger"):
            from skylos.rules.compliance import enrich_findings_with_compliance

            result["danger"] = enrich_findings_with_compliance(result["danger"])

        for u in unused:
            if u["type"] in ("function", "method"):
                result["unused_functions"].append(u)
            elif u["type"] == "import":
                result["unused_imports"].append(u)
            elif u["type"] in ("class", "type"):
                result["unused_classes"].append(u)
            elif u["type"] in ("variable", "constant"):
                result["unused_variables"].append(u)
            elif u["type"] == "parameter":
                result["unused_parameters"].append(u)

        if unused_ts_exports:
            if "unused_exports" not in result:
                result["unused_exports"] = []
            result["unused_exports"].extend(unused_ts_exports)
            result["analysis_summary"]["unused_exports_count"] = len(unused_ts_exports)

        project_cfg = load_config(path[0] if isinstance(path, (list, tuple)) else path)
        if project_cfg.get("check_circular", True):
            circular_rule = CircularDependencyRule()

            for file in files:
                if not str(file).endswith(".py"):
                    continue
                mod = modmap.get(file, "")
                raw_imp = all_raw_imports.get(file, [])
                circular_rule.add_file_imports(str(file), mod, raw_imp)

            try:
                circular_findings = circular_rule.analyze()
                if circular_findings:
                    result["circular_dependencies"] = circular_findings

                if enable_quality:
                    try:
                        from skylos.analysis.architecture import get_architecture_findings

                        dep_graph = dict(
                            circular_rule._analyzer.architecture_dependencies
                        )
                        mod_files = dict(circular_rule._analyzer.modules)
                        entrypoint_modules = (
                            pyproject_entrypoint_modules
                            | architecture_main_guard_modules
                        )
                        entrypoint_modules = _expand_reexported_entrypoint_modules(
                            pyproject_entrypoint_qnames,
                            entrypoint_modules,
                            all_raw_imports,
                            modmap,
                            mod_files,
                        )
                        package_boundary_modules = _find_package_boundary_modules(
                            all_raw_imports,
                            modmap,
                            mod_files,
                        )

                        mod_trees = {}
                        if not architecture_abstractness:
                            for file in files:
                                if not str(file).endswith(".py"):
                                    continue
                                mod = modmap.get(file, "")
                                try:
                                    src = Path(file).read_text(
                                        encoding="utf-8", errors="ignore"
                                    )
                                    mod_trees[mod] = ast.parse(src)
                                except (OSError, SyntaxError):
                                    pass

                        arch_findings, arch_summary = get_architecture_findings(
                            dependency_graph=dep_graph,
                            module_files=mod_files,
                            module_trees=mod_trees,
                            module_abstractness=architecture_abstractness,
                            module_loc=architecture_loc,
                            entrypoint_modules=entrypoint_modules,
                            package_boundary_modules=package_boundary_modules,
                            layer_policy=project_cfg.get("architecture"),
                            iad_findings_advisory=not _architecture_iad_strict(
                                project_cfg.get("architecture")
                            ),
                        )
                        ignored_rules = set(project_cfg.get("ignore", []))
                        if arch_findings:
                            arch_findings = [
                                f
                                for f in arch_findings
                                if f.get("rule_id") not in ignored_rules
                            ]
                        if arch_findings:
                            all_quality.extend(arch_findings)
                            from skylos.rules.quality.standards import enrich_finding

                            for finding in arch_findings:
                                enrich_finding(finding)
                            result.setdefault("quality", []).extend(arch_findings)
                            result["analysis_summary"]["quality_count"] = len(
                                result.get("quality", []) or []
                            )
                        if arch_summary:
                            result["architecture_metrics"] = arch_summary
                    except Exception:
                        if os.getenv("SKYLOS_DEBUG"):
                            traceback.print_exc()

            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    traceback.print_exc()

        try:
            from skylos.reporting.grader import count_lines_of_code, compute_grade

            total_loc = count_lines_of_code(files)
            result["analysis_summary"]["total_loc"] = total_loc
            result["grade"] = compute_grade(result, total_loc)
        except Exception:
            if os.getenv("SKYLOS_DEBUG"):
                traceback.print_exc()

        return result

    def analyze(
        self,
        path,
        thr=60,
        exclude_folders=None,
        enable_secrets=False,
        enable_danger=False,
        enable_quality=False,
        extra_visitors=None,
        progress_callback=None,
        custom_rules_data=None,
        changed_files=None,
        grep_verify=True,
        enable_sca=False,
        trace_file=None,
    ) -> str:
        if not isinstance(path, (str, list, tuple)):
            raise TypeError(
                f"path must be str, list, or tuple, got {type(path).__name__}"
            )
        if not (0 <= thr <= 100):
            raise ValueError(f"thr must be 0-100, got {thr}")

        clear_go_cache()

        if isinstance(path, (list, tuple)):
            _first = Path(path[0]).resolve()
            all_resolved = [Path(p).resolve() for p in path]
            project_root = Path(os.path.commonpath(all_resolved))
        else:
            _first = Path(path).resolve()
            project_root = _first
        if not project_root.is_dir():
            project_root = project_root.parent
        if project_root.exists():
            project_root = _resolve_analysis_root(project_root)

        files, root = self._discover_files(path, exclude_folders)

        from skylos.visitors.languages.typescript.workspace import (
            discover_workspace_inventory,
        )

        workspace_inventory = discover_workspace_inventory(project_root)
        project_cfg = load_config(project_root)
        project_ignore = set(project_cfg.get("ignore", []))

        if not files:
            logger.warning(f"No Python files found in {path}")
            result = {
                "unused_functions": [],
                "unused_imports": [],
                "unused_classes": [],
                "unused_variables": [],
                "unused_parameters": [],
                "unused_files": [],
                "analysis_summary": {
                    "total_files": 0,
                    "excluded_folders": exclude_folders if exclude_folders else [],
                    "monorepo_detected": workspace_inventory.is_monorepo,
                    "workspace_count": len(workspace_inventory.packages),
                    "workspace_total_packages": workspace_inventory.total_packages,
                    "workspace_diagnostic_count": len(workspace_inventory.diagnostics),
                },
                "workspaces": workspace_inventory.to_dict(project_root),
            }
            if enable_danger:
                try:
                    from skylos.rules.config import scan_config_files

                    scan_target = _first if _first.is_file() else project_root
                    config_findings = scan_config_files(
                        scan_target,
                        changed_files=changed_files,
                        ignore=project_ignore,
                    )
                    if config_findings:
                        from skylos.rules.compliance import (
                            enrich_findings_with_compliance,
                        )

                        result["danger"] = enrich_findings_with_compliance(
                            config_findings
                        )
                        result["analysis_summary"]["danger_count"] = len(config_findings)
                except Exception:
                    if os.getenv("SKYLOS_DEBUG"):
                        logger.error("Config scan failed", exc_info=True)
            return json.dumps(result)

        logger.info(f"Analyzing {len(files)} files...")

        modmap = {}
        for f in files:
            modmap[f] = self._module(root, f)

        from skylos.analysis.implicit_refs import pattern_tracker
        from skylos.analysis.implicit_refs import pattern_tracker as global_pattern_tracker

        global_pattern_tracker.known_refs.clear()
        global_pattern_tracker.known_qualified_refs.clear()
        global_pattern_tracker._compiled_patterns.clear()
        global_pattern_tracker.f_string_patterns.clear()
        global_pattern_tracker.coverage_hits.clear()
        global_pattern_tracker.covered_files_lines.clear()
        global_pattern_tracker._coverage_by_basename.clear()
        global_pattern_tracker.traced_calls.clear()
        global_pattern_tracker.traced_by_file.clear()
        global_pattern_tracker._traced_by_basename.clear()

        requested_changed_files = changed_files
        pyproject_entrypoint_qnames = set()
        pyproject_entrypoint_modules = set()

        try:
            from skylos.analysis.pyproject_entrypoints import extract_entrypoints

            for qname in extract_entrypoints(project_root):
                pyproject_entrypoint_qnames.add(qname)
                global_pattern_tracker.known_qualified_refs.add(qname)
                module_name = _entrypoint_module_name(qname)
                if module_name:
                    pyproject_entrypoint_modules.add(module_name)
        except Exception:
            logger.debug("Failed to extract pyproject entrypoints", exc_info=True)

        coverage_path = project_root / ".coverage"
        if coverage_path.exists():
            if global_pattern_tracker.load_coverage():
                logger.info(
                    f"Loaded coverage data ({len(pattern_tracker.coverage_hits)} lines)"
                )

        root = project_root
        self._project_root = project_root

        if trace_file is not False:
            trace_path = (
                project_root / ".skylos_trace"
                if trace_file is None
                else Path(trace_file)
            )
            if not trace_path.is_absolute():
                trace_path = project_root / trace_path
            if trace_path.exists():
                pattern_tracker.load_trace(str(trace_path))

        all_secrets = []
        all_dangers = []
        all_quality = []
        all_suppressed = []
        empty_files = []
        file_contexts = []
        all_clone_fragments = []
        architecture_abstractness = {}
        architecture_loc = {}
        architecture_main_guard_modules = set()

        per_file_ignore_lines = {}
        pattern_trackers = {}
        all_raw_imports = {}
        ts_raw_imports = {}
        all_inferred_types = {}
        all_instance_attr_types = {}
        all_used_attr_names = set()
        all_used_attr_context = set()
        all_param_method_refs = defaultdict(list)
        all_call_arg_types = defaultdict(list)

        injected = False
        if custom_rules_data and not os.getenv("SKYLOS_CUSTOM_RULES"):
            os.environ["SKYLOS_CUSTOM_RULES"] = json.dumps(custom_rules_data)
            injected = True
            if os.getenv("SKYLOS_DEBUG"):
                logger.info(
                    f"[DBG] Injected SKYLOS_CUSTOM_RULES (count={len(custom_rules_data)})"
                )
        else:
            if os.getenv("SKYLOS_DEBUG"):
                logger.info(
                    f"[DBG] Did NOT inject SKYLOS_CUSTOM_RULES "
                    f"(custom_rules_data={bool(custom_rules_data)}, env_already_set={bool(os.getenv('SKYLOS_CUSTOM_RULES'))})"
                )
        clone_cfg = None
        if enable_quality:
            clone_cfg = CloneConfig(
                grouping_mode=GroupingMode.CONNECTED,
                grouping_threshold=0.80,
                k_core_k=2,
                similarity_threshold=0.90,
                ignore_identifiers=True,
                ignore_literals=True,
                skip_docstrings=True,
            )

        try:
            outs = run_proc_file_parallel(
                files,
                modmap,
                extra_visitors=extra_visitors,
                jobs=int(os.getenv("SKYLOS_JOBS", "0")),
                progress_callback=progress_callback,
                custom_rules_data=custom_rules_data,
                changed_files=changed_files,
                collect_clone_fragments=enable_quality,
                clone_cfg=clone_cfg,
                collect_architecture_metrics=enable_quality,
                enable_quality_rules=enable_quality,
                enable_danger_rules=enable_danger,
            )

            if os.getenv("SKYLOS_DEBUG"):
                logger.info(f"[DBG] run_proc_file_parallel returned outs={len(outs)}")

            for file, out in zip(files, outs):
                if out is None:
                    continue

                mod = modmap[file]

                if len(out) > 12:
                    file_raw_imports = out[12]
                else:
                    file_raw_imports = []

                if len(out) > 13:
                    file_ignore_lines = out[13]
                else:
                    file_ignore_lines = set()

                if len(out) > 14:
                    file_suppressed = out[14]
                else:
                    file_suppressed = []

                file_inferred_types = out[15] if len(out) > 15 else {}
                file_instance_attr_types = out[16] if len(out) > 16 else {}
                file_used_attr_names = out[17] if len(out) > 17 else set()
                file_used_attr_context = out[18] if len(out) > 18 else set()
                file_param_method_refs = out[20] if len(out) > 20 else {}
                file_call_arg_types = out[21] if len(out) > 21 else {}
                file_clone_fragments = out[22] if len(out) > 22 else []
                file_architecture_metrics = out[23] if len(out) > 23 else None
                (
                    defs,
                    refs,
                    dyn,
                    exports,
                    test_flags,
                    framework_flags,
                    q_finds,
                    d_finds,
                    pro_finds,
                    pattern_tracker_obj,
                    empty_file_finding,
                    cfg,
                ) = out[:12]

                if file_ignore_lines:
                    per_file_ignore_lines[str(file)] = file_ignore_lines
                if file_suppressed:
                    all_suppressed.extend(file_suppressed)

                if file_raw_imports:
                    if str(file).endswith(".py"):
                        all_raw_imports[file] = file_raw_imports
                    elif str(file).endswith(_TS_JS_SOURCE_EXTS):
                        ts_raw_imports[file] = file_raw_imports

                if pattern_tracker_obj:
                    pattern_trackers[mod] = pattern_tracker_obj

                if file_inferred_types:
                    all_inferred_types.update(file_inferred_types)
                if file_instance_attr_types:
                    all_instance_attr_types.update(file_instance_attr_types)
                if file_used_attr_names:
                    all_used_attr_names.update(file_used_attr_names)
                if file_used_attr_context:
                    all_used_attr_context.update(file_used_attr_context)
                if file_clone_fragments:
                    all_clone_fragments.extend(file_clone_fragments)
                if file_architecture_metrics:
                    abstractness = file_architecture_metrics.get("abstractness")
                    loc = file_architecture_metrics.get("loc")
                    has_main_guard = file_architecture_metrics.get("has_main_guard")
                    if abstractness is not None:
                        architecture_abstractness[mod] = abstractness
                    if loc is not None:
                        architecture_loc[mod] = loc
                    if has_main_guard:
                        architecture_main_guard_modules.add(mod)
                for callee, method_refs in file_param_method_refs.items():
                    all_param_method_refs[callee].extend(method_refs)
                for callee, arg_refs in file_call_arg_types.items():
                    all_call_arg_types[callee].extend(arg_refs)

                for definition in defs:
                    if definition.type == "import":
                        key = f"{definition.filename}:{definition.name}"
                    elif str(definition.filename).endswith(_TS_JS_SOURCE_EXTS):
                        key = f"{definition.filename}:{definition.name}"
                    else:
                        key = definition.name
                    self.defs[key] = definition

                self.refs.extend(refs)
                self.dynamic.update(dyn)
                self.exports[mod].update(exports)

                file_contexts.append(
                    (defs, test_flags, framework_flags, file, mod, cfg)
                )

                if empty_file_finding:
                    empty_files.append(empty_file_finding)

                if enable_quality and q_finds:
                    all_quality.extend(q_finds)

                if enable_danger and d_finds:
                    _ign = cfg.get("ignore", [])
                    if _ign:
                        d_finds = [f for f in d_finds if f.get("rule_id") not in _ign]
                    all_dangers.extend(d_finds)

                if pro_finds:
                    all_dangers.extend(pro_finds)

                if enable_secrets and _secrets_scan_ctx is not None:
                    if changed_files is None or str(file) in changed_files:
                        try:
                            file_source_lines = (
                                out[19]
                                if isinstance(out, tuple) and len(out) > 19
                                else None
                            )
                            if file_source_lines:
                                src_lines = file_source_lines
                            else:
                                src = Path(file).read_text(
                                    encoding="utf-8", errors="ignore"
                                )
                                src_lines = src.splitlines(True)
                            rel = str(Path(file).relative_to(root))
                            ctx = {"relpath": rel, "lines": src_lines, "tree": None}
                            findings = list(_secrets_scan_ctx(ctx))
                            if findings:
                                f_ignore = per_file_ignore_lines.get(str(file), set())
                                if f_ignore:
                                    for sf in findings:
                                        if sf.get("line") in f_ignore:
                                            all_suppressed.append(
                                                {
                                                    **sf,
                                                    "category": "secrets",
                                                    "reason": "inline ignore comment",
                                                }
                                            )
                                    findings = [
                                        sf
                                        for sf in findings
                                        if sf.get("line") not in f_ignore
                                    ]
                                all_secrets.extend(findings)
                        except Exception:
                            logger.debug("Secret scan failed for file", exc_info=True)

            if enable_secrets and _secrets_scan_ctx is not None:
                scanned = {str(Path(f).resolve()) for f in files}
                if changed_files is not None:
                    cfg_candidates = []
                    for raw_path in changed_files:
                        cfg_file = Path(raw_path)
                        if not cfg_file.is_absolute():
                            cfg_file = (root / cfg_file).resolve()
                        else:
                            cfg_file = cfg_file.resolve()
                        cfg_candidates.append(cfg_file)
                else:
                    cfg_candidates = root.rglob("*")

                for cfg_file in cfg_candidates:
                    cfg_file = Path(cfg_file)
                    if not cfg_file.is_file():
                        continue
                    if not _is_secret_config_candidate(cfg_file):
                        continue
                    if str(cfg_file.resolve()) in scanned:
                        continue
                    if any(ex in cfg_file.parts for ex in (exclude_folders or [])):
                        continue
                    try:
                        src = cfg_file.read_text(encoding="utf-8", errors="ignore")
                        src_lines = src.splitlines(True)
                        rel = str(cfg_file.relative_to(root))
                        ctx = {"relpath": rel, "lines": src_lines, "tree": None}
                        findings = list(_secrets_scan_ctx(ctx))
                        if findings:
                            all_secrets.extend(findings)
                    except Exception:
                        logger.debug(
                            "Secret scan failed for config file", exc_info=True
                        )

        finally:
            if injected:
                os.environ.pop("SKYLOS_CUSTOM_RULES", None)

        if enable_quality:
            if progress_callback:
                progress_callback(0, 1, Path("PHASE: clone detection"))
            RULE_ID = "SKY-C401"

            frags = all_clone_fragments

            pairs = detect_pairs(frags, clone_cfg)
            groups = group_pairs(pairs, clone_cfg)

            for g in groups:
                if len(g.fragments) < 2:
                    continue

                g.fragments.sort(key=lambda x: (x.file_path, x.start_line))
                top = g.fragments[0]

                members_preview = []
                for frag in g.fragments[:4]:
                    members_preview.append(
                        f"{Path(frag.file_path).name}:{frag.start_line}-{frag.end_line} ({frag.kind} {frag.name})"
                    )

                if (
                    g.clone_type in (CloneType.TYPE1, CloneType.TYPE2)
                    and g.similarity >= 0.95
                ):
                    severity = "MEDIUM"
                elif g.similarity >= 0.90:
                    severity = "LOW"
                else:
                    severity = "LOW"

                all_quality.append(
                    {
                        "rule_id": RULE_ID,
                        "kind": "clone",
                        "name": top.name,
                        "simple_name": top.name,
                        "basename": Path(top.file_path).name,
                        "value": f"{g.clone_type.value} {g.similarity:.2f}",
                        "message": (
                            f"Clone group detected ({g.clone_type.value}, sim={g.similarity:.3f}, members={len(g.fragments)}) "
                            f"examples: {', '.join(members_preview)}"
                        ),
                        "file": top.file_path,
                        "line": top.start_line,
                        "severity": severity,
                        "category": "QUALITY",
                    }
                )

        if changed_files is None and (enable_quality or enable_danger):
            try:
                import subprocess

                diff_result = subprocess.run(
                    ["git", "diff", "--name-only", "HEAD"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=str(root),
                )
                if diff_result.returncode == 0 and diff_result.stdout.strip():
                    changed_files = set()
                    for line in diff_result.stdout.strip().splitlines():
                        full_path = str((root / line).resolve())
                        changed_files.add(full_path)
                staged_result = subprocess.run(
                    ["git", "diff", "--name-only", "--cached"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=str(root),
                )
                if staged_result.returncode == 0 and staged_result.stdout.strip():
                    if changed_files is None:
                        changed_files = set()
                    for line in staged_result.stdout.strip().splitlines():
                        full_path = str((root / line).resolve())
                        changed_files.add(full_path)
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error("Auto-detect git changes failed", exc_info=True)

        if changed_files and enable_quality and "SKY-L021" not in project_ignore:
            from skylos.rules.quality.regression import detect_security_regressions
            from skylos.security.contracts import resolve_diff_base_ref

            try:
                import subprocess

                diff_base = resolve_diff_base_ref(root)

                for cf in changed_files:
                    rel_cf = (
                        str(Path(cf).resolve().relative_to(root))
                        if Path(cf).is_absolute()
                        else str(cf)
                    )
                    diff_cmd = (
                        ["git", "diff", f"{diff_base}...HEAD", "--", rel_cf]
                        if diff_base
                        else ["git", "diff", "HEAD", "--", rel_cf]
                    )
                    diff_result = subprocess.run(
                        diff_cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=str(root),
                    )
                    if diff_result.returncode != 0 and diff_base:
                        diff_result = subprocess.run(
                            ["git", "diff", "HEAD", "--", rel_cf],
                            capture_output=True,
                            text=True,
                            timeout=10,
                            cwd=str(root),
                        )
                    if diff_result.returncode == 0 and diff_result.stdout.strip():
                        reg_findings = detect_security_regressions(
                            diff_result.stdout,
                            cf,
                        )
                        all_quality.extend(reg_findings)
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error("Security regression scan failed", exc_info=True)

        if changed_files and enable_danger and "SKY-SC001" not in project_ignore:
            from skylos.security.contracts import detect_security_contract_regressions

            try:
                all_dangers.extend(
                    detect_security_contract_regressions(
                        root,
                        project_cfg,
                        changed_files=changed_files,
                    )
                )
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error("Security contract scan failed", exc_info=True)

        self.pattern_trackers = pattern_trackers

        self._global_abc_classes = set()
        self._global_protocol_classes = set()
        self._global_abstract_methods = {}
        self._global_abc_implementers = {}
        self._global_protocol_implementers = {}
        self._global_protocol_method_names = {}

        for defs, test_flags, framework_flags, file, mod, cfg in file_contexts:
            self._global_abc_classes.update(
                getattr(framework_flags, "abc_classes", set())
            )
            self._global_protocol_classes.update(
                getattr(framework_flags, "protocol_classes", set())
            )

            for cls, methods in getattr(
                framework_flags, "abstract_methods", {}
            ).items():
                if cls not in self._global_abstract_methods:
                    self._global_abstract_methods[cls] = set()
                self._global_abstract_methods[cls].update(methods)

            for cls, parents in getattr(
                framework_flags, "abc_implementers", {}
            ).items():
                if cls not in self._global_abc_implementers:
                    self._global_abc_implementers[cls] = []
                self._global_abc_implementers[cls].extend(parents)

            for cls, parents in getattr(
                framework_flags, "protocol_implementers", {}
            ).items():
                if cls not in self._global_protocol_implementers:
                    self._global_protocol_implementers[cls] = []
                self._global_protocol_implementers[cls].extend(parents)

            for cls, methods in getattr(
                framework_flags, "protocol_method_names", {}
            ).items():
                if cls not in self._global_protocol_method_names:
                    self._global_protocol_method_names[cls] = set()
                self._global_protocol_method_names[cls].update(methods)

        self._duck_typed_implementers = set()

        class_methods = {}
        for def_obj in self.defs.values():
            if def_obj.type == "method" and "." in def_obj.name:
                parts = def_obj.name.split(".")
                if len(parts) >= 2:
                    class_name = parts[-2]
                    method_name = parts[-1]
                    if class_name not in class_methods:
                        class_methods[class_name] = set()
                    class_methods[class_name].add(method_name)

        for class_name, methods in class_methods.items():
            if class_name in self._global_protocol_classes:
                continue

            if class_name in self._global_protocol_implementers:
                continue

            for (
                protocol_name,
                protocol_methods,
            ) in self._global_protocol_method_names.items():
                if not protocol_methods or len(protocol_methods) < 3:
                    continue

                matching = methods & protocol_methods
                match_ratio = len(matching) / len(protocol_methods)

                if match_ratio >= 0.7 and len(matching) >= 3:
                    self._duck_typed_implementers.add(class_name)
                    break

        self._dotted_variable_simple_name_counts = Counter(
            definition.simple_name
            for definition in self.defs.values()
            if definition.type == "variable" and "." in definition.name
        )

        for defs, test_flags, framework_flags, file, mod, cfg in file_contexts:
            for definition in defs:
                apply_penalties(self, definition, test_flags, framework_flags, cfg)

        if enable_danger:
            try:
                from skylos.rules.config import scan_config_files

                scan_target = _first if _first.is_file() else project_root
                config_findings = scan_config_files(
                    scan_target,
                    changed_files=changed_files,
                    ignore=project_ignore,
                )
                if config_findings:
                    all_dangers.extend(config_findings)
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error("Config scan failed", exc_info=True)

            try:
                from skylos.rules.danger.danger_hallucination.dependency_hallucination import (
                    scan_python_dependency_hallucinations,
                )

                py_files = [
                    f for f in files if str(f).endswith((".py", ".pyi", ".pyw"))
                ]
                if py_files:
                    dep_findings = scan_python_dependency_hallucinations(
                        project_root, py_files
                    )
                    if dep_findings:
                        dep_findings = [
                            f
                            for f in dep_findings
                            if f.get("rule_id") not in project_ignore
                        ]
                        unsuppressed_dep_findings = []
                        for finding in dep_findings:
                            f_ignore = per_file_ignore_lines.get(
                                str(finding.get("file", "")), set()
                            )
                            if finding.get("line") in f_ignore:
                                all_suppressed.append(
                                    {
                                        **finding,
                                        "category": "danger",
                                        "reason": "inline ignore comment",
                                    }
                                )
                                continue
                            unsuppressed_dep_findings.append(finding)
                        dep_findings = unsuppressed_dep_findings
                        all_dangers.extend(dep_findings)
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error(traceback.format_exc())

            # --- SKY-D260: Prompt injection scanner (multi-file) ---
            if "SKY-D260" not in project_ignore:
                if progress_callback:
                    progress_callback(0, 1, Path("PHASE: prompt injection scan"))
                try:
                    from skylos.security.injection_scanner import (
                        SCANNABLE_EXTENSIONS,
                        scan_file as _injection_scan_file,
                    )

                    injection_candidates = list(files)
                    injection_root = Path(
                        path[0] if isinstance(path, (list, tuple)) else path
                    ).resolve()
                    if injection_root.is_file():
                        injection_root = injection_root.parent
                    if changed_files is not None:
                        injection_candidates = [Path(f) for f in changed_files]
                    else:
                        seen_injection_files = {
                            str(Path(f).resolve()) for f in injection_candidates
                        }
                        if injection_root.is_dir():
                            for dirpath, dirnames, filenames in os.walk(injection_root):
                                dirnames[:] = [
                                    d
                                    for d in dirnames
                                    if not d.startswith(".")
                                    and d not in (exclude_folders or [])
                                ]
                                for fname in filenames:
                                    fpath = Path(dirpath) / fname
                                    if fpath.suffix.lower() not in SCANNABLE_EXTENSIONS:
                                        continue
                                    fkey = str(fpath.resolve())
                                    if fkey in seen_injection_files:
                                        continue
                                    seen_injection_files.add(fkey)
                                    injection_candidates.append(fpath)
                    for f in injection_candidates:
                        try:
                            scan_path = Path(f).resolve().relative_to(injection_root)
                        except ValueError:
                            scan_path = None
                        inj_hits = _injection_scan_file(f, scan_path=scan_path)
                        if inj_hits:
                            all_dangers.extend(inj_hits)
                except Exception:
                    if os.getenv("SKYLOS_DEBUG"):
                        logger.error(traceback.format_exc())

        if enable_quality:
            if progress_callback:
                progress_callback(0, 1, Path("PHASE: dependency quality scan"))
            try:
                from skylos.rules.quality.unused_deps import scan_unused_dependencies

                _ud_py_files = [
                    f for f in files if str(f).endswith((".py", ".pyi", ".pyw"))
                ]
                if isinstance(path, (list, tuple)):
                    _scan_targets = [Path(p).resolve() for p in path]
                else:
                    _scan_targets = [Path(path).resolve()]

                _file_scoped_scan = bool(_scan_targets) and all(
                    target.is_file() for target in _scan_targets
                )

                if _ud_py_files and not _file_scoped_scan:
                    _ud_root = Path(
                        os.path.commonpath([str(p.resolve()) for p in _ud_py_files])
                    )
                    if _ud_root.is_file():
                        _ud_root = _ud_root.parent

                    if "SKY-U005" not in project_ignore:
                        ud_findings = scan_unused_dependencies(_ud_root, _ud_py_files)
                        if ud_findings:
                            all_quality.extend(ud_findings)

                    if (
                        "SKY-L012" not in project_ignore
                        or "SKY-L023" not in project_ignore
                    ) and project_root.exists():
                        repo_py_files = discover_source_files(
                            project_root,
                            {".py"},
                            exclude_folders=exclude_folders,
                        )
                        phantom_findings = scan_repo_phantom_security_references(
                            project_root,
                            repo_py_files,
                            target_files=_ud_py_files,
                            vibe_dictionary=build_vibe_dictionary(
                                project_cfg.get("vibe")
                            ),
                        )
                        if phantom_findings:
                            phantom_findings = [
                                f
                                for f in phantom_findings
                                if f.get("rule_id") not in project_ignore
                            ]
                            unsuppressed_findings = []
                            for finding in phantom_findings:
                                f_ignore = per_file_ignore_lines.get(
                                    str(finding.get("file", "")), set()
                                )
                                if finding.get("line") in f_ignore:
                                    all_suppressed.append(
                                        {
                                            **finding,
                                            "category": "quality",
                                            "reason": "inline ignore comment",
                                        }
                                    )
                                    continue
                                unsuppressed_findings.append(finding)
                            phantom_findings = unsuppressed_findings
                            all_quality.extend(phantom_findings)
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error(traceback.format_exc())

            try:
                policy_findings = analyze_repo_policy(
                    root,
                    project_cfg,
                    changed_files=requested_changed_files,
                )
                if policy_findings:
                    all_quality.extend(policy_findings)
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error(traceback.format_exc())

        all_sca = []
        if enable_sca:
            if progress_callback:
                progress_callback(0, 1, Path("PHASE: dependency vulnerability scan"))
            try:
                from skylos.rules.sca.vulnerability_scanner import scan_dependencies

                scan_root = project_root
                sca_findings = scan_dependencies(scan_root)
                if sca_findings:
                    all_sca.extend(sca_findings)
                    try:
                        from skylos.rules.sca.reachability import (
                            enrich_with_reachability,
                        )

                        all_sca = enrich_with_reachability(all_sca, scan_root)
                    except Exception:
                        if os.getenv("SKYLOS_DEBUG"):
                            logger.error(traceback.format_exc())
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error(traceback.format_exc())

        from skylos.visitors.languages.typescript.resolve import MonorepoResolver

        monorepo_resolver = MonorepoResolver(str(self._project_root))
        self._build_ts_import_graph(ts_raw_imports, monorepo_resolver)

        self._global_type_map = {}
        self._global_type_map.update(all_inferred_types)
        self._global_type_map.update(all_instance_attr_types)
        self._all_used_attr_names = all_used_attr_names
        self._all_used_attr_context = all_used_attr_context
        self._param_method_refs = all_param_method_refs
        self._call_arg_types = all_call_arg_types

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: mark refs"))
        self._mark_refs(progress_callback=progress_callback)
        self._mark_call_arg_method_refs()

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: dead-code liveness"))
        self._apply_dead_code_liveness(files)

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: hierarchy refs"))
        self._resolve_hierarchy_refs()

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: heuristics"))
        self._apply_heuristics()

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: exports"))
        self._mark_exports()

        self._demote_unconsumed_ts_exports()

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: entry reachability"))
        self._apply_entry_reachability()

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: transitive dead code"))
        self._propagate_transitive_dead()
        self._suppress_standalone_orm_models()

        if grep_verify:
            if progress_callback:
                progress_callback(0, 1, Path("PHASE: grep verify"))
            self._grep_verify()

        dead_ts_files = self._find_dead_ts_files(
            files, exclude_folders, workspace_inventory=workspace_inventory
        )
        empty_files.extend(dead_ts_files)

        unused_ts_exports = self._find_unused_ts_exports(
            files,
            exclude_folders,
            workspace_inventory=workspace_inventory,
        )

        result = self._build_result(
            files,
            thr,
            exclude_folders,
            enable_secrets,
            enable_danger,
            enable_quality,
            enable_sca,
            all_secrets,
            all_dangers,
            all_quality,
            all_sca,
            all_suppressed,
            empty_files,
            modmap,
            all_raw_imports,
            path,
            unused_ts_exports=unused_ts_exports,
            workspace_inventory=workspace_inventory,
            architecture_abstractness=architecture_abstractness,
            architecture_loc=architecture_loc,
            architecture_main_guard_modules=architecture_main_guard_modules,
            pyproject_entrypoint_qnames=pyproject_entrypoint_qnames,
            pyproject_entrypoint_modules=pyproject_entrypoint_modules,
        )

        return json.dumps(result, indent=2)


def _is_truly_empty_or_docstring_only(tree):
    if not isinstance(tree, ast.Module):
        return False

    if not tree.body:
        return True

    if len(tree.body) != 1:
        return False

    only = tree.body[0]
    return (
        isinstance(only, ast.Expr)
        and isinstance(only.value, ast.Constant)
        and isinstance(only.value.value, str)
    )


def proc_file(
    file_or_args,
    mod=None,
    extra_visitors=None,
    full_scan=True,
    collect_clone_fragments=False,
    clone_cfg=None,
    collect_architecture_metrics=False,
    enable_quality_rules=True,
    enable_danger_rules=True,
) -> dict | None:
    if mod is None and isinstance(file_or_args, tuple):
        file, mod = file_or_args
    else:
        file = file_or_args

    cfg = load_config(file)

    if str(file).endswith(_TS_JS_SOURCE_EXTS):
        out = scan_typescript_file(
            file,
            cfg,
            enable_quality_rules=enable_quality_rules,
            enable_danger_rules=enable_danger_rules,
        )
        if isinstance(out, tuple) and len(out) < 13:
            return (*out, *([None] * (13 - len(out))))
        return out[:13]

    if str(file).endswith(".go"):
        out = scan_go_file(file, cfg)
        if isinstance(out, tuple) and len(out) < 13:
            return (*out, *([None] * (13 - len(out))))
        return out[:13]

    if str(file).endswith(".java"):
        out = scan_java_file(
            file,
            cfg,
            enable_quality_rules=enable_quality_rules,
            enable_danger_rules=enable_danger_rules,
        )
        if isinstance(out, tuple) and len(out) < 13:
            return (*out, *([None] * (13 - len(out))))
        return out[:13]

    if str(file).endswith(".php"):
        out = scan_php_file(
            file,
            cfg,
            enable_danger_rules=enable_danger_rules,
        )
        if isinstance(out, tuple) and len(out) < 13:
            return (*out, *([None] * (13 - len(out))))
        return out[:13]

    if str(file).endswith(".rs"):
        out = scan_rust_file(
            file,
            cfg,
            enable_danger_rules=enable_danger_rules,
        )
        if isinstance(out, tuple) and len(out) < 13:
            return (*out, *([None] * (13 - len(out))))
        return out[:13]

    if str(file).endswith(".dart"):
        out = scan_dart_file(
            file,
            cfg,
            enable_danger_rules=enable_danger_rules,
        )
        if isinstance(out, tuple) and len(out) < 13:
            return (*out, *([None] * (13 - len(out))))
        return out[:13]

    try:
        source = Path(file).read_text(encoding="utf-8")
        ignore_lines = get_all_ignore_lines(source)

        tree = ast.parse(source)

        raw_imports = []
        is_init = Path(file).name == "__init__.py"
        cur_pkg = (
            mod
            if is_init
            else (mod.rsplit(".", 1)[0] if mod and "." in mod else (mod or ""))
        )
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    raw_imports.append(
                        (
                            alias.name,
                            node.lineno,
                            "import",
                            [alias.asname or alias.name],
                        )
                    )
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [a.name for a in node.names if a.name != "*"]
                raw_imports.append((node.module, node.lineno, "from_import", names))
            elif isinstance(node, ast.ImportFrom) and node.level and node.level > 0:
                if cur_pkg:
                    parts = cur_pkg.split(".")
                else:
                    parts = []

                up = node.level - 1
                if up <= len(parts):
                    base = ".".join(parts[: len(parts) - up])
                    if node.module:
                        if base:
                            resolved = f"{base}.{node.module}"
                        else:
                            resolved = node.module
                    else:
                        resolved = base
                    if resolved:
                        names = []
                        for a in node.names:
                            if a.name != "*":
                                names.append(a.name)
                        raw_imports.append(
                            (resolved, node.lineno, "from_import", names)
                        )

        empty_file_finding = None

        basename = Path(file).name
        skip_empty_report = basename in {"__init__.py", "__main__.py", "main.py"}

        if (
            _is_truly_empty_or_docstring_only(tree)
            and not skip_empty_report
            and "SKY-E002" not in cfg["ignore"]
        ):
            empty_file_finding = {
                "rule_id": "SKY-E002",
                "message": "Empty Python file (no code, or docstring-only)",
                "file": str(file),
                "line": 1,
                "severity": "LOW",
                "category": "DEAD_CODE",
            }

        from skylos.analysis.ast_mask import apply_body_mask, default_mask_spec_from_config

        mask = default_mask_spec_from_config(cfg)
        tree, masked = apply_body_mask(tree, mask)

        if masked and os.getenv("SKYLOS_DEBUG"):
            logger.info(f"{file}: masked {masked} bodies (skipped inner analysis)")

        quality_findings = []
        danger_findings = []

        if full_scan and enable_quality_rules:
            vibe_dictionary = build_vibe_dictionary(cfg.get("vibe"))
            q_rules = []
            if "SKY-Q301" not in cfg["ignore"]:
                q_rules.append(ComplexityRule(threshold=cfg["complexity"]))
            if "SKY-Q306" not in cfg["ignore"]:
                q_rules.append(CognitiveComplexityRule())
            if "SKY-Q302" not in cfg["ignore"]:
                q_rules.append(NestingRule(threshold=cfg["nesting"]))
            if "SKY-Q401" not in cfg["ignore"]:
                q_rules.append(AsyncBlockingRule())
            if "SKY-C303" not in cfg["ignore"]:
                q_rules.append(ArgCountRule(max_args=cfg["max_args"]))
            if "SKY-C304" not in cfg["ignore"]:
                q_rules.append(FunctionLengthRule(max_lines=cfg["max_lines"]))

            if "SKY-L001" not in cfg["ignore"]:
                q_rules.append(MutableDefaultRule())
            if "SKY-L002" not in cfg["ignore"]:
                q_rules.append(BareExceptRule())
            if "SKY-L003" not in cfg["ignore"]:
                q_rules.append(DangerousComparisonRule())
            if "SKY-Q305" not in cfg["ignore"]:
                q_rules.append(DuplicateBranchRule())
            if "SKY-L004" not in cfg["ignore"]:
                q_rules.append(TryBlockPatternsRule(max_lines=15))
            if "SKY-L005" not in cfg["ignore"]:
                q_rules.append(UnusedExceptVarRule())
            if "SKY-L006" not in cfg["ignore"]:
                q_rules.append(ReturnConsistencyRule())
            if "SKY-L007" not in cfg["ignore"]:
                q_rules.append(EmptyErrorHandlerRule())
            if "SKY-L008" not in cfg["ignore"]:
                q_rules.append(MissingResourceCleanupRule())
            if "SKY-L009" not in cfg["ignore"]:
                q_rules.append(DebugLeftoverRule())
            if "SKY-L010" not in cfg["ignore"]:
                q_rules.append(SecurityTodoRule())
            if "SKY-L011" not in cfg["ignore"]:
                q_rules.append(DisabledSecurityRule(vibe_dictionary=vibe_dictionary))
            if "SKY-L012" not in cfg["ignore"]:
                q_rules.append(PhantomCallRule(vibe_dictionary=vibe_dictionary))
            if "SKY-L013" not in cfg["ignore"]:
                q_rules.append(InsecureRandomRule(vibe_dictionary=vibe_dictionary))
            if "SKY-L014" not in cfg["ignore"]:
                q_rules.append(HardcodedCredentialRule(vibe_dictionary=vibe_dictionary))
            if "SKY-L032" not in cfg["ignore"]:
                q_rules.append(
                    MockPlaceholderDataRule(vibe_dictionary=vibe_dictionary)
                )
            if "SKY-L017" not in cfg["ignore"]:
                q_rules.append(ErrorDisclosureRule())
            if "SKY-L020" not in cfg["ignore"]:
                q_rules.append(
                    BroadFilePermissionsRule(vibe_dictionary=vibe_dictionary)
                )
            if "SKY-L016" not in cfg["ignore"]:
                q_rules.append(UndefinedConfigRule(vibe_dictionary=vibe_dictionary))
            if "SKY-L024" not in cfg["ignore"]:
                q_rules.append(StaleMockRule())
            if "SKY-L023" not in cfg["ignore"]:
                q_rules.append(PhantomDecoratorRule(vibe_dictionary=vibe_dictionary))
            if "SKY-L026" not in cfg["ignore"]:
                q_rules.append(UnfinishedGenerationRule())
            if "SKY-L027" not in cfg["ignore"]:
                q_rules.append(
                    DuplicateStringLiteralRule(
                        threshold=cfg.get("duplicate_strings", 3)
                    )
                )
            if "SKY-L028" not in cfg["ignore"]:
                q_rules.append(TooManyReturnsRule())
            if "SKY-L029" not in cfg["ignore"]:
                q_rules.append(BooleanTrapRule())
            if "SKY-L030" not in cfg["ignore"]:
                q_rules.append(BroadExceptionRule())
            if "SKY-L031" not in cfg["ignore"]:
                q_rules.append(
                    MissingNetworkTimeoutRule(vibe_dictionary=vibe_dictionary)
                )
            if "SKY-L033" not in cfg["ignore"]:
                q_rules.append(NoEffectStatementRule())
            # SKY-D260 (prompt injection) is now handled by injection_scanner..
            if "SKY-Q502" not in cfg["ignore"]:
                q_rules.append(
                    GodFileRule(
                        max_lines=cfg.get("god_file_max_lines", 500),
                        max_definitions=cfg.get("god_file_max_definitions", 40),
                        max_top_level_definitions=cfg.get(
                            "god_file_max_top_level_definitions",
                            25,
                        ),
                    )
                )
            if "SKY-Q501" not in cfg["ignore"]:
                q_rules.append(GodClassRule())
            if "SKY-Q701" not in cfg["ignore"]:
                q_rules.append(CBORule())
            if "SKY-Q702" not in cfg["ignore"]:
                q_rules.append(LCOMRule())
            if "SKY-T101" not in cfg["ignore"] or "SKY-T102" not in cfg["ignore"]:
                q_rules.append(TypeAnnotationPracticeRule())
            if "SKY-F101" not in cfg["ignore"] or "SKY-F102" not in cfg["ignore"]:
                q_rules.append(FrameworkPracticeRule())

            if "SKY-U001" not in cfg["ignore"]:
                q_rules.append(UnreachableCodeRule())

            q_rules.append(PerformanceRule(ignore_list=cfg["ignore"]))

            custom_rules = []
            custom_rules_json = os.getenv("SKYLOS_CUSTOM_RULES")
            if os.getenv("SKYLOS_DEBUG"):
                logger.info(
                    f"[DBG] {file}: SKYLOS_CUSTOM_RULES present={bool(custom_rules_json)} "
                    f"size={len(custom_rules_json) if custom_rules_json else 0}"
                )

            if custom_rules_json:
                try:
                    custom_rules_data = json.loads(custom_rules_json)
                    custom_rules = load_custom_rules(custom_rules_data)
                    if os.getenv("SKYLOS_DEBUG"):
                        logger.info(
                            f"[DBG] {file}: load_custom_rules -> {len(custom_rules)} rules"
                        )
                        if custom_rules:
                            logger.info(
                                f"[DBG] {file}: custom rule ids = {[r.rule_id for r in custom_rules]}"
                            )
                    q_rules.extend(custom_rules)
                except Exception as e:
                    logger.error(f"[DBG] {file}: FAILED to load custom rules: {e}")
                    if os.getenv("SKYLOS_DEBUG"):
                        logger.error(traceback.format_exc())

            try:
                community_rules_data = load_community_rules()
                if community_rules_data:
                    community_rules = load_custom_rules(community_rules_data)
                    if os.getenv("SKYLOS_DEBUG"):
                        logger.info(
                            f"[DBG] {file}: community rules -> {len(community_rules)} rules"
                        )
                    q_rules.extend(community_rules)
            except Exception:
                pass

            _set_linter_node_types(q_rules)
            linter_q = LinterVisitor(q_rules, str(file))
            linter_q.context["source"] = source
            linter_q.visit(tree)
            quality_findings = [
                f for f in linter_q.findings if f.get("rule_id") not in cfg["ignore"]
            ]

            if os.getenv("SKYLOS_DEBUG"):
                custom_hits = [
                    f
                    for f in quality_findings
                    if str(f.get("rule_id", "")).startswith("CUSTOM-")
                ]
                logger.info(
                    f"[DBG] {file}: quality_findings={len(quality_findings)} custom_hits={len(custom_hits)}"
                )
                if custom_hits:
                    logger.info(f"[DBG] {file}: first_custom_hit={custom_hits[0]}")

        if full_scan and enable_danger_rules:
            d_rules = [DangerousCallsRule()]
            _set_linter_node_types(d_rules)
            linter_d = LinterVisitor(d_rules, str(file))
            linter_d.visit(tree)
            danger_findings = linter_d.findings

            from skylos.rules.danger.danger import scan_file_with_tree

            taint_findings = []
            try:
                scan_file_with_tree(tree, Path(file), taint_findings, source=source)
            except Exception:
                logger.debug("Taint analysis failed for %s", file, exc_info=True)
            if taint_findings:
                danger_findings.extend(taint_findings)

        pro_findings = []
        if extra_visitors:
            for VisitorClass in extra_visitors:
                checker = VisitorClass(file, pro_findings)
                checker.visit(tree)

        suppressed_findings = []
        if ignore_lines:
            sup_q = [f for f in quality_findings if f.get("line") in ignore_lines]
            sup_d = [f for f in danger_findings if f.get("line") in ignore_lines]
            quality_findings = [
                f for f in quality_findings if f.get("line") not in ignore_lines
            ]
            danger_findings = [
                f for f in danger_findings if f.get("line") not in ignore_lines
            ]
            for f in sup_q:
                suppressed_findings.append(
                    {**f, "category": "quality", "reason": "inline ignore comment"}
                )
            for f in sup_d:
                suppressed_findings.append(
                    {**f, "category": "security", "reason": "inline ignore comment"}
                )

        tv = TestAwareVisitor(filename=file)
        tv.visit(tree)
        tv.ignore_lines = ignore_lines

        fv = FrameworkAwareVisitor(filename=file)
        fv.visit(tree)
        fv.finalize()
        v = Visitor(mod, file)
        v.visit(tree)
        v.finalize()

        fv.dataclass_fields = getattr(v, "dataclass_fields", set())
        fv.first_read_lineno = getattr(v, "first_read_lineno", {})
        fv.protocol_classes = getattr(v, "protocol_classes", set())
        fv.namedtuple_classes = getattr(v, "namedtuple_classes", set())
        fv.enum_classes = getattr(v, "enum_classes", set())
        fv.attrs_classes = getattr(v, "attrs_classes", set())
        fv.orm_model_classes = getattr(v, "orm_model_classes", set())
        fv.type_alias_names = getattr(v, "type_alias_names", set())
        fv.abc_classes = getattr(v, "abc_classes", set())
        fv.abstract_methods = getattr(v, "abstract_methods", {})
        fv.abc_implementers = getattr(v, "abc_implementers", {})
        fv.protocol_implementers = getattr(v, "protocol_implementers", {})
        fv.protocol_method_names = getattr(v, "protocol_method_names", {})
        fv.version_conditional_lines = getattr(v, "version_conditional_lines", set())

        architecture_metrics = None
        if collect_architecture_metrics:
            try:
                architecture_tree = None
                if masked:
                    architecture_tree = ast.parse(source)
                else:
                    architecture_tree = tree

                from skylos.analysis.architecture import _compute_abstractness, _has_main_guard

                architecture_metrics = {
                    "abstractness": _compute_abstractness(architecture_tree),
                    "has_main_guard": _has_main_guard(architecture_tree),
                    "loc": sum(
                        1
                        for line in source.splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ),
                }
            except Exception:
                logger.debug(
                    "Architecture metric extraction failed for %s",
                    file,
                    exc_info=True,
                )

        clone_fragments = []
        if (
            collect_clone_fragments
            and clone_cfg is not None
            and "SKY-C401" not in cfg.get("ignore", [])
        ):
            try:
                clone_tree = None if masked else tree
                clone_fragments = extract_fragments(
                    Path(file), source, clone_cfg, tree=clone_tree
                )
            except Exception:
                logger.debug(
                    "Clone fragment extraction failed for %s", file, exc_info=True
                )

        return (
            v.defs,
            v.refs,
            v.dyn,
            v.exports,
            tv,
            fv,
            quality_findings,
            danger_findings,
            pro_findings,
            v.pattern_tracker,
            empty_file_finding,
            cfg,
            raw_imports,
            ignore_lines,
            suppressed_findings,
            v.inferred_types,
            v.instance_attr_types,
            getattr(v, "_used_attr_names", set()),
            getattr(v, "_used_attr_names_with_context", set()),
            source.splitlines(True),
            getattr(v, "param_method_refs", {}),
            getattr(v, "call_arg_types", {}),
            clone_fragments,
            architecture_metrics,
        )

    except Exception as e:
        logger.error(f"{file}: {e}")
        if os.getenv("SKYLOS_DEBUG"):
            logger.error(traceback.format_exc())
        dummy_visitor = TestAwareVisitor(filename=file)
        dummy_visitor.ignore_lines = set()
        dummy_framework_visitor = FrameworkAwareVisitor(filename=file)
        return (
            [],
            [],
            set(),
            set(),
            dummy_visitor,
            dummy_framework_visitor,
            [],
            [],
            [],
            None,
            None,
            cfg,
            [],
            set(),
            [],
            {},
            {},
            set(),
            set(),
            [],
            {},
            {},
            [],
            None,
        )


def analyze(
    path,
    conf=60,
    exclude_folders=None,
    enable_secrets=False,
    enable_danger=False,
    enable_quality=False,
    extra_visitors=None,
    progress_callback=None,
    custom_rules_data=None,
    changed_files=None,
    grep_verify=True,
    enable_sca=False,
    trace_file=None,
) -> str:
    return Skylos().analyze(
        path,
        conf,
        exclude_folders,
        enable_secrets,
        enable_danger,
        enable_quality,
        extra_visitors,
        progress_callback,
        custom_rules_data,
        changed_files,
        grep_verify=grep_verify,
        enable_sca=enable_sca,
        trace_file=trace_file,
    )


if __name__ == "__main__":
    enable_secrets = "--secrets" in sys.argv
    enable_danger = "--danger" in sys.argv
    enable_quality = "--quality" in sys.argv

    positional = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not positional:
        print(
            "Usage: python Skylos.py <path> [confidence_threshold] [--secrets] [--danger] [--quality]"
        )
        sys.exit(2)
    p = positional[0]
    confidence = int(positional[1]) if len(positional) > 1 else 60

    result = analyze(
        p,
        confidence,
        enable_secrets=enable_secrets,
        enable_danger=enable_danger,
        enable_quality=enable_quality,
    )
    data = json.loads(result)
    print("\n Python Static Analysis Results")
    print("===================================\n")

    total_dead = 0
    for key, items in data.items():
        if key.startswith("unused_") and isinstance(items, list):
            total_dead += len(items)

    danger_count = (
        data.get("analysis_summary", {}).get("danger_count", 0) if enable_danger else 0
    )
    secrets_count = (
        data.get("analysis_summary", {}).get("secrets_count", 0)
        if enable_secrets
        else 0
    )

    print("Summary:")
    workspace_data = data.get("workspaces") or {}
    has_workspace_report = bool(
        workspace_data.get("root_package")
        or workspace_data.get("packages")
        or workspace_data.get("diagnostics")
    )
    if has_workspace_report:
        print(
            " * Workspaces: "
            f"{workspace_data.get('total_packages', 0)} packages "
            f"({workspace_data.get('package_count', 0)} child workspaces)"
        )
        if workspace_data.get("diagnostic_count"):
            print(
                f" * Workspace diagnostics: {workspace_data.get('diagnostic_count', 0)}"
            )
    if data["unused_functions"]:
        print(f" * Unreachable functions: {len(data['unused_functions'])}")
    if data["unused_imports"]:
        print(f" * Unused imports: {len(data['unused_imports'])}")
    if data["unused_classes"]:
        print(f" * Unused classes: {len(data['unused_classes'])}")
    if data["unused_variables"]:
        print(f" * Unused variables: {len(data['unused_variables'])}")
    if data["unused_files"]:
        print(f" * Empty files: {len(data['unused_files'])}")
    if enable_danger:
        print(f" * Security issues: {danger_count}")
    if enable_secrets:
        print(f" * Secrets found: {secrets_count}")

    if data["unused_functions"]:
        print("\n - Unreachable Functions")
        print("=======================")
        for i, func in enumerate(data["unused_functions"], 1):
            print(f" {i}. {func['name']}")
            print(f"    └─ {func['file']}:{func['line']}")

    if data["unused_imports"]:
        print("\n - Unused Imports")
        print("================")
        for i, imp in enumerate(data["unused_imports"], 1):
            print(f" {i}. {imp['simple_name']}")
            print(f"    └─ {imp['file']}:{imp['line']}")

    if data["unused_classes"]:
        print("\n - Unused Classes")
        print("=================")
        for i, cls in enumerate(data["unused_classes"], 1):
            print(f" {i}. {cls['name']}")
            print(f"    └─ {cls['file']}:{cls['line']}")

    if data["unused_variables"]:
        print("\n - Unused Variables")
        print("==================")
        for i, var in enumerate(data["unused_variables"], 1):
            print(f" {i}. {var['name']}")
            print(f"    └─ {var['file']}:{var['line']}")

    if data["unused_files"]:
        print("\n - Empty Files")
        print("==============")
        for i, f in enumerate(data["unused_files"], 1):
            print(f" {i}. {f['file']}")
            print(f"    └─ Line {f['line']}")

    if enable_danger and data.get("danger"):
        print("\n - Security Issues")
        print("================")
        for i, f in enumerate(data["danger"], 1):
            print(
                f" {i}. {f['message']} [{f['rule_id']}] ({f['file']}:{f['line']}) Severity: {f['severity']}"
            )

            if f.get("compliance_display"):
                ## just show 3 first
                tags = ", ".join(f["compliance_display"][:3])
                print(f"    └─ Compliance: {tags}")

    if enable_secrets and data.get("secrets"):
        print("\n - Secrets")
        print("==========")
        for i, s in enumerate(data["secrets"], 1):
            rid = s.get("rule_id", "SECRET")
            msg = s.get("message", "Potential secret")
            file = s.get("file")
            line = s.get("line", 1)
            sev = s.get("severity", "HIGH")
            print(f" {i}. {msg} [{rid}] ({file}:{line}) Severity: {sev}")

    if has_workspace_report:
        print("\n - Workspaces")
        print("============")
        root_pkg = workspace_data.get("root_package")
        if root_pkg:
            print(
                f" Root: {root_pkg.get('name')} "
                f"({root_pkg.get('relative_path', root_pkg.get('path'))})"
            )
        for pkg in workspace_data.get("packages", []):
            print(f" * {pkg.get('name')} ({pkg.get('relative_path', pkg.get('path'))})")
        for diag in workspace_data.get("diagnostics", [])[:5]:
            print(f" ! {diag.get('message')}")

    print("\n" + "─" * 50)
    if enable_danger:
        print(
            f"Found {total_dead} dead code items and {danger_count} security flaws. Add this badge to your README:"
        )
    else:
        print(f"Found {total_dead} dead code items. Add this badge to your README:")
    print("```markdown")
    print(
        f"![Dead Code: {total_dead}](https://img.shields.io/badge/Dead_Code-{total_dead}_detected-orange?logo=codacy&logoColor=red)"
    )
    print("```")

    print("\nNext steps:")
    print("  * Use --interactive to select specific items to remove")
    print("  * Use --dry-run to preview changes before applying them")
