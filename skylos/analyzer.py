#!/usr/bin/env python3
import ast
import sys
import json
import logging
import os
import traceback
from pathlib import Path
from collections import defaultdict

from skylos.visitor import Visitor

from skylos.circular_deps import CircularDependencyRule

from skylos.constants import AUTO_CALLED

from skylos.visitors.framework_aware import FrameworkAwareVisitor
from skylos.visitors.test_aware import TestAwareVisitor
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.go import scan_go_file, clear_go_cache

from skylos.rules.secrets import scan_ctx as _secrets_scan_ctx

from skylos.rules.danger.calls import DangerousCallsRule


from skylos.config import get_all_ignore_lines, load_config

from skylos.linter import LinterVisitor

from skylos.rules.quality.complexity import ComplexityRule
from skylos.rules.quality.nesting import NestingRule
from skylos.rules.quality.structure import ArgCountRule, FunctionLengthRule
from skylos.rules.quality.logic import (
    MutableDefaultRule,
    BareExceptRule,
    DangerousComparisonRule,
    TryBlockPatternsRule,
    UnusedExceptVarRule,
    ReturnConsistencyRule,
)
from skylos.rules.quality.performance import PerformanceRule
from skylos.rules.quality.unreachable import UnreachableCodeRule
from skylos.rules.quality.async_blocking import AsyncBlockingRule
from skylos.rules.quality.class_size import GodClassRule
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

from skylos.penalties import apply_penalties

from skylos.scale.parallel_static import run_proc_file_parallel
from skylos.rules.custom import load_custom_rules

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("Skylos")


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
        if not exclude_folders:
            return False

        try:
            rel_path = file_path.relative_to(root_path)
        except ValueError:
            return False

        path_parts = rel_path.parts
        rel_path_str = str(rel_path).replace("\\", "/")

        for exclude_folder in exclude_folders:
            exclude_normalized = exclude_folder.replace("\\", "/")

            if "*" in exclude_folder:
                for part in path_parts:
                    if part.endswith(exclude_folder.replace("*", "")):
                        return True
            elif "/" in exclude_normalized:
                if rel_path_str == exclude_normalized:
                    return True
                if rel_path_str.startswith(exclude_normalized + "/"):
                    return True
                check = "/" + rel_path_str + "/"
                if "/" + exclude_normalized + "/" in check:
                    return True
            else:
                if exclude_folder in path_parts:
                    return True

        return False

    _LANG_MAP = {
        ".py": "Python",
        ".go": "Go",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
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
        all_files = []

        extensions = {".py", ".go", ".ts", ".tsx"}

        for ext in extensions:
            for f in p.glob(f"**/*{ext}"):
                all_files.append(f)

        if exclude_folders:
            filtered_files = []
            excluded_count = 0

            for file_path in all_files:
                if self._should_exclude_file(file_path, root, exclude_folders):
                    excluded_count += 1
                    continue
                filtered_files.append(file_path)

            if excluded_count > 0:
                logger.info(f"Excluded {excluded_count} files from analysis")

            return filtered_files, root

        return all_files, root

    def _mark_exports(self):
        for name, definition in self.defs.items():
            if definition.in_init and not definition.simple_name.startswith("_"):
                definition.is_exported = True

        all_exported_names = set()
        for mod, export_names in self.exports.items():
            all_exported_names.update(export_names)

        for def_name, def_obj in self.defs.items():
            if str(def_obj.filename).endswith((".ts", ".tsx")):
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
                if "." not in def_obj.name:
                    continue
                parent = def_obj.name.rsplit(".", 1)[0]
                if parent in exported_classes and not def_obj.simple_name.startswith(
                    "_"
                ):
                    def_obj.is_exported = True
                    def_obj.references = max(def_obj.references, 1)

    def _resolve_ts_module(self, source: str, importer: str) -> str | None:
        if not source.startswith("."):
            return None
        base = os.path.dirname(importer)
        target = os.path.normpath(os.path.join(base, source))
        for suffix in (".ts", ".tsx", "/index.ts", "/index.tsx"):
            candidate = target + suffix
            if os.path.isfile(candidate):
                return candidate
        if os.path.isfile(target):
            return target
        return None

    def _build_ts_import_graph(self, ts_raw_imports: dict):
        self.ts_consumed_exports = defaultdict(set)
        for importer_file, raw_imports in ts_raw_imports.items():
            for imp in raw_imports:
                resolved = self._resolve_ts_module(imp["source"], str(importer_file))
                if resolved:
                    for name in imp["names"]:
                        self.ts_consumed_exports[resolved].add(name)

    def _demote_unconsumed_ts_exports(self):
        if not hasattr(self, "ts_consumed_exports"):
            return
        for name, defn in self.defs.items():
            if not defn.is_exported:
                continue
            if not str(defn.filename).endswith((".ts", ".tsx")):
                continue
            if defn.type == "import":
                continue

            consumed = self.ts_consumed_exports.get(str(defn.filename), set())
            if defn.simple_name not in consumed and "*" not in consumed:
                defn.is_exported = False

    def _propagate_transitive_dead(self):
        dead_set = set()
        for name, defn in self.defs.items():
            if (
                defn.type in ("function", "method")
                and defn.references == 0
                and not defn.is_exported
            ):
                dead_set.add(name)

        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for name, defn in self.defs.items():
                if name in dead_set:
                    continue

                if defn.type not in ("function", "method"):
                    continue
                if defn.references == 0:
                    continue
                if defn.is_exported:
                    continue

                if not defn.called_by:
                    continue

                all_callers_dead = True
                for caller in defn.called_by:
                    if caller not in dead_set:
                        all_callers_dead = False
                        break

                if all_callers_dead:
                    dead_callers = len([c for c in defn.called_by if c in dead_set])
                    if defn.references <= dead_callers:
                        dead_set.add(name)
                        defn.references = 0
                        changed = True

        logger.info(
            f"Transitive dead code propagation: {iterations} iterations, "
            f"{len(dead_set)} total dead functions"
        )

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

            # e.g. sessions.py imports Mapping from compat.py, compat.py
            # imports Mapping from collections.abc
            import_cands = [
                k for k in import_by_simple.get(simple, []) if k != import_def_key
            ]
            if len(import_cands) == 1:
                return import_cands[0]
            if import_cands and target_fqn:
                for ik in import_cands:
                    if target_fqn in ik or ik.endswith(f":{target_fqn}"):
                        return ik

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

        total_refs = len(self.refs)
        tick_every = int(os.getenv("SKYLOS_MARKREFS_TICK", "5000"))

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
                same_file_methods = []
                for d in self.defs.values():
                    if d.type == "method" and d.simple_name == ref_simple:
                        if str(d.filename) == str(ref_file):
                            same_file_methods.append(d)

                if same_file_methods:
                    for m in same_file_methods:
                        m.references += 1
                    continue

                if non_import_defs_fallback:
                    for d in non_import_defs_fallback:
                        d.references += 1
                    continue

        from skylos.implicit_refs import pattern_tracker as global_tracker

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
        if used_attr_names:
            for defn in self.defs.values():
                if defn.references > 0:
                    continue
                if defn.type in ("method", "function"):
                    pass  # always eligible
                elif defn.type == "variable" and "." in defn.name:
                    pass  # class-level attribute, eligible
                else:
                    continue
                if defn.simple_name in used_attr_names:
                    defn.references += 1

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

            for name, defn in self.defs.items():
                if defn.type == "class":
                    bases = getattr(defn, "base_classes", [])
                    for base in bases:
                        if base in registry_bases:
                            defn.references += 1
                            break

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
            # __main__.py functions
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
    ):
        clear_go_cache()

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

        if not files:
            logger.warning(f"No Python files found in {path}")
            return json.dumps(
                {
                    "unused_functions": [],
                    "unused_imports": [],
                    "unused_classes": [],
                    "unused_variables": [],
                    "unused_parameters": [],
                    "unused_files": [],
                    "analysis_summary": {
                        "total_files": 0,
                        "excluded_folders": exclude_folders if exclude_folders else [],
                    },
                }
            )

        logger.info(f"Analyzing {len(files)} Python files...")

        modmap = {}
        for f in files:
            modmap[f] = self._module(root, f)

        from skylos.implicit_refs import pattern_tracker
        from skylos.implicit_refs import pattern_tracker as global_pattern_tracker

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

        if isinstance(path, (list, tuple)):
            _first = Path(path[0]).resolve()
            all_resolved = [Path(p).resolve() for p in path]
            project_root = Path(os.path.commonpath(all_resolved))
        else:
            _first = Path(path).resolve()
            project_root = _first
        if not project_root.is_dir():
            project_root = project_root.parent

        try:
            from skylos.pyproject_entrypoints import extract_entrypoints

            for qname in extract_entrypoints(project_root):
                global_pattern_tracker.known_qualified_refs.add(qname)
        except Exception:
            pass

        coverage_path = project_root / ".coverage"
        if coverage_path.exists():
            if global_pattern_tracker.load_coverage():
                logger.info(
                    f"Loaded coverage data ({len(pattern_tracker.coverage_hits)} lines)"
                )

        root = project_root

        trace_path = project_root / ".skylos_trace"
        if trace_path.exists():
            pattern_tracker.load_trace(str(trace_path))

        all_secrets = []
        all_dangers = []
        all_quality = []
        all_suppressed = []
        empty_files = []
        file_contexts = []

        per_file_ignore_lines = {}
        pattern_trackers = {}
        all_raw_imports = {}
        ts_raw_imports = {}
        all_inferred_types = {}
        all_instance_attr_types = {}
        all_used_attr_names = set()

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
        try:
            outs = run_proc_file_parallel(
                files,
                modmap,
                extra_visitors=extra_visitors,
                jobs=int(os.getenv("SKYLOS_JOBS", "0")),
                progress_callback=progress_callback,
                custom_rules_data=custom_rules_data,
                changed_files=changed_files,
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
                    elif str(file).endswith((".ts", ".tsx")):
                        ts_raw_imports[file] = file_raw_imports

                if pattern_tracker_obj:
                    pattern_trackers[mod] = pattern_tracker_obj

                if file_inferred_types:
                    all_inferred_types.update(file_inferred_types)
                if file_instance_attr_types:
                    all_instance_attr_types.update(file_instance_attr_types)
                if file_used_attr_names:
                    all_used_attr_names.update(file_used_attr_names)

                for definition in defs:
                    if definition.type == "import":
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
                    all_dangers.extend(d_finds)

                if pro_finds:
                    all_dangers.extend(pro_finds)

                if enable_secrets and _secrets_scan_ctx is not None:
                    if changed_files is None or str(file) in changed_files:
                        try:
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
                            pass

            if enable_secrets and _secrets_scan_ctx is not None:
                _CONFIG_SUFFIXES = {
                    ".env",
                    ".yaml",
                    ".yml",
                    ".json",
                    ".toml",
                    ".ini",
                    ".cfg",
                    ".conf",
                }
                scanned = {str(f) for f in files}
                for cfg_file in root.rglob("*"):
                    if cfg_file.suffix.lower() not in _CONFIG_SUFFIXES:
                        continue
                    if str(cfg_file) in scanned:
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
                        pass

        finally:
            if injected:
                os.environ.pop("SKYLOS_CUSTOM_RULES", None)

        if enable_quality:
            RULE_ID = "SKY-C401"

            cfg_by_file = {str(file): cfg for (_, _, _, file, _, cfg) in file_contexts}

            clone_cfg = CloneConfig(
                grouping_mode=GroupingMode.CONNECTED,
                grouping_threshold=0.80,
                k_core_k=2,
                similarity_threshold=0.90,
                ignore_identifiers=True,
                ignore_literals=True,
                skip_docstrings=True,
            )

            py_files = [Path(f) for f in files if str(f).endswith(".py")]

            frags = []
            for f in py_files:
                fcfg = cfg_by_file.get(str(f))
                if fcfg and RULE_ID in fcfg.get("ignore", []):
                    continue

                src = f.read_text(encoding="utf-8", errors="ignore")
                file_frags = extract_fragments(f, src, clone_cfg)
                frags.extend(file_frags)

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

        self.pattern_trackers = pattern_trackers

        for tracker in pattern_trackers.values():
            if hasattr(tracker, "known_qualified_refs"):
                tracker.known_qualified_refs.clear()

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

        for defs, test_flags, framework_flags, file, mod, cfg in file_contexts:
            for definition in defs:
                apply_penalties(self, definition, test_flags, framework_flags, cfg)

        if enable_danger:
            try:
                from skylos.rules.danger.danger_hallucination.dependency_hallucination import (
                    scan_python_dependency_hallucinations,
                )

                py_files = [
                    f for f in files if str(f).endswith((".py", ".pyi", ".pyw"))
                ]
                if py_files:
                    dep_root = Path(
                        os.path.commonpath([str(p.resolve()) for p in py_files])
                    )
                    if dep_root.is_file():
                        dep_root = dep_root.parent
                    dep_findings = scan_python_dependency_hallucinations(
                        dep_root, py_files
                    )
                    if dep_findings:
                        all_dangers.extend(dep_findings)
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error(traceback.format_exc())

        all_sca = []
        if enable_danger:
            try:
                from skylos.rules.sca.vulnerability_scanner import scan_dependencies

                scan_root = (
                    Path(os.path.commonpath([str(p.resolve()) for p in files]))
                    if files
                    else Path(path[0] if isinstance(path, (list, tuple)) else path)
                )
                if scan_root.is_file():
                    scan_root = scan_root.parent
                sca_findings = scan_dependencies(scan_root)
                if sca_findings:
                    all_sca.extend(sca_findings)
            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    logger.error(traceback.format_exc())

        self._build_ts_import_graph(ts_raw_imports)

        self._global_type_map = {}
        self._global_type_map.update(all_inferred_types)
        self._global_type_map.update(all_instance_attr_types)
        self._all_used_attr_names = all_used_attr_names

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: mark refs"))
        self._mark_refs(progress_callback=progress_callback)

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

        shown = 0

        def def_sort_key(d):
            return (d.type, d.name)

        for d in sorted(self.defs.values(), key=def_sort_key):
            if shown >= 50:
                break
            shown += 1

        unused = []
        for definition in self.defs.values():
            if (
                definition.references == 0
                and not definition.is_exported
                and definition.confidence > 0
                and definition.confidence >= thr
            ):
                unused.append(definition.to_dict())

        context_map = {}
        for name, d in self.defs.items():
            if d.type in ("class", "function", "method") and not name.startswith("_"):
                context_map[name] = {
                    "name": d.name,
                    "file": str(d.filename),
                    "line": d.line,
                    "type": d.type,
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

        if enable_secrets and all_secrets:
            result["secrets"] = all_secrets
            result["analysis_summary"]["secrets_count"] = len(all_secrets)

        if enable_danger and all_dangers:
            result["danger"] = all_dangers
            result["analysis_summary"]["danger_count"] = len(all_dangers)

        if all_sca:
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

                if enable_quality and "SKY-Q802" not in project_cfg.get("ignore", []):
                    try:
                        from skylos.architecture import get_architecture_findings

                        dep_graph = dict(circular_rule._analyzer.dependencies)
                        mod_files = dict(circular_rule._analyzer.modules)

                        mod_trees = {}
                        for file in files:
                            if not str(file).endswith(".py"):
                                continue
                            mod = modmap.get(file, "")
                            try:
                                src = Path(file).read_text(
                                    encoding="utf-8", errors="ignore"
                                )
                                mod_trees[mod] = ast.parse(src)
                            except Exception:
                                pass

                        arch_findings, arch_summary = get_architecture_findings(
                            dependency_graph=dep_graph,
                            module_files=mod_files,
                            module_trees=mod_trees,
                        )
                        if arch_findings:
                            all_quality.extend(arch_findings)
                        if arch_summary:
                            result["architecture_metrics"] = arch_summary
                    except Exception:
                        if os.getenv("SKYLOS_DEBUG"):
                            traceback.print_exc()

            except Exception:
                if os.getenv("SKYLOS_DEBUG"):
                    traceback.print_exc()

        try:
            from skylos.grader import count_lines_of_code, compute_grade

            total_loc = count_lines_of_code(files)
            result["analysis_summary"]["total_loc"] = total_loc
            result["grade"] = compute_grade(result, total_loc)
        except Exception:
            if os.getenv("SKYLOS_DEBUG"):
                traceback.print_exc()

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


def proc_file(file_or_args, mod=None, extra_visitors=None, full_scan=True):
    if mod is None and isinstance(file_or_args, tuple):
        file, mod = file_or_args
    else:
        file = file_or_args

    cfg = load_config(file)

    if str(file).endswith((".ts", ".tsx")):
        out = scan_typescript_file(file, cfg)
        if isinstance(out, tuple) and len(out) < 13:
            return (*out, *([None] * (13 - len(out))))
        return out[:13]

    if str(file).endswith(".go"):
        out = scan_go_file(file, cfg)
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

        from skylos.ast_mask import apply_body_mask, default_mask_spec_from_config

        mask = default_mask_spec_from_config(cfg)
        tree, masked = apply_body_mask(tree, mask)

        if masked and os.getenv("SKYLOS_DEBUG"):
            logger.info(f"{file}: masked {masked} bodies (skipped inner analysis)")

        quality_findings = []
        danger_findings = []

        if full_scan:
            q_rules = []
            if "SKY-Q301" not in cfg["ignore"]:
                q_rules.append(ComplexityRule(threshold=cfg["complexity"]))
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
            if "SKY-L004" not in cfg["ignore"]:
                q_rules.append(TryBlockPatternsRule(max_lines=15))
            if "SKY-L005" not in cfg["ignore"]:
                q_rules.append(UnusedExceptVarRule())
            if "SKY-L006" not in cfg["ignore"]:
                q_rules.append(ReturnConsistencyRule())
            if "SKY-Q501" not in cfg["ignore"]:
                q_rules.append(GodClassRule())
            if "SKY-Q701" not in cfg["ignore"]:
                q_rules.append(CBORule())
            if "SKY-Q702" not in cfg["ignore"]:
                q_rules.append(LCOMRule())

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

            linter_q = LinterVisitor(q_rules, str(file))
            linter_q.visit(tree)
            quality_findings = linter_q.findings

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

            d_rules = [DangerousCallsRule()]
            linter_d = LinterVisitor(d_rules, str(file))
            linter_d.visit(tree)
            danger_findings = linter_d.findings

            from skylos.rules.danger.danger import scan_file_with_tree

            taint_findings = []
            try:
                scan_file_with_tree(tree, Path(file), taint_findings)
            except Exception:
                pass
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
):
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
