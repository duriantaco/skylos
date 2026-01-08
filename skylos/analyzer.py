#!/usr/bin/env python3
import ast
import sys
import json
import logging
import os
from pathlib import Path
from collections import defaultdict
from skylos.visitor import Visitor
from skylos.constants import AUTO_CALLED
from skylos.visitors.test_aware import TestAwareVisitor
from skylos.rules.secrets import scan_ctx as _secrets_scan_ctx
from skylos.rules.danger.danger import scan_ctx as scan_danger
import os
import traceback
from skylos.visitors.framework_aware import (
    FrameworkAwareVisitor
)
from skylos.config import get_all_ignore_lines, load_config
from skylos.visitors.languages.typescript import scan_typescript_file

from skylos.linter import LinterVisitor
from skylos.rules.quality.complexity import ComplexityRule
from skylos.rules.quality.nesting import NestingRule
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.quality.structure import ArgCountRule, FunctionLengthRule
from skylos.rules.quality.logic import (
    MutableDefaultRule,
    BareExceptRule,
    DangerousComparisonRule,
    TryBlockPatternsRule,
)
from skylos.penalties import apply_penalties
from skylos.rules.quality.performance import PerformanceRule
from skylos.rules.quality.unreachable import UnreachableCodeRule

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

    def _get_python_files(self, path, exclude_folders=None):
        p = Path(path).resolve()

        if p.is_file():
            if p.suffix == '.pyi':
                return [], p.parent
            return [p], p.parent

        root = p
        all_files = []
        for f in p.glob("**/*.py"):
            if f.suffix == ".py":
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

    def _mark_refs(self, progress_callback=None):
        total_refs = len(self.refs)
        if progress_callback:
            progress_callback(0, total_refs or 1, Path("PHASE: mark refs"))

        import_to_original = {}
        for name, def_obj in self.defs.items():
            if def_obj.type == "import":
                import_name = name.split(".")[-1]

                for def_name, orig_def in self.defs.items():
                    if (
                        orig_def.type != "import"
                        and orig_def.simple_name == import_name
                        and def_name != name
                    ):
                        import_to_original[name] = def_name
                        break

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
                if not ref_mod or ref_mod in ("self", "cls"):
                    for d in candidates:
                        d.references += 1
                    continue

            non_import_defs = []

            non_import_defs = []
            for d in simple_name_lookup.get(simple, []):
                if d.type != "import":
                    non_import_defs.append(d)

            if len(non_import_defs) == 1:
                non_import_defs[0].references += 1
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

        if hasattr(self, "pattern_trackers"):
            for tracker in self.pattern_trackers.values():
                for def_obj in self.defs.values():
                    should_mark, _, _ = tracker.should_mark_as_used(def_obj)
                    if should_mark:
                        def_obj.references += 1

        from skylos.implicit_refs import pattern_tracker as global_tracker

        if global_tracker.traced_calls:
            for def_obj in self.defs.values():
                should_mark, _, reason = global_tracker.should_mark_as_used(def_obj)
                if should_mark:
                    def_obj.references += 1

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
    ):
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

        if Path(".coverage").exists():
            if pattern_tracker.load_coverage():
                logger.info(
                    f"Loaded coverage data ({len(pattern_tracker.coverage_hits)} lines)"
                )

        root = Path(path).resolve()
        if root.is_dir():
            project_root = root
        else:
            project_root = root.parent

        trace_path = project_root / ".skylos_trace"
        if trace_path.exists():
            pattern_tracker.load_trace(str(trace_path))


        all_secrets = []
        all_dangers = []
        all_quality = []
        empty_files = []
        file_contexts = []

        pattern_trackers = {}

        for i, file in enumerate(files):
            if progress_callback:
                progress_callback(i + 1, len(files), file)
            mod = modmap[file]
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
                pattern_tracker,
                empty_file_finding,
                cfg,
            ) = proc_file(file, mod, extra_visitors)

            if pattern_tracker:
                pattern_trackers[mod] = pattern_tracker

            for definition in defs:
                if definition.type == "import":
                    key = f"{definition.filename}:{definition.name}"
                else:
                    key = definition.name
                self.defs[key] = definition

            self.refs.extend(refs)
            self.dynamic.update(dyn)
            self.exports[mod].update(exports)

            file_contexts.append((defs, test_flags, framework_flags, file, mod, cfg))

            if empty_file_finding:
                empty_files.append(empty_file_finding)

            if enable_quality and q_finds:
                all_quality.extend(q_finds)

            if enable_danger and d_finds:
                all_dangers.extend(d_finds)

            if pro_finds:
                all_dangers.extend(pro_finds)

            if enable_secrets and _secrets_scan_ctx is not None:
                try:
                    src = Path(file).read_text(encoding="utf-8", errors="ignore")
                    src_lines = src.splitlines(True)
                    rel = str(Path(file).relative_to(root))
                    ctx = {"relpath": rel, "lines": src_lines, "tree": None}
                    findings = list(_secrets_scan_ctx(ctx))
                    if findings:
                        all_secrets.extend(findings)
                except Exception:
                    pass
      
        self.pattern_trackers = pattern_trackers

        self._global_abc_classes = set()
        self._global_protocol_classes = set()
        self._global_abstract_methods = {}
        self._global_abc_implementers = {}
        self._global_protocol_implementers = {}
        self._global_protocol_method_names = {}
        
        for defs, test_flags, framework_flags, file, mod, cfg in file_contexts:
            self._global_abc_classes.update(getattr(framework_flags, "abc_classes", set()))
            self._global_protocol_classes.update(getattr(framework_flags, "protocol_classes", set()))
            
            for cls, methods in getattr(framework_flags, "abstract_methods", {}).items():
                if cls not in self._global_abstract_methods:
                    self._global_abstract_methods[cls] = set()
                self._global_abstract_methods[cls].update(methods)
            
            for cls, parents in getattr(framework_flags, "abc_implementers", {}).items():
                if cls not in self._global_abc_implementers:
                    self._global_abc_implementers[cls] = []
                self._global_abc_implementers[cls].extend(parents)
            
            for cls, parents in getattr(framework_flags, "protocol_implementers", {}).items():
                if cls not in self._global_protocol_implementers:
                    self._global_protocol_implementers[cls] = []
                self._global_protocol_implementers[cls].extend(parents)
            
            for cls, methods in getattr(framework_flags, "protocol_method_names", {}).items():
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
            
            for protocol_name, protocol_methods in self._global_protocol_method_names.items():
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

            if enable_danger and scan_danger is not None:
                try:
                    findings = scan_danger(root, [file])
                    if findings:
                        all_dangers.extend(findings)
                except Exception as e:
                    logger.error(f"Error scanning {file} for dangerous code: {e}")
                    if os.getenv("SKYLOS_DEBUG"):
                        logger.error(traceback.format_exc())

        if progress_callback:
            progress_callback(0, 1, Path("PHASE: mark refs"))
        self._mark_refs(progress_callback=progress_callback)


        if progress_callback:
            progress_callback(0, 1, Path("PHASE: heuristics"))
        self._apply_heuristics()
        
        if progress_callback:
            progress_callback(0, 1, Path("PHASE: exports"))
        self._mark_exports()

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
                whitelisted.append(
                    {
                        "name": d.simple_name,
                        "file": str(d.filename),
                        "line": d.line,
                        "reason": d.skip_reason,
                    }
                )

        result = {
            "definitions": context_map,
            "unused_functions": [],
            "unused_imports": [],
            "unused_classes": [],
            "unused_variables": [],
            "unused_parameters": [],
            "unused_files": [],
            "whitelisted": whitelisted,
            "analysis_summary": {
                "total_files": len(files),
                "excluded_folders": exclude_folders or [],
            },
        }

        if enable_secrets and all_secrets:
            result["secrets"] = all_secrets
            result["analysis_summary"]["secrets_count"] = len(all_secrets)

        if enable_danger and all_dangers:
            result["danger"] = all_dangers
            result["analysis_summary"]["danger_count"] = len(all_dangers)

        if enable_quality and all_quality:
            result["quality"] = all_quality
            result["analysis_summary"]["quality_count"] = len(all_quality)

        if empty_files:
            result["unused_files"] = empty_files
            result["analysis_summary"]["unused_files_count"] = len(empty_files)

        for u in unused:
            if u["type"] in ("function", "method"):
                result["unused_functions"].append(u)
            elif u["type"] == "import":
                result["unused_imports"].append(u)
            elif u["type"] == "class":
                result["unused_classes"].append(u)
            elif u["type"] == "variable":
                result["unused_variables"].append(u)
            elif u["type"] == "parameter":
                result["unused_parameters"].append(u)

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


def proc_file(file_or_args, mod=None, extra_visitors=None):
    if mod is None and isinstance(file_or_args, tuple):
        file, mod = file_or_args
    else:
        file = file_or_args

    cfg = load_config(file)

    if str(file).endswith((".ts", ".tsx")):
        ts_out = scan_typescript_file(file)
        if isinstance(ts_out, tuple) and len(ts_out) == 10:
            return (*ts_out, None, cfg)
        if isinstance(ts_out, tuple) and len(ts_out) == 11:
            return (*ts_out, cfg)
        if isinstance(ts_out, tuple) and len(ts_out) >= 12:
            return ts_out[:12]
        return (*ts_out, None, cfg)

    try:
        source = Path(file).read_text(encoding="utf-8")
        ignore_lines = get_all_ignore_lines(source)

        tree = ast.parse(source)

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

        q_rules = []
        if "SKY-Q301" not in cfg["ignore"]:
            q_rules.append(ComplexityRule(threshold=cfg["complexity"]))
        if "SKY-Q302" not in cfg["ignore"]:
            q_rules.append(NestingRule(threshold=cfg["nesting"]))
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

        if "SKY-U001" not in cfg["ignore"]:
            q_rules.append(UnreachableCodeRule())

        q_rules.append(PerformanceRule(ignore_list=cfg["ignore"]))

        linter_q = LinterVisitor(q_rules, str(file))
        linter_q.visit(tree)
        quality_findings = linter_q.findings

        d_rules = [DangerousCallsRule()]
        linter_d = LinterVisitor(d_rules, str(file))
        linter_d.visit(tree)
        danger_findings = linter_d.findings

        pro_findings = []
        if extra_visitors:
            for VisitorClass in extra_visitors:
                checker = VisitorClass(file, pro_findings)
                checker.visit(tree)

        tv = TestAwareVisitor(filename=file)
        tv.visit(tree)
        tv.ignore_lines = ignore_lines

        fv = FrameworkAwareVisitor(filename=file)
        fv.visit(tree)
        fv.finalize()
        v = Visitor(mod, file)
        v.visit(tree)

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
            cfg
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
