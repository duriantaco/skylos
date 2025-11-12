#!/usr/bin/env python3
import ast
import sys
import json
import logging
from pathlib import Path
from collections import defaultdict
from skylos.visitor import Visitor
from skylos.constants import ( PENALTIES, AUTO_CALLED )
from skylos.visitors.test_aware import TestAwareVisitor
from skylos.rules.secrets import scan_ctx as _secrets_scan_ctx
from skylos.rules.danger.danger import scan_ctx as scan_danger
import os
import traceback
from skylos.visitors.framework_aware import FrameworkAwareVisitor, detect_framework_usage
from skylos.rules.quality.quality import scan_ctx as scan_quality

logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')
logger=logging.getLogger('Skylos')

class Skylos:
    def __init__(self):
        self.defs={}
        self.refs=[]
        self.dynamic=set()
        self.exports=defaultdict(set)

    def _module(self,root,f):
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
        
        for exclude_folder in exclude_folders:
            if "*" in exclude_folder:
                for part in path_parts:
                    if part.endswith(exclude_folder.replace("*", "")):
                        return True
            else:
                if exclude_folder in path_parts:
                    return True
        
        return False
    
    def _get_python_files(self, path, exclude_folders=None):
        p = Path(path).resolve()
        
        if p.is_file():
            return [p], p.parent
        
        root = p
        all_files = list(p.glob("**/*.py"))
        
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
            if definition.in_init and not definition.simple_name.startswith('_'):
                definition.is_exported = True
        
        for mod, export_names in self.exports.items():
            for name in export_names:
                for def_name, def_obj in self.defs.items():
                    if (def_name.startswith(f"{mod}.") and 
                        def_obj.simple_name == name and
                        def_obj.type != "import"):
                        def_obj.is_exported = True

    def _mark_refs(self):
        import_to_original = {}
        for name, def_obj in self.defs.items():
            if def_obj.type == "import":
                import_name = name.split('.')[-1]
                
                for def_name, orig_def in self.defs.items():
                    if (orig_def.type != "import" and 
                        orig_def.simple_name == import_name and
                        def_name != name):
                        import_to_original[name] = def_name
                        break

        simple_name_lookup = defaultdict(list)
        for definition in self.defs.values():
            simple_name_lookup[definition.simple_name].append(definition)
        
        for ref, _ in self.refs:
            if ref in self.defs:
                self.defs[ref].references += 1
                if ref in import_to_original:
                    original = import_to_original[ref]
                    self.defs[original].references += 1
                continue

            simple = ref.split('.')[-1]
            ref_mod = ref.rsplit(".", 1)[0]
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

            if len(candidates) == 1:
                candidates[0].references += 1
                continue
            
            non_import_defs = []
            for d in simple_name_lookup.get(simple, []):
                if d.type != "import":
                    non_import_defs.append(d)

            if len(non_import_defs) == 1:
                non_import_defs[0].references += 1
                continue

        for module_name in self.dynamic:
            for def_name, def_obj in self.defs.items():
                if def_obj.name.startswith(f"{module_name}."):
                    if def_obj.type in ("function", "method") and not def_obj.simple_name.startswith("_"):
                        def_obj.references += 1
    
    def _get_base_classes(self, class_name):
        if class_name not in self.defs:
            return []
        
        class_def = self.defs[class_name]
        
        if hasattr(class_def, 'base_classes'):
            return class_def.base_classes
        
        return []
    
    def _apply_penalties(self, def_obj, visitor, framework):
        confidence=100

        if getattr(visitor, "ignore_lines", None) and def_obj.line in visitor.ignore_lines:
            def_obj.confidence = 0
            return

        if "." in def_obj.name:
            owner, attr = def_obj.name.rsplit(".", 1)
            owner_simple = owner.split(".")[-1]

            if (
                owner_simple == "Settings"
                or owner_simple == "Config"
                or owner_simple.endswith("Settings")
                or owner_simple.endswith("Config")
            ):
                if attr.isupper() or not attr.startswith("_"):
                    def_obj.confidence = 0
                    return
        
        if def_obj.type == "variable" and def_obj.simple_name == "_":
            def_obj.confidence = 0
            return
        
        if def_obj.simple_name.startswith("_") and not def_obj.simple_name.startswith("__"):
            confidence -= PENALTIES["private_name"] 

        if def_obj.simple_name.startswith("__") and def_obj.simple_name.endswith("__"):
            confidence -= PENALTIES["dunder_or_magic"]

        if def_obj.in_init and def_obj.type in ("function", "class"):
            confidence -= PENALTIES["in_init_file"]
            
        if def_obj.name.split(".")[0] in self.dynamic:
            confidence -= PENALTIES["dynamic_module"]

        if visitor.is_test_file or def_obj.line in visitor.test_decorated_lines:
            confidence -= PENALTIES["test_related"]

        if def_obj.type == "variable" and getattr(framework, "dataclass_fields", None):
            if def_obj.name in framework.dataclass_fields:
                def_obj.confidence = 0
                return
        
        if def_obj.type == "variable" and "." in def_obj.name:
            prefix, _ = def_obj.name.rsplit(".", 1)

            cls_def = self.defs.get(prefix)
            if cls_def and cls_def.type == "class":
                cls_simple = cls_def.simple_name

                if getattr(framework, "pydantic_models", None) and cls_simple in framework.pydantic_models:
                    def_obj.confidence = 0
                    return

                cls_node = getattr(framework, "class_defs", {}).get(cls_simple)
                if cls_node is not None:
                    schema_like = False

                    for base in cls_node.bases:
                        if isinstance(base, ast.Name) and base.id.lower().endswith(("schema", "model")):
                            schema_like = True
                            break

                        if isinstance(base, ast.Attribute) and base.attr.lower().endswith(("schema", "model")):
                            schema_like = True
                            break

                    if schema_like:
                        def_obj.confidence = 0
                        return
                    
     
        if def_obj.type == "variable":
            fr = getattr(framework, "first_read_lineno", {}).get(def_obj.name)
            if fr is not None and fr >= def_obj.line:
                def_obj.confidence = 0
                return
        
        if def_obj.type == "variable" and "." in def_obj.name:
            _, attr = def_obj.name.rsplit(".", 1)

            for other in self.defs.values():
                if other is def_obj:
                    continue
                if other.type != "variable":
                    continue
                if "." not in other.name:
                    continue
                if other.simple_name != attr:
                    continue

                def_obj.confidence = 0
                return
        
        framework_confidence = detect_framework_usage(def_obj, visitor=framework)
        if framework_confidence is not None:
            confidence = min(confidence, framework_confidence)

        if (def_obj.simple_name.startswith("__") and def_obj.simple_name.endswith("__")):
            confidence = 0

        if def_obj.type == "parameter":
            if def_obj.simple_name in ("self", "cls"):
                confidence = 0
            elif "." in def_obj.name:
                method_name = def_obj.name.split(".")[-2]
                if method_name.startswith("__") and method_name.endswith("__"):
                    confidence = 0
        
        if visitor.is_test_file or def_obj.line in visitor.test_decorated_lines:
            confidence = 0
        
        if (def_obj.type == "import" and def_obj.name.startswith("__future__.") and
            def_obj.simple_name in ("annotations", "absolute_import", "division", 
                                "print_function", "unicode_literals", "generator_stop")):
            confidence = 0
        
        def_obj.confidence = max(confidence, 0)

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
                    
                    if (method.simple_name.startswith("visit_") or
                        method.simple_name.startswith("leave_") or
                        method.simple_name.startswith("transform_")):
                        method.references += 1

                    if method.simple_name == "format" and cls.endswith("Formatter"):
                        method.references += 1

    def analyze(self, path, thr=60, exclude_folders= None, enable_secrets = False, enable_danger = False, enable_quality = False):
        files, root = self._get_python_files(path, exclude_folders)
        
        if not files:
            logger.warning(f"No Python files found in {path}")
            return json.dumps({
                "unused_functions": [], 
                "unused_imports": [], 
                "unused_classes": [],
                "unused_variables": [],
                "unused_parameters": [],
                 "analysis_summary": {
                    "total_files": 0,
                    "excluded_folders": exclude_folders if exclude_folders else []
                }
            })
        
        logger.info(f"Analyzing {len(files)} Python files...")
        
        modmap = {}
        for f in files:
            modmap[f] = self._module(root, f)
        
        all_secrets = []
        all_dangers = []
        all_quality = []
        file_contexts = []

        for file in files:
            mod = modmap[file]
            defs, refs, dyn, exports, test_flags, framework_flags = proc_file(file, mod)

            for definition in defs:
                self.defs[definition.name] = definition

            self.refs.extend(refs)
            self.dynamic.update(dyn)
            self.exports[mod].update(exports)

            file_contexts.append((defs, test_flags, framework_flags, file, mod))

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

            if enable_quality: 
                try:
                    findings = scan_quality(root, [file])
                    if findings:
                        all_quality.extend(findings)
                except Exception as e:
                    logger.error(f"Error scanning {file} for quality issues: {e}")
                    if os.getenv("SKYLOS_DEBUG"):
                        logger.error("Quality scan error", exc_info=True)

        for defs, test_flags, framework_flags, file, mod in file_contexts:
            for definition in defs:
                self._apply_penalties(definition, test_flags, framework_flags)
            
            if enable_danger and scan_danger is not None:
                try:
                    findings = scan_danger(root, [file])
                    if findings:
                        all_dangers.extend(findings)
                except Exception as e:
                    logger.error(f"Error scanning {file} for dangerous code: {e}")
                    if os.getenv("SKYLOS_DEBUG"):
                        logger.error(traceback.format_exc())

        self._mark_refs()
        self._apply_heuristics() 
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
                if definition.references == 0 and not definition.is_exported and definition.confidence > 0 and definition.confidence >= thr:
                    unused.append(definition.to_dict())

        result = {
            "unused_functions": [], 
            "unused_imports": [], 
            "unused_classes": [],
            "unused_variables": [],
            "unused_parameters": [],
            "analysis_summary": {
                "total_files": len(files),
                "excluded_folders": exclude_folders or [],
            }
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

def proc_file(file_or_args, mod=None):
    if mod is None and isinstance(file_or_args, tuple):
        file, mod = file_or_args 
    else:
        file = file_or_args 

    try:
        source = Path(file).read_text(encoding="utf-8")
        ignore_lines = {i for i, line in enumerate(source.splitlines(), start=1)
                        if "pragma: no skylos" in line}
        tree = ast.parse(source)

        tv = TestAwareVisitor(filename=file)
        tv.visit(tree)
        tv.ignore_lines = ignore_lines

        fv = FrameworkAwareVisitor(filename=file)
        fv.visit(tree)
        fv.finalize()
        v  = Visitor(mod, file)
        v.visit(tree)

        fv.dataclass_fields = getattr(v, "dataclass_fields", set())
        fv.first_read_lineno = getattr(v, "first_read_lineno", {})

        return v.defs, v.refs, v.dyn, v.exports, tv, fv
    
    except Exception as e:
        logger.error(f"{file}: {e}")
        if os.getenv("SKYLOS_DEBUG"):
            logger.error(traceback.format_exc())
        dummy_visitor = TestAwareVisitor(filename=file)
        dummy_visitor.ignore_lines = set()
        dummy_framework_visitor = FrameworkAwareVisitor(filename=file)

        return [], [], set(), set(), dummy_visitor, dummy_framework_visitor

def analyze(path, conf=60, exclude_folders=None, enable_secrets=False, enable_danger=False, enable_quality=False):
    return Skylos().analyze(path,conf, exclude_folders, enable_secrets, enable_danger, enable_quality)

if __name__ == "__main__":
    enable_secrets = ("--secrets" in sys.argv)
    enable_danger  = ("--danger"  in sys.argv)

    positional = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not positional:
        print("Usage: python Skylos.py <path> [confidence_threshold] [--secrets] [--danger]")
        sys.exit(2)

    p = positional[0]
    confidence = int(positional[1]) if len(positional) > 1 else 60

    result = analyze(p, confidence, enable_secrets=enable_secrets, enable_danger=enable_danger)
        
    data = json.loads(result)
    print("\n Python Static Analysis Results")
    print("===================================\n")
    
    total_dead = 0
    for key, items in data.items():
        if key.startswith("unused_") and isinstance(items, list):
            total_dead += len(items)

    danger_count = data.get("analysis_summary", {}).get("danger_count", 0) if enable_danger else 0
    secrets_count = data.get("analysis_summary", {}).get("secrets_count", 0) if enable_secrets else 0
    
    print("Summary:")
    if data["unused_functions"]:
        print(f" * Unreachable functions: {len(data['unused_functions'])}")
    if data["unused_imports"]:
        print(f" * Unused imports: {len(data['unused_imports'])}")
    if data["unused_classes"]:
        print(f" * Unused classes: {len(data['unused_classes'])}")
    if data["unused_variables"]:
        print(f" * Unused variables: {len(data['unused_variables'])}")
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

    if enable_danger and data.get("danger"):
        print("\n - Security Issues")
        print("================")
        for i, f in enumerate(data["danger"], 1):
            print(f" {i}. {f['message']} [{f['rule_id']}] ({f['file']}:{f['line']}) Severity: {f['severity']}")

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
        print(f"Found {total_dead} dead code items and {danger_count} security flaws. Add this badge to your README:")
    else:
        print(f"Found {total_dead} dead code items. Add this badge to your README:")
    print("```markdown")
    print(f"![Dead Code: {total_dead}](https://img.shields.io/badge/Dead_Code-{total_dead}_detected-orange?logo=codacy&logoColor=red)")
    print("```")
    
    print("\nNext steps:")
    print("  * Use --interactive to select specific items to remove")
    print("  * Use --dry-run to preview changes before applying them")
