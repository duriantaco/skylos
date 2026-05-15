import ast
import re
from functools import lru_cache
from pathlib import Path

from skylos.rules.base import SkylosRule
from skylos.rules.quality.logic_foundation import _string_literal_value
from skylos.rules.vibe_dictionary import DEFAULT_VIBE_DICTIONARY


DEBUG_FUNCTIONS = {"print", "pprint", "breakpoint", "ic"}
DEBUG_METHOD_CALLS = {
    ("pdb", "set_trace"),
    ("ipdb", "set_trace"),
    ("pudb", "set_trace"),
    ("code", "interact"),
    ("pprint", "pprint"),
}

_CLI_FILENAMES = {"cli.py", "__main__.py", "manage.py"}
_SKIP_DIRS = {"scripts", "bin", "tools"}


@lru_cache(maxsize=4096)
def _basename(filename):
    return str(filename).replace("\\", "/").rsplit("/", 1)[-1]


@lru_cache(maxsize=4096)
def _is_test_file(filename):
    base = _basename(filename)
    if base.startswith("test_") or base.endswith("_test.py") or base == "conftest.py":
        return True
    return False


@lru_cache(maxsize=4096)
def _is_cli_or_script(filename):
    filename = str(filename).replace("\\", "/")
    base = filename.rsplit("/", 1)[-1]
    if base in _CLI_FILENAMES:
        return True
    for part in filename.split("/"):
        if part in _SKIP_DIRS:
            return True
    return False


class DebugLeftoverRule(SkylosRule):
    rule_id = "SKY-L009"
    name = "Debug Leftover"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        filename = context.get("filename", "")

        func = node.func
        func_name = None
        is_method = False
        method_obj = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr
            is_method = True
            if isinstance(func.value, ast.Name):
                method_obj = func.value.id

        if not func_name:
            return None

        matched = False
        severity = "LOW"
        debug_name = func_name

        if not is_method and func_name in DEBUG_FUNCTIONS:
            matched = True
            if func_name in ("breakpoint", "ic"):
                severity = "HIGH"
            else:
                severity = "LOW"
            debug_name = func_name

        if is_method and method_obj:
            for obj, method in DEBUG_METHOD_CALLS:
                if method_obj == obj and func_name == method:
                    matched = True
                    severity = "HIGH"
                    debug_name = f"{obj}.{method}"
                    break

        if not matched:
            return None

        if func_name == "print" or (func_name == "pprint" and not is_method):
            if _is_cli_or_script(filename):
                return None
            if _is_test_file(filename):
                return None
            if self._has_main_guard(context):
                return None

        if func_name == "breakpoint" or debug_name.endswith("set_trace"):
            pass

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": severity,
                "type": "call",
                "name": debug_name,
                "simple_name": debug_name,
                "value": "debug",
                "threshold": 0,
                "message": f"Debug leftover '{debug_name}()' found. Remove before shipping.",
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]

    def _has_main_guard(self, context):
        return context.get("_has_main_guard", False)


_SECURITY_TODO_RE = re.compile(
    r"#\s*(?:TODO|FIXME|HACK|XXX|TEMP)\b[:\s].*?"
    r"(?:auth|authenticat|authori[sz]|login|permission|credential|password|secret"
    r"|token|csrf|xss|inject|sanitiz|validat|escap|encrypt|decrypt|ssl|tls"
    r"|verify|cert|cors|session|cookie|jwt|oauth|api.?key|firewall"
    r"|rate.?limit|brute.?force|acl|rbac|security|vulnerable|exploit"
    r"|unsafe|insecure|disable|bypass|hack|workaround|temporary|fixme"
    r"|hardcod)",
    re.IGNORECASE,
)


class SecurityTodoRule(SkylosRule):
    rule_id = "SKY-L010"
    name = "Security TODO Marker"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        src = context.get("_source")
        if not src:
            try:
                src = Path(filename).read_text(  # skylos: ignore[SKY-D215] analyzer reads current scan file
                    encoding="utf-8", errors="ignore"
                )
            except Exception:
                return None

        findings = []
        for i, line in enumerate(src.splitlines(), start=1):
            m = _SECURITY_TODO_RE.search(line)
            if m:
                comment = m.group(0).strip()
                if len(comment) > 120:
                    comment = comment[:117] + "..."
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "MEDIUM",
                        "type": "comment",
                        "name": "security_todo",
                        "simple_name": "security_todo",
                        "value": "unfulfilled",
                        "threshold": 0,
                        "message": f"Security-related TODO left in code: {comment}",
                        "file": filename,
                        "basename": Path(filename).name,
                        "line": i,
                        "col": m.start(),
                    }
                )

        return findings if findings else None


_DISABLED_SECURITY_PATTERNS = DEFAULT_VIBE_DICTIONARY.disabled_security_patterns
_DANGEROUS_CALLS = DEFAULT_VIBE_DICTIONARY.dangerous_calls
_DANGEROUS_DECORATORS = DEFAULT_VIBE_DICTIONARY.dangerous_decorators
_DANGEROUS_ASSIGNMENTS = DEFAULT_VIBE_DICTIONARY.dangerous_assignments


class DisabledSecurityRule(SkylosRule):
    rule_id = "SKY-L011"
    name = "Disabled Security Control"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(
            node, (ast.Call, ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign)
        ):
            return None

        filename = context.get("filename", "")

        if _is_test_file(filename):
            return None

        findings = []
        basename = _basename(filename)
        disabled_patterns = self.vibe_dictionary.disabled_security_patterns
        dangerous_calls = self.vibe_dictionary.dangerous_calls
        dangerous_decorators = self.vibe_dictionary.dangerous_decorators
        dangerous_assignments = self.vibe_dictionary.dangerous_assignments

        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in disabled_patterns:
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "HIGH",
                                "type": "call",
                                "name": kw.arg,
                                "simple_name": kw.arg,
                                "value": "disabled",
                                "threshold": 0,
                                "message": disabled_patterns[kw.arg],
                                "file": filename,
                                "basename": basename,
                                "line": kw.value.lineno,
                                "col": kw.value.col_offset,
                            }
                        )

            func = node.func
            func_name = None
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id
            if func_name in dangerous_calls:
                msg = dangerous_calls[func_name]
                if msg:
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "HIGH",
                            "type": "call",
                            "name": func_name,
                            "simple_name": func_name,
                            "value": "disabled",
                            "threshold": 0,
                            "message": msg,
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = None
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                if dec_name in dangerous_decorators:
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "HIGH",
                            "type": "decorator",
                            "name": dec_name,
                            "simple_name": dec_name,
                            "value": "disabled",
                            "threshold": 0,
                            "message": dangerous_decorators[dec_name],
                            "file": filename,
                            "basename": basename,
                            "line": dec.lineno,
                            "col": dec.col_offset,
                        }
                    )

        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in dangerous_assignments:
                expected_val, msg = dangerous_assignments[target.id]
                if msg is None:
                    pass
                elif target.id == "ALLOWED_HOSTS":
                    if isinstance(node.value, ast.List):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and elt.value == "*":
                                findings.append(
                                    {
                                        "rule_id": self.rule_id,
                                        "kind": "logic",
                                        "severity": "HIGH",
                                        "type": "assignment",
                                        "name": target.id,
                                        "simple_name": target.id,
                                        "value": "wildcard",
                                        "threshold": 0,
                                        "message": msg,
                                        "file": filename,
                                        "basename": basename,
                                        "line": node.lineno,
                                        "col": node.col_offset,
                                    }
                                )
                elif (
                    isinstance(node.value, ast.Constant)
                    and node.value.value == expected_val
                ):
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "MEDIUM",
                            "type": "assignment",
                            "name": target.id,
                            "simple_name": target.id,
                            "value": "insecure",
                            "threshold": 0,
                            "message": msg,
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        return findings if findings else None


_PHANTOM_SECURITY_NAMES = DEFAULT_VIBE_DICTIONARY.phantom_security_names


class PhantomCallRule(SkylosRule):
    rule_id = "SKY-L012"
    name = "Phantom Function Call"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
        self._defined_names = None
        self._current_file = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            self._defined_names = set()
            self._imported_names = set()
            for child in ast.walk(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._defined_names.add(child.name)
                elif isinstance(child, ast.ClassDef):
                    self._defined_names.add(child.name)
                    for item in child.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self._defined_names.add(item.name)
                elif isinstance(child, ast.ImportFrom):
                    if child.names:
                        for alias in child.names:
                            name = alias.asname if alias.asname else alias.name
                            self._imported_names.add(name)
                elif isinstance(child, ast.Import):
                    for alias in child.names:
                        name = alias.asname if alias.asname else alias.name
                        self._imported_names.add(name.split(".")[0])
            return None

        if self._defined_names is None:
            return None

        if not isinstance(node, ast.Call):
            return None

        func = node.func
        func_name = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            return None

        if not func_name:
            return None

        if func_name not in self.vibe_dictionary.phantom_security_names:
            return None

        if func_name in self._defined_names:
            return None
        if func_name in self._imported_names:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "CRITICAL",
                "type": "call",
                "name": func_name,
                "simple_name": func_name,
                "value": "phantom",
                "threshold": 0,
                "message": (
                    f"Call to '{func_name}()' but this function is never defined or imported. "
                    f"AI-generated code often hallucinates security functions."
                ),
                "file": filename,
                "basename": basename,
                "line": node.lineno,
                "col": node.col_offset,
                "vibe_category": "hallucinated_reference",
                "ai_likelihood": "high",
            }
        ]


_PHANTOM_SECURITY_DECORATORS = DEFAULT_VIBE_DICTIONARY.phantom_security_decorators


class PhantomDecoratorRule(SkylosRule):
    rule_id = "SKY-L023"
    name = "Phantom Decorator"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
        self._defined_names = None
        self._imported_names = None
        self._current_file = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            self._defined_names = set()
            self._imported_names = set()
            for child in ast.walk(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._defined_names.add(child.name)
                elif isinstance(child, ast.ClassDef):
                    self._defined_names.add(child.name)
                    for item in child.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self._defined_names.add(item.name)
                elif isinstance(child, ast.ImportFrom):
                    if child.names:
                        for alias in child.names:
                            name = alias.asname if alias.asname else alias.name
                            self._imported_names.add(name)
                elif isinstance(child, ast.Import):
                    for alias in child.names:
                        name = alias.asname if alias.asname else alias.name
                        self._imported_names.add(name.split(".")[0])
            return None

        if self._defined_names is None:
            return None

        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return None

        findings = []
        for deco in node.decorator_list:
            deco_name = self._extract_decorator_name(deco)
            if not deco_name:
                continue
            if deco_name not in self.vibe_dictionary.phantom_security_decorators:
                continue
            if deco_name in self._defined_names:
                continue
            if deco_name in self._imported_names:
                continue

            basename = Path(filename).name
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "CRITICAL",
                    "type": "decorator",
                    "name": deco_name,
                    "simple_name": deco_name,
                    "value": "phantom",
                    "threshold": 0,
                    "message": (
                        f"Decorator '@{deco_name}' is used but never defined or imported. "
                        f"AI-generated code often hallucinates security decorators."
                    ),
                    "file": filename,
                    "basename": basename,
                    "line": deco.lineno,
                    "col": deco.col_offset,
                    "vibe_category": "hallucinated_reference",
                    "ai_likelihood": "high",
                }
            )

        return findings if findings else None

    @staticmethod
    def _extract_decorator_name(deco):
        if isinstance(deco, ast.Call):
            return PhantomDecoratorRule._extract_decorator_name(deco.func)
        if isinstance(deco, ast.Name):
            return deco.id
        if isinstance(deco, ast.Attribute):
            return None
        return None


class UnfinishedGenerationRule(SkylosRule):
    rule_id = "SKY-L026"
    name = "Unfinished Generation"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        filename = context.get("filename", "")

        for deco in node.decorator_list:
            deco_name = None
            if isinstance(deco, ast.Name):
                deco_name = deco.id
            elif isinstance(deco, ast.Attribute):
                deco_name = deco.attr
            if deco_name in ("abstractmethod", "overload"):
                return None

        basename = Path(filename).name
        if basename == "__init__.py":
            return None
        if basename.startswith("test_") or basename.startswith("conftest"):
            return None

        if node.name.startswith("__") and node.name.endswith("__"):
            return None

        body = node.body
        if not body:
            return None

        stmts = body
        if isinstance(body[0], ast.Expr) and _string_literal_value(body[0].value):
            stmts = body[1:]

        if not stmts:
            return None

        if len(stmts) != 1:
            return None

        stmt = stmts[0]
        marker = None
        marker_line = stmt.lineno

        if isinstance(stmt, ast.Pass):
            marker = "pass"
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            if stmt.value.value is ...:
                marker = "..."
        elif isinstance(stmt, ast.Raise):
            exc = stmt.exc
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                if exc.func.id == "NotImplementedError":
                    marker = "NotImplementedError"
            elif isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
                marker = "NotImplementedError"

        if not marker:
            return None

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "function",
                "name": node.name,
                "simple_name": node.name,
                "value": marker,
                "threshold": 0,
                "message": (
                    f"Function '{node.name}' has only `{marker}` in its body. "
                    f"AI-generated code often leaves stub implementations that "
                    f"silently do nothing in production."
                ),
                "file": filename,
                "basename": basename,
                "line": marker_line,
                "col": stmt.col_offset,
                "vibe_category": "incomplete_generation",
                "ai_likelihood": "medium",
            }
        ]


class UndefinedConfigRule(SkylosRule):
    rule_id = "SKY-L016"
    name = "Undefined Config"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
        self._env_refs = None
        self._env_sets = None
        self._current_file = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            self._env_refs = []
            self._env_sets = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Subscript):
                    if (
                        isinstance(child.value, ast.Attribute)
                        and isinstance(child.value.value, ast.Name)
                        and child.value.value.id == "os"
                        and child.value.attr == "environ"
                    ):
                        if isinstance(child.slice, ast.Constant) and isinstance(
                            child.slice.value, str
                        ):
                            self._env_sets.add(child.slice.value)
            return None

        if self._env_refs is None:
            return None

        if not isinstance(node, ast.Call):
            return None

        env_var_name = self._extract_env_var(node)
        if not env_var_name:
            return None

        if env_var_name in self.vibe_dictionary.well_known_env_vars:
            return None

        if env_var_name in self._env_sets:
            return None

        upper = env_var_name.upper()
        is_flag = any(
            upper.startswith(p)
            for p in ("ENABLE_", "DISABLE_", "USE_", "FEATURE_", "FLAG_", "TOGGLE_")
        )

        if not is_flag:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "call",
                "name": env_var_name,
                "simple_name": env_var_name,
                "value": "undefined",
                "threshold": 0,
                "message": (
                    f"Feature flag '{env_var_name}' is checked but never defined in this file. "
                    f"AI-generated code often references configuration that was never set up."
                ),
                "file": filename,
                "basename": basename,
                "line": node.lineno,
                "col": node.col_offset,
                "vibe_category": "ghost_config",
                "ai_likelihood": "medium",
            }
        ]

    @staticmethod
    def _extract_env_var(node):
        func = node.func
        if isinstance(func, ast.Attribute):
            if (
                func.attr == "getenv"
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                if node.args and isinstance(node.args[0], ast.Constant):
                    return node.args[0].value
            if (
                func.attr == "get"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "environ"
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id == "os"
            ):
                if node.args and isinstance(node.args[0], ast.Constant):
                    return node.args[0].value
        return None


_WELL_KNOWN_ENV_VARS = DEFAULT_VIBE_DICTIONARY.well_known_env_vars


class StaleMockRule(SkylosRule):
    rule_id = "SKY-L024"
    name = "Stale Mock"
    node_types = (ast.Module, ast.Call)

    _parse_cache: dict = {}

    def __init__(self):
        self._current_file = None
        self._is_test = False
        self._project_root_cache = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            basename = Path(filename).name
            self._is_test = basename.startswith("test_") or basename.startswith(
                "conftest"
            )
            self._project_root_cache = None
            return None

        if not self._is_test:
            return None

        target_str = None
        target_node = None

        if isinstance(node, ast.Call):
            target_str, target_node = self._extract_patch_target(node)

        if not target_str or not target_node:
            return None

        parts = target_str.split(".")
        if len(parts) < 2:
            return None

        attr_name = parts[-1]
        module_parts = parts[:-1]

        if self._project_root_cache is None:
            self._project_root_cache = self._find_project_root(filename) or False
        project_root = self._project_root_cache
        if not project_root:
            return None

        module_file = self._resolve_module(project_root, module_parts)
        if not module_file:
            return None

        try:
            stat = module_file.stat()
            cache_key = (str(module_file), stat.st_mtime_ns, stat.st_size)
        except OSError:
            return None

        defined_names = StaleMockRule._parse_cache.get(cache_key)
        if defined_names is None:
            try:
                source = module_file.read_text(errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                StaleMockRule._parse_cache[cache_key] = set()
                return None
            defined_names = set()
            for child in ast.walk(tree):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defined_names.add(child.name)
                elif isinstance(child, ast.ClassDef):
                    defined_names.add(child.name)
                elif isinstance(child, ast.Assign):
                    for t in child.targets:
                        if isinstance(t, ast.Name):
                            defined_names.add(t.id)
                elif isinstance(child, ast.ImportFrom):
                    if child.names:
                        for alias in child.names:
                            name = alias.asname if alias.asname else alias.name
                            defined_names.add(name)
                elif isinstance(child, ast.Import):
                    for alias in child.names:
                        name = alias.asname if alias.asname else alias.name
                        defined_names.add(name.split(".")[0])
            StaleMockRule._parse_cache[cache_key] = defined_names

        if attr_name in defined_names:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "HIGH",
                "type": "mock",
                "name": target_str,
                "simple_name": attr_name,
                "value": "stale",
                "threshold": 0,
                "message": (
                    f"mock.patch('{target_str}') references '{attr_name}' "
                    f"but it does not exist in '{'.'.join(module_parts)}'. "
                    f"The function may have been renamed or removed, "
                    f"making this mock silently ineffective."
                ),
                "file": filename,
                "basename": basename,
                "line": target_node.lineno,
                "col": target_node.col_offset,
                "vibe_category": "stale_reference",
                "ai_likelihood": "medium",
            }
        ]

    @staticmethod
    def _extract_patch_target(call_node):
        func = call_node.func

        is_patch = False
        if isinstance(func, ast.Attribute) and func.attr == "patch":
            is_patch = True
        elif isinstance(func, ast.Name) and func.id == "patch":
            is_patch = True
        elif isinstance(func, ast.Attribute) and func.attr == "object":
            return None, None

        if not is_patch:
            return None, None

        if call_node.args and isinstance(call_node.args[0], ast.Constant):
            if isinstance(call_node.args[0].value, str):
                return call_node.args[0].value, call_node
        return None, None

    @staticmethod
    def _find_project_root(filepath):
        p = Path(filepath).resolve().parent
        for _ in range(20):
            if (p / "pyproject.toml").exists():
                return p
            if (p / "setup.py").exists():
                return p
            if (p / ".git").exists():
                return p
            parent = p.parent
            if parent == p:
                break
            p = parent
        return None

    @staticmethod
    def _resolve_module(project_root, module_parts):
        pkg_path = project_root / "/".join(module_parts) / "__init__.py"
        if pkg_path.is_file():
            return pkg_path

        mod_path = (
            project_root / "/".join(module_parts[:-1]) / (module_parts[-1] + ".py")
            if len(module_parts) > 1
            else project_root / (module_parts[0] + ".py")
        )
        if mod_path.is_file():
            return mod_path

        if len(module_parts) >= 2:
            flat_path = project_root / ("/".join(module_parts) + ".py")
            if Path(flat_path).is_file():
                return Path(flat_path)

        direct = project_root / ("/".join(module_parts) + ".py")
        if Path(direct).is_file():
            return Path(direct)

        return None


_SECURITY_VAR_KEYWORDS = DEFAULT_VIBE_DICTIONARY.security_var_keywords
_INSECURE_RANDOM_FUNCS = DEFAULT_VIBE_DICTIONARY.insecure_random_funcs


def _var_name_is_security(name, vibe_dictionary=None):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    lower = name.lower()
    for kw in vibe_dictionary.security_var_keywords:
        if kw in lower:
            return True
    return False


class InsecureRandomRule(SkylosRule):
    rule_id = "SKY-L013"
    name = "Insecure Randomness"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(node, ast.Assign):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        call = node.value
        if not isinstance(call, ast.Call):
            return None

        func = call.func
        func_name = None
        is_random_module = False

        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "random":
                if func.attr in self.vibe_dictionary.insecure_random_funcs:
                    func_name = f"random.{func.attr}"
                    is_random_module = True
        elif isinstance(func, ast.Name):
            if func.id in self.vibe_dictionary.insecure_random_funcs:
                func_name = func.id

        if not func_name or not is_random_module:
            return None

        for target in node.targets:
            var_name = None
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr
            elif isinstance(target, ast.Subscript) and isinstance(
                target.value, ast.Name
            ):
                var_name = target.value.id

            if var_name and _var_name_is_security(var_name, self.vibe_dictionary):
                basename = Path(filename).name
                return [
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "HIGH",
                        "type": "call",
                        "name": func_name,
                        "simple_name": func_name,
                        "value": "insecure_random",
                        "threshold": 0,
                        "message": (
                            f"'{func_name}()' used for security-sensitive value '{var_name}'. "
                            f"Use 'secrets' module instead (e.g. secrets.token_urlsafe())."
                        ),
                        "file": filename,
                        "basename": basename,
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                ]

        return None


_CREDENTIAL_VAR_NAMES = DEFAULT_VIBE_DICTIONARY.credential_var_names
_CREDENTIAL_VAR_SUFFIXES = DEFAULT_VIBE_DICTIONARY.credential_var_suffixes

_CREDENTIAL_DSN_RE = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:]+:[^@]+@",
)

_PLACEHOLDER_VALUES = DEFAULT_VIBE_DICTIONARY.placeholder_values
_MOCK_CONTEXT_WORDS = {
    "mock",
    "fake",
    "dummy",
    "placeholder",
    "sample",
    "example",
    "fixture",
    "stub",
    "demo",
}
_PLACEHOLDER_EMAIL_RE = re.compile(
    r"(?i)^[a-z0-9._%+-]+@"
    r"("
    r"example\.(?:com|org|net)|test\.(?:com|org|net)|localhost|invalid|"
    r"foo\.com|bar\.com"
    r")$"
)
_PLACEHOLDER_PHONE_RE = re.compile(
    r"(?:^|[^0-9])"
    r"(\(?(?:0{3}|1{3}|123)\)?[-.\s]?(?:0{3,4}|1{3,4}|456)[-.\s]?"
    r"(?:0{4}|1{4}|7890))"
    r"(?:[^0-9]|$)"
)
_UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_TEST_CREDENTIAL_RE = re.compile(
    r"(?i)^(?:password|secret|api[_-]?key|token|credential|auth)[0-9]*$"
    r"|^(?:password|secret)123$"
    r"|^test(?:password|secret|key)$"
)
_PLACEHOLDER_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.org",
    "test.net",
    "foo.com",
    "bar.com",
)


def _is_credential_var(name, vibe_dictionary=None):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    lower = name.lower()
    if lower in vibe_dictionary.credential_var_names:
        return True
    for suffix in vibe_dictionary.credential_var_suffixes:
        if lower.endswith(suffix):
            return True
    return False


def _name_has_mock_context(name: str) -> bool:
    parts = {p for p in re.split(r"[^a-zA-Z0-9]+", name.lower()) if p}
    return bool(parts & _MOCK_CONTEXT_WORDS)


def _target_names(node) -> list[str]:
    names = []

    def collect(target):
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                collect(item)

    if isinstance(node, ast.Assign):
        for target in node.targets:
            collect(target)
    elif isinstance(node, ast.AnnAssign):
        collect(node.target)

    return names


def _is_low_entropy_uuid(value: str) -> bool:
    if not _UUID_RE.match(value):
        return False
    cleaned = value.replace("-", "").lower()
    if not cleaned:
        return False
    if len(set(cleaned)) <= 2:
        return True
    return cleaned in {
        "00000000000000000000000000000000",
        "11111111111111111111111111111111",
        "ffffffffffffffffffffffffffffffff",
        "12345678123456781234567812345678",
    }


def _is_repetitive_placeholder(value: str) -> bool:
    if len(value) < 4 or len(value) > 20:
        return False
    if len(set(value)) == 1:
        return True
    if len(value) % 2 == 0:
        pair = value[:2]
        return pair * (len(value) // 2) == value
    return False


def _classify_placeholder_value(
    value: str,
    target_names: list[str],
    vibe_dictionary=None,
):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    stripped = value.strip()
    lower = stripped.lower()
    target_context = any(_name_has_mock_context(name) for name in target_names)
    credential_context = any(
        _is_credential_var(name, vibe_dictionary) for name in target_names
    )

    if _PLACEHOLDER_EMAIL_RE.match(stripped):
        return "placeholder_email", "MEDIUM", "Email uses a test/example domain"

    if _is_low_entropy_uuid(stripped):
        return (
            "low_entropy_uuid",
            "MEDIUM",
            "UUID has a low-entropy placeholder pattern",
        )

    if _PLACEHOLDER_PHONE_RE.search(stripped):
        return "placeholder_phone", "MEDIUM", "Phone number uses a placeholder pattern"

    if credential_context and _TEST_CREDENTIAL_RE.match(stripped):
        return (
            "test_credential",
            "HIGH",
            "Credential value is a common test placeholder",
        )

    if target_context and lower in vibe_dictionary.placeholder_values:
        return "placeholder_value", "MEDIUM", "Value is a configured placeholder token"

    if target_context and any(domain in lower for domain in _PLACEHOLDER_DOMAINS):
        return "placeholder_domain", "LOW", "Value references a test/example domain"

    if target_context and _is_repetitive_placeholder(stripped):
        return "repetitive_placeholder", "LOW", "Value is a repetitive placeholder"

    return None


def _is_env_lookup(node):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                if func.value.id == "os" and func.attr in ("getenv", "environ"):
                    return True
            if isinstance(func.value, ast.Attribute):
                if hasattr(func.value, "attr") and func.value.attr == "environ":
                    return True
        if isinstance(func, ast.Name) and func.id == "getenv":
            return True
    if isinstance(func if isinstance(node, ast.Call) else node, ast.Subscript):
        val = node.value if isinstance(node, ast.Subscript) else None
        if val and isinstance(val, ast.Attribute):
            if hasattr(val, "attr") and val.attr == "environ":
                return True
    return False


class HardcodedCredentialRule(SkylosRule):
    rule_id = "SKY-L014"
    name = "Hardcoded Credential"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(node, (ast.Assign, ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        findings = []
        basename = _basename(filename)

        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            var_name = None
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr

            if var_name and _is_credential_var(var_name, self.vibe_dictionary):
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    str_val = value.value
                    if not str_val or str_val.strip() == "":
                        return None
                    try:
                        if _is_env_lookup(value):
                            return None
                    except Exception:
                        pass

                    severity = "HIGH"
                    if str_val.lower() in self.vibe_dictionary.placeholder_values:
                        severity = "MEDIUM"

                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": severity,
                            "type": "assignment",
                            "name": var_name,
                            "simple_name": var_name,
                            "value": "hardcoded",
                            "threshold": 0,
                            "message": (
                                f"Hardcoded credential in '{var_name}'. "
                                f"Use environment variables or a secrets manager instead."
                            ),
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    if _CREDENTIAL_DSN_RE.search(value.value):
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "HIGH",
                                "type": "assignment",
                                "name": var_name,
                                "simple_name": var_name,
                                "value": "hardcoded_dsn",
                                "threshold": 0,
                                "message": (
                                    f"Connection string in '{var_name}' contains embedded credentials. "
                                    f"Use environment variables for database URLs."
                                ),
                                "file": filename,
                                "basename": basename,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg, default in _iter_arg_defaults(node):
                if hasattr(arg, "arg"):
                    arg_name = arg.arg
                else:
                    arg_name = str(arg)

                if _is_credential_var(arg_name, self.vibe_dictionary):
                    if isinstance(default, ast.Constant) and isinstance(
                        default.value, str
                    ):
                        str_val = default.value
                        if str_val and str_val.strip():
                            severity = "HIGH"
                            if (
                                str_val.lower()
                                in self.vibe_dictionary.placeholder_values
                            ):
                                severity = "MEDIUM"
                            findings.append(
                                {
                                    "rule_id": self.rule_id,
                                    "kind": "logic",
                                    "severity": severity,
                                    "type": "default",
                                    "name": arg_name,
                                    "simple_name": arg_name,
                                    "value": "hardcoded_default",
                                    "threshold": 0,
                                    "message": (
                                        f"Hardcoded credential in default argument '{arg_name}'. "
                                        f"Use environment variables or None with runtime lookup."
                                    ),
                                    "file": filename,
                                    "basename": basename,
                                    "line": default.lineno,
                                    "col": default.col_offset,
                                }
                            )

        return findings if findings else None


class MockPlaceholderDataRule(SkylosRule):
    rule_id = "SKY-L032"
    name = "Mock Or Placeholder Data"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(
            node,
            (ast.Assign, ast.AnnAssign, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        findings = []
        basename = _basename(filename)

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = _string_literal_value(node.value)
            if value is not None:
                self._add_finding(
                    findings,
                    value=value,
                    target_names=_target_names(node),
                    filename=filename,
                    basename=basename,
                    line=getattr(node.value, "lineno", getattr(node, "lineno", 1)),
                    col=getattr(
                        node.value,
                        "col_offset",
                        getattr(node, "col_offset", 0),
                    ),
                )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg, default in _iter_arg_defaults(node):
                value = _string_literal_value(default)
                if value is None:
                    continue
                arg_name = arg.arg if hasattr(arg, "arg") else str(arg)
                self._add_finding(
                    findings,
                    value=value,
                    target_names=[arg_name],
                    filename=filename,
                    basename=basename,
                    line=getattr(default, "lineno", getattr(node, "lineno", 1)),
                    col=getattr(
                        default,
                        "col_offset",
                        getattr(node, "col_offset", 0),
                    ),
                )

        return findings if findings else None

    def _add_finding(
        self,
        findings,
        *,
        value,
        target_names,
        filename,
        basename,
        line,
        col,
    ):
        classification = _classify_placeholder_value(
            value,
            target_names,
            self.vibe_dictionary,
        )
        if not classification:
            return

        placeholder_type, severity, rationale = classification
        name = target_names[0] if target_names else placeholder_type
        findings.append(
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": severity,
                "type": "literal",
                "name": name,
                "simple_name": name,
                "value": placeholder_type,
                "threshold": 0,
                "mock_data_type": placeholder_type,
                "message": (
                    f"Mock or placeholder data in '{name}' "
                    f"({placeholder_type}). {rationale}."
                ),
                "file": filename,
                "basename": basename,
                "line": line,
                "col": col,
            }
        )


def _iter_arg_defaults(func_node):
    args = func_node.args
    num_defaults = len(args.defaults)
    num_args = len(args.args)
    offset = num_args - num_defaults

    for i, default in enumerate(args.defaults):
        if default:
            yield args.args[offset + i], default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default:
            yield arg, default


_HTTP_RESPONSE_CONSTRUCTORS = {
    "JsonResponse",
    "jsonify",
    "Response",
    "HTMLResponse",
    "JSONResponse",
    "PlainTextResponse",
    "make_response",
    "HttpResponse",
    "HttpResponseBadRequest",
    "HttpResponseServerError",
}

_HTTP_RETURN_KEYS = {"error", "message", "detail", "msg", "reason"}


class ErrorDisclosureRule(SkylosRule):
    rule_id = "SKY-L017"
    name = "Error Information Disclosure"

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        exc_var = node.name
        if not exc_var:
            return None

        findings = []
        basename = Path(filename).name

        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                self._check_disclosure(
                    child.value, exc_var, child, filename, basename, findings
                )

            if isinstance(child, ast.Call):
                func = child.func
                func_name = None
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr
                if func_name in _HTTP_RESPONSE_CONSTRUCTORS:
                    for arg in child.args:
                        self._check_disclosure(
                            arg, exc_var, child, filename, basename, findings
                        )
                    for kw in child.keywords:
                        self._check_disclosure(
                            kw.value, exc_var, child, filename, basename, findings
                        )

        return findings if findings else None

    def _check_disclosure(
        self, value_node, exc_var, report_node, filename, basename, findings
    ):
        if self._is_exc_stringification(value_node, exc_var):
            findings.append(
                self._make_finding(report_node, filename, basename, exc_var)
            )
            return

        if isinstance(value_node, ast.Dict):
            for k, v in zip(value_node.keys, value_node.values):
                if k and isinstance(k, ast.Constant) and isinstance(k.value, str):
                    if k.value.lower() in _HTTP_RETURN_KEYS:
                        if self._is_exc_stringification(v, exc_var):
                            findings.append(
                                self._make_finding(
                                    report_node, filename, basename, exc_var
                                )
                            )
                            return

        if isinstance(value_node, ast.JoinedStr):
            for val in value_node.values:
                if isinstance(val, ast.FormattedValue):
                    if self._is_exc_stringification(val.value, exc_var):
                        findings.append(
                            self._make_finding(report_node, filename, basename, exc_var)
                        )
                        return
                    if isinstance(val.value, ast.Name) and val.value.id == exc_var:
                        findings.append(
                            self._make_finding(report_node, filename, basename, exc_var)
                        )
                        return

    def _is_exc_stringification(self, node, exc_var):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("str", "repr"):
                if node.args and isinstance(node.args[0], ast.Name):
                    if node.args[0].id == exc_var:
                        return True

            if isinstance(func, ast.Attribute) and func.attr == "format_exc":
                if isinstance(func.value, ast.Name) and func.value.id == "traceback":
                    return True

        if isinstance(node, ast.Name) and node.id == exc_var:
            return True
        return False

    def _make_finding(self, node, filename, basename, exc_var):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": "MEDIUM",
            "type": "block",
            "name": "error_disclosure",
            "simple_name": "error_disclosure",
            "value": "exception_leaked",
            "threshold": 0,
            "message": (
                f"Exception details ('{exc_var}') returned in HTTP response. "
                f"This exposes internal stack traces to attackers. Return a generic error message instead."
            ),
            "file": filename,
            "basename": basename,
            "line": node.lineno,
            "col": node.col_offset,
        }


_SENSITIVE_FILE_KEYWORDS = DEFAULT_VIBE_DICTIONARY.sensitive_file_keywords
_NETWORK_TIMEOUT_CALLS = DEFAULT_VIBE_DICTIONARY.network_timeout_calls


def _is_sensitive_filename(name, vibe_dictionary=None):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    lower = name.lower()
    for kw in vibe_dictionary.sensitive_file_keywords:
        if kw in lower:
            return True
    return False


class BroadFilePermissionsRule(SkylosRule):
    rule_id = "SKY-L020"
    name = "Overly Broad File Permissions"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        func = node.func
        func_name = None

        if isinstance(func, ast.Attribute) and func.attr == "chmod":
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                func_name = "os.chmod"

        if func_name != "os.chmod":
            return None

        if len(node.args) < 2:
            return None

        mode_node = node.args[1]
        mode_val = None

        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, int):
            mode_val = mode_node.value

        if mode_val is None:
            return None

        basename = Path(filename).name

        path_arg = node.args[0]
        target_name = ""
        if isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str):
            target_name = path_arg.value
        elif isinstance(path_arg, ast.Name):
            target_name = path_arg.id

        is_sensitive = _is_sensitive_filename(target_name, self.vibe_dictionary)

        if mode_val & 0o777 == 0o777:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} grants full access to all users.",
                )
            ]

        if mode_val & 0o002:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} is world-writable.",
                )
            ]

        if is_sensitive and mode_val & 0o077:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} on sensitive file. Use 0o600 for private keys and credentials.",
                )
            ]

        return None

    def _make_finding(self, node, filename, basename, mode_val, severity, message):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": severity,
            "type": "call",
            "name": "os.chmod",
            "simple_name": "os.chmod",
            "value": oct(mode_val),
            "threshold": 0,
            "message": message,
            "file": filename,
            "basename": basename,
            "line": node.lineno,
            "col": node.col_offset,
        }


def _qualified_call_name(func_node):
    parts = []
    node = func_node
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class MissingNetworkTimeoutRule(SkylosRule):
    rule_id = "SKY-L031"
    name = "Missing Network Timeout"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        call_name = _qualified_call_name(node.func)
        if call_name not in self.vibe_dictionary.network_timeout_calls:
            return None

        if any(kw.arg == "timeout" for kw in node.keywords):
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "call",
                "name": call_name,
                "simple_name": call_name,
                "value": "no_timeout",
                "threshold": 0,
                "message": (
                    f"Network call '{call_name}()' has no timeout. "
                    f"LLM-generated integrations often omit timeouts and can hang worker threads."
                ),
                "file": filename,
                "basename": basename,
                "line": node.lineno,
                "col": node.col_offset,
                "vibe_category": "missing_resilience_control",
                "ai_likelihood": "medium",
            }
        ]
