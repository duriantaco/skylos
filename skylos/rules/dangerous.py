from __future__ import annotations
import ast
from pathlib import Path

ALLOWED_SUFFIXES = (".py", ".pyi", ".pyw")

## will expand this list later with more rules 
DANGEROUS_CALLS = {
    "eval": ("SKY-D201", "HIGH", "Use of eval()"),
    "exec": ("SKY-D202", "HIGH", "Use of exec()"),
    "os.system": ("SKY-D203", "MEDIUM", "Use of os.system"),
    "pickle.load": ("SKY-D204", "CRITICAL", "Untrusted deserialization via pickle.load"),
    "pickle.loads": ("SKY-D205", "CRITICAL", "Untrusted deserialization via pickle.loads"),
    "yaml.load": ("SKY-D206", "HIGH", "yaml.load without SafeLoader"),
    "hashlib.md5": ("SKY-D207", "MEDIUM", "Weak hash (MD5)"),
    "hashlib.sha1": ("SKY-D208", "MEDIUM", "Weak hash (SHA1)"),
    ## this is for arguments like process
    "subprocess.*": ("SKY-D209", "HIGH", "subprocess.* with shell=True",
                     {"kw_equals": {"shell": True}}),

    "requests.*": ("SKY-D210", "HIGH", "requests call with verify=False",
                   {"kw_equals": {"verify": False}}),
}

def _matches_rule(name, rule_key):
    if not name:
        return False
    if rule_key.endswith(".*"):
        return name.startswith(rule_key[:-2] + ".")
    return name == rule_key

def _kw_equals(node: ast.Call, requirements):
    if not requirements:
        return True
    kw_map = {}
    keywords = node.keywords or []
    for kw in keywords:
        if kw.arg:
            kw_map[kw.arg] = kw.value
        
    for key, expected in requirements.items():
        val = kw_map.get(key)
        if not isinstance(val, ast.Constant):
            return False
        if val.value is not expected:
            return False
    return True

def qualified_name_from_call(node: ast.Call):
    f = node.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(f, ast.Name):
        return f.id
    return None

def _yaml_load_without_safeloader(node: ast.Call):
    name = qualified_name_from_call(node)
    if name != "yaml.load":
        return False

    for kw in node.keywords or []:
        if kw.arg == "Loader":
            try:
                text = ast.unparse(kw.value)
                return "SafeLoader" not in text
            except Exception:
                return True
    return True

def _add_finding(findings,
                 file_path: Path,
                 node: ast.AST,
                 rule_id,
                 severity,
                 message):
    findings.append({
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(file_path),
        "line": getattr(node, "lineno", 1),
        "col": getattr(node, "col_offset", 0),
    })

def scan_ctx(root, files):
    findings = []

    for file_path in files:
        if file_path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue

        try:
            src = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src)
        except Exception:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = qualified_name_from_call(node)
            if not name:
                continue

            for rule_key, tup in DANGEROUS_CALLS.items():
                rule_id, severity, message, *rest = tup

                if rest:
                    opts = rest[0]
                else:
                    opts = None

                if not _matches_rule(name, rule_key):
                    continue
                
                if rule_key == "yaml.load":
                    if not _yaml_load_without_safeloader(node):
                        continue

                if opts and "kw_equals" in opts:
                    if not _kw_equals(node, opts["kw_equals"]):
                        continue

                _add_finding(findings, file_path, node, rule_id, severity, message)
                break

    return findings
