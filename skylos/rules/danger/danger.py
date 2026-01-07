from __future__ import annotations
import ast
import sys
from pathlib import Path
from .danger_sql.sql_flow import scan as scan_sql
from .danger_cmd.cmd_flow import scan as scan_cmd
from .danger_sql.sql_raw_flow import scan as scan_sql_raw
from .danger_net.ssrf_flow import scan as scan_ssrf
from .danger_fs.path_flow import scan as scan_path
from .danger_web.xss_flow import scan as scan_xss

ALLOWED_SUFFIXES = (".py", ".pyi", ".pyw")

DANGEROUS_CALLS = {
    "eval": ("SKY-D201", "HIGH", "Use of eval()"),
    "exec": ("SKY-D202", "HIGH", "Use of exec()"),
    "os.system": ("SKY-D203", "CRITICAL", "Use of os.system()"),
    "pickle.load": (
        "SKY-D204",
        "CRITICAL",
        "Untrusted deserialization via pickle.load",
    ),
    "pickle.loads": (
        "SKY-D205",
        "CRITICAL",
        "Untrusted deserialization via pickle.loads",
    ),
    "yaml.load": ("SKY-D206", "HIGH", "yaml.load without SafeLoader"),
    "hashlib.md5": ("SKY-D207", "MEDIUM", "Weak hash (MD5)"),
    "hashlib.sha1": ("SKY-D208", "MEDIUM", "Weak hash (SHA1)"),
    "subprocess.*": (
        "SKY-D209",
        "HIGH",
        "subprocess call with shell=True",
        {"kw_equals": {"shell": True}},
    ),
    "requests.*": (
        "SKY-D210",
        "HIGH",
        "requests call with verify=False",
        {"kw_equals": {"verify": False}},
    ),
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
    for kw in node.keywords or []:
        if kw.arg:
            kw_map[kw.arg] = kw.value

    for key, expected in requirements.items():
        val = kw_map.get(key)
        if not isinstance(val, ast.Constant):
            return False
        if val.value != expected:
            return False
    return True


def qualified_name_from_call(node: ast.Call):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _yaml_load_without_safeloader(node: ast.Call):
    name = qualified_name_from_call(node)
    if name != "yaml.load":
        return False

    for kw in node.keywords or []:
        if kw.arg == "Loader":
            text = ast.unparse(kw.value)
            return "SafeLoader" not in text
    return True


def _add_finding(findings, file_path: Path, node: ast.AST, rule_id, severity, message):
    findings.append(
        {
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "file": str(file_path),
            "line": getattr(node, "lineno", 1),
            "col": getattr(node, "col_offset", 0),
        }
    )


def _scan_file(file_path: Path, findings):
    src = file_path.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(src)

    scan_sql(tree, file_path, findings)
    scan_cmd(tree, file_path, findings)
    scan_sql_raw(tree, file_path, findings)
    scan_ssrf(tree, file_path, findings)
    scan_path(tree, file_path, findings)
    scan_xss(tree, file_path, findings)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name = qualified_name_from_call(node)
        if not name:
            continue

        for rule_key, tup in DANGEROUS_CALLS.items():
            rule_id = tup[0]
            severity = tup[1]
            message = tup[2]

            if len(tup) > 3:
                opts = tup[3]
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


def scan_ctx(_, files):
    findings = []

    for file_path in files:
        if file_path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue

        try:
            _scan_file(file_path, findings)
        except Exception as e:
            print(f"Scan failed for {file_path}: {e}", file=sys.stderr)

    return findings
