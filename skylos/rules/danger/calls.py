import ast
from skylos.rules.base import SkylosRule

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


def _qualified_name_from_call(node: ast.Call):
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
            if isinstance(kw.value, (ast.Constant, ast.NameConstant)):
                kw_map[kw.arg] = kw.value.value
            elif isinstance(kw.value, ast.Name) and kw.value.id in ("True", "False"):
                kw_map[kw.arg] = kw.value.id == "True"

    for key, expected in requirements.items():
        val = kw_map.get(key)
        if val != expected:
            return False
    return True


def _yaml_load_without_safeloader(node: ast.Call):
    for kw in node.keywords or []:
        if kw.arg == "Loader":
            if "SafeLoader" in ast.dump(kw.value):
                return False
    return True


class DangerousCallsRule(SkylosRule):
    rule_id = "SKY-D200"
    name = "Dangerous Function Calls"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        name = _qualified_name_from_call(node)
        if not name:
            return None

        findings = []

        for rule_key, tup in DANGEROUS_CALLS.items():
            if not _matches_rule(name, rule_key):
                continue

            rule_id = tup[0]
            severity = tup[1]
            message = tup[2]
            opts = tup[3] if len(tup) > 3 else None

            if rule_key == "yaml.load":
                if not _yaml_load_without_safeloader(node):
                    continue

            if opts and "kw_equals" in opts:
                if not _kw_equals(node, opts["kw_equals"]):
                    continue

            findings.append(
                {
                    "rule_id": rule_id,
                    "severity": severity,
                    "message": message,
                    "file": context.get("filename"),
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )
            break

        return findings if findings else None
