import ast
from skylos.rules.danger.danger_jwt.jwt_flow import scan


def _scan_code(code, filename="app.py"):
    tree = ast.parse(code)
    findings = []
    scan(tree, filename, findings)
    return findings


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def test_jwt_algorithm_none():
    code = "import jwt\ndecoded = jwt.decode(token, 'secret', algorithms=['none'])\n"
    findings = _scan_code(code)
    assert "SKY-D232" in _rule_ids(findings)


def test_jwt_verify_false():
    code = (
        "import jwt\ndecoded = jwt.decode(token, options={'verify_signature': False})\n"
    )
    findings = _scan_code(code)
    assert "SKY-D232" in _rule_ids(findings)


def test_jwt_verify_false_legacy():
    code = "import jwt\ndecoded = jwt.decode(token, verify=False)\n"
    findings = _scan_code(code)
    assert "SKY-D232" in _rule_ids(findings)


def test_jwt_safe_decode():
    code = "import jwt\ndecoded = jwt.decode(token, 'secret', algorithms=['HS256'])\n"
    findings = _scan_code(code)
    assert "SKY-D232" not in _rule_ids(findings)


def test_jwt_safe_decode_rs256():
    code = "import jwt\ndecoded = jwt.decode(token, public_key, algorithms=['RS256'])\n"
    findings = _scan_code(code)
    assert "SKY-D232" not in _rule_ids(findings)
