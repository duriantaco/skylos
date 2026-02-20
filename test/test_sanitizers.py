from pathlib import Path
from skylos.rules.danger.danger import scan_ctx


def _write(tmp_path: Path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return p


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def _scan_one(tmp_path: Path, name, code):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def test_xss_html_escape_clears_taint(tmp_path):
    code = (
        "from flask import request\n"
        "import html\n"
        "def f():\n"
        "    name = request.args.get('name')\n"
        "    safe = html.escape(name)\n"
        "    return '<h1>' + safe + '</h1>'\n"
    )
    out = _scan_one(tmp_path, "safe_xss.py", code)
    xss_findings = [f for f in out if "XSS" in f.get("message", "").upper()]
    assert len(xss_findings) == 0


def test_xss_without_sanitizer_flags(tmp_path):
    code = (
        "from flask import request\n"
        "def f():\n"
        "    name = request.args.get('name')\n"
        "    return '<h1>' + name + '</h1>'\n"
    )
    out = _scan_one(tmp_path, "vuln_xss.py", code)
    xss_findings = [f for f in out if "XSS" in f.get("message", "").upper()]
    assert len(xss_findings) > 0


def test_cmd_shlex_quote_clears_taint(tmp_path):
    code = (
        "import os, shlex\n"
        "def f(user_input):\n"
        "    safe = shlex.quote(user_input)\n"
        "    os.system('echo ' + safe)\n"
    )
    out = _scan_one(tmp_path, "safe_cmd.py", code)
    assert "SKY-D212" not in _rule_ids(out)


def test_cmd_without_sanitizer_flags(tmp_path):
    code = "import os\ndef f(user_input):\n    os.system('echo ' + user_input)\n"
    out = _scan_one(tmp_path, "vuln_cmd.py", code)
    assert "SKY-D212" in _rule_ids(out)


def test_html_escape_does_not_clear_sql_taint(tmp_path):
    code = (
        "import html, sqlite3\n"
        "def f(user_input):\n"
        "    safe = html.escape(user_input)\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    conn.execute('SELECT * FROM users WHERE name=' + safe)\n"
    )
    out = _scan_one(tmp_path, "cross_type.py", code)
    sql_findings = [f for f in out if f["rule_id"] in ("SKY-D211", "SKY-D217")]
    assert len(sql_findings) > 0


def test_shlex_quote_does_not_clear_xss_taint(tmp_path):
    code = (
        "from flask import request\n"
        "import shlex\n"
        "def f():\n"
        "    name = request.args.get('name')\n"
        "    safe = shlex.quote(name)\n"
        "    return '<h1>' + safe + '</h1>'\n"
    )
    out = _scan_one(tmp_path, "cross_type2.py", code)
    xss_findings = [f for f in out if "XSS" in f.get("message", "").upper()]
    assert len(xss_findings) > 0
