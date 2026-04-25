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


def test_open_tainted_flags(tmp_path):
    code = (
        "def f(p):\n"
        "    with open(p, 'r', encoding='utf-8', errors='ignore') as fh:\n"
        "        fh.read()\n"
    )
    out = _scan_one(tmp_path, "pt_open.py", code)
    assert "SKY-D215" in _rule_ids(out)


def test_os_remove_tainted_flags(tmp_path):
    code = "import os\ndef f(p):\n    os.remove(p)\n"
    out = _scan_one(tmp_path, "pt_os.py", code)
    assert "SKY-D215" in _rule_ids(out)


def test_open_constant_ok(tmp_path):
    code = "def f():\n    open('README.md', 'r')\n"
    out = _scan_one(tmp_path, "pt_ok.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_pathlib_read_text_tainted_join_flags(tmp_path):
    code = (
        "from pathlib import Path\n"
        "BASE = Path('/srv/uploads')\n"
        "def f(name):\n"
        "    return (BASE / name).read_text(encoding='utf-8')\n"
    )
    out = _scan_one(tmp_path, "pt_pathlib_read.py", code)
    assert "SKY-D215" in _rule_ids(out)


def test_pathlib_name_projection_sanitizes_path_join(tmp_path):
    code = (
        "from pathlib import Path\n"
        "BASE = Path('/srv/uploads')\n"
        "def f(raw):\n"
        "    name = Path(raw).name\n"
        "    return (BASE / name).read_text(encoding='utf-8')\n"
    )
    out = _scan_one(tmp_path, "pt_pathlib_name_safe.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_string_replace_on_tainted_value_is_not_path_sink(tmp_path):
    code = "def f(raw):\n    return raw.replace('x', 'y')\n"
    out = _scan_one(tmp_path, "pt_string_replace_safe.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_path_like_global_shadowed_by_string_assignment(tmp_path):
    code = (
        "from pathlib import Path\n"
        "p = Path('/srv/uploads')\n"
        "def f(raw):\n"
        "    p = raw\n"
        "    return p.replace('x', 'y')\n"
    )
    out = _scan_one(tmp_path, "pt_path_like_shadow_assign.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_path_like_global_shadowed_by_parameter(tmp_path):
    code = (
        "from pathlib import Path\n"
        "p = Path('/srv/uploads')\n"
        "def f(p):\n"
        "    return p.replace('x', 'y')\n"
    )
    out = _scan_one(tmp_path, "pt_path_like_shadow_param.py", code)
    assert "SKY-D215" not in _rule_ids(out)
