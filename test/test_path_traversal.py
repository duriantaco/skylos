from pathlib import Path

import pytest

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


def test_shutil_rmtree_keyword_path_matches_positional_sink(tmp_path):
    code = """
import shutil
from pathlib import Path

def positional_argument(destination: str) -> None:
    destination_path = Path(destination)
    shutil.rmtree(destination_path)

def keyword_argument(destination: str) -> None:
    destination_path = Path(destination)
    shutil.rmtree(path=destination_path)
"""

    out = _scan_one(tmp_path, "pt_rmtree_keyword.py", code)
    symbols = {
        finding["symbol"]
        for finding in out
        if finding.get("rule_id") == "SKY-D215"
    }

    assert {"positional_argument", "keyword_argument"} <= symbols


@pytest.mark.parametrize(
    "call",
    [
        "open(file=path, mode='r')",
        "os.open(path=path, flags=os.O_RDONLY)",
        "os.unlink(path=path)",
        "os.remove(path=path)",
        "os.mkdir(path=path)",
        "os.rmdir(path=path)",
        "os.makedirs(name=path)",
        "shutil.copy(src=path, dst='fixed')",
        "shutil.copy2(src=path, dst='fixed')",
        "shutil.copytree(src=path, dst='fixed')",
        "shutil.move(src=path, dst='fixed')",
        "shutil.rmtree(path=path)",
    ],
)
def test_keyword_bound_first_path_argument_flags(tmp_path, call):
    code = f"""
import os
import shutil

def vulnerable(path):
    {call}
"""

    out = _scan_one(tmp_path, "pt_keyword_path.py", code)

    assert "SKY-D215" in _rule_ids(out)


def test_os_open_keyword_flags_preserve_symlink_write_classification(tmp_path):
    code = """
import os

def vulnerable(path):
    os.open(path=path, flags=os.O_WRONLY)
"""

    out = _scan_one(tmp_path, "pt_os_open_keyword_flags.py", code)
    rule_ids = _rule_ids(out)

    assert "SKY-D215" in rule_ids
    assert "SKY-D324" in rule_ids
    assert "SKY-D325" not in rule_ids


def test_tainted_non_path_keyword_does_not_flag_literal_rmtree_path(tmp_path):
    code = """
import shutil

def cleanup(onerror):
    shutil.rmtree(path="/srv/cache", onerror=onerror)
"""

    out = _scan_one(tmp_path, "pt_rmtree_non_path_keyword.py", code)

    assert "SKY-D215" not in _rule_ids(out)


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
