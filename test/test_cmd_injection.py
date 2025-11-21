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


def test_os_system_tainted_flags(tmp_path):
    code = "import os\ndef f(x):\n    os.system('echo ' + x)\n"
    out = _scan_one(tmp_path, "cmd_os.py", code)
    assert "SKY-D212" in _rule_ids(out)


def test_subprocess_shell_true_tainted_flags(tmp_path):
    code = (
        "import subprocess\n"
        "def f(cmd):\n"
        "    subprocess.run('sh -c ' + cmd, shell=True)\n"
    )
    out = _scan_one(tmp_path, "cmd_subp.py", code)
    assert "SKY-D212" in _rule_ids(out)


def test_os_system_constant_does_not_trigger_D212(tmp_path):
    code = "import os\ndef f():\n    os.system('echo hi')\n"
    out = _scan_one(tmp_path, "cmd_const.py", code)
    assert "SKY-D212" not in _rule_ids(out)
