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


def _d212_lines(findings):
    return sorted(f["line"] for f in findings if f["rule_id"] == "SKY-D212")


def test_shell_string_sinks_and_import_aliases_flag_d212(tmp_path):
    code = (
        "import asyncio, os, subprocess\n"
        "import subprocess as sp\n"
        "from os import system\n"
        "from subprocess import run as r\n"
        "def a(x):\n    return os.popen('ping ' + x).read()\n"
        "async def b(x):\n    return await asyncio.create_subprocess_shell(x)\n"
        "def c(x):\n    return subprocess.getoutput(f'grep {x} f')\n"
        "def d(x):\n    return sp.run(x, shell=True)\n"
        "def e(x):\n    system('echo ' + x)\n"
        "def g(x):\n    return r(f'tar xf {x}', shell=True)\n"
    )
    out = _scan_one(tmp_path, "cmd_shell_sinks.py", code)
    assert _d212_lines(out) == [6, 8, 10, 12, 14, 16]


def test_non_literal_shell_value_can_enable_the_shell(tmp_path):
    code = (
        "import subprocess, sys\n"
        "def a(cmd, use_shell):\n    return subprocess.run(cmd, shell=use_shell)\n"
        "def b(cmd):\n    return subprocess.run(cmd, shell=False)\n"
        "def c(path):\n    return subprocess.run(['ls', '-l', path])\n"
        "def d(use_shell):\n    return subprocess.run(['git', 'status'], shell=use_shell)\n"
    )
    out = _scan_one(tmp_path, "cmd_shell_flag.py", code)
    assert _d212_lines(out) == [3]


def test_exec_family_flags_tainted_program_or_shell_script(tmp_path):
    code = (
        "import os, pty, subprocess, sys\n"
        "def a(prog):\n    os.execvp(prog, [prog, '--help'])\n"
        "def b(script):\n    os.execl('/bin/sh', 'sh', '-c', script)\n"
        "def c(prog):\n    os.spawnlp(os.P_WAIT, prog, prog)\n"
        "def d(cmd):\n    pty.spawn(cmd)\n"
        "def e(script):\n    subprocess.run(['bash', '-c', script])\n"
        "def f():\n    os.execv(sys.executable, [sys.executable] + sys.argv)\n"
        "def g(target):\n    os.execlp('git', 'git', 'fetch', target)\n"
        "def h():\n    pty.spawn(['/bin/bash', '-l'])\n"
    )
    out = _scan_one(tmp_path, "cmd_exec_family.py", code)
    assert _d212_lines(out) == [3, 5, 7, 9, 11]


def test_local_function_named_like_a_command_sink_is_not_d212(tmp_path):
    code = (
        "def system(command):\n    return command.upper()\n"
        "def f(x):\n    return system('echo ' + x)\n"
    )
    out = _scan_one(tmp_path, "cmd_local_name.py", code)
    assert "SKY-D212" not in _rule_ids(out)


def test_new_shell_sinks_report_d203_or_d209_patterns(tmp_path):
    code = (
        "import asyncio, os, subprocess\n"
        "def a(x):\n    return os.popen('cat ' + x).read()\n"
        "def b():\n    return os.popen('uptime').read()\n"
        "def c():\n    return subprocess.getoutput('uname -a')\n"
        "async def d(x):\n    return await asyncio.create_subprocess_shell(x)\n"
    )
    out = _scan_one(tmp_path, "cmd_patterns.py", code)
    found = {(f["rule_id"], f["line"], f["severity"]) for f in out}
    assert ("SKY-D203", 3, "CRITICAL") in found
    assert ("SKY-D203", 5, "LOW") in found
    assert ("SKY-D209", 7, "LOW") in found
    assert ("SKY-D209", 9, "HIGH") in found
