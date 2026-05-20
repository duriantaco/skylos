import ast
from pathlib import Path
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.calls import DangerousCallsRule


def _write(tmp_path: Path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return p


def _rule_ids(findings):
    rule_ids = set()
    for f in findings:
        rule_ids.add(f["rule_id"])
    return rule_ids


def _scan_one(tmp_path: Path, name, code):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def _scan_dangerous_calls_rule(code):
    linter = LinterVisitor([DangerousCallsRule()], "rule_direct.py")
    linter.visit(ast.parse(code))
    return linter.findings


def test_eval(tmp_path):
    out = _scan_one(tmp_path, "a_eval.py", 'eval("1+1")\n')
    assert "SKY-D201" in _rule_ids(out)


def test_exec(tmp_path):
    out = _scan_one(tmp_path, "a_exec.py", 'exec("print(1)")\n')
    assert "SKY-D202" in _rule_ids(out)


def test_os_system(tmp_path):
    out = _scan_one(tmp_path, "a_os.py", "import os\nos.system('echo hi')\n")
    assert "SKY-D203" in _rule_ids(out)


def test_pickle_loads(tmp_path):
    out = _scan_one(
        tmp_path, "a_pickle.py", "import pickle\npickle.loads(b'\\x80\\x04K\\x01.')\n"
    )
    assert "SKY-D205" in _rule_ids(out)


def test_yaml_load_without_safeloader(tmp_path):
    out = _scan_one(tmp_path, "a_yaml.py", "import yaml\nyaml.load('a: 1')\n")
    assert "SKY-D206" in _rule_ids(out)


def test_md5_sha1(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_hashes.py",
        "import hashlib\nhashlib.md5(b'd')\nhashlib.sha1(b'd')\n",
    )
    ids = _rule_ids(out)
    assert "SKY-D207" in ids
    assert "SKY-D208" in ids


def test_subprocess_shell_true(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_subproc.py",
        "import subprocess\nsubprocess.run('echo hi', shell=True)\n",
    )
    assert "SKY-D209" in _rule_ids(out)


def test_requests_verify_false(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_requests.py",
        "import requests\nrequests.get('https://x', verify=False)\n",
    )
    assert "SKY-D210" in _rule_ids(out)


def test_symlink_following_write_flags_attacker_controlled_output(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_symlink_write.py",
        """
from pathlib import Path

def save(raw_path, data):
    out = Path(raw_path)
    out.write_text(data, encoding="utf-8")
""",
    )
    assert "SKY-D324" in _rule_ids(out)


def test_symlink_following_read_flags_attacker_controlled_history(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_symlink_read.py",
        """
def show_history(project_root):
    path = project_root / ".skylos" / "debt_history.jsonl"
    return path.read_text(encoding="utf-8")
""",
    )
    assert "SKY-D325" in _rule_ids(out)


def test_basename_only_sidecar_still_flags_symlink_read(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_sidecar.py",
        """
from pathlib import Path

def load_sidecar(raw_path):
    safe_name = Path(raw_path).name
    return Path(safe_name).read_text(encoding="utf-8")
""",
    )
    assert "SKY-D325" in _rule_ids(out)


def test_bounded_nofollow_read_is_not_symlink_finding(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_safe_read.py",
        """
import os
import stat

MAX_BYTES = 4096

def load(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("not a regular file")
        if file_stat.st_size > MAX_BYTES:
            raise ValueError("too large")
        with os.fdopen(fd, "rb") as handle:
            return handle.read(MAX_BYTES)
    finally:
        os.close(fd)
""",
    )
    assert "SKY-D324" not in _rule_ids(out)
    assert "SKY-D325" not in _rule_ids(out)


def test_unsafe_archive_extractall_flags(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_archive.py",
        """
import tarfile

def unpack(archive_path, dest):
    with tarfile.open(archive_path) as archive:
        archive.extractall(dest)
""",
    )
    assert "SKY-D326" in _rule_ids(out)


def test_archive_member_validation_suppresses_extractall_finding(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_safe_archive.py",
        """
import tarfile
from pathlib import Path

def unpack(archive_path, dest):
    with tarfile.open(archive_path) as archive:
        for member in archive.getmembers():
            member_path = Path(member.name)
            if member.issym() or member.islnk() or member_path.is_absolute():
                raise ValueError("unsafe archive member")
            if ".." in member_path.parts:
                raise ValueError("unsafe archive member")
        archive.extractall(dest)
""",
    )
    assert "SKY-D326" not in _rule_ids(out)


def test_random_random_flags_weak_security_random(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_random.py",
        "import random\ndef weak_token():\n    return str(random.random())\n",
    )
    assert "SKY-D250" in _rule_ids(out)


def test_secrets_token_urlsafe_is_not_weak_random(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_secrets.py",
        "import secrets\ndef strong_token():\n    return secrets.token_urlsafe(16)\n",
    )
    assert "SKY-D250" not in _rule_ids(out)


def test_random_choice_for_non_security_value_is_not_weak_random(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_random_color.py",
        "import random\ndef pick_color():\n    return random.choice(['red', 'blue'])\n",
    )
    assert "SKY-D250" not in _rule_ids(out)


def test_random_in_author_named_function_is_not_weak_random(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_random_author.py",
        "import random\ndef build_author_slug():\n    return str(random.random())\n",
    )
    assert "SKY-D250" not in _rule_ids(out)


def test_subprocess_alias_shell_true_flags(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_subproc_alias.py",
        "import subprocess as sp\nsp.run('echo hi', shell=True)\n",
    )
    assert "SKY-D209" in _rule_ids(out)


def test_subprocess_imported_run_shell_true_flags(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_subproc_from.py",
        "from subprocess import run\nrun('echo hi', shell=True)\n",
    )
    assert "SKY-D209" in _rule_ids(out)


def test_requests_session_verify_false_flags(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_requests_session.py",
        "import requests\nrequests.Session().get('https://x', verify=False)\n",
    )
    assert "SKY-D210" in _rule_ids(out)


def test_requests_assigned_session_verify_false_flags(tmp_path):
    out = _scan_one(
        tmp_path,
        "a_requests_assigned_session.py",
        "import requests\ns = requests.Session()\ns.get('https://x', verify=False)\n",
    )
    assert "SKY-D210" in _rule_ids(out)


def test_dangerous_calls_rule_resolves_alias_and_assigned_session():
    findings = _scan_dangerous_calls_rule(
        "import subprocess as sp\n"
        "from subprocess import run\n"
        "import requests\n"
        "sp.run('echo hi', shell=True)\n"
        "run('echo hi', shell=True)\n"
        "s = requests.Session()\n"
        "s.get('https://x', verify=False)\n"
    )
    ids = _rule_ids(findings)
    assert "SKY-D209" in ids
    assert "SKY-D210" in ids


def test_assigned_session_does_not_leak_across_functions(tmp_path):
    code = (
        "import requests\n"
        "def build():\n"
        "    s = requests.Session()\n"
        "    return s\n"
        "def use(s):\n"
        "    s.get('https://x', verify=False)\n"
    )
    out = _scan_one(tmp_path, "requests_session_scope.py", code)
    assert "SKY-D210" not in _rule_ids(out)


def test_yaml_safe_loader_does_not_trigger(tmp_path):
    code = (
        "import yaml\n"
        "from yaml import SafeLoader\n"
        "yaml.load('a: 1', Loader=SafeLoader)\n"
    )
    out = _scan_one(tmp_path, "b_yaml_safe.py", code)
    assert "SKY-D206" not in _rule_ids(out)


def test_yaml_positional_safe_loader_does_not_trigger(tmp_path):
    code = "import yaml\nyaml.load('a: 1', yaml.SafeLoader)\n"
    out = _scan_one(tmp_path, "b_yaml_safe_positional.py", code)
    assert "SKY-D206" not in _rule_ids(out)


def test_subprocess_without_shell_true_is_ok(tmp_path):
    code = "import subprocess\nsubprocess.run(['echo','hi'])\n"
    out = _scan_one(tmp_path, "b_subproc_ok.py", code)
    assert "SKY-D209" not in _rule_ids(out)


def test_requests_default_verify_true_is_ok(tmp_path):
    code = "import requests\nrequests.get('https://example.com')\n"
    out = _scan_one(tmp_path, "b_requests_ok.py", code)
    assert "SKY-D210" not in _rule_ids(out)


def test_sql_execute_interpolated_flags(tmp_path):
    code = """
def f(cur, name):
    # f-string interpolation -> should flag SKY-D211
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
"""
    out = _scan_one(tmp_path, "sql_interp.py", code)
    assert "SKY-D211" in _rule_ids(out)


def test_sql_execute_parameterized_ok(tmp_path):
    code = """
def f(cur, name):
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
"""
    out = _scan_one(tmp_path, "sql_param_ok.py", code)
    assert "SKY-D211" not in _rule_ids(out)


def test_sql_execute_tainted_query_with_params_flags(tmp_path):
    code = """
def f(cur, query, params):
    cur.execute(query, params)
"""
    out = _scan_one(tmp_path, "sql_tainted_query_params.py", code)
    assert "SKY-D211" in _rule_ids(out)


def test_sql_execute_neutral_connection_alias_flags(tmp_path):
    code = """
import sqlite3

def f(name):
    c = sqlite3.connect(":memory:")
    c.execute(f"SELECT * FROM users WHERE name = '{name}'")
"""
    out = _scan_one(tmp_path, "sql_connection_alias.py", code)
    assert "SKY-D211" in _rule_ids(out)


def test_unrelated_execute_receiver_is_not_db(tmp_path):
    code = """
def f(name):
    c = object()
    c.execute(f"SELECT * FROM users WHERE name = '{name}'")
"""
    out = _scan_one(tmp_path, "sql_unrelated_execute.py", code)
    assert "SKY-D211" not in _rule_ids(out)


def test_sql_execute_query_mutated_after_static_assignment_flags(tmp_path):
    code = """
def f(cur, request):
    query = "SELECT * FROM users WHERE id = "
    query += request.args["id"]
    cur.execute(query)
"""
    out = _scan_one(tmp_path, "sql_augassign_mutation.py", code)
    assert "SKY-D211" in _rule_ids(out)


def test_sql_execute_query_shadowing_outer_static_assignment_flags(tmp_path):
    code = """
query = "SELECT * FROM users"

def f(cur, request):
    query = request.args["query"]
    cur.execute(query)
"""
    out = _scan_one(tmp_path, "sql_shadowed_query.py", code)
    assert "SKY-D211" in _rule_ids(out)


def test_sql_execute_query_static_augassign_ok(tmp_path):
    code = """
def f(cur):
    query = "SELECT *"
    query += " FROM users"
    cur.execute(query)
"""
    out = _scan_one(tmp_path, "sql_static_augassign.py", code)
    assert "SKY-D211" not in _rule_ids(out)


def test_sql_constant_format_query_ok(tmp_path):
    code = """
def f(cur):
    cur.execute("SELECT * FROM users WHERE role = {}".format("admin"))
"""
    out = _scan_one(tmp_path, "sql_constant_format.py", code)
    assert "SKY-D211" not in _rule_ids(out)


def test_sql_executescript_or_executemany_interpolated_flags(tmp_path):
    code = """
def g(cur, tbl):
    cur.executescript("CREATE TABLE " + tbl)

def h(cur, values):
    cur.executemany("INSERT INTO t (a,b) VALUES (" + values + ")", [])
"""
    out = _scan_one(tmp_path, "sql_execscripts.py", code)
    ids = _rule_ids(out)
    assert "SKY-D211" in ids
