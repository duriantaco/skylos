from pathlib import Path
from skylos.rules.dangerous import scan_ctx

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
    out = _scan_one(tmp_path, "a_pickle.py", "import pickle\npickle.loads(b'\\x80\\x04K\\x01.')\n")
    assert "SKY-D205" in _rule_ids(out)

def test_yaml_load_without_safeloader(tmp_path):
    out = _scan_one(tmp_path, "a_yaml.py", "import yaml\nyaml.load('a: 1')\n")
    assert "SKY-D206" in _rule_ids(out)

def test_md5_sha1(tmp_path):
    out = _scan_one(tmp_path, "a_hashes.py", "import hashlib\nhashlib.md5(b'd')\nhashlib.sha1(b'd')\n")
    ids = _rule_ids(out)
    assert "SKY-D207" in ids
    assert "SKY-D208" in ids

def test_subprocess_shell_true(tmp_path):
    out = _scan_one(tmp_path, "a_subproc.py", "import subprocess\nsubprocess.run('echo hi', shell=True)\n")
    assert "SKY-D209" in _rule_ids(out)

def test_requests_verify_false(tmp_path):
    out = _scan_one(tmp_path, "a_requests.py", "import requests\nrequests.get('https://x', verify=False)\n")
    assert "SKY-D210" in _rule_ids(out)

def test_yaml_safe_loader_does_not_trigger(tmp_path):
    code = (
        "import yaml\n"
        "from yaml import SafeLoader\n"
        "yaml.load('a: 1', Loader=SafeLoader)\n"
    )
    out = _scan_one(tmp_path, "b_yaml_safe.py", code)
    assert "SKY-D206" not in _rule_ids(out)

def test_subprocess_without_shell_true_is_ok(tmp_path):
    code = "import subprocess\nsubprocess.run(['echo','hi'])\n"
    out = _scan_one(tmp_path, "b_subproc_ok.py", code)
    assert "SKY-D209" not in _rule_ids(out)

def test_requests_default_verify_true_is_ok(tmp_path):
    code = "import requests\nrequests.get('https://example.com')\n"
    out = _scan_one(tmp_path, "b_requests_ok.py", code)
    assert "SKY-D210" not in _rule_ids(out)
