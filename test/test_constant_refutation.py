"""Constant-argument refutation post-pass for Python danger findings.

Engine cases come from the research technique ``sec_sccp_fx`` (reviewer and
red-team twins, the red-team battery, the fix-round variants, the
cross-certified ``cpm_sec`` battery, the revision-7 twins and the probe twins),
exported to ``fixtures/constant_refutation/cases.json``. Twin sources are
written to ``tmp_path`` and only parsed, never imported or executed.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.constant_refutation import (
    _FRAME_ACCESS,
    ENV_VAR,
    REASON_PREFIX,
    refutation_enabled,
    refute_constant_argument_findings,
)
from skylos.rules.danger.constant_refutation import engine as E

# Scope limits of the pipeline wrapper (see the package docstring).
WRAPPER_KEEPS_MECHANISMS = {"F0", "S2b-pyyaml"}
WRAPPER_KEEPS_RULES = {"SKY-D326"}

CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "constant_refutation" / "cases.json").read_text(
        encoding="utf-8"
    )
)


def _materialise(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _absolute(findings, root: Path):
    return [{**f, "file": str(root / f["file"])} for f in findings]


def _run(root: Path, findings):
    suppressed = []
    kept = refute_constant_argument_findings(
        findings, project_root=root, suppressed=suppressed
    )
    return kept, suppressed


def _key(f, root: Path):
    rel = Path(f["file"]).relative_to(root).as_posix()
    return f"{f['rule_id']}@{rel}:{f['line']}"


@pytest.mark.parametrize("case", sorted(CASES["twins"]))
def test_reviewer_and_redteam_twins(tmp_path, case):
    spec = CASES["twins"][case]
    root = _materialise(tmp_path / case, spec["files"])
    findings = _absolute(spec["findings"], root)
    # The vendored engine matches the research technique's expectations exactly.
    engine_kept, log = E.refute(findings, root)
    assert not [entry for entry in log if "error" in entry]
    engine_keys = {_key(f, root) for f in engine_kept}
    drops = set(spec["drops"])
    for f in findings:
        key = _key(f, root)
        assert (key not in engine_keys) == (key in drops), f"engine: {key}"

    # The pipeline wrapper drops exactly the engine drops its scope limits allow.
    mechanisms = {
        f"{e['rule_id']}@{e['file']}:{e['line']}": e["mechanism"] for e in log if e.get("drop")
    }
    inspects_frames = any(_FRAME_ACCESS.search(text) for text in spec["files"].values())
    expected = set()
    for f in findings:
        key = _key(f, root)
        tagged = (f.get("low_risk_context") or {}).get("reason") in E.F0_REASONS
        if (
            key in mechanisms
            and mechanisms[key] not in WRAPPER_KEEPS_MECHANISMS
            and f["rule_id"] not in WRAPPER_KEEPS_RULES
            and not tagged
            and not inspects_frames
        ):
            expected.add(key)
    kept, suppressed = _run(root, findings)
    kept_keys = {_key(f, root) for f in kept}
    for f in findings:
        key = _key(f, root)
        assert (key not in kept_keys) == (key in expected), f"wrapper: {key}"
    assert len(kept) + len(suppressed) == len(findings)
    for record in suppressed:
        assert record["category"] == "danger"
        assert record["reason"].startswith(REASON_PREFIX + ": ")
        assert record["refutation"]["mechanism"]


BATTERY_SIZES = {"redteam": 39, "fixround": 10, "cpm_sec": 49}


@pytest.mark.parametrize("group", sorted(BATTERY_SIZES))
def test_batteries_lose_no_vulnerable_call(tmp_path, group):
    lost, vulnerable = [], 0
    for name, spec in sorted(CASES["batteries"][group].items()):
        root = _materialise(tmp_path / name, spec["files"])
        findings = _absolute(spec["findings"], root)
        kept, _ = _run(root, findings)
        kept_keys = {(f["rule_id"], f["file"], int(f["line"])) for f in kept}
        for call in spec["calls"]:
            if call["verdict"] != "VULNERABLE":
                continue
            vulnerable += 1
            path = str(root / call["file"])
            rules = {
                f["rule_id"]
                for f in findings
                if f["file"] == path
                and int(f["line"]) == call["line"]
                and int(f.get("col") or 0) == call["col"]
            }
            if not any((rule, path, call["line"]) in kept_keys for rule in rules):
                lost.append((name, call["file"], call["line"], call["col"]))
    assert vulnerable == BATTERY_SIZES[group]
    assert lost == []


def _marked_findings(root: Path, rule: str, files: dict):
    findings, marks = [], {}
    for rel, text in files.items():
        for lineno, line in enumerate(text.splitlines(), start=1):
            for mark in ("KEEP", "DROP"):
                if line.rstrip().endswith("# " + mark):
                    findings.append(
                        {"rule_id": rule, "file": str(root / rel), "line": lineno}
                    )
                    marks[(str(root / rel), lineno)] = mark
    return findings, marks


@pytest.mark.parametrize("index", range(len(CASES["rev7"])))
def test_revision_seven_twins(tmp_path, index):
    spec = CASES["rev7"][index]
    root = _materialise(tmp_path / "proj", spec["files"])
    findings, marks = _marked_findings(root, spec["rule"], spec["files"])
    assert marks
    kept, _ = _run(root, findings)
    kept_keys = {(f["file"], f["line"]) for f in kept}
    for key, mark in sorted(marks.items()):
        assert (key in kept_keys) == (mark == "KEEP"), (spec["name"], key, mark)


def test_probe_twin_battery(tmp_path):
    probe = CASES["probe"]
    _materialise(
        tmp_path,
        {"pkg/__init__.py": "", "pkg/helpers.py": probe["helpers"], "pkg/other.py": probe["other"]},
    )
    findings, expect = [], {}
    for i, case in enumerate(probe["cases"]):
        body = textwrap.indent(textwrap.dedent(case["body"]).strip("\n"), "    ")
        src = probe["header"] + "\n\ndef view():\n" + body + "\n"
        path = tmp_path / f"case_{i:02d}.py"
        path.write_text(src, encoding="utf-8")
        line = next(
            j + 1 for j, ln in enumerate(src.splitlines()) if ln.rstrip().endswith("# SINK")
        )
        findings.append({"rule_id": case["rule"], "file": str(path), "line": line})
        expect[(str(path), line)] = (case["name"], case["drop"])
    kept, _ = _run(tmp_path, findings)
    kept_keys = {(f["file"], f["line"]) for f in kept}
    for key, (name, drop) in sorted(expect.items()):
        assert (key not in kept_keys) == drop, name


def test_fail_closed_and_out_of_scope(tmp_path):
    (tmp_path / "bad.py").write_text("def f(:\n    eval('1')\n")
    (tmp_path / "a.py").write_text(
        "import random, hashlib\nx = random.random()\nh = hashlib.md5(b'k')\n"
    )
    findings = [
        {"rule_id": "SKY-D201", "file": str(tmp_path / "bad.py"), "line": 2},
        {"rule_id": "SKY-D201", "file": str(tmp_path / "gone.py"), "line": 1},
        {"rule_id": "SKY-D292", "file": str(tmp_path / "ci.yml"), "line": 3},
        {"rule_id": "SKY-D250", "file": str(tmp_path / "a.py"), "line": 2,
         "low_risk_context": {"reason": "constant-argument"}},
        {"rule_id": "SKY-D207", "file": str(tmp_path / "a.py"), "line": 3,
         "low_risk_context": {"reason": "non-sensitive-hash-input"}},
    ]
    kept, suppressed = _run(tmp_path, findings)
    assert kept == findings
    assert suppressed == []


@pytest.mark.parametrize(
    ("value", "enabled"),
    [(None, True), ("1", True), ("yes", True), ("0", False), ("false", False),
     ("No", False), (" off ", False)],
)
def test_refutation_enabled_values(value, enabled):
    env = {} if value is None else {ENV_VAR: value}
    assert refutation_enabled(env) is enabled


APP = '''\
import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/find")
def find():
    name = request.args.get("name", "")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return "ok"


@app.route("/uptime")
def uptime():
    os.system("uptime")
    return "ok"


@app.route("/docs")
def docs():
    os.system("make docs")
    return "ok"


@app.route("/list")
def listing():
    limit = int(request.args.get("limit", "10"))
    cur = sqlite3.connect("app.db").cursor()
    order = "id"
    if request.args.get("desc"):
        order = "id DESC"
    cur.execute("SELECT id FROM t ORDER BY " + order + " LIMIT %d" % limit)
    return "ok"


@app.route("/mode")
def mode():
    cmd = request.args.get("cmd", "")
    mode = "safe"
    if mode == "safe":
        cmd = "ls -la /tmp"
    subprocess.run(cmd, shell=True)
    return "ok"


@app.route("/home")
def home():
    command = "echo $HOME"
    subprocess.run(command, shell=True)
    return "ok"
'''

TAINTED = {("SKY-D203", 13), ("SKY-D212", 13), ("SKY-D211", 21)}
REFUTED = {("SKY-D211", 44), ("SKY-D209", 54), ("SKY-D212", 54)}
# Literal commands Skylos already marks low-risk (kept raw, hidden by default,
# counted by the gate) are left to that policy; `$HOME` expands the
# environment, so it is never proved closed.
SKYLOS_DEMOTED = {("SKY-D203", 27), ("SKY-D203", 33)}
CONSTANT_KEPT = SKYLOS_DEMOTED | {("SKY-D209", 61)}


def _scan(root: Path):
    result = json.loads(analyze(str(root), enable_danger=True, grep_verify=False))
    listed = {(f["rule_id"], f["line"]) for f in result.get("danger", [])}
    refuted = {
        (f["rule_id"], f["line"]): f
        for f in result.get("suppressed", [])
        if str(f.get("reason", "")).startswith(REASON_PREFIX)
    }
    return result, listed, refuted


@pytest.fixture
def app_root(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'sample'\n")
    (tmp_path / "app.py").write_text(APP)
    return tmp_path


def test_scan_keeps_tainted_and_drops_constant_findings(app_root, monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    result, listed, refuted = _scan(app_root)
    assert TAINTED <= listed
    assert CONSTANT_KEPT <= listed
    assert not (REFUTED & listed)
    assert set(refuted) == REFUTED
    demoted = {
        (f["rule_id"], f["line"])
        for f in result["danger"]
        if (f.get("low_risk_context") or {}).get("reason") == "constant-shell-command"
    }
    assert SKYLOS_DEMOTED <= demoted
    for record in refuted.values():
        assert record["category"] == "danger"
        assert record["reason"] == f"{REASON_PREFIX}: {record['refutation']['mechanism']}"


def test_scan_is_deterministic(app_root, monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    first, _, _ = _scan(app_root)
    second, _, _ = _scan(app_root)
    for key in ("danger", "suppressed"):
        assert json.dumps(first.get(key), sort_keys=True) == json.dumps(
            second.get(key), sort_keys=True
        )


def test_scan_opt_out_lists_every_finding(app_root, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "0")
    _, listed, refuted = _scan(app_root)
    assert refuted == {}
    assert TAINTED | REFUTED | CONSTANT_KEPT <= listed


_HASH_SEED_SCRIPT = r"""
import json, sys
from pathlib import Path
from skylos.rules.danger.constant_refutation import refute_constant_argument_findings
cases = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
out = {}
for name in sorted(cases):
    root = Path(sys.argv[2]) / name
    findings = [{**f, "file": str(root / f["file"])} for f in cases[name]["findings"]]
    suppressed = []
    kept = refute_constant_argument_findings(findings, project_root=root, suppressed=suppressed)
    out[name] = [[f["rule_id"], f["line"]] for f in kept] + [
        [s["rule_id"], s["line"], s["reason"], s["refutation"]] for s in suppressed]
sys.stdout.write(json.dumps(out, sort_keys=True))
"""


def test_output_identical_across_hash_seeds(tmp_path):
    twins = CASES["twins"]
    for name, spec in twins.items():
        _materialise(tmp_path / "src" / name, spec["files"])
    cases_file = tmp_path / "twins.json"
    cases_file.write_text(json.dumps(twins), encoding="utf-8")
    script = tmp_path / "run_seed.py"
    script.write_text(_HASH_SEED_SCRIPT, encoding="utf-8")
    repo_root = str(Path(__file__).resolve().parent.parent)
    outputs = []
    for seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": repo_root}
        env.pop(ENV_VAR, None)
        proc = subprocess.run(
            [sys.executable, "-B", str(script), str(cases_file), str(tmp_path / "src")],
            capture_output=True, text=True, env=env, cwd=str(tmp_path), check=True,
        )
        outputs.append(proc.stdout)
    assert outputs[0] == outputs[1] == outputs[2]
    assert any(json.loads(outputs[0]).values())


def test_frame_inspection_turns_the_pass_off(app_root, monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    (app_root / "debug.py").write_text(
        "import sys\n\n\ndef caller_frame():\n    return sys._getframe(1)\n"
    )
    _, listed, refuted = _scan(app_root)
    assert refuted == {}
    assert TAINTED | REFUTED | CONSTANT_KEPT <= listed


def test_archive_extraction_of_an_upload_is_never_refuted(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'sample'\n")
    (tmp_path / "app.py").write_text(
        "import shutil\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.post('/unpack')\n"
        "def upload():\n"
        "    request.files['archive'].save('/tmp/upload.zip')\n"
        "    shutil.unpack_archive('/tmp/upload.zip', '/srv/uploads')\n"
    )
    _, listed, refuted = _scan(tmp_path)
    assert ("SKY-D326", 7) in listed
    assert refuted == {}


def test_files_with_many_findings_are_left_alone(tmp_path):
    lines = "".join(f"    os.system('uptime {i}')\n" for i in range(51))
    (tmp_path / "many.py").write_text("import os\n\n\ndef run():\n" + lines)
    findings = [
        {"rule_id": "SKY-D203", "file": str(tmp_path / "many.py"), "line": 5 + i, "col": 4}
        for i in range(51)
    ]
    kept, suppressed = _run(tmp_path, findings)
    assert kept == findings and suppressed == []
    kept, suppressed = _run(tmp_path, findings[:50])
    assert len(suppressed) == 50
