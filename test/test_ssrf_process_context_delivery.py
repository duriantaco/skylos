"""SSRF process controls: fixture programs are parsed, never executed."""

import ast

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.danger_fs import path_provenance
from skylos.rules.danger.danger_net import ssrf_flow


def _scan(tmp_path, worker, launcher="", *, extra=None):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="url-context"\n')
    files = []
    sources = {"worker.py": worker, **(extra or {})}
    if launcher:
        sources["z_routes.py"] = launcher
    for name, source in sources.items():
        path = tmp_path / name
        path.write_text(source)
        files.append(path)
    return [
        row
        for row in scan_ctx(tmp_path, files)
        if row["rule_id"] == "SKY-D216" and row["file"] == str(tmp_path / "worker.py")
    ]


def _worker(operand, setup=""):
    return (
        "import sys, os, requests, foreign\n"
        + setup
        + "def fetch():\n    return requests.get("
        + operand
        + ", timeout=5)\nfetch()\n"
    )


def _launcher(tmp_path, argv, options="", setup=""):
    return (
        "import subprocess, sys, foreign\nfrom fastapi import FastAPI\napp=FastAPI()\n"
        + setup
        + "@app.post('/fetch')\ndef web_fetch(url: str):\n    return subprocess.run("
        + argv
        + ", cwd="
        + repr(str(tmp_path))
        + options
        + ")\n"
    )


@pytest.mark.parametrize("operand", ["sys.argv[1]", "os.environ['FETCH_URL']"])
def test_unrelated_launched_program_does_not_taint_this_worker(tmp_path, operand):
    rows = _scan(
        tmp_path,
        _worker(operand),
        _launcher(tmp_path, "[sys.executable, 'other.py', url]"),
        extra={"other.py": "import sys\nprint(sys.argv[1])\n"},
    )
    assert rows == []


@pytest.mark.parametrize(
    "setup", ["sys.argv[1]=foreign.url\n", "os.environ['FETCH_URL']=foreign.url\n"]
)
def test_changed_worker_input_provider_does_not_prove_operator_origin(tmp_path, setup):
    operand = "sys.argv[1]" if setup.startswith("sys") else "os.environ['FETCH_URL']"
    rows = _scan(tmp_path, _worker(operand, setup))
    assert rows and rows[0]["severity"] == "CRITICAL"
    assert rows[0]["metadata"]["process_context"]["status"] in {
        "unknown",
        "untrusted",
        "incomplete",
    }


@pytest.mark.parametrize("control", ["provider", "unpacked"])
def test_uncertain_launch_contract_keeps_the_url_review_visible(tmp_path, control):
    setup = "subprocess.run=foreign.launch\n" if control == "provider" else ""
    options = ", **foreign.options" if control == "unpacked" else ""
    rows = _scan(
        tmp_path,
        _worker("sys.argv[1]"),
        _launcher(
            tmp_path,
            "[sys.executable, 'worker.py', 'https://fixed.example/']",
            options,
            setup,
        ),
    )
    assert rows
    assert rows[0]["metadata"]["process_context"]["status"] in {"unknown", "incomplete"}
    assert rows[0]["message"].startswith("Needs review:")
    assert (
        "not established"
        in rows[0]["metadata"]["security_evidence"]["confidence_reason"]
    )


def test_process_resolution_limit_cannot_restore_operator_suppression(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(path_provenance, "_MAX_RESOLUTION_WORK", 0)
    rows = _scan(tmp_path, _worker("sys.argv[1]"))
    assert rows and rows[0]["metadata"]["process_context"]["status"] == "incomplete"


def test_missing_complete_project_context_is_visible_not_operator_proof(tmp_path):
    text = _worker("sys.argv[1]")
    filename = tmp_path / "worker.py"
    filename.write_text(text)
    rows = []
    ssrf_flow.scan(ast.parse(text), filename, rows)
    assert rows and rows[0]["metadata"]["process_context"]["status"] == "incomplete"


def test_subtree_below_a_repository_marker_cannot_exclude_outside_launchers(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="outer"\n')
    inner = tmp_path / "inner"
    inner.mkdir()
    path = inner / "worker.py"
    path.write_text(_worker("sys.argv[1]"))
    rows = [row for row in scan_ctx(inner, [path]) if row["rule_id"] == "SKY-D216"]
    assert rows and rows[0]["metadata"]["process_context"]["status"] == "incomplete"


def test_path_shape_safe_facts_are_not_operator_source_authority(tmp_path):
    rows = _scan(
        tmp_path,
        _worker(
            "'https://' + hashlib.sha256(sys.argv[1].encode()).hexdigest()",
            "import hashlib\n",
        ),
    )
    assert rows and rows[0]["metadata"]["process_context"]["status"] == "unknown"
    assert any(
        "structured operator origin" in step
        for chain in rows[0]["metadata"]["process_context"]["unknown"]
        for step in chain
    )


def test_forwarded_argv_evidence_names_its_actual_route_origin(tmp_path):
    rows = _scan(
        tmp_path,
        _worker("sys.argv[1]"),
        _launcher(tmp_path, "[sys.executable, 'worker.py', url]"),
    )
    assert rows and rows[0]["metadata"]["process_context"]["status"] == "untrusted"
    assert "web_fetch" in rows[0]["metadata"]["untrusted_source"]
    assert any(
        "process launch" in step
        for step in rows[0]["metadata"]["security_evidence"]["path"]
    )


def test_operator_component_cannot_authorize_a_path_safe_hash_component(tmp_path):
    rows = _scan(
        tmp_path,
        _worker(
            "sys.argv[1] + hashlib.sha256(foreign.value).hexdigest()",
            "import hashlib\n",
        ),
    )
    assert rows and rows[0]["metadata"]["process_context"]["status"] == "unknown"
    assert rows[0]["metadata"]["process_context"]["operator"]
    assert any(
        "path-safe value producer" in step
        for chain in rows[0]["metadata"]["process_context"]["unknown"]
        for step in chain
    )


@pytest.mark.parametrize("setting", ["sys.argv[1]", "os.getenv('FETCH_URL')"])
@pytest.mark.parametrize("operand", ["BASE", "f'{BASE}/health'", "build()"])
@pytest.mark.parametrize("forwarded", [False, True])
def test_module_host_setting_has_worker_process_origin(
    tmp_path, setting, operand, forwarded
):
    worker = _worker(
        operand, f"BASE={setting}\n" + "def build():\n    return f'{BASE}/health'\n"
    )
    launcher = ""
    if forwarded:
        if setting.startswith("sys"):
            launcher = _launcher(tmp_path, "[sys.executable, 'worker.py', url]")
        else:
            launcher = _launcher(
                tmp_path, "[sys.executable, 'worker.py']", ", env={'FETCH_URL': url}"
            )
    rows = _scan(tmp_path, worker, launcher)
    assert bool(rows) is forwarded
    if forwarded:
        assert rows[0]["metadata"]["process_context"]["status"] in {
            "untrusted",
            "unknown",
        }


def test_fixed_module_host_ignores_remote_path_component(tmp_path):
    worker = _worker(
        "f'{BASE}/path/{PART}'", "BASE='https://fixed.example'\nPART=sys.argv[1]\n"
    )
    assert not _scan(
        tmp_path, worker, _launcher(tmp_path, "[sys.executable, 'worker.py', url]")
    )


def test_reflective_module_access_keeps_process_provider_review(tmp_path):
    worker = _worker(
        "f'{BASE}/health'",
        "BASE=os.getenv('URL')\nHAS=hasattr(sys.modules[__name__], 'X')\n",
    )
    rows = _scan(tmp_path, worker)
    assert rows and rows[0]["metadata"]["process_context"]["status"] == "unknown"


def test_bounded_module_host_tracing_keeps_review(tmp_path):
    source = "VALUE0=os.getenv('URL')\n" + "".join(
        f"VALUE{i}=VALUE{i - 1}\n" for i in range(1, 300)
    )
    rows = _scan(tmp_path, _worker("VALUE299", source))
    assert rows and rows[0]["metadata"]["process_context"]["status"] == "incomplete"
