"""Run-time dispatch in a separate program does not hide a filename proof."""

import ast
from pathlib import Path

import pytest

from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.rules.danger.danger_fs.path_provenance import (
    resolve_helper_parameter_findings,
)


APP = """import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from storage import load, save

ROOT = os.environ.get("RUNS_DIR", "/srv/runs")
app = FastAPI(title="runs")


class ReplayRequest(BaseModel):
    name: str = Field(min_length=1, max_length=96)


def clean(raw: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in raw)
    return cleaned or "run"


def checked_dir(raw: str) -> str:
    safe = clean(raw)
    if safe != raw:
        raise HTTPException(status_code=400, detail="invalid name")
    return os.path.join(ROOT, raw)


@app.get("/runs/{name}")
def view(name: str):
    path = os.path.join(checked_dir(name), "manifest.json")
    save(path)
    return load(path)


@app.post("/replay")
def replay(payload: ReplayRequest):
    path = os.path.join(ROOT, clean(payload.name.strip()), "replay.json")
    save(path)
    return load(path)
"""
STORAGE = """def load(path):
    with open(path, "r") as stream:
        return stream.read()


def save(path):
    with open(path, "w") as stream:
        stream.write("record")
"""
RUNNER = """import sys
from pathlib import Path


def main():
    source = Path(sys.argv[1]).read_text()
    namespace = {}
    exec(compile(source, "candidate", "exec"), namespace)


if __name__ == "__main__":
    main()
"""


def _resolve(tmp_path, extra):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="dispatch-proof"\n')
    files = {"app.py": APP, "storage.py": STORAGE, **extra}
    findings = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        scan(ast.parse(text), path, findings)
    suppressed = []
    kept = resolve_helper_parameter_findings(
        findings, scan_path=tmp_path, project_root=tmp_path, suppressed=suppressed
    )
    traversal = [
        (Path(f["file"]).name, f["line"], f["metadata"]["path_provenance"]["status"])
        for f in kept
        if f["rule_id"] == "SKY-D215"
    ]
    statuses = sorted(
        f["metadata"]["path_provenance"]["status"]
        for f in suppressed
        if f["rule_id"] == "SKY-D215"
    )
    return traversal, statuses, suppressed


def test_dispatch_in_a_separate_program_leaves_the_proof_unknown_not_untrusted(
    tmp_path,
):
    traversal, statuses, suppressed = _resolve(tmp_path, {"tools/runner.py": RUNNER})
    assert traversal == []
    assert statuses == ["unknown", "unknown"]
    chains = [
        chain[0]
        for row in suppressed
        if row["rule_id"] == "SKY-D215"
        for chain in row["metadata"]["path_provenance"]["unknown"]
    ]
    assert any("picks its target at run time" in step for step in chains)


@pytest.mark.parametrize(
    "extra",
    [
        {"app.py": APP + "\n\ndef run(source):\n    exec(source, {})\n"},
        {"tools/runner.py": "import app\n" + RUNNER},
        {
            "server.py": "import app\nimport plugin\n",
            "plugin.py": RUNNER,
        },
        {
            "server.py": "import app\n",
            "app.py": APP.replace(
                "from storage import load, save\n",
                "from storage import load, save\nimport hooks\n",
            ),
            "hooks.py": RUNNER,
        },
    ],
    ids=[
        "dispatch-in-the-serving-module",
        "dispatching-program-imports-the-app",
        "dispatch-loaded-by-the-server",
        "dispatch-imported-by-the-app",
    ],
)
def test_dispatch_that_can_share_the_serving_process_keeps_traversal(tmp_path, extra):
    traversal, _, _ = _resolve(tmp_path, extra)
    assert sorted(traversal) == [
        ("storage.py", 2, "untrusted"),
        ("storage.py", 7, "untrusted"),
    ]


def test_separate_program_does_not_excuse_an_unchecked_route(tmp_path):
    unchecked = APP.replace(
        '    path = os.path.join(checked_dir(name), "manifest.json")\n',
        '    path = os.path.join(ROOT, name, "manifest.json")\n',
    ).replace("clean(payload.name.strip())", "payload.name.strip()")
    traversal, _, _ = _resolve(
        tmp_path, {"app.py": unchecked, "tools/runner.py": RUNNER}
    )
    assert sorted(traversal) == [
        ("storage.py", 2, "untrusted"),
        ("storage.py", 7, "untrusted"),
    ]


def test_separate_program_does_not_excuse_a_custom_string_from_the_server(tmp_path):
    custom = APP + (
        "\n\nclass Raw(str):\n    def __iter__(self):\n        yield Raw('/')\n\n"
        "    def isalnum(self):\n        return True\n\n\n"
        "view(Raw('x'))\n"
    )
    traversal, _, _ = _resolve(tmp_path, {"app.py": custom, "tools/runner.py": RUNNER})
    assert sorted(traversal) == [
        ("storage.py", 2, "untrusted"),
        ("storage.py", 7, "untrusted"),
    ]
