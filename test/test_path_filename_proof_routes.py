"""Filename proofs for FastAPI request models in realistic application layouts."""

import ast
from pathlib import Path

import pytest

from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.rules.danger.danger_fs.path_provenance import (
    resolve_helper_parameter_findings,
)


HEADER = """import os
from datetime import datetime
from typing import Optional

from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from storage import load, save

ROOT = os.environ.get("RUNS_DIR", "/srv/runs")
app = FastAPI(title="runs")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])
app.mount("/files", StaticFiles(directory=ROOT), name="files")


class StartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None
    interval: float = Field(default=1.0, ge=0.5)


class ReplayRequest(BaseModel):
    name: str = Field(min_length=1, max_length=96)


def clean(raw: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in raw)
    return cleaned or datetime.utcnow().strftime("run_%Y%m%d_%H%M%S")


def checked_dir(raw: str) -> str:
    safe = clean(raw)
    if safe != raw:
        raise HTTPException(status_code=400, detail="invalid name")
    return os.path.join(ROOT, raw)
"""
START = """
@app.post("/start", response_model=dict)
def start(payload: StartRequest | None = Body(default=None)):
    request = payload or StartRequest()
    base = (request.name or "").strip() or datetime.utcnow().strftime("run_%Y%m%d")
    path = os.path.join(ROOT, clean(base), "manifest.json")
    save(path)
    return load(path)
"""
REPLAY = """
@app.post("/replay")
def replay(payload: ReplayRequest):
    path = os.path.join(checked_dir(payload.name.strip()), "manifest.json")
    save(path)
    return load(path)
"""
VIEW = """
@app.get("/runs/{name}")
def view(name: str):
    path = os.path.join(checked_dir(name), "manifest.json")
    save(path)
    return load(path)
"""
PRELUDE = """from typing import Annotated, Any
from pydantic import AfterValidator


class Raw(str):
    def __iter__(self):
        yield Raw('/')

    def isalnum(self):
        return True


def fresh():
    return StartRequest(name=Raw('x'))


class Base(BaseModel):
    @classmethod
    def build(cls, raw):
        return cls(name=raw)
"""
MODEL_LOOKALIKES = (HEADER + START).replace(
    "\nROOT = ", "\n" + PRELUDE + "\nROOT = ", 1
)
STORAGE = """def load(path):
    with open(path, "r") as stream:
        return stream.read()


def save(path):
    with open(path, "w") as stream:
        stream.write("record")
"""


def _resolve(tmp_path, files, base):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="route-proof"\n')
    findings = []
    for name, text in files.items():
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        scan(ast.parse(text), path, findings)
    suppressed = []
    kept = resolve_helper_parameter_findings(
        findings, scan_path=tmp_path, project_root=tmp_path, suppressed=suppressed
    )
    return kept, suppressed


def _scan(tmp_path, source, extra=None, package=False):
    files = {"app.py": source, "storage.py": STORAGE, **(extra or {})}
    base = tmp_path
    if package:
        base = tmp_path / "service"
        files["__init__.py"] = ""
        files = {
            name: text.replace("from storage import", "from .storage import")
            for name, text in files.items()
        }
    kept, suppressed = _resolve(tmp_path, files, base)
    assert {
        (f["rule_id"], Path(f["file"]).name, f["line"])
        for f in kept
        if f["rule_id"] in {"SKY-D324", "SKY-D325"}
    } == {("SKY-D324", "storage.py", 7), ("SKY-D325", "storage.py", 2)}
    traversal = [f for f in kept if f["rule_id"] == "SKY-D215"]
    statuses = sorted(
        f["metadata"]["path_provenance"]["status"]
        for f in suppressed
        if f["rule_id"] == "SKY-D215"
    )
    return traversal, statuses


@pytest.mark.parametrize(
    "source",
    [HEADER + START, HEADER + REPLAY, HEADER + VIEW, MODEL_LOOKALIKES],
    ids=[
        "optional-body-field",
        "required-body-field",
        "path-parameter",
        "beside-lookalikes",
    ],
)
def test_validated_request_value_through_a_character_filter_is_traversal_safe(
    tmp_path, source
):
    kept, statuses = _scan(tmp_path, source)
    assert not kept
    assert statuses == ["safe", "safe"]


def test_public_package_importers_stay_unknown_instead_of_safe(tmp_path):
    kept, statuses = _scan(tmp_path, HEADER + START + REPLAY + VIEW, package=True)
    assert not kept
    assert statuses == ["unknown", "unknown"]


def test_calls_on_unresolved_receivers_stay_unknown_instead_of_safe(tmp_path):
    extra = {"jobs.py": "def run(service):\n    service.view(object())\n"}
    kept, statuses = _scan(tmp_path, HEADER + VIEW, extra=extra)
    assert not kept
    assert statuses == ["unknown", "unknown"]


def test_patching_in_unrelated_programs_and_tests_does_not_disable_the_proof(tmp_path):
    extra = {
        "tests/test_app.py": "from unittest import mock\nimport app\n\ndef test_view():\n"
        "    with mock.patch('app.clean', lambda raw: raw):\n        app.view('x')\n",
        "tools/report.py": "import storage\n\ndef main():\n    globals()['load'] = print\n",
    }
    kept, _ = _scan(tmp_path, HEADER + VIEW, extra=extra)
    assert not kept


@pytest.mark.parametrize(
    "extra",
    [
        {"server.py": "import app\napp.clean = lambda raw: raw\n"},
        {
            "server.py": "from unittest import mock\nimport app\nmock.patch('app.clean', str).start()\n"
        },
        {"server.py": "import sys\nimport app\nsys.modules['app'].clean = str\n"},
        {"server.py": "import app\nsetattr(app, 'clean', str)\n"},
        {"storage.py": STORAGE + "def swap():\n    globals()['open'] = print\n"},
        {
            "server.py": "import importlib\nimport app\nimportlib.import_module(app.ROOT)\n",
            "plugin.py": "def install():\n    globals()['clean'] = str\n",
        },
    ],
    ids=[
        "importer-rebinds-helper",
        "importer-mock-patch",
        "sys-modules-rebind",
        "importer-setattr",
        "imported-module-namespace-write",
        "dynamically-loaded-module",
    ],
)
def test_patching_inside_the_serving_process_keeps_traversal(tmp_path, extra):
    kept, _ = _scan(tmp_path, HEADER + VIEW, extra=extra)
    assert len(kept) == 2


@pytest.mark.parametrize(
    "old, new",
    [
        (
            'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])',
            "from starlette.middleware.base import BaseHTTPMiddleware\n"
            "async def rewrite(request, call_next):\n    return await call_next(request)\n"
            "app.add_middleware(BaseHTTPMiddleware, dispatch=rewrite)",
        ),
        ("StaticFiles(directory=ROOT)", "FastAPI()"),
        ('strftime("run_%Y%m%d_%H%M%S")', 'strftime("%Y/%m/%d")'),
        ('strftime("run_%Y%m%d_%H%M%S")', 'strftime("run_%x")'),
        ("from datetime import datetime", "from clock import datetime"),
    ],
    ids=[
        "dispatch-middleware",
        "mounted-app",
        "separator-format",
        "locale-format",
        "project-clock",
    ],
)
def test_unproved_runtime_or_fallback_keeps_traversal(tmp_path, old, new):
    source = HEADER.replace(old, new)
    assert source != HEADER
    extra = {
        "clock.py": "class datetime:\n    @staticmethod\n    def utcnow():\n        return Path()\n"
    }
    kept, _ = _scan(tmp_path, source + START, extra=extra)
    assert len(kept) == 2


@pytest.mark.parametrize(
    "old, new",
    [
        (
            "    name: Optional[str] = None\n",
            "    name: Optional[str] = None\n\n    @classmethod\n    def build(cls, raw):\n        return cls(name=raw)\n",
        ),
        (
            "    name: Optional[str] = None\n",
            "    name: Annotated[str, AfterValidator(Raw)] = None\n",
        ),
        ("    name: Optional[str] = None\n", "    name: Any = None\n"),
        (
            "    name: Optional[str] = None\n",
            "    name: Optional[str] = Field(default_factory=Raw)\n",
        ),
        ("class StartRequest(BaseModel):", "class StartRequest(Base):"),
        (
            "    request = payload or StartRequest()\n",
            "    request = payload or StartRequest()\n    request.name = Raw(request.name)\n",
        ),
        (
            "    request = payload or StartRequest()\n",
            "    request = payload or StartRequest.model_construct(name=Raw('x'))\n",
        ),
        (
            "    request = payload or StartRequest()\n",
            "    request = payload or StartRequest(name=Raw('x'))\n",
        ),
        (
            "payload: StartRequest | None = Body(default=None)",
            "payload: StartRequest | None = Body(default_factory=fresh)",
        ),
    ],
    ids=[
        "model-method",
        "annotated-validator",
        "any-field",
        "default-factory",
        "base-with-method",
        "field-reassigned",
        "model-construct",
        "constructor-arguments",
        "body-default-factory",
    ],
)
def test_unvalidated_model_values_keep_traversal(tmp_path, old, new):
    source = MODEL_LOOKALIKES
    changed = source.replace(old, new)
    assert changed != source
    kept, _ = _scan(tmp_path, changed)
    assert len(kept) == 2


@pytest.mark.parametrize(
    "old, new",
    [
        ("    safe = clean(raw)\n", "    safe = clean(raw)\n    safe = raw\n"),
        ("    safe = clean(raw)\n", "    safe = raw.strip()\n"),
        ("    if safe != raw:\n", "    if safe != raw.lower():\n"),
        (
            '        raise HTTPException(status_code=400, detail="invalid name")\n',
            "        print('invalid name')\n",
        ),
        (
            "    return os.path.join(ROOT, raw)\n",
            "    raw = raw + '/..'\n    return os.path.join(ROOT, raw)\n",
        ),
    ],
    ids=[
        "alias-rebound",
        "alias-not-filtered",
        "compared-to-other-value",
        "result-ignored",
        "rebound-after-check",
    ],
)
def test_alias_guard_that_proves_nothing_keeps_traversal(tmp_path, old, new):
    source = HEADER.replace(old, new)
    assert source != HEADER
    kept, _ = _scan(tmp_path, source + VIEW)
    assert len(kept) == 2


def test_direct_call_with_a_custom_model_value_keeps_traversal(tmp_path):
    suffix = """
class Raw(str):
    def __iter__(self):
        yield Raw('/')

    def isalnum(self):
        return True


replay(ReplayRequest.model_construct(name=Raw('x')))
"""
    kept, _ = _scan(tmp_path, HEADER + REPLAY + suffix)
    assert len(kept) == 2


def test_filter_applied_after_the_sink_keeps_traversal(tmp_path):
    route = """
@app.get("/runs/{name}")
def view(name: str):
    path = os.path.join(ROOT, name, "manifest.json")
    save(path)
    clean(name)
    return load(path)
"""
    kept, _ = _scan(tmp_path, HEADER + route)
    assert len(kept) == 2


def test_filtered_launch_argument_leaves_launched_cli_paths_unproven(tmp_path):
    route = """
import subprocess
import sys


@app.post("/export/{name}")
def export(name: str):
    return subprocess.run([sys.executable, "report.py", clean(name)])
"""
    report = (
        "import sys\nfrom pathlib import Path\n\n\n"
        "def read_doc(path):\n    return Path(path).read_text()\n\n\n"
        "if __name__ == '__main__':\n    print(read_doc(sys.argv[1]))\n"
    )
    files = {"app.py": HEADER + route, "storage.py": STORAGE, "report.py": report}
    _, suppressed = _resolve(tmp_path, files, tmp_path)
    reader = [f for f in suppressed if f["symbol"] == "read_doc"]
    assert {f["rule_id"] for f in reader} == {"SKY-D215", "SKY-D325"}
    for finding in reader:
        provenance = finding["metadata"]["path_provenance"]
        assert provenance["status"] == "unknown"
        assert any(
            "process launch passes untrusted arguments" in chain[0]
            for chain in provenance["unknown"]
        )
