"""Absolute imports do not select an unrelated package sibling."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


CASES = [
    {
        "name": "tls-entry-import-sibling-noop",
        "rule": "SKY-D210",
        "want": True,
        "source": "import pkg.app\n",
        "providers": {
            "pkg/__init__.py": "",
            "pkg/app.py": 'import requests\nrequests.get("https://example.com",verify=False)\n',
            "pkg/requests.py": 'def get(url,verify=True):\n    return {"url":url}\n',
        },
        "required_file": "pkg/app.py",
        "reason": "Entry imports package; absolute requests imports root/sitepackages, not pkg/requests.py",
    },
    {
        "name": "tls-direct-root-noop-control",
        "rule": "SKY-D210",
        "want": False,
        "source": 'import requests\nrequests.get("https://example.com",verify=False)\n',
        "providers": {
            "requests.py": 'def get(url,verify=True):\n    return {"url":url}\n'
        },
    },
    {
        "name": "route-entry-import-sibling-inert",
        "rule": "SKY-D283",
        "want": True,
        "source": "import pkg.app\n",
        "providers": {
            "pkg/__init__.py": "",
            "pkg/app.py": 'from fastapi import FastAPI\nimport uvicorn\napp=FastAPI()\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok":True}\nuvicorn.run(app,host="0.0.0.0")\n',
            "pkg/fastapi.py": "class FastAPI:\n    def __init__(self,*args,**kwargs):\n        pass\n    def post(self,*args,**kwargs):\n        return lambda handler:handler\n",
        },
        "required_file": "pkg/app.py",
        "reason": "Entry imports package; absolute fastapi imports root/sitepackages, not pkg/fastapi.py",
    },
    {
        "name": "route-direct-root-inert-control",
        "rule": "SKY-D283",
        "want": False,
        "source": 'from fastapi import FastAPI\nimport uvicorn\napp=FastAPI()\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok":True}\nuvicorn.run(app,host="0.0.0.0")\n',
        "providers": {
            "fastapi.py": "class FastAPI:\n    def __init__(self,*args,**kwargs):\n        pass\n    def post(self,*args,**kwargs):\n        return lambda handler:handler\n"
        },
    },
]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_inert_provider_proof_uses_the_absolute_import_root(
    tmp_path, monkeypatch, case
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    entry = write_fixture(root, "entry.py", case["source"])
    files = [entry]
    for relative, source in case.get("providers", {}).items():
        files.append(write_fixture(root, relative, source))
    raw = [row for row in scan_ctx(root, files) if row["rule_id"] == case["rule"]]
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert not result.get("analysis_errors")
    listed = [row for row in result.get("danger", []) if row["rule_id"] == case["rule"]]
    assert bool(raw) is bool(listed) is case["want"]
    if case["want"]:
        assert all(row["file"].endswith(case["required_file"]) for row in raw + listed)
        assert all(row["severity"] in {"HIGH", "CRITICAL"} for row in raw + listed)
        assert all(row["listing"]["listed"] for row in listed)
    assert check_gate(
        result, {"gate": {"max_high": 0, "max_critical": 0, "max_security": 0}}
    )[0] is (not case["want"])
