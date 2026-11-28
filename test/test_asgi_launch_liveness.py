import json
from textwrap import dedent

import pytest

from skylos.analyzer import Skylos

FACTORY = """\
from fastapi import FastAPI

def greeting():
    return "Hello"

def build_application():
    app = FastAPI()

    @app.get("/")
    def homepage():
        return greeting()

    return app

def unused_neighbor():
    return "unused"
"""


def _scan(root, files, confidence, grep):
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(source), encoding="utf-8")
    analyzer = Skylos()
    result = json.loads(analyzer.analyze(str(root), thr=confidence, grep_verify=grep))
    assert not result.get("analysis_errors")
    return analyzer, {
        item["full_name"]
        for bucket in ("unused_functions", "unused_variables", "unused_classes")
        for item in result.get(bucket, ())
    }


@pytest.mark.parametrize("confidence,grep", [(0, False), (80, True)])
@pytest.mark.parametrize(
    "launcher",
    [
        {
            "Dockerfile": 'FROM python:3.13\nCMD ["uvicorn", "service:build_application", "--factory"]\n'
        },
        {
            "Dockerfile": "FROM python:3.13\nCMD python -m uvicorn --factory --port 8080 service:build_application\n"
        },
        {
            "launch.py": """
            from uvicorn import run as serve
            if __name__ == "__main__":
                serve(app="service:build_application", factory=True)
            """
        },
    ],
)
def test_explicit_launch_factory_roots_its_routes(tmp_path, confidence, grep, launcher):
    analyzer, unused = _scan(
        tmp_path, {"service.py": FACTORY, **launcher}, confidence, grep
    )
    assert "service.build_application" not in unused
    assert "service.greeting" not in unused
    assert "service.unused_neighbor" in unused
    assert analyzer.defs["service.build_application.homepage"].heuristic_refs.get(
        "framework_root"
    )


@pytest.mark.parametrize(
    "launcher",
    [
        {"pyproject.toml": '[tool.fastapi]\nentrypoint = "api.service:application"\n'},
        {
            "Dockerfile": 'FROM python:3.13\nCMD ["fastapi", "run", "--entrypoint", "api.service:application"]\n'
        },
        {
            "Dockerfile": 'FROM python:3.13\nENTRYPOINT ["uvicorn"]\nCMD ["api.service:application"]\n'
        },
        {"launch.py": 'import uvicorn\nuvicorn.run("api.service:application")\n'},
    ],
)
def test_launch_of_concrete_app_keeps_only_selected_export(tmp_path, launcher):
    _, unused = _scan(
        tmp_path,
        {
            "api/__init__.py": "",
            "api/service.py": FACTORY
            + "\napplication = build_application()\nspare = build_application()\n",
            **launcher,
        },
        80,
        True,
    )
    assert "api.service.application" not in unused
    assert "api.service.spare" in unused


@pytest.mark.parametrize(
    "launcher",
    [
        {
            "pyproject.toml": '[tool.fastapi]\nentrypoint = "service:build_application"\n'
        },
        {
            "Dockerfile": 'FROM python:3.13 AS builder\nCMD ["uvicorn", "service:build_application", "--factory"]\nFROM python:3.13\nCMD ["echo", "uvicorn", "service:build_application", "--factory"]\n'
        },
        {
            "Dockerfile": 'FROM python:3.13\nRUN uvicorn service:build_application --factory\nCMD ["echo", "service:build_application"]\n'
        },
        {
            "Dockerfile": 'FROM python:3.13\nSHELL ["python", "-c"]\nCMD uvicorn service:build_application --factory\n'
        },
        {
            "launch.py": 'import uvicorn\ndef unused():\n    uvicorn.run("service:build_application", factory=True)\n'
        },
        {
            "launch.py": 'import uvicorn\nif __name__ == "other":\n    uvicorn.run("service:build_application", factory=True)\n'
        },
        {
            "launch.py": 'import uvicorn\nclass Fake:\n    def run(self, app, factory=False):\n        return None\nuvicorn = Fake()\nuvicorn.run("service:build_application", factory=True)\n'
        },
        {
            "uvicorn.py": "def run(app, factory=False): pass\n",
            "launch.py": 'import uvicorn\nuvicorn.run("service:build_application", factory=True)\n',
        },
    ],
)
def test_non_launcher_does_not_prove_factory_use(tmp_path, launcher):
    analyzer, unused = _scan(tmp_path, {"service.py": FACTORY, **launcher}, 80, True)
    assert "service.build_application" in unused
    assert not analyzer.defs["service.build_application.homepage"].heuristic_refs.get(
        "framework_root"
    )


def test_nested_asgi_launcher_uses_its_own_project_root(tmp_path):
    _, unused = _scan(
        tmp_path,
        {
            "first/service.py": FACTORY,
            "first/Dockerfile": 'FROM python:3.13\nCMD ["uvicorn", "--factory", "service:build_application"]\n',
            "second/service.py": FACTORY,
        },
        80,
        True,
    )
    assert "first.service.build_application" not in unused
    assert "second.service.build_application" in unused


@pytest.mark.parametrize("flag", ["--help", "--"])
def test_fastapi_cli_requires_a_running_command(tmp_path, flag):
    _, unused = _scan(
        tmp_path,
        {
            "service.py": FACTORY + "\napplication = build_application()\n",
            "Dockerfile": f'FROM python:3.13\nCMD ["fastapi", "run", "{flag}", "--entrypoint=service:application"]\n',
        },
        80,
        True,
    )
    assert "service.application" in unused
