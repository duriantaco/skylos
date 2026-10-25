"""FastAPI execution evidence belongs to callables and actual contracts."""

import json

import pytest

from skylos.analyzer import Skylos


def _scan(root, source, analyzer=None):
    path = root / "app.py"
    path.write_text(source, encoding="utf-8")
    analyzer = analyzer or Skylos()
    result = json.loads(analyzer.analyze(str(root), thr=0, grep_verify=False))
    assert not result.get("analysis_errors")
    return result, {
        definition.name: definition for definition in analyzer.defs.values()
    }


def test_one_line_route_does_not_mark_ordinary_parameter_as_framework_root(tmp_path):
    result, definitions = _scan(
        tmp_path,
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/')\ndef endpoint(ignored_flag: bool = False): return 1\n",
    )
    assert "app.endpoint.ignored_flag" in {
        item["full_name"] for item in result["unused_parameters"]
    }
    assert (
        "framework_root" not in definitions["app.endpoint.ignored_flag"].heuristic_refs
    )
    assert definitions["app.endpoint"].heuristic_refs.get("framework_root") == 1.0


def test_one_line_route_keeps_injected_parameter_but_reports_plain_neighbor(tmp_path):
    result, definitions = _scan(
        tmp_path,
        "from fastapi import FastAPI, Depends\napp = FastAPI()\n"
        "def authorize(): return True\n"
        "@app.get('/')\n"
        "def endpoint(token=Depends(authorize), ignored_flag: bool = False): return 1\n",
    )
    unused = {item["full_name"] for item in result["unused_parameters"]}
    assert "app.endpoint.token" not in unused
    assert "app.endpoint.ignored_flag" in unused
    assert "framework_root" not in definitions["app.endpoint.token"].heuristic_refs


def test_other_framework_root_survives_fastapi_reconciliation(tmp_path):
    result, definitions = _scan(
        tmp_path,
        "from fastapi import FastAPI\nfrom celery import shared_task\n"
        "class Local:\n"
        "    def get(self, path): return lambda function: function\n"
        "fake = Local()\n"
        "@shared_task\n@fake.get('/')\n"
        "def task_endpoint(): return task_helper()\n"
        "def task_helper(): return 1\n",
    )
    unused = {item["full_name"] for item in result["unused_functions"]}
    assert "app.task_endpoint" not in unused
    assert "app.task_helper" not in unused
    assert definitions["app.task_endpoint"].heuristic_refs.get("framework_root") == 1.0


def test_reused_analyzer_refreshes_fastapi_provider_evidence(tmp_path):
    analyzer = Skylos()
    source = (
        "from fastapi import FastAPI\n{provider}\n"
        "app = FastAPI()\n@app.get('/')\n"
        "def endpoint(): return helper()\ndef helper(): return 1\n"
    )
    _, real_definitions = _scan(tmp_path, source.format(provider=""), analyzer)
    assert real_definitions["app.endpoint"].heuristic_refs.get("framework_root") == 1.0
    fake = "class FastAPI:\n    def get(self, path): return lambda function: function"
    result, fake_definitions = _scan(tmp_path, source.format(provider=fake), analyzer)
    assert "framework_root" not in fake_definitions["app.endpoint"].heuristic_refs
    assert {"app.endpoint", "app.helper"} <= {
        item["full_name"] for item in result["unused_functions"]
    }


@pytest.mark.parametrize(
    ("provider", "decorator", "strong"),
    [
        ("from celery import shared_task as task_entry", "task_entry", True),
        ("from plugin import register_entry", "register_entry", False),
    ],
)
def test_unrelated_decorators_keep_their_own_evidence(
    tmp_path, provider, decorator, strong
):
    result, definitions = _scan(
        tmp_path,
        "from fastapi import FastAPI\n"
        "class Local:\n"
        "    def get(self, path): return lambda function: function\n"
        "fake = Local()\n"
        f"{provider}\n@{decorator}\n@fake.get('/')\n"
        "def endpoint(): return helper()\n"
        "def helper(): return 1\n",
    )
    assert not {"app.endpoint", "app.helper"} & {
        item["full_name"] for item in result["unused_functions"]
    }
    assert (
        bool(definitions["app.endpoint"].heuristic_refs.get("framework_root")) is strong
    )
