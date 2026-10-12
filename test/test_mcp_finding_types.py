"""Compact MCP replies retain complete risk records and saved scan evidence."""

import copy
import json
import asyncio

import pytest

import skylos_mcp.server as server
from skylos.core.safe_cache_io import read_project_text_no_symlink


class FakeMCP:
    def __init__(self):
        self.tools = {}
        self.resources = {}

    def tool(self):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn

        return register

    def resource(self, uri):
        def register(fn):
            self.resources[uri] = fn
            return fn

        return register


def _finding(rule, index, *, severity="HIGH"):
    return {
        "rule_id": rule,
        "severity": severity,
        "file": "src/app.py",
        "line": index + 1,
        "name": f"item_{index}",
        "message": f"evidence {rule} {index}",
        "evidence": {"trace": [f"step-{index}", "sink"], "extra": {"known": False}},
        "value": index,
    }


def _mixed_result():
    return {
        "analysis_summary": {"total_files": 1, "quality_count": 2050},
        "quality": [
            *[_finding("SKY-Q301", n) for n in range(1800)],
            *[_finding("SKY-L001", n, severity="LOW") for n in range(100)],
            *[_finding("SKY-T103", n) for n in range(150)],
        ],
        "custom_rules": [_finding("CUSTOM-review", n) for n in range(80)],
        "unused_functions": [
            {"name": f"orphan_{n}", "file": "src/app.py", "line": n + 1}
            for n in range(80)
        ],
        "analysis_errors": [
            {"kind": "parse_error", "file": "bad.py", "detail": "keep this error"}
        ],
    }


def test_compact_summary_never_caps_defect_review_or_errors():
    result = _mixed_result()
    original = copy.deepcopy(result)
    reply = server._make_summary(result)

    assert len(reply["quality"]) == 250
    assert reply["quality"] == original["quality"][1800:]
    assert reply["custom_rules"] == original["custom_rules"]
    assert reply["unused_functions"] == original["unused_functions"]
    assert reply["analysis_errors"] == original["analysis_errors"]
    assert reply["finding_types"] == {
        "defect": 100,
        "review": 310,
        "advice": 1800,
        "advice_groups": 1,
    }
    assert reply["advice_groups"] == [
        {
            "rule_id": "SKY-Q301",
            "name": "Cyclomatic complexity",
            "count": 1800,
            "file_count": 1,
        }
    ]
    assert result == original
    assert "evidence SKY-Q301" not in json.dumps(reply)


@pytest.mark.parametrize("expanded", [False, True])
def test_quality_tool_resources_always_keep_every_record(
    monkeypatch, tmp_path, expanded
):
    result = _mixed_result()
    monkeypatch.setattr(server, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(server, "_results_cache", {})
    monkeypatch.setattr(server, "_gate", lambda _name: None)
    monkeypatch.setattr(server, "_run_analysis", lambda *_args, **_kwargs: result)
    mcp = FakeMCP()
    server._register_tools(mcp)

    reply = json.loads(mcp.tools["quality_check"](".", expand_advice=expanded))
    run_id = reply["_run_id"]
    assert reply["_result_uri"] == f"skylos://results/{run_id}"
    assert reply["advice_details"] == {
        "expanded": expanded,
        "resource_uri": reply["_result_uri"],
        "expand_parameter": "expand_advice",
    }
    assert len(reply["quality"]) == (2050 if expanded else 250)
    saved_path = server._result_path(run_id)
    assert saved_path is not None
    assert saved_path.parent == tmp_path.resolve()
    saved_text = read_project_text_no_symlink(
        tmp_path, saved_path, max_bytes=2 * 1024 * 1024
    )
    assert saved_text is not None
    saved = json.loads(saved_text)
    assert saved["result"] == result
    assert len(saved["result"]["quality"]) == 2050
    assert saved["result"]["quality"][0]["finding_type"] == "advice"
    assert saved["result"]["quality"][1800]["finding_type"] == "defect"
    assert saved["result"]["quality"][1900]["finding_type"] == "review"
    assert json.loads(mcp.resources["skylos://results/latest"]()) == saved
    assert json.loads(mcp.resources["skylos://results/{run_id}"](run_id)) == saved
    # A cache miss must retrieve the same full report from disk.
    server._results_cache.clear()
    assert json.loads(mcp.resources["skylos://results/{run_id}"](run_id)) == saved
    assert json.loads(mcp.resources["skylos://results/latest"]()) == saved


def test_architecture_advice_is_grouped_without_losing_review_or_metrics():
    advice = _finding("SKY-Q802", 0)
    review = _finding("SKY-Q805", 1)
    result = {
        "analysis_summary": {},
        "quality": [advice, review],
        "architecture_metrics": {
            "system_metrics": {"architecture_fitness": 0.9},
            "advisories": [
                {"module": "app", "signals": [copy.deepcopy(advice), review]}
            ],
        },
        "analysis_errors": [{"kind": "partial_architecture"}],
    }
    original = copy.deepcopy(result)
    compact = server._architecture_payload(result)
    expanded = server._architecture_payload(result, expand_advice=True)
    assert compact["findings"] == [review]
    assert compact["architecture_metrics"]["advisories"][0]["signals"] == [review]
    assert compact["architecture_metrics"]["system_metrics"] == {
        "architecture_fitness": 0.9
    }
    assert compact["analysis_errors"] == result["analysis_errors"]
    assert compact["finding_types"]["advice"] == 1
    assert expanded["findings"] == [advice, review]
    assert result == original


def test_health_score_keeps_risk_records_and_grade_scope():
    result = _mixed_result()
    result["danger"] = [_finding("SKY-D201", 9)]
    result["grade"] = {"overall": {"score": 32, "letter": "F"}, "categories": {}}
    reply = server._health_score_payload(result)
    assert reply["grade"] == result["grade"]
    assert reply["danger"] == result["danger"]
    assert len(reply["quality"]) == 250
    assert reply["analysis_summary"]["quality_count"] == 2050


@pytest.mark.parametrize(
    "tool",
    [
        "analyze",
        "security_scan",
        "quality_check",
        "architecture_check",
        "health_score",
        "secrets_scan",
    ],
)
def test_scan_tool_description_explains_expansion_and_complete_resource(tool):
    mcp = FakeMCP()
    server._register_tools(mcp)
    description = mcp.tools[tool].__doc__
    assert "expand_advice=True" in description
    assert "_result_uri" in description
    assert "complete" in description


def test_registered_fastmcp_schema_reply_and_full_resource(monkeypatch, tmp_path):
    FastMCP = pytest.importorskip("mcp.server.fastmcp").FastMCP
    result = {"quality": [_finding("SKY-Q301", 0), _finding("SKY-L001", 1)]}
    monkeypatch.setattr(server, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(server, "_results_cache", {})
    monkeypatch.setattr(server, "_gate", lambda _name: None)
    monkeypatch.setattr(server, "_run_analysis", lambda *_args, **_kwargs: result)
    mcp = FastMCP("finding-types-test")
    server._register_tools(mcp)
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    schema = tools["quality_check"].inputSchema
    assert schema["properties"]["expand_advice"]["type"] == "boolean"
    assert schema["properties"]["expand_advice"]["default"] is False
    assert "expand_advice" not in schema.get("required", [])

    response = asyncio.run(mcp.call_tool("quality_check", {"path": "."}))
    contents = response[0] if isinstance(response, tuple) else response
    reply = json.loads(contents[0].text)
    assert len(reply["quality"]) == 1
    resource = list(asyncio.run(mcp.read_resource(reply["_result_uri"])))
    saved = json.loads(resource[0].content)
    assert saved["result"] == result
    assert len(saved["result"]["quality"]) == 2

    response = asyncio.run(
        mcp.call_tool("quality_check", {"path": ".", "expand_advice": True})
    )
    contents = response[0] if isinstance(response, tuple) else response
    assert len(json.loads(contents[0].text)["quality"]) == 2
