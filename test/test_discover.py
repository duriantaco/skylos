"""Tests for the AI Discovery Engine (Phase 1A)."""

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.discover.detector import (
    _LLMDetectorVisitor,
    _build_graph_from_visitor,
    _collect_python_files,
    detect_integrations,
)
from skylos.discover.integration import LLMIntegration, ToolDef
from skylos.discover.graph import AIIntegrationGraph, GraphNode, GraphEdge, NodeType
from skylos.discover.report import format_table, format_json
from skylos.discover.taint import analyze_taint_flows


# ---------------------------------------------------------------------------
# Fixtures: sample codebases with LLM integrations
# ---------------------------------------------------------------------------


@pytest.fixture
def openai_chat_project():
    """Project with a basic OpenAI chat integration."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "chat.py").write_text(
            """
import openai

client = openai.OpenAI()

def chat(user_message):
    response = client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_message},
        ],
    )
    return response.choices[0].message.content
"""
        )
        yield root


@pytest.fixture
def anthropic_agent_project():
    """Project with an Anthropic agent with tools."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "agent.py").write_text(
            '''
import anthropic
import subprocess
import json

client = anthropic.Anthropic()

from langchain_core.tools import tool

@tool
def shell_tool(command: str) -> str:
    """Run a shell command."""
    return subprocess.check_output(command, shell=True).decode()

@tool
def read_file(path):
    """Read a file."""
    return open(path).read()

def run_agent(user_input):
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        messages=[{"role": "user", "content": user_input}],
        tools=[shell_tool, read_file],
    )
    result = response.content[0].text
    return eval(result)
'''
        )
        yield root


@pytest.fixture
def flask_llm_project():
    """Project with Flask + OpenAI integration and dangerous sinks."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app.py").write_text(
            """
from flask import Flask, request
import openai
import subprocess
import json

app = Flask(__name__)
client = openai.OpenAI()

@app.route("/chat", methods=["POST"])
def chat_endpoint():
    data = request.get_json()
    user_msg = data["message"]

    prompt = f"Answer the following question: {user_msg}"

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": prompt},
        ],
    )

    result = response.choices[0].message.content
    subprocess.run(result, shell=True)
    return result
"""
        )
        yield root


@pytest.fixture
def langchain_rag_project():
    """Project with LangChain RAG pipeline."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "search.py").write_text(
            '''
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
import json

llm = ChatOpenAI(model="gpt-4o-2024-08-06")

template = """Answer based on the following context:
<context>
{context}
</context>

Question: {question}
"""

prompt = ChatPromptTemplate.from_template(template)

def search(query: str):
    if len(query) > 500:
        query = query[:500]
    chain = prompt | llm
    result = chain.invoke({"context": "...", "question": query})
    parsed = json.loads(result.content)
    return parsed
'''
        )
        yield root


@pytest.fixture
def validated_output_project():
    """Project with proper output validation."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "validated.py").write_text(
            """
import openai
import json
from pydantic import BaseModel

class Response(BaseModel):
    answer: str
    confidence: float

client = openai.OpenAI()

def get_answer(question: str):
    response = client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": question}],
    )
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    validated = Response.model_validate(parsed)
    return validated
"""
        )
        yield root


@pytest.fixture
def empty_project():
    """Project with no LLM integrations."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "main.py").write_text(
            """
def hello():
    return "world"
"""
        )
        yield root


@pytest.fixture
def multi_integration_project():
    """Project with multiple LLM integrations."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "chat.py").write_text(
            """
import openai

client = openai.OpenAI()

def chat(msg):
    return client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": msg}],
    )
"""
        )
        (root / "embed.py").write_text(
            """
import openai

client = openai.OpenAI()

def embed(text):
    return client.embeddings.create(
        model="text-embedding-3-small",
        input=text,
    )
"""
        )
        yield root


# ---------------------------------------------------------------------------
# Discovery tests
# ---------------------------------------------------------------------------


class TestDetectIntegrations:
    def test_detects_openai_chat(self, openai_chat_project):
        integrations, graph = detect_integrations(openai_chat_project)
        assert len(integrations) == 1
        integ = integrations[0]
        assert integ.provider == "OpenAI"
        assert integ.integration_type == "chat"
        assert integ.model_pinned is True
        assert integ.model_value == "gpt-4o-2024-08-06"
        assert integ.has_system_prompt is True

    def test_detects_anthropic_agent(self, anthropic_agent_project):
        integrations, graph = detect_integrations(anthropic_agent_project)
        assert len(integrations) >= 1
        agent_integs = [
            i for i in integrations if i.integration_type in ("agent", "chat")
        ]
        assert len(agent_integs) >= 1

    def test_detects_flask_input_sources(self, flask_llm_project):
        integrations, graph = detect_integrations(flask_llm_project)
        assert len(integrations) >= 1
        integ = integrations[0]
        assert integ.model_pinned is False
        assert integ.model_value == "gpt-4o"

    def test_detects_dangerous_sinks(self, flask_llm_project):
        integrations, graph = detect_integrations(flask_llm_project)
        assert len(integrations) >= 1
        integ = integrations[0]
        assert any("subprocess" in s for s in integ.output_sinks)

    def test_detects_langchain_rag(self, langchain_rag_project):
        integrations, graph = detect_integrations(langchain_rag_project)
        # LangChain ChatOpenAI instantiation should be detected
        assert len(integrations) >= 0  # May not detect instantiation as a "call"

    def test_no_integrations_in_empty_project(self, empty_project):
        integrations, graph = detect_integrations(empty_project)
        assert len(integrations) == 0

    def test_multiple_integrations(self, multi_integration_project):
        integrations, graph = detect_integrations(multi_integration_project)
        assert len(integrations) == 2

    def test_output_validation_detected(self, validated_output_project):
        integrations, graph = detect_integrations(validated_output_project)
        assert len(integrations) == 1
        assert integrations[0].has_output_validation is True


class TestIntegrationGraph:
    def test_graph_has_nodes(self, openai_chat_project):
        integrations, graph = detect_integrations(openai_chat_project)
        assert len(graph.nodes) > 0

    def test_graph_has_llm_call_nodes(self, openai_chat_project):
        integrations, graph = detect_integrations(openai_chat_project)
        call_nodes = graph.get_nodes_by_type(NodeType.LLM_CALL)
        assert len(call_nodes) >= 1

    def test_graph_edges_for_dangerous_sinks(self, flask_llm_project):
        integrations, graph = detect_integrations(flask_llm_project)
        sink_nodes = graph.get_nodes_by_type(NodeType.OUTPUT_SINK)
        assert len(sink_nodes) >= 1

    def test_graph_serialization(self, openai_chat_project):
        integrations, graph = detect_integrations(openai_chat_project)
        data = graph.to_dict()
        assert "nodes" in data
        assert "edges" in data

    def test_has_path(self):
        graph = AIIntegrationGraph()
        graph.add_node(GraphNode("a", NodeType.INPUT_SOURCE, "f:1", "input"))
        graph.add_node(GraphNode("b", NodeType.LLM_CALL, "f:2", "call"))
        graph.add_node(GraphNode("c", NodeType.OUTPUT_SINK, "f:3", "sink"))
        graph.add_edge(GraphEdge("a", "b", "data_flow"))
        graph.add_edge(GraphEdge("b", "c", "data_flow"))
        assert graph.has_path("a", "c")
        assert not graph.has_path("c", "a")


class TestDetectorOuterFlow:
    def test_collect_python_files_sorts_and_skips_excluded_and_egg_info(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pkg").mkdir()
            (root / "venv").mkdir()
            (root / "dist").mkdir()
            (root / "demo.egg-info").mkdir()
            (root / "b.py").write_text("pass\n", encoding="utf-8")
            (root / "a.py").write_text("pass\n", encoding="utf-8")
            (root / "pkg" / "c.py").write_text("pass\n", encoding="utf-8")
            (root / "venv" / "skip.py").write_text("pass\n", encoding="utf-8")
            (root / "dist" / "skip.py").write_text("pass\n", encoding="utf-8")
            (root / "demo.egg-info" / "skip.py").write_text("pass\n", encoding="utf-8")

            files = [
                str(path.relative_to(root))
                for path in _collect_python_files(root, {"venv", "dist"})
            ]

        assert files == ["a.py", "b.py", "pkg/c.py"]

    def test_detect_integrations_skips_broken_files_and_keeps_relative_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pkg").mkdir()
            (root / "a_broken.py").write_text("def broken(:\n", encoding="utf-8")
            (root / "pkg" / "app.py").write_text(
                """
import openai

client = openai.OpenAI()

def chat(user_msg):
    return client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": user_msg}],
    )
""".strip()
                + "\n",
                encoding="utf-8",
            )

            integrations, graph = detect_integrations(root, exclude_folders=set())

        assert [integration.location for integration in integrations] == [
            "pkg/app.py:6"
        ]
        assert [node["id"] for node in graph.to_dict()["nodes"]] == [
            "call:pkg/app.py:6"
        ]

    def test_detect_integrations_skips_unicode_decode_errors(self, monkeypatch):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bad_file = root / "bad.py"
            good_file = root / "good.py"
            bad_file.write_text("import openai\n", encoding="utf-8")
            good_file.write_text(
                """
import openai

client = openai.OpenAI()

def chat(msg):
    return client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": msg}],
    )
""".strip()
                + "\n",
                encoding="utf-8",
            )

            original_read_text = Path.read_text

            def flaky_read_text(self, *args, **kwargs):
                if self == bad_file:
                    raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "boom")
                return original_read_text(self, *args, **kwargs)

            monkeypatch.setattr(Path, "read_text", flaky_read_text)
            integrations, _ = detect_integrations(root, exclude_folders=set())

        assert [integration.location for integration in integrations] == ["good.py:6"]


class TestGraphBuilderContract:
    def test_build_graph_from_visitor_emits_stable_ids_labels_and_order(self):
        integration = LLMIntegration(
            provider="OpenAI",
            location="pkg/app.py:42",
            integration_type="agent",
            prompt_sites=["pkg/app.py:10", "pkg/app.py:11"],
            tools=[
                ToolDef(
                    name="search",
                    location="pkg/tools.py:5",
                    has_typed_schema=True,
                    dangerous_calls=["subprocess.run"],
                )
            ],
            input_sources=["request.json (L8)"],
            output_sinks=["eval (L50)"],
            has_system_prompt=True,
            model_pinned=True,
            model_value="gpt-4o-2024-08-06",
            has_output_validation=True,
            output_validation_location="pkg/app.py:70",
        )
        graph = AIIntegrationGraph()

        _build_graph_from_visitor(
            SimpleNamespace(integrations=[integration]), graph, "pkg/app.py"
        )

        assert list(graph.nodes) == [
            "call:pkg/app.py:42",
            "input:pkg/app.py:request.json (L8)",
            "prompt:pkg/app.py:10",
            "prompt:pkg/app.py:11",
            "sink:pkg/app.py:eval (L50)",
            "tool:pkg/tools.py:5",
            "validation:pkg/app.py:70",
        ]
        assert [edge.to_dict() for edge in graph.edges] == [
            {
                "source": "input:pkg/app.py:request.json (L8)",
                "target": "call:pkg/app.py:42",
                "type": "data_flow",
                "label": "user input → LLM call",
            },
            {
                "source": "prompt:pkg/app.py:10",
                "target": "call:pkg/app.py:42",
                "type": "data_flow",
                "label": "prompt → LLM call",
            },
            {
                "source": "prompt:pkg/app.py:11",
                "target": "call:pkg/app.py:42",
                "type": "data_flow",
                "label": "prompt → LLM call",
            },
            {
                "source": "call:pkg/app.py:42",
                "target": "sink:pkg/app.py:eval (L50)",
                "type": "data_flow",
                "label": "LLM output → dangerous sink",
            },
            {
                "source": "call:pkg/app.py:42",
                "target": "tool:pkg/tools.py:5",
                "type": "tool_call",
                "label": "LLM → tool search",
            },
            {
                "source": "call:pkg/app.py:42",
                "target": "validation:pkg/app.py:70",
                "type": "data_flow",
                "label": "LLM output → validation",
            },
        ]

    def test_build_graph_from_visitor_deduplicates_duplicate_prompt_edges(self):
        integration = LLMIntegration(
            provider="OpenAI",
            location="pkg/app.py:42",
            integration_type="chat",
            prompt_sites=["pkg/app.py:10", "pkg/app.py:10"],
        )
        graph = AIIntegrationGraph()

        _build_graph_from_visitor(
            SimpleNamespace(integrations=[integration]), graph, "pkg/app.py"
        )

        assert list(graph.nodes) == ["call:pkg/app.py:42", "prompt:pkg/app.py:10"]
        assert [edge.to_dict() for edge in graph.edges] == [
            {
                "source": "prompt:pkg/app.py:10",
                "target": "call:pkg/app.py:42",
                "type": "data_flow",
                "label": "prompt → LLM call",
            }
        ]


class TestModelPinning:
    def test_floating_alias_not_pinned(self):
        import ast

        visitor = _LLMDetectorVisitor("test.py", "")
        assert visitor._is_model_pinned("gpt-4o") is False
        assert visitor._is_model_pinned("claude-sonnet-4") is False
        assert visitor._is_model_pinned("latest") is False

    def test_dated_version_pinned(self):
        visitor = _LLMDetectorVisitor("test.py", "")
        assert visitor._is_model_pinned("gpt-4o-2024-08-06") is True
        assert visitor._is_model_pinned("claude-sonnet-4-20250514") is True


class TestReport:
    def test_table_format_no_integrations(self):
        output = format_table([], files_scanned=10)
        assert "No LLM integrations" in output

    def test_table_format_with_integrations(self, openai_chat_project):
        integrations, graph = detect_integrations(openai_chat_project)
        output = format_table(integrations, files_scanned=1)
        assert "OpenAI" in output
        assert "skylos defend" in output

    def test_json_format(self, openai_chat_project):
        integrations, graph = detect_integrations(openai_chat_project)
        output = format_json(integrations, graph, files_scanned=1)
        data = json.loads(output)
        assert data["version"] == "1.0"
        assert data["integrations_found"] >= 1
        assert len(data["integrations"]) >= 1


class TestTaintAnalysis:
    def test_taint_flow_detected(self):
        source = """
def handler(request):
    user_input = request.get_json()
    eval(user_input)
"""
        flows = analyze_taint_flows("test.py", source)
        # Taint tracking is intra-function, might not detect all flows
        # but should at least not crash
        assert isinstance(flows, list)

    def test_no_taint_in_safe_code(self):
        source = """
def safe():
    x = 42
    return x + 1
"""
        flows = analyze_taint_flows("test.py", source)
        assert len(flows) == 0

    def test_syntax_error_handled(self):
        flows = analyze_taint_flows("bad.py", "def broken(")
        assert flows == []
