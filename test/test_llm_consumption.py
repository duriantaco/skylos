from pathlib import Path

from skylos.rules.danger.danger import scan_ctx


def _write(tmp_path: Path, name: str, code: str) -> Path:
    file_path = tmp_path / name
    file_path.write_text(code, encoding="utf-8")
    return file_path


def _scan_one(tmp_path: Path, name: str, code: str):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def _d267_findings(findings):
    return [finding for finding in findings if finding["rule_id"] == "SKY-D267"]


def test_openai_call_without_token_or_timeout_flags_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "llm_no_bounds.py",
        """
from openai import OpenAI

client = OpenAI()

def answer(messages):
    return client.chat.completions.create(model="gpt-4o", messages=messages)
""",
    )

    d267 = _d267_findings(findings)
    assert d267
    assert "no max token limit" in d267[0]["message"]
    assert "no request timeout" in d267[0]["message"]


def test_openai_call_with_token_and_timeout_is_not_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "llm_bounded.py",
        """
from openai import OpenAI

client = OpenAI(timeout=30)

def answer(messages):
    return client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=400,
    )
""",
    )

    assert "SKY-D267" not in _rule_ids(findings)


def test_llm_call_inside_obvious_unbounded_loop_flags_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "llm_loop.py",
        """
import openai

def poll(messages):
    while True:
        openai.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            max_tokens=200,
            timeout=20,
        )
""",
    )

    d267 = _d267_findings(findings)
    assert d267
    assert "obvious unbounded loop" in d267[0]["message"]


def test_langchain_client_bounds_suppress_invoke_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "langchain_bounded.py",
        """
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(max_tokens=300, request_timeout=20)

def answer(question):
    return llm.invoke(question)
""",
    )

    assert "SKY-D267" not in _rule_ids(findings)


def test_agent_executor_without_iteration_cap_flags_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "agent_no_iteration_cap.py",
        """
from langchain.agents import initialize_agent

def build_agent(tools, llm):
    return initialize_agent(tools, llm)
""",
    )

    d267 = _d267_findings(findings)
    assert d267
    assert "no iteration or time cap" in d267[0]["message"]


def test_agent_executor_with_iteration_cap_is_not_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "agent_iteration_cap.py",
        """
from langchain.agents import initialize_agent

def build_agent(tools, llm):
    return initialize_agent(tools, llm, max_iterations=5)
""",
    )

    assert "SKY-D267" not in _rule_ids(findings)

