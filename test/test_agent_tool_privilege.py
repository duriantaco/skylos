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


def test_shell_tool_registered_to_langchain_agent_flags_d264(tmp_path):
    findings = _scan_one(
        tmp_path,
        "agent_shell_tool.py",
        """
from langchain.agents import initialize_agent
from langchain_community.tools import ShellTool

def build_agent(llm):
    return initialize_agent([ShellTool()], llm, max_iterations=5)
""",
    )

    assert "SKY-D264" in _rule_ids(findings)


def test_tool_wrapping_os_system_registered_to_agent_flags_d264(tmp_path):
    findings = _scan_one(
        tmp_path,
        "agent_os_system_tool.py",
        """
import os
from langchain.agents import Tool, initialize_agent

shell_tool = Tool(name="shell", func=os.system, description="run a command")

def build_agent(llm):
    return initialize_agent([shell_tool], llm, max_iterations=5)
""",
    )

    assert "SKY-D264" in _rule_ids(findings)


def test_load_tools_terminal_registered_to_agent_flags_d264(tmp_path):
    findings = _scan_one(
        tmp_path,
        "agent_load_tools.py",
        """
from langchain.agents import initialize_agent, load_tools

def build_agent(llm):
    tools = load_tools(["terminal"])
    return initialize_agent(tools, llm, max_iterations=5)
""",
    )

    assert "SKY-D264" in _rule_ids(findings)


def test_crewai_agent_with_python_repl_tool_flags_d264(tmp_path):
    findings = _scan_one(
        tmp_path,
        "crewai_agent.py",
        """
from crewai import Agent
from langchain_experimental.tools import PythonREPLTool

agent = Agent(
    role="ops",
    goal="operate systems",
    backstory="operator",
    tools=[PythonREPLTool()],
)
""",
    )

    assert "SKY-D264" in _rule_ids(findings)


def test_tool_wrapper_without_langchain_initialize_token_flags_d264(tmp_path):
    findings = _scan_one(
        tmp_path,
        "generic_agent_tool.py",
        """
import os
from platform_agent import Agent, Tool

shell_tool = Tool(func=os.system, name="shell")
agent = Agent(tools=[shell_tool])
""",
    )

    assert "SKY-D264" in _rule_ids(findings)


def test_safe_lookup_tool_registered_to_agent_is_not_d264(tmp_path):
    findings = _scan_one(
        tmp_path,
        "safe_agent_tool.py",
        """
from langchain.agents import Tool, initialize_agent

def lookup(query: str) -> str:
    return "ok"

lookup_tool = Tool(name="lookup", func=lookup, description="read-only lookup")

def build_agent(llm):
    return initialize_agent([lookup_tool], llm, max_iterations=5)
""",
    )

    assert "SKY-D264" not in _rule_ids(findings)
