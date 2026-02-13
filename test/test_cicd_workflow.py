import yaml
import pytest

from skylos.cicd.workflow import generate_workflow


def test_default_workflow_valid_yaml():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    assert parsed["name"] == "Skylos Analysis"
    assert "on" in parsed or True in parsed
    assert "jobs" in parsed


def test_workflow_has_all_steps():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    step_names = [s.get("name", "") for s in steps]

    assert "Checkout" in step_names
    assert "Setup Python" in step_names
    assert "Install Skylos" in step_names
    assert "Run Skylos Analysis" in step_names
    assert "Quality Gate" in step_names
    assert "GitHub Annotations" in step_names
    assert "PR Review Comments" in step_names


def test_workflow_triggers():
    content = generate_workflow(triggers=["pull_request", "push"])
    parsed = yaml.safe_load(content)
    assert "pull_request" in parsed.get("on") or parsed.get(True)
    assert "push" in parsed.get("on") or parsed.get(True)


def test_workflow_custom_python_version():
    content = generate_workflow(python_version="3.11")
    assert "'3.11'" in content


def test_workflow_analysis_flags():
    content = generate_workflow(analysis_types=["security", "quality"])
    assert "--danger" in content
    assert "--quality" in content
    assert "--secrets" not in content


def test_workflow_no_llm_by_default():
    content = generate_workflow()
    assert "SKYLOS_API_KEY" not in content
    assert "agent review" not in content


def test_workflow_with_llm():
    content = generate_workflow(use_llm=True, model="claude-sonnet-4-5-20250929")
    assert "agent review" in content
    assert "claude-sonnet-4-5-20250929" in content
    assert "SKYLOS_API_KEY" in content


def test_workflow_baseline_flag():
    content = generate_workflow(use_baseline=True)
    assert "--baseline" in content


def test_workflow_no_baseline():
    content = generate_workflow(use_baseline=False)
    assert "--baseline" not in content


def test_workflow_permissions():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    perms = parsed["permissions"]
    assert perms["contents"] == "read"
    assert perms["pull-requests"] == "write"


def test_workflow_schedule_trigger():
    content = generate_workflow(triggers=["schedule"])
    parsed = yaml.safe_load(content)
    assert "schedule" in parsed.get("on") or parsed.get(True)
