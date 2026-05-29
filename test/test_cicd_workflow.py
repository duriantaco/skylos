import pytest
import yaml
from skylos.cicd.workflow import generate_workflow
from skylos.rules.config.cicd.github_actions import scan_github_actions


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
    assert "Pull Skylos Cloud Policy" in step_names
    assert "Run Skylos Analysis" in step_names
    assert "Quality Gate" in step_names
    assert "GitHub Annotations" in step_names
    assert "PR Review Comments" in step_names
    quality_gate = next(s for s in steps if s.get("name") == "Quality Gate")
    assert "--advisory" not in quality_gate["run"]
    pr_review = next(s for s in steps if s.get("name") == "PR Review Comments")
    assert "--evidence-cards" in pr_review["run"]


def test_workflow_can_generate_advisory_gate():
    content = generate_workflow(advisory_gate=True)
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    quality_gate = next(s for s in steps if s.get("name") == "Quality Gate")
    assert "--advisory" in quality_gate["run"]


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
    assert "--sca" not in content


def test_workflow_includes_dependency_scan_by_default():
    content = generate_workflow()
    assert "--sca" in content


def test_workflow_uses_baseline_by_default():
    content = generate_workflow()
    assert "--baseline" in content


def test_workflow_omits_baseline_when_disabled():
    content = generate_workflow(use_baseline=False)
    assert "--baseline" not in content


def test_workflow_pull_request_analysis_is_diff_aware():
    content = generate_workflow()
    assert 'pr_base_ref="origin/${GITHUB_BASE_REF:-main}"' in content
    assert '--diff-base "$pr_base_ref"' in content
    assert '--diff "$pr_base_ref"' in content
    assert "github.base_ref" not in content


def test_workflow_quotes_base_ref_in_pr_review_step():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    pr_review = next(s for s in steps if s.get("name") == "PR Review Comments")
    assert 'pr_base_ref="origin/${GITHUB_BASE_REF:-main}"' in pr_review["run"]
    assert '--diff-base "$pr_base_ref"' in pr_review["run"]
    assert "github.base_ref" not in pr_review["run"]


def test_workflow_no_llm_by_default():
    content = generate_workflow()
    assert "SKYLOS_API_KEY" not in content
    assert "agent review" not in content
    assert "agent scan" not in content


def test_workflow_with_llm():
    content = generate_workflow(use_llm=True, model="claude-sonnet-4-5-20250929")
    assert "agent scan" in content
    assert "--changed" in content
    assert "claude-sonnet-4-5-20250929" in content
    assert "SKYLOS_API_KEY" in content


def test_workflow_claude_model_adds_anthropic_key():
    content = generate_workflow(use_llm=True, model="claude-sonnet-4-20250514")
    assert "ANTHROPIC_API_KEY" in content


def test_workflow_non_claude_model_no_anthropic_key():
    content = generate_workflow(use_llm=True, model="gpt-4.1")
    assert "ANTHROPIC_API_KEY" not in content


def test_workflow_permissions():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    assert parsed["permissions"] == {"contents": "read"}
    job = parsed["jobs"]["skylos"]
    assert job["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
        "id-token": "write",
    }
    assert job["timeout-minutes"] == 15


def test_generated_workflow_passes_skylos_actions_audit(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "skylos.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(generate_workflow(), encoding="utf-8")

    assert scan_github_actions(tmp_path) == []


def test_generated_claude_workflow_passes_skylos_actions_audit(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "skylos.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        generate_workflow(
            use_upload=True,
            use_llm=True,
            use_defend=True,
            use_claude_security=True,
            model="gpt-4.1",
        ),
        encoding="utf-8",
    )

    assert scan_github_actions(tmp_path) == []


def test_workflow_schedule_trigger():
    content = generate_workflow(triggers=["schedule"])
    parsed = yaml.safe_load(content)
    assert "schedule" in parsed.get("on") or parsed.get(True)


def test_workflow_no_upload_by_default():
    content = generate_workflow()
    assert "--upload" not in content
    assert "Pull Skylos Cloud Policy" in content
    assert "skylos sync pull" in content
    assert "SKYLOS_TOKEN" not in content


def test_workflow_with_upload():
    content = generate_workflow(use_upload=True)
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    sync_step = next(s for s in steps if s.get("name") == "Pull Skylos Cloud Policy")
    analysis_step = next(s for s in steps if s.get("name") == "Run Skylos Analysis")
    assert "skylos sync pull" in sync_step["run"]
    assert "--upload" in analysis_step["run"]
    assert analysis_step["env"] == {
        "SKYLOS_COMMIT": "${{ github.event.pull_request.head.sha || github.sha }}",
        "SKYLOS_BRANCH": "${{ github.event.pull_request.head.ref || github.ref_name }}",
    }
    assert "env" not in sync_step


def test_workflow_upload_with_llm():
    content = generate_workflow(use_upload=True, use_llm=True, model="gpt-4.1")
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    analysis_step = next(s for s in steps if s.get("name") == "Run Skylos Analysis")
    assert "--upload" in analysis_step["run"]
    assert "SKYLOS_COMMIT" in analysis_step["env"]
    llm_step = next(s for s in steps if s.get("name") == "Skylos Agent Review (LLM)")
    assert "SKYLOS_API_KEY" in llm_step["env"]


def test_workflow_scan_path_is_monorepo_aware():
    content = generate_workflow(scan_path="apps/api", use_upload=True, use_defend=True)
    assert "skylos apps/api" in content
    assert "skylos defend apps/api" in content
    assert '--json -o "$RUNNER_TEMP/defense-results.json"' in content
    assert '--defense-input "$RUNNER_TEMP/defense-results.json"' in content
    assert "--defense-input defense-results.json" not in content


def test_workflow_prefixes_leading_dash_scan_path():
    content = generate_workflow(scan_path="-service")
    assert "skylos ./-service" in content


@pytest.mark.parametrize("control_char", ["\n", "\r", "\t", "\x7f"])
def test_workflow_rejects_scan_path_control_characters(control_char):
    payload = f"apps/api{control_char}      - name: Injected Step"

    with pytest.raises(ValueError, match="scan_path"):
        generate_workflow(
            scan_path=payload,
            use_llm=True,
            use_defend=True,
        )


def test_workflow_pins_installed_skylos_version():
    content = generate_workflow(skylos_version="4.9.0")
    assert "python -m pip install skylos==4.9.0" in content
