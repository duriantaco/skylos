import json

import pytest

from skylos.cicd.agent_review import AgentReviewError, run_agent_review
from skylos.cicd.agent_review_workflow import generate_agent_review_workflow

REVIEW_ID = "bceace5a-dc9e-4c39-bc96-c670c4354c62"
ORIGIN = "https://skylos.dev"
REVIEW_URL = f"{ORIGIN}/api/pr-reviews/{REVIEW_ID}"


class Response:
    def __init__(self, data, status=200):
        self.status_code = status
        self.body = json.dumps(data).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def iter_content(self, chunk_size):
        yield self.body


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return next(self.responses)


@pytest.fixture
def environ():
    return {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": "owner/repo",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/oidc?audience=old",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "github-request-token",
    }


@pytest.fixture
def bundle():
    return {
        "token": "ephemeral-runner-token",
        "repository": "owner/repo",
        "prNumber": 5,
        "baseSha": "a" * 40,
        "headSha": "b" * 40,
        "model": "gpt-4.1",
        "proxyBaseUrl": REVIEW_URL + "/v1",
        "files": [{"path": "src/app.py", "content": "answer = 42\nprint(answer)\n"}],
    }


def completion(findings=None, *, finish_reason="stop"):
    return Response(
        {
            "choices": [
                {
                    "finish_reason": finish_reason,
                    "message": {"content": json.dumps({"findings": findings or []})},
                }
            ]
        }
    )


def test_runs_bound_review_without_executing_source(environ, bundle, tmp_path):
    marker = tmp_path / "executed"
    bundle["files"][0]["content"] = (
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    )
    finding = {
        "rule_id": "SKY-L000",
        "issue_type": "bug",
        "severity": "medium",
        "message": "Possible failure",
        "line": 2,
        "end_line": None,
        "confidence": "high",
        "explanation": None,
        "suggestion": None,
        "symbol": None,
        "security_details": None,
    }
    session = Session(
        [
            Response({"value": "oidc-token"}),
            Response(bundle),
            completion([finding]),
            Response({"ok": True}),
        ]
    )

    assert run_agent_review(REVIEW_ID, ORIGIN, environ=environ, session=session) == 0

    assert not marker.exists()
    assert len(session.calls) == 4
    assert session.calls[0][1].endswith("audience=skylos")
    assert "audience=old" not in session.calls[0][1]
    assert session.calls[1][1] == REVIEW_URL + "/runner"
    assert session.calls[1][2]["headers"]["Authorization"] == "Bearer oidc-token"
    _, url, request = session.calls[2]
    assert url == REVIEW_URL + "/v1/chat/completions"
    assert request["json"]["stream"] is False
    assert request["json"]["model"] == "gpt-4.1"
    assert request["headers"]["Authorization"] == "Bearer ephemeral-runner-token"
    result = session.calls[3][2]["json"]
    assert result["status"] == "completed"
    assert result["findings"][0] == {
        "file": "src/app.py",
        "line": 2,
        "rule_id": "SKY-L000",
        "message": "Possible failure",
        "severity": "MEDIUM",
        "category": "bug",
        "explanation": None,
        "suggestion": None,
        "confidence": "high",
        "security_details": None,
    }
    assert result["summary"]["headSha"] == "b" * 40
    assert all(call[2]["allow_redirects"] is False for call in session.calls)


@pytest.mark.parametrize(
    "path",
    [
        "../app.py",
        "/app.py",
        "src/../app.py",
        "src\\app.py",
        "src//app.py",
        "C:/app.py",
        ".skylos.toml",
        "src/\napp.py",
    ],
)
def test_rejects_unsafe_source_before_model_call(environ, bundle, path):
    bundle["files"][0]["path"] = path
    session = Session(
        [Response({"value": "oidc-token"}), Response(bundle), Response({"ok": True})]
    )
    with pytest.raises(AgentReviewError, match="unsafe"):
        run_agent_review(REVIEW_ID, ORIGIN, environ=environ, session=session)
    assert session.calls[-1][1] == REVIEW_URL + "/complete"
    assert session.calls[-1][2]["json"]["status"] == "failed"
    assert len(session.calls) == 3


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "other/repo"),
        ("prNumber", True),
        ("headSha", "HEAD"),
        ("baseSha", "main"),
        ("proxyBaseUrl", "https://attacker.example/v1"),
        ("model", "gpt-4.1\n--key"),
    ],
)
def test_binds_identity_and_credentials_to_cloud(environ, bundle, field, value):
    bundle[field] = value
    session = Session(
        [Response({"value": "oidc-token"}), Response(bundle), Response({"ok": True})]
    )
    with pytest.raises(AgentReviewError):
        run_agent_review(REVIEW_ID, ORIGIN, environ=environ, session=session)
    assert len(session.calls) == 3
    assert all("attacker.example" not in call[1] for call in session.calls)


@pytest.mark.parametrize("case", ["file", "count", "total", "duplicate"])
def test_source_limits_fail_before_any_paid_call(environ, bundle, case):
    if case == "file":
        bundle["files"][0]["content"] = "x" * (65536 + 1)
    elif case == "count":
        bundle["files"] = [
            {"path": f"{index}.py", "content": "pass"} for index in range(31)
        ]
    elif case == "total":
        bundle["files"] = [
            {"path": f"{index}.py", "content": "x" * 65536} for index in range(9)
        ]
    else:
        bundle["files"] *= 2
    session = Session(
        [Response({"value": "oidc-token"}), Response(bundle), Response({"ok": True})]
    )
    with pytest.raises(AgentReviewError):
        run_agent_review(REVIEW_ID, ORIGIN, environ=environ, session=session)
    assert len(session.calls) == 3
    assert session.calls[-1][2]["json"]["status"] == "failed"


@pytest.mark.parametrize(
    "reply",
    [
        Response({"error": "provider failed"}),
        completion(finish_reason="length"),
        completion([{"severity": "nonsense"}]),
        completion([{"line": 999}]),
        Response({}, status=429),
    ],
)
def test_model_errors_fail_instead_of_reporting_clean(environ, bundle, reply):
    session = Session(
        [
            Response({"value": "oidc-token"}),
            Response(bundle),
            reply,
            Response({"ok": True}),
        ]
    )
    with pytest.raises(AgentReviewError):
        run_agent_review(REVIEW_ID, ORIGIN, environ=environ, session=session)
    assert len(session.calls) == 4
    assert session.calls[-1][2]["json"]["status"] == "failed"
    assert session.calls[-1][2]["json"]["findings"] == []


def test_requires_dispatch_and_trusted_oidc_host(environ):
    session = Session([])
    environ["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://attacker.example/oidc"
    with pytest.raises(AgentReviewError, match="OIDC"):
        run_agent_review(REVIEW_ID, ORIGIN, environ=environ, session=session)
    environ["GITHUB_EVENT_NAME"] = "pull_request"
    with pytest.raises(AgentReviewError, match="workflow_dispatch"):
        run_agent_review(REVIEW_ID, ORIGIN, environ=environ, session=session)
    assert session.calls == []


@pytest.mark.parametrize(
    "review_id,origin",
    [
        ("../runner", ORIGIN),
        (REVIEW_ID, "http://skylos.dev"),
        (REVIEW_ID, "https://token@skylos.dev"),
        (REVIEW_ID, "https://skylos.dev/path"),
    ],
)
def test_rejects_untrusted_entry_parameters(environ, review_id, origin):
    session = Session([])
    with pytest.raises(AgentReviewError):
        run_agent_review(review_id, origin, environ=environ, session=session)
    assert session.calls == []


def test_workflow_has_no_checkout_or_provider_key():
    workflow = generate_agent_review_workflow(skylos_version="4.51.0")
    assert "'skylos==4.51.0'" in workflow
    assert "workflow_dispatch:" in workflow
    assert "review_id:" in workflow
    assert "id-token: write" in workflow
    assert "checkout" not in workflow.lower().replace("checked out", "")
    assert "API_KEY" not in workflow
    assert "pull_request:" not in workflow
    assert '"$SKYLOS_REVIEW_ID"' in workflow
    assert "cancel-in-progress: false" in workflow


@pytest.mark.parametrize(
    "version", ["latest", "4.51.0 --extra-index-url x", "4.51.0\nmalicious"]
)
def test_workflow_requires_exact_release(version):
    with pytest.raises(ValueError):
        generate_agent_review_workflow(skylos_version=version)


def test_cli_dispatches_approved_review_command(monkeypatch):
    from types import SimpleNamespace

    from skylos.cicd import agent_review
    from skylos.commands.cicd_cmd import run_cicd_command

    messages = []
    calls = []

    def run(review_id, cloud_url):
        calls.append((review_id, cloud_url))
        return 0

    monkeypatch.setattr(agent_review, "run_agent_review", run)
    result = run_cicd_command(
        ["agent-review", "--review-id", REVIEW_ID],
        console_factory=lambda: SimpleNamespace(print=messages.append),
        load_config_func=None,
        run_gate_interaction_func=None,
        emit_github_annotations_func=None,
    )
    assert result == 0
    assert calls == [(REVIEW_ID, ORIGIN)]
    assert messages == ["Skylos agent review completed"]
