"""GitLab job authentication transport; no live credentials or HTTP calls."""

import json
from types import SimpleNamespace

import pytest

import skylos.api as api
import skylos.cloud.sync as sync

_JWT = "fixture-header.fixture-payload.fixture-signature"


@pytest.fixture(autouse=True)
def isolated_ci(monkeypatch, tmp_path):
    for key in (
        "SKYLOS_TOKEN",
        "SKYLOS_GITLAB_ID_TOKEN",
        "SKYLOS_PROJECT_ROOT",
        "GITLAB_CI",
        "CI_SERVER_URL",
        "GITHUB_ACTIONS",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "JENKINS_URL",
        "BUILD_NUMBER",
        "CIRCLECI",
        "SKYLOS_COMMIT",
        "SKYLOS_BRANCH",
        "SKYLOS_ACTOR",
        "SKYLOS_PR_NUMBER",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(api, "_get_repo_root_for_link", lambda: tmp_path)
    monkeypatch.setattr(api, "_read_json", lambda path: None)
    monkeypatch.setattr(api, "get_key", lambda name: None)
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(sync, "_find_repo_root", lambda: tmp_path)
    monkeypatch.setattr(sync, "_linked_project_id", lambda root: None)
    monkeypatch.setattr(sync, "_load_creds", lambda: {})

    def no_network(*args, **kwargs):
        pytest.fail("GitLab auth tests must replace each HTTP transport explicitly")

    monkeypatch.setattr(api.requests, "get", no_network)
    monkeypatch.setattr(api.requests, "post", no_network)


def _gitlab(monkeypatch):
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.com")
    monkeypatch.setenv("SKYLOS_GITLAB_ID_TOKEN", _JWT)


@pytest.mark.parametrize("getter", [api.get_project_token, sync.get_token])
def test_gitlab_job_token_selected_without_network(monkeypatch, getter):
    _gitlab(monkeypatch)
    assert getter() == f"gitlab_oidc:{_JWT}"


@pytest.mark.parametrize("getter", [api.get_project_token, sync.get_token])
def test_explicit_project_token_keeps_priority(monkeypatch, getter):
    _gitlab(monkeypatch)
    monkeypatch.setenv("SKYLOS_TOKEN", "fixture-project-token")
    assert getter() == "fixture-project-token"


@pytest.mark.parametrize(
    "ci,server",
    [
        ("", "https://gitlab.com"),
        ("false", "https://gitlab.com"),
        ("TRUE", "https://gitlab.com"),
        ("true", "https://gitlab.example.invalid"),
        ("true", "http://gitlab.com"),
        ("true", "https://gitlab.com/"),
        ("true", "https://gitlab.com.invalid"),
        ("true", "https://gitlab.com:443"),
    ],
)
def test_gitlab_auto_auth_requires_exact_gitlab_com_ci_context(monkeypatch, ci, server):
    _gitlab(monkeypatch)
    monkeypatch.setenv("GITLAB_CI", ci)
    monkeypatch.setenv("CI_SERVER_URL", server)
    assert api._try_gitlab_oidc_token() is None
    assert api.get_project_token() is None
    assert sync.get_token() is None


@pytest.mark.parametrize(
    "value", ["", "token\n", "token value", "token\tvalue", "é", "x" * 16_385]
)
def test_gitlab_token_rejects_empty_unbounded_or_header_unsafe_values(
    monkeypatch, value
):
    _gitlab(monkeypatch)
    monkeypatch.setenv("SKYLOS_GITLAB_ID_TOKEN", value)
    assert api._try_gitlab_oidc_token() is None


@pytest.mark.parametrize("builder", [api._build_auth_headers, sync._auth_headers])
@pytest.mark.parametrize(
    "token,expected",
    [
        (
            f"gitlab_oidc:{_JWT}",
            {"Authorization": f"Bearer {_JWT}", "X-Skylos-Auth": "gitlab_oidc"},
        ),
        (
            "oidc:github-fixture",
            {"Authorization": "Bearer github-fixture", "X-Skylos-Auth": "oidc"},
        ),
        ("project-fixture", {"Authorization": "Bearer project-fixture"}),
    ],
)
def test_auth_headers_distinguish_gitlab_github_and_project_tokens(
    builder, token, expected
):
    assert builder(token) == expected


def test_github_oidc_existing_precedence_and_headers_are_unchanged(monkeypatch):
    _gitlab(monkeypatch)
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: "oidc:github-fixture")
    assert api.get_project_token() == "oidc:github-fixture"
    assert sync.get_token() == "oidc:github-fixture"


@pytest.mark.parametrize(
    "endpoint", ["/api/sync/whoami", "/api/sync/config", "/api/sync/suppressions"]
)
def test_sync_handshake_uses_gitlab_auth_header(monkeypatch, endpoint):
    _gitlab(monkeypatch)
    seen = []

    def get(url, **kwargs):
        seen.append((url, kwargs))
        return SimpleNamespace(
            status_code=200, json=lambda: {"ok": True}, raise_for_status=lambda: None
        )

    monkeypatch.setattr(sync.requests, "get", get)
    assert sync.api_get(endpoint, sync.get_token()) == {"ok": True}
    assert len(seen) == 1
    url, options = seen[0]
    assert url.endswith(endpoint)
    assert options["headers"] == {
        "Authorization": f"Bearer {_JWT}",
        "X-Skylos-Auth": "gitlab_oidc",
    }
    assert _JWT not in url


def test_project_info_uses_gitlab_auth_header_and_credit_lookup_is_not_attempted(
    monkeypatch,
):
    _gitlab(monkeypatch)
    headers = []

    def get(url, **kwargs):
        assert url == api.WHOAMI_URL
        headers.append(kwargs["headers"])
        return SimpleNamespace(
            status_code=200, json=lambda: {"project": {"id": "fixture-project"}}
        )

    monkeypatch.setattr(api.requests, "get", get)
    token = api.get_project_token()
    assert api.get_project_info(token)["project"]["id"] == "fixture-project"
    assert api.get_credit_balance(token) is None
    assert headers == [
        {"Authorization": f"Bearer {_JWT}", "X-Skylos-Auth": "gitlab_oidc"}
    ]


def test_gitlab_metadata_preserves_namespace_and_mr_context_without_tokens(monkeypatch):
    _gitlab(monkeypatch)
    values = {
        "CI_PROJECT_ID": "104",
        "CI_PROJECT_PATH": "org/subgroup/service",
        "CI_PROJECT_NAMESPACE": "org/subgroup",
        "CI_PIPELINE_ID": "201",
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_JOB_ID": "302",
        "CI_COMMIT_SHA": "a" * 40,
        "CI_COMMIT_BRANCH": "",
        "CI_MERGE_REQUEST_IID": "12",
        "CI_MERGE_REQUEST_SOURCE_PROJECT_ID": "104",
        "CI_MERGE_REQUEST_TARGET_PROJECT_ID": "104",
        "CI_MERGE_REQUEST_SOURCE_PROJECT_PATH": "org/subgroup/service",
        "CI_MERGE_REQUEST_TARGET_PROJECT_PATH": "org/subgroup/service",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature/example",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        "CI_DEFAULT_BRANCH": "main",
        "CI_COMMIT_REF_PROTECTED": "false",
        "CI_MERGE_REQUEST_DIFF_BASE_SHA": "b" * 40,
        "GITLAB_USER_LOGIN": "fixture-user",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(api, "_read_git_head", lambda: ("fallback", "HEAD"))
    commit, branch, actor, ci = api.get_git_info()
    assert (commit, branch, actor) == ("a" * 40, "feature/example", "fixture-user")
    assert ci["provider"] == "gitlab"
    assert ci["server_url"] == "https://gitlab.com"
    assert (
        ci["project_id"]
        == ci["merge_request_source_project_id"]
        == ci["merge_request_target_project_id"]
        == "104"
    )
    assert (
        ci["project_path"]
        == ci["merge_request_source_project_path"]
        == ci["merge_request_target_project_path"]
        == "org/subgroup/service"
    )
    assert ci["pr_number"] == 12
    assert ci["merge_request_target_branch_name"] == "main"
    assert ci["merge_request_diff_base_sha"] == "b" * 40
    metadata = api._build_report_metadata(
        commit_hash=commit,
        branch=branch,
        actor=actor,
        ci=ci,
        project_root="packages/api",
    )
    encoded = json.dumps(metadata)
    assert _JWT not in encoded
    assert "SKYLOS_GITLAB_ID_TOKEN" not in encoded
    assert metadata["project_root"] == "packages/api"


def test_upload_uses_common_protocol_without_putting_token_in_payload(
    monkeypatch, caplog
):
    _gitlab(monkeypatch)
    payload = {
        "runs": [],
        "ci": {"provider": "gitlab", "project_id": "104"},
        "project_root": "",
    }
    prepared = SimpleNamespace(
        legacy_payload=payload, metadata=payload, grade_data=None
    )
    monkeypatch.setattr(api, "_prepare_report_upload", lambda *args, **kwargs: prepared)
    monkeypatch.setattr(
        api, "_should_use_legacy_inline_report_upload", lambda value: True
    )
    seen = []

    def post(url, *, headers, json, **kwargs):
        seen.append((url, headers, json))
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "success": True,
                "scan_id": "fixture-saved-scan",
                "quality_gate_passed": True,
            },
            text="ok",
            headers={},
        )

    monkeypatch.setattr(api.requests, "post", post)
    response = api.upload_report({"danger": []}, quiet=True)
    assert response["success"] is True
    assert len(seen) == 1
    url, headers, body = seen[0]
    assert url == api.REPORT_URL
    assert headers["Authorization"] == f"Bearer {_JWT}"
    assert headers["X-Skylos-Auth"] == "gitlab_oidc"
    assert _JWT not in json.dumps(body)
    assert _JWT not in caplog.text


def test_gitlab_job_tokens_are_not_partially_printed_by_sync():
    assert sync.mask_token(f"gitlab_oidc:{_JWT}") == "<GitLab job ID token>"


@pytest.mark.parametrize("builder", [api._build_auth_headers, sync._auth_headers])
@pytest.mark.parametrize(
    "root,expected",
    [("", ""), (".", ""), ("apps//api", "apps/api"), ("apps\\api", "apps/api")],
)
def test_managed_auth_carries_explicit_normalized_project_root(
    monkeypatch, builder, root, expected
):
    monkeypatch.setenv("SKYLOS_PROJECT_ROOT", root)
    assert builder(f"gitlab_oidc:{_JWT}")["X-Skylos-Project-Root"] == expected
    assert "X-Skylos-Project-Root" not in builder("oidc:github-fixture")
    assert "X-Skylos-Project-Root" not in builder("fixture-project-token")


@pytest.mark.parametrize(
    "root",
    [
        "/tmp/app",
        "../app",
        "apps/../app",
        "C:\\app",
        "https://example.invalid/app",
        "app\x00name",
    ],
)
def test_invalid_explicit_root_never_becomes_a_header(monkeypatch, root):
    # Direct helper invocation supports testing NUL without invalid process env.
    from skylos.cloud.gitlab import managed_project_root

    monkeypatch.setattr("skylos.cloud.gitlab.os.getenv", lambda key: root)
    with pytest.raises(ValueError, match="repository-relative"):
        managed_project_root()


def test_known_git_relative_cwd_is_a_root_hint_but_unrelated_cwd_is_not(
    tmp_path, monkeypatch
):
    from skylos.cloud.gitlab import managed_project_root

    assert managed_project_root(tmp_path, cwd=tmp_path / "apps" / "api") == "apps/api"
    assert managed_project_root(tmp_path / "repo", cwd=tmp_path / "other") is None
    assert managed_project_root() is None


def test_upload_root_mismatch_fails_before_report_http(monkeypatch):
    _gitlab(monkeypatch)
    monkeypatch.setenv("SKYLOS_PROJECT_ROOT", "apps/api")
    prepared = SimpleNamespace(metadata={"project_root": "apps/web"})
    monkeypatch.setattr(api, "_prepare_report_upload", lambda *a, **k: prepared)
    response = api.upload_report({}, quiet=True)
    assert response == {
        "success": False,
        "error": "GitLab project-root binding does not match scan root.",
    }


@pytest.mark.parametrize("failure", ["timeout", "connection", 302, 307, 500, 501, 503])
def test_managed_post_uses_one_long_attempt_and_redacts_ambiguous_errors(
    monkeypatch, failure
):
    calls = []
    secret = "fixture.secret.must.not.be.logged"

    def post(url, **kwargs):
        calls.append((url, kwargs))
        if failure == "timeout":
            raise api.requests.exceptions.Timeout(secret)
        if failure == "connection":
            raise api.requests.exceptions.ConnectionError(secret)
        return SimpleNamespace(status_code=failure, text=secret)

    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(
        api.REPORT_URL,
        {"X-Skylos-Auth": "gitlab_oidc"},
        {},
        quiet=True,
        accepted_statuses=(200, 501),
    )
    assert response is None
    assert len(calls) == 1
    assert calls[0][1]["timeout"] == 300
    assert calls[0][1]["allow_redirects"] is False
    assert "outcome unknown" in error
    assert "Check Cloud" in error
    assert secret not in error


@pytest.mark.parametrize("failure_at", ["init", "complete"])
@pytest.mark.parametrize("failure", ["timeout", 500])
def test_managed_artifact_failure_never_falls_back_to_another_upload(
    monkeypatch, failure_at, failure
):
    _gitlab(monkeypatch)
    prepared = SimpleNamespace(metadata={"project_root": ""}, grade_data=None)
    monkeypatch.setattr(api, "_prepare_report_upload", lambda *a, **k: prepared)
    monkeypatch.setattr(
        api, "_should_use_legacy_inline_report_upload", lambda value: False
    )
    monkeypatch.setattr(api, "_build_report_artifacts", lambda value: {})
    monkeypatch.setattr(api, "_build_report_init_payload", lambda *a: {})

    def no_fallback(*args, **kwargs):
        pytest.fail("ambiguous managed request must not fall back or re-upload")

    monkeypatch.setattr(api, "upload_report_compatibility", no_fallback)
    calls = []

    def post(url, **kwargs):
        calls.append(url)
        assert kwargs["timeout"] == 300
        if failure_at == "complete" and url == api.REPORT_INIT_URL:
            return SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "scan_id": "fixture-scan",
                    "upload_id": "fixture-upload",
                    "artifacts": {},
                },
                text="ok",
            )
        if failure == "timeout":
            raise api.requests.exceptions.Timeout("private fixture detail")
        return SimpleNamespace(status_code=500, text="private fixture detail")

    monkeypatch.setattr(api.requests, "post", post)
    result = api.upload_report({}, quiet=True)
    assert result["success"] is False
    assert result["code"] == "GITLAB_DELIVERY_UNKNOWN"
    assert result["gitlab_delivery_exit_code"] == 2
    assert calls == (
        [api.REPORT_INIT_URL]
        if failure_at == "init"
        else [api.REPORT_INIT_URL, api.REPORT_COMPLETE_URL]
    )


def test_nonmanaged_post_retains_existing_retries_and_timeout(monkeypatch):
    calls = []

    def post(url, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(status_code=500, text="fixture")

    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(
        api.REPORT_URL, {"X-Skylos-Auth": "oidc"}, {}, quiet=True, timeout=17
    )
    assert response is None and "Server Error 500" in error
    assert len(calls) == 3
    assert all(call["timeout"] == 17 for call in calls)
    assert all("allow_redirects" not in call for call in calls)


@pytest.mark.parametrize("status", [404, 405])
def test_managed_unsupported_artifact_endpoint_does_not_use_lossy_fallback(
    monkeypatch, status
):
    _gitlab(monkeypatch)
    prepared = SimpleNamespace(
        metadata={"project_root": ""},
        grade_data=None,
        legacy_payload_size_bytes=4_000_001,
    )
    monkeypatch.setattr(api, "_prepare_report_upload", lambda *a, **k: prepared)
    monkeypatch.setattr(
        api, "_should_use_legacy_inline_report_upload", lambda value: False
    )
    monkeypatch.setattr(api, "_build_report_artifacts", lambda value: {})
    monkeypatch.setattr(api, "_build_report_init_payload", lambda *a: {})
    calls = []

    def post(url, **kwargs):
        calls.append(url)
        return SimpleNamespace(status_code=status, text="fixture")

    def no_fallback(*args, **kwargs):
        pytest.fail("managed uploads must never use lossy compact fallback")

    monkeypatch.setattr(api.requests, "post", post)
    monkeypatch.setattr(api, "upload_report_compatibility", no_fallback)
    result = api.upload_report({}, quiet=True)
    assert result["code"] == "UPLOAD_PROTOCOL_UNSUPPORTED"
    assert result["gitlab_delivery_exit_code"] == 2
    assert (
        "Lossy compatibility fallback is disabled" in result["gitlab_delivery_message"]
    )
    assert calls == [api.REPORT_INIT_URL]


def test_managed_compatibility_entrypoint_rejects_without_building_or_posting(
    monkeypatch,
):
    def no_post(*args, **kwargs):
        pytest.fail("managed uploads must not post compact findings")

    monkeypatch.setattr(api.requests, "post", no_post)
    result = api.upload_report_compatibility(
        "gitlab_oidc:fixture", object(), quiet=True
    )
    assert result["success"] is False
    assert result["gitlab_delivery_exit_code"] == 2
    assert "Lossy compatibility fallback is disabled" in result["error"]
