import os
import importlib
import unittest
from unittest.mock import patch, MagicMock, mock_open

import skylos.api as api
from skylos.api import (
    upload_report,
    extract_snippet,
    get_git_info,
    _detect_ci,
    _extract_pr_number,
    _normalize_branch,
)


class TestSkylosApi(unittest.TestCase):
    @patch("subprocess.check_output")
    @patch("skylos.api.get_project_token")
    @patch("requests.post")
    def test_upload_report_success(self, mock_post, mock_token, mock_git):
        mock_token.return_value = "test_token_123"
        mock_git.side_effect = [b"mock_commit_hash\n", b"main\n", b"/mock/git/root\n"]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"scanId": "scan_abc_789"}
        mock_post.return_value = mock_response

        dummy_results = {
            "danger": [
                {
                    "file": "app.py",
                    "line": 10,
                    "message": "High risk",
                    "rule_id": "SKY-D001",
                }
            ],
            "quality": [],
        }

        result = upload_report(dummy_results, is_forced=True)

        self.assertTrue(result["success"])
        self.assertEqual(result["scan_id"], "scan_abc_789")

        args, kwargs = mock_post.call_args
        payload = kwargs["json"]
        self.assertEqual(payload["commit_hash"], "mock_commit_hash")
        self.assertTrue(payload["is_forced"])
        self.assertEqual(payload["version"], "2.1.0")

    @patch("skylos.api.get_project_token")
    def test_upload_report_no_token(self, mock_token):
        mock_token.return_value = None
        result = upload_report({})
        self.assertFalse(result["success"])
        self.assertEqual(
            result["error"],
            "No token found. Run 'skylos sync connect' or set SKYLOS_TOKEN.",
        )

    @patch("subprocess.check_output")
    @patch("skylos.api.get_project_token")
    @patch("requests.post")
    def test_upload_report_retry_logic(self, mock_post, mock_token, mock_git):
        mock_token.return_value = "token"
        mock_git.return_value = b"test\n"

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        result = upload_report({"danger": []})

        self.assertFalse(result["success"])
        self.assertEqual(mock_post.call_count, 3)
        self.assertIn("Server Error 500", result["error"])

    def test_extract_snippet_valid(self):
        content = "line1\nline2\nline3\nline4\nline5\n"
        with patch("builtins.open", mock_open(read_data=content)):
            snippet = extract_snippet("fake.py", 3, context=1)
            self.assertEqual(snippet, "line2\nline3\nline4")

    def test_extract_snippet_context_zero(self):
        content = "a\nb\nc\nd\n"
        with patch("builtins.open", mock_open(read_data=content)):
            snippet = extract_snippet("fake.py", 3, context=0)
            self.assertEqual(snippet, "c")

    def test_extract_snippet_missing_file_returns_none(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            snippet = extract_snippet("missing.py", 1, context=2)
            self.assertIsNone(snippet)

    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor", {}))
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("skylos.api.get_project_info")
    @patch("requests.post")
    def test_upload_report_whoami_failure_still_uploads(
        self, mock_post, mock_info, _, _mock_git_info, mock_token
    ):
        mock_token.return_value = "token"
        mock_info.return_value = None

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"scanId": "scan_ok"}
        mock_post.return_value = mock_response

        result = upload_report({"danger": []}, quiet=False)
        self.assertTrue(result["success"])
        self.assertEqual(result["scan_id"], "scan_ok")
        self.assertEqual(mock_post.call_count, 1)

    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor", {}))
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("requests.post")
    def test_upload_report_401_returns_invalid_token_error(
        self, mock_post, _, _mock_git_info, mock_token
    ):
        mock_token.return_value = "token"
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "Unauthorized"
        mock_post.return_value = resp

        result = upload_report({"danger": []})
        self.assertFalse(result["success"])
        self.assertEqual(
            result["error"],
            "Invalid API token. Run 'skylos sync connect' to reconnect.",
        )
        self.assertEqual(mock_post.call_count, 1)

    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor", {}))
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("requests.post")
    def test_retry_returns_last_error_text(
        self, mock_post, _, _mock_git_info, mock_token
    ):
        mock_token.return_value = "token"

        r1 = MagicMock(status_code=500, text="E1")
        r2 = MagicMock(status_code=502, text="E2")
        r3 = MagicMock(status_code=503, text="E3")
        mock_post.side_effect = [r1, r2, r3]

        result = upload_report({"danger": []})
        self.assertFalse(result["success"])
        self.assertEqual(mock_post.call_count, 3)
        self.assertIn("Server Error 503", result["error"])
        self.assertIn("E3", result["error"])

    def test_base_url_api_suffix_endpoints(self):
        old = os.environ.get("SKYLOS_API_URL")
        try:
            os.environ["SKYLOS_API_URL"] = "https://example.com/api"
            importlib.reload(api)
            self.assertEqual(api.REPORT_URL, "https://example.com/api/report")
            self.assertEqual(api.WHOAMI_URL, "https://example.com/api/sync/whoami")
        finally:
            if old is None:
                os.environ.pop("SKYLOS_API_URL", None)
            else:
                os.environ["SKYLOS_API_URL"] = old
            importlib.reload(api)

    @patch("skylos.api.SarifExporter")
    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor", {}))
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("requests.post")
    def test_prepare_for_sarif_normalizes_missing_fields(
        self, mock_post, _root, _git, mock_token, mock_exporter
    ):
        mock_token.return_value = "token"

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"scanId": "scan_norm"}
        mock_post.return_value = resp

        mock_exporter.return_value.generate.return_value = {"version": "2.1.0"}

        result = upload_report({"danger": [{"message": "oops"}]}, quiet=True)
        self.assertTrue(result["success"])

        all_findings = mock_exporter.call_args[0][0]
        self.assertEqual(len(all_findings), 1)
        f = all_findings[0]
        self.assertEqual(f["rule_id"], "SKY-D000")
        self.assertEqual(f["line_number"], 1)
        self.assertEqual(f["file_path"], "unknown")
        self.assertEqual(f["category"], "SECURITY")
        self.assertEqual(f["message"], "oops")

    @patch("skylos.api.SarifExporter")
    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor", {}))
    @patch("skylos.api.get_git_root", return_value="/mock/git/root")
    @patch("requests.post")
    def test_prepare_for_sarif_relpaths_when_git_root_present(
        self, mock_post, _root, _git, mock_token, mock_exporter
    ):
        mock_token.return_value = "token"

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"scanId": "scan_path"}
        mock_post.return_value = resp

        mock_exporter.return_value.generate.return_value = {"version": "2.1.0"}

        result = upload_report(
            {"danger": [{"file": "/mock/git/root/app.py", "line": 5, "message": "m"}]},
            quiet=True,
        )
        self.assertTrue(result["success"])

        all_findings = mock_exporter.call_args[0][0]
        f = all_findings[0]
        self.assertEqual(f["file_path"], "app.py")
        self.assertEqual(f["line_number"], 5)

    @patch("skylos.api.SarifExporter")
    @patch("skylos.api.get_project_token")
    @patch(
        "skylos.api.get_git_info",
        return_value=(
            "abc123",
            "feature/test",
            "jenkins-bot",
            {"provider": "jenkins", "build_number": "42", "pr_number": 99},
        ),
    )
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("requests.post")
    def test_upload_report_includes_ci_metadata(
        self, mock_post, _, _mock_git_info, mock_token, mock_exporter
    ):
        mock_token.return_value = "token"
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"scanId": "scan_ci"}
        mock_post.return_value = resp

        mock_exporter.return_value.generate.return_value = {"version": "2.1.0"}

        result = upload_report({"danger": []}, quiet=True)
        self.assertTrue(result["success"])

        args, kwargs = mock_post.call_args
        payload = kwargs["json"]
        self.assertEqual(payload["commit_hash"], "abc123")
        self.assertEqual(payload["branch"], "feature/test")
        self.assertEqual(payload["actor"], "jenkins-bot")
        self.assertEqual(payload["ci"]["provider"], "jenkins")
        self.assertEqual(payload["ci"]["pr_number"], 99)


class TestDetectCI(unittest.TestCase):
    def _clear_ci_env(self):
        ci_vars = [
            "GITHUB_ACTIONS",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_WORKFLOW",
            "GITHUB_ACTOR",
            "GITHUB_REPOSITORY",
            "GITHUB_REF",
            "GITHUB_SHA",
            "JENKINS_URL",
            "BUILD_NUMBER",
            "BUILD_URL",
            "JOB_NAME",
            "CHANGE_ID",
            "CHANGE_BRANCH",
            "CHANGE_TARGET",
            "GIT_BRANCH",
            "GIT_COMMIT",
            "CIRCLECI",
            "CIRCLE_BUILD_NUM",
            "CIRCLE_WORKFLOW_ID",
            "CIRCLE_USERNAME",
            "CIRCLE_BRANCH",
            "CIRCLE_SHA1",
            "CIRCLE_PULL_REQUEST",
            "GITLAB_CI",
            "CI_PIPELINE_ID",
            "CI_JOB_ID",
            "CI_COMMIT_SHA",
            "CI_COMMIT_BRANCH",
            "CI_MERGE_REQUEST_IID",
            "GITLAB_USER_LOGIN",
        ]
        for var in ci_vars:
            os.environ.pop(var, None)

    def setUp(self):
        self._clear_ci_env()

    def tearDown(self):
        self._clear_ci_env()

    def test_detect_github_actions(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_RUN_ID"] = "12345"
        os.environ["GITHUB_ACTOR"] = "octocat"
        os.environ["GITHUB_REPOSITORY"] = "owner/repo"
        os.environ["GITHUB_REF"] = "refs/heads/main"
        os.environ["GITHUB_SHA"] = "abc123def"

        provider, meta = _detect_ci()

        self.assertEqual(provider, "github_actions")
        self.assertEqual(meta["run_id"], "12345")
        self.assertEqual(meta["actor"], "octocat")
        self.assertEqual(meta["repo"], "owner/repo")
        self.assertEqual(meta["ref"], "refs/heads/main")
        self.assertEqual(meta["sha"], "abc123def")

    def test_detect_jenkins(self):
        os.environ["JENKINS_URL"] = "https://jenkins.example.com"
        os.environ["BUILD_NUMBER"] = "42"
        os.environ["BUILD_URL"] = "https://jenkins.example.com/job/test/42"
        os.environ["JOB_NAME"] = "test-job"
        os.environ["GIT_BRANCH"] = "origin/feature-branch"
        os.environ["GIT_COMMIT"] = "deadbeef123"

        provider, meta = _detect_ci()

        self.assertEqual(provider, "jenkins")
        self.assertEqual(meta["build_number"], "42")
        self.assertEqual(meta["job_name"], "test-job")
        self.assertEqual(meta["git_branch"], "origin/feature-branch")
        self.assertEqual(meta["git_commit"], "deadbeef123")

    def test_detect_jenkins_with_pr(self):
        os.environ["BUILD_NUMBER"] = "99"
        os.environ["CHANGE_ID"] = "123"
        os.environ["CHANGE_BRANCH"] = "feature/my-pr"
        os.environ["CHANGE_TARGET"] = "main"

        provider, meta = _detect_ci()

        self.assertEqual(provider, "jenkins")
        self.assertEqual(meta["change_id"], "123")
        self.assertEqual(meta["change_branch"], "feature/my-pr")
        self.assertEqual(meta["change_target"], "main")

    def test_detect_circleci(self):
        os.environ["CIRCLECI"] = "true"
        os.environ["CIRCLE_BUILD_NUM"] = "567"
        os.environ["CIRCLE_WORKFLOW_ID"] = "workflow-abc"
        os.environ["CIRCLE_USERNAME"] = "circleuser"
        os.environ["CIRCLE_BRANCH"] = "develop"
        os.environ["CIRCLE_SHA1"] = "cafebabe"
        os.environ["CIRCLE_PULL_REQUEST"] = "https://github.com/owner/repo/pull/45"

        provider, meta = _detect_ci()

        self.assertEqual(provider, "circleci")
        self.assertEqual(meta["build_num"], "567")
        self.assertEqual(meta["workflow_id"], "workflow-abc")
        self.assertEqual(meta["username"], "circleuser")
        self.assertEqual(meta["branch"], "develop")
        self.assertEqual(meta["sha1"], "cafebabe")
        self.assertEqual(meta["pr_url"], "https://github.com/owner/repo/pull/45")

    def test_detect_gitlab(self):
        os.environ["GITLAB_CI"] = "true"
        os.environ["CI_PIPELINE_ID"] = "999"
        os.environ["CI_JOB_ID"] = "888"
        os.environ["CI_COMMIT_SHA"] = "gitlab123"
        os.environ["CI_COMMIT_BRANCH"] = "feature/gitlab"
        os.environ["CI_MERGE_REQUEST_IID"] = "77"
        os.environ["GITLAB_USER_LOGIN"] = "gitlabuser"

        provider, meta = _detect_ci()

        self.assertEqual(provider, "gitlab")
        self.assertEqual(meta["pipeline_id"], "999")
        self.assertEqual(meta["job_id"], "888")
        self.assertEqual(meta["commit_sha"], "gitlab123")
        self.assertEqual(meta["commit_branch"], "feature/gitlab")
        self.assertEqual(meta["merge_request_iid"], "77")
        self.assertEqual(meta["user_login"], "gitlabuser")

    def test_detect_no_ci_returns_none(self):
        provider, meta = _detect_ci()

        self.assertIsNone(provider)
        self.assertEqual(meta, {})


class TestExtractPRNumber(unittest.TestCase):
    def setUp(self):
        os.environ.pop("SKYLOS_PR_NUMBER", None)
        os.environ.pop("GITHUB_REF", None)

    def tearDown(self):
        os.environ.pop("SKYLOS_PR_NUMBER", None)
        os.environ.pop("GITHUB_REF", None)

    def test_skylos_pr_number_override_wins(self):
        os.environ["SKYLOS_PR_NUMBER"] = "999"
        meta = {"change_id": "123"}

        result = _extract_pr_number("jenkins", meta)

        self.assertEqual(result, 999)

    def test_skylos_pr_number_invalid_returns_none(self):
        os.environ["SKYLOS_PR_NUMBER"] = "not-a-number"

        result = _extract_pr_number("jenkins", {})

        self.assertIsNone(result)

    def test_github_actions_pr_from_ref(self):
        os.environ["GITHUB_REF"] = "refs/pull/42/merge"

        result = _extract_pr_number("github_actions", {})

        self.assertEqual(result, 42)

    def test_github_actions_non_pr_ref_returns_none(self):
        os.environ["GITHUB_REF"] = "refs/heads/main"

        result = _extract_pr_number("github_actions", {})

        self.assertIsNone(result)

    def test_jenkins_change_id(self):
        meta = {"change_id": "123"}

        result = _extract_pr_number("jenkins", meta)

        self.assertEqual(result, 123)

    def test_jenkins_no_change_id_returns_none(self):
        meta = {"build_number": "42"}

        result = _extract_pr_number("jenkins", meta)

        self.assertIsNone(result)

    def test_circleci_pr_url_extraction(self):
        meta = {"pr_url": "https://github.com/owner/repo/pull/55"}

        result = _extract_pr_number("circleci", meta)

        self.assertEqual(result, 55)

    def test_circleci_pr_url_with_trailing_slash(self):
        meta = {"pr_url": "https://github.com/owner/repo/pull/66/"}

        result = _extract_pr_number("circleci", meta)

        self.assertEqual(result, 66)

    def test_circleci_no_pr_url_returns_none(self):
        meta = {"branch": "main"}

        result = _extract_pr_number("circleci", meta)

        self.assertIsNone(result)

    def test_circleci_non_pr_url_returns_none(self):
        meta = {"pr_url": "https://github.com/owner/repo/commit/abc"}

        result = _extract_pr_number("circleci", meta)

        self.assertIsNone(result)

    def test_gitlab_merge_request_iid(self):
        meta = {"merge_request_iid": "77"}

        result = _extract_pr_number("gitlab", meta)

        self.assertEqual(result, 77)

    def test_gitlab_no_mr_returns_none(self):
        meta = {"pipeline_id": "123"}

        result = _extract_pr_number("gitlab", meta)

        self.assertIsNone(result)

    def test_unknown_provider_returns_none(self):
        result = _extract_pr_number("unknown_ci", {"pr": "123"})

        self.assertIsNone(result)

    def test_none_provider_returns_none(self):
        result = _extract_pr_number(None, {})

        self.assertIsNone(result)


class TestNormalizeBranch(unittest.TestCase):
    def test_removes_refs_heads_prefix(self):
        result = _normalize_branch("refs/heads/main")
        self.assertEqual(result, "main")

    def test_removes_origin_prefix(self):
        result = _normalize_branch("origin/feature-branch")
        self.assertEqual(result, "feature-branch")

    def test_removes_both_prefixes_sequentially(self):
        result = _normalize_branch("refs/heads/origin/weird")
        self.assertEqual(result, "weird")

    def test_already_clean_branch_unchanged(self):
        result = _normalize_branch("feature/my-branch")
        self.assertEqual(result, "feature/my-branch")

    def test_main_unchanged(self):
        result = _normalize_branch("main")
        self.assertEqual(result, "main")

    def test_none_returns_none(self):
        result = _normalize_branch(None)
        self.assertIsNone(result)

    def test_empty_string_returns_empty(self):
        result = _normalize_branch("")
        self.assertEqual(result, "")

    def test_non_string_returns_as_is(self):
        result = _normalize_branch(123)
        self.assertEqual(result, 123)


class TestGetGitInfo(unittest.TestCase):
    def _clear_all_env(self):
        vars_to_clear = [
            "SKYLOS_COMMIT",
            "SKYLOS_BRANCH",
            "SKYLOS_ACTOR",
            "SKYLOS_PR_NUMBER",
            "GITHUB_ACTIONS",
            "GITHUB_SHA",
            "GITHUB_REF",
            "GITHUB_ACTOR",
            "JENKINS_URL",
            "BUILD_NUMBER",
            "GIT_COMMIT",
            "GIT_BRANCH",
            "CHANGE_ID",
            "CHANGE_BRANCH",
            "CIRCLECI",
            "CIRCLE_SHA1",
            "CIRCLE_BRANCH",
            "CIRCLE_USERNAME",
            "CIRCLE_PULL_REQUEST",
            "GITLAB_CI",
            "CI_COMMIT_SHA",
            "CI_COMMIT_BRANCH",
            "GITLAB_USER_LOGIN",
            "CI_MERGE_REQUEST_IID",
            "USER",
        ]
        for var in vars_to_clear:
            os.environ.pop(var, None)

    def setUp(self):
        self._clear_all_env()

    def tearDown(self):
        self._clear_all_env()

    @patch("subprocess.check_output")
    def test_local_environment_uses_git(self, mock_git):
        mock_git.side_effect = [b"localcommit123\n", b"my-branch\n"]
        os.environ["USER"] = "localuser"

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "localcommit123")
        self.assertEqual(branch, "my-branch")
        self.assertEqual(actor, "localuser")
        self.assertEqual(ci, {})

    @patch("subprocess.check_output")
    def test_env_overrides_always_win(self, mock_git):
        os.environ["SKYLOS_COMMIT"] = "override-sha"
        os.environ["SKYLOS_BRANCH"] = "override-branch"
        os.environ["SKYLOS_ACTOR"] = "override-actor"
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_SHA"] = "github-sha"
        os.environ["GITHUB_REF"] = "refs/heads/github-branch"
        os.environ["GITHUB_ACTOR"] = "github-actor"

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "override-sha")
        self.assertEqual(branch, "override-branch")
        self.assertEqual(actor, "override-actor")
        self.assertEqual(ci["provider"], "github_actions")

    @patch("subprocess.check_output")
    def test_github_actions_full_flow(self, mock_git):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_SHA"] = "ghsha123"
        os.environ["GITHUB_REF"] = "refs/pull/42/merge"
        os.environ["GITHUB_ACTOR"] = "octocat"
        os.environ["GITHUB_RUN_ID"] = "12345"

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "ghsha123")
        self.assertEqual(actor, "octocat")
        self.assertEqual(ci["provider"], "github_actions")
        self.assertEqual(ci["pr_number"], 42)
        self.assertEqual(ci["run_id"], "12345")

    @patch("subprocess.check_output")
    def test_jenkins_full_flow(self, mock_git):
        os.environ["JENKINS_URL"] = "https://jenkins.example.com"
        os.environ["BUILD_NUMBER"] = "99"
        os.environ["GIT_COMMIT"] = "jenkinssha"
        os.environ["CHANGE_BRANCH"] = "feature/jenkins-pr"
        os.environ["CHANGE_ID"] = "55"

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "jenkinssha")
        self.assertEqual(branch, "feature/jenkins-pr")
        self.assertEqual(ci["provider"], "jenkins")
        self.assertEqual(ci["pr_number"], 55)
        self.assertEqual(ci["build_number"], "99")

    @patch("subprocess.check_output")
    def test_jenkins_detached_head_uses_git_branch_env(self, mock_git):
        """Jenkins often checks out in detached HEAD; should use GIT_BRANCH."""
        os.environ["BUILD_NUMBER"] = "100"
        os.environ["GIT_COMMIT"] = "detachedsha"
        os.environ["GIT_BRANCH"] = "origin/main"

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "detachedsha")
        self.assertEqual(branch, "main")
        self.assertEqual(ci["provider"], "jenkins")

    @patch("subprocess.check_output")
    def test_circleci_full_flow(self, mock_git):
        os.environ["CIRCLECI"] = "true"
        os.environ["CIRCLE_SHA1"] = "circlesha"
        os.environ["CIRCLE_BRANCH"] = "develop"
        os.environ["CIRCLE_USERNAME"] = "circlebot"
        os.environ["CIRCLE_PULL_REQUEST"] = "https://github.com/o/r/pull/88"

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "circlesha")
        self.assertEqual(branch, "develop")
        self.assertEqual(actor, "circlebot")
        self.assertEqual(ci["provider"], "circleci")
        self.assertEqual(ci["pr_number"], 88)

    @patch("subprocess.check_output")
    def test_gitlab_full_flow(self, mock_git):
        os.environ["GITLAB_CI"] = "true"
        os.environ["CI_COMMIT_SHA"] = "gitlabsha"
        os.environ["CI_COMMIT_BRANCH"] = "feature/gitlab"
        os.environ["GITLAB_USER_LOGIN"] = "gitlabuser"
        os.environ["CI_MERGE_REQUEST_IID"] = "33"

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "gitlabsha")
        self.assertEqual(branch, "feature/gitlab")
        self.assertEqual(actor, "gitlabuser")
        self.assertEqual(ci["provider"], "gitlab")
        self.assertEqual(ci["pr_number"], 33)

    @patch("subprocess.check_output")
    def test_fallback_to_git_when_ci_vars_missing(self, mock_git):
        os.environ["JENKINS_URL"] = "https://jenkins.example.com"
        os.environ["BUILD_NUMBER"] = "1"

        mock_git.side_effect = [b"gitfallbacksha\n", b"fallback-branch\n"]

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "gitfallbacksha")
        self.assertEqual(branch, "fallback-branch")
        self.assertEqual(ci["provider"], "jenkins")

    @patch("subprocess.check_output")
    def test_git_failure_returns_unknown(self, mock_git):
        mock_git.side_effect = Exception("git not found")

        commit, branch, actor, ci = get_git_info()

        self.assertEqual(commit, "unknown")
        self.assertEqual(branch, "unknown")
        self.assertEqual(ci, {})

    @patch("subprocess.check_output")
    def test_ci_metadata_excludes_none_values(self, mock_git):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_SHA"] = "sha123"
        os.environ["GITHUB_REF"] = "refs/heads/main"

        commit, branch, actor, ci = get_git_info()

        self.assertNotIn("run_id", ci)
        self.assertEqual(ci["sha"], "sha123")


class TestVerifyReport(unittest.TestCase):
    @patch("skylos.api.get_project_token")
    def test_verify_report_no_token(self, mock_token):
        mock_token.return_value = None

        from skylos.api import verify_report

        result = verify_report({})

        self.assertFalse(result["success"])
        self.assertIn("token", result["error"].lower())

    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_project_info")
    def test_verify_report_free_plan_rejected(self, mock_info, mock_token):
        mock_token.return_value = "token"
        mock_info.return_value = {"plan": "free"}

        from skylos.api import verify_report

        result = verify_report({})

        self.assertFalse(result["success"])
        self.assertIn("Pro", result["error"])

    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_project_info")
    @patch("skylos.api.get_git_info", return_value=("sha", "branch", "actor", {}))
    @patch("skylos.api.get_git_root", return_value=None)
    def test_verify_report_no_findings(self, _, _git, mock_info, mock_token):
        mock_token.return_value = "token"
        mock_info.return_value = {"plan": "pro"}

        from skylos.api import verify_report

        result = verify_report({"danger": [], "secrets": []})

        self.assertFalse(result["success"])
        self.assertIn("No security findings", result["error"])


if __name__ == "__main__":
    unittest.main()