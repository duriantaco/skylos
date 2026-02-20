import json
import pathlib
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from skylos.pipeline import (
    _norm,
    _empty_result,
    _infer_root,
    _is_duplicate,
    run_static_on_files,
    run_pipeline,
)

FAKE_STATIC_RESULT = {
    "definitions": {
        "mod.used_func": {
            "name": "used_func",
            "file": "/proj/a.py",
            "line": 10,
            "type": "function",
        },
        "mod.dead_func": {
            "name": "dead_func",
            "file": "/proj/a.py",
            "line": 20,
            "type": "function",
        },
        "mod.MyClass": {
            "name": "MyClass",
            "file": "/proj/b.py",
            "line": 1,
            "type": "class",
        },
    },
    "unused_functions": [
        {
            "name": "dead_func",
            "file": "/proj/a.py",
            "line": 20,
            "message": "Unused function: dead_func",
            "confidence": 75,
        },
    ],
    "unused_imports": [
        {
            "name": "os",
            "file": "/proj/a.py",
            "line": 1,
            "message": "Unused import: os",
            "confidence": 90,
        },
    ],
    "unused_variables": [],
    "unused_parameters": [],
    "unused_classes": [],
    "danger": [
        {
            "name": "eval_call",
            "file": "/proj/a.py",
            "line": 30,
            "message": "Use of eval()",
            "confidence": 95,
        },
    ],
    "quality": [
        {
            "name": "long_func",
            "file": "/proj/b.py",
            "line": 50,
            "message": "Function too long",
            "confidence": 60,
        },
    ],
    "secrets": [],
}


def _fresh_static():
    return json.loads(json.dumps(FAKE_STATIC_RESULT))


def _agent_args(**overrides):
    defaults = dict(
        path="/proj",
        quiet=False,
        llm_only=False,
        static_only=False,
        skip_verification=False,
        min_confidence="low",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _console():
    c = MagicMock()
    c.print = MagicMock()
    return c


def _llm_finding(
    file="/proj/a.py",
    line=99,
    message="SQL injection",
    rule_id="SEC-001",
    severity="high",
    confidence="high",
    issue_type="security",
):
    f = MagicMock()
    f.location.file = file
    f.location.line = line
    f.message = message
    f.rule_id = rule_id
    f.severity.value = severity
    f.confidence.value = confidence
    f.issue_type.value = issue_type
    return f


P_ANALYZE = "skylos.analyzer.analyze"
P_EXCLUDE = "skylos.constants.parse_exclude_folders"
P_CUSTOM = "skylos.sync.get_custom_rules"
P_LLM = "skylos.llm.analyzer.SkylosLLM"
P_LLM_CONF = "skylos.llm.analyzer.AnalyzerConfig"
P_CONF = "skylos.llm.schemas.Confidence"
P_VERIFIER = "skylos.llm.dead_code_verifier.DeadCodeVerifierAgent"
P_AGENTCFG = "skylos.llm.agents.AgentConfig"
P_PROGRESS = "rich.progress.Progress"
P_STATIC_FN = "skylos.pipeline.run_static_on_files"


class TestNorm:
    def test_resolves_path(self, tmp_path):
        f = tmp_path / "a.py"
        f.touch()
        assert _norm(f) == str(f.resolve())

    def test_fallback_on_bad_input(self):
        assert _norm("\x00bad") == "\x00bad"


class TestEmptyResult:
    def test_has_all_keys(self):
        r = _empty_result()
        for k in [
            "definitions",
            "unused_functions",
            "unused_imports",
            "unused_variables",
            "unused_parameters",
            "unused_classes",
            "danger",
            "quality",
            "secrets",
        ]:
            assert k in r

    def test_definitions_is_dict_rest_are_lists(self):
        r = _empty_result()
        assert r["definitions"] == {}
        for k in list(r):
            if k != "definitions":
                assert r[k] == []


class TestInferRoot:
    def test_finds_git_root(self, tmp_path):
        (tmp_path / ".git").mkdir()
        sub = tmp_path / "pkg"
        sub.mkdir()
        f = sub / "mod.py"
        f.touch()
        assert _infer_root(f) == tmp_path.resolve()

    def test_finds_pyproject_root(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        f = tmp_path / "src" / "mod.py"
        f.parent.mkdir()
        f.touch()
        assert _infer_root(f) == tmp_path.resolve()

    def test_accepts_directory(self, tmp_path):
        (tmp_path / ".git").mkdir()
        sub = tmp_path / "pkg"
        sub.mkdir()
        assert _infer_root(sub) == tmp_path.resolve()


class TestIsDuplicate:
    def test_same_file_line_message_prefix(self):
        existing = [
            {
                "file": "/proj/a.py",
                "line": 30,
                "message": "Use of eval() is dangerous and should be avoided",
            }
        ]
        new = {
            "file": "/proj/a.py",
            "line": 30,
            "message": "Use of eval() is dangerous",
        }
        assert _is_duplicate(new, existing) is True

    def test_nearby_line_within_tolerance(self):
        existing = [
            {
                "file": "/proj/a.py",
                "line": 30,
                "message": "Use of eval() is dangerous and risky",
            }
        ]
        new = {
            "file": "/proj/a.py",
            "line": 32,
            "message": "Use of eval() is dangerous",
        }
        assert _is_duplicate(new, existing) is True

    def test_different_file_not_dup(self):
        existing = [{"file": "/proj/a.py", "line": 30, "message": "Use of eval()"}]
        new = {"file": "/proj/b.py", "line": 30, "message": "Use of eval()"}
        assert _is_duplicate(new, existing) is False

    def test_far_line_not_dup(self):
        existing = [{"file": "/proj/a.py", "line": 30, "message": "Use of eval()"}]
        new = {"file": "/proj/a.py", "line": 100, "message": "Use of eval()"}
        assert _is_duplicate(new, existing) is False

    def test_different_message_not_dup(self):
        existing = [{"file": "/proj/a.py", "line": 30, "message": "Use of eval()"}]
        new = {
            "file": "/proj/a.py",
            "line": 30,
            "message": "SQL injection vulnerability found here",
        }
        assert _is_duplicate(new, existing) is False

    def test_empty_existing(self):
        assert _is_duplicate({"file": "x", "line": 1, "message": "m"}, []) is False


class TestRunStaticOnFiles:
    @patch(P_CUSTOM, return_value=None)
    @patch(P_EXCLUDE, return_value={"venv", ".venv"})
    @patch(P_ANALYZE)
    def test_analyzes_project_root_not_per_file(self, mock_analyze, _exc, _cust):
        mock_analyze.return_value = json.dumps(FAKE_STATIC_RESULT)

        run_static_on_files(
            ["/proj/a.py", "/proj/b.py"],
            project_root=pathlib.Path("/proj"),
        )

        mock_analyze.assert_called_once()
        assert mock_analyze.call_args[0][0] == "/proj"

    @patch(P_CUSTOM, return_value=None)
    @patch(P_EXCLUDE, return_value={"venv"})
    @patch(P_ANALYZE)
    def test_filters_findings_to_target_files(self, mock_analyze, _exc, _cust):
        mock_analyze.return_value = json.dumps(FAKE_STATIC_RESULT)

        result = run_static_on_files(
            ["/proj/a.py"],
            project_root=pathlib.Path("/proj"),
        )

        assert len(result["unused_functions"]) == 1
        assert len(result["danger"]) == 1
        # b.py quality finding filtered out
        assert len(result["quality"]) == 0

    @patch(P_CUSTOM, return_value=None)
    @patch(P_EXCLUDE, return_value={"venv"})
    @patch(P_ANALYZE)
    def test_keeps_full_defs_map(self, mock_analyze, _exc, _cust):
        mock_analyze.return_value = json.dumps(FAKE_STATIC_RESULT)

        result = run_static_on_files(
            ["/proj/a.py"],
            project_root=pathlib.Path("/proj"),
        )

        assert "mod.MyClass" in result["definitions"]
        assert "mod.dead_func" in result["definitions"]

    @patch(P_CUSTOM, return_value=None)
    @patch(P_EXCLUDE, return_value={"venv", ".venv"})
    @patch(P_ANALYZE)
    def test_passes_exclude_folders(self, mock_analyze, _exc, _cust):
        mock_analyze.return_value = json.dumps(FAKE_STATIC_RESULT)

        run_static_on_files(["/proj/a.py"], project_root=pathlib.Path("/proj"))

        kwargs = mock_analyze.call_args[1]
        assert "exclude_folders" in kwargs
        assert "venv" in kwargs["exclude_folders"]

    def test_empty_files_returns_empty(self):
        assert run_static_on_files([]) == _empty_result()

    @patch(P_CUSTOM, return_value=None)
    @patch(P_EXCLUDE, return_value=set())
    @patch(P_ANALYZE, side_effect=Exception("boom"))
    def test_returns_empty_on_analyze_failure(self, _a, _e, _c):
        result = run_static_on_files(["/proj/a.py"], project_root=pathlib.Path("/proj"))
        assert result == _empty_result()

    @patch(P_CUSTOM, return_value=None)
    @patch(P_EXCLUDE, return_value=set())
    @patch(P_ANALYZE)
    def test_copies_analysis_summary(self, mock_analyze, _e, _c):
        data = {**FAKE_STATIC_RESULT, "analysis_summary": {"total_files": 42}}
        mock_analyze.return_value = json.dumps(data)

        result = run_static_on_files(["/proj/a.py"], project_root=pathlib.Path("/proj"))
        assert result["analysis_summary"]["total_files"] == 42


class TestPipelinePhase1:
    @patch(P_LLM)
    @patch(P_STATIC_FN, return_value=_fresh_static())
    @patch(P_PROGRESS)
    def test_categorises_static_findings(self, _prog, _static, mock_llm, tmp_path):
        mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        findings = run_pipeline(
            path=str(proj),
            model="t",
            api_key="k",
            agent_args=_agent_args(static_only=True, skip_verification=True),
            console=_console(),
            changed_files=[str(proj / "a.py")],
        )

        categories = {f.get("_category") for f in findings}
        assert "dead_code" in categories
        assert "security" in categories

    @patch(P_LLM)
    @patch(P_STATIC_FN, return_value=_fresh_static())
    @patch(P_PROGRESS)
    def test_dead_code_gets_static_source(self, _prog, _static, mock_llm, tmp_path):
        mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        findings = run_pipeline(
            path=str(proj),
            model="t",
            api_key="k",
            agent_args=_agent_args(static_only=True, skip_verification=True),
            console=_console(),
            changed_files=[str(proj / "a.py")],
        )

        dead = [f for f in findings if f["_category"] == "dead_code"]
        assert all(f["_source"] == "static" for f in dead)

    @patch(P_LLM)
    @patch(P_ANALYZE)
    @patch(P_PROGRESS)
    def test_llm_only_mode_skips_static(self, _prog, mock_analyze, mock_llm, tmp_path):
        mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        run_pipeline(
            path=str(proj),
            model="t",
            api_key="k",
            agent_args=_agent_args(llm_only=True),
            console=_console(),
        )

        mock_analyze.assert_not_called()

    @patch(P_LLM)
    @patch(P_STATIC_FN, return_value=_fresh_static())
    @patch(P_PROGRESS)
    def test_generates_message_for_dead_code(self, _prog, _static, mock_llm, tmp_path):
        mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        findings = run_pipeline(
            path=str(proj),
            model="t",
            api_key="k",
            agent_args=_agent_args(static_only=True, skip_verification=True),
            console=_console(),
            changed_files=[str(proj / "a.py")],
        )

        dead = [f for f in findings if f["_category"] == "dead_code"]
        for f in dead:
            assert f.get("message"), f"Dead code finding missing message: {f}"


class TestPipelinePhase2a:
    def _run_with_verifier(self, verified_results, tmp_path, **extra_args):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("def dead_func(): pass")

        mock_verifier = MagicMock()
        mock_verifier.test_api_connection.return_value = (True, "OK")
        mock_verifier.annotate_findings.return_value = verified_results

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
            patch(P_VERIFIER, return_value=mock_verifier),
            patch(P_AGENTCFG),
        ):
            mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(static_only=True, **extra_args),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        return findings, mock_verifier

    def test_true_positive_gets_high_confidence(self, tmp_path):
        verified = [
            {
                "name": "dead_func",
                "file": "/proj/a.py",
                "line": 20,
                "message": "Unused function: dead_func",
                "_source": "static",
                "_category": "dead_code",
                "_llm_verdict": "TRUE_POSITIVE",
            },
        ]
        findings, _ = self._run_with_verifier(verified, tmp_path)

        dead = [f for f in findings if f.get("_category") == "dead_code"]
        assert len(dead) == 1
        assert dead[0]["_source"] == "static+llm"
        assert dead[0]["_confidence"] == "high"

    def test_false_positive_demoted_not_dropped(self, tmp_path):
        verified = [
            {
                "name": "dead_func",
                "file": "/proj/a.py",
                "line": 20,
                "_category": "dead_code",
                "_llm_verdict": "FALSE_POSITIVE",
                "_llm_challenged": True,
            },
        ]
        findings, _ = self._run_with_verifier(verified, tmp_path)

        dead = [f for f in findings if f.get("_category") == "dead_code"]
        assert len(dead) == 1
        assert dead[0]["_confidence"] == "low"
        assert dead[0]["_llm_challenged"] is True

    def test_uncertain_treated_as_static_only(self, tmp_path):
        verified = [
            {
                "name": "dead_func",
                "file": "/proj/a.py",
                "line": 20,
                "_category": "dead_code",
                "_llm_verdict": "UNCERTAIN",
            },
        ]
        findings, _ = self._run_with_verifier(verified, tmp_path)

        dead = [f for f in findings if f.get("_category") == "dead_code"]
        assert len(dead) == 1
        # UNCERTAIN = LLM couldn't verify → keep as static-only medium confidence
        assert dead[0]["_confidence"] == "medium"
        assert dead[0]["_source"] == "static"

    def test_verifier_receives_defs_map_and_source_cache(self, tmp_path):
        _, mock_verifier = self._run_with_verifier([], tmp_path)

        kwargs = mock_verifier.annotate_findings.call_args[1]
        assert "defs_map" in kwargs
        assert "source_cache" in kwargs
        assert kwargs["confidence_range"] == (10, 100)

    def test_skip_verification_passes_through(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(static_only=True, skip_verification=True),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        dead = [f for f in findings if f["_category"] == "dead_code"]
        assert len(dead) == 2  # unused_functions + unused_imports
        assert all(f["_confidence"] == "medium" for f in dead)

    def test_verifier_failure_falls_back_gracefully(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        mock_verifier = MagicMock()
        mock_verifier.test_api_connection.return_value = (True, "OK")
        mock_verifier.annotate_findings.side_effect = Exception("LLM down")

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
            patch(P_VERIFIER, return_value=mock_verifier),
            patch(P_AGENTCFG),
        ):
            mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(static_only=True),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        dead = [f for f in findings if f["_category"] == "dead_code"]
        assert len(dead) == 2
        assert all(f["_confidence"] == "medium" for f in dead)


class TestPipelinePhase2b:
    def _run_with_llm_findings(self, llm_findings_list, tmp_path, **kw):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        llm_result = MagicMock()
        llm_result.findings = llm_findings_list

        with (
            patch(P_STATIC_FN, return_value=_empty_result()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_llm.return_value.analyze_files.return_value = llm_result

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(**kw),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        return findings

    def test_llm_findings_marked_needs_review(self, tmp_path):
        findings = self._run_with_llm_findings(
            [_llm_finding(issue_type="security")], tmp_path
        )

        llm = [f for f in findings if f["_source"] == "llm"]
        assert len(llm) == 1
        assert llm[0]["_needs_review"] is True
        assert llm[0]["_ci_blocking"] is False

    def test_llm_dead_code_discoveries_included(self, tmp_path):
        findings = self._run_with_llm_findings(
            [
                _llm_finding(
                    issue_type="dead_code",
                    line=10,
                    rule_id="DC-001",
                    message="unused func a",
                ),
                _llm_finding(
                    issue_type="unused",
                    line=20,
                    rule_id="DC-002",
                    message="unused func b",
                ),
                _llm_finding(
                    issue_type="unreachable",
                    line=30,
                    rule_id="DC-003",
                    message="unreachable code",
                ),
                _llm_finding(
                    issue_type="security",
                    line=40,
                    rule_id="SEC-001",
                    message="SQL injection",
                ),
            ],
            tmp_path,
        )

        llm = [f for f in findings if f["_source"] == "llm"]
        # All 4 findings should now be included (dead code no longer dropped)
        assert len(llm) == 4

    def test_deduplicates_against_static(self, tmp_path):
        llm_dup = _llm_finding(
            file="/proj/a.py",
            line=31,
            message="Use of eval()",
            issue_type="security",
        )

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        llm_result = MagicMock()
        llm_result.findings = [llm_dup]

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_llm.return_value.analyze_files.return_value = llm_result

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(skip_verification=True),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        llm_only = [f for f in findings if f["_source"] == "llm"]
        assert len(llm_only) == 0

    def test_static_only_skips_llm_analysis(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

            run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(static_only=True, skip_verification=True),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

            mock_llm.return_value.analyze_files.assert_not_called()

    def test_llm_failure_doesnt_crash(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_llm.return_value.analyze_files.side_effect = Exception("API down")

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(skip_verification=True),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        assert len(findings) > 0

    def test_llm_confidence_always_medium(self, tmp_path):
        findings = self._run_with_llm_findings(
            [_llm_finding(issue_type="security", confidence="high")], tmp_path
        )

        llm = [f for f in findings if f["_source"] == "llm"]
        assert llm[0]["_confidence"] == "medium"


class TestPipelineOutput:
    def test_high_confidence_sorted_before_medium(self, tmp_path):
        verified = [
            {
                "name": "dead_func",
                "file": "/proj/a.py",
                "line": 20,
                "_category": "dead_code",
                "_llm_verdict": "TRUE_POSITIVE",
                "_source": "static",
                "message": "Unused function: dead_func",
            },
            {
                "name": "os",
                "file": "/proj/a.py",
                "line": 1,
                "_category": "dead_code",
                "_llm_verdict": "UNCERTAIN",
                "_source": "static",
                "message": "Unused import: os",
            },
        ]

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        mock_verifier = MagicMock()
        mock_verifier.test_api_connection.return_value = (True, "OK")
        mock_verifier.annotate_findings.return_value = verified

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
            patch(P_VERIFIER, return_value=mock_verifier),
            patch(P_AGENTCFG),
        ):
            mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(static_only=True),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        confidences = [f["_confidence"] for f in findings]
        high_idxs = [i for i, c in enumerate(confidences) if c == "high"]
        med_idxs = [i for i, c in enumerate(confidences) if c == "medium"]

        if high_idxs and med_idxs:
            assert max(high_idxs) < min(med_idxs)

    def test_every_finding_has_confidence(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_llm.return_value.analyze_files.return_value = MagicMock(
                findings=[_llm_finding(issue_type="security")]
            )

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(skip_verification=True),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        for f in findings:
            assert "_confidence" in f, f"Missing _confidence: {f}"
            assert f["_confidence"] in ("high", "medium")

    def test_every_finding_has_source_and_category(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_llm.return_value.analyze_files.return_value = MagicMock(
                findings=[_llm_finding(issue_type="security")]
            )

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(skip_verification=True),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        for f in findings:
            assert "_source" in f
            assert "_category" in f


class TestPipelineIntegration:
    def test_full_flow_phase1_2a_2b(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("def dead_func(): pass\nimport os\neval('x')")

        verified = [
            {
                "name": "dead_func",
                "file": "/proj/a.py",
                "line": 20,
                "_category": "dead_code",
                "_source": "static",
                "_llm_verdict": "TRUE_POSITIVE",
                "message": "Unused function: dead_func",
            },
            {
                "name": "os",
                "file": "/proj/a.py",
                "line": 1,
                "_category": "dead_code",
                "_source": "static",
                "_llm_verdict": "FALSE_POSITIVE",
                "_llm_challenged": True,
                "message": "Unused import: os",
            },
        ]

        mock_verifier = MagicMock()
        mock_verifier.test_api_connection.return_value = (True, "OK")
        mock_verifier.annotate_findings.return_value = verified

        llm_sec = _llm_finding(
            file="/proj/a.py",
            line=99,
            message="Hardcoded credential found",
            issue_type="security",
        )

        with (
            patch(P_STATIC_FN, return_value=_fresh_static()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
            patch(P_VERIFIER, return_value=mock_verifier),
            patch(P_AGENTCFG),
        ):
            mock_llm.return_value.analyze_files.return_value = MagicMock(
                findings=[llm_sec]
            )

            findings = run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(),
                console=_console(),
                changed_files=[str(proj / "a.py")],
            )

        sources = {f["_source"] for f in findings}
        assert "static+llm" in sources
        assert "llm" in sources
        assert "static" in sources

        llm_only = [f for f in findings if f["_source"] == "llm"]
        assert all(f["_needs_review"] is True for f in llm_only)
        assert all(f["_ci_blocking"] is False for f in llm_only)

        dead = [f for f in findings if f.get("_category") == "dead_code"]
        dead_names = [f.get("name") for f in dead]
        # "os" is now kept (demoted to low confidence, not dropped)
        assert "os" in dead_names
        os_finding = [f for f in dead if f.get("name") == "os"][0]
        assert os_finding["_confidence"] == "low"
        assert os_finding["_llm_challenged"] is True

    def test_review_mode_calls_run_static_on_files(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        with (
            patch(P_STATIC_FN) as mock_static,
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_static.return_value = _empty_result()
            mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

            changed = [str(proj / "a.py")]
            run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(),
                console=_console(),
                changed_files=changed,
            )

            mock_static.assert_called_once()
            assert mock_static.call_args[0][0] == changed

    def test_analyze_mode_calls_run_analyze_directly(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x = 1")

        with (
            patch(P_ANALYZE) as mock_analyze,
            patch(P_EXCLUDE, return_value=set()),
            patch(P_PROGRESS),
            patch(P_LLM) as mock_llm,
        ):
            mock_analyze.return_value = json.dumps(_empty_result())
            mock_llm.return_value.analyze_files.return_value = MagicMock(findings=[])

            run_pipeline(
                path=str(proj),
                model="t",
                api_key="k",
                agent_args=_agent_args(),
                console=_console(),
            )

            mock_analyze.assert_called_once()
            assert mock_analyze.call_args[0][0] == str(proj)
