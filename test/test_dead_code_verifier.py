import json
from unittest.mock import MagicMock, patch

import pytest

from skylos.llm.dead_code_verifier import (
    Verdict,
    CONFIDENCE_CAP,
    CONFIDENCE_FLOOR,
    apply_verdict,
    _normalize_path,
    _parse_confidence,
    _parse_int,
    build_verification_context,
    DeadCodeVerifierAgent,
)


def _finding(**overrides):
    base = {
        "name": "dead_func",
        "full_name": "mod.dead_func",
        "file": "/proj/a.py",
        "line": 20,
        "type": "function",
        "message": "Unused function: dead_func",
        "confidence": 75,
        "references": 0,
        "calls": [],
        "called_by": [],
        "decorators": [],
    }
    base.update(overrides)
    return base


def _defs_map():
    return {
        "mod.dead_func": {
            "name": "dead_func",
            "file": "/proj/a.py",
            "line": 20,
            "type": "function",
        },
        "mod.used_func": {
            "name": "used_func",
            "file": "/proj/a.py",
            "line": 10,
            "type": "function",
        },
    }


def _source_cache():
    lines = (
        ["import os\n"] * 10
        + [
            "# line 11\n",
            "# line 12\n",
            "# line 13\n",
            "# line 14\n",
            "# line 15\n",
            "# line 16\n",
            "# line 17\n",
            "# line 18\n",
            "# line 19\n",
            "def dead_func():\n",
            "    pass\n",
        ]
        + ["# filler\n"] * 10
    )
    return {"/proj/a.py": "".join(lines)}


class TestVerdict:
    def test_values(self):
        assert Verdict.TRUE_POSITIVE.value == "TRUE_POSITIVE"
        assert Verdict.FALSE_POSITIVE.value == "FALSE_POSITIVE"
        assert Verdict.UNCERTAIN.value == "UNCERTAIN"

    def test_from_string(self):
        assert Verdict("TRUE_POSITIVE") is Verdict.TRUE_POSITIVE

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            Verdict("BOGUS")


class TestApplyVerdict:
    def test_true_positive_adds_15(self):
        f = _finding(confidence=70)
        assert apply_verdict(f, Verdict.TRUE_POSITIVE) == 85

    def test_false_positive_subtracts_30(self):
        f = _finding(confidence=70)
        assert apply_verdict(f, Verdict.FALSE_POSITIVE) == 40

    def test_uncertain_no_change(self):
        f = _finding(confidence=70)
        assert apply_verdict(f, Verdict.UNCERTAIN) == 70

    def test_caps_at_95(self):
        f = _finding(confidence=90)
        assert apply_verdict(f, Verdict.TRUE_POSITIVE) == CONFIDENCE_CAP

    def test_floors_at_20(self):
        f = _finding(confidence=30)
        assert apply_verdict(f, Verdict.FALSE_POSITIVE) == CONFIDENCE_FLOOR

    def test_string_confidence_high(self):
        f = _finding(confidence="high")
        assert apply_verdict(f, Verdict.TRUE_POSITIVE) == 95

    def test_string_confidence_medium(self):
        f = _finding(confidence="medium")
        assert apply_verdict(f, Verdict.UNCERTAIN) == 60

    def test_string_confidence_low(self):
        f = _finding(confidence="low")
        assert apply_verdict(f, Verdict.FALSE_POSITIVE) == CONFIDENCE_FLOOR


class TestNormalizePath:
    def test_resolves(self, tmp_path):
        f = tmp_path / "a.py"
        f.touch()
        assert _normalize_path(f) == str(f.resolve())

    def test_fallback(self):
        assert _normalize_path("\x00bad") == "\x00bad"


class TestParseHelpers:
    def test_parse_confidence_int(self):
        assert _parse_confidence(80) == 80

    def test_parse_confidence_string_high(self):
        assert _parse_confidence("high") == 85

    def test_parse_confidence_string_medium(self):
        assert _parse_confidence("medium") == 60

    def test_parse_confidence_string_low(self):
        assert _parse_confidence("low") == 40

    def test_parse_confidence_unknown_string(self):
        assert _parse_confidence("very_high") == 60

    def test_parse_confidence_none(self):
        assert _parse_confidence(None) == 60

    def test_parse_int_int(self):
        assert _parse_int(42) == 42

    def test_parse_int_string(self):
        assert _parse_int("7") == 7

    def test_parse_int_bad_string(self):
        assert _parse_int("abc", default=99) == 99

    def test_parse_int_none(self):
        assert _parse_int(None) == 0


class TestBuildVerificationContext:
    def test_includes_name_and_file(self):
        ctx = build_verification_context(_finding(), _defs_map())
        assert "dead_func" in ctx
        assert "/proj/a.py" in ctx

    def test_includes_references_count(self):
        ctx = build_verification_context(_finding(references=0), _defs_map())
        assert "References found across entire project: 0" in ctx

    def test_includes_call_graph(self):
        f = _finding(called_by=["main.run"], calls=["os.path.join"])
        ctx = build_verification_context(f, _defs_map())
        assert "main.run" in ctx
        assert "os.path.join" in ctx

    def test_no_callers_message(self):
        ctx = build_verification_context(_finding(called_by=[]), _defs_map())
        assert "NOBODY" in ctx

    def test_includes_decorators(self):
        f = _finding(decorators=["@app.route"])
        ctx = build_verification_context(f, _defs_map())
        assert "@app.route" in ctx

    def test_includes_source_lines(self):
        source = _source_cache()
        lines = source["/proj/a.py"].splitlines()
        ctx = build_verification_context(_finding(line=20), _defs_map(), lines)
        assert ">>>" in ctx
        assert "def dead_func" in ctx

    def test_no_source_lines(self):
        ctx = build_verification_context(_finding(), _defs_map(), None)
        assert "Code Context" not in ctx

    def test_defs_map_match(self):
        ctx = build_verification_context(_finding(), _defs_map())
        assert "Found in defs_map as: `mod.dead_func`" in ctx

    def test_defs_map_no_match(self):
        ctx = build_verification_context(
            _finding(name="ghost", full_name="mod.ghost"), _defs_map()
        )
        assert "not found in defs_map" in ctx

    def test_includes_potential_alive_reasons(self):
        ctx = build_verification_context(_finding(), _defs_map())
        assert "Dynamic dispatch" in ctx
        assert "Framework magic" in ctx

    def test_lambda_and_closure_flags(self):
        f = _finding(is_lambda=True, is_closure=True, closes_over=["x", "y"])
        ctx = build_verification_context(f, _defs_map())
        assert "Is lambda: yes" in ctx
        assert "Is closure: yes" in ctx
        assert "x" in ctx


class TestVerifySingle:
    def _make_agent(self, llm_response):
        agent = DeadCodeVerifierAgent.__new__(DeadCodeVerifierAgent)
        agent.config = MagicMock(stream=True)
        agent._adapter = MagicMock()
        agent._adapter.stream.return_value = iter([llm_response])
        return agent

    def test_true_positive(self):
        resp = json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "No dynamic refs"})
        agent = self._make_agent(resp)

        result = agent.verify_single(_finding(confidence=70), _defs_map())

        assert result.verdict == Verdict.TRUE_POSITIVE
        assert result.adjusted_confidence == 85  # 70 + 15
        assert result.rationale == "No dynamic refs"

    def test_false_positive(self):
        resp = json.dumps(
            {"verdict": "FALSE_POSITIVE", "rationale": "Used via getattr"}
        )
        agent = self._make_agent(resp)

        result = agent.verify_single(_finding(confidence=70), _defs_map())

        assert result.verdict == Verdict.FALSE_POSITIVE
        assert result.adjusted_confidence == 40  # 70 - 30

    def test_uncertain(self):
        resp = json.dumps({"verdict": "UNCERTAIN", "rationale": "Can't tell"})
        agent = self._make_agent(resp)

        result = agent.verify_single(_finding(confidence=70), _defs_map())

        assert result.verdict == Verdict.UNCERTAIN
        assert result.adjusted_confidence == 70  # no change

    def test_skips_nonzero_refs(self):
        agent = self._make_agent("")

        result = agent.verify_single(_finding(references=3), _defs_map())

        assert result.verdict == Verdict.UNCERTAIN
        assert "3 references exist" in result.rationale
        agent._adapter.stream.assert_not_called()

    def test_handles_markdown_fenced_json(self):
        resp = '```json\n{"verdict": "TRUE_POSITIVE", "rationale": "dead"}\n```'
        agent = self._make_agent(resp)

        result = agent.verify_single(_finding(), _defs_map())
        assert result.verdict == Verdict.TRUE_POSITIVE

    def test_handles_invalid_verdict_string(self):
        resp = json.dumps({"verdict": "MAYBE_DEAD", "rationale": "dunno"})
        agent = self._make_agent(resp)

        result = agent.verify_single(_finding(), _defs_map())
        assert result.verdict == Verdict.UNCERTAIN

    def test_handles_llm_garbage(self):
        agent = self._make_agent("I think this code is probably dead because reasons")

        result = agent.verify_single(_finding(), _defs_map())
        assert result.verdict == Verdict.UNCERTAIN
        assert "failed" in result.rationale.lower()

    def test_handles_llm_exception(self):
        agent = DeadCodeVerifierAgent.__new__(DeadCodeVerifierAgent)
        agent.config = MagicMock(stream=True)
        agent._adapter = MagicMock()
        agent._adapter.stream.side_effect = Exception("timeout")

        result = agent.verify_single(_finding(), _defs_map())
        assert result.verdict == Verdict.UNCERTAIN

    def test_uses_source_cache(self):
        resp = json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "dead"})
        agent = self._make_agent(resp)
        cache = _source_cache()

        agent.verify_single(_finding(), _defs_map(), source_cache=cache)

        call_args = agent._adapter.stream.call_args[0]
        user_prompt = call_args[1]
        assert "def dead_func" in user_prompt

    def test_non_streaming_mode(self):
        resp = json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "dead"})
        agent = DeadCodeVerifierAgent.__new__(DeadCodeVerifierAgent)
        agent.config = MagicMock(stream=False)
        agent._adapter = MagicMock()
        agent._adapter.complete.return_value = resp

        result = agent.verify_single(_finding(), _defs_map())

        assert result.verdict == Verdict.TRUE_POSITIVE
        agent._adapter.complete.assert_called_once()
        agent._adapter.stream.assert_not_called()


class TestVerifyBatch:
    def _make_agent(self, responses):
        agent = DeadCodeVerifierAgent.__new__(DeadCodeVerifierAgent)
        agent.config = MagicMock(stream=True)
        agent._adapter = MagicMock()
        agent._adapter.stream.side_effect = [iter([r]) for r in responses]
        return agent

    def test_only_verifies_within_confidence_range(self):
        resp = json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "dead"})
        agent = self._make_agent([resp])

        findings = [
            _finding(name="low_conf", confidence=30),
            _finding(name="in_range", confidence=70),
            _finding(name="high_conf", confidence=90),
        ]

        results = agent.verify_batch(findings, _defs_map(), confidence_range=(50, 85))

        assert agent._adapter.stream.call_count == 1

        verdicts = {r.finding["name"]: r.verdict for r in results}
        assert verdicts["in_range"] == Verdict.TRUE_POSITIVE
        assert verdicts["low_conf"] == Verdict.UNCERTAIN
        assert verdicts["high_conf"] == Verdict.TRUE_POSITIVE

    def test_skips_nonzero_refs(self):
        agent = self._make_agent([])

        findings = [_finding(confidence=70, references=5)]
        results = agent.verify_batch(findings, _defs_map(), confidence_range=(50, 85))

        assert len(results) == 1
        assert results[0].verdict == Verdict.UNCERTAIN
        assert "5 references" in results[0].rationale
        agent._adapter.stream.assert_not_called()

    def test_high_confidence_auto_promoted(self):
        agent = self._make_agent([])

        findings = [_finding(confidence=90)]
        results = agent.verify_batch(findings, _defs_map(), confidence_range=(50, 85))

        assert results[0].verdict == Verdict.TRUE_POSITIVE
        assert "High confidence" in results[0].rationale

    def test_below_range_gets_uncertain(self):
        agent = self._make_agent([])

        findings = [_finding(confidence=30)]
        results = agent.verify_batch(findings, _defs_map(), confidence_range=(50, 85))

        assert results[0].verdict == Verdict.UNCERTAIN
        assert "Below confidence" in results[0].rationale

    def test_empty_findings(self):
        agent = self._make_agent([])
        results = agent.verify_batch([], _defs_map())
        assert results == []

    def test_preserves_order(self):
        responses = [
            json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "dead"}),
            json.dumps({"verdict": "FALSE_POSITIVE", "rationale": "alive"}),
        ]
        agent = self._make_agent(responses)

        findings = [
            _finding(name="first", confidence=70),
            _finding(name="second", confidence=70),
        ]
        results = agent.verify_batch(findings, _defs_map(), confidence_range=(50, 85))

        assert results[0].finding["name"] == "first"
        assert results[0].verdict == Verdict.TRUE_POSITIVE
        assert results[1].finding["name"] == "second"
        assert results[1].verdict == Verdict.FALSE_POSITIVE


class TestAnnotateFindings:
    def _make_agent(self, responses):
        agent = DeadCodeVerifierAgent.__new__(DeadCodeVerifierAgent)
        agent.config = MagicMock(stream=True)
        agent._adapter = MagicMock()
        agent._adapter.stream.side_effect = [iter([r]) for r in responses]
        return agent

    def test_true_positive_annotations(self):
        resp = json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "No refs"})
        agent = self._make_agent([resp])

        results = agent.annotate_findings(
            [_finding(confidence=70)], _defs_map(), confidence_range=(50, 85)
        )

        assert len(results) == 1
        r = results[0]
        assert r["_llm_verdict"] == "TRUE_POSITIVE"
        assert r["_llm_rationale"] == "No refs"
        assert r["_verified_by_llm"] is True
        assert r["_confidence_adjusted"] == 85
        assert "_suppressed" not in r

    def test_false_positive_gets_suppressed(self):
        resp = json.dumps(
            {"verdict": "FALSE_POSITIVE", "rationale": "Used via getattr"}
        )
        agent = self._make_agent([resp])

        results = agent.annotate_findings(
            [_finding(confidence=70)], _defs_map(), confidence_range=(50, 85)
        )

        r = results[0]
        assert r["_llm_verdict"] == "FALSE_POSITIVE"
        assert r["_suppressed"] is True
        assert "getattr" in r["_suppressed_reason"]
        assert r["_verified_by_llm"] is True

    def test_uncertain_not_verified(self):
        resp = json.dumps({"verdict": "UNCERTAIN", "rationale": "Can't tell"})
        agent = self._make_agent([resp])

        results = agent.annotate_findings(
            [_finding(confidence=70)], _defs_map(), confidence_range=(50, 85)
        )

        r = results[0]
        assert r["_llm_verdict"] == "UNCERTAIN"
        assert r["_verified_by_llm"] is False
        assert "_suppressed" not in r

    def test_does_not_mutate_original(self):
        resp = json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "dead"})
        agent = self._make_agent([resp])

        original = _finding(confidence=70)
        original_keys = set(original.keys())

        agent.annotate_findings([original], _defs_map(), confidence_range=(50, 85))

        # Original should not have annotation keys
        assert set(original.keys()) == original_keys

    def test_mixed_verdicts(self):
        responses = [
            json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "dead"}),
            json.dumps({"verdict": "FALSE_POSITIVE", "rationale": "alive via plugin"}),
        ]
        agent = self._make_agent(responses)

        findings = [
            _finding(name="dead_one", confidence=70),
            _finding(name="alive_one", confidence=70),
        ]
        results = agent.annotate_findings(
            findings, _defs_map(), confidence_range=(50, 85)
        )

        assert results[0]["_llm_verdict"] == "TRUE_POSITIVE"
        assert "_suppressed" not in results[0]
        assert results[1]["_llm_verdict"] == "FALSE_POSITIVE"
        assert results[1]["_suppressed"] is True


class TestAgentInit:
    @patch("skylos.llm.agents.create_llm_adapter")
    def test_lazy_adapter_creation(self, mock_create):
        mock_create.return_value = MagicMock()
        config = MagicMock()

        agent = DeadCodeVerifierAgent(config)
        assert agent._adapter is None

        adapter = agent.get_adapter()
        assert adapter is not None
        mock_create.assert_called_once_with(config)

        agent.get_adapter()
        mock_create.assert_called_once()

    @patch("skylos.llm.agents.AgentConfig")
    def test_default_config(self, mock_cfg):
        mock_cfg.return_value = MagicMock()
        agent = DeadCodeVerifierAgent()
        assert agent.config is mock_cfg.return_value
