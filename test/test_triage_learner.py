import json
import time

import pytest

from skylos.triage_learner import (
    MIN_CONFIDENCE_AUTO,
    MIN_CONFIDENCE_SUGGEST,
    MIN_OBSERVATIONS_AUTO,
    MIN_OBSERVATIONS_SUGGEST,
    TRIAGE_DIR,
    TRIAGE_FILE,
    TriageLearner,
    TriagePattern,
    _glob_match,
    _pattern_key,
)


class TestTriagePattern:
    def test_creation_defaults(self):
        p = TriagePattern(
            pattern_type="file_glob",
            pattern="src/**",
            rule_id="D001",
            action="dismiss",
        )
        assert p.confidence == 0.0
        assert p.observations == 0
        assert p.last_updated == 0.0

    def test_creation_full(self):
        p = TriagePattern(
            pattern_type="name_pattern",
            pattern="test_*",
            rule_id="D002",
            action="accept",
            confidence=0.9,
            observations=10,
            last_updated=1234.0,
        )
        assert p.confidence == 0.9
        assert p.observations == 10
        assert p.last_updated == 1234.0

    def test_to_dict(self):
        p = TriagePattern(
            pattern_type="decorator",
            pattern="@pytest.fixture",
            rule_id="D003",
            action="dismiss",
            confidence=0.8,
            observations=5,
            last_updated=999.0,
        )
        d = p.to_dict()
        assert d == {
            "pattern_type": "decorator",
            "pattern": "@pytest.fixture",
            "rule_id": "D003",
            "action": "dismiss",
            "confidence": 0.8,
            "observations": 5,
            "last_updated": 999.0,
        }

    def test_from_dict(self):
        data = {
            "pattern_type": "file_glob",
            "pattern": "tests/**",
            "rule_id": "D004",
            "action": "accept",
            "confidence": 0.75,
            "observations": 3,
            "last_updated": 500.0,
        }
        p = TriagePattern.from_dict(data)
        assert p.pattern_type == "file_glob"
        assert p.pattern == "tests/**"
        assert p.rule_id == "D004"
        assert p.action == "accept"
        assert p.confidence == 0.75
        assert p.observations == 3
        assert p.last_updated == 500.0

    def test_from_dict_missing_keys(self):
        p = TriagePattern.from_dict({})
        assert p.pattern_type == ""
        assert p.pattern == ""
        assert p.rule_id == ""
        assert p.action == ""
        assert p.confidence == 0.0
        assert p.observations == 0
        assert p.last_updated == 0.0

    def test_roundtrip(self):
        original = TriagePattern(
            pattern_type="name_pattern",
            pattern="__*__",
            rule_id="D005",
            action="dismiss",
            confidence=0.95,
            observations=20,
            last_updated=12345.6,
        )
        rebuilt = TriagePattern.from_dict(original.to_dict())
        assert rebuilt == original


class TestHelpers:
    def test_pattern_key(self):
        p = TriagePattern(
            pattern_type="file_glob",
            pattern="src/**",
            rule_id="D001",
            action="dismiss",
        )
        assert _pattern_key(p) == "file_glob:src/**:D001:dismiss"

    def test_glob_match_star(self):
        assert _glob_match("test_foo", "test_*")
        assert not _glob_match("foo_test", "test_*")

    def test_glob_match_double_star(self):
        assert _glob_match("src/foo/bar.py", "src/**")

    def test_glob_match_extension(self):
        assert _glob_match("tests/test_utils.py", "**/test_*.py")


class TestLearnFromTriage:
    def _make_finding(self, **overrides):
        base = {
            "rule_id": "D001",
            "file": "src/utils/helpers.py",
            "simple_name": "my_func",
        }
        base.update(overrides)
        return base

    def test_invalid_action_returns_empty(self):
        learner = TriageLearner()
        result = learner.learn_from_triage(self._make_finding(), "ignore")
        assert result == []

    def test_empty_action_returns_empty(self):
        learner = TriageLearner()
        result = learner.learn_from_triage(self._make_finding(), "")
        assert result == []

    def test_dismiss_creates_patterns(self):
        learner = TriageLearner()
        result = learner.learn_from_triage(self._make_finding(), "dismiss")
        assert len(result) > 0
        for p in result:
            assert p.action == "dismiss"
            assert p.observations == 1
            assert p.confidence == 0.5

    def test_accept_creates_patterns(self):
        learner = TriageLearner()
        result = learner.learn_from_triage(self._make_finding(), "accept")
        assert len(result) > 0
        for p in result:
            assert p.action == "accept"

    def test_file_glob_pattern_extracted(self):
        learner = TriageLearner()
        result = learner.learn_from_triage(self._make_finding(), "dismiss")
        types = [p.pattern_type for p in result]
        assert "file_glob" in types
        file_globs = [p for p in result if p.pattern_type == "file_glob"]
        patterns = [p.pattern for p in file_globs]
        assert "src/**" in patterns

    def test_test_file_glob_pattern(self):
        learner = TriageLearner()
        finding = self._make_finding(file="test/test_foo.py")
        result = learner.learn_from_triage(finding, "dismiss")
        file_globs = [p for p in result if p.pattern_type == "file_glob"]
        patterns = [p.pattern for p in file_globs]
        assert "**/test_*.py" in patterns

    def test_name_pattern_test_prefix(self):
        learner = TriageLearner()
        finding = self._make_finding(simple_name="test_something")
        result = learner.learn_from_triage(finding, "dismiss")
        name_patterns = [p for p in result if p.pattern_type == "name_pattern"]
        patterns = [p.pattern for p in name_patterns]
        assert "test_*" in patterns

    def test_name_pattern_dunder(self):
        learner = TriageLearner()
        finding = self._make_finding(simple_name="__init__")
        result = learner.learn_from_triage(finding, "dismiss")
        name_patterns = [p for p in result if p.pattern_type == "name_pattern"]
        patterns = [p.pattern for p in name_patterns]
        assert "__*__" in patterns

    def test_name_pattern_private(self):
        learner = TriageLearner()
        finding = self._make_finding(simple_name="_helper")
        result = learner.learn_from_triage(finding, "dismiss")
        name_patterns = [p for p in result if p.pattern_type == "name_pattern"]
        patterns = [p.pattern for p in name_patterns]
        assert "_*" in patterns

    def test_name_no_prefix_no_name_pattern(self):
        learner = TriageLearner()
        finding = self._make_finding(simple_name="regular_func")
        result = learner.learn_from_triage(finding, "dismiss")
        name_patterns = [p for p in result if p.pattern_type == "name_pattern"]
        assert name_patterns == []

    def test_decorator_patterns(self):
        learner = TriageLearner()
        finding = self._make_finding(decorators=["@pytest.fixture", "@staticmethod"])
        result = learner.learn_from_triage(finding, "dismiss")
        dec_patterns = [p for p in result if p.pattern_type == "decorator"]
        assert len(dec_patterns) == 2
        dec_values = {p.pattern for p in dec_patterns}
        assert "@pytest.fixture" in dec_values
        assert "@staticmethod" in dec_values

    def test_empty_decorator_skipped(self):
        learner = TriageLearner()
        finding = self._make_finding(decorators=["", "  ", "@valid"])
        result = learner.learn_from_triage(finding, "dismiss")
        dec_patterns = [p for p in result if p.pattern_type == "decorator"]
        assert len(dec_patterns) == 1
        assert dec_patterns[0].pattern == "@valid"

    def test_decorators_not_list_ignored(self):
        learner = TriageLearner()
        finding = self._make_finding(decorators="not_a_list")
        result = learner.learn_from_triage(finding, "dismiss")
        dec_patterns = [p for p in result if p.pattern_type == "decorator"]
        assert dec_patterns == []

    def test_no_rule_id_returns_empty(self):
        learner = TriageLearner()
        finding = self._make_finding(rule_id="")
        result = learner.learn_from_triage(finding, "dismiss")
        assert result == []

    def test_repeated_observations_increase_confidence(self):
        learner = TriageLearner()
        finding = self._make_finding()

        learner.learn_from_triage(finding, "dismiss")
        learner.learn_from_triage(finding, "dismiss")
        result = learner.learn_from_triage(finding, "dismiss")

        for p in result:
            assert p.observations == 3
            assert p.confidence == pytest.approx(0.75)

    def test_confidence_converges_toward_1(self):
        learner = TriageLearner()
        finding = self._make_finding()
        for _ in range(20):
            result = learner.learn_from_triage(finding, "dismiss")
        for p in result:
            assert p.confidence > 0.9

    def test_pattern_count(self):
        learner = TriageLearner()
        assert learner.pattern_count == 0
        learner.learn_from_triage(self._make_finding(), "dismiss")
        assert learner.pattern_count > 0

    def test_no_file_path_skips_file_glob(self):
        learner = TriageLearner()
        finding = self._make_finding(file="")
        result = learner.learn_from_triage(finding, "dismiss")
        file_globs = [p for p in result if p.pattern_type == "file_glob"]
        assert file_globs == []

    def test_single_component_path_no_dir_glob(self):
        learner = TriageLearner()
        finding = self._make_finding(file="script.py")
        result = learner.learn_from_triage(finding, "dismiss")
        file_globs = [p for p in result if p.pattern_type == "file_glob"]
        dir_globs = [p for p in file_globs if p.pattern.endswith("/**")]
        assert dir_globs == []

    def test_name_fallback_to_name_key(self):
        learner = TriageLearner()
        finding = {"rule_id": "D001", "file": "a/b.py", "name": "test_fallback"}
        result = learner.learn_from_triage(finding, "dismiss")
        name_patterns = [p for p in result if p.pattern_type == "name_pattern"]
        patterns = [p.pattern for p in name_patterns]
        assert "test_*" in patterns

    def test_empty_finding(self):
        learner = TriageLearner()
        result = learner.learn_from_triage({}, "dismiss")
        assert result == []

    def test_get_patterns(self):
        learner = TriageLearner()
        learner.learn_from_triage(self._make_finding(), "dismiss")
        patterns = learner.get_patterns()
        assert len(patterns) == learner.pattern_count
        assert all(isinstance(p, TriagePattern) for p in patterns)


class TestPredictTriage:
    def _make_finding(self, **overrides):
        base = {
            "rule_id": "D001",
            "file": "src/utils/helpers.py",
            "simple_name": "my_func",
        }
        base.update(overrides)
        return base

    def _train_learner(self, learner, finding, action, n):
        for _ in range(n):
            learner.learn_from_triage(finding, action)

    def test_no_patterns_returns_none(self):
        learner = TriageLearner()
        assert learner.predict_triage(self._make_finding()) is None

    def test_insufficient_observations_returns_none(self):
        learner = TriageLearner()
        finding = self._make_finding()
        self._train_learner(learner, finding, "dismiss", MIN_OBSERVATIONS_SUGGEST - 1)
        assert learner.predict_triage(finding) is None

    def test_sufficient_observations_returns_prediction(self):
        learner = TriageLearner()
        finding = self._make_finding()
        self._train_learner(learner, finding, "dismiss", MIN_OBSERVATIONS_SUGGEST + 2)
        result = learner.predict_triage(finding)
        assert result is not None
        action, confidence = result
        assert action == "dismiss"
        assert confidence >= MIN_CONFIDENCE_SUGGEST

    def test_prediction_returns_best_confidence(self):
        learner = TriageLearner()
        finding = self._make_finding()
        self._train_learner(learner, finding, "dismiss", 20)
        result = learner.predict_triage(finding)
        assert result is not None
        _, confidence = result
        assert confidence > 0.9

    def test_nonmatching_finding_returns_none(self):
        learner = TriageLearner()
        train_finding = self._make_finding(rule_id="D001")
        self._train_learner(learner, train_finding, "dismiss", 10)
        other = self._make_finding(rule_id="D999")
        assert learner.predict_triage(other) is None

    def test_file_glob_match(self):
        learner = TriageLearner()
        finding = self._make_finding(file="src/deep/nested.py")
        self._train_learner(learner, finding, "accept", 10)
        new_finding = self._make_finding(file="src/other/thing.py")
        result = learner.predict_triage(new_finding)
        assert result is not None
        assert result[0] == "accept"

    def test_decorator_match(self):
        learner = TriageLearner()
        finding = self._make_finding(decorators=["@property"])
        self._train_learner(learner, finding, "dismiss", 10)
        new_finding = self._make_finding(
            file="other/file.py",
            simple_name="different",
            decorators=["@property"],
        )
        result = learner.predict_triage(new_finding)
        assert result is not None
        assert result[0] == "dismiss"


class TestAutoTriageCandidates:
    def _make_finding(self, **overrides):
        base = {
            "rule_id": "D001",
            "file": "src/utils/helpers.py",
            "simple_name": "my_func",
        }
        base.update(overrides)
        return base

    def _train_learner(self, learner, finding, action, n):
        for _ in range(n):
            learner.learn_from_triage(finding, action)

    def test_empty_findings(self):
        learner = TriageLearner()
        assert learner.get_auto_triage_candidates([]) == []

    def test_no_patterns_returns_empty(self):
        learner = TriageLearner()
        findings = [self._make_finding()]
        assert learner.get_auto_triage_candidates(findings) == []

    def test_insufficient_observations_excluded(self):
        learner = TriageLearner()
        finding = self._make_finding()
        self._train_learner(learner, finding, "dismiss", MIN_OBSERVATIONS_AUTO - 1)
        result = learner.get_auto_triage_candidates([finding])
        assert result == []

    def test_sufficient_observations_included(self):
        learner = TriageLearner()
        finding = self._make_finding()
        self._train_learner(learner, finding, "dismiss", MIN_OBSERVATIONS_AUTO + 5)
        result = learner.get_auto_triage_candidates([finding])
        assert len(result) >= 1
        f, action, confidence = result[0]
        assert action == "dismiss"
        assert confidence >= MIN_CONFIDENCE_AUTO

    def test_multiple_findings_filtered(self):
        learner = TriageLearner()
        trained = self._make_finding(rule_id="D001", file="src/a/b.py")
        self._train_learner(learner, trained, "dismiss", 15)

        findings = [
            trained,
            self._make_finding(rule_id="D999", file="other/x.py"),
        ]
        result = learner.get_auto_triage_candidates(findings)
        matched_rule_ids = {f["rule_id"] for f, _, _ in result}
        assert "D999" not in matched_rule_ids


class TestPersistence:
    def _make_finding(self, **overrides):
        base = {
            "rule_id": "D001",
            "file": "src/utils/helpers.py",
            "simple_name": "test_func",
        }
        base.update(overrides)
        return base

    def test_save_creates_file(self, tmp_path):
        learner = TriageLearner()
        learner.learn_from_triage(self._make_finding(), "dismiss")
        learner.save(tmp_path)
        path = tmp_path / TRIAGE_DIR / TRIAGE_FILE
        assert path.exists()

    def test_save_creates_directory(self, tmp_path):
        learner = TriageLearner()
        learner.save(tmp_path)
        assert (tmp_path / TRIAGE_DIR).is_dir()

    def test_save_valid_json(self, tmp_path):
        learner = TriageLearner()
        learner.learn_from_triage(self._make_finding(), "dismiss")
        learner.save(tmp_path)
        path = tmp_path / TRIAGE_DIR / TRIAGE_FILE
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "version" in data
        assert data["version"] == 1
        assert "patterns" in data
        assert isinstance(data["patterns"], list)

    def test_load_roundtrip(self, tmp_path):
        learner1 = TriageLearner()
        finding = self._make_finding()
        learner1.learn_from_triage(finding, "dismiss")
        learner1.learn_from_triage(finding, "dismiss")
        learner1.save(tmp_path)

        learner2 = TriageLearner()
        learner2.load(tmp_path)
        assert learner2.pattern_count == learner1.pattern_count

        patterns1 = sorted(learner1.get_patterns(), key=lambda p: _pattern_key(p))
        patterns2 = sorted(learner2.get_patterns(), key=lambda p: _pattern_key(p))
        for p1, p2 in zip(patterns1, patterns2):
            assert p1.pattern_type == p2.pattern_type
            assert p1.pattern == p2.pattern
            assert p1.rule_id == p2.rule_id
            assert p1.action == p2.action
            assert p1.confidence == pytest.approx(p2.confidence)
            assert p1.observations == p2.observations

    def test_load_missing_file_no_error(self, tmp_path):
        learner = TriageLearner()
        learner.load(tmp_path)
        assert learner.pattern_count == 0

    def test_load_corrupt_json_no_error(self, tmp_path):
        path = tmp_path / TRIAGE_DIR / TRIAGE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json {{{", encoding="utf-8")
        learner = TriageLearner()
        learner.load(tmp_path)
        assert learner.pattern_count == 0

    def test_load_empty_patterns(self, tmp_path):
        path = tmp_path / TRIAGE_DIR / TRIAGE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"version": 1, "patterns": []}), encoding="utf-8")
        learner = TriageLearner()
        learner.load(tmp_path)
        assert learner.pattern_count == 0

    def test_load_preserves_predictions(self, tmp_path):
        learner1 = TriageLearner()
        finding = self._make_finding()
        for _ in range(10):
            learner1.learn_from_triage(finding, "dismiss")
        learner1.save(tmp_path)

        learner2 = TriageLearner()
        learner2.load(tmp_path)
        result = learner2.predict_triage(finding)
        assert result is not None
        assert result[0] == "dismiss"


class TestEdgeCases:
    def test_windows_path_separators(self):
        learner = TriageLearner()
        finding = {
            "rule_id": "D001",
            "file": "src\\utils\\helpers.py",
            "simple_name": "func",
        }
        result = learner.learn_from_triage(finding, "dismiss")
        file_globs = [p for p in result if p.pattern_type == "file_glob"]
        patterns = [p.pattern for p in file_globs]
        assert "src/**" in patterns

    def test_rule_type_pattern_matches(self):
        learner = TriageLearner()
        p = TriagePattern(
            pattern_type="rule_type",
            pattern="unused",
            rule_id="D001",
            action="dismiss",
            confidence=0.9,
            observations=10,
        )
        learner._patterns[_pattern_key(p)] = p
        finding = {"rule_id": "D001", "file": "x.py", "simple_name": "f"}
        result = learner.predict_triage(finding)
        assert result is not None
        assert result[0] == "dismiss"

    def test_unknown_pattern_type_no_match(self):
        learner = TriageLearner()
        p = TriagePattern(
            pattern_type="unknown_type",
            pattern="*",
            rule_id="D001",
            action="dismiss",
            confidence=0.95,
            observations=10,
        )
        learner._patterns[_pattern_key(p)] = p
        finding = {"rule_id": "D001", "file": "x.py"}
        result = learner.predict_triage(finding)
        assert result is None

    def test_last_updated_changes_on_learn(self):
        learner = TriageLearner()
        finding = {"rule_id": "D001", "file": "a/b.py", "simple_name": "f"}
        before = time.time()
        learner.learn_from_triage(finding, "dismiss")
        after = time.time()
        for p in learner.get_patterns():
            assert before <= p.last_updated <= after
