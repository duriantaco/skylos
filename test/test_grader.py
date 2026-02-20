import pytest
from pathlib import Path

from skylos.grader import (
    score_to_letter,
    compute_grade,
    score_security,
    score_quality,
    score_dead_code,
    score_dependencies,
    score_secrets,
    count_lines_of_code,
    _interpolate_dead_code_score,
    generate_badge_url,
    generate_badge_svg,
    CATEGORY_WEIGHTS,
)


def _empty_result(**overrides):
    base = {
        "danger": [],
        "quality": [],
        "secrets": [],
        "dependency_vulnerabilities": [],
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
    }
    base.update(overrides)
    return base


class TestScoreToLetter:
    def test_a_plus(self):
        assert score_to_letter(100) == "A+"
        assert score_to_letter(97) == "A+"

    def test_a(self):
        assert score_to_letter(93) == "A"
        assert score_to_letter(96) == "A"

    def test_a_minus(self):
        assert score_to_letter(90) == "A-"
        assert score_to_letter(92) == "A-"

    def test_b_plus(self):
        assert score_to_letter(87) == "B+"
        assert score_to_letter(89) == "B+"

    def test_b(self):
        assert score_to_letter(83) == "B"
        assert score_to_letter(86) == "B"

    def test_b_minus(self):
        assert score_to_letter(80) == "B-"
        assert score_to_letter(82) == "B-"

    def test_c_range(self):
        assert score_to_letter(77) == "C+"
        assert score_to_letter(73) == "C"
        assert score_to_letter(70) == "C-"

    def test_d_range(self):
        assert score_to_letter(67) == "D+"
        assert score_to_letter(63) == "D"
        assert score_to_letter(60) == "D-"

    def test_f(self):
        assert score_to_letter(59) == "F"
        assert score_to_letter(30) == "F"
        assert score_to_letter(0) == "F"

    def test_clamp_over_100(self):
        assert score_to_letter(105) == "A+"

    def test_clamp_negative(self):
        assert score_to_letter(-5) == "F"


class TestScoreSecurity:
    def test_no_findings(self):
        score, issue = score_security([])
        assert score == 100

    def test_critical_caps_at_55(self):
        findings = [{"severity": "CRITICAL", "message": "SQL injection"}]
        score, _ = score_security(findings)
        assert score <= 55

    def test_high_caps_at_79(self):
        findings = [{"severity": "HIGH", "message": "Weak hash"}]
        score, _ = score_security(findings)
        assert score <= 79

    def test_multiple_criticals_stack(self):
        findings = [
            {"severity": "CRITICAL", "message": "SQL injection"},
            {"severity": "CRITICAL", "message": "Command injection"},
        ]
        score, _ = score_security(findings)
        # cap 55, then -15 -15 = 25
        assert score == 25

    def test_mixed_severities(self):
        findings = [
            {"severity": "HIGH", "message": "XSS"},
            {"severity": "MEDIUM", "message": "Open redirect"},
            {"severity": "LOW", "message": "Info disclosure"},
        ]
        score, _ = score_security(findings)
        # cap 79, then -8 -3 -1 = 67
        assert score == 67

    def test_key_issue_is_worst(self):
        findings = [
            {"severity": "LOW", "message": "Info disclosure"},
            {"severity": "CRITICAL", "message": "RCE found"},
        ]
        _, issue = score_security(findings)
        assert "RCE" in issue

    def test_floor_at_zero(self):
        findings = [{"severity": "CRITICAL", "message": f"vuln{i}"} for i in range(10)]
        score, _ = score_security(findings)
        assert score == 0


class TestScoreQuality:
    def test_no_findings(self):
        score, _ = score_quality([], 10000)
        assert score == 100

    def test_normalized_per_1k_loc(self):
        findings = [{"severity": "MEDIUM", "message": "Complex"}]
        score_small, _ = score_quality(findings, 500)
        score_large, _ = score_quality(findings, 50000)
        assert score_large > score_small

    def test_critical_quality_caps(self):
        findings = [{"severity": "CRITICAL", "message": "Extreme complexity"}]
        score, _ = score_quality(findings, 10000)
        assert score <= 55


class TestScoreDeadCode:
    def test_no_dead_code(self):
        result = _empty_result()
        score, _ = score_dead_code(result, 10000)
        assert score == 100

    def test_moderate_density(self):
        result = _empty_result(unused_functions=[{"name": f"f{i}"} for i in range(10)])
        # 10 dead in 2000 LOC = 5/1K = score 85
        score, _ = score_dead_code(result, 2000)
        assert score == 85

    def test_high_density_low_score(self):
        result = _empty_result(unused_functions=[{"name": f"f{i}"} for i in range(50)])
        # 50 dead in 1000 LOC = 50/1K
        score, _ = score_dead_code(result, 1000)
        assert score == 0

    def test_key_issue_format(self):
        result = _empty_result(unused_functions=[{"name": f"f{i}"} for i in range(5)])
        _, issue = score_dead_code(result, 5000)
        assert "5 dead symbols" in issue
        assert "/1K LOC" in issue

    def test_zero_loc_uses_raw_count(self):
        result = _empty_result(unused_functions=[{"name": f"f{i}"} for i in range(3)])
        score, _ = score_dead_code(result, 0)
        assert score < 100


class TestInterpolation:
    def test_zero_density(self):
        assert _interpolate_dead_code_score(0) == 100

    def test_exact_breakpoints(self):
        assert _interpolate_dead_code_score(5) == 85
        assert _interpolate_dead_code_score(15) == 55
        assert _interpolate_dead_code_score(30) == 20
        assert _interpolate_dead_code_score(50) == 0

    def test_midpoint(self):
        score = _interpolate_dead_code_score(10.0)
        assert 55 < score < 85

    def test_beyond_max(self):
        assert _interpolate_dead_code_score(100) == 0

    def test_negative(self):
        assert _interpolate_dead_code_score(-5) == 100


class TestScoreDependencies:
    def test_no_findings(self):
        score, _ = score_dependencies([])
        assert score == 100

    def test_critical_vuln(self):
        findings = [{"severity": "CRITICAL", "message": "CVE-2024-1234"}]
        score, _ = score_dependencies(findings)
        assert score <= 55


class TestScoreSecrets:
    def test_no_secrets(self):
        score, _ = score_secrets([])
        assert score == 100

    def test_one_secret_caps_at_69(self):
        score, _ = score_secrets([{"message": "AWS key"}])
        assert score == 69

    def test_additional_subtract_20(self):
        secrets = [{"message": f"Secret {i}"} for i in range(3)]
        score, _ = score_secrets(secrets)
        # 69 - 20 - 20 = 29
        assert score == 29

    def test_floor_at_zero(self):
        secrets = [{"message": f"Secret {i}"} for i in range(10)]
        score, _ = score_secrets(secrets)
        assert score == 0

    def test_key_issue_single(self):
        _, issue = score_secrets([{"message": "AWS key found"}])
        assert "AWS key" in issue

    def test_key_issue_multiple(self):
        secrets = [{"message": "s1"}, {"message": "s2"}]
        _, issue = score_secrets(secrets)
        assert "2 secrets" in issue


class TestComputeGrade:
    def test_clean_codebase_a_plus(self):
        result = _empty_result()
        grade = compute_grade(result, 10000)
        assert grade["overall"]["letter"] == "A+"
        assert grade["overall"]["score"] == 100

    def test_critical_security_caps_overall(self):
        result = _empty_result(danger=[{"severity": "CRITICAL", "message": "RCE"}])
        grade = compute_grade(result, 10000)
        assert grade["overall"]["score"] <= 79
        assert grade["overall"]["letter"][0] in ("C", "D", "F")

    def test_weights_sum_to_one(self):
        assert abs(sum(CATEGORY_WEIGHTS.values()) - 1.0) < 0.001

    def test_all_categories_present(self):
        grade = compute_grade(_empty_result(), 1000)
        for cat in ("security", "quality", "dead_code", "dependencies", "secrets"):
            assert cat in grade["categories"]
            cat_data = grade["categories"][cat]
            assert "score" in cat_data
            assert "letter" in cat_data
            assert "weight" in cat_data
            assert "key_issue" in cat_data

    def test_total_loc_included(self):
        grade = compute_grade(_empty_result(), 42000)
        assert grade["total_loc"] == 42000

    def test_secrets_subgrade_capped(self):
        result = _empty_result(secrets=[{"message": "API key"}])
        grade = compute_grade(result, 10000)
        assert grade["categories"]["secrets"]["score"] <= 69

    def test_mixed_issues_weighted(self):
        result = _empty_result(
            danger=[{"severity": "HIGH", "message": "XSS"}],
            quality=[{"severity": "MEDIUM", "message": "Complex"}],
            unused_functions=[{"name": f"f{i}"} for i in range(10)],
        )
        grade = compute_grade(result, 5000)
        assert 0 < grade["overall"]["score"] < 100
        assert grade["categories"]["security"]["score"] < 100
        assert grade["categories"]["quality"]["score"] < 100
        assert grade["categories"]["dead_code"]["score"] < 100


class TestCountLinesOfCode:
    def test_python_file(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n\n# comment\ny = 2\n")
        assert count_lines_of_code([f]) == 2

    def test_typescript_file(self, tmp_path):
        f = tmp_path / "test.ts"
        f.write_text("const x = 1;\n\n// comment\nconst y = 2;\n")
        assert count_lines_of_code([f]) == 2

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("")
        assert count_lines_of_code([f]) == 0

    def test_nonexistent_file(self):
        assert count_lines_of_code([Path("/nonexistent/file.py")]) == 0

    def test_multiple_files(self, tmp_path):
        f1 = tmp_path / "a.py"
        f1.write_text("x = 1\ny = 2\n")
        f2 = tmp_path / "b.py"
        f2.write_text("z = 3\n")
        assert count_lines_of_code([f1, f2]) == 3


class TestBadge:
    def test_url_format(self):
        url = generate_badge_url("A+", 98)
        assert "img.shields.io" in url
        assert "brightgreen" in url

    def test_url_f_grade(self):
        url = generate_badge_url("F", 30)
        assert "red" in url

    def test_svg_contains_grade(self):
        svg = generate_badge_svg("B+", 84)
        assert "Skylos" in svg
        assert "B+" in svg
        assert "<svg" in svg
