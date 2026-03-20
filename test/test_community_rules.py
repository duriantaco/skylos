"""Tests for community rules: taint-flow patterns, YAML loading, CLI commands."""

from __future__ import annotations

import ast
import os
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml

from skylos.rules.custom import YAMLRule, load_custom_rules, load_community_rules
from skylos.linter import LinterVisitor


def _make_taint_rule(
    sources=None, sinks=None, sanitizers=None, rule_id="TEST-001"
):
    return YAMLRule(
        {
            "rule_id": rule_id,
            "name": "test taint rule",
            "severity": "HIGH",
            "category": "security",
            "yaml_config": {
                "message": "Tainted input flows to sink",
                "pattern": {
                    "type": "taint_flow",
                    "sources": sources or ["request.form", "request.args"],
                    "sinks": sinks or ["cursor.execute", "db.execute"],
                    "sanitizers": sanitizers or ["int", "escape_string"],
                },
            },
        }
    )


def _run_rule_on_code(rule, code):
    """Run a rule against source code and return findings."""
    tree = ast.parse(textwrap.dedent(code))
    linter = LinterVisitor([rule], "test.py")
    linter.visit(tree)
    return linter.findings


class TestTaintFlowDetection:
    """Tests for taint_flow pattern type in YAMLRule."""

    def test_source_to_sink_flagged(self):
        """Direct tainted variable used in sink call should be flagged."""
        code = """
        def handle():
            user_input = request.form["name"]
            cursor.execute(user_input)
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "TEST-001"
        assert findings[0]["severity"] == "HIGH"

    def test_source_to_sink_via_fstring(self):
        """Tainted variable in f-string passed to sink should be flagged."""
        code = """
        def handle():
            name = request.args["name"]
            cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        assert len(findings) >= 1

    def test_source_to_sink_via_format(self):
        """Tainted variable in .format() passed to sink should be flagged."""
        code = """
        def handle():
            name = request.form["name"]
            query = "SELECT * FROM users WHERE name = '{}'".format(name)
            db.execute(query)
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        assert len(findings) >= 1

    def test_sanitizer_removes_taint(self):
        """Sanitizer call on tainted variable should remove taint."""
        code = """
        def handle():
            user_id = request.form["id"]
            safe_id = int(user_id)
            cursor.execute(safe_id)
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        # safe_id should NOT be tainted because int() is a sanitizer
        taint_findings = [f for f in findings if f["rule_id"] == "TEST-001"]
        assert len(taint_findings) == 0

    def test_no_source_no_finding(self):
        """Non-source data flowing to sink should not be flagged."""
        code = """
        def handle():
            data = "safe_static_string"
            cursor.execute(data)
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        assert len(findings) == 0

    def test_source_without_sink_no_finding(self):
        """Source data that never reaches a sink should not be flagged."""
        code = """
        def handle():
            user_input = request.form["name"]
            print(user_input)
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        assert len(findings) == 0

    def test_direct_source_in_sink_call(self):
        """Source expression directly as sink argument should be flagged."""
        code = """
        def handle():
            cursor.execute(request.form["query"])
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        assert len(findings) >= 1

    def test_function_scope_reset(self):
        """Taint state should reset at function boundaries."""
        code = """
        def first():
            user_input = request.form["name"]

        def second():
            cursor.execute(user_input)
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        # user_input in second() should not be tainted (different scope)
        assert len(findings) == 0

    def test_multiple_sinks(self):
        """Multiple sink calls with same tainted variable should produce multiple findings."""
        code = """
        def handle():
            name = request.form["name"]
            cursor.execute(name)
            db.execute(name)
        """
        rule = _make_taint_rule()
        findings = _run_rule_on_code(rule, code)
        assert len(findings) >= 2


class TestLoadCommunityRules:
    """Tests for load_community_rules function."""

    def test_load_from_directory(self, tmp_path):
        """Load rules from .yml files in a directory."""
        rules_dir = tmp_path / ".skylos" / "rules"
        rules_dir.mkdir(parents=True)

        rule_content = {
            "rules": [
                {
                    "id": "COMM-001",
                    "name": "Test rule",
                    "severity": "HIGH",
                    "category": "security",
                    "message": "Test message",
                    "pattern": {"type": "call", "function_match": ["eval"]},
                }
            ]
        }
        (rules_dir / "test_pack.yml").write_text(yaml.dump(rule_content))

        with patch("pathlib.Path.home", return_value=tmp_path):
            result = load_community_rules()

        assert len(result) == 1
        assert result[0]["rule_id"] == "COMM-001"
        assert result[0]["rule_type"] == "yaml"
        assert result[0]["enabled"] is True

    def test_load_empty_directory(self, tmp_path):
        """Return empty list when no rules installed."""
        rules_dir = tmp_path / ".skylos" / "rules"
        rules_dir.mkdir(parents=True)

        with patch("pathlib.Path.home", return_value=tmp_path):
            result = load_community_rules()

        assert result == []

    def test_load_no_directory(self, tmp_path):
        """Return empty list when rules directory doesn't exist."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = load_community_rules()

        assert result == []

    def test_load_multiple_packs(self, tmp_path):
        """Load rules from multiple .yml files."""
        rules_dir = tmp_path / ".skylos" / "rules"
        rules_dir.mkdir(parents=True)

        for i in range(3):
            content = {
                "rules": [
                    {
                        "id": f"PACK{i}-001",
                        "name": f"Rule from pack {i}",
                        "severity": "MEDIUM",
                        "pattern": {"type": "call", "function_match": ["test"]},
                    }
                ]
            }
            (rules_dir / f"pack{i}.yml").write_text(yaml.dump(content))

        with patch("pathlib.Path.home", return_value=tmp_path):
            result = load_community_rules()

        assert len(result) == 3

    def test_load_skips_invalid_yaml(self, tmp_path):
        """Invalid YAML files should be silently skipped."""
        rules_dir = tmp_path / ".skylos" / "rules"
        rules_dir.mkdir(parents=True)

        (rules_dir / "bad.yml").write_text("{{{{not valid yaml")
        content = {
            "rules": [
                {
                    "id": "GOOD-001",
                    "name": "Good rule",
                    "severity": "LOW",
                    "pattern": {"type": "call", "function_match": ["test"]},
                }
            ]
        }
        (rules_dir / "good.yml").write_text(yaml.dump(content))

        with patch("pathlib.Path.home", return_value=tmp_path):
            result = load_community_rules()

        assert len(result) == 1
        assert result[0]["rule_id"] == "GOOD-001"

    def test_community_rules_become_yaml_rules(self, tmp_path):
        """Community rules should be loadable as YAMLRule objects."""
        rules_dir = tmp_path / ".skylos" / "rules"
        rules_dir.mkdir(parents=True)

        content = {
            "rules": [
                {
                    "id": "COMM-001",
                    "name": "Eval detection",
                    "severity": "HIGH",
                    "category": "security",
                    "message": "Avoid eval",
                    "pattern": {
                        "type": "call",
                        "function_match": ["eval"],
                        "args": {"is_dynamic": True, "position": 0},
                    },
                }
            ]
        }
        (rules_dir / "security.yml").write_text(yaml.dump(content))

        with patch("pathlib.Path.home", return_value=tmp_path):
            community_data = load_community_rules()

        rules = load_custom_rules(community_data)
        assert len(rules) == 1
        assert rules[0].rule_id == "COMM-001"
        assert isinstance(rules[0], YAMLRule)


class TestRuleValidation:
    """Tests for skylos rules validate logic."""

    def test_valid_rule_file(self, tmp_path):
        """A well-formed rule file should pass validation."""
        content = {
            "rules": [
                {
                    "id": "V-001",
                    "name": "Valid rule",
                    "severity": "HIGH",
                    "pattern": {"type": "call", "function_match": ["eval"]},
                }
            ]
        }
        rule_file = tmp_path / "valid.yml"
        rule_file.write_text(yaml.dump(content))

        data = yaml.safe_load(rule_file.read_text())
        assert "rules" in data
        rule = data["rules"][0]
        assert "id" in rule
        assert "name" in rule
        assert "severity" in rule
        assert "type" in rule["pattern"]

    def test_missing_id(self, tmp_path):
        """Rule missing 'id' should be caught by validation."""
        content = {
            "rules": [
                {
                    "name": "No ID rule",
                    "severity": "HIGH",
                    "pattern": {"type": "call"},
                }
            ]
        }
        rule_file = tmp_path / "bad.yml"
        rule_file.write_text(yaml.dump(content))

        data = yaml.safe_load(rule_file.read_text())
        rule = data["rules"][0]
        assert "id" not in rule

    def test_missing_pattern_type(self, tmp_path):
        """Rule with pattern missing 'type' should be caught."""
        content = {
            "rules": [
                {
                    "id": "V-002",
                    "name": "No type",
                    "severity": "HIGH",
                    "pattern": {"function_match": ["eval"]},
                }
            ]
        }
        rule_file = tmp_path / "notype.yml"
        rule_file.write_text(yaml.dump(content))

        data = yaml.safe_load(rule_file.read_text())
        assert "type" not in data["rules"][0]["pattern"]

    def test_taint_flow_requires_sources_and_sinks(self, tmp_path):
        """taint_flow rules must have sources and sinks."""
        content = {
            "rules": [
                {
                    "id": "V-003",
                    "name": "Bad taint",
                    "severity": "HIGH",
                    "pattern": {"type": "taint_flow"},
                }
            ]
        }
        rule_file = tmp_path / "badtaint.yml"
        rule_file.write_text(yaml.dump(content))

        data = yaml.safe_load(rule_file.read_text())
        pattern = data["rules"][0]["pattern"]
        assert pattern["type"] == "taint_flow"
        assert "sources" not in pattern
        assert "sinks" not in pattern

    def test_valid_taint_flow_rule(self, tmp_path):
        """A complete taint_flow rule should pass validation."""
        content = {
            "rules": [
                {
                    "id": "V-004",
                    "name": "SQL injection",
                    "severity": "HIGH",
                    "pattern": {
                        "type": "taint_flow",
                        "sources": ["request.form"],
                        "sinks": ["cursor.execute"],
                        "sanitizers": ["int"],
                    },
                }
            ]
        }
        rule_file = tmp_path / "taint.yml"
        rule_file.write_text(yaml.dump(content))

        data = yaml.safe_load(rule_file.read_text())
        pattern = data["rules"][0]["pattern"]
        assert pattern["type"] == "taint_flow"
        assert "sources" in pattern
        assert "sinks" in pattern


class TestRulesInstall:
    """Tests for rule installation with mocked filesystem."""

    def test_install_from_pack_name(self, tmp_path):
        """Install by pack name should download from known URL."""
        from skylos.cli import _rules_install

        rules_dir = tmp_path / "rules"
        console = MagicMock()

        yaml_content = yaml.dump(
            {
                "rules": [
                    {
                        "id": "PACK-001",
                        "name": "Pack rule",
                        "severity": "HIGH",
                        "pattern": {"type": "call", "function_match": ["eval"]},
                    }
                ]
            }
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = yaml_content.encode("utf-8")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            _rules_install(console, rules_dir, "flask-security")

        installed = rules_dir / "flask-security.yml"
        assert installed.exists()
        data = yaml.safe_load(installed.read_text())
        assert len(data["rules"]) == 1

    def test_install_from_url(self, tmp_path):
        """Install by direct URL should use that URL."""
        from skylos.cli import _rules_install

        rules_dir = tmp_path / "rules"
        console = MagicMock()

        yaml_content = yaml.dump(
            {
                "rules": [
                    {
                        "id": "URL-001",
                        "name": "URL rule",
                        "severity": "MEDIUM",
                        "pattern": {"type": "call", "function_match": ["exec"]},
                    }
                ]
            }
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = yaml_content.encode("utf-8")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            _rules_install(
                console,
                rules_dir,
                "https://example.com/my-rules.yml",
            )

        installed = rules_dir / "my-rules.yml"
        assert installed.exists()


class TestRulesRemove:
    """Tests for rule removal."""

    def test_remove_existing_pack(self, tmp_path):
        """Remove should delete the rule file."""
        from skylos.cli import _rules_remove

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "mypack.yml").write_text("rules: []")

        console = MagicMock()
        _rules_remove(console, rules_dir, "mypack")

        assert not (rules_dir / "mypack.yml").exists()

    def test_remove_nonexistent_pack(self, tmp_path):
        """Remove of missing pack should exit with error."""
        from skylos.cli import _rules_remove

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir(parents=True)
        console = MagicMock()

        with pytest.raises(SystemExit):
            _rules_remove(console, rules_dir, "nonexistent")
