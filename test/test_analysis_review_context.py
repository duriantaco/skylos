from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from skylos import analyze
import skylos.cli as cli
from skylos.commands import review_cmd
from skylos.config import DEFAULTS
from skylos.core.review_context import (
    build_analysis_review_context,
    review_context_hash_for_category,
    review_context_is_valid,
)
from skylos.core.review_decisions import annotate_result_identities
from skylos.reporting.result_builder import _attach_effective_review_config_hashes


class _VisitorOne:
    pass


class _VisitorTwo:
    marker = 2


def _context(
    root: Path,
    *,
    target: Path | None = None,
    config: dict | None = None,
    threshold: int = 60,
    excluded=(),
    requested_changed_files=None,
    effective_changed_files=None,
    enable_secrets=False,
    enable_danger=False,
    enable_quality=False,
    enable_ai_defects=False,
    enable_sca=False,
    enable_dependency_hallucinations=True,
    grep_verify=True,
    trace_file=None,
    required_config_rules=None,
    dependency_bump_diff_base=None,
    custom_rules_data=None,
    extra_visitors=None,
):
    target = target or root
    scope_kind = (
        "repository_root" if target == root and not excluded else "subdirectory"
    )
    return build_analysis_review_context(
        root,
        target,
        config=copy.deepcopy(DEFAULTS if config is None else config),
        threshold=threshold,
        exclude_folders=excluded,
        requested_changed_files=requested_changed_files,
        effective_changed_files=effective_changed_files,
        enable_secrets=enable_secrets,
        enable_danger=enable_danger,
        enable_quality=enable_quality,
        enable_ai_defects=enable_ai_defects,
        enable_sca=enable_sca,
        enable_dependency_hallucinations=enable_dependency_hallucinations,
        grep_verify=grep_verify,
        trace_file=trace_file,
        required_config_rules=required_config_rules,
        dependency_bump_diff_base=dependency_bump_diff_base,
        custom_rules_data=custom_rules_data,
        extra_visitors=extra_visitors,
        analysis_scope={
            "kind": scope_kind,
            "complete_repository": target == root and not excluded,
        },
        environ={},
    )


def _hash(context, category):
    value = review_context_hash_for_category(context, category)
    assert value is not None
    return value


def _synthetic_result(source: Path, review_context, **finding_overrides):
    finding = {
        "rule_id": "SKY-D215",
        "file": str(source),
        "line": 2,
        "symbol": "write_report",
        "severity": "HIGH",
        "message": "unsafe path",
        "evidence_contract": {
            "schema_version": 1,
            "proof_state": "candidate",
            "sources": ["path"],
            "sinks": ["open"],
            "symbols": ["write_report"],
            "traces": [],
            "limitations": [],
        },
    }
    finding.update(finding_overrides)
    return {
        "danger": [finding],
        "analysis_summary": {"review_context": review_context},
    }


def test_review_context_uses_category_specific_config_inputs(tmp_path):
    baseline = copy.deepcopy(DEFAULTS)
    quality_only = copy.deepcopy(DEFAULTS)
    quality_only["complexity"] = baseline["complexity"] + 5
    quality_only["nudges"] = not baseline["nudges"]

    first = _context(tmp_path, config=baseline, enable_danger=True)
    second = _context(tmp_path, config=quality_only, enable_danger=True)

    assert _hash(first, "DEAD_CODE") == _hash(second, "DEAD_CODE")
    assert _hash(first, "SECURITY") == _hash(second, "SECURITY")
    assert _hash(first, "QUALITY") != _hash(second, "QUALITY")

    dead_change = copy.deepcopy(DEFAULTS)
    dead_change["dead_code"]["entrypoints"] = [{"name": "worker"}]
    security_change = copy.deepcopy(DEFAULTS)
    security_change["security_contracts"] = [{"rule_id": "SKY-SC001"}]

    assert _hash(first, "DEAD_CODE") != _hash(
        _context(tmp_path, config=dead_change, enable_danger=True),
        "DEAD_CODE",
    )
    assert _hash(first, "SECURITY") != _hash(
        _context(tmp_path, config=security_change, enable_danger=True),
        "SECURITY",
    )

    source = tmp_path / "app.py"
    source.write_text(
        "def write_report(path):\n    open(path, 'w').write('ok')\n",
        encoding="utf-8",
    )
    baseline_identity = annotate_result_identities(
        _synthetic_result(source, first),
        tmp_path,
    )["danger"][0]
    quality_only_identity = annotate_result_identities(
        _synthetic_result(source, second),
        tmp_path,
    )["danger"][0]
    security_change_identity = annotate_result_identities(
        _synthetic_result(
            source,
            _context(tmp_path, config=security_change, enable_danger=True),
        ),
        tmp_path,
    )["danger"][0]

    assert baseline_identity["context_hash"] == quality_only_identity["context_hash"]
    assert baseline_identity["context_hash"] != security_change_identity["context_hash"]


def test_python_dead_finding_ignores_quality_only_config_changes(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def orphan():\n    return 1\n", encoding="utf-8")

    def orphan_identity(overrides):
        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_quality=True,
                grep_verify=False,
                include_review_proofs=True,
                project_config_overrides=overrides,
            )
        )
        annotated = annotate_result_identities(result, tmp_path)
        return next(
            finding
            for finding in annotated["unused_functions"]
            if finding.get("symbol") == "orphan"
        )

    baseline = orphan_identity({"complexity": 10, "nudges": True})
    quality_change = orphan_identity({"complexity": 25, "nudges": False})

    assert baseline["stable_fingerprint"] == quality_change["stable_fingerprint"]
    assert baseline["context_hash"] == quality_change["context_hash"]


def test_review_context_binds_only_category_relevant_options(tmp_path):
    app = tmp_path / "app.py"
    other = tmp_path / "other.py"
    app.write_text("pass\n", encoding="utf-8")
    other.write_text("pass\n", encoding="utf-8")

    baseline = _context(tmp_path, enable_danger=True)
    review_scan = _context(
        tmp_path,
        enable_danger=True,
        enable_quality=True,
        enable_secrets=True,
        enable_ai_defects=True,
    )
    assert _hash(baseline, "DEAD_CODE") == _hash(review_scan, "DEAD_CODE")

    higher_threshold = _context(tmp_path, threshold=75, enable_danger=True)
    assert _hash(baseline, "DEAD_CODE") != _hash(higher_threshold, "DEAD_CODE")
    assert _hash(baseline, "SECURITY") == _hash(higher_threshold, "SECURITY")

    selected_rule = _context(
        tmp_path,
        enable_danger=True,
        required_config_rules=["sky-gpu001"],
    )
    assert _hash(baseline, "SECURITY") != _hash(selected_rule, "SECURITY")
    assert _hash(baseline, "DEAD_CODE") == _hash(selected_rule, "DEAD_CODE")

    auto_diff = _context(
        tmp_path,
        enable_danger=True,
        effective_changed_files={app},
    )
    assert _hash(baseline, "DEAD_CODE") == _hash(auto_diff, "DEAD_CODE")
    assert _hash(baseline, "SECURITY") != _hash(auto_diff, "SECURITY")

    explicit_diff = _context(
        tmp_path,
        enable_danger=True,
        requested_changed_files={other},
        effective_changed_files={other},
    )
    assert _hash(baseline, "DEAD_CODE") != _hash(explicit_diff, "DEAD_CODE")


def test_custom_rule_inputs_do_not_invalidate_builtin_quality(tmp_path):
    first = _context(
        tmp_path,
        enable_quality=True,
        custom_rules_data=[{"rule_id": "CUSTOM-ONE", "pattern": "first"}],
    )
    second = _context(
        tmp_path,
        enable_quality=True,
        custom_rules_data=[{"rule_id": "CUSTOM-ONE", "pattern": "second"}],
    )

    assert _hash(first, "QUALITY") == _hash(second, "QUALITY")
    assert _hash(first, "CUSTOM") != _hash(second, "CUSTOM")

    visitor_one = _context(
        tmp_path,
        enable_danger=True,
        enable_quality=True,
        enable_ai_defects=True,
        extra_visitors=[_VisitorOne],
    )
    visitor_two = _context(
        tmp_path,
        enable_danger=True,
        enable_ai_defects=True,
        extra_visitors=[_VisitorTwo],
    )
    same_visitor_without_quality = _context(
        tmp_path,
        enable_danger=True,
        enable_ai_defects=True,
        extra_visitors=[_VisitorOne],
    )
    same_visitor_without_danger = _context(
        tmp_path,
        enable_ai_defects=True,
        extra_visitors=[_VisitorOne],
    )

    assert _hash(visitor_one, "CUSTOM") == _hash(visitor_two, "CUSTOM")
    assert _hash(visitor_one, "CUSTOM") == _hash(
        same_visitor_without_quality,
        "CUSTOM",
    )
    assert _hash(visitor_one, "SECURITY") != _hash(visitor_two, "SECURITY")
    assert _hash(visitor_one, "RELIABILITY") != _hash(visitor_two, "RELIABILITY")
    assert _hash(visitor_one, "AI_DEFECT") != _hash(visitor_two, "AI_DEFECT")
    assert _hash(visitor_one, "AI_DEFECT") != _hash(
        same_visitor_without_danger,
        "AI_DEFECT",
    )


def test_incomplete_extensions_only_disable_their_output_categories(tmp_path):
    baseline = _context(
        tmp_path,
        enable_danger=True,
        enable_quality=True,
        enable_ai_defects=True,
    )
    malformed_rules = _context(
        tmp_path,
        enable_danger=True,
        enable_quality=True,
        enable_ai_defects=True,
        custom_rules_data={"rule": object()},
    )
    uninspectable_visitor = _context(
        tmp_path,
        enable_danger=True,
        enable_quality=True,
        enable_ai_defects=True,
        extra_visitors=[len],
    )

    assert review_context_is_valid(malformed_rules)
    assert review_context_hash_for_category(malformed_rules, "CUSTOM") is None
    assert _hash(malformed_rules, "DEAD_CODE") == _hash(baseline, "DEAD_CODE")
    assert _hash(malformed_rules, "SECURITY") == _hash(baseline, "SECURITY")
    assert _hash(malformed_rules, "QUALITY") == _hash(baseline, "QUALITY")

    assert review_context_is_valid(uninspectable_visitor)
    assert _hash(uninspectable_visitor, "CUSTOM") == _hash(baseline, "CUSTOM")
    assert review_context_hash_for_category(uninspectable_visitor, "SECURITY") is None
    assert (
        review_context_hash_for_category(uninspectable_visitor, "RELIABILITY") is None
    )
    assert review_context_hash_for_category(uninspectable_visitor, "AI_DEFECT") is None
    assert _hash(uninspectable_visitor, "DEAD_CODE") == _hash(
        baseline,
        "DEAD_CODE",
    )
    assert _hash(uninspectable_visitor, "QUALITY") == _hash(baseline, "QUALITY")


def test_review_context_is_stable_when_checkout_moves(tmp_path):
    first = tmp_path / "first" / "repo"
    second = tmp_path / "second" / "repo"
    for root in (first, second):
        (root / "src").mkdir(parents=True)
        (root / "src" / "app.py").write_text("pass\n", encoding="utf-8")

    first_context = _context(
        first,
        target=first / "src",
        excluded={first / "build", "node_modules"},
        requested_changed_files={first / "src" / "app.py"},
        effective_changed_files={first / "src" / "app.py"},
        enable_danger=True,
    )
    second_context = _context(
        second,
        target=second / "src",
        excluded={second / "build", "node_modules"},
        requested_changed_files={second / "src" / "app.py"},
        effective_changed_files={second / "src" / "app.py"},
        enable_danger=True,
    )

    assert review_context_is_valid(first_context)
    assert first_context == second_context
    assert str(first) not in json.dumps(first_context)
    assert str(second) not in json.dumps(second_context)

    first_source = first / "src" / "app.py"
    second_source = second / "src" / "app.py"
    first_source.write_text(
        "def write_report(path):\n    open(path, 'w').write('ok')\n",
        encoding="utf-8",
    )
    second_source.write_text(first_source.read_text(encoding="utf-8"), encoding="utf-8")
    first_identity = annotate_result_identities(
        _synthetic_result(first_source, first_context),
        first,
    )["danger"][0]
    second_identity = annotate_result_identities(
        _synthetic_result(second_source, second_context),
        second,
    )["danger"][0]

    assert first_identity["stable_fingerprint"] == second_identity["stable_fingerprint"]
    assert first_identity["context_hash"] == second_identity["context_hash"]


def test_material_scan_scope_change_resurfaces_finding(tmp_path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text(
        "def write_report(path):\n    open(path, 'w').write('ok')\n",
        encoding="utf-8",
    )
    repository_context = _context(tmp_path, enable_danger=True)
    file_context = _context(tmp_path, target=source, enable_danger=True)

    repository_identity = annotate_result_identities(
        _synthetic_result(source, repository_context),
        tmp_path,
    )["danger"][0]
    file_identity = annotate_result_identities(
        _synthetic_result(source, file_context),
        tmp_path,
    )["danger"][0]

    assert repository_identity["context_hash"] != file_identity["context_hash"]


def test_nested_file_config_change_resurfaces_quality_finding(tmp_path):
    repo = tmp_path / "repo"
    package = repo / "package"
    package.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    source = package / "app.py"
    source.write_text(
        "def branchy(value):\n"
        "    if value == 1:\n"
        "        return 1\n"
        "    if value == 2:\n"
        "        return 2\n"
        "    if value == 3:\n"
        "        return 3\n"
        "    return 0\n\n"
        "print(branchy(1))\n",
        encoding="utf-8",
    )
    nested_config = package / "pyproject.toml"

    def scan(complexity: int):
        nested_config.write_text(
            f"[tool.skylos]\ncomplexity = {complexity}\n",
            encoding="utf-8",
        )
        result = json.loads(
            analyze(
                str(repo),
                conf=0,
                enable_quality=True,
                grep_verify=False,
                include_review_proofs=True,
            )
        )
        annotated = annotate_result_identities(result, repo)
        finding = next(
            item for item in annotated["quality"] if item.get("rule_id") == "SKY-Q301"
        )
        return result["analysis_summary"]["review_context"], finding

    first_context, first = scan(1)
    second_context, second = scan(2)

    assert first["message"] != second["message"]
    assert _hash(first_context, "QUALITY") == _hash(second_context, "QUALITY")
    assert _hash(first_context, "SECURITY") == _hash(second_context, "SECURITY")
    assert first["stable_fingerprint"] == second["stable_fingerprint"]
    assert first["context_hash"] != second["context_hash"]


def test_repo_level_finding_under_nested_config_keeps_root_context(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    package = tmp_path / "package"
    package.mkdir()
    (package / "pyproject.toml").write_text(
        "[tool.skylos]\ncomplexity = 99\n",
        encoding="utf-8",
    )
    clone = (
        "def FUNCTION(value):\n"
        "    total = value + 1\n"
        "    total = total * 2\n"
        "    total = total - 3\n"
        "    total = total / 4\n"
        "    total = total + 5\n"
        "    total = total * 6\n"
        "    total = total - 7\n"
        "    total = total / 8\n"
        "    return total\n\n"
        "print(FUNCTION(1))\n"
    )
    (package / "first.py").write_text(
        clone.replace("FUNCTION", "first"),
        encoding="utf-8",
    )
    (package / "second.py").write_text(
        clone.replace("FUNCTION", "second"),
        encoding="utf-8",
    )

    def scan(nudges: bool):
        (tmp_path / "pyproject.toml").write_text(
            f"[tool.skylos]\nnudges = {str(nudges).lower()}\n",
            encoding="utf-8",
        )
        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_quality=True,
                grep_verify=False,
                include_review_proofs=True,
            )
        )
        raw = next(
            item for item in result["quality"] if item.get("rule_id") == "SKY-C401"
        )
        assert "_analysis_config_hash" not in raw
        annotated = annotate_result_identities(result, tmp_path)
        return next(
            item
            for item in annotated["quality"]
            if item.get("rule_id") == "SKY-C401"
        )

    first = scan(False)
    second = scan(True)

    assert first["stable_fingerprint"] == second["stable_fingerprint"]
    assert first["context_hash"] != second["context_hash"]


def test_large_nested_package_does_not_expand_global_review_context(tmp_path):
    root_config = copy.deepcopy(DEFAULTS)
    nested_config = copy.deepcopy(DEFAULTS)
    nested_config["complexity"] += 1
    findings = [
        {
            "rule_id": "SKY-Q301",
            "file": str(tmp_path / "package" / f"module_{index}.py"),
            "line": 1,
            "_analysis_worker_config": nested_config,
        }
        for index in range(2_100)
    ]
    result = {"quality": findings}

    _attach_effective_review_config_hashes(result, root_config)
    context = _context(tmp_path, config=root_config, enable_quality=True)

    assert review_context_is_valid(context)
    assert len(json.dumps(context)) < 10_000
    assert all(
        item.get("_analysis_config_hash", "").startswith("sha256:")
        for item in findings
    )
    assert all("_analysis_worker_config" not in item for item in findings)


def test_no_source_findings_receive_the_same_effective_review_context(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM ubuntu:latest\n", encoding="utf-8")
    finding = {
        "rule_id": "SKY-D234",
        "file": str(dockerfile),
        "line": 1,
        "severity": "HIGH",
        "message": "container runs as root",
    }
    options = {
        "enable_danger": True,
        "include_review_context": True,
        "grep_verify": False,
        "exclude_folders": ["node_modules"],
        "project_config_overrides": {
            "security_contracts": [{"rule_id": "SKY-SC001"}],
        },
        "required_config_rules": ["SKY-GPU001"],
    }

    with patch("skylos.rules.config.scan_config_files", return_value=[finding]):
        no_source = json.loads(analyze(str(tmp_path), **options))

    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    with patch("skylos.rules.config.scan_config_files", return_value=[finding]):
        with_source = json.loads(analyze(str(tmp_path), **options))

    no_source_context = no_source["analysis_summary"]["review_context"]
    with_source_context = with_source["analysis_summary"]["review_context"]
    assert no_source["danger"]
    assert review_context_is_valid(no_source_context)
    assert no_source_context == with_source_context


def test_no_source_security_secret_sca_and_ai_findings_all_get_context(
    tmp_path,
):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies": {}}\n', encoding="utf-8")

    class ScaFindings(list):
        receipt = {"status": "complete", "complete": True}

    with (
        patch(
            "skylos.rules.config.scan_config_files",
            return_value=[
                {
                    "rule_id": "SKY-D234",
                    "file": str(manifest),
                    "line": 1,
                    "severity": "HIGH",
                    "message": "unsafe deployment config",
                }
            ],
        ),
        patch(
            "skylos.analyzer._scan_secret_config_candidates",
            return_value=[
                {
                    "rule_id": "SKY-S101",
                    "file": str(manifest),
                    "line": 1,
                    "severity": "HIGH",
                    "message": "secret",
                }
            ],
        ),
        patch(
            "skylos.rules.ai_defect.manifest_dependency_hallucination.scan_manifest_dependency_hallucinations",
            return_value=[
                {
                    "rule_id": "SKY-D222",
                    "file": str(manifest),
                    "line": 1,
                    "severity": "MEDIUM",
                    "message": "unknown package",
                }
            ],
        ),
        patch(
            "skylos.rules.sca.vulnerability_scanner.scan_dependencies",
            return_value=ScaFindings(
                [
                    {
                        "rule_id": "SKY-SCA-001",
                        "file": str(manifest),
                        "line": 1,
                        "severity": "HIGH",
                        "message": "vulnerable package",
                    }
                ]
            ),
        ),
    ):
        result = json.loads(
            analyze(
                str(tmp_path),
                enable_danger=True,
                enable_secrets=True,
                enable_sca=True,
                enable_ai_defects=True,
                include_review_context=True,
                grep_verify=False,
            )
        )

    assert result["danger"]
    assert result["secrets"]
    assert result["dependency_vulnerabilities"]
    assert result["ai_defects"]
    assert review_context_is_valid(result["analysis_summary"]["review_context"])


def test_ordinary_scan_omits_review_context_and_transient_config_fields(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "pyproject.toml").write_text(
        "[tool.skylos]\ncomplexity = 1\n",
        encoding="utf-8",
    )
    (package / "app.py").write_text(
        "def branchy(value):\n"
        "    if value:\n"
        "        return 1\n"
        "    return 0\n\n"
        "print(branchy(True))\n",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_quality=True,
            grep_verify=False,
        )
    )

    assert "review_context" not in result["analysis_summary"]
    serialized = json.dumps(result)
    assert "_analysis_worker_config" not in serialized
    assert "_analysis_config_hash" not in serialized


def test_reviewed_dead_finding_matches_an_ordinary_cli_scan(
    tmp_path,
    monkeypatch,
    capsys,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    source = repo / "app.py"
    source.write_text("def orphan():\n    return 1\n", encoding="utf-8")
    notes = repo / "notes.txt"
    notes.write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "app.py", "notes.txt"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Skylos Test",
            "-c",
            "user.email=skylos-test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    # Review enables diff-aware categories, so it auto-detects this unrelated
    # worktree change. An ordinary dead-code scan does not; the dead-code
    # identity must ignore that category-specific internal selection.
    notes.write_text("changed\n", encoding="utf-8")
    cloud_cache = tmp_path / "reviewed-findings"
    local_cache = tmp_path / "local-review-decisions"
    monkeypatch.setattr(
        review_cmd.review_decisions,
        "_cache_root",
        lambda value=None: (
            Path(value).expanduser() if value is not None else cloud_cache
        ),
    )
    monkeypatch.setattr(
        review_cmd.review_decisions,
        "_local_cache_root",
        lambda value=None: (
            Path(value).expanduser() if value is not None else local_cache
        ),
    )
    for key in (
        "CI",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_JOB",
        "CI_PIPELINE_ID",
        "BUILD_BUILDID",
        "CIRCLE_WORKFLOW_ID",
        "BUILD_TAG",
    ):
        monkeypatch.delenv(key, raising=False)

    def choose_dead(_console, findings, _input_fn):
        return next(
            finding
            for finding in findings
            if finding.get("_review_category") == "DEAD_CODE"
            and finding.get("symbol") == "orphan"
        )

    monkeypatch.setattr(review_cmd, "_choose_finding", choose_dead)
    answers = iter(["1", "unused test helper"])
    review_exit = review_cmd.run_review_command(
        [str(repo)],
        input_fn=lambda _prompt: next(answers),
        environ={},
    )
    assert review_exit == 0

    capsys.readouterr()
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", str(repo), "--json", "--no-provenance"],
    )
    cli.main()
    result = json.loads(capsys.readouterr().out)

    assert result["unused_functions"] == []
    assert any(
        finding.get("symbol") == "orphan"
        for finding in result.get("reviewed_findings", [])
    )


def test_invalid_or_tampered_review_context_does_not_mint_identity(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "def write_report(path):\n    open(path, 'w').write('ok')\n",
        encoding="utf-8",
    )
    context = _context(tmp_path, enable_danger=True)
    tampered = copy.deepcopy(context)
    tampered["scope"]["targets"] = ["other"]

    annotated = annotate_result_identities(
        _synthetic_result(source, tampered),
        tmp_path,
    )

    assert "stable_fingerprint" not in annotated["danger"][0]


def test_malformed_effective_file_config_hash_does_not_mint_identity(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "def write_report(path):\n    open(path, 'w').write('ok')\n",
        encoding="utf-8",
    )
    result = _synthetic_result(source, _context(tmp_path, enable_danger=True))
    result["danger"][0]["_analysis_config_hash"] = "not-a-sha256"

    annotated = annotate_result_identities(result, tmp_path)

    assert "stable_fingerprint" not in annotated["danger"][0]
    assert "_analysis_config_hash" not in annotated["danger"][0]


def test_severity_and_evidence_changes_resurface_with_same_context(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "def write_report(path):\n    open(path, 'w').write('ok')\n",
        encoding="utf-8",
    )
    context = _context(tmp_path, enable_danger=True)
    baseline = annotate_result_identities(
        _synthetic_result(source, context),
        tmp_path,
    )["danger"][0]
    critical = annotate_result_identities(
        _synthetic_result(source, context, severity="CRITICAL"),
        tmp_path,
    )["danger"][0]
    verified_contract = copy.deepcopy(
        _synthetic_result(source, context)["danger"][0]["evidence_contract"]
    )
    verified_contract["proof_state"] = "verified"
    verified = annotate_result_identities(
        _synthetic_result(source, context, evidence_contract=verified_contract),
        tmp_path,
    )["danger"][0]

    assert baseline["context_hash"] != critical["context_hash"]
    assert baseline["context_hash"] != verified["context_hash"]
