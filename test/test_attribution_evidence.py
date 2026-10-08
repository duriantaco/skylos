from __future__ import annotations

import json
import subprocess

import pytest

from skylos.commands.hook_attribution import capture_after, capture_before
from skylos.commands import hook_attribution
from skylos.reporting import attribution_evidence as evidence
from skylos.reporting.provenance import (
    analyze_provenance,
    annotate_findings_with_provenance,
)


def git(root, *args):
    return (
        subprocess.check_output(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=root,
            stderr=subprocess.DEVNULL,
        )
        .decode()
        .strip()
    )


@pytest.fixture
def repository(tmp_path):
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.name", "Test User")
    git(tmp_path, "config", "user.email", "test@example.com")
    (tmp_path / "app.py").write_text("first = 1\nsecond = 2\nthird = 3\n")
    git(tmp_path, "add", "app.py")
    git(tmp_path, "commit", "-m", "initial")
    git(tmp_path, "update-ref", "refs/remotes/origin/main", "HEAD")
    return tmp_path


def note_text(path="app.py"):
    return (
        f"{path}\n  s_0123456789abcd::t_0123456789abcd 2\n  h_0123456789abcd 1\n---\n"
        + json.dumps(
            {
                "schema_version": "authorship/3.0.0",
                "base_commit_sha": "0" * 40,
                "prompts": {},
                "sessions": {
                    "s_0123456789abcd": {
                        "agent_id": {
                            "tool": "claude",
                            "id": "session",
                            "model": "model",
                        }
                    }
                },
                "humans": {
                    "h_0123456789abcd": {"author": "Test User <test@example.com>"}
                },
            }
        )
    )


def trace(
    root,
    *,
    ranges=None,
    source=None,
    revision=None,
    filename="trace.json",
    tool="codex",
):
    text = (root / "app.py").read_text()
    record = {
        "version": "0.1.0",
        "id": "00000000-0000-4000-8000-000000000001",
        "timestamp": "2026-10-08T00:00:00Z",
        "tool": {"name": tool},
        "files": [
            {
                "path": "app.py",
                "conversations": [
                    {
                        "contributor": {"type": "ai", "model_id": "openai/test-model"},
                        "ranges": ranges or [{"start_line": 2, "end_line": 2}],
                    }
                ],
            }
        ],
    }
    if source != "unbound":
        record["metadata"] = {
            "dev.skylos": {
                "files": {"app.py": {"content_hash": evidence.content_hash(text)}}
            }
        }
    if revision:
        record["vcs"] = {"type": "git", "revision": revision}
    directory = root / ".agent-trace"
    directory.mkdir(exist_ok=True)
    (directory / filename).write_text(json.dumps(record))
    return record


def payload(root, tool="Edit", tool_id="edit-1", **tool_input):
    return {
        "cwd": str(root),
        "session_id": "test-session",
        "tool_use_id": tool_id,
        "tool_name": tool,
        "model_id": "anthropic/test-model",
        "tool_input": {"file_path": str(root / "app.py"), **tool_input},
    }


def test_git_ai_published_session_and_known_human_format():
    parsed = evidence.parse_git_ai_note(note_text())
    assert parsed["app.py"][0]["agent_lines"] == [(2, 2)]
    assert parsed["app.py"][0]["type"] == "ai"
    assert parsed["app.py"][1]["type"] == "human"


def test_git_ai_legacy_prompt_and_quoted_path():
    text = '"dir/my file.py"\n  0123456789abcdef 1-2,4\n---\n' + json.dumps(
        {
            "schema_version": "authorship/3.0.0",
            "base_commit_sha": "0" * 40,
            "prompts": {
                "0123456789abcdef": {
                    "agent_id": {"tool": "cursor", "id": "old", "model": "model"}
                }
            },
        }
    )
    assert evidence.parse_git_ai_note(text)["dir/my file.py"][0]["agent_lines"] == [
        (1, 2),
        (4, 4),
    ]


@pytest.mark.parametrize(
    "path",
    [
        "../outside.py",
        "/tmp/outside.py",
        "dir/../outside.py",
        ".git/config",
        "C:/app.py",
        "dir\\app.py",
    ],
)
def test_git_ai_rejects_unsafe_paths(path):
    assert evidence.parse_git_ai_note(note_text(path)) == {}


@pytest.mark.parametrize(
    "change",
    [
        (
            "  s_0123456789abcd::t_0123456789abcd 2",
            "   s_0123456789abcd::t_0123456789abcd 2",
        ),
        (
            "  s_0123456789abcd::t_0123456789abcd 2",
            "  s_0123456789abcd::t_0123456789abcd 0",
        ),
        (
            "  s_0123456789abcd::t_0123456789abcd 2",
            "  s_0123456789abcd::t_0123456789abcd 3-2",
        ),
        ("authorship/3.0.0", "authorship/99.0.0"),
    ],
)
def test_git_ai_rejects_invalid_records(change):
    assert evidence.parse_git_ai_note(note_text().replace(*change)) == {}


def test_git_ai_note_is_bound_to_head_and_current_content(repository):
    git(repository, "notes", "--ref=refs/notes/ai", "add", "-m", note_text(), "HEAD")
    report = analyze_provenance(repository)
    file = report.files["app.py"]
    assert file.attribution_level == "recorded"
    assert file.evidence_source == "git_ai"
    assert file.agent_lines == [(2, 2)]
    assert file.revision == git(repository, "rev-parse", "HEAD")
    assert report.human_files == ["app.py"]
    findings = annotate_findings_with_provenance(
        [
            {"file": "app.py", "line": 1},
            {"file": "app.py", "line": 2},
            {"file": "app.py", "line": 3},
        ],
        report,
    )
    assert [f["ai_authored"] for f in findings] == [False, True, None]
    (repository / "app.py").write_text("manually changed\n")
    changed = analyze_provenance(repository)
    assert changed.agent_files == []
    assert changed.status["line_records_summary"]["stale_files"] == 1


def test_trace_content_hash_binding_and_commit_revision(repository):
    trace(repository)
    report = analyze_provenance(repository)
    file = report.files["app.py"]
    assert file.agent_lines == [(2, 2)]
    assert file.revision == git(repository, "rev-parse", "HEAD")
    (repository / "app.py").write_text("new line\nfirst = 1\nsecond = 2\nthird = 3\n")
    assert analyze_provenance(repository).agent_files == []


def test_trace_git_revision_binding_without_vendor_metadata(repository):
    trace(repository, source="unbound", revision=git(repository, "rev-parse", "HEAD"))
    assert (
        analyze_provenance(repository).files["app.py"].attribution_level == "recorded"
    )


def test_unbound_trace_cannot_become_recorded(repository):
    trace(repository, source="unbound")
    assert analyze_provenance(repository).agent_files == []


def test_bad_range_and_range_hash_cannot_become_recorded(repository):
    trace(repository, ranges=[{"start_line": 2, "end_line": 200}])
    assert analyze_provenance(repository).agent_files == []
    trace(
        repository,
        ranges=[{"start_line": 2, "end_line": 2, "content_hash": "sha256:" + "0" * 64}],
    )
    assert analyze_provenance(repository).agent_files == []


def test_trace_rejects_symlink_source_and_parent(repository, tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("first = 1\nsecond = 2\nthird = 3\n")
    record = trace(repository)
    (repository / "app.py").unlink()
    (repository / "app.py").symlink_to(outside)
    assert analyze_provenance(repository).agent_files == []
    (repository / "app.py").unlink()
    (repository / "app.py").write_text(outside.read_text())
    (repository / "linked").symlink_to(outside.parent, target_is_directory=True)
    record["files"][0]["path"] = f"linked/{outside.name}"
    (repository / ".agent-trace/trace.json").write_text(json.dumps(record))
    assert analyze_provenance(repository).agent_files == []


def test_conflicting_agent_records_stay_unknown(repository):
    trace(repository, tool="claude", filename="one.json")
    trace(repository, tool="codex", filename="two.json")
    report = analyze_provenance(repository)
    assert report.agent_files == []
    finding = annotate_findings_with_provenance(
        [{"file": "app.py", "line": 2}], report
    )[0]
    assert finding["ai_authored"] is None
    assert finding["attribution_level"] == "unknown"
    from skylos.api._ai_detection import detect_ai_code

    detection = detect_ai_code(repository)
    assert detection["detected"] is False
    assert detection["attribution_level"] == "unknown"


def test_declared_commit_does_not_claim_unchanged_context_or_line_ownership(repository):
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    git(repository, "add", "app.py")
    git(
        repository,
        "commit",
        "-m",
        "AI assisted\n\nCo-authored-by: Claude <noreply@anthropic.com>",
    )
    report = analyze_provenance(repository)
    assert report.files["app.py"].agent_lines == []
    assert report.files["app.py"].attribution_level == "declared"
    assert report.confidence == "low"
    findings = annotate_findings_with_provenance(
        [{"file": "app.py", "line": 1}, {"file": "app.py", "line": 2}], report
    )
    assert all(f["ai_authored"] is None and f["ai_declared"] for f in findings)


def test_named_commit_and_other_agents_line_record_both_survive(repository):
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 30\n")
    git(repository, "add", "app.py")
    git(
        repository,
        "commit",
        "-m",
        "AI assisted\n\nCo-authored-by: Claude <noreply@anthropic.com>",
    )
    trace(repository, tool="cursor", ranges=[{"start_line": 2, "end_line": 3}])

    report = analyze_provenance(repository)
    file = report.to_dict()["files"]["app.py"]
    assert file["agent_authored"] is True
    assert file["attribution_level"] == "recorded"
    assert file["agent_name"] == "cursor"
    assert file["contributors"][0]["agent_name"] == "cursor"
    assert file["contributors"][0]["agent_lines"] == [(2, 3)]
    assert file["commit_contributors"] == [
        {
            "type": "ai",
            "agent_name": "claude",
            "agent_lines": [],
            "evidence_source": "commit_metadata",
        }
    ]
    assert report.summary["agents_seen"] == ["claude", "cursor"]
    assert report.summary["declared_count"] == 1
    assert report.summary["recorded_count"] == 1
    findings = annotate_findings_with_provenance(
        [{"file": "app.py", "line": 1}, {"file": "app.py", "line": 2}], report
    )
    assert findings[0]["ai_authored"] is None
    assert findings[0]["ai_agent"] is None
    assert findings[1]["ai_authored"] is True
    assert findings[1]["ai_agent"] == "cursor"
    assert all(f["ai_declared"] for f in findings)
    assert all(f["ai_declared_agents"] == ["claude"] for f in findings)

    from skylos.api import _detect_report_provenance_data

    upload = _detect_report_provenance_data(repository)
    assert (
        upload["files"]["app.py"]["commit_contributors"] == file["commit_contributors"]
    )
    assert upload["summary"]["agents_seen"] == ["claude", "cursor"]


@pytest.mark.parametrize("record_type", ["human", "unknown"])
def test_non_agent_line_records_cannot_erase_named_commit_policy_or_ai_hint(
    repository, record_type
):
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    git(repository, "add", "app.py")
    git(
        repository,
        "commit",
        "-m",
        "AI assisted\n\nCo-authored-by: Claude <noreply@anthropic.com>",
    )
    record = trace(repository, tool="cursor")
    record["files"][0]["conversations"][0]["contributor"] = {"type": record_type}
    (repository / ".agent-trace/trace.json").write_text(json.dumps(record))

    report = analyze_provenance(repository)
    file = report.files["app.py"]
    assert file.agent_authored is True, "the independent file declaration survives"
    assert file.agent_lines == []
    assert file.agent_name is None, (
        "a human/unknown range does not acquire an AI writer"
    )
    assert file.commit_contributors[0]["agent_name"] == "claude"
    assert report.agent_files == ["app.py"]
    assert report.summary["declared_count"] == 1
    assert report.summary["recorded_count"] == 0
    assert report.summary["agents_seen"] == ["claude"]
    assert report.confidence == "low"
    findings = annotate_findings_with_provenance(
        [
            {"file": "app.py", "line": 1},
            {
                "file": "app.py",
                "line": 2,
                "category": "danger",
                "rule_id": "SKY-D201",
                "severity": "HIGH",
                "message": "eval() usage",
            },
        ],
        report,
    )
    assert findings[0]["ai_authored"] is None
    assert findings[1]["ai_authored"] is (False if record_type == "human" else None)
    assert all(f["ai_declared"] for f in findings)
    assert all(f["ai_declared_agents"] == ["claude"] for f in findings)
    assert all(f["ai_agent"] is None for f in findings)

    from skylos.api import _detect_report_provenance_data
    from skylos.api._ai_detection import detect_ai_code
    from skylos.cicd.risk_passport import build_risk_passport

    hint = detect_ai_code(repository)
    assert hint["detected"] is True
    assert hint["ai_files"] == ["app.py"]
    assert hint["attribution_level"] == "declared"
    upload = _detect_report_provenance_data(repository)
    assert upload["files"]["app.py"]["agent_authored"] is True
    assert upload["files"]["app.py"]["commit_contributors"][0]["agent_name"] == "claude"
    passport = build_risk_passport(
        all_findings=findings, diff_findings=[findings[1]], provenance=upload
    )
    assert passport["recommendation"] == "BLOCK"
    assert passport["ai_authored_files"] == 0
    assert passport["declared_agent_files"] == 1
    assert passport["ai_agents"] == ["claude"]
    assert passport["high_risk_ai_files"] == []
    assert passport["reasons"] == [
        "Declared agent file association: proven HIGH security finding"
    ]


def test_multiple_commit_declarations_survive_a_third_agents_line_record(repository):
    for agent, message in [("Claude", "first"), ("Codex", "second")]:
        (repository / "app.py").write_text(
            f"first = '{message}'\nsecond = 2\nthird = 3\n"
        )
        git(repository, "add", "app.py")
        git(repository, "commit", "-m", f"Change\n\nGenerated-by: {agent}")
    trace(repository, tool="cursor")
    report = analyze_provenance(repository)
    assert report.summary["agents_seen"] == ["claude", "codex", "cursor"]
    assert report.summary["declared_count"] == 1
    assert [c["agent_name"] for c in report.files["app.py"].commit_contributors] == [
        "claude",
        "codex",
    ]
    finding = annotate_findings_with_provenance(
        [{"file": "app.py", "line": 1}], report
    )[0]
    assert finding["ai_authored"] is None
    assert finding["ai_declared"] is True
    assert finding["ai_declared_agents"] == ["claude", "codex"]


def test_untagged_commits_are_unknown_not_human(repository):
    (repository / "app.py").write_text("changed = 1\n")
    git(repository, "add", "app.py")
    git(repository, "commit", "-m", "ordinary unlabelled commit")
    report = analyze_provenance(repository)
    assert report.human_files == []
    assert report.unknown_files == ["app.py"]


def test_hook_records_exact_diff_not_approximate_payload_ranges(repository):
    edit = payload(repository, old_string="second = 2", new_string="second = 20")
    assert capture_before(repository, "claude", edit)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    edit["tool_response"] = {"structuredPatch": [{"newStart": 99, "lines": ["+wrong"]}]}
    assert capture_after(repository, "claude", edit)
    file = analyze_provenance(repository).files["app.py"]
    assert file.agent_lines == [(2, 2)]
    assert file.revision is None
    trace_file = next((repository / ".skylos/agent-traces").glob("*.json"))
    raw = trace_file.read_text()
    assert "second = 20" not in raw
    assert "second = 2" not in raw


def test_hook_write_uses_actual_changed_lines_and_later_drift_invalidates(repository):
    after = "first = 1\nsecond = 20\nthird = 3\n"
    edit = payload(repository, tool="Write", content=after)
    capture_before(repository, "codex", edit)
    (repository / "app.py").write_text(after)
    capture_after(repository, "codex", edit)
    assert analyze_provenance(repository).files["app.py"].agent_lines == [(2, 2)]
    (repository / "app.py").write_text("manual\n" + after)
    assert analyze_provenance(repository).agent_files == []


def test_hook_retains_unique_unchanged_lines_across_another_agent_edit(repository):
    first = payload(repository, old_string="second = 2", new_string="second = 20")
    capture_before(repository, "claude", first)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    capture_after(repository, "claude", first)
    second = payload(
        repository, tool_id="edit-2", old_string="third = 3", new_string="third = 30"
    )
    capture_before(repository, "codex", second)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 30\n")
    capture_after(repository, "codex", second)
    report = analyze_provenance(repository)
    findings = annotate_findings_with_provenance(
        [{"file": "app.py", "line": 2}, {"file": "app.py", "line": 3}], report
    )
    assert [f["ai_agent"] for f in findings] == ["claude", "codex"]


def test_hook_ambiguous_duplicate_edit_is_unknown(repository):
    (repository / "app.py").write_text("duplicate\nduplicate\n")
    edit = payload(repository, old_string="duplicate", new_string="new")
    capture_before(repository, "claude", edit)
    (repository / "app.py").write_text("new\nduplicate\n")
    capture_after(repository, "claude", edit)
    assert analyze_provenance(repository).agent_files == []


def test_hook_missing_checkpoint_and_shell_changes_are_unknown(repository):
    edit = payload(repository, old_string="second = 2", new_string="second = 20")
    capture_after(repository, "claude", edit)
    assert analyze_provenance(repository).agent_files == []
    shell = payload(repository, tool="Bash", command="some script")
    capture_before(repository, "claude", shell, shell=True)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    capture_after(repository, "claude", shell, shell=True)
    report = analyze_provenance(repository)
    assert report.agent_files == []
    assert report.status["line_records_summary"]["capture_gaps"] == 2


def test_hook_validates_patch_bytes_before_recording_agent(repository):
    edit = payload(
        repository,
        tool="apply_patch",
        command="*** Begin Patch\n*** Update File: app.py\n@@\n first = 1\n-second = 2\n+second = 20\n third = 3\n*** End Patch",
    )
    capture_before(repository, "codex", edit)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    capture_after(repository, "codex", edit)
    assert analyze_provenance(repository).files["app.py"].agent_lines == [(2, 2)]


def test_hook_failed_tool_and_overlapping_checkpoint_do_not_record_ai(repository):
    edit = payload(repository, old_string="second = 2", new_string="second = 20")
    capture_before(repository, "claude", edit)
    capture_before(repository, "claude", edit)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    capture_after(repository, "claude", edit)
    assert analyze_provenance(repository).agent_files == []


def test_distinct_parallel_tool_ids_on_same_file_are_unknown(repository):
    first = payload(repository, old_string="second = 2", new_string="second = 20")
    second = payload(
        repository,
        tool_id="other-call",
        old_string="second = 2",
        new_string="second = 20",
    )
    capture_before(repository, "claude", first)
    capture_before(repository, "claude", second)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    capture_after(repository, "claude", first)
    capture_after(repository, "claude", second)
    assert analyze_provenance(repository).agent_files == []


def test_partial_failed_edit_captures_unknown_lines(repository):
    edit = payload(repository, old_string="second = 2", new_string="second = 20")
    capture_before(repository, "claude", edit)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    edit["hook_event_name"] = "PostToolUseFailure"
    capture_after(repository, "claude", edit)
    report = analyze_provenance(repository)
    assert report.agent_files == []
    assert report.files["app.py"].contributors[0]["type"] == "unknown"


def test_current_trace_keeps_advancing_after_history_fills(repository, monkeypatch):
    monkeypatch.setattr(hook_attribution, "MAX_RECORDS", 2)
    first = payload(repository, old_string="second = 2", new_string="second = 20")
    capture_before(repository, "claude", first)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 3\n")
    assert capture_after(repository, "claude", first)
    second = payload(
        repository, tool_id="edit-2", old_string="third = 3", new_string="third = 30"
    )
    capture_before(repository, "codex", second)
    (repository / "app.py").write_text("first = 1\nsecond = 20\nthird = 30\n")
    assert capture_after(repository, "codex", second)
    assert len(list((repository / ".skylos/agent-traces").glob("*.json"))) == 2
    report = analyze_provenance(repository)
    findings = annotate_findings_with_provenance(
        [{"file": "app.py", "line": 2}, {"file": "app.py", "line": 3}], report
    )
    assert [f["ai_agent"] for f in findings] == ["claude", "codex"]


def test_same_agent_different_models_keep_separate_contributors(repository):
    record = trace(repository)
    record["files"][0]["conversations"].append(
        {
            "contributor": {"type": "ai", "model_id": "openai/another-model"},
            "ranges": [{"start_line": 3, "end_line": 3}],
        }
    )
    (repository / ".agent-trace/trace.json").write_text(json.dumps(record))
    contributors = analyze_provenance(repository).files["app.py"].contributors
    assert {c["model_id"] for c in contributors} == {
        "openai/test-model",
        "openai/another-model",
    }


def test_absolute_paths_require_known_repository_root(repository):
    trace(repository)
    report = analyze_provenance(repository)
    findings = annotate_findings_with_provenance(
        [
            {"file": str(repository / "app.py"), "line": 2},
            {"file": str(repository.parent / "another" / "app.py"), "line": 2},
        ],
        report,
    )
    assert findings[0]["ai_authored"] is True
    assert findings[1]["ai_authored"] is None


@pytest.mark.parametrize("value", [".", "", "..", "a/./b", "a//b", "a/../b", 1, [], {}])
def test_invalid_path_types_never_raise(value):
    assert evidence.safe_relative_path(value) is None


@pytest.mark.parametrize("value", [1, [], {}, None])
def test_invalid_git_ai_base_types_never_raise(value):
    text = note_text().replace(
        '"base_commit_sha": "' + "0" * 40 + '"',
        '"base_commit_sha": ' + json.dumps(value),
    )
    assert evidence.parse_git_ai_note(text) == {}


def test_git_ai_extremely_large_range_numbers_are_rejected():
    text = note_text().replace(
        "  s_0123456789abcd::t_0123456789abcd 2",
        "  s_0123456789abcd::t_0123456789abcd " + "9" * 5000,
    )
    assert evidence.parse_git_ai_note(text) == {}


@pytest.mark.parametrize(
    "mutation",
    [
        "root_list",
        "metadata_list",
        "range_hash_number",
        "vcs_revision_list",
        "contributor_list",
    ],
)
def test_malformed_trace_never_crashes_scan(repository, mutation):
    record = trace(repository, source="unbound")
    if mutation == "root_list":
        record = []
    elif mutation == "metadata_list":
        record["metadata"] = ["unexpected"]
    elif mutation == "range_hash_number":
        record["files"][0]["conversations"][0]["ranges"][0]["content_hash"] = 42
    elif mutation == "vcs_revision_list":
        record["vcs"] = {"type": "git", "revision": []}
    elif mutation == "contributor_list":
        record["files"][0]["conversations"][0]["contributor"] = []
    (repository / ".agent-trace/trace.json").write_text(json.dumps(record))
    report = analyze_provenance(repository)
    assert report.agent_files == []
    assert report.status["line_records_summary"]["rejected_records"] == 1


def test_reader_limits_oversized_records_and_source_bytes(repository, monkeypatch):
    trace(repository)
    monkeypatch.setattr(evidence, "MAX_RECORD_BYTES", 100)
    assert analyze_provenance(repository).agent_files == []
    monkeypatch.setattr(evidence, "MAX_RECORD_BYTES", 2_000_000)
    monkeypatch.setattr(evidence, "MAX_TOTAL_BYTES", 1)
    report = analyze_provenance(repository)
    assert report.agent_files == []
    assert report.status["line_records_summary"]["limited"] is True


def test_tool_names_are_canonicalized_without_classifying_unknown_tools(repository):
    trace(repository, tool="claude-code")
    assert analyze_provenance(repository).files["app.py"].agent_name == "claude"
    trace(repository, tool="my-custom-agent")
    assert (
        analyze_provenance(repository).files["app.py"].agent_name == "my-custom-agent"
    )


def test_missing_before_image_never_adopts_reported_whole_file_ownership(repository):
    edit = payload(
        repository, tool="Write", content=(repository / "app.py").read_text()
    )
    edit["tool_response"] = {"type": "create"}
    capture_after(repository, "claude", edit)
    report = analyze_provenance(repository)
    assert report.agent_files == []
    assert report.status["line_records_summary"]["capture_gaps"] == 1
