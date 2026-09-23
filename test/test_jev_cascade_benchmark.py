import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import jev_cascade_benchmark as benchmark
from scripts.jev_cascade_benchmark import _matches, _reported, _score


def test_source_root_stages_nested_file_without_following_symlinks(tmp_path: Path):
    root = benchmark._source_root(
        tmp_path,
        [{"path": "pkg/module.py", "content": "answer = 42\n"}],
        "static",
    )

    assert root == (tmp_path / "static" / "project").resolve()
    assert (root / "pkg" / "module.py").read_text(encoding="utf-8") == ("answer = 42\n")


@pytest.mark.parametrize(
    "path", ["../escape.py", "pkg/../../escape.py", "/escape.py", ""]
)
def test_source_root_rejects_paths_outside_snapshot(tmp_path: Path, path: str):
    with pytest.raises(benchmark.JevBenchmarkError, match="unsafe staged source path"):
        benchmark._source_root(
            tmp_path,
            [{"path": path, "content": "escaped = True\n"}],
            "static",
        )

    assert not list(tmp_path.rglob("escape.py"))


def test_source_root_rejects_preexisting_arm_symlink(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (tmp_path / "static").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(
        benchmark.JevBenchmarkError, match="cannot create isolated static source root"
    ):
        benchmark._source_root(
            tmp_path,
            [{"path": "module.py", "content": "escaped = True\n"}],
            "static",
        )

    assert not (outside / "project").exists()


def test_source_root_rejects_unknown_arm(tmp_path: Path):
    with pytest.raises(benchmark.JevBenchmarkError, match="unsupported benchmark arm"):
        benchmark._source_root(tmp_path, [], "../outside")

    assert not any(tmp_path.iterdir())


def test_cascade_reported_keeps_jev_only_static_finding():
    output = {
        "verified_findings": [
            {"name": "old", "_jev_agreed": True},
            {"name": "rescued", "_llm_verdict": "FALSE_POSITIVE"},
            {"name": "confirmed", "_llm_verdict": "TRUE_POSITIVE"},
            {"name": "uncertain", "_llm_verdict": "UNCERTAIN"},
            {
                "name": "jev_retained",
                "_jev_judged_retained": True,
                "_llm_verdict": "TRUE_POSITIVE",
            },
        ],
        "new_dead_code": [{"name": "challenged"}],
    }
    assert [item["name"] for item in _reported(output)] == [
        "old",
        "confirmed",
        "challenged",
    ]


def test_label_matching_uses_path_symbol_and_optional_line(tmp_path: Path):
    root = tmp_path / "project"
    finding = {
        "file": str(root / "pkg" / "mod.py"),
        "name": "Handler.handle",
        "type": "function",
        "line": 7,
    }
    assert _matches(
        finding,
        {"file": "pkg/mod.py", "symbol": "handle", "kind": "function", "line": 7},
        root,
    )
    assert not _matches(
        finding,
        {"file": "pkg/mod.py", "symbol": "handle", "kind": "function", "line": 2},
        root,
    )
    assert not _matches(
        finding,
        {"file": "pkg/mod.py", "symbol": "handle", "kind": "class", "line": 7},
        root,
    )


def test_qualified_method_labels_and_line_disambiguate(tmp_path: Path):
    root = tmp_path / "project"
    first = {
        "file": str(root / "code.py"),
        "name": "First.handle",
        "type": "method",
        "line": 3,
    }
    second = {
        "file": str(root / "code.py"),
        "name": "Second.handle",
        "type": "method",
        "line": 8,
    }
    first_label = {"file": "code.py", "symbol": "First.handle", "kind": "function"}
    second_label = {
        "file": "code.py",
        "symbol": "handle",
        "kind": "function",
        "line": 8,
    }
    assert _matches(first, first_label, root)
    assert not _matches(second, first_label, root)
    assert _matches(second, second_label, root)
    assert not _matches(first, second_label, root)


def test_duplicate_and_ambiguous_labels_are_rejected():
    label = {"file": "code.py", "symbol": "old", "kind": "function"}
    with pytest.raises(benchmark.JevBenchmarkError, match="duplicate label"):
        benchmark._validate_labels("case", {"unused": [label], "used": [dict(label)]})
    qualified = {
        "file": "code.py",
        "symbol": "Worker.old",
        "kind": "function",
        "label_id": "other",
    }
    with pytest.raises(benchmark.JevBenchmarkError, match="ambiguous labels"):
        benchmark._validate_labels("case", {"unused": [label], "used": [qualified]})


def test_unlabeled_static_candidate_is_rejected(tmp_path: Path):
    root = tmp_path / "project"
    findings = [
        {
            "file": str(root / "code.py"),
            "name": "surprise",
            "type": "function",
            "line": 1,
        }
    ]
    labels = {
        "unused": [{"file": "code.py", "symbol": "old", "kind": "function"}],
        "used": [],
    }
    with pytest.raises(benchmark.JevBenchmarkError, match="unlabeled static candidate"):
        benchmark._candidate_coverage("case", labels, findings, root)


def test_unlabeled_new_dead_code_is_rejected(tmp_path: Path):
    root = tmp_path / "project"
    findings = [
        {
            "file": str(root / "code.py"),
            "name": "surprise",
            "type": "function",
            "line": 1,
        }
    ]
    labels = {
        "unused": [{"file": "code.py", "symbol": "old", "kind": "function"}],
        "used": [],
    }
    with pytest.raises(
        benchmark.JevBenchmarkError, match="unlabeled or ambiguous new_dead_code"
    ):
        benchmark._validate_new_dead("case", labels, findings, root)


def test_arm_inventory_mismatch_is_rejected_before_verification(
    tmp_path: Path, monkeypatch
):
    case = {
        "id": "case",
        "expect": {
            "unused": [
                {"file": "code.py", "symbol": "first", "kind": "function"},
                {"file": "code.py", "symbol": "second", "kind": "function"},
            ],
            "used": [],
        },
    }
    files = [{"path": "code.py", "content": "def first(): pass\ndef second(): pass\n"}]

    def scan(root, *, scan=None):
        name = "first" if root.parent.name == "static" else "second"
        return (
            [
                {
                    "file": str(root / "code.py"),
                    "name": name,
                    "type": "function",
                    "line": 1,
                }
            ],
            {},
        )

    monkeypatch.setattr(benchmark, "_scan", scan)
    with pytest.raises(benchmark.JevBenchmarkError, match="inventories differ"):
        benchmark._prepare_case(tmp_path, case, files, ["static", "judge"])


def test_manifest_scan_policy_is_used_by_static_analyzer(tmp_path: Path, monkeypatch):
    captured = {}

    def analyze(path, **kwargs):
        captured.update(kwargs)
        return {"definitions": {}}

    monkeypatch.setattr("skylos.analyzer.analyze", analyze)
    benchmark._scan(tmp_path, scan={"confidence": 0, "grep_verify": False})
    assert captured["conf"] == 0
    assert captured["grep_verify"] is False
    assert benchmark._scan_policy(
        {"id": "case", "scan": {"confidence": 0, "grep_verify": True}}
    ) == {
        "confidence": 0,
        "grep_verify": True,
    }
    with pytest.raises(benchmark.JevBenchmarkError, match="unsupported scan settings"):
        benchmark._scan_policy({"id": "case", "scan": {"trace": True}})


def test_expected_manifest_digest_blocks_paid_run_before_cases(tmp_path, monkeypatch):
    output = tmp_path / "never-created.json"
    monkeypatch.setattr(
        benchmark, "_load_manifest_snapshot", lambda path: ({}, "actual-digest")
    )
    monkeypatch.setattr(
        benchmark,
        "_manifest_cases",
        lambda *args: pytest.fail("manifest mismatch must stop before case prep"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "jev_cascade_benchmark.py",
            "--live",
            "--expect-manifest-digest",
            "expected-digest",
            "--output",
            str(output),
        ],
    )
    with pytest.raises(
        benchmark.JevBenchmarkError, match="manifest digest does not match"
    ):
        benchmark.main()
    assert not output.exists()


def test_score_closed_labels():
    rows = [
        {"expected": "unused", "reported": True},
        {"expected": "unused", "reported": False},
        {"expected": "used", "reported": True},
        {"expected": "used", "reported": False},
    ]
    assert _score(rows) == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "accuracy": 0.5,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
    }


def test_legacy_manifest_labels_without_ids_are_supported(tmp_path, monkeypatch):
    def scan(root, *, scan=None):
        return (
            [
                {
                    "file": str(root / "code.py"),
                    "name": "old",
                    "type": "function",
                    "line": 1,
                }
            ],
            {},
        )

    def verify(**kwargs):
        finding = kwargs["findings"][0]
        finding["_llm_verdict"] = "TRUE_POSITIVE"
        return SimpleNamespace(
            output={"verified_findings": [finding], "new_dead_code": [], "stats": {}}
        )

    monkeypatch.setattr(benchmark, "_scan", scan)
    monkeypatch.setattr(benchmark, "run_verification_harness", verify)
    result = benchmark._run_arm(
        tmp_path,
        [{"path": "code.py", "content": "def old():\n    pass\n"}],
        {
            "unused": [{"file": "code.py", "symbol": "old", "kind": "function"}],
            "used": [],
        },
        arm="baseline",
        model="fake",
        api_key="fake",
    )
    assert result["labels"][0]["label_id"] == "code.py:old:"
    assert result["score"]["tp"] == 1


def test_static_arm_scores_every_frozen_label_even_without_a_candidate(
    tmp_path, monkeypatch
):
    def scan(root, *, scan=None):
        return (
            [
                {
                    "file": str(root / "code.py"),
                    "name": "old",
                    "type": "function",
                    "line": 1,
                }
            ],
            {},
        )

    monkeypatch.setattr(benchmark, "_scan", scan)
    result = benchmark._run_static_arm(
        tmp_path,
        [{"path": "code.py", "content": "def old():\n    pass\n"}],
        {
            "unused": [
                {"file": "code.py", "symbol": "old", "kind": "function", "line": 1},
                {
                    "file": "code.py",
                    "symbol": "missing_dead",
                    "kind": "function",
                    "line": 5,
                },
            ],
            "used": [
                {
                    "file": "code.py",
                    "symbol": "missing_live",
                    "kind": "function",
                    "line": 9,
                }
            ],
        },
    )
    assert result["score"] == {
        "tp": 1,
        "fp": 0,
        "fn": 1,
        "tn": 1,
        "accuracy": 2 / 3,
        "precision": 1.0,
        "recall": 0.5,
        "f1": 2 / 3,
    }
    assert len(result["labels"]) == 3
    assert result["stats"] == {"llm_calls": 0, "total_tokens": 0}


def test_static_only_writes_score_without_api_keys_or_verifier(tmp_path, monkeypatch):
    output = tmp_path / "static.json"
    case = {
        "id": "case-1",
        "expect": {
            "unused": [
                {"file": "code.py", "symbol": "old", "kind": "function", "line": 1}
            ],
            "used": [
                {"file": "code.py", "symbol": "live", "kind": "function", "line": 4}
            ],
        },
    }
    monkeypatch.setattr(benchmark, "_load_manifest_snapshot", lambda path: ({}, "hash"))
    monkeypatch.setattr(benchmark, "_manifest_cases", lambda manifest, path: [case])
    monkeypatch.setattr(benchmark, "_safe_case_path", lambda case: tmp_path)
    monkeypatch.setattr(
        benchmark,
        "_read_case_files",
        lambda path: [{"path": "code.py", "content": "def old():\n    pass\n"}],
    )
    monkeypatch.setattr(
        benchmark,
        "_scan",
        lambda root, *, scan=None: (
            [
                {
                    "file": str(root / "code.py"),
                    "name": "old",
                    "type": "function",
                    "line": 1,
                }
            ],
            {},
        ),
    )
    monkeypatch.setattr(
        benchmark,
        "run_verification_harness",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("called verifier")),
    )
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["jev_cascade_benchmark.py", "--static-only", "--output", str(output)],
    )
    assert benchmark.main() == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["arms"] == ["static"]
    assert report["status"] == "complete"
    assert report["static"]["score"]["accuracy"] == 1.0
    assert report["static"]["llm_calls"] == 0
    assert "baseline" not in report
    assert "cascade" not in report


def test_live_report_includes_four_arms_on_identical_labels(tmp_path, monkeypatch):
    output = tmp_path / "four-arms.json"
    case = {
        "id": "case-1",
        "expect": {
            "unused": [
                {"file": "code.py", "symbol": "old", "kind": "function", "line": 1}
            ],
            "used": [
                {"file": "code.py", "symbol": "live", "kind": "function", "line": 4}
            ],
        },
    }
    rows = [
        {"label_id": "old", "expected": "unused", "reported": True},
        {"label_id": "live", "expected": "used", "reported": False},
    ]

    def fake_arm(*args, arm=None, **kwargs):
        return {
            "static_candidate_count": 1,
            "stats": {"llm_calls": int(arm != "static"), "total_tokens": 4},
            "elapsed_seconds": 1.0,
            "static_scan_seconds": 0.1,
            "score": benchmark._score(rows),
            "labels": rows,
        }

    monkeypatch.setattr(benchmark, "_load_manifest_snapshot", lambda path: ({}, "hash"))
    monkeypatch.setattr(benchmark, "_manifest_cases", lambda manifest, path: [case])
    monkeypatch.setattr(benchmark, "_safe_case_path", lambda case: tmp_path)
    monkeypatch.setattr(
        benchmark,
        "_read_case_files",
        lambda path: [{"path": "code.py", "content": "def old():\n    pass\n"}],
    )
    monkeypatch.setattr(
        benchmark, "_run_static_arm", lambda *a, **kw: fake_arm(arm="static")
    )
    monkeypatch.setattr(benchmark, "_run_arm", lambda *a, **kw: fake_arm(**kw))
    monkeypatch.setattr(
        benchmark,
        "_scan",
        lambda root, *, scan=None: (
            [
                {
                    "file": str(root / "code.py"),
                    "name": "old",
                    "type": "function",
                    "line": 1,
                }
            ],
            {},
        ),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    monkeypatch.setenv("TYPESAFE_API_KEY", "fake")
    monkeypatch.setattr(
        sys,
        "argv",
        ["jev_cascade_benchmark.py", "--live", "--output", str(output)],
    )
    assert benchmark.main() == 1  # Stubbed judge has no Jev response.
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["arms"] == ["static", "baseline", "cascade", "judge"]
    assert [report[arm]["score"]["accuracy"] for arm in report["arms"]] == [1.0] * 4
    assert all(len(report["cases"][0][arm]["labels"]) == 2 for arm in report["arms"])
    assert report["verification_mode"] == "judge_all"
    assert report["cases"][0]["scan_policy"] == {
        "confidence": 60,
        "grep_verify": True,
    }
    assert len(report["cases"][0]["source_digest"]) == 64
    assert len(report["cases"][0]["static_candidate_inventory_digest"]) == 64
    assert report["cases"][0]["coverage"] == {
        "static_candidate_count": 1,
        "matched_static_candidate_count": 1,
        "label_count": 2,
        "matched_label_count": 1,
        "unmatched_label_count": 1,
    }


def test_all_cases_preflight_before_any_paid_call(tmp_path, monkeypatch):
    output = tmp_path / "must-not-exist.json"
    cases = [
        {
            "id": case_id,
            "expect": {
                "unused": [{"file": "code.py", "symbol": "old", "kind": "function"}],
                "used": [],
            },
        }
        for case_id in ("first", "second")
    ]
    monkeypatch.setattr(benchmark, "_load_manifest_snapshot", lambda path: ({}, "hash"))
    monkeypatch.setattr(benchmark, "_manifest_cases", lambda manifest, path: cases)
    monkeypatch.setattr(benchmark, "_safe_case_path", lambda case: tmp_path)
    monkeypatch.setattr(
        benchmark,
        "_read_case_files",
        lambda path: [{"path": "code.py", "content": "def old(): pass\n"}],
    )
    calls = []

    def scan(root, *, scan=None):
        calls.append(root)
        name = "old" if len(calls) <= 4 else "unlabeled"
        return (
            [
                {
                    "file": str(root / "code.py"),
                    "name": name,
                    "type": "function",
                    "line": 1,
                }
            ],
            {},
        )

    monkeypatch.setattr(benchmark, "_scan", scan)
    monkeypatch.setattr(
        benchmark,
        "run_verification_harness",
        lambda **kwargs: pytest.fail(
            "paid verifier must not run before all cases pass"
        ),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    monkeypatch.setenv("TYPESAFE_API_KEY", "fake")
    monkeypatch.setattr(
        sys,
        "argv",
        ["jev_cascade_benchmark.py", "--live", "--output", str(output)],
    )
    with pytest.raises(benchmark.JevBenchmarkError, match="unlabeled static candidate"):
        benchmark.main()
    assert len(calls) == 5
    assert not output.exists()


def test_live_judge_only_runs_no_other_paid_arm(tmp_path, monkeypatch):
    output = tmp_path / "judge-only.json"
    case = {
        "id": "case-1",
        "expect": {
            "unused": [
                {"file": "code.py", "symbol": "old", "kind": "function", "line": 1}
            ],
            "used": [],
        },
    }
    called_arms = []

    def fake_arm(*args, arm=None, **kwargs):
        called_arms.append(arm)
        rows = [{"label_id": "old", "expected": "unused", "reported": True}]
        return {
            "static_candidate_count": 1,
            "stats": {"llm_calls": 0, "total_tokens": 0, "jev_agreed": 1},
            "elapsed_seconds": 1.0,
            "static_scan_seconds": 0.1,
            "score": benchmark._score(rows),
            "labels": rows,
        }

    monkeypatch.setattr(benchmark, "_load_manifest_snapshot", lambda path: ({}, "hash"))
    monkeypatch.setattr(benchmark, "_manifest_cases", lambda manifest, path: [case])
    monkeypatch.setattr(benchmark, "_safe_case_path", lambda case: tmp_path)
    monkeypatch.setattr(
        benchmark,
        "_read_case_files",
        lambda path: [{"path": "code.py", "content": "def old():\n    pass\n"}],
    )
    monkeypatch.setattr(benchmark, "_run_static_arm", lambda *a: None)
    monkeypatch.setattr(benchmark, "_run_arm", fake_arm)
    monkeypatch.setattr(
        benchmark,
        "_scan",
        lambda root, *, scan=None: (
            [
                {
                    "file": str(root / "code.py"),
                    "name": "old",
                    "type": "function",
                    "line": 1,
                }
            ],
            {},
        ),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    monkeypatch.setenv("TYPESAFE_API_KEY", "fake")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "jev_cascade_benchmark.py",
            "--live",
            "--judge-only",
            "--output",
            str(output),
        ],
    )

    assert benchmark.main() == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert called_arms == ["judge"]
    assert report["arms"] == ["judge"]
    assert report["status"] == "complete"
    assert report["judge"]["score"]["accuracy"] == 1.0


def test_judge_arm_passes_mode_and_suppresses_confident_retained(tmp_path, monkeypatch):
    captured = {}

    def scan(root, *, scan=None):
        return (
            [
                {
                    "file": str(root / "code.py"),
                    "name": "live",
                    "type": "function",
                    "line": 1,
                }
            ],
            {},
        )

    def verify(**kwargs):
        captured.update(kwargs)
        finding = kwargs["findings"][0]
        finding.update(
            {
                "_jev_judged_retained": True,
                "_jev_status": "disagreed",
                "_jev_choice": "retained",
                "_jev_confidence": 0.91,
                "_jev_choice_probability": 0.95,
                "_llm_verdict": "FALSE_POSITIVE",
            }
        )
        return SimpleNamespace(
            output={"verified_findings": [finding], "new_dead_code": [], "stats": {}}
        )

    monkeypatch.setattr(benchmark, "_scan", scan)
    monkeypatch.setattr(benchmark, "run_verification_harness", verify)
    result = benchmark._run_arm(
        tmp_path,
        [{"path": "code.py", "content": "def live():\n    pass\n"}],
        {
            "unused": [],
            "used": [{"file": "code.py", "symbol": "live", "kind": "function"}],
        },
        arm="judge",
        model="fake",
        api_key="fake",
    )
    assert captured["jev_judge"] is True
    assert captured["jev_precheck"] is False
    assert result["score"]["tn"] == 1
    assert result["labels"][0]["jev_judged_retained"] is True
    assert result["labels"][0]["jev_confidence"] == 0.91
    assert result["labels"][0]["jev_choice_probability"] == 0.95
