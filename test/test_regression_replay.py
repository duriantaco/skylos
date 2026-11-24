"""End-to-end controls for the pytest regression replay prototype."""

import json
import os
import subprocess
import sys

import pytest

from skylos.done.regression_replay import main
from skylos.done.replay_grade import grade


@pytest.fixture(scope="module")
def variants(tmp_path_factory):
    repo = tmp_path_factory.mktemp("replay-fixture")
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}

    def git(*args):
        return subprocess.check_output(("git", *args), cwd=repo, env=env, text=True)

    def commit(label, body):
        (repo / "sorter.py").write_text(f"def order(values):\n    {body}\n")
        git("add", "sorter.py", *(("test_sorter.py",) if label == "fixed" else ()))
        git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.com",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "-qm",
            label,
        )
        return git("rev-parse", "HEAD").strip()

    git("init", "--quiet", "--template=")
    buggy = commit("buggy", "return values")
    partial = commit("partial", "return sorted(values) if len(values) < 3 else values")
    broken = commit("broken", "raise RuntimeError('dependency unavailable')")
    correct = commit("correct", "return list(sorted(tuple(values)))")
    (repo / "test_sorter.py").write_text(
        "from sorter import order\n"
        "import pytest\n\n"
        "def test_behavior():\n"
        "    assert order([3, 1, 2]) == [1, 2, 3]\n\n"
        "def test_weak():\n"
        "    assert order([1, 2]) == [1, 2]\n\n"
        "def test_partial():\n"
        "    assert order([2, 1]) == [1, 2]\n\n"
        "def test_brittle():\n"
        "    assert order([2, 1]) == [1, 2]\n"
        "    assert order.__code__.co_names == ('sorted',)\n\n"
        "@pytest.fixture\n"
        "def initialized():\n"
        "    assert order([2, 1]) == [1, 2]\n\n"
        "def test_setup_only(initialized):\n"
        "    pass\n\n"
        "def test_wrong_expectation():\n"
        "    assert order([2, 1]) == [2, 1]\n\n"
        "@pytest.mark.parametrize('data', [[2, 1]], ids=['reverse'])\n"
        "def test_parameterized(data):\n"
        "    assert order(data) == [1, 2]\n"
    )
    fixed = commit("fixed", "return sorted(values)")
    (repo / "test_submission.py").write_text(
        "from sorter import order\n\n"
        "def test_reverse():\n"
        "    assert order([3, 2, 1]) == [1, 2, 3]\n"
    )
    git("add", "test_submission.py")
    submission = commit("submission", "raise RuntimeError('must never run')")
    # The results must concern the committed test bytes.
    (repo / "test_sorter.py").write_text("raise RuntimeError('dirty checkout')\n")
    return repo, fixed, buggy, partial, broken, correct, submission


@pytest.mark.parametrize(
    ("test_name", "label", "extra", "verdict", "exit_code"),
    [
        ("behavior", "buggy", ["--expect-assertion", "5"], "DETECTED", 0),
        ("behavior", "buggy", ["--expect-assertion", "4"], "UNEXPECTED_ASSERTION", 1),
        ("weak", "buggy", [], "BUG_SURVIVED", 1),
        ("partial", "partial", [], "BUG_SURVIVED", 1),
        ("brittle", "buggy", [], "REJECTED_CORRECT_VARIANT", 1),
        ("behavior", "broken", [], "INCONCLUSIVE", 2),
        ("setup_only", "buggy", [], "INCONCLUSIVE", 2),
        ("wrong_expectation", "buggy", [], "REFERENCE_FAILED", 1),
        ("parameterized[reverse]", "buggy", [], "DETECTED", 0),
    ],
)
def test_replay(variants, test_name, label, extra, verdict, exit_code, capsys):
    repo, fixed, buggy, partial, broken, correct, _ = variants
    outcome = main(
        [
            "--repo",
            str(repo),
            "--fixed",
            fixed,
            "--buggy",
            {"buggy": buggy, "partial": partial, "broken": broken}[label],
            "--correct",
            correct,
            "--source",
            "sorter.py",
            "--test",
            f"test_sorter.py::test_{test_name}",
            "--allow-local-execution",
            *extra,
        ]
    )
    receipt = json.loads(capsys.readouterr().out)
    assert outcome == exit_code, receipt
    assert receipt["verdict"] == verdict
    expected_reference = (
        "assertion_failed" if verdict == "REFERENCE_FAILED" else "passed"
    )
    assert receipt["variants"][0]["status"] == expected_reference
    assert all(len(variant["runs"]) == 2 for variant in receipt["variants"])
    if verdict == "DETECTED":
        assert receipt["variants"][1]["status"] == "assertion_failed"
        assert "assert" in receipt["variants"][1]["runs"][0]["detail"]
        assert receipt["variants"][2]["status"] == "passed"
    assert (
        repo / "test_sorter.py"
    ).read_text() == "raise RuntimeError('dirty checkout')\n"


def test_skylos_done_replay_cli(variants, monkeypatch, capsys):
    from skylos.cli import main as skylos_main

    repo, fixed, buggy, _, _, _, _ = variants
    argv = [
        "skylos",
        "done",
        "replay",
        "--repo",
        str(repo),
        "--fixed",
        fixed,
        "--buggy",
        buggy,
        "--source",
        "sorter.py",
        "--test",
        "test_sorter.py::test_behavior",
        "--expect-assertion",
        "5",
        "--timeout",
        "30",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as denied:
        skylos_main()
    assert denied.value.code == 2
    denied_output = capsys.readouterr()
    assert denied_output.out == ""
    assert "skylos done replay" in denied_output.err
    assert "--allow-local-execution" in denied_output.err

    monkeypatch.setattr(sys, "argv", [*argv, "--allow-local-execution"])
    with pytest.raises(SystemExit) as approved:
        skylos_main()
    output = capsys.readouterr()
    assert approved.value.code == 0, output
    receipt = json.loads(output.out)
    assert receipt["verdict"] == "DETECTED"
    assert [variant["commit"] for variant in receipt["variants"]] == [fixed, buggy]


@pytest.mark.parametrize(
    ("candidate", "baseline", "expected", "outcomes", "exit_code"),
    [
        ("behavior", "partial", "IMPROVED", ["caught_by_both", "candidate_only"], 0),
        ("partial", "behavior", "REGRESSED", ["caught_by_both", "baseline_only"], 1),
        (
            "brittle",
            "behavior",
            "CONTROL_FAILED",
            ["caught_by_both", "caught_by_both"],
            1,
        ),
    ],
)
def test_paired_replay(
    variants, candidate, baseline, expected, outcomes, exit_code, capsys
):
    repo, fixed, buggy, partial, _, correct, _ = variants
    outcome = main(
        [
            "--repo",
            str(repo),
            "--fixed",
            fixed,
            "--buggy",
            buggy,
            "--buggy",
            partial,
            "--correct",
            correct,
            "--source",
            "sorter.py",
            "--allow-local-execution",
            "--test",
            f"test_sorter.py::test_{candidate}",
            "--baseline-test",
            f"test_sorter.py::test_{baseline}",
        ]
    )
    receipt = json.loads(capsys.readouterr().out)
    assert outcome == exit_code, receipt
    assert receipt["verdict"] == expected
    assert [
        pair["outcome"] for pair in receipt["pairs"] if pair["role"] == "buggy"
    ] == outcomes
    assert [v["commit"] for v in receipt["baseline"]["variants"]] == [
        v["commit"] for v in receipt["candidate"]["variants"]
    ]


def test_grade_committed_agent_test_against_reviewed_variants(variants):
    repo, fixed, buggy, partial, _, correct, revision = variants
    task = {
        "fixed": fixed,
        "buggy": [buggy, partial],
        "correct": [correct],
        "source": ["sorter.py"],
    }
    report = grade(
        {
            "benchmark": "Sorting regression",
            "cases": [
                {**task, "id": "submitted", "title": "Submitted case"},
                {**task, "id": "omitted", "title": "Omitted case"},
            ],
        },
        {
            "label": "Fixture submission",
            "tests": {
                "submitted": {
                    "test": "test_submission.py::test_reverse",
                    "revision": revision,
                }
            },
        },
        repo,
        30,
    )
    assert report["counts"] == {
        "passed": 1,
        "failed": 0,
        "missing": 1,
        "inconclusive": 0,
    }
    assert report["total"] == 2
    assert report["cases"][0]["evidence"]["test_commit"] == revision
    assert report["cases"][1]["evidence"] is None
