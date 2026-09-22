from __future__ import annotations

from pathlib import Path

import pytest

from skylos.llm.jev_triage import triage_findings


def _finding(path: Path, name: str = "unused") -> dict:
    return {
        "name": name,
        "simple_name": name,
        "type": "function",
        "file": str(path),
        "line": 1,
        "references": 0,
    }


def _answer(choice: str, confidence: float = 0.95) -> dict:
    probabilities = {
        "retained": 0.025,
        "unreferenced": 0.025,
        "insufficient_evidence": 0.025,
    }
    probabilities[choice] = 0.95
    return {
        "type": "choice",
        "choice": choice,
        "confidence": confidence,
        "probabilities": probabilities,
    }


@pytest.fixture
def small_project(tmp_path: Path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("def unused():\n    pass\n", encoding="utf-8")
    monkeypatch.setenv("TYPESAFE_API_KEY", "local-test-key")
    return tmp_path, source


def test_agreement_batches_candidates_and_sends_complete_project(small_project):
    root, source = small_project
    source.write_text(
        "def unused():\n    pass\ndef other():\n    pass\n", encoding="utf-8"
    )
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'example'\n", encoding="utf-8"
    )
    calls = []

    def transport(payload, key):
        calls.append((payload, key))
        return {
            "model": payload["model"],
            "answers": {
                question_id: _answer("unreferenced")
                for question_id in payload["questions"]
            },
        }

    other = _finding(source, "other")
    other["line"] = 3
    results = triage_findings(root, [_finding(source), other], transport=transport)

    assert [result["status"] for result in results] == ["agreed", "agreed"]
    assert len(calls) == 1
    payload, key = calls[0]
    assert key == "local-test-key"
    assert {item["path"] for item in payload["state"]["repository_files"]} == {
        "app.py",
        "pyproject.toml",
    }
    assert [
        item["instructions"]["target"]["symbol"]
        for item in payload["questions"].values()
    ] == ["unused", "other"]


def test_skylos_run_artifacts_are_not_uploaded(small_project):
    root, source = small_project
    trace_dir = root / ".skylos" / "runs" / "run-123"
    trace_dir.mkdir(parents=True)
    (trace_dir / "events.jsonl").write_text(
        "private trace that must not reach Jev\n" * 4_000, encoding="utf-8"
    )
    cache_dir = root / ".skylos" / "cache"
    cache_dir.mkdir()
    (cache_dir / "grep_results.json").write_text("cached private state\n")
    (root / ".skylos" / "config.yaml").write_text("entrypoints: []\n")

    def transport(payload, _key):
        files = payload["state"]["repository_files"]
        assert {item["path"] for item in files} == {
            "app.py",
            ".skylos/config.yaml",
        }
        assert all("private trace" not in item["content"] for item in files)
        assert all("cached private state" not in item["content"] for item in files)
        return {
            "model": payload["model"],
            "answers": {"q0000": _answer("unreferenced")},
        }

    result = triage_findings(root, [_finding(source)], transport=transport)[0]
    assert result["status"] == "agreed"


@pytest.mark.parametrize(
    ("choice", "confidence", "status"),
    [
        ("unreferenced", 0.79, "uncertain"),
        ("retained", 0.95, "disagreed"),
        ("retained", 0.79, "uncertain"),
        ("insufficient_evidence", 0.95, "uncertain"),
    ],
)
def test_non_agreement_keeps_broad_llm_path(small_project, choice, confidence, status):
    root, source = small_project

    def transport(payload, _key):
        return {
            "model": payload["model"],
            "answers": {"q0000": _answer(choice, confidence)},
        }

    result = triage_findings(root, [_finding(source)], transport=transport)[0]
    assert result["status"] == status
    assert result["choice"] == choice


def test_judge_threshold_applies_to_choice_probability(small_project):
    root, source = small_project

    def transport(payload, _key):
        answer = _answer("retained", 0.99)
        answer["probabilities"]["retained"] = 0.89
        answer["probabilities"]["unreferenced"] = 0.055
        answer["probabilities"]["insufficient_evidence"] = 0.055
        return {
            "model": payload["model"],
            "answers": {"q0000": answer},
        }

    result = triage_findings(
        root,
        [_finding(source)],
        transport=transport,
        min_confidence=0.9,
    )[0]
    assert result["status"] == "uncertain"
    assert result["choice_probability"] == 0.89


def test_missing_key_never_calls_transport(small_project, monkeypatch):
    root, source = small_project
    monkeypatch.delenv("TYPESAFE_API_KEY")

    def forbidden(*_args):
        pytest.fail("transport should not be called without a key")

    assert triage_findings(root, [_finding(source)], transport=forbidden)[0] == {
        "status": "unavailable",
        "choice": None,
        "confidence": None,
        "reason": "missing_api_key",
    }


@pytest.mark.parametrize(
    "extra_path, contents",
    [
        (".env", "KEY=secret\n"),
        ("credentials.json", "{}\n"),
        ("notes.txt", "-----BEGIN PRIVATE KEY-----\nprivate\n"),
        ("large.txt", "x" * 65_000),
        ("image.bin", "\x00bytes\n"),
    ],
)
def test_unsafe_or_incomplete_scope_falls_back_without_upload(
    small_project, extra_path, contents
):
    root, source = small_project
    (root / extra_path).write_text(contents, encoding="utf-8")

    def forbidden(*_args):
        pytest.fail("unsafe project must not be uploaded")

    result = triage_findings(root, [_finding(source)], transport=forbidden)[0]
    assert result["status"] == "unavailable"
    assert result["reason"] == "unsafe_or_incomplete_project"


def test_symlink_in_project_refuses_entire_scope(small_project):
    root, source = small_project
    # A symlink to an in-project file is enough to make the text scope ambiguous.
    (root / "alias.py").symlink_to(source)

    def forbidden(*_args):
        pytest.fail("symlinked project must not be uploaded")

    result = triage_findings(root, [_finding(source)], transport=forbidden)[0]
    assert result["status"] == "unavailable"
    assert result["reason"] == "unsafe_or_incomplete_project"


def test_symlinked_project_root_refuses_upload(small_project):
    root, source = small_project
    alias = root.parent / f"{root.name}-alias"
    alias.symlink_to(root, target_is_directory=True)

    def forbidden(*_args):
        pytest.fail("symlinked project root must not be uploaded")

    result = triage_findings(alias, [_finding(source)], transport=forbidden)[0]
    assert result["status"] == "unavailable"
    assert result["reason"] == "unsafe_or_incomplete_project"


def test_invalid_candidate_does_not_block_valid_candidate(small_project):
    root, source = small_project
    invalid = _finding(root.parent / "outside.py")

    def transport(payload, _key):
        assert list(payload["questions"]) == ["q0001"]
        return {
            "model": payload["model"],
            "answers": {"q0001": _answer("unreferenced")},
        }

    results = triage_findings(root, [invalid, _finding(source)], transport=transport)
    assert [item["status"] for item in results] == ["unavailable", "agreed"]
    assert results[0]["reason"] == "invalid_candidate"


def test_stale_symbol_or_line_falls_back_without_upload(small_project):
    root, source = small_project
    stale = _finding(source, "absent")
    wrong_line = _finding(source)
    wrong_line["line"] = 2

    def forbidden(*_args):
        pytest.fail("stale candidates must not be uploaded")

    results = triage_findings(root, [stale, wrong_line], transport=forbidden)
    assert [item["reason"] for item in results] == [
        "invalid_candidate",
        "invalid_candidate",
    ]


def test_qualified_method_name_uses_simple_source_symbol(small_project):
    root, source = small_project
    source.write_text("class Builder:\n    def old_handler(self):\n        pass\n")
    finding = _finding(source, "Builder.old_handler")
    finding["line"] = 2
    finding["type"] = "method"

    def transport(payload, _key):
        target = payload["questions"]["q0000"]["instructions"]["target"]
        assert target["symbol"] == "old_handler"
        return {
            "model": payload["model"],
            "answers": {"q0000": _answer("unreferenced")},
        }

    assert (
        triage_findings(root, [finding], transport=transport)[0]["status"] == "agreed"
    )


@pytest.mark.parametrize(
    "bad_response",
    [
        None,
        {},
        {"model": "other", "answers": {"q0000": _answer("unreferenced")}},
        {"model": "jev-1.13.0", "answers": {}},
        {
            "model": "jev-1.13.0",
            "answers": {
                "q0000": {
                    "type": "choice",
                    "choice": "unreferenced",
                    "confidence": 0.99,
                    "probabilities": {},
                }
            },
        },
    ],
)
def test_malformed_response_falls_back(small_project, bad_response):
    root, source = small_project
    result = triage_findings(
        root, [_finding(source)], transport=lambda *_: bad_response
    )[0]
    assert result["status"] == "unavailable"
    assert result["reason"] == "invalid_response"


def test_transport_error_falls_back(small_project):
    root, source = small_project

    def transport(*_args):
        raise TimeoutError("timed out")

    result = triage_findings(root, [_finding(source)], transport=transport)[0]
    assert result["status"] == "unavailable"
    assert result["reason"] == "request_failed"
