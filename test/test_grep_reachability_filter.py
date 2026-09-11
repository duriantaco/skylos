"""Ownership decisions must apply to every grep path, including cached evidence."""

from unittest.mock import patch

import pytest

from skylos.core.grep_verify import grep_verify_findings
from skylos.core.safe_cache_io import write_text_no_symlink


class MemoryCache:
    repository_fingerprint = "fixed-test-snapshot"

    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def put(self, key, value):
        self.values[key] = value


def candidate(tmp_path):
    source = tmp_path / "worker.py"
    assert write_text_no_symlink(source, "def calculate_payload():\n    return 1\n")
    return {
        "file": str(source),
        "line": 1,
        "name": "calculate_payload",
        "simple_name": "calculate_payload",
        "full_name": "worker.calculate_payload",
        "type": "function",
    }


@pytest.mark.parametrize("parallel", [False, True])
def test_filter_rechecks_raw_cached_evidence_when_ownership_changes(tmp_path, parallel):
    finding = candidate(tmp_path)
    cache = MemoryCache()
    allow = False

    def ownership_filter(_finding, results):
        return results if allow else {}

    with patch(
        "skylos.core.grep_verify.multi_strategy_search",
        return_value={"references": ["caller.py:1:calculate_payload()"]},
    ) as search:
        first = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=ownership_filter,
        )
        assert first.complete
        assert not first
        allow = True
        second = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=ownership_filter,
        )
        assert second.complete
        assert second[finding["full_name"]].alive
        assert search.call_count == 1


@pytest.mark.parametrize("parallel", [False, True])
def test_filter_failure_marks_verification_incomplete(tmp_path, parallel):
    finding = candidate(tmp_path)

    def failing_filter(_finding, _results):
        raise ValueError("source ownership unavailable")

    with patch(
        "skylos.core.grep_verify.multi_strategy_search",
        return_value={"references": ["caller.py:1:calculate_payload()"]},
    ):
        result = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            evidence_filter=failing_filter,
        )
    assert not result.complete
    assert result.incomplete_reason == "verification_incomplete"
    assert not result


@pytest.mark.parametrize("parallel", [False, True])
def test_complete_search_does_not_reuse_an_early_exit_cache(tmp_path, parallel):
    finding = candidate(tmp_path)
    cache = MemoryCache()
    with patch(
        "skylos.core.grep_verify.multi_strategy_search",
        return_value={"references": ["caller.py:1:calculate_payload()"]},
    ) as search:
        before = grep_verify_findings(
            [finding], str(tmp_path), parallel=parallel, cache=cache
        )
        assert before[finding["full_name"]].alive
        after = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=lambda _finding, _results: {},
        )
        assert after.complete
        assert not after
        assert search.call_count == 2


@pytest.mark.parametrize("parallel", [False, True])
def test_rejected_source_hits_do_not_hide_later_config_evidence(tmp_path, parallel):
    finding = candidate(tmp_path)
    assert write_text_no_symlink(
        tmp_path / "caller.py", "def uncalled():\n" + "    calculate_payload()\n" * 6
    )
    assert write_text_no_symlink(
        tmp_path / "settings.yaml", "callback: worker.py:calculate_payload\n"
    )

    def source_filter(_finding, results):
        # Model six source references accounted for by an unreachable caller.
        # The config registration remains independent evidence.
        return {
            key: [line for line in lines if "caller.py:" not in line]
            for key, lines in results.items()
        }

    result = grep_verify_findings(
        [finding],
        str(tmp_path),
        parallel=parallel,
        evidence_filter=source_filter,
    )
    assert result.complete
    verdict = result[finding["full_name"]]
    assert verdict.alive
    assert any("settings.yaml" in line for line in verdict.evidence)


@pytest.mark.parametrize("parallel", [False, True])
def test_real_source_search_respects_filter(tmp_path, parallel):
    finding = candidate(tmp_path)
    assert write_text_no_symlink(
        tmp_path / "caller.py", "def uncalled():\n    calculate_payload()\n"
    )
    result = grep_verify_findings(
        [finding],
        str(tmp_path),
        parallel=parallel,
        evidence_filter=lambda _finding, _results: {},
    )
    assert result.complete
    assert not result


@pytest.mark.parametrize("parallel", [False, True])
@pytest.mark.parametrize("reverse_entries", [False, True])
def test_same_named_import_and_function_receive_their_own_cached_verdict(
    tmp_path, parallel, reverse_entries
):
    from skylos.analyzer import (
        _apply_grep_verify_verdicts,
        _collect_grep_verify_candidates,
    )
    from skylos.visitors.base import Definition

    finding = candidate(tmp_path)
    importer = tmp_path / "consumer.py"
    assert write_text_no_symlink(importer, "from worker import calculate_payload\n")
    function = Definition(finding["full_name"], "function", finding["file"], 1)
    imported = Definition(finding["full_name"], "import", importer, 1)
    function.confidence = imported.confidence = 80
    entries = [("function", function), ("import", imported)]
    if reverse_entries:
        entries.reverse()
    candidates, definitions = _collect_grep_verify_candidates(dict(entries))
    assert {item["full_name"] for item in candidates} == {finding["full_name"]}
    assert len(definitions) == 2
    cache = MemoryCache()

    def raw_evidence(item, _root, **_options):
        if item["type"] == "function":
            return {
                "references": [f"{importer}:1:from worker import calculate_payload"]
            }
        return {}

    with patch(
        "skylos.core.grep_verify.multi_strategy_search", side_effect=raw_evidence
    ) as search:
        for _ in range(2):
            function.references = imported.references = 0
            result = grep_verify_findings(
                candidates, str(tmp_path), parallel=parallel, cache=cache
            )
            assert result.complete
            assert _apply_grep_verify_verdicts(definitions, result) == 1
            assert function.references == 1
            assert imported.references == 0
        assert search.call_count == 2
