"""Real searches must not turn clipped, rejected hits into complete absence."""

import ast
from pathlib import Path

import pytest

from skylos.core.grep_cache import GrepCache
from skylos.core.grep_verify import grep_verify_findings
from skylos.core.grep_verify_common import _grep_line_number, _grep_line_path
from skylos.core.safe_cache_io import write_text_no_symlink


class _ObservedCache(GrepCache):
    def __init__(self):
        super().__init__()
        self.hits = 0

    def get(self, key):
        value = super().get(key)
        self.hits += value is not None
        return value


def _fixture(root, dead_hit_count, stub_name="z_contract.pyi"):
    source = root / "worker.py"
    body = (
        "def calculate_payload():\n    return 42\n\n\n\n\n"
        "def obsolete_calls():\n" + "    calculate_payload()\n" * dead_hit_count
    )
    assert write_text_no_symlink(source, body)
    # This external type-stub import is in the SAME references strategy as
    # the dead calls. The ordinary imports strategy searches only *.py.
    stub = root / stub_name
    assert write_text_no_symlink(stub, "from worker import calculate_payload\n")
    obsolete = ast.parse(body).body[1]
    dead_lines = set(range(obsolete.body[0].lineno, obsolete.end_lineno + 1))

    def ownership_filter(_finding, results):
        def relevant(hit):
            path = _grep_line_path(hit)
            line = _grep_line_number(hit)
            if not path or line is None:
                return True
            path = Path(path)
            if not path.is_absolute():
                path = root / path
            # obsolete_calls has no caller or escape in this source. Its
            # body cannot independently establish usage of calculate_payload.
            return path.resolve() != source.resolve() or line not in dead_lines

        return {
            name: [hit for hit in hits if relevant(hit)]
            for name, hits in results.items()
        }

    finding = {
        "file": str(source),
        "line": 1,
        "type": "function",
        "name": "calculate_payload",
        "simple_name": "calculate_payload",
        "full_name": "worker.calculate_payload",
    }
    return finding, ownership_filter


@pytest.mark.parametrize("dead_hit_count", [6, 12, 300])
@pytest.mark.parametrize("parallel", [False, True])
@pytest.mark.parametrize("cached", [False, True])
def test_later_stub_reference_is_rescued_or_search_abstains(
    tmp_path, dead_hit_count, parallel, cached
):
    finding, ownership_filter = _fixture(tmp_path, dead_hit_count)
    cache = _ObservedCache() if cached else None
    results = [
        grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=ownership_filter,
        )
        for _ in range(2 if cached else 1)
    ]

    for result in results:
        verdict = result.get(finding["full_name"])
        assert (verdict is not None and verdict.alive) or not result.complete, (
            "Later conservative evidence exists in z_contract.pyi; rejecting "
            "the clipped dead-caller prefix cannot establish a complete search."
        )
        if verdict is not None and verdict.alive:
            assert any("z_contract.pyi:" in hit for hit in verdict.evidence)
        else:
            assert result.incomplete_reason
    if cached:
        assert cache.hits > 0


@pytest.mark.parametrize("parallel", [False, True])
def test_unclipped_stub_reference_remains_a_positive_control(tmp_path, parallel):
    finding, ownership_filter = _fixture(tmp_path, 1)
    result = grep_verify_findings(
        [finding],
        str(tmp_path),
        parallel=parallel,
        evidence_filter=ownership_filter,
    )

    assert result.complete
    assert result[finding["full_name"]].alive
    assert any(
        "z_contract.pyi:" in hit for hit in result[finding["full_name"]].evidence
    )


@pytest.mark.parametrize("parallel", [False, True])
@pytest.mark.parametrize("cached", [False, True])
def test_retained_positive_evidence_can_rescue_despite_a_search_cap(
    tmp_path, parallel, cached
):
    finding, ownership_filter = _fixture(tmp_path, 300, "a_contract.pyi")
    cache = _ObservedCache() if cached else None

    for _ in range(2 if cached else 1):
        result = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=ownership_filter,
        )
        assert result.complete
        verdict = result[finding["full_name"]]
        assert verdict.alive
        assert any("a_contract.pyi:" in hit for hit in verdict.evidence)
    if cached:
        assert cache.hits > 0


@pytest.mark.parametrize("parallel", [False, True])
@pytest.mark.parametrize("cached", [False, True])
def test_overlapping_module_aliases_do_not_invent_evidence_loss(
    tmp_path, parallel, cached
):
    source = tmp_path / "src" / "pkg" / "worker.py"
    source.parent.mkdir(parents=True)
    assert write_text_no_symlink(source, "def calculate_payload():\n    return 42\n")
    assert write_text_no_symlink(
        tmp_path / "notes.py",
        "def obsolete_notes():\n" + "    'src.pkg.worker'\n" * 3,
    )
    finding = {
        "file": str(source),
        "line": 1,
        "type": "function",
        "name": "calculate_payload",
        "simple_name": "calculate_payload",
        "full_name": "pkg.worker.calculate_payload",
    }
    cache = _ObservedCache() if cached else None

    for _ in range(2 if cached else 1):
        result = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=lambda _finding, _results: {},
        )
        # src.pkg.worker and pkg.worker match the same three note lines.
        # Duplicate matches cannot imply that a sixth unique hit was lost.
        assert result.complete
        assert not result
    if cached:
        assert cache.hits > 0


@pytest.mark.parametrize("parallel", [False, True])
@pytest.mark.parametrize("cached", [False, True])
def test_irrelevant_module_substrings_do_not_block_a_complete_search(
    tmp_path, parallel, cached
):
    source = tmp_path / "app.py"
    assert write_text_no_symlink(source, "RESULT = 42\n")
    assert write_text_no_symlink(
        tmp_path / "models.py",
        "".join(f"mapped_column_{index} = None\n" for index in range(12)),
    )
    finding = {
        "file": str(source),
        "line": 1,
        "type": "variable",
        "name": "RESULT",
        "simple_name": "RESULT",
        "full_name": "app.RESULT",
    }
    cache = _ObservedCache() if cached else None

    for _ in range(2 if cached else 1):
        result = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=lambda _finding, results: results,
        )
        # The module-name substring "app" occurs in "mapped_column". These
        # weak hints cannot establish usage of RESULT even without a cap.
        assert result.complete
        assert not result
    if cached:
        assert cache.hits > 0


@pytest.mark.parametrize("parallel", [False, True])
@pytest.mark.parametrize("cached", [False, True])
def test_overlapping_dispatch_patterns_count_physical_lines_once(
    tmp_path, parallel, cached
):
    source = tmp_path / "worker.py"
    assert write_text_no_symlink(source, "def calculate_payload():\n    return 42\n")
    assert write_text_no_symlink(
        tmp_path / "notes.py",
        "def obsolete_notes(receiver, registry):\n"
        + '    getattr(receiver, "calculate_payload"); registry["calculate_payload"]\n'
        * 3,
    )
    finding = {
        "file": str(source),
        "line": 1,
        "type": "function",
        "name": "calculate_payload",
        "simple_name": "calculate_payload",
        "full_name": "worker.calculate_payload",
    }
    cache = _ObservedCache() if cached else None

    for _ in range(2 if cached else 1):
        result = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=lambda _finding, _results: {},
        )
        # getattr and registry lookup both match each unreachable source line.
        # Three unique lines fit the cap even though there are six matches.
        assert result.complete
        assert not result
    if cached:
        assert cache.hits > 0


@pytest.mark.parametrize("parallel", [False, True])
@pytest.mark.parametrize("cached", [False, True])
def test_later_protocol_cast_cannot_be_lost_as_a_weak_type_hint(
    tmp_path, parallel, cached
):
    source = tmp_path / "worker.py"
    assert write_text_no_symlink(
        source, "class Receiver:\n    def calculate_payload(self):\n        return 42\n"
    )
    cast_source = tmp_path / "usage.py"
    assert write_text_no_symlink(
        cast_source,
        "def obsolete_casts():\n"
        + "    cast(Protocol, Receiver())\n" * 5
        + "live_receiver = cast(Protocol, Receiver())\n",
    )
    finding = {
        "file": str(source),
        "line": 2,
        "type": "method",
        "name": "calculate_payload",
        "simple_name": "calculate_payload",
        "full_name": "worker.Receiver.calculate_payload",
    }

    def ownership_filter(_finding, results):
        return {
            key: [
                hit
                for hit in hits
                if not (
                    _grep_line_path(hit) == str(cast_source)
                    and _grep_line_number(hit) in range(2, 7)
                )
            ]
            for key, hits in results.items()
        }

    cache = _ObservedCache() if cached else None
    for _ in range(2 if cached else 1):
        result = grep_verify_findings(
            [finding],
            str(tmp_path),
            parallel=parallel,
            cache=cache,
            evidence_filter=ownership_filter,
        )
        # The sixth cast is a module-level use. Method protocol casts can
        # establish usage, so discarding it must prevent a negative verdict.
        assert not result.complete
        assert result.incomplete_reason
        assert not result
    if cached:
        assert cache.hits > 0
