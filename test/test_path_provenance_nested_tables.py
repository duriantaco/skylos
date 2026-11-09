"""Static regressions for #1051: dictionary selectors are not path values.

Fixtures are parsed by the analyzer, never imported or executed. In particular,
their rmtree(), input(), unknown mutator and callback calls do not run.
"""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.core.safe_cache_io import write_text_no_symlink


ISSUE_1051 = '''\
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal


def main() -> None:
    """Reset two directories owned by this invocation."""
    with TemporaryDirectory() as directory:
        houses: dict[Literal['base', 'head'], Path] = {
            'base': Path(directory) / 'base',
            'head': Path(directory) / 'head',
        }
        for house in houses.values():
            house.mkdir()

        def reset_house(side: Literal['base', 'head']) -> None:
            """Reset the selected temporary directory."""
            house = houses[side]
            shutil.rmtree(house)
            house.mkdir()

        reset_house('base')
        reset_house('head')


if __name__ == '__main__':
    main()
'''

NO_LITERAL_HINTS = (
    ISSUE_1051.replace("from typing import Literal\n", "")
    .replace("houses: dict[Literal['base', 'head'], Path]", "houses")
    .replace("side: Literal['base', 'head']", "side")
)

# Unknown callers may choose a key, but cannot add path bytes to the actual
# finite dictionary values. This differs from the path-component case below.
ESCAPED_FINITE_SELECTOR = ISSUE_1051.replace(
    "import shutil", "import shutil\nfrom plugin import register"
).replace(
    "        reset_house('base')",
    "        register(reset_house)\n        reset_house('base')",
)

DEFINITION = "        def reset_house(side: Literal['base', 'head']) -> None:"
FIRST_CALL = "        reset_house('base')"
GATE = {"gate": {"max_high": 0, "max_security": 0}}
MUTATIONS = {
    "rebind": "houses = {'base': Path(input()), 'head': Path(directory) / 'head'}",
    "subscript_write": "houses['base'] = Path(input())",
    "alias_write": "alias = houses\nalias['base'] = Path(input())",
    "alias_update": "alias = houses\nalias.update({'base': Path(input())})",
}


def _scan(tmp_path, monkeypatch, source):
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    assert write_text_no_symlink(root / "pyproject.toml", '[project]\nname="fixture"\n')
    assert write_text_no_symlink(root / "repro.py", source)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return result


def _rows(result, section):
    return [row for row in result.get(section, []) if row.get("rule_id") == "SKY-D215"]


def _assert_identity(row, source):
    sink_line = source.splitlines().index("            shutil.rmtree(house)") + 1
    assert (row["rule_id"], Path(row["file"]).name, row["line"], row["symbol"]) == (
        "SKY-D215",
        "repro.py",
        sink_line,
        "reset_house",
    )
    assert row["severity"] == "HIGH"


def _insert(source, statement, *, before_definition):
    marker = DEFINITION if before_definition else FIRST_CALL
    indented = "\n".join("        " + line for line in statement.splitlines())
    return source.replace(marker, indented + "\n" + marker, 1)


@pytest.mark.parametrize(
    "source",
    [ISSUE_1051, NO_LITERAL_HINTS, ESCAPED_FINITE_SELECTOR],
    ids=["issue1051", "no_literal_hints", "escaped_finite_selector"],
)
def test_nested_literal_table_retains_safe_proof(tmp_path, monkeypatch, source):
    result = _scan(tmp_path, monkeypatch, source)
    assert _rows(result, "danger") == []
    [finding] = _rows(result, "suppressed")
    _assert_identity(finding, source)
    proof = finding["metadata"]["path_provenance"]
    assert proof["status"] == "safe"
    assert proof["complete_project"] is True
    steps = [step for chain in proof["safe"] for step in chain]
    assert any(
        "temporary path from `tempfile.TemporaryDirectory()`" in step for step in steps
    )
    assert any("`houses` = Dict" in step for step in steps)
    assert any("item of `houses`" in step for step in steps)
    assert not proof.get("untrusted")
    assert not proof.get("unknown")

    # The raw safe record survives JSON, but it is absent from listed dangers
    # and cannot fail a zero-tolerance security gate.
    from skylos.reporting.listing import listed_result

    assert _rows(json.loads(json.dumps(result)), "suppressed") == [finding]
    assert _rows(listed_result(result), "danger") == []
    assert check_gate(result, GATE)[0] is True


def _assert_untrusted_result(result, source):
    from skylos.reporting.listing import is_listed, listed_result

    [finding] = _rows(result, "danger")
    _assert_identity(finding, source)
    assert _rows(result, "suppressed") == []
    metadata = finding["metadata"]
    assert "input()" in metadata["security_evidence"]["source"]
    proof = metadata.get("path_provenance")
    if proof is not None:
        assert proof["status"] == "untrusted"
        assert proof["untrusted"]
    assert is_listed(finding, "danger") is True
    assert _rows(listed_result(result), "danger") == [finding]
    assert check_gate(result, GATE)[0] is False
    return finding


def test_literal_annotation_does_not_hide_an_attacker_controlled_value(
    tmp_path, monkeypatch
):
    source = ISSUE_1051.replace("Path(directory) / 'base'", "Path(input())")
    _assert_untrusted_result(_scan(tmp_path, monkeypatch, source), source)


@pytest.mark.parametrize(
    "before_definition", [True, False], ids=["before_def", "after_def"]
)
@pytest.mark.parametrize("mutation", MUTATIONS)
def test_captured_table_mutations_remain_reported(
    tmp_path, monkeypatch, mutation, before_definition
):
    source = _insert(
        ISSUE_1051, MUTATIONS[mutation], before_definition=before_definition
    )
    finding = _assert_untrusted_result(_scan(tmp_path, monkeypatch, source), source)
    if mutation.startswith("alias_"):
        proof = finding["metadata"]["path_provenance"]
        assert proof["status"] == "untrusted"
        chain = [step for steps in proof["untrusted"] for step in steps]
        expected = (
            "stores into `alias`"
            if mutation == "alias_write"
            else "`alias.update(...)` adds to it"
        )
        assert any(expected in step for step in chain)


def test_unknown_container_mutator_is_not_a_safe_proof(tmp_path, monkeypatch):
    source = ISSUE_1051.replace(
        "import shutil", "import shutil\nfrom plugin import mutate"
    )
    source = _insert(source, "mutate(houses)", before_definition=False)
    result = _scan(tmp_path, monkeypatch, source)
    assert _rows(result, "danger") == []
    [finding] = _rows(result, "suppressed")
    _assert_identity(finding, source)
    proof = finding["metadata"]["path_provenance"]
    assert proof["status"] == "unknown"
    assert proof["safe"]
    assert any(
        "container `houses` is passed to `mutate(...)`, which may change it" in step
        for chain in proof["unknown"]
        for step in chain
    )
    assert _rows(json.loads(json.dumps(result)), "suppressed") == [finding]


def test_escaped_callback_with_a_path_component_keeps_unknown_caller_evidence(
    tmp_path, monkeypatch
):
    source = ISSUE_1051.replace(
        "import shutil", "import shutil\nfrom plugin import register"
    )
    source = source.replace("house = houses[side]", "house = houses['base'] / side")
    source = _insert(source, "register(reset_house)", before_definition=False)
    result = _scan(tmp_path, monkeypatch, source)
    assert _rows(result, "danger") == []
    [finding] = _rows(result, "suppressed")
    _assert_identity(finding, source)
    proof = finding["metadata"]["path_provenance"]
    assert proof["status"] == "unknown"
    assert any(
        "`reset_house` is passed as a value; its callers are not visible" in step
        for chain in proof["unknown"]
        for step in chain
    )
    assert _rows(json.loads(json.dumps(result)), "suppressed") == [finding]
