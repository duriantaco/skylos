"""Nested source evaluation shares work limits and cannot prove partial results."""

import ast

import pytest

from skylos.deadcode.python_project_sources import Function, ProjectSourceIndex
from test.fixture_paths import write_fixture


def _index(tmp_path):
    path = write_fixture(
        tmp_path,
        "paths.py",
        'def leaf():\n    return "live.js"\n\n'
        "def middle():\n    leaf()\n    leaf()\n    return leaf()\n\n"
        "def listing():\n    middle()\n    middle()\n    return middle()\n",
    )
    index = ProjectSourceIndex(tmp_path, [path])
    return index, path, index.definitions[path]["listing"]


@pytest.mark.parametrize(
    ("counter", "limit"), [("budget", 150_000), ("owner_steps", 1_000_000)]
)
def test_nested_calls_cannot_reset_the_callers_remaining_budget(
    tmp_path, counter, limit
):
    index, path, listing = _index(tmp_path)
    setattr(index, counter, limit - 20)

    result = index.call(Function(path, listing), [], {})

    assert result is None
    assert getattr(index, counter) > limit
    # Count abstract operations rather than wall time. Exhaustion in a child
    # must stop its parents too, and must never certify the caller as complete.
    assert index.total_steps <= 30
    assert (path, id(listing)) not in index.completed
    assert not index.active_calls


def test_nested_calls_within_budget_keep_the_returned_path_proof(tmp_path):
    index, path, listing = _index(tmp_path)

    result = index.resolve_text(ast.parse("listing()", mode="eval").body, path)

    assert result == {"live.js"}
    assert (path, id(listing)) in index.completed
    assert index.budget == index.total_steps
    assert index.owner_steps == index.total_steps


def test_exhausted_branching_call_cannot_certify_a_returned_path(tmp_path):
    index, path, listing = _index(tmp_path)
    index.owner_steps = 1_000_000 - 20
    call = ast.parse("listing()", mode="eval").body

    result = index.resolve_text(call, path)

    assert result is None
    assert index.total_steps <= 30
    assert (path, id(call)) not in index.completed_call_sites
    assert (path, id(listing)) not in index.completed
