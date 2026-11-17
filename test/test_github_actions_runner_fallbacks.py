"""Finite fallback proofs preserve unknown and self-hosted runner choices."""

import pytest
from skylos.rules.config.cicd.runner_labels import runner_may_be_self_hosted


def job(matrix, expression="${{ matrix.os || 'ubuntu-latest' }}"):
    return {"runs-on": expression, "strategy": {"matrix": matrix}}


@pytest.mark.parametrize(
    "matrix",
    [
        {"include": [{"python": "3.12"}, {"python": "3.13"}]},
        {"python": ["3.12", "3.13"]},
        {"os": ["ubuntu-latest", "windows-latest"]},
        {"os": [None, False, 0, "", "macos-latest"]},
    ],
)
def test_literal_hosted_fallback(matrix):
    assert not runner_may_be_self_hosted(job(matrix))


@pytest.mark.parametrize(
    "matrix,expression",
    [
        ({"os": ["self-hosted", None]}, "${{ matrix.os || 'ubuntu-latest' }}"),
        (
            {"include": [{"python": "3.13"}, {"os": "custom-label"}]},
            "${{ matrix.os || 'ubuntu-latest' }}",
        ),
        ({"python": ["3.13"]}, "${{ matrix.os || 'self-hosted' }}"),
        ({"python": ["3.13"]}, "${{ matrix.os || inputs.runner }}"),
        ({"os": ["${{ inputs.runner }}"]}, "${{ matrix.os || 'ubuntu-latest' }}"),
        ({"python": ["3.13"]}, '${{ matrix.os || "ubuntu-latest" }}'),
        ({"OS": ["self-hosted"]}, "${{ matrix.os || 'ubuntu-latest' }}"),
        (
            {"os": ["ubuntu-latest"], "OS": ["self-hosted"]},
            "${{ matrix.os || 'ubuntu-latest' }}",
        ),
        ({"os": [[]]}, "${{ matrix.os || 'ubuntu-latest' }}"),
        ({"os": ["false"]}, "${{ matrix.os || 'ubuntu-latest' }}"),
        ({"os": ["0"]}, "${{ matrix.os || 'ubuntu-latest' }}"),
    ],
)
def test_possible_self_hosted_or_unresolved_value_still_warns(matrix, expression):
    assert runner_may_be_self_hosted(job(matrix, expression))
