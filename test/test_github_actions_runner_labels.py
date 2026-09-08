import pytest

from skylos.rules.config.cicd.runner_labels import runner_may_be_self_hosted


@pytest.mark.parametrize(
    ("selection", "expected"),
    [
        ("ubuntu-latest", False),
        ("custom-runner", False),
        (["linux", "x64"], False),
        ({"labels": "ubuntu-latest"}, False),
        ({"labels": ["ubuntu-latest"]}, False),
        ("self-hosted", True),
        ("SELF-HOSTED", True),
        (["linux", "self-hosted"], True),
        ({"labels": ["linux", "self-hosted"]}, True),
        ({"group": "build-runners", "labels": "ubuntu-latest"}, True),
        ({"group": None}, True),
        (None, True),
        (True, True),
        (42, True),
        ("", True),
        ([], True),
        ({}, True),
        ({"labels": []}, True),
        ({"labels": {"labels": "ubuntu-latest"}}, True),
        (["ubuntu-latest", None], True),
        (["ubuntu-latest", ["linux"]], True),
    ],
)
def test_fixed_runner_selection(selection, expected):
    assert runner_may_be_self_hosted({"runs-on": selection}) is expected


def test_job_without_runner_selection():
    assert runner_may_be_self_hosted({}) is False


def _matrix_job(matrix, selection="${{ matrix.os }}"):
    return {"runs-on": selection, "strategy": {"matrix": matrix}}


@pytest.mark.parametrize(
    "selection",
    [
        "${{ matrix.os }}",
        ["${{ matrix.os }}"],
        {"labels": "${{ matrix.os }}"},
        {"labels": ["${{ matrix.os }}"]},
    ],
)
def test_literal_hosted_matrix(selection):
    job = _matrix_job(
        {"os": ["ubuntu-latest", "windows-latest", "macos-latest"]}, selection
    )
    assert runner_may_be_self_hosted(job) is False


def test_literal_object_property_and_label_array():
    job = _matrix_job(
        {"runner": [{"labels": ["ubuntu-latest"]}, {"labels": "windows-2022"}]},
        "${{ matrix.runner.labels }}",
    )
    assert runner_may_be_self_hosted(job) is False


@pytest.mark.parametrize(
    "matrix",
    [
        {"include": [{"os": "ubuntu-latest"}, {"os": "macos-latest"}]},
        {"os": ["ubuntu-latest"], "include": [{"os": "windows-latest"}]},
        {"os": ["ubuntu-latest"], "include": [{"toolchain": "stable"}]},
        {
            "toolchain": ["stable", "beta"],
            "include": [{"os": "ubuntu-latest"}, {"os": "windows-latest"}],
        },
        {"os": ["ubuntu-latest"], "exclude": [{"os": "ubuntu-latest"}]},
    ],
)
def test_literal_matrix_includes_and_excludes(matrix):
    assert runner_may_be_self_hosted(_matrix_job(matrix)) is False


@pytest.mark.parametrize(
    "matrix",
    [
        None,
        {},
        "${{ inputs.matrix }}",
        {"os": None},
        {"os": []},
        {"os": "ubuntu-latest"},
        {"os": [None]},
        {"os": ["ubuntu-latest", "custom-runner"]},
        {"os": ["ubuntu-latest-custom"]},
        {"os": ["${{ inputs.os }}"]},
        {"os": ["ubuntu-latest"], "other": "${{ inputs.versions }}"},
        {"os": ["ubuntu-latest"], "include": [{"os": "custom-runner"}]},
        {
            "include": [{"os": "custom-runner"}, {"os": "ubuntu-latest"}],
        },
        {
            "os": ["ubuntu-latest"],
            "include": [{"os": "custom-runner"}, {"os": "ubuntu-latest"}],
        },
        {"os": ["custom-runner"], "include": [{"os": "ubuntu-latest"}]},
        {"os": ["ubuntu-latest"], "include": [{"OS": "custom-runner"}]},
        {"os": ["ubuntu-latest"], "OS": ["custom-runner"]},
        {"os": ["ubuntu-latest"], "Include": [{"os": "custom-runner"}]},
        {"include": [{"os": "ubuntu-latest"}, {"toolchain": "stable"}]},
        {
            "os": ["ubuntu-latest"],
            "toolchain": ["stable"],
            "include": [{"toolchain": "nightly"}],
        },
        {"os": ["custom-runner"], "exclude": [{"os": "custom-runner"}]},
        {
            "os": ["ubuntu-latest"],
            "include": [{"os": "windows-latest"}],
            "exclude": [{"os": "ubuntu-latest"}],
        },
        {"os": ["ubuntu-latest"], "include": None},
        {"os": ["ubuntu-latest"], "exclude": "invalid"},
        {"os": ["ubuntu-latest"], "include": [None]},
    ],
)
def test_unproven_or_malformed_matrix_is_conservative(matrix):
    assert runner_may_be_self_hosted(_matrix_job(matrix)) is True


@pytest.mark.parametrize(
    "selection",
    [
        "${{ inputs.os }}",
        "${{ matrix.missing }}",
        "${{ matrix.os.name }}",
        "${{ matrix.os || inputs.os }}",
        "prefix-${{ matrix.os }}",
        "${{ fromJSON(inputs.labels) }}",
        {"group": "build-runners", "labels": "${{ matrix.os }}"},
    ],
)
def test_unresolved_selection_is_conservative(selection):
    assert (
        runner_may_be_self_hosted(_matrix_job({"os": ["ubuntu-latest"]}, selection))
        is True
    )


def test_matrix_expansion_is_bounded():
    job = _matrix_job({"os": ["ubuntu-latest"] * 17, "version": list(range(17))})
    assert runner_may_be_self_hosted(job) is True


def test_recursive_matrix_is_bounded():
    matrix = {"os": ["ubuntu-latest"]}
    matrix["recursive"] = [matrix]
    assert runner_may_be_self_hosted(_matrix_job(matrix)) is True
