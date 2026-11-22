"""Worker processes must not import modules from the checkout being scanned."""

import os
from concurrent.futures import Future

import pytest

import skylos.scale.parallel_static as ps
from skylos.scale.safe_spawn import SAFE_PATH_VAR, no_cwd_imports_in_children


@pytest.mark.parametrize("before", [None, ""])
def test_sets_safe_path_inside_and_restores_it_after(monkeypatch, before):
    if before is None:
        monkeypatch.delenv(SAFE_PATH_VAR, raising=False)
    else:
        monkeypatch.setenv(SAFE_PATH_VAR, before)
    with no_cwd_imports_in_children():
        assert os.environ[SAFE_PATH_VAR] == "1"
    assert os.environ.get(SAFE_PATH_VAR) == before


def test_keeps_a_value_the_user_already_set(monkeypatch):
    monkeypatch.setenv(SAFE_PATH_VAR, "yes")
    with no_cwd_imports_in_children():
        assert os.environ[SAFE_PATH_VAR] == "yes"
    assert os.environ[SAFE_PATH_VAR] == "yes"


def test_nested_blocks_restore_only_when_the_outer_one_exits(monkeypatch):
    monkeypatch.delenv(SAFE_PATH_VAR, raising=False)
    with no_cwd_imports_in_children():
        with no_cwd_imports_in_children():
            pass
        assert os.environ[SAFE_PATH_VAR] == "1"
    assert SAFE_PATH_VAR not in os.environ


def test_static_pool_starts_and_feeds_workers_with_safe_path(monkeypatch, tmp_path):
    monkeypatch.delenv(SAFE_PATH_VAR, raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    seen = []

    class RecordingExecutor:
        def __init__(self, max_workers=None, initializer=None):
            seen.append(("init", os.environ.get(SAFE_PATH_VAR)))

        def submit(self, fn, *args, **kwargs):
            seen.append(("submit", os.environ.get(SAFE_PATH_VAR)))
            future = Future()
            future.set_result((str(args[0]), "ok"))
            return future

        def shutdown(self, wait=True, cancel_futures=False):
            seen.append(("shutdown", os.environ.get(SAFE_PATH_VAR)))

    monkeypatch.setattr(ps, "ProcessPoolExecutor", RecordingExecutor)
    files = [tmp_path / "a.py", tmp_path / "b.py"]
    out = ps.run_proc_file_parallel(files, {files[0]: "a", files[1]: "b"}, jobs=2)

    assert out == ["ok", "ok"]
    assert seen == [
        ("init", "1"),
        ("submit", "1"),
        ("submit", "1"),
        ("shutdown", "1"),
    ]
    assert SAFE_PATH_VAR not in os.environ


def test_real_workers_do_not_run_a_checkout_module_named_like_the_stdlib(
    monkeypatch, tmp_path
):
    # With the spawn and forkserver start methods every worker starts as
    # ``python -c``, which puts the working directory first on sys.path, and
    # imports ``json`` (via the resource tracker) before multiprocessing swaps
    # in the parent's sys.path. Under ``fork`` there is no new interpreter.
    planted = tmp_path / "json"
    planted.mkdir()
    (planted / "__init__.py").write_text(
        "import os\n"
        "here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))\n"
        "open(os.path.join(here, 'PLANTED_RAN_IN_' + str(os.getpid())), 'w').close()\n"
    )
    files = []
    for name in ("one", "two", "three"):
        path = tmp_path / f"{name}.py"
        path.write_text(f"def {name}():\n    return 1\n")
        files.append(path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(SAFE_PATH_VAR, raising=False)

    out = ps.run_proc_file_parallel(
        files,
        {path: path.stem for path in files},
        jobs=2,
        enable_quality_rules=False,
        enable_danger_rules=False,
        project_root=tmp_path,
        _worker_fn=ps._worker,
    )

    assert not sorted(p.name for p in tmp_path.glob("PLANTED_RAN_IN_*"))
    assert all(result is not None for result in out)
