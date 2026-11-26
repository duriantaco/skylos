import ast

import skylos.scale.parallel_static as ps
from skylos.rules.danger.callable_bindings import callable_names


class DummyFuture:
    def __init__(self, value):
        self._value = value

    def result(self):
        return self._value


class ExplodingFuture:
    def result(self):
        raise TypeError("cannot pickle tree_sitter.Language object")


class DummyExecutor:
    def __init__(self, max_workers=None, initializer=None):
        self.max_workers = max_workers
        self.initializer = initializer
        self.futures = []
        self.shutdown_calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def shutdown(self, wait=True, cancel_futures=False):
        self.shutdown_calls.append((wait, cancel_futures))

    def submit(self, fn, *args, **kwargs):
        file_str, out = fn(*args, **kwargs)
        fut = DummyFuture((file_str, out))
        self.futures.append(fut)
        return fut


class ExplodingExecutor:
    def __init__(self, max_workers=None, initializer=None):
        self.max_workers = max_workers
        self.futures = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def shutdown(self, wait=True, cancel_futures=False):
        pass

    def submit(self, fn, *args, **kwargs):
        fut = ExplodingFuture()
        self.futures.append(fut)
        return fut


class ShouldNotRunExecutor:
    def __init__(self, max_workers=None, initializer=None):
        raise AssertionError("parallel executor should not be used")


def fake_as_completed(futs):
    fs = list(futs)
    fs.reverse()
    for f in fs:
        yield f


def test_parallel_path_preserves_order(monkeypatch, tmp_path):
    monkeypatch.setattr(ps, "ProcessPoolExecutor", DummyExecutor)
    monkeypatch.setattr(ps, "as_completed", fake_as_completed)

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    project_roots = []

    def fake_proc_file(file_path, mod, extra_visitors=None, full_scan=True, **kwargs):
        project_roots.append(kwargs.get("project_root"))
        return ("ok", str(file_path), mod)

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "x.py", tmp_path / "y.py", tmp_path / "z.py"]
    modmap = {files[0]: "mx", files[1]: "my", files[2]: "mz"}

    out = ps.run_proc_file_parallel(
        files,
        modmap,
        jobs=2,
        project_root=tmp_path,
    )

    assert out[0] == ("ok", str(files[0]), "mx")
    assert out[1] == ("ok", str(files[1]), "my")
    assert out[2] == ("ok", str(files[2]), "mz")
    assert project_roots == [tmp_path, tmp_path, tmp_path]


def test_go_files_use_serial_path_to_keep_module_cache_effective(monkeypatch, tmp_path):
    monkeypatch.setattr(ps, "ProcessPoolExecutor", ShouldNotRunExecutor)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    calls = []
    active = set()

    def fake_proc_file(file_path, mod, extra_visitors=None, full_scan=True, **kwargs):
        assert active == {file_path}
        calls.append(str(file_path))
        return ("go-ok", str(file_path), mod)

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "a.go", tmp_path / "b.go"]
    modmap = {files[0]: "m", files[1]: "m"}

    def report_completion(done, total, path):
        assert not active
        assert calls == [str(file) for file in files[:done]]
        assert total == len(files)
        assert path == files[done - 1]

    report_completion.file_started = active.add
    report_completion.file_finished = active.remove
    out = ps.run_proc_file_parallel(
        files, modmap, jobs=2, progress_callback=report_completion
    )

    assert out == [("go-ok", str(files[0]), "m"), ("go-ok", str(files[1]), "m")]
    assert calls == [str(files[0]), str(files[1])]


def _worker_waiting_for_progress(file_path, *_args, **_kwargs):
    import time

    ready = file_path.parent / "busy-worker-started"
    resume = file_path.parent / "resume-workers"
    if file_path.name == "busy.py":
        ready.touch()
    wait_for = ready if file_path.name == "quick.py" else resume
    until = time.monotonic() + 12
    while not wait_for.exists() and time.monotonic() < until:
        time.sleep(0.01)
    return str(file_path), wait_for.exists()


def _worker_security_cache_disabled(file_path, *_args, **_kwargs):
    return str(file_path), ps.security_units.get() is None


def test_nested_pool_drops_inherited_serial_security_cache(monkeypatch, tmp_path):
    import multiprocessing
    from functools import partial

    start = "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
    monkeypatch.setattr(
        ps,
        "ProcessPoolExecutor",
        partial(ps.ProcessPoolExecutor, mp_context=multiprocessing.get_context(start)),
    )
    outer_file = tmp_path / "outer.py"
    outer_file.write_text("value = 1\n")
    inner_files = [tmp_path / "one.py", tmp_path / "two.py"]
    previous = ps.SecurityUnitCache()
    token = ps.security_units.set(previous)

    def run_nested_pool(_done, _total, _file):
        serial_cache = ps.security_units.get()
        assert serial_cache is not None and serial_cache is not previous
        outcomes = ps.run_proc_file_parallel(
            inner_files,
            {f: f.stem for f in inner_files},
            jobs=2,
            _worker_fn=_worker_security_cache_disabled,
        )
        assert outcomes == [True, True]
        assert ps.security_units.get() is serial_cache

    try:
        ps.run_proc_file_parallel(
            [outer_file], {outer_file: "outer"}, jobs=1, progress_callback=run_nested_pool
        )
        assert ps.security_units.get() is previous
    finally:
        ps.security_units.reset(token)


def test_parallel_activity_counts_only_workers_that_entered_a_file(tmp_path):
    files = [
        tmp_path / name for name in ("quick.py", "busy.py", "three.py", "four.py")
    ]
    providers = []

    def on_progress(done, total, path):
        if done == 1:
            try:
                assert path == files[0]
                active = providers[-1]()
                assert files[1] in active
                assert files[0] not in active and files[-1] not in active
            finally:
                (tmp_path / "resume-workers").touch()

    on_progress.parallel_activity = providers.append
    result = ps.run_proc_file_parallel(
        files,
        {f: f.stem for f in files},
        jobs=2,
        progress_callback=on_progress,
        _worker_fn=_worker_waiting_for_progress,
    )
    assert result == [True] * len(files)
    assert providers[-1] is None


def test_unavailable_shared_activity_keeps_parallel_completion_counts(monkeypatch, tmp_path):
    import multiprocessing

    def unavailable(*args):
        raise OSError("shared memory unavailable")

    monkeypatch.setattr(multiprocessing, "RawArray", unavailable)
    monkeypatch.setattr(ps, "ProcessPoolExecutor", DummyExecutor)
    monkeypatch.setattr(ps, "as_completed", fake_as_completed)
    files = [tmp_path / "a.py", tmp_path / "b.py"]
    completed = []
    providers = []

    def progress(done, total, file):
        completed.append((done, total))

    progress.parallel_activity = providers.append
    result = ps.run_proc_file_parallel(
        files,
        {f: f.stem for f in files},
        jobs=2,
        progress_callback=progress,
        _worker_fn=lambda file, *args, **kwargs: (str(file), file.stem),
    )
    assert result == ["a", "b"]
    assert completed == [(1, 2), (2, 2)]
    assert providers == []


def test_mixed_files_keep_non_go_parallel_and_preserve_order(monkeypatch, tmp_path):
    monkeypatch.setattr(ps, "ProcessPoolExecutor", DummyExecutor)
    monkeypatch.setattr(ps, "as_completed", fake_as_completed)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    def fake_proc_file(file_path, mod, extra_visitors=None, full_scan=True, **kwargs):
        return ("mixed-ok", str(file_path), mod)

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "a.py", tmp_path / "b.go", tmp_path / "c.ts"]
    modmap = {files[0]: "py", files[1]: "go", files[2]: "ts"}
    progress = []

    out = ps.run_proc_file_parallel(
        files,
        modmap,
        jobs=2,
        progress_callback=lambda done, total, path: progress.append(
            (done, total, path.name)
        ),
    )

    assert out[0] == ("mixed-ok", str(files[0]), "py")
    assert out[1] == ("mixed-ok", str(files[1]), "go")
    assert out[2] == ("mixed-ok", str(files[2]), "ts")
    assert progress == [(1, 3, "c.ts"), (2, 3, "a.py"), (3, 3, "b.go")]


def test_parallel_path_retries_parent_process_when_worker_result_fails(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(ps, "ProcessPoolExecutor", ExplodingExecutor)
    monkeypatch.setattr(ps, "as_completed", fake_as_completed)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    def fake_proc_file(file_path, mod, extra_visitors=None, full_scan=True, **kwargs):
        return ("retry-ok", str(file_path), mod)

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    file_path = tmp_path / "app.ts"
    modmap = {file_path: "app"}

    out = ps.run_proc_file_parallel([file_path], modmap, jobs=2)

    assert out == [("retry-ok", str(file_path), "app")]


def _crashing_worker(file_path, mod, *args):
    """Real-process worker: dies natively on the sentinel file."""
    import os
    import signal

    if str(file_path).endswith("crash_me.py"):
        os.kill(os.getpid(), signal.SIGSEGV)
    return str(file_path), ("ok", str(file_path), mod)


def test_worker_segfault_is_isolated_and_never_retried_in_parent(
    monkeypatch, tmp_path
):
    import skylos.analyzer

    def parent_proc_file(*args, **kwargs):
        raise AssertionError("crashed file must not be re-run in the parent")

    monkeypatch.setattr(skylos.analyzer, "proc_file", parent_proc_file)

    files = [tmp_path / f"f{i}.py" for i in range(6)]
    files.insert(3, tmp_path / "crash_me.py")
    modmap = {f: f.stem for f in files}
    progress = []
    providers = []

    def completed(done, total, path):
        progress.append((done, total))

    completed.parallel_activity = providers.append

    out = ps.run_proc_file_parallel(
        files,
        modmap,
        jobs=2,
        progress_callback=completed,
        _worker_fn=_crashing_worker,
    )

    assert len(out) == len(files)
    for f, result in zip(files, out):
        if f.name == "crash_me.py":
            assert isinstance(result, ps.WorkerCrash)
            assert result.file == str(f)
        else:
            assert result == ("ok", str(f), f.stem)
    assert progress[-1] == (len(files), len(files))
    assert providers[-1] is None
    assert all(provider() == () for provider in providers if provider is not None)


def test_analyzer_reports_worker_crash_as_analysis_error(monkeypatch, tmp_path):
    import skylos.analyzer as analyzer_mod

    good = tmp_path / "good.py"
    good.write_text("def used():\n    return 1\n\nused()\n", encoding="utf-8")
    bad = tmp_path / "crash_me.py"
    bad.write_text("x = 1\n", encoding="utf-8")
    real_parallel = analyzer_mod.run_proc_file_parallel

    def fake_parallel(files, modmap, **kwargs):
        outs = real_parallel(
            [f for f in files if f.name != "crash_me.py"], modmap, **kwargs
        )
        by_name = dict(zip([f for f in files if f.name != "crash_me.py"], outs))
        return [
            ps.WorkerCrash(str(f)) if f.name == "crash_me.py" else by_name[f]
            for f in files
        ]

    monkeypatch.setattr(analyzer_mod, "run_proc_file_parallel", fake_parallel)
    import json

    result = json.loads(analyzer_mod.analyze(str(tmp_path)))
    errors = [e for e in result["analysis_errors"] if e["kind"] == "worker_crash"]
    assert len(errors) == 1
    assert errors[0]["file"].endswith("crash_me.py")
    assert errors[0]["message"] == ps.WORKER_CRASH_MESSAGE
    assert errors[0]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"


class InterruptedFuture:
    def result(self):
        raise KeyboardInterrupt


class _FakeProcess:
    def __init__(self):
        self.terminated = False
        self.joined = False

    def terminate(self):
        self.terminated = True

    def join(self, timeout=None):
        self.joined = True


class InterruptingExecutor(DummyExecutor):
    instances = []

    def __init__(self, max_workers=None, initializer=None):
        super().__init__(max_workers, initializer)
        self._processes = {1: _FakeProcess(), 2: _FakeProcess()}
        InterruptingExecutor.instances.append(self)

    def submit(self, fn, *args, **kwargs):
        fut = InterruptedFuture()
        self.futures.append(fut)
        return fut


def test_ctrl_c_stops_workers_without_waiting_for_queued_files(monkeypatch, tmp_path):
    import pytest

    InterruptingExecutor.instances.clear()
    monkeypatch.setattr(ps, "ProcessPoolExecutor", InterruptingExecutor)
    monkeypatch.setattr(ps, "as_completed", fake_as_completed)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    files = [tmp_path / "x.py", tmp_path / "y.py"]
    modmap = {files[0]: "mx", files[1]: "my"}

    with pytest.raises(KeyboardInterrupt):
        ps.run_proc_file_parallel(files, modmap, jobs=2, project_root=tmp_path)

    (executor,) = InterruptingExecutor.instances
    # Queued work is cancelled and the call does not wait for it.
    assert executor.shutdown_calls == [(False, True)]
    assert all(p.terminated and p.joined for p in executor._processes.values())
    # Workers ignore SIGINT; the parent stops them, so they print no traceback.
    assert executor.initializer is ps._ignore_sigint


def test_pool_shuts_down_and_waits_after_normal_completion(monkeypatch, tmp_path):
    created = []

    class RecordingExecutor(DummyExecutor):
        def __init__(self, max_workers=None, initializer=None):
            super().__init__(max_workers, initializer)
            created.append(self)

    monkeypatch.setattr(ps, "ProcessPoolExecutor", RecordingExecutor)
    monkeypatch.setattr(ps, "as_completed", fake_as_completed)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    import skylos.analyzer

    monkeypatch.setattr(
        skylos.analyzer,
        "proc_file",
        lambda file_path, mod, extra_visitors=None, full_scan=True, **kw: ("ok",),
    )
    files = [tmp_path / "x.py", tmp_path / "y.py"]
    ps.run_proc_file_parallel(files, {files[0]: "a", files[1]: "b"}, jobs=2)

    assert created[0].shutdown_calls == [(True, False)]


def test_python_danger_worker_results_do_not_need_parent_retry(monkeypatch, tmp_path):
    """Danger rules cache flow state on the module; worker results must still
    cross the process boundary instead of being recomputed in the parent."""
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    source = (
        "import os\n"
        "import random\n"
        "\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
        "\n"
        "def weak():\n"
        "    return random.random()\n"
        "\n"
        "def helper(x):\n"
        "    return x + 1\n"
        "\n"
        "def main():\n"
        "    run('echo hi')\n"
        "    helper(1)\n"
        "    weak()\n"
        "\n"
        "main()\n"
    )
    files = []
    for name in ("one.py", "two.py"):
        path = tmp_path / name
        path.write_text(source, encoding="utf-8")
        files.append(path)
    modmap = {path: path.stem for path in files}

    retried = []
    monkeypatch.setattr(
        ps, "_retry_in_parent", lambda *args, **kwargs: retried.append(args[0])
    )

    out = ps.run_proc_file_parallel(
        files,
        modmap,
        jobs=2,
        enable_danger_rules=True,
        project_root=tmp_path,
    )

    assert retried == []
    assert len(out) == len(files)
    for result in out:
        assert not isinstance(result, ps.WorkerCrash)
        names = [definition.name for definition in result[0]]
        assert any(name.endswith(".run") for name in names)
        assert len(result[7]) == 2  # SKY-D203 and SKY-D212 for os.system

        # The unpickled index must rebuild its id-keyed caches from the
        # restored module, not stay empty.
        definition = next(
            definition for definition in result[0] if definition.name.endswith(".run")
        )
        module = definition.node.parent
        assert isinstance(module, ast.Module)
        call = next(
            node for node in ast.walk(definition.node) if isinstance(node, ast.Call)
        )
        assert callable_names(call, None, module, definition.filename) == ("os.system",)
