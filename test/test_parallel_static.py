import skylos.scale.parallel_static as ps


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

    def fake_proc_file(file_path, mod, extra_visitors=None, full_scan=True, **kwargs):
        calls.append(str(file_path))
        return ("go-ok", str(file_path), mod)

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "a.go", tmp_path / "b.go"]
    modmap = {files[0]: "m", files[1]: "m"}

    out = ps.run_proc_file_parallel(files, modmap, jobs=2)

    assert out == [("go-ok", str(files[0]), "m"), ("go-ok", str(files[1]), "m")]
    assert calls == [str(files[0]), str(files[1])]


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

    out = ps.run_proc_file_parallel(
        files,
        modmap,
        jobs=2,
        progress_callback=lambda done, total, path: progress.append((done, total)),
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
