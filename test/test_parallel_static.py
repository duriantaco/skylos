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
    def __init__(self, max_workers=None):
        self.max_workers = max_workers
        self.futures = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def submit(self, fn, *args, **kwargs):
        file_str, out = fn(*args, **kwargs)
        fut = DummyFuture((file_str, out))
        self.futures.append(fut)
        return fut


class ExplodingExecutor:
    def __init__(self, max_workers=None):
        self.max_workers = max_workers
        self.futures = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def submit(self, fn, *args, **kwargs):
        fut = ExplodingFuture()
        self.futures.append(fut)
        return fut


class ShouldNotRunExecutor:
    def __init__(self, max_workers=None):
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

    def fake_proc_file(file_path, mod, extra_visitors=None, full_scan=True, **kwargs):
        return ("ok", str(file_path), mod)

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "x.py", tmp_path / "y.py", tmp_path / "z.py"]
    modmap = {files[0]: "mx", files[1]: "my", files[2]: "mz"}

    out = ps.run_proc_file_parallel(files, modmap, jobs=2)

    assert out[0] == ("ok", str(files[0]), "mx")
    assert out[1] == ("ok", str(files[1]), "my")
    assert out[2] == ("ok", str(files[2]), "mz")


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
