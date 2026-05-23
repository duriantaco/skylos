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
