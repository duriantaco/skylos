from __future__ import annotations

from pathlib import Path
from concurrent.futures import Future

import skylos.scale.parallel_static as ps


class DummyCache:
    def __init__(self):
        self.store = {}
        self.get_calls = []
        self.put_calls = []

    def get(self, f):
        self.get_calls.append(f)
        return self.store.get(Path(f))

    def put(self, f, out):
        self.put_calls.append((Path(f), out))
        self.store[Path(f)] = out


class DummyCachePutFails(DummyCache):
    def __init__(self, fail_first=True):
        super().__init__()
        self.fail_first = fail_first
        self._failed = False

    def put(self, f, out):
        self.put_calls.append((Path(f), out))
        if self.fail_first and not self._failed:
            self._failed = True
            raise RuntimeError("cache put failed")
        self.store[Path(f)] = out


class DummyExecutor:
    def __init__(self, max_workers=1):
        self.max_workers = max_workers
        self.submitted = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def submit(self, fn, *args, **kwargs):
        fut = Future()
        self.submitted.append((fn, args, kwargs))
        try:
            fut.set_result(fn(*args, **kwargs))
        except Exception as e:
            fut.set_exception(e)
        return fut


def test_pytest_env_forces_jobs_1_and_runs_sequential(monkeypatch, tmp_path):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")

    calls = []

    def fake_proc_file(file_path, mod, extra_visitors=None):
        calls.append((Path(file_path), mod, extra_visitors))
        return ("ok", str(file_path))

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "a.py", tmp_path / "b.py"]
    modmap = {files[0]: "m1", files[1]: "m2"}

    out = ps.run_proc_file_parallel(files, modmap, jobs=999)

    assert len(out) == 2
    assert calls[0][0] == files[0]
    assert calls[1][0] == files[1]

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)


def test_cache_hit_skips_proc_file(monkeypatch, tmp_path):
    calls = []

    def fake_proc_file(file_path, mod, extra_visitors=None):
        calls.append(Path(file_path))
        return ("computed", str(file_path))

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "a.py", tmp_path / "b.py"]
    modmap = {files[0]: "m1", files[1]: "m2"}

    cache = DummyCache()
    cache.store[files[0]] = ("cached", "a")

    out = ps.run_proc_file_parallel(files, modmap, jobs=1, cache=cache)

    assert out[0] == ("cached", "a")
    assert out[1] == ("computed", str(files[1]))

    assert calls == [files[1]]

    assert len(cache.put_calls) == 1
    assert cache.put_calls[0][0] == files[1]


def test_progress_callback_called_sequential(monkeypatch, tmp_path):
    def fake_proc_file(file_path, mod, extra_visitors=None):
        return ("ok", str(file_path))

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "a.py", tmp_path / "b.py", tmp_path / "c.py"]
    modmap = {f: "mod" for f in files}

    progress = []

    def cb(i, total, f):
        progress.append((i, total, Path(f)))

    out = ps.run_proc_file_parallel(files, modmap, jobs=1, progress_callback=cb)

    assert len(out) == 3
    assert progress == [
        (1, 3, files[0]),
        (2, 3, files[1]),
        (3, 3, files[2]),
    ]


def test_parallel_path_preserves_order(monkeypatch, tmp_path):
    monkeypatch.setattr(ps, "ProcessPoolExecutor", DummyExecutor)

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    def fake_proc_file(file_path, mod, _=None):
        return ("ok", str(file_path), mod)

    import skylos.analyzer

    monkeypatch.setattr(skylos.analyzer, "proc_file", fake_proc_file)

    files = [tmp_path / "x.py", tmp_path / "y.py", tmp_path / "z.py"]
    modmap = {files[0]: "mx", files[1]: "my", files[2]: "mz"}

    cache = DummyCachePutFails(fail_first=True)

    out = ps.run_proc_file_parallel(files, modmap, jobs=2, cache=cache)

    assert out[0] == ("ok", str(files[0]), "mx")
    assert out[1] == ("ok", str(files[1]), "my")
    assert out[2] == ("ok", str(files[2]), "mz")

    assert len(cache.put_calls) == 1
