import json
import runpy
import sys
import threading
from pathlib import Path
from unittest.mock import patch
from skylos.tracer import CallTracer, start_tracing, stop_tracing
import skylos.tracer as tracer_mod


def _collect_traced_names(tracer):
    traced = set()
    for f, fn, _line in tracer.called_functions:
        traced.add((Path(f).name, fn))
    return traced


def test_should_trace_file_include_only_mode():
    tracer = CallTracer(include_patterns=["/proj/src/"])
    assert tracer._should_trace_file("/proj/src/a.py") is True
    assert tracer._should_trace_file("/proj/other/b.py") is False
    assert tracer._should_trace_file("") is False
    assert tracer._should_trace_file(None) is False


def test_should_trace_file_exclude_default_blocks_site_packages():
    tracer = CallTracer()
    assert tracer._should_trace_file("/usr/lib/python/site-packages/x.py") is False
    assert tracer._should_trace_file("/myproj/app/main.py") is True


def test_trace_records_calls_and_counts_increment(tmp_path):
    src = tmp_path / "mini_mod.py"
    src.write_text(
        "def a():\n"
        "    return 1\n"
        "\n"
        "def b():\n"
        "    return a() + 1\n"
        "\n"
        "def run():\n"
        "    b()\n"
        "    b()\n"
        "    return 0\n"
        "\n"
        "run()\n",
        encoding="utf-8",
    )

    tracer = CallTracer(include_patterns=[str(src)])

    with tracer:
        runpy.run_path(str(src), run_name="__main__")

    traced = _collect_traced_names(tracer)

    assert ("mini_mod.py", "a") in traced
    assert ("mini_mod.py", "b") in traced
    assert ("mini_mod.py", "run") in traced

    b_key = None
    for f, fn, line in tracer.called_functions:
        if Path(f).name == "mini_mod.py" and fn == "b":
            b_key = (f, fn, line)
            break

    assert b_key is not None
    assert tracer.call_counts[b_key] == 2


def test_include_overrides_exclude_patterns(tmp_path):

    src = tmp_path / "pytest_of_fake.py"
    src.write_text(
        "def foo():\n"
        "    return 123\n"
        "\n"
        "foo()\n",
        encoding="utf-8",
    )

    tracer = CallTracer(
        include_patterns=[str(src)],
        exclude_patterns=["pytest"],
    )

    with tracer:
        runpy.run_path(str(src), run_name="__main__")

    traced = _collect_traced_names(tracer)
    assert ("pytest_of_fake.py", "foo") in traced


def test_context_manager_restores_previous_profiles(monkeypatch):
    def dummy_prof(frame, event, arg):
        return dummy_prof

    monkeypatch.setattr(sys, "getprofile", lambda: dummy_prof)
    monkeypatch.setattr(threading, "getprofile", lambda: dummy_prof)

    tracer = CallTracer(include_patterns=["/definitely/not/used"])


    with tracer:
        pass

    assert sys.getprofile() is dummy_prof
    assert threading.getprofile() is dummy_prof



def test_save_writes_expected_json_and_counts(tmp_path):
    tracer = CallTracer()
    tracer.called_functions.add(("/project/app.py", "f", 10))
    tracer.call_counts[("/project/app.py", "f", 10)] = 3

    out = tmp_path / ".skylos_trace"

    with patch("builtins.print") as p:
        tracer.save(out)

    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert isinstance(data["calls"], list)
    assert len(data["calls"]) == 1

    item = data["calls"][0]
    assert item["file"] == "/project/app.py"
    assert item["function"] == "f"
    assert item["line"] == 10
    assert item["count"] == 3

    assert p.called is True


def test_load_returns_none_when_missing(tmp_path):
    missing = tmp_path / "does_not_exist.trace"
    calls = CallTracer.load(missing)
    assert calls is None


def test_load_invalid_json_returns_none_and_warns(tmp_path):
    bad = tmp_path / ".skylos_trace"
    bad.write_text("{not json", encoding="utf-8")

    with patch("builtins.print") as p:
        calls = CallTracer.load(bad)

    assert calls is None
    assert p.called is True


def test_load_roundtrip_keys_only(tmp_path):
    tracer = CallTracer()
    tracer.called_functions.add(("/project/app.py", "f", 10))
    tracer.call_counts[("/project/app.py", "f", 10)] = 3

    out = tmp_path / ".skylos_trace"
    tracer.save(out)

    calls = CallTracer.load(out)
    assert calls is not None
    assert ("/project/app.py", "f", 10) in calls


def test_global_start_and_stop_tracing_creates_file_and_returns_tracer(tmp_path):
    out = tmp_path / ".skylos_trace"

    with patch("builtins.print") as p:
        tr = start_tracing(include_patterns=["/definitely/not/used"])
        assert tr is not None

        stopped = stop_tracing(save_path=str(out))

    assert stopped is not None
    assert out.exists()
    assert p.called is True

def _has_traced(tracer, filename: str, func: str) -> bool:
    for f, fn, _line in tracer.called_functions:
        if Path(f).name == filename and fn == func:
            return True
    return False


def _count_for(tracer, filename: str, func: str):
    for f, fn, line in tracer.called_functions:
        if Path(f).name == filename and fn == func:
            return tracer.call_counts[(f, fn, line)]
    return None


def test_traces_calls_inside_new_thread(tmp_path):
    src = tmp_path / "thread_mod.py"
    src.write_text(
        "import threading\n"
        "\n"
        "def inner():\n"
        "    return 7\n"
        "\n"
        "def worker():\n"
        "    inner()\n"
        "    inner()\n"
        "\n"
        "def run():\n"
        "    t = threading.Thread(target=worker)\n"
        "    t.start()\n"
        "    t.join()\n"
        "\n"
        "run()\n",
        encoding="utf-8",
    )

    tracer = CallTracer(include_patterns=[str(src)])

    with tracer:
        runpy.run_path(str(src), run_name="__main__")

    assert _has_traced(tracer, "thread_mod.py", "run") is True
    assert _has_traced(tracer, "thread_mod.py", "worker") is True
    assert _has_traced(tracer, "thread_mod.py", "inner") is True

    cnt = _count_for(tracer, "thread_mod.py", "inner")
    assert cnt is not None
    assert cnt == 2


def test_exclude_patterns_prevent_tracing_when_no_include(tmp_path):
    src = tmp_path / "no_trace_mod.py"
    src.write_text(
        "def a():\n"
        "    return 1\n"
        "\n"
        "def run():\n"
        "    return a()\n"
        "\n"
        "run()\n",
        encoding="utf-8",
    )

    tracer = CallTracer(include_patterns=None, exclude_patterns=[str(src)])

    with tracer:
        runpy.run_path(str(src), run_name="__main__")

    assert _has_traced(tracer, "no_trace_mod.py", "a") is False
    assert _has_traced(tracer, "no_trace_mod.py", "run") is False


def test_start_stop_restore_previous_traces(monkeypatch):
    calls = {
        "sys_set": [],
        "thread_set": [],
    }

    def dummy_prev(frame, event, arg):
        return dummy_prev

    def fake_sys_getprofile():
        return dummy_prev

    def fake_thread_getprofile():
        return dummy_prev

    def fake_sys_setprofile(fn):
        calls["sys_set"].append(fn)

    def fake_thread_setprofile(fn):
        calls["thread_set"].append(fn)


    monkeypatch.setattr(sys, "getprofile", fake_sys_getprofile)
    monkeypatch.setattr(threading, "getprofile", fake_thread_getprofile)
    monkeypatch.setattr(sys, "setprofile", fake_sys_setprofile)
    monkeypatch.setattr(threading, "setprofile", fake_thread_setprofile)

    tr = CallTracer(include_patterns=["/does/not/matter"])

    tr.start()
    tr.stop()

    assert len(calls["sys_set"]) >= 2
    assert calls["sys_set"][0] == tr._trace_calls
    assert calls["sys_set"][-1] == dummy_prev

    assert len(calls["thread_set"]) >= 2
    assert calls["thread_set"][0] == tr._trace_calls
    assert calls["thread_set"][-1] == dummy_prev


def test_pytest_configure_and_unconfigure_call_start_stop(monkeypatch):
    started = {"called": False, "include": None}
    stopped = {"called": False}

    def fake_start_tracing(include_patterns=None, exclude_patterns=None):
        started["called"] = True
        started["include"] = include_patterns
        return CallTracer()

    def fake_stop_tracing(save_path=".skylos_trace"):
        stopped["called"] = True
        return None

    monkeypatch.setattr(tracer_mod, "start_tracing", fake_start_tracing)
    monkeypatch.setattr(tracer_mod, "stop_tracing", fake_stop_tracing)

    class DummyConfig:
        def getoption(self, name, default=None):
            if name == "--skylos-trace":
                return True
            if name == "--skylos-trace-include":
                return "a,b,c"
            return default

    cfg = DummyConfig()

    tracer_mod.pytest_configure(cfg)
    assert started["called"] is True
    assert started["include"] == ["a", "b", "c"]

    tracer_mod.pytest_unconfigure(cfg)
    assert stopped["called"] is True


def test_pytest_addoption_registers_expected_flags():
    added = []

    class DummyParser:
        def addoption(self, name, **kwargs):
            added.append(name)

    parser = DummyParser()
    tracer_mod.pytest_addoption(parser)

    assert "--skylos-trace" in added
    assert "--skylos-trace-include" in added


def test_stop_tracing_when_never_started_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)

    out = tmp_path / ".skylos_trace"
    stopped = tracer_mod.stop_tracing(save_path=str(out))

    assert stopped is None
    assert out.exists() is False


def test_get_stats_reports_files_sorted_and_counts():
    tr = CallTracer()
    tr.called_functions.add(("/b/file2.py", "f2", 20))
    tr.called_functions.add(("/a/file1.py", "f1", 10))
    tr.called_functions.add(("/a/file1.py", "f3", 30))

    stats = tr.get_stats()

    assert stats["unique_functions"] == 3
    assert stats["files_traced"] == 2

    files = stats["files"]
    assert isinstance(files, list)
    assert files == sorted(files)
    assert "/a/file1.py" in files
    assert "/b/file2.py" in files
