import ast
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/warm_edit_benchmark.py"
SPEC = importlib.util.spec_from_file_location("_warm_edit_benchmark", SCRIPT)
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


@pytest.fixture
def metadata(monkeypatch):
    monkeypatch.setattr(bench, "_git", lambda *args: "")
    monkeypatch.setattr(bench, "_version", lambda *args: "probe")


@pytest.mark.parametrize("original", [b"x = 1", b"x = 1\n", b"x = 1\r\n"])
def test_edits_remain_valid_python_and_restore_original(
    tmp_path, monkeypatch, metadata, original
):
    target = tmp_path / "app.py"
    target.write_bytes(original)
    seen = []

    def run(skylos, repo, path):
        source = path.read_bytes()
        ast.parse(source)
        seen.append(source)
        return 0.01, 0, "clean", []

    monkeypatch.setattr(bench, "_run_recheck", run)
    result = bench.benchmark(tmp_path, target, 2, "probe")

    assert len(seen) == 3 and len(set(seen)) == 3
    assert target.read_bytes() == original
    assert result["warm_p50_seconds"] == 0.01


@pytest.mark.parametrize("fail_at", [1, 2])
def test_unexpected_exit_stops_immediately_and_restores(
    tmp_path, monkeypatch, metadata, fail_at
):
    target = tmp_path / "app.py"
    original = b"x = 1\n"
    target.write_bytes(original)
    calls = []

    def run(*args):
        calls.append(target.read_bytes())
        return 0.01, 2 if len(calls) == fail_at else 0, "incomplete", []

    monkeypatch.setattr(bench, "_run_recheck", run)
    with pytest.raises(SystemExit, match="hook recheck failed"):
        bench.benchmark(tmp_path, target, 4, "probe")

    assert len(calls) == fail_at
    assert target.read_bytes() == original


def test_recheck_exception_restores_benchmark_edit(tmp_path, monkeypatch, metadata):
    target = tmp_path / "app.py"
    original = b"x = 1\n"
    target.write_bytes(original)
    calls = []

    def run(*args):
        calls.append(1)
        if len(calls) == 2:
            raise OSError("probe failed")
        return 0.01, 0, "clean", []

    monkeypatch.setattr(bench, "_run_recheck", run)
    with pytest.raises(OSError, match="probe failed"):
        bench.benchmark(tmp_path, target, 2, "probe")

    assert target.read_bytes() == original


def test_independent_edit_is_preserved(tmp_path, monkeypatch, metadata):
    target = tmp_path / "app.py"
    target.write_bytes(b"x = 1\n")
    independent = b"user_edit = 2\n"
    calls = []

    def run(*args):
        calls.append(1)
        if len(calls) == 2:
            target.write_bytes(independent)
        return 0.01, 0, "clean", []

    monkeypatch.setattr(bench, "_run_recheck", run)
    with pytest.raises(SystemExit, match="changed outside the benchmark"):
        bench.benchmark(tmp_path, target, 4, "probe")

    assert target.read_bytes() == independent
    assert len(calls) == 2


def test_recheck_records_stderr_stats_without_replacing_verdict(tmp_path, monkeypatch):
    target = tmp_path / "app.py"
    telemetry = {"module_facts": {"enabled": True, "hits": 8, "rebuilt": 1}}
    captured = []

    def run(command, **kwargs):
        captured.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            "Skylos: no blocking issues\n",
            "notice\nSKYLOS_VERIFY_STATS=" + json.dumps(telemetry) + "\n",
        )

    monkeypatch.setattr(bench.subprocess, "run", run)
    seconds, code, verdict, stats = bench._run_recheck("skylos-probe", tmp_path, target)

    assert seconds >= 0 and code == 0
    assert verdict == "Skylos: no blocking issues"
    assert stats == [telemetry]
    assert captured[0][0] == ["skylos-probe", "hook", "recheck", str(target)]
    assert captured[0][1]["env"]["SKYLOS_VERIFY_STATS"] == "1"


def test_stderr_verdict_ignores_telemetry_and_malformed_stats(tmp_path, monkeypatch):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 2, "", "incomplete scan\nSKYLOS_VERIFY_STATS=not-json\n"
        )

    monkeypatch.setattr(bench.subprocess, "run", run)
    _, code, verdict, stats = bench._run_recheck("probe", tmp_path, tmp_path / "app.py")

    assert code == 2 and verdict == "incomplete scan" and stats == []


def test_each_round_records_its_own_stats(tmp_path, monkeypatch, metadata):
    target = tmp_path / "app.py"
    target.write_bytes(b"x = 1\n")
    records = [
        {"module_facts": {"hits": 0, "rebuilt": 2}},
        {"module_facts": {"hits": 1, "rebuilt": 1}},
    ]
    pending = iter(records)
    monkeypatch.setattr(
        bench, "_run_recheck", lambda *args: (0.01, 0, "clean", [next(pending)])
    )

    result = bench.benchmark(tmp_path, target, 1, "probe")

    assert [run["verification_stats"] for run in result["runs"]] == [
        [r] for r in records
    ]
