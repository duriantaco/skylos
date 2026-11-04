import http.client
import io
import json
import os
import subprocess
import threading

from rich.console import Console

from skylos.commands.done_cmd import run_done_command
from skylos.graph import build_graph
from skylos.graph.pipeline import pipeline
from skylos.graph.server import GraphServer


def git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Skylos Test", "-c", "user.email=test@example.invalid", *args],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout.strip()


def write(root, files):
    for name, source in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)  # skylos: ignore[SKY-D324] fixed paths under a fresh pytest tmp_path


CALC = "def add(a, b):\n    return a + b\n\n\ndef double(x):\n    return x * 2\n"
TESTS = (
    "from calc import add, double\n\n\ndef test_add():\n    assert add(1, 2) == 3\n\n\n"
    "def test_double():\n    assert double(2) == 4\n"
)


def repo(root):
    write(root, {"calc.py": CALC, "tests/test_calc.py": TESTS})
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    return root


def done(root, *extra):
    return run_done_command([str(root), "--base", "HEAD~1", *extra], console=Console(file=io.StringIO()))


def stage(run, key):
    return next(s for s in run["stages"] if s["key"] == key)


def two_runs(root):
    repo(root)
    write(root, {"calc.py": CALC.replace("return x * 2", "return x + x")})
    git(root, "commit", "-qam", "same result, new code")
    assert done(root) == 0
    first = sorted((root / ".skylos" / "receipts").glob("*.json"))
    old = [p for p in first if p.name != "latest.json"][0]
    os.utime(old, (1_700_000_000, 1_700_000_000))
    write(root, {
        "calc.py": CALC.replace("return x * 2", "return x * 3"),
        "tests/test_calc.py": TESTS.replace("\n\n\ndef test_double():\n    assert double(2) == 4\n", "\n"),
    })
    git(root, "commit", "-qam", "agent change that drops a test")
    assert done(root) == 1
    return root


def test_each_done_run_is_a_row_newest_first_with_its_stages(tmp_path):
    root = two_runs(tmp_path)
    data = pipeline(root)
    assert [c["key"] for c in data["columns"]] == ["tests", "honest", "guards", "security", "coverage", "unused", "other", "review", "verdict"]
    newest, older = data["runs"]
    assert newest["verdict"] == "fail"
    assert stage(newest, "verdict")["state"] == "fail"
    honest = stage(newest, "honest")
    assert honest["state"] == "fail"
    assert any(f["file"] == "tests/test_calc.py" for c in honest["checks"] for f in c["findings"])
    assert "No tests deleted, skipped or weakened (FAIL)" in newest["brief"]
    assert newest["brief"].splitlines()[1].endswith("(FAIL)")
    assert "Fix the code, not the checks" in newest["brief"]
    assert newest["rerun"].startswith("skylos done --base ")
    assert older["verdict"] == "pass"
    assert stage(older, "tests")["state"] == "pass"
    assert older["brief"] == ""
    assert stage(older, "review")["state"] == "not_run"


def test_a_saved_review_lands_on_the_run_for_the_same_commits(tmp_path):
    root = two_runs(tmp_path)
    capture = io.StringIO()
    assert run_done_command(["map", str(root), "--base", "HEAD~1"], console=Console(file=capture)) == 0
    newest = pipeline(root)["runs"][0]
    review = stage(newest, "review")
    assert review["state"] == "info"
    assert review["label"] == "1 to read first"
    assert review["review"]["read_first"][0]["name"] == "double"
    assert stage(pipeline(root)["runs"][1], "review")["state"] == "not_run"
    assert done(root) == 1
    assert stage(pipeline(root)["runs"][0], "guards")["state"] == "pass"


def test_unreadable_or_linked_receipts_are_left_out(tmp_path):
    root = two_runs(tmp_path)
    receipts = root / ".skylos" / "receipts"
    (receipts / "broken.json").write_text("{not json")
    (receipts / "forged.json").write_text(json.dumps({"schema": "nope"}))
    outside = tmp_path / "outside.json"
    outside.write_text((receipts / "latest.json").read_text())
    (receipts / "linked.json").symlink_to(outside)
    data = pipeline(root)
    assert len(data["runs"]) == 2
    assert data["unreadable"] == 2


def _get(port, path, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request("GET", path, headers=headers or {})
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, body


def test_viewer_serves_the_pipeline_only_with_its_token(tmp_path):
    root = two_runs(tmp_path)
    build_graph(root)
    server = GraphServer(root, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        assert _get(port, "/api/pipeline")[0] == 403
        status, body = _get(port, "/api/pipeline", {"X-Skylos-Token": server.token})
        assert status == 200
        assert [run["verdict"] for run in json.loads(body)["runs"]] == ["fail", "pass"]
    finally:
        server.shutdown()
        server.server_close()


def test_a_review_never_lands_on_another_head_with_the_same_base(tmp_path):
    repo(tmp_path)
    base = git(tmp_path, "rev-parse", "HEAD")
    write(tmp_path, {"calc.py": CALC.replace("return x * 2", "return x + x")})
    git(tmp_path, "commit", "-qam", "first head")
    assert run_done_command([str(tmp_path), "--base", base], console=Console(file=io.StringIO())) == 0
    first = [p for p in (tmp_path / ".skylos" / "receipts").glob("*.json") if p.name != "latest.json"][0]
    os.utime(first, (1_700_000_000, 1_700_000_000))
    write(tmp_path, {"calc.py": CALC.replace("return a + b", "return b + a")})
    git(tmp_path, "commit", "-qam", "second head")
    assert run_done_command([str(tmp_path), "--base", base], console=Console(file=io.StringIO())) == 0
    assert run_done_command(["map", str(tmp_path), "--base", base], console=Console(file=io.StringIO())) == 0
    newest, older = pipeline(tmp_path)["runs"]
    assert stage(newest, "review")["state"] == "info"
    assert stage(older, "review")["state"] == "not_run"


def test_a_rerun_on_the_same_commit_does_not_erase_the_failed_run(tmp_path):
    repo(tmp_path)
    write(tmp_path, {"tests/test_calc.py": TESTS.replace("\n\n\ndef test_double():\n    assert double(2) == 4\n", "\n")})
    git(tmp_path, "commit", "-qam", "agent deletes a test")
    assert done(tmp_path) == 1
    write(tmp_path, {"tests/test_calc.py": TESTS})
    assert done(tmp_path) == 0
    runs = pipeline(tmp_path)["runs"]
    assert [(run["verdict"], run["dirty"]) for run in runs] == [("pass", True), ("fail", False)]
    assert runs[0]["head"] == runs[1]["head"]


def test_the_history_keeps_the_last_fifty_runs(tmp_path):
    from skylos.done.receipt import HISTORY_LIMIT

    repo(tmp_path)
    write(tmp_path, {"calc.py": CALC.replace("return x * 2", "return x + x")})
    git(tmp_path, "commit", "-qam", "same result")
    history = tmp_path / ".skylos" / "receipts" / "history"
    history.mkdir(parents=True)
    for number in range(HISTORY_LIMIT + 5):
        (history / f"20200101T0000{number:02d}000000Z-old.json").write_text("{}")
    assert done(tmp_path) == 0
    kept = sorted(path.name for path in history.glob("*.json"))
    assert len(kept) == HISTORY_LIMIT
    assert not any(name.startswith("20200101T000000") for name in kept)
    assert kept[-1].endswith(".json") and not kept[-1].endswith("-old.json")


def test_a_review_saved_later_with_other_edits_never_lands_on_an_earlier_run(tmp_path):
    repo(tmp_path)
    write(tmp_path, {"tests/test_calc.py": TESTS.replace("\n\n\ndef test_double():\n    assert double(2) == 4\n", "\n")})
    git(tmp_path, "commit", "-qam", "agent deletes a test")
    assert done(tmp_path) == 1
    write(tmp_path, {"tests/test_calc.py": TESTS})
    assert done(tmp_path) == 0
    assert run_done_command(["map", str(tmp_path), "--base", "HEAD~1"], console=Console(file=io.StringIO())) == 0
    newest, failed = pipeline(tmp_path)["runs"]
    assert stage(newest, "review")["state"] == "info"
    assert stage(failed, "review")["state"] == "not_run"
    assert failed["brief"].startswith("Skylos done found problems")
