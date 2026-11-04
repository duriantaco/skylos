import io
import json
import subprocess

from rich.console import Console

from skylos.commands.done_cmd import run_done_command
from skylos.graph import build_graph


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


BASE = {
    "calc.py": "def add(a, b):\n    return a + b\n",
    "tests/test_calc.py": "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
}


def repo(root, extra=None):
    files = dict(BASE)
    files.update(extra or {})
    write(root, files)
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    return root


def done_receipt(root, capsys):
    capsys.readouterr()
    run_done_command([str(root), "--base", "HEAD", "--no-tests", "--format", "json"], console=Console(file=io.StringIO()))
    return json.loads(capsys.readouterr().out)


def check(receipt, check_id):
    return next(c for c in receipt["checks"] if c["id"] == check_id)


def flagged_paths(receipt):
    return sorted(f["file"] for f in check(receipt, "gate_tampering")["findings"])


def test_files_skylos_graph_writes_are_not_a_settings_change(tmp_path, capsys):
    repo(tmp_path)
    build_graph(tmp_path)
    write(tmp_path, {".skylos/graph/reviews/abc-def.json": "{}"})
    receipt = done_receipt(tmp_path, capsys)
    assert check(receipt, "gate_tampering")["status"] == "pass"
    assert flagged_paths(receipt) == []


def test_shared_descriptions_are_not_a_settings_change_but_are_still_checked(tmp_path, capsys):
    repo(tmp_path)
    write(tmp_path, {".skylos/graph/notes.json": json.dumps({"nodes": {"calc.add": {"text": "Adds two numbers."}}})})
    receipt = done_receipt(tmp_path, capsys)
    assert check(receipt, "gate_tampering")["status"] == "pass"
    write(tmp_path, {".skylos/graph/notes.json": json.dumps({"aws": "AKIA" + "Q4ZJ7XK2PLMN3RTB", "secret": "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzQ4ZJ7XK2P"})})
    receipt = done_receipt(tmp_path, capsys)
    assert check(receipt, "secrets")["status"] == "fail"
    assert any(f["file"] == ".skylos/graph/notes.json" for f in check(receipt, "secrets")["findings"])


def test_other_skylos_files_stay_protected(tmp_path, capsys):
    repo(tmp_path)
    write(tmp_path, {
        ".skylos/graph-settings.json": "{}",
        ".skylos/rules/custom.yaml": "rules: []\n",
    })
    receipt = done_receipt(tmp_path, capsys)
    assert check(receipt, "gate_tampering")["status"] == "fail"
    assert flagged_paths(receipt) == [".skylos/graph-settings.json", ".skylos/rules/custom.yaml"]


def test_descriptions_listed_by_name_in_protected_paths_stay_protected(tmp_path, capsys):
    settings = '[tool.skylos.done]\nprotected_paths = [".skylos/", ".skylos/graph/notes.json"]\n'
    repo(tmp_path, {"pyproject.toml": settings})
    write(tmp_path, {".skylos/graph/notes.json": "{}"})
    receipt = done_receipt(tmp_path, capsys)
    assert check(receipt, "gate_tampering")["status"] == "fail"
    assert flagged_paths(receipt) == [".skylos/graph/notes.json"]
