import hashlib
import json
import subprocess

from skylos.cicd.context_packet import build_pr_context, format_context_for_model


def _write(root, name, source):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    return path


def _finding(name="app.py", line=3):
    return {"file": name, "line": line, "rule_id": "SKY-D201"}


def test_packet_connects_imported_caller_and_callee_without_executing_source(tmp_path):
    app = "from service import run\ndef route(value):\n    return run(value)\n"
    service = "def run(value):\n    return eval(value)\nraise RuntimeError('never import this')\n"
    _write(tmp_path, "app.py", app)
    _write(tmp_path, "service.py", service)
    _write(tmp_path, "test/test_app.py", "from app import route\n")
    packet = build_pr_context(tmp_path, [_finding()])

    assert {node["id"] for node in packet["nodes"]} == {"app.route", "service.run"}
    assert packet["edges"] == [
        {"from": "app.route", "to": "service.run", "kind": "static_call"}
    ]
    assert (
        packet["file_digests"]["service.py"]
        == hashlib.sha256(service.encode()).hexdigest()
    )
    assert packet["related_tests"] == ["test/test_app.py"]
    assert packet["checks"] == []
    assert "no tests were run" in " ".join(packet["limitations"])
    assert "runtime reachability" in " ".join(packet["limitations"])
    assert (
        build_pr_context(tmp_path, [_finding()])["snapshot_id"] == packet["snapshot_id"]
    )


def test_packet_marks_budget_and_unparseable_files_incomplete(tmp_path):
    _write(tmp_path, "app.py", "def f():\n  return 1\n")
    _write(tmp_path, "bad.py", "def broken(\n")
    packet = build_pr_context(tmp_path, [_finding(line=2)])
    assert "could not be parsed" in " ".join(packet["limitations"])
    limited = build_pr_context(tmp_path, [_finding(line=2)], max_files=1)
    assert list(limited["file_digests"]) == ["app.py"]
    assert "File discovery budget" in " ".join(limited["limitations"])
    assert packet["snapshot_id"] != limited["snapshot_id"]


def test_packet_rejects_outside_and_symlink_source(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _write(tmp_path, "outside.py", "SECRET = 'external'\n")
    (root / "linked.py").symlink_to(tmp_path / "outside.py")
    (root / "directory").symlink_to(tmp_path, target_is_directory=True)
    packet = build_pr_context(root, [_finding("../outside.py"), _finding("linked.py")])
    assert packet["file_digests"] == {}
    assert packet["nodes"] == []


def test_packet_excludes_private_maintenance_files_even_if_requested(tmp_path):
    for directory in (".agents", ".codex", ".claude", ".skylos", ".aws"):
        _write(
            tmp_path, directory + "/private.py", "def private():\n    return 'local'\n"
        )
    packet = build_pr_context(tmp_path, [_finding(".agents/private.py", line=2)])
    assert packet["file_digests"] == {}
    assert packet["nodes"] == []


def test_packet_snapshot_changes_with_source_and_model_data_is_redacted(tmp_path):
    _write(tmp_path, "app.py", "def f():\n    return 1\n")
    before = build_pr_context(tmp_path, [_finding(line=2)])
    _write(tmp_path, "app.py", "def f():\n    return 2\n")
    after = build_pr_context(tmp_path, [_finding(line=2)])
    assert before["snapshot_id"] != after["snapshot_id"]
    token = "gh" + "p_" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW2xY4zA6"
    after["nodes"][0]["excerpt"] = f"API_TOKEN='{token}'"
    text = format_context_for_model(after)
    assert token not in text
    assert "untrusted source data" in text
    assert "runtime proof" in text


def test_model_budget_retains_limits_and_valid_json():
    packet = {
        "version": 1,
        "nodes": [{"excerpt": "x" * 50_000}] * 10,
        "limitations": ["Partial graph"],
        "snapshot_id": "a" * 64,
    }
    text = format_context_for_model(packet, max_chars=1000)
    data = json.loads(text.split("\n")[1])
    assert "nodes" not in data
    assert "Partial graph" in data["limitations"]
    assert any("budget reached" in item for item in data["limitations"])


def test_real_packet_capacity_preserves_limitations_and_snapshot():
    packet = {
        "file_digests": {f"module{i}.py": "a" * 64 for i in range(80)},
        "nodes": [
            {
                "id": str(i),
                "file": f"module{i}.py",
                "line": 1,
                "end_line": 2,
                "kind": "function",
                "source_sha256": "b" * 64,
                "excerpt": "def f(): pass",
                "excerpt_complete": True,
            }
            for i in range(24)
        ],
        "edges": [
            {"from": str(i % 24), "to": str((i + 1) % 24), "kind": "static_call"}
            for i in range(48)
        ],
        "limitations": ["Dynamic dispatch is unknown", "No runtime proof"],
        "snapshot_id": "c" * 64,
    }
    data = json.loads(format_context_for_model(packet, max_chars=64000).split("\n")[1])
    assert data["snapshot_id"] == "c" * 64
    assert data["limitations"] == packet["limitations"]
    assert len(data["edges"]) == 48


def test_model_hash_records_keep_distinct_long_paths():
    prefix = "package/" + "a" * 90
    paths = {prefix + "/first.py": "a" * 64, prefix + "/second.py": "b" * 64}
    text = format_context_for_model({"file_digests": paths, "limitations": []})
    data = json.loads(text.split("\n")[1])
    assert data["file_digests"] == [
        {"file": name, "sha256": digest} for name, digest in paths.items()
    ]


def test_source_links_only_bind_matching_commit_blobs(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, text=True).strip()

    git("init", "-q")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")
    _write(tmp_path, "app.py", "def f():\n    return 1\n")
    git("add", "app.py")
    git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "baseline")
    head = git("rev-parse", "HEAD")
    packet = build_pr_context(tmp_path, [_finding(line=2)])
    assert packet["head_sha"] == head
    assert packet["committed_files"] == ["app.py"]
    _write(tmp_path, "app.py", "def f():\n    return 2\n")
    changed = build_pr_context(tmp_path, [_finding(line=2)])
    assert changed["head_sha"] == head
    assert changed["committed_files"] == []


def test_racing_source_discards_graph_and_source_binding(tmp_path, monkeypatch):
    from skylos.cicd import context_packet

    _write(tmp_path, "app.py", "def f():\n    return 1\n")
    original = context_packet._grounding._parse_project_graph

    def race(*args, **kwargs):
        graph = original(*args, **kwargs)
        _write(tmp_path, "app.py", "def f():\n    return 2\n")
        return graph

    monkeypatch.setattr(context_packet._grounding, "_parse_project_graph", race)
    packet = build_pr_context(tmp_path, [_finding(line=2)])
    assert packet["file_digests"] == {}
    assert packet["nodes"] == []
    assert packet["edges"] == []
    assert "Source changed" in " ".join(packet["limitations"])


def test_transient_source_change_cannot_change_hashed_graph(tmp_path, monkeypatch):
    from skylos.cicd import context_packet

    original_source = "def f():\n    return safe()\ndef safe():\n    return 1\n"
    _write(tmp_path, "app.py", original_source)
    original = context_packet._grounding._parse_project_graph

    def transient(*args, **kwargs):
        _write(
            tmp_path,
            "app.py",
            "def f():\n    return injected()\ndef injected():\n    return 2\n",
        )
        try:
            return original(*args, **kwargs)
        finally:
            _write(tmp_path, "app.py", original_source)

    monkeypatch.setattr(context_packet._grounding, "_parse_project_graph", transient)
    packet = build_pr_context(tmp_path, [_finding(line=2)])
    assert {node["id"] for node in packet["nodes"]} == {"app.f", "app.safe"}
    assert packet["edges"] == [
        {"from": "app.f", "to": "app.safe", "kind": "static_call"}
    ]
