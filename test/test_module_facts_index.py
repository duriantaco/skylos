"""Persistent module-facts index: cached scans must equal uncached scans."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from skylos.analysis import ast_cache
from skylos.commands import hook_cmd
from skylos.commands.warm_cache_cmd import run_warm_cache_command
from skylos.core.fast_paths import ParentResolver, is_within, relative_parts
from skylos.core.file_discovery import exclusion_matcher, should_exclude_path
from skylos.rules.ai_defect import installed_modules_cache
from skylos.rules.ai_defect import module_facts_index as mfi
from skylos.rules.ai_defect import phantom_refs
from skylos.rules.ai_defect import python_api_hallucination as python_api
from skylos.rules.ai_defect.python_api_hallucination import (
    scan_python_local_api_hallucinations,
)
from skylos.verify_change import verify_change_path

REPO_ROOT = Path(__file__).resolve().parents[1]

FIXTURE = {
    "pkg/__init__.py": "from pkg import extra as ex\nfrom pkg import helpers\n",
    "pkg/helpers.py": "def real():\n    return 1\n\n\nVALUE = 2\n",
    "pkg/sub.py": (
        "from typing import TYPE_CHECKING\n\n"
        "if TYPE_CHECKING:\n"
        "    from pkg.helpers import real as typed_real\n\n\n"
        "def sub_fn():\n"
        "    return 1\n"
    ),
    "pkg/dyn.py": "def __getattr__(name):\n    return name\n",
    "broken.py": "def oops(:\n",
    "app.py": (
        "import pkg\n"
        "import pkg.helpers\n"
        "import broken\n"
        "from pkg import dyn, helpers, sub\n"
        "from pkg.helpers import missing_name, real\n\n"
        "helpers.real()\n"
        "helpers.not_there()\n"
        "sub.sub_fn()\n"
        "sub.gone()\n"
        "pkg.helpers.VALUE\n"
        "dyn.anything()\n"
        "broken.oops()\n"
        "pkg.ex.thing()\n"
    ),
    "other.py": "import app\n\napp.helpers.real()\napp.nothing()\n",
}


def _write(root: Path, name: str, source: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        source, encoding="utf-8"
    )
    return path


def _project(root: Path) -> None:
    for name, source in FIXTURE.items():
        _write(root, name, source)


def _py_files(root: Path) -> list[Path]:
    return sorted(
        p for p in root.rglob("*.py") if ".skylos" not in p.relative_to(root).parts
    )


def _scan(root: Path, targets: list[str], *, cached: bool):
    files = _py_files(root)
    target_paths = [root / name for name in targets]
    if not cached:
        return scan_python_local_api_hallucinations(
            root, files, target_files=target_paths
        )
    with mfi.module_facts_index_session(root) as index:
        result = scan_python_local_api_hallucinations(
            root, files, target_files=target_paths
        )
    return result, mfi.describe(index)


def _assert_same(root: Path, targets: list[str]):
    expected = _scan(root, targets, cached=False)
    (actual, info) = _scan(root, targets, cached=True)
    assert json.dumps(actual, sort_keys=True, default=str) == json.dumps(
        expected, sort_keys=True, default=str
    )
    return expected, info


def _names(result) -> list[str]:
    findings, _ = result
    return sorted(str(f.get("simple_name")) for f in findings)


def test_cached_scan_equals_uncached_across_edits_removals_and_additions(tmp_path):
    _project(tmp_path)
    targets = ["app.py", "other.py"]

    cold, info = _assert_same(tmp_path, targets)
    assert info["loaded_entries"] == 0
    assert info["entries"] == len(_py_files(tmp_path))
    assert (tmp_path / mfi.CACHE_PATH).is_file()
    assert "not_there" in _names(cold)
    assert "gone" in _names(cold)

    warm, info = _assert_same(tmp_path, targets)
    assert warm == cold
    assert info["loaded_entries"] == len(_py_files(tmp_path))
    assert info["hits"] > 0

    # Edit a non-target module: its cached facts must be rebuilt.
    _write(
        tmp_path,
        "pkg/helpers.py",
        "def real():\n    return 1\n\n\ndef not_there():\n    return 3\n\n\nVALUE = 2\n",
    )
    edited, _ = _assert_same(tmp_path, targets)
    assert "not_there" not in _names(edited)

    # Remove a module that a target imports.
    (tmp_path / "pkg" / "sub.py").unlink()
    removed, _ = _assert_same(tmp_path, targets)
    assert "gone" not in _names(removed)

    # Add a module. pkg/__init__.py is unchanged on disk, but its facts
    # depended on "is pkg.extra a local module?", so its entry must be
    # invalidated: the ``ex`` alias now re-exports module pkg.extra, and
    # pkg.ex.thing() becomes a checked (missing) member of it.
    _write(tmp_path, "pkg/extra.py", "def other():\n    return 1\n")
    added, _ = _assert_same(tmp_path, targets)
    assert "thing" in _names(added)
    assert "thing" not in _names(removed)

    # Fix the parse error in a non-target module.
    _write(tmp_path, "broken.py", "def oops():\n    return 1\n")
    _assert_same(tmp_path, targets)


def test_warm_scan_parses_only_target_files(tmp_path, monkeypatch):
    _project(tmp_path)
    _scan(tmp_path, ["app.py"], cached=True)

    parsed: list[str] = []
    original = ast_cache.load_python_module

    def counting(path, mode):
        parsed.append(Path(path).name)
        return original(path, mode)

    monkeypatch.setattr(phantom_refs, "load_python_module", counting)
    monkeypatch.setattr(python_api, "load_python_module", counting)
    _scan(tmp_path, ["app.py"], cached=True)

    assert set(parsed) == {"app.py"}


def test_index_header_mismatch_rebuilds(tmp_path, monkeypatch):
    _project(tmp_path)
    _scan(tmp_path, ["app.py"], cached=True)
    monkeypatch.setattr(mfi, "_implementation_fingerprint", lambda: ["other"])
    _, info = _assert_same(tmp_path, ["app.py"])
    assert info["loaded_entries"] == 0
    # Every module is rebuilt once (the coverage pass then reuses them).
    assert info["misses"] == len(_py_files(tmp_path))


def test_corrupt_index_fails_open(tmp_path):
    _project(tmp_path)
    cache = tmp_path / mfi.CACHE_PATH
    cache.parent.mkdir(parents=True)
    cache.write_text("{not json", encoding="utf-8")
    _assert_same(tmp_path, ["app.py"])
    cache.write_text(
        json.dumps({"header": mfi._implementation_fingerprint(), "entries": {"x": 1}}),
        encoding="utf-8",
    )
    _assert_same(tmp_path, ["app.py"])


def test_tampered_entry_payload_is_rebuilt(tmp_path):
    _project(tmp_path)
    _scan(tmp_path, ["app.py"], cached=True)
    cache = tmp_path / mfi.CACHE_PATH
    data = json.loads(cache.read_text(encoding="utf-8"))
    for entry in data["entries"].values():
        entry["facts"] = {"broken": True} if entry["status"] == "ok" else None
    cache.write_text(json.dumps(data), encoding="utf-8")
    _assert_same(tmp_path, ["app.py"])


def test_index_is_inactive_outside_a_session(tmp_path):
    _project(tmp_path)
    assert mfi.active_module_facts_index() is None
    _scan(tmp_path, ["app.py"], cached=False)
    assert not (tmp_path / mfi.CACHE_PATH).exists()


def test_recording_modules_only_supports_membership():
    recording = mfi.RecordingModules({"a", "b"})
    assert "a" in recording
    assert "z" not in recording
    assert recording.queries == {"a": True, "z": False}
    with pytest.raises(TypeError):
        list(recording)


def test_verify_change_path_matches_with_index(tmp_path):
    _project(tmp_path)
    target = tmp_path / "app.py"
    expected = verify_change_path(target, behavior_comparison=False)
    for _ in range(2):  # cold, then warm
        with mfi.module_facts_index_session(tmp_path):
            actual = verify_change_path(target, behavior_comparison=False)
        assert actual == expected


def test_post_edit_hook_uses_index_and_matches_uncached(tmp_path):
    _project(tmp_path)
    (tmp_path / ".git").mkdir()
    target = tmp_path / "app.py"
    payload = json.dumps(
        {
            "session_id": "s1",
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "cwd": str(tmp_path),
            "tool_input": {"file_path": str(target), "content": FIXTURE["app.py"]},
        }
    )
    env = {"CLAUDE_PROJECT_DIR": str(tmp_path)}

    def run(deps):
        out = io.StringIO()
        hook_cmd.run_hook_command(
            ["post-edit"], stdin=io.StringIO(payload), stdout=out, deps=deps
        )
        return out.getvalue()

    uncached = run(
        hook_cmd.HookDeps(
            verify=lambda target, **kw: verify_change_path(target, **kw), env=env
        )
    )
    (tmp_path / ".skylos" / "agent-session.json").unlink()
    cold = run(hook_cmd.HookDeps(env=env))
    assert (tmp_path / mfi.CACHE_PATH).is_file()
    (tmp_path / ".skylos" / "agent-session.json").unlink()
    warm = run(hook_cmd.HookDeps(env=env))
    assert "not_there" in uncached
    assert cold == uncached
    assert warm == uncached


def test_warm_cache_command_builds_index(tmp_path):
    _project(tmp_path)
    (tmp_path / ".git").mkdir()
    lines: list[str] = []
    assert run_warm_cache_command(Namespace(path=str(tmp_path)), print_func=lines.append) == 0
    assert (tmp_path / mfi.CACHE_PATH).is_file()
    assert "Indexed" in lines[-1]

    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / ".git").mkdir()
    lines.clear()
    assert run_warm_cache_command(Namespace(path=str(empty)), print_func=lines.append) == 0
    assert "nothing to warm" in lines[-1]


def test_installed_module_mapping_cache(tmp_path, monkeypatch):
    calls = []

    def build():
        calls.append(1)
        return {"yaml": {"pyyaml"}, "requests": {"requests"}}

    # Outside a session: always rebuilt, never persisted.
    assert installed_modules_cache.installed_module_mapping(build) == build()
    assert not (tmp_path / installed_modules_cache.CACHE_PATH).exists()
    calls.clear()

    with mfi.module_facts_index_session(tmp_path):
        first = installed_modules_cache.installed_module_mapping(build)
        second = installed_modules_cache.installed_module_mapping(build)
    assert first == second == build()
    assert len(calls) == 2  # the explicit build() above plus one cold build

    calls.clear()
    monkeypatch.setattr(installed_modules_cache, "environment_key", lambda: ["new"])
    with mfi.module_facts_index_session(tmp_path):
        installed_modules_cache.installed_module_mapping(build)
    assert len(calls) == 1


def test_real_installed_module_mapping_round_trips(tmp_path):
    from skylos.rules.ai_defect import dependency_hallucination as dep

    fresh = dep._build_installed_module_mapping()
    with mfi.module_facts_index_session(tmp_path):
        cold = installed_modules_cache.installed_module_mapping(
            dep._build_installed_module_mapping
        )
        warm = installed_modules_cache.installed_module_mapping(
            dep._build_installed_module_mapping
        )
    assert cold == warm == fresh


def test_parent_resolver_matches_path_resolve(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "linkdir").symlink_to(real_dir, target_is_directory=True)
    (tmp_path / "linkfile.py").symlink_to(real_dir / "a.py")
    resolver = ParentResolver()
    candidates = [
        real_dir / "a.py",
        tmp_path / "linkdir" / "a.py",
        tmp_path / "linkfile.py",
        tmp_path / "linkdir" / "missing.py",
        real_dir / ".." / "real" / "a.py",
        tmp_path / "linkdir",
    ]
    for path in candidates:
        assert resolver.resolve(path) == path.resolve()
        try:
            expected = path.resolve(strict=True)
        except OSError:
            with pytest.raises(OSError):
                resolver.resolve(path, strict=True)
        else:
            assert resolver.resolve(path, strict=True) == expected


def test_relative_helpers_match_pathlib(tmp_path):
    root = tmp_path
    for path in (root / "a" / "b.py", root, root / "x"):
        assert is_within(path, root)
        assert relative_parts(path, root) == path.relative_to(root).parts
    for rel_root, rel_path in ((Path("."), Path("src/a.py")), (Path("src"), Path("src/a/b.py"))):
        assert relative_parts(rel_path, rel_root) == rel_path.relative_to(rel_root).parts
        assert is_within(rel_path, rel_root)
    outside = tmp_path.parent / (tmp_path.name + "-sibling") / "c.py"
    assert not is_within(outside, root)
    with pytest.raises(ValueError):
        relative_parts(outside, root)


def test_exclusion_matcher_matches_should_exclude_path(tmp_path):
    patterns = ["node_modules", "build/out", "*.egg-info", "**/gen/**", str(tmp_path / "abs")]
    matcher = exclusion_matcher(tmp_path, patterns)
    for rel in (
        "src/app.py",
        "node_modules/x/index.js",
        "build/out/a.py",
        "build/other/a.py",
        "pkg.egg-info/PKG-INFO",
        "a/gen/b.py",
        "abs/file.py",
        ".",
    ):
        path = tmp_path / rel
        assert matcher(path) == should_exclude_path(path, tmp_path, patterns), rel
    assert not exclusion_matcher(tmp_path, None)(tmp_path / "a.py")


def test_run_memo_is_scoped_to_a_cache_session():
    calls = []

    def compute():
        calls.append(1)
        return len(calls)

    assert ast_cache.run_memo(("k",), compute) == 1
    assert ast_cache.run_memo(("k",), compute) == 2
    with ast_cache.python_ast_cache_session():
        assert ast_cache.run_memo(("k",), compute) == 3
        assert ast_cache.run_memo(("k",), compute) == 3
    with ast_cache.python_ast_cache_session():
        assert ast_cache.run_memo(("k",), compute) == 4


def test_hook_entry_skips_full_cli_import(tmp_path):
    code = (
        "import sys\n"
        "sys.argv = ['skylos', 'hook', 'pre-bash']\n"
        "from skylos import entry\n"
        "try:\n"
        "    entry.main()\n"
        "except SystemExit:\n"
        "    pass\n"
        "heavy = [m for m in ('skylos.cli', 'keyring', 'rich', 'skylos.analyzer') "
        "if m in sys.modules]\n"
        "sys.stderr.write('HEAVY=' + ','.join(heavy))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        input='{"tool_name": "Bash", "tool_input": {"command": "ls"}}',
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        timeout=60,
    )
    assert "HEAVY=" in result.stderr
    assert result.stderr.split("HEAVY=")[-1].strip() == ""
