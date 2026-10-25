"""Explicit scan roots keep their evidence even beneath excluded folder names."""

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from skylos.analyzer import analyze
from skylos.constants import parse_exclude_folders
import skylos.core.grep_verify_common as grep_common
from skylos.core.grep_verify_common import (
    _make_grep_request,
    _run_grep_request,
    _run_python_grep_batch,
    execute_grep_batch,
    grep_verification_scope,
)


_REAL_WHICH = shutil.which
_PRECHECK = """from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    name: str

    def verdict(self) -> str:
        return "OK" if self.name else "BLOCKED"


def render(candidates: Sequence[Candidate]) -> str:
    return "\\n".join(candidate.verdict() for candidate in candidates)
"""
_RETIRED_HELPER = """

def retired_helper() -> str:
    return "obsolete"
"""
_MAIN_GUARD = """

if __name__ == "__main__":
    print(render([Candidate("a")]))
"""
_CAPABILITY = """from __future__ import annotations

from typing import NamedTuple


class Capability(NamedTuple):
    verdict: str


def is_supported(capability: Capability) -> bool:
    return capability.verdict == "yes"


if __name__ == "__main__":
    print(is_supported(Capability("yes")))
"""


def _project(tmp_path, placement):
    ancestor = {
        "ordinary": "workspace",
        "build": "build",
        "venv": "venv",
        "claude_configured": ".claude",
        "claude_unconfigured": ".claude",
    }[placement]
    root = tmp_path / ancestor / "project"
    root.mkdir(parents=True)
    config = '[tool.skylos]\nexclude = [".claude"]\n'
    if placement != "claude_configured":
        config = "[tool.skylos]\n"
    (root / "pyproject.toml").write_text(config, encoding="utf-8")
    return root


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize(
    "include_neighbor", [False, True], ids=["no_neighbor", "unused_neighbor"]
)
@pytest.mark.parametrize("collision", [False, True], ids=["no_collision", "collision"])
@pytest.mark.parametrize(
    "placement",
    ["ordinary", "build", "venv", "claude_configured", "claude_unconfigured"],
)
def test_generator_method_call_is_independent_of_scan_root_ancestors(
    tmp_path, placement, collision, include_neighbor, confidence
):
    root = _project(tmp_path, placement)
    source = _PRECHECK + (_RETIRED_HELPER if include_neighbor else "") + _MAIN_GUARD
    (root / "precheck.py").write_text(source, encoding="utf-8")
    if collision:
        (root / "capability.py").write_text(_CAPABILITY, encoding="utf-8")

    exclusions = sorted(
        parse_exclude_folders(
            config_exclude_folders=[".claude"]
            if placement == "claude_configured"
            else None
        )
    )
    result = json.loads(
        analyze(
            str(root),
            conf=confidence,
            exclude_folders=exclusions,
            grep_verify=True,
            grep_cache=False,
        )
    )
    unused = {item["full_name"] for item in result["unused_functions"]}

    assert "precheck.Candidate.verdict" not in unused
    assert "precheck.render" not in unused
    if include_neighbor:
        assert "precheck.retired_helper" in unused
    assert not result.get("analysis_errors")


_BACKEND_MODES = [
    pytest.param("rg", "direct", id="rg_direct"),
    pytest.param("rg", "batch", id="rg_batch"),
    pytest.param("grep", "direct", id="grep_direct"),
    pytest.param("grep", "batch", id="grep_batch"),
    pytest.param("python", "direct", id="python_direct"),
    pytest.param("python", "batch", id="python_batch"),
]


@pytest.mark.parametrize("backend,mode", _BACKEND_MODES)
@pytest.mark.parametrize(
    "placement",
    [
        "ordinary",
        "build_ancestor",
        "venv_ancestor",
        "venv_root",
        "claude_ancestor",
        "nested_claude_ancestor",
    ],
)
def test_search_backends_keep_included_evidence_and_reject_excluded_descendants(
    tmp_path, monkeypatch, backend, mode, placement
):
    if backend in {"rg", "grep"} and _REAL_WHICH(backend) is None:
        pytest.skip(f"needs the {backend} executable")
    if backend == "python" and not grep_common._python_grep_secure_reads_available():
        pytest.skip("needs secure in-process grep reads")

    root = {
        "ordinary": tmp_path / "workspace" / "project",
        "build_ancestor": tmp_path / "build" / "project",
        "venv_ancestor": tmp_path / "venv" / "project",
        "venv_root": tmp_path / "venv",
        "claude_ancestor": tmp_path / ".claude" / "project",
        "nested_claude_ancestor": tmp_path / ".claude" / "worktrees" / "project",
    }[placement]
    root.mkdir(parents=True)
    configured_exclusion = {
        "build_ancestor": "build",
        "claude_ancestor": ".claude",
        "nested_claude_ancestor": ".claude/worktrees",
    }.get(placement)
    directories = ["included", "excluded", "venv"]
    if configured_exclusion:
        directories.append(configured_exclusion)
    for directory in directories:
        (root / directory).mkdir(parents=True)
        (root / directory / "reference.py").write_text(
            "candidate.verdict()\n", encoding="utf-8"
        )

    def which(executable, *args, **kwargs):
        if executable == "rg" and backend != "rg":
            return None
        return _REAL_WHICH(executable, *args, **kwargs)

    monkeypatch.setattr(grep_common.shutil, "which", which)
    if backend == "grep":
        monkeypatch.setattr(
            grep_common, "_python_grep_secure_reads_available", lambda: False
        )

    request = _make_grep_request(
        "candidate.verdict()",
        str(root),
        use_regex=False,
        include_globs=["*.py"],
        fixed_string=True,
        max_results=20,
    )
    exclusions = ["excluded", "venv"]
    if configured_exclusion:
        exclusions.append(configured_exclusion)
    with grep_verification_scope(root, exclusions):
        if backend == "python":
            with patch.object(
                grep_common,
                "_run_grep_request",
                side_effect=AssertionError("in-process request spawned grep"),
            ):
                run = _run_python_grep_batch if mode == "direct" else execute_grep_batch
                results = run([request])
                assert request in results
                lines = results[request]
        elif mode == "direct":
            lines = _run_grep_request(request, require_complete=True)
        else:
            results = execute_grep_batch([request])
            assert request in results
            lines = results[request]

    paths = {
        Path(grep_common._split_grep_evidence(line)[0]).relative_to(root).as_posix()
        for line in lines
    }
    assert paths == {"included/reference.py"}


@pytest.mark.parametrize("backend,mode", _BACKEND_MODES)
@pytest.mark.parametrize(
    "root_style",
    ["egg_info_ancestor", "egg_info_root", "relative_directory", "explicit_file"],
)
def test_backend_evidence_with_glob_ancestors_and_root_forms(
    tmp_path, monkeypatch, backend, mode, root_style
):
    if backend in {"rg", "grep"} and _REAL_WHICH(backend) is None:
        pytest.skip(f"needs the {backend} executable")
    if backend == "python" and not grep_common._python_grep_secure_reads_available():
        pytest.skip("needs secure in-process grep reads")

    root = {
        "egg_info_ancestor": tmp_path / "sample.egg-info" / "project",
        "egg_info_root": tmp_path / "sample.egg-info",
        "relative_directory": tmp_path / "venv" / "project",
        "explicit_file": tmp_path / "venv" / "project",
    }[root_style]
    root.mkdir(parents=True)
    if root_style == "explicit_file":
        included = root / "reference.py"
        (root / "sibling.py").write_text("candidate.verdict()\n", encoding="utf-8")
    else:
        included = root / "included" / "reference.py"
        included.parent.mkdir()
    included.write_text("candidate.verdict()\n", encoding="utf-8")
    for directory in ("excluded", "venv", "sample.egg-info"):
        (root / directory).mkdir()
        (root / directory / "reference.py").write_text(
            "candidate.verdict()\n", encoding="utf-8"
        )

    target = included if root_style == "explicit_file" else root
    if root_style == "relative_directory":
        monkeypatch.chdir(tmp_path)
        target = Path("venv") / "project"

    def which(executable, *args, **kwargs):
        if executable == "rg" and backend != "rg":
            return None
        return _REAL_WHICH(executable, *args, **kwargs)

    monkeypatch.setattr(grep_common.shutil, "which", which)
    if backend == "grep":
        monkeypatch.setattr(
            grep_common, "_python_grep_secure_reads_available", lambda: False
        )

    request = _make_grep_request(
        "candidate.verdict()",
        str(target),
        use_regex=False,
        include_globs=["*.py"],
        fixed_string=True,
        max_results=20,
    )
    with grep_verification_scope(target, ["excluded", "venv", "sample.egg-info"]):
        if backend == "python":
            with patch.object(
                grep_common,
                "_run_grep_request",
                side_effect=AssertionError("in-process request spawned grep"),
            ):
                run = _run_python_grep_batch if mode == "direct" else execute_grep_batch
                results = run([request])
                assert request in results
                lines = results[request]
        elif mode == "direct":
            lines = _run_grep_request(request, require_complete=True)
        else:
            results = execute_grep_batch([request])
            assert request in results
            lines = results[request]

    paths = {Path(grep_common._split_grep_evidence(line)[0]) for line in lines}
    assert paths == {included}


def test_grep_fallback_requests_filename_for_an_explicit_file(tmp_path):
    target = tmp_path / "reference.py"
    target.write_text("candidate.verdict()\n", encoding="utf-8")
    request = _make_grep_request(
        "candidate.verdict()",
        str(target),
        use_regex=False,
        include_globs=["*.py"],
        fixed_string=True,
        max_results=20,
    )

    command = grep_common._grep_fallback_command(request, "grep", str(target))

    # GNU grep otherwise omits the filename required by the NUL evidence parser.
    assert "-H" in command
