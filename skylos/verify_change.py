from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from skylos.contracts import (
    contract_enables_dependency_hallucinations,
    contract_project_config_overrides,
    discover_contract_path,
    load_contract,
    scan_contract_route_guardrails,
)
from skylos.core.verify_change_schema import (
    build_verify_change_response,
    parse_line_range,
)

__all__ = [
    "build_verify_change_response",
    "parse_line_range",
    "verify_change_diff",
    "verify_change_path",
    "verify_change_stdin_payload",
]


def verify_change_path(
    path: str | Path,
    *,
    file: str | Path | None = None,
    line_range: str | tuple[int, int] | None = None,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
    project_context: bool = False,
    include_dependency_hallucinations: bool = True,
    include_security_findings: bool = True,
    contract_path: str | Path | None = None,
    contract_enabled: bool = True,
    analyze_func=None,
    behavior_comparison: bool = True,
) -> dict[str, Any]:
    target = Path(path).expanduser()
    target_file = _optional_path(file)
    _validate_verify_target(target, target_file)
    scan_target = _scan_target(target, target_file, project_context=project_context)
    root = _root_for_verify_target(target)
    contract_file = _contract_path_for_verify_target(
        target=target,
        scan_target=scan_target,
        root=root,
        contract_path=contract_path,
        contract_enabled=contract_enabled,
    )
    contract = None
    if contract_file is not None:
        contract = load_contract(
            contract_file,
            project_root=_contract_project_root_for_verify(contract_file, root),
        )
    include_deps = (
        include_dependency_hallucinations
        or contract_enables_dependency_hallucinations(contract)
    )
    changed_files = _changed_files_for_verify(
        target,
        scan_target,
        target_file,
    )

    analyzer_owned = analyze_func is None
    if analyzer_owned:
        from skylos.analyzer import analyze as analyze_func

    analysis_options = _analysis_options(
        confidence=confidence,
        exclude_folders=exclude_folders,
        include_dependency_hallucinations=include_deps,
        include_security_findings=include_security_findings,
        changed_files=changed_files,
        project_config_overrides=contract_project_config_overrides(contract),
    )
    raw_result = analyze_func(str(scan_target), **analysis_options)
    analysis_result = _analysis_result_dict(raw_result)
    _absolutize_secret_paths(analysis_result, scan_target)
    _add_contract_route_findings(
        analysis_result,
        contract=contract,
        root=root,
        changed_files=changed_files,
    )

    response = build_verify_change_response(
        analysis_result,
        project_root=root,
        target_file=target_file,
        line_range=line_range,
        scan_target=scan_target,
        contract=contract,
        include_security_findings=include_security_findings,
        analyzer_owned=analyzer_owned,
    )
    _rebase_display_paths(response, root)
    if not behavior_comparison:
        # Callers that only act on ``fail`` (agent hooks) skip the Git
        # behavior model: it can only downgrade ``pass`` to ``incomplete``.
        return response
    from skylos.verification.changes import compare_working_changes

    behavior = compare_working_changes(
        path, file=file, line_range=line_range, exclude_folders=exclude_folders
    )
    response["behavior"] = behavior
    if behavior["status"] in {"different", "unknown"}:
        if response["status"] == "pass":
            response["status"] = "incomplete"
        response["summary"] += (
            "; behavior comparison needs review: modeled changes detected"
            if behavior["status"] == "different"
            else "; behavior comparison incomplete"
        )
    return response


def _rebase_display_paths(response: dict[str, Any], root: Path) -> None:
    """Report ``range.file`` relative to the Git root, not the target's folder.

    A single-file target uses its parent directory as the analysis root, so
    without this every finding would name only the file's basename.
    """
    display_root = _git_root(root)
    if display_root is None or display_root == root:
        return

    def rebase(value: Any) -> Any:
        if not isinstance(value, str) or not value or value == "unknown":
            return value
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            return candidate.resolve().relative_to(display_root).as_posix()
        except (OSError, ValueError):
            return value

    for finding in _result_findings(response):
        rng = finding.get("range")
        if isinstance(rng, dict):
            rng["file"] = rebase(rng.get("file"))
    target = response.get("target")
    if isinstance(target, dict) and target.get("file"):
        target["file"] = rebase(target["file"])


def _git_root(start: Path) -> Path | None:
    try:
        resolved = start.resolve()
    except OSError:
        return None
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").exists():
            return parent
    return None


# --------------------------------------------------------------------------
# verify --diff REF: every line changed since REF (committed, staged,
# unstaged) plus untracked files.
# --------------------------------------------------------------------------

MAX_DIFF_FILES = 200
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9_./@{}~^:+-]{1,200}$")


def verify_change_diff(
    path: str | Path = ".",
    *,
    ref: str = "HEAD",
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
    include_dependency_hallucinations: bool = True,
    include_security_findings: bool = True,
    contract_path: str | Path | None = None,
    contract_enabled: bool = True,
    analyze_func=None,
    git_runner=None,
) -> dict[str, Any]:
    """Verify the lines changed since ``ref`` (default ``HEAD``).

    Covers commits after ``ref``, staged and unstaged edits, and untracked
    files. Findings outside the changed lines are dropped. The behavior model
    is not run: it only compares against ``HEAD``.
    """
    run = git_runner or _run_git
    target = Path(path).expanduser()
    base = target if target.is_dir() else target.parent
    if not ref or ref.startswith("-") or not _SAFE_REF_RE.match(ref):
        raise ValueError(f"invalid --diff ref: {ref!r}")
    top = run(base, ["rev-parse", "--show-toplevel"])
    if top is None:
        raise ValueError(f"--diff needs a Git repository: {base.absolute()}")
    root = Path(top.strip()).resolve()
    if run(root, ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"]) is None:
        raise ValueError(f"--diff ref not found: {ref}")
    diff = run(
        root,
        ["diff", "--no-color", "--no-ext-diff", "-U0", "--diff-filter=AMRC", ref, "--"],
    )
    untracked = run(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    if diff is None or untracked is None:
        raise ValueError("git diff failed")
    changed = parse_added_lines(diff)
    for rel in untracked.split("\0"):
        if rel:
            changed[rel] = None
    scope = target.resolve()
    selected = {
        rel: ranges
        for rel, ranges in sorted(changed.items())
        if _within(root / rel, scope) and (root / rel).is_file()
    }

    findings: list[dict[str, Any]] = []
    incomplete: list[str] = []
    skipped = max(0, len(selected) - MAX_DIFF_FILES)
    with _facts_session(root, enabled=analyze_func is None):
        for rel, ranges in list(selected.items())[:MAX_DIFF_FILES]:
            if ranges == []:
                continue  # only deletions
            _verify_diff_file(
                root,
                rel,
                ranges,
                findings,
                incomplete,
                confidence=confidence,
                exclude_folders=exclude_folders,
                include_dependency_hallucinations=include_dependency_hallucinations,
                include_security_findings=include_security_findings,
                contract_path=contract_path,
                contract_enabled=contract_enabled,
                analyze_func=analyze_func,
            )

    if findings:
        status = "fail"
    elif incomplete or skipped:
        status = "incomplete"
    else:
        status = "pass"
    summary = (
        f"{len(findings)} issue(s) on lines changed since {ref}"
        if findings
        else f"No issues on lines changed since {ref}"
    )
    if incomplete:
        summary += f"; verification incomplete for {len(incomplete)} file(s)"
    if skipped:
        summary += f"; {skipped} changed file(s) not checked (limit {MAX_DIFF_FILES})"
    return {
        "schema_version": 2,
        "tool": "verify_change",
        "status": status,
        "target": {
            "path": str(root),
            "file": None,
            "range": None,
            "diff": {"ref": ref, "files": list(selected)},
        },
        "findings": findings,
        "summary": summary,
        "security_checks_enabled": bool(include_security_findings),
    }


def _verify_diff_file(root, rel, ranges, findings, incomplete, **kwargs) -> None:
    result = verify_change_path(root / rel, behavior_comparison=False, **kwargs)
    if result.get("status") == "incomplete":
        incomplete.append(rel)
    for finding in _result_findings(result):
        rng = finding.get("range") or {}
        if not _range_overlaps(rng, ranges):
            continue
        rng["file"] = rel
        findings.append(finding)


def _facts_session(root: Path, *, enabled: bool):
    """Reuse the project module-facts cache across the per-file checks."""
    import contextlib

    if not enabled:
        return contextlib.nullcontext()
    try:
        from skylos.rules.ai_defect.module_facts_index import (
            module_facts_index_session,
        )
    except ImportError:
        return contextlib.nullcontext()
    return module_facts_index_session(root)


def parse_added_lines(diff: str) -> dict[str, list[tuple[int, int]] | None]:
    """Map each file in a ``git diff -U0`` to the line ranges it adds."""
    changed: dict[str, list[tuple[int, int]] | None] = {}
    current: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            if name == "/dev/null":
                current = None
                continue
            if name.startswith('"'):
                try:
                    name = json.loads(name)
                except ValueError:
                    current = None
                    continue
            current = name[2:] if name.startswith("b/") else name
            changed.setdefault(current, [])
            continue
        if current is None:
            continue
        match = _HUNK_RE.match(line)
        if match:
            start = int(match.group(1))
            count = int(match.group(2)) if match.group(2) is not None else 1
            if count > 0:
                ranges = changed[current]
                assert ranges is not None
                ranges.append((start, start + count - 1))
    return changed


def _range_overlaps(rng: dict[str, Any], ranges: list[tuple[int, int]] | None) -> bool:
    if ranges is None:
        return True
    try:
        start = int(rng.get("start_line") or 1)
        end = int(rng.get("end_line") or start)
    except (TypeError, ValueError):
        return False
    return any(not (end < lo or start > hi) for lo, hi in ranges)


def _within(path: Path, scope: Path) -> bool:
    try:
        path.resolve().relative_to(scope)
    except (OSError, ValueError):
        return False
    return True


def _run_git(cwd: Path, args: list[str]) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.quotepath=false", *args],
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def verify_change_stdin_payload(
    payload: dict[str, Any],
    *,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
    analyze_func=None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("stdin manifest must be a JSON object")

    code = payload.get("code")
    if not isinstance(code, str):
        raise ValueError("stdin manifest must include a string 'code' field")

    manifest_file = _safe_manifest_file(
        _manifest_value(payload, ("file",), "snippet.py")
    )
    line_range = _manifest_value(payload, ("line_range", "range"), None)
    # Stays opt-in for snippets: they are scanned inside a temp root, where
    # project-local imports cannot resolve and would be misreported as
    # hallucinated dependencies.
    include_deps = bool(payload.get("include_dependency_hallucinations", False))
    include_security = _manifest_bool(payload, "include_security_findings", True)
    contract_path = _manifest_value(payload, ("contract_path", "contract"), None)
    contract_enabled = _manifest_contract_enabled(payload)
    contract_path = _manifest_contract_path(
        payload,
        contract_path=contract_path,
        contract_enabled=contract_enabled,
    )

    with tempfile.TemporaryDirectory(prefix="skylos-verify-") as tmp:
        tmp_root = Path(tmp)
        temp_file = _write_manifest_code(tmp_root, manifest_file, code)

        result = verify_change_path(
            temp_file,
            line_range=line_range,
            confidence=confidence,
            exclude_folders=exclude_folders,
            include_dependency_hallucinations=include_deps,
            include_security_findings=include_security,
            contract_path=contract_path,
            contract_enabled=contract_enabled,
            analyze_func=analyze_func,
        )

    result["target"]["path"] = _manifest_target_path(payload)
    result["target"]["file"] = _manifest_file_for_output(manifest_file)
    for finding in _result_findings(result):
        finding["range"]["file"] = _manifest_file_for_output(manifest_file)
    return result


def _analysis_options(
    *,
    confidence: int,
    exclude_folders: list[str] | None,
    include_dependency_hallucinations: bool,
    include_security_findings: bool,
    changed_files: list[str] | None,
    project_config_overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    options = {
        "conf": confidence,
        "exclude_folders": exclude_folders,
        "enable_quality": True,
        "enable_danger": include_security_findings,
        "enable_ai_defects": True,
        "enable_dependency_hallucinations": include_dependency_hallucinations,
        "enable_secrets": include_security_findings,
        "grep_verify": False,
        "trace_file": False,
    }
    if changed_files:
        options["changed_files"] = changed_files
    if project_config_overrides:
        options["project_config_overrides"] = project_config_overrides
    return options


def _contract_path_for_verify_target(
    *,
    target: Path,
    scan_target: Path,
    root: Path,
    contract_path: str | Path | None,
    contract_enabled: bool,
) -> Path | None:
    if not contract_enabled:
        if contract_path is not None:
            raise ValueError("contract_path cannot be used when contracts are disabled")
        return None
    if contract_path is not None:
        return _contract_path_for_verify(contract_path, root)

    discovered = discover_contract_path(scan_target)
    if discovered is not None:
        return discovered
    return discover_contract_path(target)


def _contract_path_for_verify(contract_path: str | Path, root: Path) -> Path:
    raw = Path(contract_path).expanduser()
    if raw.is_absolute():
        return raw

    root_candidate = root / raw
    if root_candidate.exists():
        return root_candidate

    cwd_candidate = Path.cwd() / raw
    if cwd_candidate.exists():
        return cwd_candidate

    return root_candidate


def _contract_project_root_for_verify(
    contract_path: str | Path,
    default_root: Path,
) -> Path:
    try:
        resolved = Path(contract_path).expanduser().resolve(strict=False)
    except OSError:
        return default_root
    if resolved.parent.name == ".skylos":
        return resolved.parent.parent
    try:
        resolved.relative_to(default_root)
    except ValueError:
        return resolved.parent
    return default_root


def _add_contract_route_findings(
    analysis_result: dict[str, Any],
    *,
    contract,
    root: Path,
    changed_files: list[str] | None,
) -> None:
    if contract is None:
        return

    scan_root = _contract_scan_root(contract, root)
    route_findings = scan_contract_route_guardrails(
        contract,
        scan_root,
        files=changed_files,
    )
    if not route_findings:
        return

    existing = analysis_result.get("ai_defects")
    if isinstance(existing, list):
        existing.extend(route_findings)
    else:
        analysis_result["ai_defects"] = route_findings


def _contract_scan_root(contract, default_root: Path) -> Path:
    contract_path = getattr(contract, "path", None)
    if not isinstance(contract_path, Path):
        return default_root
    parent = contract_path.parent
    if parent.name == ".skylos":
        return parent.parent
    return parent


def _changed_files_for_verify(
    target: Path,
    scan_target: Path,
    target_file: Path | None,
) -> list[str] | None:
    # The analyzer resolves relative changed files against its own analysis
    # root, not against the verify target or the caller's cwd, so a relative
    # path can match nothing and silently drop changed-file-scoped findings
    # (security findings in particular). Always hand it an absolute path.
    if target_file is not None:
        selected = _scan_target(target, target_file, project_context=False)
        return [os.path.abspath(selected)]
    if scan_target.is_file():
        return [os.path.abspath(scan_target)]
    return None


def _absolutize_secret_paths(
    analysis_result: dict[str, Any],
    scan_target: Path,
) -> None:
    """Secrets report files relative to the analyzer's discovery root.

    That root is the scanned directory, or the parent of a scanned file, which
    is not necessarily the verify project root used to match findings.
    """
    secrets = analysis_result.get("secrets")
    if not isinstance(secrets, list):
        return
    try:
        resolved = scan_target.resolve()
    except OSError:
        return
    base = resolved if resolved.is_dir() else resolved.parent
    for finding in secrets:
        if not isinstance(finding, dict):
            continue
        file_value = finding.get("file")
        if not isinstance(file_value, str) or not file_value:
            continue
        if Path(file_value).is_absolute():
            continue
        finding["file"] = str(base / file_value)


def _write_manifest_code(root: Path, manifest_file: Path, code: str) -> Path:
    root_resolved = root.resolve()
    temp_file = _contained_manifest_path(root_resolved, manifest_file)
    temp_file.parent.mkdir(parents=True, exist_ok=True)
    _write_new_file_no_follow(temp_file, code)
    return temp_file


def _contained_manifest_path(root: Path, manifest_file: Path) -> Path:
    candidate = (root / manifest_file).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("stdin manifest file must stay inside the temp root") from exc
    return candidate


def _write_new_file_no_follow(path: Path, code: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] contained temp manifest path with no-follow create
            path, flags, 0o600
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(code)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _validate_verify_target(path: Path, target_file: Path | None) -> None:
    # Validate the selected file even when analysis will scan its whole project.
    selected = _scan_target(path, target_file, project_context=False)
    for candidate in (path, selected):
        if not candidate.exists():
            raise ValueError(
                f"Verification target does not exist: {candidate.absolute()}"
            )
        if not (candidate.is_file() or candidate.is_dir()):
            raise ValueError(
                f"Verification target must be a file or directory: {candidate.absolute()}"
            )
    if target_file is not None and not selected.is_file():
        raise ValueError(f"--file must select a file: {selected.absolute()}")


def _scan_target(
    path: Path,
    target_file: Path | None,
    *,
    project_context: bool,
) -> Path:
    if target_file is None:
        return path
    if project_context:
        if path.is_dir():
            return path
    if target_file.is_absolute():
        return target_file
    if path.is_dir():
        return path / target_file
    return target_file


def _safe_manifest_file(value: Any) -> Path:
    raw = str(value).strip()
    if not raw:
        raw = "snippet.py"

    path = Path(raw)
    if path.is_absolute():
        raise ValueError("stdin manifest file must be relative")
    for part in path.parts:
        if part in {"", ".", ".."}:
            raise ValueError("stdin manifest file must not contain traversal segments")
    return path


def _optional_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    return Path(value).expanduser()


def _root_for_verify_target(target: Path) -> Path:
    if target.is_dir():
        return _project_root(target)
    return _project_root(target.parent)


def _project_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_file():
        candidate = candidate.parent
    try:
        return candidate.resolve()
    except OSError:
        return candidate


def _analysis_result_dict(raw_result: Any) -> dict[str, Any]:
    if isinstance(raw_result, str):
        parsed = json.loads(raw_result)
    else:
        parsed = raw_result

    if isinstance(parsed, dict):
        return parsed
    return {}


def _manifest_value(
    payload: dict[str, Any],
    keys: tuple[str, ...],
    default: Any,
) -> Any:
    for key in keys:
        value = payload.get(key)
        if _has_manifest_value(value):
            return value
    return default


def _manifest_contract_enabled(payload: dict[str, Any]) -> bool:
    return _manifest_bool(payload, "contract_enabled", True)


def _manifest_bool(payload: dict[str, Any], key: str, default: bool) -> bool:
    value = payload.get(key, default)
    if isinstance(value, bool):
        return value
    raise ValueError(f"stdin manifest {key} must be true or false")


def _manifest_contract_path(
    payload: dict[str, Any],
    *,
    contract_path: Any,
    contract_enabled: bool,
) -> Any:
    if not contract_enabled or _has_manifest_value(contract_path):
        return contract_path

    discovered = discover_contract_path(_manifest_contract_discovery_start(payload))
    if discovered is None:
        return contract_path
    return discovered


def _manifest_contract_discovery_start(payload: dict[str, Any]) -> Path:
    target = Path(_manifest_target_path(payload)).expanduser()
    if target.is_absolute():
        return target
    return Path.cwd() / target


def _has_manifest_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        if value.strip() == "":
            return False
    return True


def _manifest_target_path(payload: dict[str, Any]) -> str:
    value = _manifest_value(payload, ("path",), ".")
    return str(value)


def _manifest_file_for_output(manifest_file: Path) -> str:
    return str(manifest_file).replace("\\", "/")


def _result_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings = result.get("findings")
    if isinstance(findings, list):
        return findings
    return []
