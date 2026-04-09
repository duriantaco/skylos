from __future__ import annotations

import ast
import difflib
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skylos.constants import (
    SAFETY_BUMP,
    SAFETY_LOW,
    SAFETY_MEDIUM,
    SAFETY_MINIMAL,
    SAFETY_VERY_HIGH,
    SUBPROCESS_TIMEOUT,
)

logger = logging.getLogger(__name__)
TEXT_ENCODING = "utf-8"
PYTHON_EXTS = {".py", ".pyi"}
JS_TS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
BRACE_PAIRS = {"{": "}", "(": ")", "[": "]"}
BRACE_CLOSERS = set(BRACE_PAIRS.values())
BASE_SAFETY_SCORES = {
    "import": SAFETY_VERY_HIGH,
    "function": 0.9,
    "variable": SAFETY_MEDIUM,
    "class": SAFETY_LOW,
    "method": SAFETY_MINIMAL,
}

_BRACE_LANG_EXTS = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
}


def _find_brace_block_end(lines: list[str], start_idx: int) -> int:
    """Find the end of a brace-delimited block (TS/Go/Java/Rust).

    Scans from *start_idx* forward, tracking ``{`` / ``}`` nesting.
    Returns the 0-indexed line of the closing ``}``.
    """
    if start_idx >= len(lines):
        return start_idx

    depth = 0
    found_open = False
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                found_open = True
                continue
            if ch != "}":
                continue
            depth -= 1
            if found_open and depth == 0:
                return i
    return min(start_idx + 1, len(lines) - 1)


def _validate_python_syntax(file_path: str, content: str) -> list[str]:
    try:
        ast.parse(content, filename=file_path)
    except SyntaxError as e:
        return [f"{file_path}: Python syntax error after removal: {e}"]
    return []


def _validate_with_tempfile(
    file_path: str,
    content: str,
    *,
    tool: str,
    suffix: str,
    command: list[str],
    label: str,
) -> list[str]:
    if not shutil.which(tool):
        return []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding=TEXT_ENCODING,
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        result = subprocess.run(
            command + [tmp_path],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        if result.returncode != 0:
            msg = (result.stderr or result.stdout).strip()
            return [f"{file_path}: {label} syntax error after removal: {msg}"]
    except (subprocess.SubprocessError, OSError):
        pass
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return []


def _validate_js_ts_syntax(file_path: str, content: str, ext: str) -> list[str]:
    suffix = ext if ext.startswith(".") else f".{ext}"
    return _validate_with_tempfile(
        file_path,
        content,
        tool="node",
        suffix=suffix,
        command=["node", "--check"],
        label="JS/TS",
    )


def _validate_go_syntax(file_path: str, content: str) -> list[str]:
    return _validate_with_tempfile(
        file_path,
        content,
        tool="gofmt",
        suffix=".go",
        command=["gofmt", "-e"],
        label="Go",
    )


def _validate_rust_syntax(file_path: str, content: str) -> list[str]:
    return _validate_with_tempfile(
        file_path,
        content,
        tool="rustfmt",
        suffix=".rs",
        command=["rustfmt", "--check"],
        label="Rust",
    )


def _validate_file(file_path: str, content: str) -> list[str]:
    ext = Path(file_path).suffix.lower()

    if ext in PYTHON_EXTS:
        return _validate_python_syntax(file_path, content)
    if ext in JS_TS_EXTS:
        return _validate_js_ts_syntax(file_path, content, ext)
    if ext == ".go":
        return _validate_go_syntax(file_path, content)
    if ext == ".rs":
        return _validate_rust_syntax(file_path, content)
    if ext == ".java":
        return _check_brace_balance(file_path, content)
    return []


def _check_brace_balance(file_path: str, content: str) -> list[str]:
    stack: list[str] = []
    for ch in content:
        if ch in BRACE_PAIRS:
            stack.append(BRACE_PAIRS[ch])
            continue
        if ch not in BRACE_CLOSERS:
            continue
        if not stack or stack[-1] != ch:
            return [f"{file_path}: Unbalanced '{ch}' after removal"]
        stack.pop()
    if stack:
        return [f"{file_path}: Unclosed delimiter(s) after removal: {''.join(stack)}"]
    return []


@dataclass
class RemovalPatch:
    file_path: str
    line_range: tuple[int, int]
    replacement: str
    finding_name: str
    finding_type: str
    depends_on: list[str] = field(default_factory=list)
    safety_score: float = 1.0  # 0-1, higher = safer

    @property
    def line_count(self) -> int:
        return self.line_range[1] - self.line_range[0] + 1


def _build_dependency_dag(
    findings: list[dict],
    defs_map: dict[str, Any],
) -> dict[str, list[str]]:
    finding_names = {f.get("full_name", f.get("name", "")) for f in findings}
    dag: dict[str, list[str]] = {}

    for finding in findings:
        name = finding.get("full_name", finding.get("name", ""))
        if not name:
            continue
        deps = []
        info = defs_map.get(name, {})
        if isinstance(info, dict):
            for callee in info.get("calls", []):
                if callee in finding_names and callee != name:
                    deps.append(callee)
        dag[name] = deps

    return dag


def _topological_sort(dag: dict[str, list[str]]) -> list[str]:
    in_degree: dict[str, int] = {node: 0 for node in dag}
    for node, deps in dag.items():
        for dep in deps:
            if dep in in_degree:
                in_degree[dep] = in_degree.get(dep, 0) + 1

    queue = [node for node, deg in in_degree.items() if deg == 0]
    result = []
    while queue:
        node = queue.pop(0)
        result.append(node)
        for dep_node, deps in dag.items():
            if node in deps:
                in_degree[dep_node] -= 1
                if in_degree[dep_node] == 0:
                    queue.append(dep_node)

    for node in dag:
        if node not in result:
            result.append(node)

    return result


def _compute_safety_score(finding: dict) -> float:
    """
    Compute a safety score (0-1) for a finding based on type, confidence, and LLM verdict.
    Higher score means safer to remove.
    """
    kind = finding.get("type", "")
    score = BASE_SAFETY_SCORES.get(kind, 1.0)

    # LLM-verified findings are safer
    if finding.get("_llm_verdict") == "TRUE_POSITIVE":
        score = min(score + SAFETY_BUMP, 1.0)

    conf = finding.get("confidence", 60)
    if isinstance(conf, (int, float)) and conf >= 90:
        score = min(score + SAFETY_BUMP, 1.0)

    return round(score, 2)


def _find_block_end(lines: list[str], start_idx: int) -> int:
    if start_idx >= len(lines):
        return start_idx

    first_line = lines[start_idx]
    base_indent = len(first_line) - len(first_line.lstrip())

    end_idx = start_idx
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            end_idx = i
            continue

        current_indent = len(line) - len(line.lstrip())
        if current_indent <= base_indent:
            break
        end_idx = i

    return end_idx


def _find_import_range(lines: list[str], start_idx: int) -> int:
    if start_idx >= len(lines):
        return start_idx

    line = lines[start_idx]
    if "(" in line and ")" not in line:
        for i in range(start_idx + 1, len(lines)):
            if ")" in lines[i]:
                return i
    end = start_idx
    while end < len(lines) - 1 and lines[end].rstrip().endswith("\\"):
        end += 1
    return end


def _build_name_to_finding(verified_findings: list[dict]) -> dict[str, dict]:
    name_to_finding: dict[str, dict] = {}
    for finding in verified_findings:
        name = finding.get("full_name", finding.get("name", ""))
        if name:
            name_to_finding[name] = finding
    return name_to_finding


def _resolve_abs_path(file_path: str, root: Path) -> str:
    if Path(file_path).is_absolute():
        return file_path
    return str(root / file_path)


def _load_file_lines(
    file_cache: dict[str, list[str]], abs_path: str
) -> list[str] | None:
    if abs_path in file_cache:
        return file_cache[abs_path]
    try:
        file_cache[abs_path] = (
            Path(abs_path).read_text(encoding=TEXT_ENCODING).splitlines()
        )
    except (OSError, UnicodeDecodeError):
        return None
    return file_cache[abs_path]


def _find_decorator_start(lines: list[str], start_idx: int) -> int:
    dec_start = start_idx
    while dec_start > 0 and lines[dec_start - 1].strip().startswith("@"):
        dec_start -= 1
    return dec_start


def _resolve_patch_range(
    lines: list[str],
    abs_path: str,
    kind: str,
    line: int,
) -> tuple[int, int] | None:
    start_idx = line - 1
    if start_idx >= len(lines):
        return None

    ext = Path(abs_path).suffix.lower()
    if kind in ("function", "method", "class"):
        if ext in _BRACE_LANG_EXTS:
            end_idx = _find_brace_block_end(lines, start_idx)
        else:
            end_idx = _find_block_end(lines, start_idx)
        return _find_decorator_start(lines, start_idx), end_idx

    if kind == "import":
        return start_idx, _find_import_range(lines, start_idx)

    if kind == "variable":
        end_idx = start_idx
        while end_idx < len(lines) - 1 and lines[end_idx].rstrip().endswith("\\"):
            end_idx += 1
        return start_idx, end_idx

    return start_idx, start_idx


def _build_replacement(
    lines: list[str],
    start_idx: int,
    end_idx: int,
    mode: str,
) -> str:
    if mode != "comment":
        return ""
    commented = []
    for idx in range(start_idx, end_idx + 1):
        commented.append(f"# DEAD CODE: {lines[idx]}")
    return "\n".join(commented)


def _build_patch_for_finding(
    finding: dict,
    *,
    root: Path,
    file_cache: dict[str, list[str]],
    dag: dict[str, list[str]],
    mode: str,
    min_safety: float,
) -> RemovalPatch | None:
    safety = _compute_safety_score(finding)
    if safety < min_safety:
        return None

    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    kind = finding.get("type", "")
    if not file_path or not line:
        return None

    abs_path = _resolve_abs_path(file_path, root)
    lines = _load_file_lines(file_cache, abs_path)
    if lines is None:
        return None

    patch_range = _resolve_patch_range(lines, abs_path, kind, line)
    if patch_range is None:
        return None
    start_idx, end_idx = patch_range

    name = finding.get("full_name", finding.get("name", ""))
    return RemovalPatch(
        file_path=abs_path,
        line_range=(start_idx + 1, end_idx + 1),
        replacement=_build_replacement(lines, start_idx, end_idx, mode),
        finding_name=name,
        finding_type=kind,
        depends_on=dag.get(name, []),
        safety_score=safety,
    )


def generate_removal_plan(
    verified_findings: list[dict],
    defs_map: dict[str, Any],
    project_root: str | Path,
    *,
    mode: str = "delete",
    min_safety: float = 0.0,
) -> list[RemovalPatch]:
    root = Path(project_root)
    dag = _build_dependency_dag(verified_findings, defs_map)
    order = _topological_sort(dag)
    name_to_finding = _build_name_to_finding(verified_findings)
    patches: list[RemovalPatch] = []
    file_cache: dict[str, list[str]] = {}

    for name in order:
        finding = name_to_finding.get(name)
        if not finding:
            continue
        patch = _build_patch_for_finding(
            finding,
            root=root,
            file_cache=file_cache,
            dag=dag,
            mode=mode,
            min_safety=min_safety,
        )
        if patch is not None:
            patches.append(patch)

    patches.sort(key=lambda p: (p.file_path, -p.line_range[0]))

    return patches


def generate_unified_diff(
    patches: list[RemovalPatch],
    project_root: str | Path,
) -> str:
    root = Path(project_root).resolve()
    diffs: list[str] = []
    file_cache: dict[str, list[str]] = {}

    patches_by_file: dict[str, list[RemovalPatch]] = {}
    for patch in patches:
        patches_by_file.setdefault(patch.file_path, []).append(patch)

    for file_path, file_patches in sorted(patches_by_file.items()):
        try:
            original_lines = (
                Path(file_path).read_text(encoding="utf-8").splitlines(keepends=True)
            )
        except (OSError, UnicodeDecodeError):
            continue

        modified_lines = list(original_lines)
        for patch in sorted(file_patches, key=lambda p: -p.line_range[0]):
            start = patch.line_range[0] - 1
            end = patch.line_range[1]
            if patch.replacement:
                replacement_lines = [
                    line + "\n" for line in patch.replacement.splitlines()
                ]
                modified_lines[start:end] = replacement_lines
            else:
                modified_lines[start:end] = []

        try:
            rel_path = str(Path(file_path).resolve().relative_to(root))
        except ValueError:
            rel_path = file_path

        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
            lineterm="",
        )
        diff_text = "\n".join(diff)
        if diff_text:
            diffs.append(diff_text)

    return "\n".join(diffs)


def apply_patches(
    patches: list[RemovalPatch],
    project_root: str | Path,
    *,
    dry_run: bool = True,
    backup: bool = True,
) -> dict[str, str]:
    results: dict[str, str] = {}

    patches_by_file: dict[str, list[RemovalPatch]] = {}
    for patch in patches:
        patches_by_file.setdefault(patch.file_path, []).append(patch)

    for file_path, file_patches in patches_by_file.items():
        try:
            content = Path(file_path).read_text(encoding="utf-8")
            lines = content.splitlines(keepends=True)
        except (OSError, UnicodeDecodeError) as e:
            logger.warning("Cannot read %s: %s", file_path, e)
            continue

        for patch in sorted(file_patches, key=lambda p: -p.line_range[0]):
            start = patch.line_range[0] - 1
            end = patch.line_range[1]
            if patch.replacement:
                replacement_lines = [
                    line + "\n" for line in patch.replacement.splitlines()
                ]
                lines[start:end] = replacement_lines
            else:
                lines[start:end] = []

        new_content = "".join(lines)
        results[file_path] = new_content

        if not dry_run:
            if backup:
                shutil.copy2(file_path, file_path + ".bak")
            Path(file_path).write_text(new_content, encoding="utf-8")
            logger.info("Applied %d patches to %s", len(file_patches), file_path)

    return results


def validate_patches(
    patches: list[RemovalPatch],
    project_root: str | Path,
) -> list[str]:
    errors: list[str] = []

    applied = apply_patches(patches, project_root, dry_run=True, backup=False)

    for file_path, new_content in applied.items():
        errors.extend(_validate_file(file_path, new_content))

    return errors


def generate_fix_summary(patches: list[RemovalPatch]) -> dict[str, Any]:
    files_affected = len({p.file_path for p in patches})
    total_lines = sum(p.line_count for p in patches)
    by_type: dict[str, int] = {}
    for p in patches:
        by_type[p.finding_type] = by_type.get(p.finding_type, 0) + 1

    return {
        "total_patches": len(patches),
        "files_affected": files_affected,
        "total_lines_removed": total_lines,
        "by_type": by_type,
        "avg_safety_score": (
            round(sum(p.safety_score for p in patches) / len(patches), 2)
            if patches
            else 0.0
        ),
    }
