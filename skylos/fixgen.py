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
            elif ch == "}":
                depth -= 1
                if found_open and depth == 0:
                    return i
    return min(start_idx + 1, len(lines) - 1)


def _validate_file(file_path: str, content: str) -> list[str]:
    ext = Path(file_path).suffix.lower()

    if ext in (".py", ".pyi"):
        try:
            ast.parse(content, filename=file_path)
        except SyntaxError as e:
            return [f"{file_path}: Python syntax error after removal: {e}"]
        return []

    if ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        if not shutil.which("node"):
            return []
        suffix = ext if ext.startswith(".") else f".{ext}"
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            result = subprocess.run(
                ["node", "--check", tmp_path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
            if result.returncode != 0:
                msg = (result.stderr or result.stdout).strip()
                return [f"{file_path}: JS/TS syntax error after removal: {msg}"]
        except (subprocess.SubprocessError, OSError):
            pass
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return []

    if ext == ".go":
        if not shutil.which("gofmt"):
            return []
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".go",
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            result = subprocess.run(
                ["gofmt", "-e", tmp_path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
            if result.returncode != 0:
                msg = (result.stderr or result.stdout).strip()
                return [f"{file_path}: Go syntax error after removal: {msg}"]
        except (subprocess.SubprocessError, OSError):
            pass
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return []

    if ext == ".rs":
        if not shutil.which("rustfmt"):
            return []
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".rs",
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            result = subprocess.run(
                ["rustfmt", "--check", tmp_path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
            if result.returncode != 0:
                msg = (result.stderr or result.stdout).strip()
                return [f"{file_path}: Rust syntax error after removal: {msg}"]
        except (subprocess.SubprocessError, OSError):
            pass
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return []

    if ext == ".java":
        return _check_brace_balance(file_path, content)

    return []


def _check_brace_balance(file_path: str, content: str) -> list[str]:
    pairs = {"{": "}", "(": ")", "[": "]"}
    closers = set(pairs.values())
    stack: list[str] = []
    for i, ch in enumerate(content):
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in closers:
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
    score = 1.0
    kind = finding.get("type", "")

    if kind == "import":
        score = SAFETY_VERY_HIGH

    elif kind == "function":
        score = 0.9

    elif kind == "variable":
        score = SAFETY_MEDIUM

    elif kind == "class":
        score = SAFETY_LOW

    # Methods are riskiest (may be overrides)
    elif kind == "method":
        score = SAFETY_MINIMAL

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

    name_to_finding = {}
    for f in verified_findings:
        name = f.get("full_name", f.get("name", ""))
        if name:
            name_to_finding[name] = f

    patches: list[RemovalPatch] = []
    file_cache: dict[str, list[str]] = {}

    for name in order:
        finding = name_to_finding.get(name)
        if not finding:
            continue

        safety = _compute_safety_score(finding)
        if safety < min_safety:
            continue

        file_path = finding.get("file", "")
        line = finding.get("line", 0)
        kind = finding.get("type", "")

        if not file_path or not line:
            continue

        abs_path = file_path if Path(file_path).is_absolute() else str(root / file_path)
        if abs_path not in file_cache:
            try:
                file_cache[abs_path] = (
                    Path(abs_path).read_text(encoding="utf-8").splitlines()
                )
            except (OSError, UnicodeDecodeError):
                continue

        lines = file_cache[abs_path]
        start_idx = line - 1

        if start_idx >= len(lines):
            continue

        ext = Path(abs_path).suffix.lower()
        is_brace_lang = ext in _BRACE_LANG_EXTS
        if kind in ("function", "method", "class"):
            if is_brace_lang:
                end_idx = _find_brace_block_end(lines, start_idx)
            else:
                end_idx = _find_block_end(lines, start_idx)
            dec_start = start_idx
            while dec_start > 0 and lines[dec_start - 1].strip().startswith("@"):
                dec_start -= 1
            start_idx = dec_start
        elif kind == "import":
            end_idx = _find_import_range(lines, start_idx)
        elif kind == "variable":
            end_idx = start_idx
            while end_idx < len(lines) - 1 and lines[end_idx].rstrip().endswith("\\"):
                end_idx += 1
        else:
            end_idx = start_idx

        if mode == "comment":
            commented = []
            for i in range(start_idx, end_idx + 1):
                commented.append(f"# DEAD CODE: {lines[i]}")
            replacement = "\n".join(commented)
        else:
            replacement = ""

        patches.append(
            RemovalPatch(
                file_path=abs_path,
                line_range=(start_idx + 1, end_idx + 1),  # back to 1-indexed
                replacement=replacement,
                finding_name=name,
                finding_type=kind,
                depends_on=dag.get(name, []),
                safety_score=safety,
            )
        )

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
