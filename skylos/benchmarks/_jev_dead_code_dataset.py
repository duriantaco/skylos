from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from skylos.benchmarks._jev_dead_code_golden import (
    GOLDEN_SCHEMA,
    golden_manifest_metadata,
    normalize_golden_cases,
)
from skylos.benchmarks._jev_dead_code_types import (
    JevBatch,
    JevBenchmarkError,
    JevQuestion,
)
from skylos.benchmarks.dead_code import validate_manifest
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    read_text_no_symlink,
)


JEV_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-1.13.0"
PROMPT_VERSION = "skylos-dead-code-jev-v1"
MAX_FILE_BYTES = 64_000
MAX_STATE_BYTES = 64_000
MAX_MANIFEST_BYTES = 2_000_000
CHOICES = ("retained", "unreferenced", "insufficient_evidence")
SOURCE_SUFFIXES = {
    ".cs",
    ".dart",
    ".fxml",
    ".go",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".pyi",
    ".rs",
    ".toml",
    ".ts",
    ".tsx",
    ".xml",
    ".yaml",
    ".yml",
}
SOURCE_NAMES = {"go.mod", "package.json", "pyproject.toml"}
LABEL_SIGNAL_WORDS = (
    "unused",
    "used",
    "dead",
    "stale",
    "dormant",
    "sample",
    "debug",
    "dangerous",
    "archived",
    "lab",
)


def _manifest_text(path: str | Path) -> str:
    text = read_text_no_symlink(path, max_bytes=MAX_MANIFEST_BYTES)
    if text is None:
        raise JevBenchmarkError("cannot safely read the benchmark manifest")
    return text


def _load_manifest(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(_manifest_text(path))
    except json.JSONDecodeError as exc:
        raise JevBenchmarkError("benchmark manifest is not valid JSON") from exc
    if not isinstance(value, dict):
        raise JevBenchmarkError("benchmark manifest must be a JSON object")
    return value


def manifest_digest(path: str | Path) -> str:
    return hashlib.sha256(_manifest_text(path).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def prompt_digest() -> str:
    return _digest(
        {
            "version": PROMPT_VERSION,
            "choices": CHOICES,
            "question": _question_payload("function", "example.py", "candidate_001"),
        }
    )


def manifest_metadata(path: str | Path) -> dict[str, Any]:
    manifest = _load_manifest(path)
    if manifest.get("schema_version") == GOLDEN_SCHEMA:
        return golden_manifest_metadata(manifest)
    return {
        "format": "skylos-dead-code-manifest/v1",
        "split": None,
        "label_state": "local_regression",
    }


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _manifest_cases(
    manifest: dict[str, Any], manifest_path: str | Path
) -> list[dict[str, Any]]:
    if manifest.get("schema_version") == GOLDEN_SCHEMA:
        return normalize_golden_cases(manifest, manifest_path)
    source_root = Path(manifest_path).expanduser().resolve().parent
    cases = validate_manifest(manifest, manifest_path)
    return [{**case, "_source_root": str(source_root)} for case in cases]


def _select_cases(
    manifest_path: str | Path,
    selected_cases: set[str] | None,
) -> list[dict[str, Any]]:
    manifest = _load_manifest(manifest_path)
    cases = _manifest_cases(manifest, manifest_path)
    selected = set(selected_cases or ())
    if not selected:
        return cases
    known = {case["id"] for case in cases}
    unknown = sorted(selected - known)
    if unknown:
        raise JevBenchmarkError(f"unknown dead-code benchmark case: {unknown[0]}")
    return [case for case in cases if case["id"] in selected]


def _safe_case_path(case: dict[str, Any]) -> Path:
    manifest_root = Path(case["_source_root"]).resolve()
    raw_path = Path(str(case["path"]))
    if raw_path.is_absolute():
        raise JevBenchmarkError(f"case {case['id']} path must be relative")
    case_path = (manifest_root / raw_path).resolve()
    if not _is_relative_to(case_path, manifest_root):
        raise JevBenchmarkError(f"case {case['id']} path escapes the manifest root")
    return case_path


def _source_candidates(case_path: Path) -> list[Path]:
    candidates = [case_path] if case_path.is_file() else list(case_path.rglob("*"))
    return sorted(
        (
            path
            for path in candidates
            if path.is_file()
            and (path.suffix.lower() in SOURCE_SUFFIXES or path.name in SOURCE_NAMES)
        ),
        key=lambda path: path.as_posix(),
    )


def _read_case_files(case_path: Path) -> list[dict[str, str]]:
    root = case_path if case_path.is_dir() else case_path.parent
    files: list[dict[str, str]] = []
    total_bytes = 0
    for path in _source_candidates(case_path):
        if path.is_symlink():
            raise JevBenchmarkError(f"benchmark source cannot be a symlink: {path}")
        resolved = path.resolve()
        if not _is_relative_to(resolved, root.resolve()):
            raise JevBenchmarkError(f"benchmark source escapes its case root: {path}")
        text = read_project_text_no_symlink(
            root,
            resolved,
            max_bytes=MAX_FILE_BYTES,
        )
        if text is None:
            raise JevBenchmarkError(f"cannot safely read benchmark source: {path}")
        total_bytes += len(text.encode("utf-8"))
        if total_bytes > MAX_STATE_BYTES:
            raise JevBenchmarkError(
                f"case source exceeds the {MAX_STATE_BYTES}-byte Jev benchmark limit"
            )
        files.append(
            {
                "path": resolved.relative_to(root.resolve()).as_posix(),
                "content": text.replace("\r\n", "\n").replace("\r", "\n"),
            }
        )
    if not files:
        raise JevBenchmarkError(f"case has no supported source files: {case_path}")
    return files


def _expectations(case: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    expect = case.get("expect") or {}
    items: list[tuple[str, dict[str, Any]]] = []
    for label in ("unused", "used"):
        items.extend((label, item) for item in expect.get(label, []) or [])
    return items


def _signal_mapping(case: dict[str, Any]) -> dict[str, str]:
    symbols = sorted(
        {
            str(item["symbol"])
            for _label, item in _expectations(case)
            if any(word in str(item["symbol"]).lower() for word in LABEL_SIGNAL_WORDS)
        },
        key=lambda value: (value.lower(), value),
    )
    return {symbol: f"candidate_{index:03d}" for index, symbol in enumerate(symbols, 1)}


def _neutralize_text(text: str, mapping: dict[str, str]) -> str:
    for original in sorted(mapping, key=len, reverse=True):
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(original)}(?![A-Za-z0-9_])"
        text = re.sub(pattern, mapping[original], text)
    for index, word in enumerate(LABEL_SIGNAL_WORDS, 1):
        text = re.sub(
            rf"(?i)(?<![A-Za-z0-9_]){re.escape(word)}(?![A-Za-z0-9_])",
            f"neutral_{index:02d}",
            text,
        )
    return text


def _question_payload(
    kind: str,
    file: str,
    symbol: str,
    line: int | None = None,
) -> dict[str, Any]:
    target: dict[str, Any] = {"kind": kind, "file": file, "symbol": symbol}
    if line is not None:
        target["line"] = line
    return {
        "type": "choice",
        "instructions": {
            "task": (
                "Determine whether the target is semantically retained by the supplied "
                "repository. Use concrete code, configuration, metadata, framework, "
                "callback, registry, export, reflection, and entrypoint evidence. "
                "Treat the supplied fixture as complete. Do not infer liveness from "
                "identifier wording."
            ),
            "target": target,
        },
        "criteria": {
            "retained": (
                "A concrete direct or indirect path can use, register, expose, or "
                "invoke the target."
            ),
            "unreferenced": (
                "No concrete path in the complete supplied fixture retains the target."
            ),
            "insufficient_evidence": (
                "The supplied fixture cannot support either conclusion without "
                "guessing."
            ),
        },
    }


def _mapped_files(
    files: list[dict[str, str]],
    mapping: dict[str, str],
) -> list[dict[str, str]]:
    if not mapping:
        return files
    return [
        {
            "path": item["path"],
            "content": _neutralize_text(item["content"], mapping),
        }
        for item in files
    ]


def _case_questions(
    case: dict[str, Any],
    mapping: dict[str, str],
) -> tuple[dict[str, Any], tuple[JevQuestion, ...]]:
    questions = []
    request_questions = {}
    for index, (expected, item) in enumerate(_expectations(case), 1):
        question_id = f"q{index:04d}"
        symbol = str(item["symbol"])
        sent_symbol = mapping.get(symbol, symbol)
        raw_line = item.get("line")
        line = int(raw_line) if raw_line is not None else None
        request_questions[question_id] = _question_payload(
            str(item["kind"]), str(item["file"]), sent_symbol, line
        )
        questions.append(
            JevQuestion(
                question_id=question_id,
                case_id=str(case["id"]),
                expected=expected,
                kind=str(item["kind"]),
                file=str(item["file"]),
                symbol=symbol,
                sent_symbol=sent_symbol,
                line=line,
                label_id=item.get("label_id"),
                taxonomy=tuple(
                    str(value)
                    for value in item.get("_taxonomy", case.get("taxonomy", []))
                ),
            )
        )
    return request_questions, tuple(questions)


def _build_batch(
    case: dict[str, Any],
    manifest_path: str | Path,
    *,
    arm: str,
) -> JevBatch:
    files = _read_case_files(_safe_case_path(case))
    known_paths = {item["path"] for item in files}
    for _expected, item in _expectations(case):
        if str(item["file"]) not in known_paths:
            raise JevBenchmarkError(
                f"case {case['id']} target file is not in the supplied fixture: "
                f"{item['file']}"
            )
    mapping = _signal_mapping(case) if arm == "neutralized" else {}
    files = _mapped_files(files, mapping)
    request_questions, questions = _case_questions(case, mapping)
    payload = {
        "state": {
            "repository_files": files,
            "fixture_scope": (
                "This is the complete synthetic repository fixture for the "
                "requested targets."
            ),
        },
        "model": JEV_MODEL,
        "questions": request_questions,
    }
    state_bytes = len(_canonical_json(payload["state"]).encode("utf-8"))
    if state_bytes > MAX_STATE_BYTES:
        raise JevBenchmarkError(
            f"case state exceeds the {MAX_STATE_BYTES}-byte Jev benchmark limit"
        )
    return JevBatch(
        case_id=str(case["id"]),
        arm=arm,
        payload=payload,
        questions=questions,
        request_digest=_digest(payload),
        state_bytes=state_bytes,
    )


def prepare_batches(
    manifest_path: str | Path,
    selected_cases: set[str] | None = None,
) -> list[JevBatch]:
    cases = _select_cases(manifest_path, selected_cases)
    return [
        _build_batch(case, manifest_path, arm=arm)
        for case in cases
        for arm in ("original", "neutralized")
    ]


def build_plan(
    manifest_path: str | Path,
    selected_cases: set[str] | None = None,
) -> dict[str, Any]:
    batches = prepare_batches(manifest_path, selected_cases)
    originals = [batch for batch in batches if batch.arm == "original"]
    expected = [
        question.expected for batch in originals for question in batch.questions
    ]
    return {
        "benchmark": "jev_dead_code",
        "mode": "plan",
        "network_used": False,
        "manifest": str(Path(manifest_path).expanduser().absolute()),
        "manifest_digest": manifest_digest(manifest_path),
        "manifest_metadata": manifest_metadata(manifest_path),
        "model": JEV_MODEL,
        "endpoint": JEV_ENDPOINT,
        "prompt_version": PROMPT_VERSION,
        "prompt_digest": prompt_digest(),
        "case_count": len(originals),
        "request_count": len(batches),
        "decision_count": sum(len(batch.questions) for batch in batches),
        "ground_truth_count": len(expected),
        "unused_count": expected.count("unused"),
        "used_count": expected.count("used"),
        "state_bytes": sum(batch.state_bytes for batch in batches),
        "arms": ["original", "neutralized"],
    }
