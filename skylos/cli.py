import argparse
import importlib
import importlib.util
import json
import sys
import re
import logging
import os
import secrets as secrets_lib
import shutil
import tempfile
from types import SimpleNamespace
from skylos.cli_core.dispatch import (
    EARLY_COMMAND_HANDLERS as EARLY_COMMAND_HANDLERS,
    dispatch_early_command,
    is_first_level_help_request,
    run_early_command_help,
)
from skylos.cli_core.main_parser import (
    apply_main_output_format,
    build_main_parser,
    parse_main_cli_args,
)
from skylos.constants import (
    parse_exclude_folders,
    DEFAULT_EXCLUDE_FOLDERS,
    get_non_library_dir_kind,
)
from skylos.config import (
    ConfigError as ConfigError,
    load_config,
    resolve_config_file_path,
)
from skylos.cloud.credentials import PROVIDERS
from skylos.core.result_cache import (
    build_trace_cache_key,
    load_trace_cache,
    read_trace_payload,
    save_trace_cache,
    write_trace_payload,
)
from skylos.remediation.safety import resolve_remediation_path

from pathlib import Path
import pathlib
import skylos
from io import StringIO
import subprocess
import textwrap

from skylos.reporting.github_annotations import (
    _emit_github_annotation as _emit_github_annotation,
    _emit_github_annotations,
    _emit_github_grade_annotation as _emit_github_grade_annotation,
    _filter_github_annotations_by_severity as _filter_github_annotations_by_severity,
    _github_annotation_items as _github_annotation_items,
    _github_annotation_sort_key as _github_annotation_sort_key,
    _github_dead_code_annotation as _github_dead_code_annotation,
    _github_finding_annotation as _github_finding_annotation,
)
from skylos.reporting.llm_report import (
    _collect_llm_report_findings as _collect_llm_report_findings,
    _default_dead_code_llm_fields as _default_dead_code_llm_fields,
    _format_llm_report_section as _format_llm_report_section,
    _generate_llm_report as _generate_llm_report,
    _llm_report_code_block as _llm_report_code_block,
    _llm_report_secret_block as _llm_report_secret_block,
    _llm_report_sort_key as _llm_report_sort_key,
)
from skylos.ui.rich_report import (
    _dead_code_why as _dead_code_why,
    _display_cap as _display_cap,
    _display_rule_name as _display_rule_name,
    _format_confidence as _format_confidence,
    _grep_verify_pill as _grep_verify_pill,
    _quality_detail as _quality_detail,
    _render_circular_deps as _render_circular_deps,
    _render_custom_rules as _render_custom_rules,
    _render_danger as _render_danger,
    _render_grade as _render_grade,
    _render_quality as _render_quality,
    _render_result_tree as _render_result_tree,
    _render_sca as _render_sca,
    _render_secrets as _render_secrets,
    _render_unused as _render_unused,
    _render_unused_simple as _render_unused_simple,
    _results_pill as _results_pill,
    _score_style as _score_style,
    _verification_label as _verification_label,
    _verification_proof as _verification_proof,
    render_results,
)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress as Progress
from rich.progress import SpinnerColumn as SpinnerColumn
from rich.progress import TextColumn as TextColumn
from rich.theme import Theme
from rich.logging import RichHandler
from rich.rule import Rule

class _LazyInquirer:
    """Import inquirer only when an interactive prompt is actually used."""

    _module = None

    def _load(self):
        if self._module is None:
            self._module = importlib.import_module("inquirer")
        return self._module

    def __getattr__(self, name):
        return getattr(self._load(), name)


def _inquirer_available() -> bool:
    try:
        return importlib.util.find_spec("inquirer") is not None
    except (ImportError, ValueError):
        return False


INTERACTIVE_AVAILABLE = _inquirer_available()
inquirer = _LazyInquirer() if INTERACTIVE_AVAILABLE else None


def _get_inquirer():
    return inquirer if INTERACTIVE_AVAILABLE else None

logger = logging.getLogger(__name__)

SarifExporter = None
SkylosLLM = None
AnalyzerConfig = None
LLM_AVAILABLE = False

DEFAULT_AGENT_MODEL = "gpt-4.1"
AGENT_PROVIDER_CHOICES = (
    "openai",
    "anthropic",
    "google",
    "mistral",
    "groq",
    "xai",
    "together",
    "deepseek",
    "ollama",
)
AGENT_PROVIDER_HELP = "Force LLM provider"
AGENT_BASE_URL_HELP = "OpenAI-compatible base URL (Ollama/LM Studio/vLLM)"


def _codemods_module():
    return importlib.import_module("skylos.remediation.codemods")


def remove_unused_import_cst(*args, **kwargs):
    return _codemods_module().remove_unused_import_cst(*args, **kwargs)


def remove_unused_function_cst(*args, **kwargs):
    return _codemods_module().remove_unused_function_cst(*args, **kwargs)


def comment_out_unused_import_cst(*args, **kwargs):
    return _codemods_module().comment_out_unused_import_cst(*args, **kwargs)


def comment_out_unused_function_cst(*args, **kwargs):
    return _codemods_module().comment_out_unused_function_cst(*args, **kwargs)


def run_analyze(*args, **kwargs):
    from skylos.analyzer import analyze as run_analyze_impl

    return run_analyze_impl(*args, **kwargs)


def resolve_llm_runtime(*args, **kwargs):
    from skylos.llm.runtime import resolve_llm_runtime as resolve_llm_runtime_impl

    return resolve_llm_runtime_impl(*args, **kwargs)


def run_gate_interaction(*args, **kwargs):
    from skylos.core.gatekeeper import run_gate_interaction as run_gate_interaction_impl

    return run_gate_interaction_impl(*args, **kwargs)


def upload_report(*args, **kwargs):
    from skylos.api import upload_report as upload_report_impl

    return upload_report_impl(*args, **kwargs)


def run_pipeline(*args, **kwargs):
    from skylos.pipeline import run_pipeline as run_pipeline_impl

    return run_pipeline_impl(*args, **kwargs)


def review_security_scan_result(*args, **kwargs):
    from skylos.llm.security_taskflow import (
        review_security_analysis_result as review_security_analysis_result_impl,
    )

    return review_security_analysis_result_impl(*args, **kwargs)["result"]


def run_security_taskflow(*args, **kwargs):
    from skylos.llm.security_taskflow import (
        run_security_taskflow as run_security_taskflow_impl,
    )

    return run_security_taskflow_impl(*args, **kwargs)


def discover_source_files(*args, **kwargs):
    from skylos.core.file_discovery import (
        discover_source_files as discover_source_files_impl,
    )

    return discover_source_files_impl(*args, **kwargs)


def _read_staged_text(project_root: Path, relpath: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f":{relpath}"],
        capture_output=True,
        text=True,
        cwd=project_root,
    )
    if result.returncode == 0:
        return result.stdout
    return None


def _scan_staged_secret_files(
    project_root: Path,
    relpaths: list[str],
    *,
    ignore_tests: bool,
) -> list[dict]:
    from skylos.rules.secrets import scan_ctx as secret_scan_ctx

    findings: list[dict] = []
    for relpath in relpaths:
        src = _read_staged_text(project_root, relpath)
        if src is None:
            candidate = (project_root / relpath).resolve()
            try:
                src = candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
        ctx = {
            "relpath": relpath,
            "lines": src.splitlines(True),
            "tree": None,
        }
        findings.extend(list(secret_scan_ctx(ctx, ignore_tests=ignore_tests)))
    return findings


def _join_phrase(parts: list[str]) -> str:
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return " ".join((parts[0], "and", parts[1]))
    return f"{', '.join(parts[:-1])}, {' '.join(('and', parts[-1]))}"


def _list_dirty_relevant_paths(project_root: Path, is_relevant_path) -> list[str]:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        capture_output=True,
        text=True,
        cwd=project_root,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    relevant = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        status = line[:2]
        if status == "??":
            relpath = line[3:]
        elif len(status) == 2 and status[1] != " ":
            relpath = line[3:]
        else:
            continue
        if " -> " in relpath:
            relpath = relpath.rsplit(" -> ", 1)[-1]
        relpath = relpath.strip()
        if relpath and is_relevant_path(Path(relpath)):
            relevant.append(relpath)
    return relevant


def _deep_audit_output_exclude_paths(
    audit_path: pathlib.Path,
    output_path: str | None,
) -> list[pathlib.Path] | None:
    if not output_path:
        return None

    target = audit_path.resolve()
    project_root = target.parent if target.is_file() else target
    output = pathlib.Path(output_path).expanduser()
    if not output.is_absolute():
        output = pathlib.Path.cwd() / output
    output = output.resolve()
    try:
        output.relative_to(project_root)
    except ValueError:
        return None
    return [output]


def _deep_audit_project_root(audit_path: pathlib.Path) -> pathlib.Path:
    target = audit_path.resolve()
    return target.parent if target.is_file() else target


def _empty_changed_deep_audit_payload(
    audit_path: pathlib.Path,
    *,
    fail_on: str | None,
    export_format: str,
    severity: str | None,
    verdicts: list[str] | None,
) -> tuple[dict, object | None]:
    from skylos.audit.export import build_deep_audit_export
    from skylos.audit.store import AuditStore
    from skylos.audit.types import AuditCIGateSummary, AuditScanSummary

    project_root = _deep_audit_project_root(audit_path)
    store = AuditStore(project_root)
    summary = AuditScanSummary(
        project_id=store.project_id,
        project_root=str(project_root),
        files_scanned=0,
        records_written=0,
        candidate_count=0,
        redacted_candidates=0,
        pending_files=0,
        not_analyzed_files=0,
        complete=True,
    )
    payload = {
        "mode": "deep_no_changes",
        "changed_scope": True,
        "no_changed_files": True,
        "summary": summary.to_dict(),
        "audit_project_dir": str(store.project_dir),
        "changed_files": [],
    }
    if fail_on:
        payload["ci"] = AuditCIGateSummary(
            fail_on=fail_on,
            exit_code=0,
            blocking_counts={
                "findings": 0,
                "pending": 0,
                "not_analyzed": 0,
                "skipped": 0,
                "error": 0,
                "locked": 0,
                "stale_analyzed": 0,
                "limited": 0,
            },
            complete=True,
            reason="no changed files to audit",
        ).to_dict()

    export_payload = None
    if export_format in {"json", "sarif", "md", "markdown", "md-dir"}:
        export_payload = build_deep_audit_export(
            store=store,
            min_severity=severity,
            verdicts=verdicts,
            allowed_files=[],
        )
        payload["export"] = export_payload
    return payload, export_payload


def _write_deep_audit_payload(path: str | pathlib.Path, payload: dict) -> None:
    from skylos.audit.export import write_deep_audit_export

    write_deep_audit_export(payload, path, "json")


def _handle_empty_changed_deep_audit(
    agent_args,
    audit_path: pathlib.Path,
    console,
) -> int:
    export_format = getattr(agent_args, "format", "table")
    output_path = getattr(agent_args, "output", None)
    quiet = getattr(agent_args, "quiet", False)
    payload, export_payload = _empty_changed_deep_audit_payload(
        audit_path,
        fail_on=getattr(agent_args, "fail_on", None),
        export_format=export_format,
        severity=getattr(agent_args, "severity", None),
        verdicts=getattr(agent_args, "verdict", None),
    )

    if export_format in {"sarif", "md", "markdown", "md-dir"}:
        if export_payload is None:
            return 1
        from skylos.audit.export import (
            render_deep_audit_export,
            write_deep_audit_export,
        )

        if output_path:
            written_paths = write_deep_audit_export(
                export_payload,
                output_path,
                export_format,
            )
            if not quiet:
                console.print(
                    f"[dim]No changed files to audit. Written "
                    f"{len(written_paths)} empty export file(s) to "
                    f"{output_path}[/dim]"
                )
        elif not quiet:
            print(render_deep_audit_export(export_payload, export_format), end="")
        return 0

    if output_path:
        _write_deep_audit_payload(output_path, payload)

    if export_format == "json":
        if not quiet:
            print(json.dumps(payload, indent=2, sort_keys=True))
    elif not quiet:
        if output_path:
            console.print(
                f"[dim]No changed files to audit. Wrote empty audit report "
                f"to {output_path}[/dim]"
            )
        else:
            console.print("[dim]No changed files to audit.[/dim]")
    return 0


def _create_precommit_snapshot(project_root: Path):
    snapshot_dir = tempfile.TemporaryDirectory(prefix="skylos_precommit_")
    snapshot_root = Path(snapshot_dir.name).resolve()
    result = subprocess.run(
        [
            "git",
            "checkout-index",
            "--all",
            "--force",
            f"--prefix={str(snapshot_root) + os.sep}",
        ],
        capture_output=True,
        text=True,
        cwd=project_root,
    )
    if result.returncode != 0:
        snapshot_dir.cleanup()
        return None, None
    return snapshot_dir, snapshot_root


def _remap_precommit_result_files(
    result: dict, source_root: Path, target_root: Path
) -> dict:
    if source_root.resolve() == target_root.resolve():
        return result

    remapped = dict(result)
    for category in [
        "unused_functions",
        "unused_imports",
        "unused_classes",
        "unused_variables",
        "unused_parameters",
        "unused_files",
        "danger",
        "quality",
        "secrets",
        "custom_rules",
    ]:
        items = result.get(category, [])
        if not items:
            continue

        mapped_items = []
        for item in items:
            if not isinstance(item, dict):
                mapped_items.append(item)
                continue

            mapped = dict(item)
            file_value = mapped.get("file")
            if file_value:
                file_path = Path(str(file_value))
                if file_path.is_absolute():
                    try:
                        relpath = file_path.resolve().relative_to(source_root.resolve())
                    except ValueError:
                        relpath = None
                else:
                    relpath = file_path
                if relpath is not None:
                    mapped["file"] = str((target_root / relpath).resolve())
            mapped_items.append(mapped)

        remapped[category] = mapped_items

    return remapped


_PRECOMMIT_HUNK_RE = re.compile(r"^@@ .+ \+(\d+)(?:,(\d+))? @@")


def _parse_unified_diff_ranges(diff_output: str) -> list[dict]:
    entries = []
    current_file = None

    for line in diff_output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        match = _PRECOMMIT_HUNK_RE.match(line)
        if match and current_file:
            start = int(match.group(1))
            count = int(match.group(2) or 1)
            if count > 0:
                entries.append(
                    {
                        "file": current_file,
                        "start": start,
                        "end": start + count - 1,
                    }
                )

    return entries


def _normalize_precommit_path(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def _path_suffixes(path: str) -> tuple[str, ...]:
    normalized = _normalize_precommit_path(path)
    if not normalized:
        return ()
    parts = normalized.split("/")
    return tuple("/".join(parts[idx:]) for idx in range(len(parts)))


def _build_changed_range_index(
    changed_ranges: list[dict],
) -> dict[str, list[tuple[int, int]]]:
    index: dict[str, list[tuple[int, int]]] = {}
    for entry in changed_ranges:
        key = _normalize_precommit_path(entry["file"])
        index.setdefault(key, []).append((entry["start"], entry["end"]))
    return index


def _ranges_for_precommit_file(
    file_path: str, changed_range_index: dict[str, list[tuple[int, int]]]
) -> list[tuple[int, int]]:
    for candidate in _path_suffixes(file_path):
        ranges = changed_range_index.get(candidate)
        if ranges:
            return ranges
    return []


def _finding_is_in_changed_lines(
    finding: dict, changed_range_index: dict[str, list[tuple[int, int]]]
) -> bool:
    if str(finding.get("rule_id", "")) == "SKY-L021":
        return True

    file_ranges = _ranges_for_precommit_file(
        str(finding.get("file", "")), changed_range_index
    )
    if not file_ranges:
        return False

    line = int(finding.get("line") or 0)
    return any(start <= line <= end for start, end in file_ranges)


def _get_cached_changed_line_ranges(
    project_root: Path, staged_paths: list[str] | None = None
) -> list[dict] | None:
    cmd = ["git", "diff", "--cached", "--unified=0"]
    if staged_paths:
        cmd.extend(["--", *staged_paths])
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=project_root,
    )
    if result.returncode != 0:
        return None
    return _parse_unified_diff_ranges(result.stdout)


def _filter_precommit_findings_to_changed_lines(
    findings: list[dict], changed_ranges: list[dict] | None
) -> list[dict]:
    if changed_ranges is None:
        return findings

    changed_range_index = _build_changed_range_index(changed_ranges)
    return [
        finding
        for finding in findings
        if _finding_is_in_changed_lines(finding, changed_range_index)
    ]


LOCAL_PRECOMMIT_BLOCKING_QUALITY_RULE_IDS = {"SKY-L021"}
LOCAL_PRECOMMIT_BLOCKING_QUALITY_SEVERITIES = {"CRITICAL", "HIGH"}
LOCAL_PRECOMMIT_ADVISORY_QUALITY_RULE_IDS = {"SKY-Q802", "SKY-Q803"}


def _precommit_blocks_finding(finding: dict) -> bool:
    category = str(finding.get("category", "")).lower()
    if category in {"security", "secrets"}:
        return True
    if category != "quality":
        return True

    rule_id = str(finding.get("rule_id", ""))
    if (
        rule_id in LOCAL_PRECOMMIT_ADVISORY_QUALITY_RULE_IDS
        and finding.get("advisory") is True
    ):
        return False

    if rule_id in LOCAL_PRECOMMIT_BLOCKING_QUALITY_RULE_IDS:
        return True

    severity = str(finding.get("severity", "")).upper()
    return severity in LOCAL_PRECOMMIT_BLOCKING_QUALITY_SEVERITIES


def _apply_precommit_gate_policy(findings: list[dict]) -> tuple[list[dict], int]:
    blocking = []
    suppressed = 0
    for finding in findings:
        if _precommit_blocks_finding(finding):
            blocking.append(finding)
        else:
            suppressed += 1
    return blocking, suppressed


def llm_estimate_cost(files, model):
    try:
        from skylos.llm.ui import estimate_cost as llm_estimate_cost_impl
    except ImportError:
        approx_tokens = 0
        for file_path in files:
            try:
                approx_tokens += max(Path(file_path).stat().st_size // 4, 1)
            except OSError:
                approx_tokens += 1
        return approx_tokens, 0.0

    return llm_estimate_cost_impl(files, model)


def _get_sarif_exporter_class():
    global SarifExporter

    if SarifExporter is None:
        from skylos.reporting.sarif import SarifExporter as sarif_exporter_impl

        SarifExporter = sarif_exporter_impl

    return SarifExporter


def _ensure_llm_support() -> bool:
    global SkylosLLM, AnalyzerConfig, LLM_AVAILABLE

    if SkylosLLM is not None:
        LLM_AVAILABLE = True
        return True

    try:
        from skylos.llm.analyzer import (
            SkylosLLM as skylos_llm_impl,
            AnalyzerConfig as analyzer_config_impl,
        )
    except ImportError:
        LLM_AVAILABLE = False
        return False

    SkylosLLM = skylos_llm_impl
    AnalyzerConfig = analyzer_config_impl
    LLM_AVAILABLE = True
    return True


def _build_analyzer_config(**kwargs):
    global AnalyzerConfig

    if AnalyzerConfig is None:
        try:
            from skylos.llm.analyzer import AnalyzerConfig as analyzer_config_impl
        except ImportError:
            return SimpleNamespace(**kwargs)
        AnalyzerConfig = analyzer_config_impl

    return AnalyzerConfig(**kwargs)


class CleanFormatter(logging.Formatter):
    def format(self, record):
        return record.getMessage()


def _skylos_console_theme():
    return Theme(
        {
            "good": "bold green",
            "warn": "bold yellow",
            "bad": "bold red",
            "muted": "dim",
            "brand": "bold cyan",
        }
    )


def setup_logger(output_file=None):
    console = Console(theme=_skylos_console_theme())

    logger = logging.getLogger("skylos")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    rich_handler = RichHandler(
        console=console, show_time=False, show_path=False, markup=True
    )
    rich_handler.setFormatter(CleanFormatter())
    logger.addHandler(rich_handler)

    if output_file:
        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler = logging.FileHandler(output_file)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    logger.propagate = False
    logger.console = console
    return logger


def remove_unused_import(file_path, import_name, line_number, *, root_path=None):
    try:
        path = resolve_remediation_path(file_path, root_path=root_path)
        src = path.read_text(encoding="utf-8")
        new_code, changed = remove_unused_import_cst(src, import_name, line_number)
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True

    except Exception as e:
        logging.error(f"Failed to remove import {import_name} from {file_path}: {e}")
        return False


def remove_unused_function(file_path, function_name, line_number, *, root_path=None):
    try:
        path = resolve_remediation_path(file_path, root_path=root_path)
        src = path.read_text(encoding="utf-8")
        new_code, changed = remove_unused_function_cst(src, function_name, line_number)
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True

    except Exception as e:
        logging.error(
            f"Failed to remove function {function_name} from {file_path}: {e}"
        )
        return False


def comment_out_unused_import(
    file_path, import_name, line_number, marker="SKYLOS DEADCODE", *, root_path=None
):
    try:
        path = resolve_remediation_path(file_path, root_path=root_path)
        src = path.read_text(encoding="utf-8")
        new_code, changed = comment_out_unused_import_cst(
            src, import_name, line_number, marker=marker
        )
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True

    except Exception as e:
        logging.error(
            f"Failed to comment out import {import_name} from {file_path}: {e}"
        )
        return False


def comment_out_unused_function(
    file_path, function_name, line_number, marker="SKYLOS DEADCODE", *, root_path=None
):
    try:
        path = resolve_remediation_path(file_path, root_path=root_path)
        src = path.read_text(encoding="utf-8")
        new_code, changed = comment_out_unused_function_cst(
            src, function_name, line_number, marker=marker
        )
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True

    except Exception as e:
        logging.error(
            f"Failed to comment out function {function_name} from {file_path}: {e}"
        )
        return False


def _shorten_path(path, root_path=None, keep_parts=3):
    if not path:
        return "?"

    try:
        p = Path(path).resolve()
        cwd = Path.cwd().resolve()

        rel = p.relative_to(cwd)
        return str(rel)

    except ValueError:
        return str(p)
    except Exception:
        return str(path)


def find_project_root(path):
    try:
        p = Path(path).resolve()
    except Exception:
        return Path.cwd().resolve()

    if p.is_file():
        cur = p.parent
    else:
        cur = p

    while True:
        if (cur / "pyproject.toml").exists():
            return cur
        if (cur / ".git").exists():
            return cur

        parent = cur.parent
        if parent == cur:
            break
        cur = parent

    return Path.cwd().resolve()


def _rel_to_project_root(file_path: str, project_root: Path) -> str:
    if not file_path:
        return "?"
    try:
        p = Path(file_path).resolve()
        root = Path(project_root).resolve()
        return str(p.relative_to(root)).replace("\\", "/")
    except Exception:
        return str(file_path).replace("\\", "/")


def _normalize_agent_findings(payload, project_root: Path):
    if isinstance(payload, dict):
        items = payload.get("findings") or payload.get("merged_findings") or []
        payload = dict(payload)
        payload["findings"] = _normalize_agent_findings(items, project_root)
        return payload

    out = []
    for f in payload or []:
        if not isinstance(f, dict):
            continue
        ff = dict(f)
        ff["file"] = _rel_to_project_root(ff.get("file", ""), project_root)
        try:
            ff["line"] = int(ff.get("line") or 1)
        except Exception:
            ff["line"] = 1
        out.append(ff)
    return out


def _agent_findings_to_result_json(findings):
    result = {
        "danger": [],
        "quality": [],
        "secrets": [],
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
    }

    category_map = {
        "security": "danger",
        "danger": "danger",
        "quality": "quality",
        "secret": "secrets",
        "secrets": "secrets",
    }

    dead_code_map = {
        "SKY-U001": "unused_functions",
        "SKY-U002": "unused_imports",
        "SKY-U003": "unused_variables",
        "SKY-U004": "unused_classes",
    }

    for f in findings or []:
        item = dict(f)
        item.setdefault("file_path", item.get("file", ""))
        item.setdefault("line_number", item.get("line", 1))

        cat = str(item.get("_category") or item.get("category") or "").lower()
        rule_id = str(item.get("rule_id") or item.get("rule") or "")

        if cat == "dead_code" or rule_id.startswith("SKY-U"):
            bucket = dead_code_map.get(rule_id, "unused_functions")
            result[bucket].append(item)
        elif cat in category_map:
            result[category_map[cat]].append(item)
        else:
            result["quality"].append(item)

    return result


def _is_tty():
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def _is_main_machine_output(args) -> bool:
    return bool(
        getattr(args, "json", False)
        or getattr(args, "llm", False)
        or getattr(args, "github", False)
        or getattr(args, "concise", False)
    )


def _has_high_intent_findings(result: dict) -> bool:
    secrets = result.get("secrets") or []
    if len(secrets) > 0:
        return True

    def _is_highish(item: dict) -> bool:
        sev = str(item.get("severity", "")).strip().lower()
        return sev in ("high", "critical")

    for item in result.get("danger") or []:
        if _is_highish(item):
            return True

    for item in result.get("custom_rules") or []:
        if _is_highish(item):
            return True

    return False


def _set_no_upload_prompt(project_root: Path, value: bool) -> bool:
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        return False

    content = pyproject.read_text(encoding="utf-8", errors="ignore")

    key_line = f"no_upload_prompt = {'true' if value else 'false'}"

    if "[tool.skylos]" not in content:
        content = content.rstrip() + "\n\n[tool.skylos]\n" + key_line + "\n"
        pyproject.write_text(content, encoding="utf-8")
        return True

    if re.search(r"(?m)^\s*no_upload_prompt\s*=\s*(true|false)\s*$", content):
        content = re.sub(
            r"(?m)^\s*no_upload_prompt\s*=\s*(true|false)\s*$",
            key_line,
            content,
        )
        pyproject.write_text(content, encoding="utf-8")
        return True

    content = re.sub(
        r"(?m)^\[tool\.skylos\]\s*$",
        "[tool.skylos]\n" + key_line,
        content,
        count=1,
    )
    pyproject.write_text(content, encoding="utf-8")
    return True


def _detect_link_file(project_root: Path) -> Path | None:
    p = project_root / ".skylos" / "link.json"

    if p.exists():
        return p
    else:
        return None


def _print_upload_destination(console: Console, project_root: Path):
    using_env = bool(os.getenv("SKYLOS_TOKEN"))
    link_path = _detect_link_file(project_root)
    has_link = link_path is not None

    if using_env:
        console.print("[brand]Auto-uploading:[/brand] SKYLOS_TOKEN")
    elif has_link:
        console.print(
            f"[brand]Auto-uploading:[/brand] linked project ([muted]{link_path}[/muted])"
        )
    else:
        console.print(
            "[warn]Upload destination:[/warn] default token (no repo link found)"
        )

    return has_link, using_env


def _selected_main_upload_static_categories(args) -> list[str]:
    categories = ["dead_code"]
    if getattr(args, "danger", False):
        categories.append("danger")
    if getattr(args, "quality", False):
        categories.append("quality")
    if getattr(args, "secrets", False):
        categories.append("secrets")
    if getattr(args, "sca", False):
        categories.append("dependency")
    return categories


def _print_main_upload_manifest(console: Console, args, result) -> None:
    from skylos.cloud.upload_manifest import (
        build_code_scan_manifest,
        print_upload_manifest,
    )

    print_upload_manifest(
        console,
        [
            build_code_scan_manifest(
                _selected_main_upload_static_categories(args),
                provenance_attached=bool((result or {}).get("provenance")),
            )
        ],
        auto_upload=not getattr(args, "_explicit_upload_requested", False),
    )


def _render_upload_failure(console: Console, upload_resp: dict[str, object]) -> None:
    code = str(upload_resp.get("code") or "")
    err = str(upload_resp.get("error") or "").strip()
    if code == "UPLOAD_PROTOCOL_UNSUPPORTED":
        console.print(
            "[warn]Upload unavailable:[/warn] this Skylos Cloud endpoint only supports inline scan uploads right now."
        )
        console.print(
            "[dim]Large scans need artifact upload support via /api/report/init and /api/report/complete.[/dim]"
        )
        return

    if err and err != (
        "No token found. Run 'skylos login' or 'skylos project use', or set SKYLOS_TOKEN."
    ):
        console.print(f"[warn]Upload failed:[/warn] {err}")


def _is_ci():
    return any(
        os.getenv(v)
        for v in (
            "CI",
            "GITHUB_ACTIONS",
            "JENKINS_URL",
            "BUILD_NUMBER",
            "CIRCLECI",
            "GITLAB_CI",
            "BITBUCKET_PIPELINE_UUID",
            "AZURE_PIPELINES",
            "TF_BUILD",
        )
    )


def _print_upload_cta(console: Console, project_root: Path):
    if _is_ci():
        return

    has_link = _detect_link_file(project_root) is not None
    has_env = bool(os.getenv("SKYLOS_TOKEN"))
    connected = has_link or has_env

    console.print()
    if connected:
        console.print(
            Panel(
                "\n".join(
                    [
                        "[bold]Upload to Skylos Cloud for trend tracking and PR blocking[/bold]",
                        "",
                        "  [bold cyan]skylos . --upload[/bold cyan]",
                        "",
                        "  [dim]Dashboard:[/dim] https://skylos.dev/dashboard",
                    ]
                ),
                title="[bold]☁️  Skylos Cloud[/bold]",
                border_style="blue",
                padding=(1, 2),
            )
        )
    else:
        console.print(
            Panel(
                "\n".join(
                    [
                        "[bold]Upload to Skylos Cloud in one command[/bold]",
                        "",
                        "  [bold cyan]skylos . --upload[/bold cyan]",
                        "",
                        "  [dim]Browser opens → pick project → done![/dim]",
                        "  [dim]Dashboard:[/dim] https://skylos.dev",
                    ]
                ),
                title="[bold]☁️  Skylos Cloud[/bold]",
                border_style="blue",
                padding=(1, 2),
            )
        )


def _print_feature_hints(console: Console, args):
    """Print contextual hints about features the user hasn't used yet."""
    if _is_ci():
        return

    hints = []

    ran_all = getattr(args, "all_checks", False)
    ran_danger = getattr(args, "danger", False)
    ran_secrets = getattr(args, "secrets", False)
    ran_quality = getattr(args, "quality", False)

    if not ran_all and not (ran_danger and ran_secrets and ran_quality):
        extras = []
        if not ran_danger:
            extras.append("security")
        if not ran_secrets:
            extras.append("secrets")
        if not ran_quality:
            extras.append("quality")
        hints.append(
            f"[dim]Add {' + '.join(extras)} scanning:[/dim] [bold]skylos . -a[/bold]"
        )

    hint_file = Path.home() / ".skylos" / ".hint_index"
    try:
        idx = int(hint_file.read_text().strip()) if hint_file.exists() else 0
    except (ValueError, OSError):
        idx = 0

    rotating_hints = [
        "[dim]Run the full local bundle:[/dim] [bold]skylos suite .[/bold]",
        "[dim]Scan for AI/LLM guardrails:[/dim] [bold]skylos defend .[/bold]",
        "[dim]Map LLM integrations:[/dim] [bold]skylos discover .[/bold]",
        "[dim]LLM-verified dead code (100% accuracy):[/dim] [bold]skylos agent verify .[/bold]",
        "[dim]Auto-fix dead code interactively:[/dim] [bold]skylos . -i[/bold]",
    ]

    hints.append(rotating_hints[idx % len(rotating_hints)])

    try:
        hint_file.parent.mkdir(parents=True, exist_ok=True)
        hint_file.write_text(str(idx + 1))
    except OSError:
        pass

    if hints:
        console.print()
        for hint in hints:
            console.print(f"  {hint}")


def interactive_selection(
    console: Console, unused_functions, unused_imports, root_path=None
):
    prompt = _get_inquirer()
    if prompt is None:
        console.print(
            "[bad]Interactive mode requires 'inquirer'. Install with: pip install inquirer[/bad]"
        )
        return [], []

    selected_functions = []
    selected_imports = []

    if unused_functions:
        console.print(
            "\n[brand][bold]Select unused functions to remove (space to select):[/bold][/brand]"
        )

        function_choices = []
        for item in unused_functions:
            short = _shorten_path(item.get("file"), root_path)
            choice_text = f"{item['name']} ({short}:{item['line']})"
            function_choices.append((choice_text, item))

        questions = [
            prompt.Checkbox(
                "functions",
                message="Select functions to remove",
                choices=function_choices,
            )
        ]
        answers = prompt.prompt(questions)
        if answers:
            selected_functions = answers["functions"]

    if unused_imports:
        console.print(
            "\n[brand][bold]Select unused imports to act on (space to select):[/bold][/brand]"
        )

        import_choices = []
        for item in unused_imports:
            short = _shorten_path(item.get("file"), root_path)
            choice_text = f"{item['name']} ({short}:{item['line']})"
            import_choices.append((choice_text, item))

        questions = [
            prompt.Checkbox(
                "imports", message="Select imports to remove", choices=import_choices
            )
        ]
        answers = prompt.prompt(questions)
        if answers:
            selected_imports = answers["imports"]

    return selected_functions, selected_imports


def print_badge(
    dead_code_count,
    logger,
    *,
    danger_enabled=False,
    danger_count=0,
    quality_enabled=False,
    quality_count=0,
):
    console: Console = logger.console
    console.print(Rule(style="muted"))

    has_dead_code = dead_code_count > 0
    has_danger = danger_enabled and danger_count > 0
    has_quality = quality_enabled and quality_count > 0

    if not has_dead_code and not has_danger and not has_quality:
        console.print(
            Panel.fit(
                "[good]Your code is 100% dead-code free![/good]\nAdd this badge to your README:",
                border_style="good",
            )
        )
        console.print("```markdown")
        console.print(
            "![Dead Code Free](https://img.shields.io/badge/Dead_Code-Free-brightgreen?logo=moleculer&logoColor=white)"
        )
        console.print("```")
        return

    headline = f"Found {dead_code_count} dead-code items"
    if danger_enabled:
        headline += f" and {danger_count} security issues"
    if quality_enabled:
        headline += f" and {quality_count} quality issues"
    headline += ". Add this badge to your README:"

    console.print(Panel.fit(headline, border_style="warn"))
    console.print("```markdown")
    console.print(
        f"![Dead Code: {dead_code_count}](https://img.shields.io/badge/Dead_Code-{dead_code_count}_detected-orange?logo=codacy&logoColor=red)"
    )
    console.print("```")


_DISPLAY_FILTER_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_DISPLAY_FILTER_CATEGORY_MAP = {
    "unused_functions": "dead_code",
    "unused_imports": "dead_code",
    "unused_parameters": "dead_code",
    "unused_variables": "dead_code",
    "unused_classes": "dead_code",
    "unused_fixtures": "dead_code",
    "danger": "security",
    "secrets": "secret",
    "quality": "quality",
    "circular_dependencies": "quality",
    "custom_rules": "quality",
    "dependency_vulnerabilities": "dependency",
}


def _display_filter_min_rank(severity):
    if severity:
        return _DISPLAY_FILTER_SEVERITY_RANK.get(str(severity).lower(), 0)
    return 0


def _display_filter_allowed_categories(category):
    if category:
        return {c.strip().lower() for c in category.split(",")}
    return None


def _display_filter_matches_file(item, file_filter):
    if not file_filter:
        return True
    return file_filter in (item.get("file") or item.get("file_path") or "")


def _display_filter_has_severity(items):
    for item in items:
        if "severity" in item:
            return True
    return False


def _display_filter_passes_severity(item, min_rank):
    sev = (item.get("severity") or "").lower()
    return _DISPLAY_FILTER_SEVERITY_RANK.get(sev, 0) >= min_rank


def _display_filter_items(items, file_filter, min_rank):
    kept = items
    if file_filter:
        kept = [
            item for item in kept if _display_filter_matches_file(item, file_filter)
        ]

    if min_rank > 0 and kept and _display_filter_has_severity(kept):
        kept = [
            item for item in kept if _display_filter_passes_severity(item, min_rank)
        ]

    return kept


def _apply_display_filters(result, severity=None, category=None, file_filter=None):
    import copy

    min_rank = _display_filter_min_rank(severity)
    allowed_cats = _display_filter_allowed_categories(category)

    filtered = copy.copy(result)

    for key, cat in _DISPLAY_FILTER_CATEGORY_MAP.items():
        items = result.get(key, []) or []
        if not items:
            continue

        if allowed_cats and cat not in allowed_cats:
            filtered[key] = []
            continue

        filtered[key] = _display_filter_items(items, file_filter, min_rank)

    return filtered


def render_pretty_results(
    console: Console,
    result: dict,
    *,
    root_path=None,
    limit=None,
):
    from skylos.ui.terminal_report import render_pretty_results as render_impl

    return render_impl(console, result, root_path=root_path, limit=limit)


def _write_rich_report_output(
    output_file: str,
    result: dict,
    *,
    tree: bool = False,
    root_path=None,
    limit=None,
):
    buffer = StringIO()
    file_console = Console(
        theme=_skylos_console_theme(),
        file=buffer,
        force_terminal=False,
    )
    render_results(
        file_console,
        result,
        tree=tree,
        root_path=root_path,
        limit=limit,
        copy_badge=False,
    )
    pathlib.Path(output_file).write_text(buffer.getvalue(), encoding="utf-8")


def _write_pretty_report_output(
    output_file: str,
    result: dict,
    *,
    root_path=None,
    limit=None,
):
    buffer = StringIO()
    file_console = Console(
        theme=_skylos_console_theme(),
        file=buffer,
        force_terminal=False,
    )
    render_pretty_results(
        file_console,
        result,
        root_path=root_path,
        limit=limit,
    )
    pathlib.Path(output_file).write_text(buffer.getvalue(), encoding="utf-8")


def run_init():
    from skylos.commands.init_cmd import run_init_command

    return run_init_command()


def run_whitelist(pattern=None, reason=None, show=False):
    from skylos.commands.whitelist_cmd import run_whitelist as run_whitelist_impl

    return run_whitelist_impl(pattern=pattern, reason=reason, show=show)


def get_git_changed_files(
    root_path,
    base_ref=None,
    *,
    strict_base=False,
    include_deleted=False,
):
    from skylos.core.cli_shared import (
        get_git_changed_files as get_git_changed_files_impl,
    )

    return get_git_changed_files_impl(
        root_path,
        base_ref=base_ref,
        strict_base=strict_base,
        include_deleted=include_deleted,
    )


def estimate_cost(files):
    from skylos.core.cli_shared import estimate_cost as estimate_cost_impl

    return estimate_cost_impl(files)


def _run_clean_command(argv):
    from skylos.commands.clean_cmd import run_clean_command

    return run_clean_command(argv)


def _run_cache_command(argv):
    from skylos.commands.cache_cmd import run_cache_command

    return run_cache_command(argv, console_factory=Console)


def run_debt_command(argv):
    from skylos.commands.debt_cmd import run_debt_command as run_debt_command_impl
    from skylos.api import upload_debt_report

    return run_debt_command_impl(
        argv,
        console_factory=Console,
        get_git_changed_files_func=get_git_changed_files,
        resolve_llm_runtime_func=resolve_llm_runtime,
        parse_exclude_folders_func=parse_exclude_folders,
        load_config_func=load_config,
        upload_debt_report_func=upload_debt_report,
    )


def run_defend_command(argv):
    from skylos.commands.defend_cmd import run_defend_command as run_defend_command_impl

    return run_defend_command_impl(
        argv,
        console_factory=Console,
        progress_factory=Progress,
    )


def run_suite_command(argv):
    from skylos.api import (
        get_git_root,
        upload_debt_report,
        upload_defense_report,
    )
    from skylos.commands.suite_cmd import run_suite_command as run_suite_command_impl

    return run_suite_command_impl(
        argv,
        console_factory=Console,
        progress_factory=Progress,
        parse_exclude_folders_func=parse_exclude_folders,
        load_config_func=load_config,
        run_analyze_func=run_analyze,
        get_git_root_func=get_git_root,
        upload_report_func=upload_report,
        upload_defense_report_func=upload_defense_report,
        upload_debt_report_func=upload_debt_report,
    )


def run_ingest_command(argv):
    from skylos.commands.ingest_cmd import run_ingest_command as run_ingest_command_impl

    return run_ingest_command_impl(
        argv,
        console_factory=Console,
    )


def run_provenance_command(argv):
    from skylos.api import get_git_root
    from skylos.commands.provenance_cmd import (
        run_provenance_command as run_provenance_command_impl,
    )

    return run_provenance_command_impl(
        argv,
        console_factory=Console,
        progress_factory=Progress,
        get_git_root_func=get_git_root,
    )


def run_cicd_command(argv):
    from skylos.commands.cicd_cmd import run_cicd_command as run_cicd_command_impl

    return run_cicd_command_impl(
        argv,
        console_factory=Console,
        load_config_func=load_config,
        run_gate_interaction_func=run_gate_interaction,
        emit_github_annotations_func=_emit_github_annotations,
    )


def _load_addopts():
    from skylos.core.cli_shared import load_addopts

    return load_addopts()


def _handle_rules_command(argv):
    from skylos.commands.rules_cmd import run_rules_command

    return run_rules_command(argv, console_factory=Console)


def _rules_install(console, rules_dir, pack_or_url):
    from skylos.commands.rules_cmd import install_rules

    return install_rules(console, rules_dir, pack_or_url)


def _rules_list(console, rules_dir):
    from skylos.commands.rules_cmd import list_rules

    return list_rules(console, rules_dir)


def _rules_remove(console, rules_dir, name):
    from skylos.commands.rules_cmd import remove_rules

    exit_code = remove_rules(console, rules_dir, name)
    if exit_code:
        raise SystemExit(exit_code)
    return exit_code


def _run_command_overview(_argv):
    from skylos.ui.help import print_command_overview

    print_command_overview(Console())
    return 0


def _run_commands_command(_argv):
    from skylos.ui.help import print_flat_commands

    print_flat_commands(Console())
    return 0


def _run_tour_command(_argv):
    from skylos.ui.tour import run_tour

    run_tour(Console())
    return 0


def _run_key_command(argv):
    from skylos.commands.key_cmd import run_key_command

    return run_key_command(argv or ["menu"])


def _run_credits_command(_argv):
    from skylos.commands.credits_cmd import run_credits_command

    return run_credits_command()


def _run_init_command(_argv):
    return run_init()


def _run_baseline_command(argv):
    from skylos.commands.baseline_cmd import run_baseline_command

    return run_baseline_command(argv)


def _run_badge_command(_argv):
    from skylos.commands.badge_cmd import run_badge_command

    return run_badge_command()


def _run_whitelist_command(argv):
    from skylos.commands.whitelist_cmd import run_whitelist_command

    return run_whitelist_command(argv)


def _run_doctor_command(_argv):
    from skylos.commands.doctor_cmd import run_doctor_command

    return run_doctor_command()


def _run_whoami_command(_argv):
    from skylos.commands.whoami_cmd import run_whoami_command

    return run_whoami_command()


def _run_login_command(_argv):
    from skylos.commands.login_cmd import run_login_command

    return run_login_command()


def _run_sync_command(argv):
    from skylos.commands.sync_cmd import run_sync_command

    return run_sync_command(argv)


def _run_project_command(argv):
    from skylos.commands.project_cmd import run_project_command

    return run_project_command(argv)


def _run_sonar_command(argv):
    from skylos.commands.sonar_cmd import run_sonar_command

    return run_sonar_command(argv, console_factory=Console)


def _run_verify_command(argv):
    from skylos.commands.verify_cmd import run_verify_command

    return run_verify_command(argv)


def _attach_upload_project_context(result: dict, project_root: pathlib.Path) -> None:
    try:
        from skylos.api import get_git_root as _get_git_root
        from skylos.cloud.project_context import project_context_for_upload

        upload_context = project_context_for_upload(project_root, _get_git_root())
        result["project_root"] = upload_context["project_root"]
        result.setdefault("analysis_summary", {})["project_root"] = upload_context[
            "project_root"
        ]
    except (ImportError, OSError, ValueError, TypeError, AttributeError) as exc:
        logger.debug("Failed to attach upload project context: %s", exc)


def _upload_agent_run_best_effort(
    command: str,
    summary: dict,
    *,
    model: str | None = None,
    provider: str | None = None,
    duration_seconds: float | None = None,
) -> None:
    try:
        from skylos.api import upload_agent_run
    except ImportError as exc:
        logger.debug("Agent run telemetry unavailable: %s", exc)
        return

    upload_agent_run(
        command,
        summary,
        model=model,
        provider=provider,
        duration_seconds=duration_seconds,
    )


def _run_removed_city_command(_argv):
    console = Console()
    console.print("[bold red]Error:[/bold red] `skylos city` has been removed.")
    console.print(
        "[dim]Use[/dim] [bold]skylos suite .[/bold] [dim]for the full local bundle,[/dim] "
        "[bold]skylos debt .[/bold] [dim]for technical debt hotspots, or[/dim] "
        "[bold]skylos discover .[/bold] [dim]for codebase mapping.[/dim]"
    )
    raise SystemExit(2)


def _run_discover_command(argv):
    from skylos.commands.discover_cmd import run_discover_command

    return run_discover_command(argv)


def _run_web_server_command(argv):
    from skylos.commands.run_cmd import run_run_command

    return run_run_command(
        argv,
        console_factory=Console,
        load_config_func=load_config,
        parse_exclude_folders_func=parse_exclude_folders,
    )


def _run_scan_command(argv):
    from skylos.commands.scan_cmd import run_scan_command

    return run_scan_command(argv, cli_module=sys.modules[__name__])


def _is_first_level_help_request(argv):
    return is_first_level_help_request(argv)


def _run_early_command_help(command):
    return run_early_command_help(command, console_factory=Console)


def _dispatch_early_command(argv):
    return dispatch_early_command(argv, globals(), console_factory=Console)


def _rules_validate(console, path_str):
    from skylos.commands.rules_cmd import validate_rules

    return validate_rules(console, path_str)


def _build_main_parser():
    return build_main_parser(version=skylos.__version__)


def _apply_main_output_format(parser, args):
    return apply_main_output_format(parser, args)


def _parse_main_cli_args(parser, argv):
    return parse_main_cli_args(parser, argv, addopts_loader=_load_addopts)


def _resolve_main_project_root(paths):
    project_root = pathlib.Path(paths[0]).resolve()
    if project_root.is_file():
        project_root = project_root.parent
    if len(paths) > 1:
        all_resolved = [pathlib.Path(path).resolve() for path in paths]
        project_root = pathlib.Path(os.path.commonpath(all_resolved))
    return project_root


def _print_default_excludes(console):
    console.print("[brand]Default excluded folders:[/brand]")
    for folder in sorted(DEFAULT_EXCLUDE_FOLDERS):
        console.print(f" {folder}")
    console.print(f"\n[muted]Total: {len(DEFAULT_EXCLUDE_FOLDERS)} folders[/muted]")
    console.print("\nUse --no-default-excludes to disable these exclusions")
    console.print("Use --include-folder <folder> to force include specific folders")


def _build_main_scan_context(args):
    if getattr(args, "all_checks", False):
        args.danger = True
        args.secrets = True
        args.quality = True
        args.sca = True

    project_root = _resolve_main_project_root(args.path)
    logger = setup_logger()
    console = logger.console

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"Analyzing path(s): {args.path}")
        if args.exclude_folders:
            logger.debug(f"Excluding folders: {args.exclude_folders}")

    use_defaults = not args.no_default_excludes
    config_file = resolve_config_file_path(getattr(args, "config_file", None))
    project_cfg = load_config(project_root, config_file=config_file)
    final_exclude_folders = parse_exclude_folders(
        user_exclude_folders=args.exclude_folders,
        config_exclude_folders=project_cfg.get("exclude"),
        use_defaults=use_defaults,
        include_folders=args.include_folders,
    )
    _apply_config_driven_analysis_flags(args, project_cfg, console)

    return SimpleNamespace(
        project_root=project_root,
        logger=logger,
        console=console,
        final_exclude_folders=final_exclude_folders,
        config=project_cfg,
        config_file=config_file,
    )


def _formatted_output_gate_exit_code(
    result: dict,
    config: dict,
    args,
    *,
    provenance=None,
) -> int:
    """Evaluate --gate for output modes that must not print gate UI."""
    from skylos.core.gatekeeper import (
        build_summary_markdown,
        check_gate,
        write_github_summary,
    )

    config = config or {}
    gate_cfg = config.get("gate") or {}
    strict = bool(getattr(args, "strict", False) or gate_cfg.get("strict", False))
    passed, reasons = check_gate(result, config, strict=strict, provenance=provenance)

    if bool(getattr(args, "summary", False)):
        write_github_summary(build_summary_markdown(result, passed, reasons))

    if passed or bool(getattr(args, "force", False)):
        return 0
    return 1


def _concise_scan_exit_code(
    result: dict, config: dict, args, *, provenance=None
) -> int:
    if bool(getattr(args, "gate", False)):
        return _formatted_output_gate_exit_code(
            result,
            config,
            args,
            provenance=provenance,
        )

    if not bool(getattr(args, "force", False)):
        return 1 if _has_concise_findings(result) else 0

    return 0


CONCISE_FINDING_CATEGORIES = (
    ("unused_functions", "unused function"),
    ("unused_imports", "unused import"),
    ("unused_classes", "unused class"),
    ("unused_variables", "unused variable"),
    ("unused_parameters", "unused parameter"),
    ("unused_files", "unused file"),
    ("unused_fixtures", "unused fixture"),
    ("danger", "security issue"),
    ("quality", "quality issue"),
    ("secrets", "secret"),
    ("custom_rules", "custom rule"),
    ("dependency_vulnerabilities", "dependency vulnerability"),
)


def _has_concise_findings(result: dict) -> bool:
    for category, _label in CONCISE_FINDING_CATEGORIES:
        if result.get(category):
            return True
    return False


def _concise_line(item: dict, label: str, root_path=None) -> str:
    file_path = item.get("file") or item.get("file_path") or "?"
    line = item.get("line") or item.get("line_number") or 1
    try:
        line = max(1, int(line))
    except (TypeError, ValueError):
        line = 1
    return f"{_shorten_path(file_path, root_path)}:{line}  {label}"


def _format_concise_results(result: dict, *, root_path=None, limit=None) -> str:
    lines: list[str] = []

    for category, fallback_label in CONCISE_FINDING_CATEGORIES:
        items = list(result.get(category, []) or [])
        if limit is not None:
            items = items[:limit]
        for item in items:
            if not isinstance(item, dict):
                continue
            label = (
                item.get("message")
                or item.get("msg")
                or item.get("detail")
                or fallback_label
            )
            lines.append(_concise_line(item, str(label), root_path=root_path))

    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def _strict_scan_exit_code(result: dict, args) -> int:
    """Evaluate --strict when it is used without --gate."""
    if not bool(getattr(args, "strict", False)):
        return 0
    if bool(getattr(args, "gate", False)) or bool(getattr(args, "force", False)):
        return 0

    from skylos.core.gatekeeper import check_gate

    passed, _reasons = check_gate(result, {}, strict=True)
    return 0 if passed else 1


def _apply_config_driven_analysis_flags(args, project_cfg, console):
    security_contracts_configured = bool(project_cfg.get("security_contracts") or [])
    explicit_category_flags = any(
        getattr(args, name, False) for name in ("danger", "secrets", "quality")
    )

    enabled_from_policy = []
    if not explicit_category_flags:
        if (
            bool(project_cfg.get("security_enabled", False))
            or security_contracts_configured
        ):
            args.danger = True
            enabled_from_policy.append("danger")
        if bool(project_cfg.get("secrets_enabled", False)):
            args.secrets = True
            enabled_from_policy.append("secrets")
        if bool(project_cfg.get("quality_enabled", False)):
            args.quality = True
            enabled_from_policy.append("quality")

        if enabled_from_policy and not _is_main_machine_output(args):
            console.print(
                "[brand]Using synced/local Skylos policy:[/brand] enabling "
                + ", ".join(enabled_from_policy)
                + " analysis."
            )
        return

    # Security contracts are explicit security policy. If they are configured,
    # always run danger analysis so the contracts cannot be silently skipped.
    if not getattr(args, "danger", False) and security_contracts_configured:
        args.danger = True
        if not _is_main_machine_output(args):
            console.print(
                "[brand]Security contracts configured:[/brand] enabling danger analysis automatically."
            )


def _print_main_scan_banner(args, console, final_exclude_folders):
    if args.list_default_excludes:
        _print_default_excludes(console)
        return True

    if _is_main_machine_output(args):
        return False

    if getattr(args, "format", "rich") == "pretty":
        console.print(
            f"[brand]skylos[/brand] [muted]v{skylos.__version__} · scanning...[/muted]"
        )
        if final_exclude_folders and getattr(args, "verbose", False):
            console.print(
                f"[muted]excluding: {', '.join(sorted(final_exclude_folders))}[/muted]"
            )
        return False

    banner = (
        "[bold cyan]"
        " ███████ ██   ██ ██    ██ ██       ██████  ███████\n"
        " ██      ██  ██   ██  ██  ██      ██    ██ ██     \n"
        " ███████ █████     ████   ██      ██    ██ ███████\n"
        "      ██ ██  ██     ██    ██      ██    ██      ██\n"
        " ███████ ██   ██    ██    ███████  ██████  ███████\n"
        "[/bold cyan]\n"
        "  [bold white]v" + skylos.__version__ + "[/bold white]"
        "  [dim]│[/dim]  [blue]github.com/duriantaco/skylos[/blue]"
    )
    console.print(Panel(banner, border_style="cyan", padding=(1, 2)))
    console.print()

    if final_exclude_folders:
        console.print(
            f"[warn] Excluding:[/warn] {', '.join(sorted(final_exclude_folders))}"
        )
    else:
        console.print("[good] No folders excluded[/good]")

    return False


def _trace_cache_requested(args) -> bool:
    if not getattr(args, "trace", False):
        return False
    if getattr(args, "no_cache", False):
        return False
    if getattr(args, "pytest_fixtures", False):
        return False
    return bool(getattr(args, "cache", False) or getattr(args, "refresh_cache", False))


def _trusted_module_file(module_name: str) -> Path:
    module = importlib.import_module(module_name)
    module_file = getattr(module, "__file__", None)
    if not module_file:
        raise RuntimeError(f"Could not resolve trusted module path: {module_name}")
    return Path(module_file).resolve()


def _trace_subprocess_script() -> str:
    return textwrap.dedent("""\
import importlib.util
import os
import sys

project_root = os.path.realpath(sys.argv[1])
trace_output = os.path.realpath(sys.argv[2])
tracer_module_path = os.path.realpath(sys.argv[3])
fixtures_output = os.path.realpath(sys.argv[4])
fixtures_plugin_path = os.path.realpath(sys.argv[5]) if sys.argv[5] else ""
use_fixtures = sys.argv[6] == "1"


def _entry_realpath(entry):
    if not entry:
        entry = os.getcwd()
    if not os.path.isabs(entry):
        entry = os.path.join(os.getcwd(), entry)
    try:
        return os.path.realpath(entry)
    except OSError:
        return None


sys.path[:] = [
    entry for entry in sys.path if _entry_realpath(entry) != project_root
]


def _load_trusted_module(name, module_path):
    spec = importlib.util.spec_from_file_location(name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load trusted module: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tracer_module = _load_trusted_module("_skylos_trusted_tracer", tracer_module_path)
CallTracer = tracer_module.CallTracer
if use_fixtures:
    _load_trusted_module(
        "skylos.plugins.pytest_unused_fixtures",
        fixtures_plugin_path,
    )

import pytest

sys.path.insert(0, project_root)

tracer = CallTracer(exclude_patterns=["site-packages", "venv", ".venv", "pytest", "_pytest"])
tracer.start()

ret = 0
try:
    pytest_args = ["-q"]
    if use_fixtures:
        os.environ["SKYLOS_UNUSED_FIXTURES_OUT"] = fixtures_output
        pytest_args += ["-p", "skylos.plugins.pytest_unused_fixtures"]

    ret = pytest.main(pytest_args)

finally:
    tracer.stop()
    tracer.save(trace_output)

sys.exit(ret)
""")


def _trace_subprocess_command(
    project_root: Path,
    trace_file: Path,
    *,
    pytest_fixtures: bool,
) -> list[str]:
    tracer_module_path = _trusted_module_file("skylos.core.tracer")
    fixtures_plugin_path = (
        _trusted_module_file("skylos.plugins.pytest_unused_fixtures")
        if pytest_fixtures
        else ""
    )
    return [
        sys.executable,
        "-c",
        _trace_subprocess_script(),
        str(project_root),
        str(trace_file),
        str(tracer_module_path),
        str(project_root / ".skylos_unused_fixtures.json"),
        str(fixtures_plugin_path),
        "1" if pytest_fixtures else "0",
    ]


def _coverage_execution_allowed(args) -> bool:
    return bool(getattr(args, "allow_coverage_execution", False))


def _run_pre_analysis_steps(args, project_root, console):
    pytest_fixtures_ok = None
    trace_file_for_analysis = None
    quiet_output = _is_main_machine_output(args)

    if args.coverage:
        if not _coverage_execution_allowed(args):
            if not quiet_output:
                console.print(
                    "[warn]Skipping --coverage test execution. "
                    "Re-run with --allow-coverage-execution only for trusted repositories.[/warn]"
                )
        else:
            if not quiet_output:
                console.print("[brand]Running tests with coverage...[/brand]")

            cmd = ["coverage", "run", "-m", "pytest", "-q"]
            env = os.environ.copy()

            if args.pytest_fixtures:
                env["SKYLOS_UNUSED_FIXTURES_OUT"] = str(
                    project_root / ".skylos_unused_fixtures.json"
                )
                cmd += ["-p", "skylos.plugins.pytest_unused_fixtures"]

            pytest_result = subprocess.run(
                cmd,
                cwd=project_root,
                capture_output=True,
                env=env,
            )

            if pytest_result.returncode != 0:
                if not quiet_output:
                    console.print("[warn]pytest failed, trying unittest...[/warn]")
                subprocess.run(
                    ["coverage", "run", "-m", "unittest", "discover"],
                    cwd=project_root,
                    capture_output=True,
                )

            if not quiet_output:
                console.print("[good]Coverage data collected[/good]")

    if args.trace:
        if not quiet_output:
            console.print("[brand]Running tests with call tracing...[/brand]")

        trace_file = project_root / ".skylos_trace"
        trace_cache_enabled = _trace_cache_requested(args)
        trace_cache_key = None
        trace_cache_fingerprint = None
        trace_cache_hit = False

        if trace_cache_enabled:
            trace_cache_key, trace_cache_fingerprint = build_trace_cache_key(
                project_root,
                args.path,
                pytest_args=["-q"],
                pytest_fixtures=bool(args.pytest_fixtures),
                return_fingerprint=True,
            )
            if not getattr(args, "refresh_cache", False):
                cached_entry = load_trace_cache(project_root, trace_cache_key)
                if cached_entry is not None:
                    write_trace_payload(trace_file, cached_entry["trace"])
                    trace_file_for_analysis = trace_file
                    trace_cache_hit = True
                    if not quiet_output:
                        console.print(
                            "[brand]Trace cache hit:[/brand] reusing cached pytest call trace."
                        )

        if not trace_cache_hit:
            try:
                trace_file.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

            trace_result = subprocess.run(
                _trace_subprocess_command(
                    project_root,
                    trace_file,
                    pytest_fixtures=bool(args.pytest_fixtures),
                ),
                cwd=project_root,
                capture_output=True,
                text=True,
            )

            trace_payload = read_trace_payload(trace_file)
            if trace_payload is not None:
                trace_file_for_analysis = trace_file
            else:
                trace_file_for_analysis = False

            if trace_result.returncode != 0 and not quiet_output:
                if trace_payload is not None:
                    console.print(
                        "[warn]Tests had failures, but trace data was collected.[/warn]"
                    )
                else:
                    console.print(
                        "[warn]Trace run failed; continuing without trace.[/warn]"
                    )
                    if trace_result.stderr:
                        console.print(trace_result.stderr)
            elif trace_payload is None and not quiet_output:
                console.print(
                    "[warn]Trace run completed but no usable trace was produced.[/warn]"
                )
            elif not quiet_output:
                console.print("[good]Trace data collected[/good]")

            if (
                trace_cache_enabled
                and trace_cache_key is not None
                and trace_payload is not None
                and trace_result.returncode == 0
            ):
                save_trace_cache(
                    project_root,
                    trace_cache_key,
                    trace_payload,
                    pytest_returncode=trace_result.returncode,
                    fingerprint_summary=trace_cache_fingerprint,
                )

    if args.pytest_fixtures and (not args.coverage) and (not args.trace):
        if not quiet_output:
            console.print(
                "[brand]Running tests to detect unused pytest fixtures...[/brand]"
            )

        env = os.environ.copy()
        env["SKYLOS_UNUSED_FIXTURES_OUT"] = str(
            project_root / ".skylos_unused_fixtures.json"
        )

        pytest_targets = []
        if len(args.path) == 1:
            path = pathlib.Path(args.path[0]).resolve()
            if path.is_file():
                pytest_targets = [str(path)]

        fixture_result = subprocess.run(
            [
                "pytest",
                "-q",
                *pytest_targets,
                "-p",
                "skylos.plugins.pytest_unused_fixtures",
            ],
            cwd=project_root,
            capture_output=True,
            text=True,
            env=env,
        )

        pytest_fixtures_ok = fixture_result.returncode == 0

        if not quiet_output:
            if pytest_fixtures_ok:
                console.print("[good]Unused fixture report collected[/good]")
            else:
                console.print(
                    "[warn]pytest had failures; unused fixture report may be partial[/warn]"
                )

    custom_rules_data = None
    if not quiet_output:
        try:
            from skylos.cloud.sync import get_custom_rules, get_token

            token = get_token()
            if token:
                custom_rules_data = get_custom_rules()
                if custom_rules_data:
                    console.print(
                        f"[brand]Loaded {len(custom_rules_data)} custom rules from cloud[/brand]"
                    )
        except Exception as e:
            if args.verbose:
                console.print(f"[warn]Could not load custom rules: {e}[/warn]")

    changed_files = None
    if getattr(args, "diff_base", None):
        try:
            os.environ["SKYLOS_DIFF_BASE"] = args.diff_base
            diff_result = subprocess.run(
                ["git", "diff", "--name-only", f"{args.diff_base}...HEAD"],
                cwd=project_root,
                capture_output=True,
                text=True,
            )
            if diff_result.returncode == 0:
                changed_files = set()
                for line in diff_result.stdout.strip().splitlines():
                    changed_files.add(str((project_root / line).resolve()))
                if not quiet_output:
                    console.print(
                        f"[brand]--diff-base:[/brand] {len(changed_files)} changed files "
                        f"(full scan on changed, defs/refs-only on rest)"
                    )
            elif not quiet_output:
                console.print(
                    f"[warn]git diff failed: {diff_result.stderr.strip()}. "
                    f"Running full analysis.[/warn]"
                )
        except FileNotFoundError:
            if not quiet_output:
                console.print("[warn]git not found. Running full analysis.[/warn]")

    return SimpleNamespace(
        pytest_fixtures_ok=pytest_fixtures_ok,
        custom_rules_data=custom_rules_data,
        changed_files=changed_files,
        trace_file=trace_file_for_analysis,
    )


def _add_agent_model_arg(parser, *, default=DEFAULT_AGENT_MODEL):
    parser.add_argument("--model", default=default)


def _add_agent_output_arg(parser):
    parser.add_argument("--output", "-o", help="Output file")


def _add_agent_quiet_arg(parser):
    parser.add_argument("--quiet", "-q", action="store_true")


def _add_agent_provider_arg(parser):
    parser.add_argument(
        "--provider",
        choices=AGENT_PROVIDER_CHOICES,
        default=None,
        help=AGENT_PROVIDER_HELP,
    )


def _add_agent_base_url_arg(parser):
    parser.add_argument(
        "--base-url",
        default=None,
        help=AGENT_BASE_URL_HELP,
    )


PROMPT_TEMPLATE_KINDS = {"security", "quality", "security_audit", "review"}


def _add_agent_prompt_template_arg(parser):
    parser.add_argument(
        "--prompt-template",
        action="append",
        default=None,
        metavar="KIND=PATH",
        help=(
            "Trusted prompt template file to append. KIND must be one of "
            "security, quality, security_audit, or review. Repeatable."
        ),
    )


def _add_agent_security_quick_args(parser):
    parser.add_argument(
        "path", nargs="?", default=".", help="File or directory to analyze"
    )
    _add_agent_model_arg(parser)
    parser.add_argument(
        "--format", choices=["table", "tree", "json", "sarif"], default="table"
    )
    _add_agent_output_arg(parser)
    _add_agent_quiet_arg(parser)
    _add_agent_provider_arg(parser)
    _add_agent_base_url_arg(parser)
    _add_agent_prompt_template_arg(parser)
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Interactive file selection",
    )


def _add_agent_security_deep_args(parser):
    parser.add_argument("path", nargs="?", default=".")
    _add_agent_model_arg(parser)
    _add_agent_provider_arg(parser)
    _add_agent_base_url_arg(parser)
    _add_agent_prompt_template_arg(parser)
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help=(
            "Stage 1 only: update static threat-model/candidate state without "
            "LLM calls"
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume pending Deep Mode processing work",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force Deep Mode reprocessing for already analyzed files",
    )
    parser.add_argument(
        "--changed",
        action="store_true",
        help="Restrict Deep Mode security work to git-changed files",
    )
    parser.add_argument(
        "--base",
        default=None,
        help="Base ref for changed-file scans",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit Deep Mode agent processing; scan-only records all candidates",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit 1 when Deep Mode work at or above this severity remains",
    )
    parser.add_argument(
        "--revalidate",
        action="store_true",
        help="Stage 2 validation: revalidate stored Deep Mode findings",
    )
    parser.add_argument(
        "--challenge",
        action="store_true",
        help="Challenge prior uncertain Deep Mode revalidation verdicts",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "sarif", "md", "markdown", "md-dir"],
        default="table",
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Filter Deep Mode export entries to this severity or higher",
    )
    parser.add_argument(
        "--verdict",
        action="append",
        choices=[
            "true_positive",
            "false_positive",
            "fixed",
            "uncertain",
            "pending",
            "not_analyzed",
            "error",
            "skipped",
            "deleted",
        ],
        help="Filter Deep Mode export entries by verdict/status",
    )
    parser.add_argument(
        "--include-deleted",
        action="store_true",
        help="Include deleted Deep Mode audit records in exports",
    )
    parser.add_argument("--out", "--output", "-o", dest="output")
    _add_agent_quiet_arg(parser)


def _security_deep_workflow_payload(
    *,
    mode: str,
    summary,
    process_summary=None,
    revalidation_summary=None,
):
    discovery_status = "queued"
    discovery_detail = "Static candidates were recorded for later agent processing."
    if process_summary is not None:
        discovery_status = "completed" if process_summary.complete else "incomplete"
        discovery_detail = (
            f"Processed {process_summary.processed_files} file(s), "
            f"added {process_summary.findings_added} finding(s)."
        )
    elif revalidation_summary is not None:
        discovery_status = (
            "completed" if revalidation_summary.complete else "incomplete"
        )
        discovery_detail = (
            f"Revalidated {revalidation_summary.revalidated_findings} finding(s), "
            f"challenged {revalidation_summary.challenged_findings}."
        )

    remediation_status = "handoff"
    remediation_detail = (
        "Validated findings are kept in Deep Mode state/export formats; patch "
        "application remains explicit through `skylos agent remediate`."
    )
    if process_summary is None and revalidation_summary is None:
        remediation_status = "pending" if summary.candidate_count else "not_needed"
        remediation_detail = (
            "Run `skylos agent security-deep` without `--scan-only` or run "
            "`--revalidate` before remediation."
        )
    if summary.candidate_count == 0 and process_summary is None:
        remediation_status = "not_needed"
        remediation_detail = "No Deep Mode security candidates were found."

    return {
        "name": "security-deep",
        "compatibility": (
            "Equivalent to `skylos agent audit --deep` with clearer workflow "
            "naming."
        ),
        "mode": mode,
        "stages": [
            {
                "number": 1,
                "name": "threat_model_context",
                "status": "completed",
                "detail": (
                    f"Scanned {summary.files_scanned} file(s), recorded "
                    f"{summary.candidate_count} security candidate(s), and "
                    "updated persisted Deep Mode project context."
                ),
            },
            {
                "number": 2,
                "name": "discovery_validation",
                "status": discovery_status,
                "detail": discovery_detail,
            },
            {
                "number": 3,
                "name": "remediation_handoff",
                "status": remediation_status,
                "detail": remediation_detail,
            },
        ],
    }


def _print_security_deep_workflow(console, workflow):
    console.print("[brand]Security Deep stages:[/brand]")
    for stage in workflow.get("stages", []):
        console.print(
            f"  Stage {stage['number']}: {stage['name']} "
            f"({stage['status']})"
        )


def _explicit_prompt_templates_from_args(agent_args, console):
    values = list(getattr(agent_args, "prompt_template", None) or [])
    if not values:
        return None, None

    templates = {}
    for raw_value in values:
        if "=" not in raw_value:
            console.print(
                "[bad]--prompt-template must use KIND=PATH, for example "
                "security_audit=/trusted/templates/audit.md[/bad]"
            )
            sys.exit(2)

        kind, raw_path = raw_value.split("=", 1)
        kind = kind.strip()
        raw_path = raw_path.strip()
        if kind not in PROMPT_TEMPLATE_KINDS:
            valid = ", ".join(sorted(PROMPT_TEMPLATE_KINDS))
            console.print(
                f"[bad]Unknown prompt template kind '{kind}'. Valid: {valid}[/bad]"
            )
            sys.exit(2)
        if not raw_path:
            console.print("[bad]--prompt-template path must not be empty[/bad]")
            sys.exit(2)

        path = pathlib.Path(raw_path).expanduser()
        if not path.is_absolute():
            path = pathlib.Path.cwd() / path
        if path.is_symlink():
            console.print(
                f"[bad]Prompt template must not be a symlink: {raw_path}[/bad]"
            )
            sys.exit(2)
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            console.print(f"[bad]Prompt template not found: {raw_path}[/bad]")
            sys.exit(2)
        if not resolved.is_file():
            console.print(f"[bad]Prompt template is not a file: {raw_path}[/bad]")
            sys.exit(2)

        templates[kind] = str(resolved)

    return templates, pathlib.Path("/")


def _build_agent_parser():
    agent_parser = argparse.ArgumentParser(prog="skylos agent")
    agent_sub = agent_parser.add_subparsers(dest="agent_cmd", required=True)

    p_scan = agent_sub.add_parser("scan", help="Hybrid analysis (static + LLM)")
    p_scan.add_argument(
        "path", nargs="?", default=".", help="File or directory to analyze"
    )
    _add_agent_model_arg(p_scan)
    p_scan.add_argument(
        "--format", choices=["table", "tree", "json", "sarif"], default="table"
    )
    _add_agent_output_arg(p_scan)
    p_scan.add_argument(
        "--min-confidence", choices=["high", "medium", "low"], default="low"
    )
    p_scan.add_argument(
        "--llm-only", action="store_true", help="Skip static, run LLM only"
    )
    _add_agent_quiet_arg(p_scan)
    _add_agent_provider_arg(p_scan)
    _add_agent_base_url_arg(p_scan)
    _add_agent_prompt_template_arg(p_scan)
    p_scan.add_argument(
        "--upload",
        action="store_true",
        help="Upload results to skylos.dev dashboard",
    )
    p_scan.add_argument(
        "--force",
        action="store_true",
        help="Force upload even if quality gate fails",
    )
    p_scan.add_argument(
        "--strict",
        action="store_true",
        help="Exit with error code if findings are reported",
    )
    p_scan.add_argument(
        "--verification-mode",
        choices=["judge_all", "production"],
        default="production",
        help="Dead-code verifier mode when --verify-dead-code is enabled",
    )
    p_scan.add_argument(
        "--verify-dead-code",
        action="store_true",
        help="Run the slower LLM dead-code verification pass before showing final results",
    )
    p_scan.add_argument(
        "--with-fixes",
        action="store_true",
        help="Generate fix suggestions for findings (slower)",
    )
    p_scan.add_argument(
        "--no-fixes",
        action="store_true",
        help="Disable fix suggestions (compatibility alias; fixes are off by default)",
    )
    p_scan.add_argument(
        "--changed",
        action="store_true",
        help="Analyze only git-changed files",
    )
    p_scan.add_argument(
        "--security",
        action="store_true",
        help="Security-only LLM audit mode",
    )
    p_scan.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Interactive file selection (with --security)",
    )

    p_audit = agent_sub.add_parser(
        "audit",
        help="Deep security audit state and candidate workflow",
    )
    p_audit.add_argument("path", nargs="?", default=".")
    _add_agent_model_arg(p_audit)
    _add_agent_provider_arg(p_audit)
    _add_agent_base_url_arg(p_audit)
    _add_agent_prompt_template_arg(p_audit)
    p_audit.add_argument(
        "--deep",
        action="store_true",
        help="Enable the explicit Deep Mode audit workflow",
    )
    p_audit.add_argument(
        "--scan-only",
        action="store_true",
        help="Create/update static audit candidates without LLM calls",
    )
    p_audit.add_argument(
        "--resume",
        action="store_true",
        help="Resume pending Deep Mode processing work",
    )
    p_audit.add_argument(
        "--force",
        action="store_true",
        help="Force Deep Mode reprocessing for already analyzed files",
    )
    p_audit.add_argument(
        "--changed",
        action="store_true",
        help="Restrict Deep Mode audit work to git-changed files",
    )
    p_audit.add_argument(
        "--base",
        default=None,
        help="Base ref for changed-file scans",
    )
    p_audit.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit Deep Mode agent processing; scan-only records all candidates",
    )
    p_audit.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit 1 when Deep Mode work at or above this severity remains",
    )
    p_audit.add_argument(
        "--revalidate",
        action="store_true",
        help="Persistently revalidate stored Deep Mode findings",
    )
    p_audit.add_argument(
        "--challenge",
        action="store_true",
        help="Challenge prior uncertain Deep Mode revalidation verdicts",
    )
    p_audit.add_argument(
        "--format",
        choices=["table", "json", "sarif", "md", "markdown", "md-dir"],
        default="table",
    )
    p_audit.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Filter Deep Mode export entries to this severity or higher",
    )
    p_audit.add_argument(
        "--verdict",
        action="append",
        choices=[
            "true_positive",
            "false_positive",
            "fixed",
            "uncertain",
            "pending",
            "not_analyzed",
            "error",
            "skipped",
            "deleted",
        ],
        help="Filter Deep Mode export entries by verdict/status",
    )
    p_audit.add_argument(
        "--include-deleted",
        action="store_true",
        help="Include deleted Deep Mode audit records in exports",
    )
    p_audit.add_argument("--out", "--output", "-o", dest="output")
    _add_agent_quiet_arg(p_audit)

    p_security_quick = agent_sub.add_parser(
        "security-quick",
        help="Quick one-shot LLM security audit (alias for scan --security)",
    )
    _add_agent_security_quick_args(p_security_quick)

    p_security_deep = agent_sub.add_parser(
        "security-deep",
        help=(
            "Three-stage security workflow: threat model/context, "
            "discovery/validation, and remediation handoff"
        ),
    )
    _add_agent_security_deep_args(p_security_deep)

    p_remediate = agent_sub.add_parser(
        "remediate",
        help="Scan, fix, optionally test, and create PR for security/quality issues",
    )
    p_remediate.add_argument("path", nargs="?", default=".")
    _add_agent_model_arg(p_remediate)
    p_remediate.add_argument(
        "--max-fixes",
        type=int,
        default=10,
        help="Maximum number of findings to fix (default: 10)",
    )
    p_remediate.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be fixed without applying changes",
    )
    p_remediate.add_argument(
        "--auto-pr",
        action="store_true",
        help="Automatically create a PR with fixes",
    )
    p_remediate.add_argument(
        "--branch-prefix", default="skylos/fix", help="Git branch prefix"
    )
    p_remediate.add_argument(
        "--test-cmd",
        default=None,
        help="Trusted custom test command to run without a shell",
    )
    p_remediate.add_argument(
        "--auto-test",
        action="store_true",
        help="Opt in to auto-detected project tests after applying fixes",
    )
    p_remediate.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Only fix findings at or above this severity",
    )
    p_remediate.add_argument(
        "--standards",
        nargs="?",
        const="__builtin__",
        default=None,
        help="Enable LLM-guided cleanup mode (optional: path to custom standards .md file)",
    )
    _add_agent_quiet_arg(p_remediate)
    _add_agent_provider_arg(p_remediate)
    _add_agent_base_url_arg(p_remediate)

    p_verify = agent_sub.add_parser(
        "verify",
        help="LLM-verify dead code findings (reduce false positives, catch more dead code)",
    )
    p_verify.add_argument("path", help="File or directory to analyze")
    _add_agent_model_arg(p_verify)
    p_verify.add_argument(
        "--conf", type=int, default=60, help="Static analysis confidence threshold"
    )
    p_verify.add_argument(
        "--max-verify",
        type=int,
        default=50,
        help="Max findings to verify with LLM (default: 50)",
    )
    p_verify.add_argument(
        "--max-challenge",
        type=int,
        default=20,
        help="Max survivors to challenge with LLM (default: 20)",
    )
    p_verify.add_argument(
        "--no-entry-discovery",
        action="store_true",
        help="Skip entry point discovery pass",
    )
    p_verify.add_argument(
        "--no-survivor-challenge",
        action="store_true",
        help="Skip survivor challenge pass",
    )
    p_verify.add_argument(
        "--verification-mode",
        choices=["judge_all", "production"],
        default="judge_all",
        help="Dead-code verifier mode: judge_all sends nearly every refs==0 candidate to the LLM",
    )
    p_verify.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )
    _add_agent_output_arg(p_verify)
    _add_agent_quiet_arg(p_verify)
    _add_agent_provider_arg(p_verify)
    _add_agent_base_url_arg(p_verify)
    p_verify.add_argument(
        "--grep-workers",
        type=int,
        default=4,
        help="Number of parallel grep workers (default: 4)",
    )
    p_verify.add_argument(
        "--parallel-grep",
        action="store_true",
        help="Enable parallel grep execution for faster verification",
    )
    p_verify.add_argument(
        "--fix",
        action="store_true",
        help="Generate removal patches for confirmed dead code",
    )
    p_verify.add_argument(
        "--fix-mode",
        choices=["delete", "comment"],
        default="delete",
        help="Fix mode: delete removes code, comment comments it out (default: delete)",
    )
    p_verify.add_argument(
        "--apply",
        action="store_true",
        help="Apply generated patches (use with --fix)",
    )
    p_verify.add_argument(
        "--pr",
        action="store_true",
        help="Create a branch, apply patches, and commit (use with --fix)",
    )

    p_watch = agent_sub.add_parser(
        "watch",
        help="Continuously maintain active-agent state for a repository",
    )
    p_watch.add_argument("path", nargs="?", default=".")
    p_watch.add_argument("--interval", type=float, default=5.0)
    p_watch.add_argument(
        "--cycles",
        type=int,
        default=0,
        help="Number of refresh cycles to run (0 means keep watching)",
    )
    p_watch.add_argument("--once", action="store_true")
    p_watch.add_argument("--conf", type=int, default=80)
    p_watch.add_argument("--no-baseline", action="store_true")
    p_watch.add_argument("--state-file", default=None)
    p_watch.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )
    p_watch.add_argument("--limit", type=int, default=10)
    p_watch.add_argument(
        "--learn", action="store_true", help="Enable triage pattern learning"
    )

    p_precommit = agent_sub.add_parser(
        "pre-commit",
        help="Staged local hook: security, secrets, and quality for staged source/config files",
    )
    p_precommit.add_argument("path", nargs="?", default=".")
    p_precommit.add_argument("--conf", type=int, default=80)
    p_precommit.add_argument("--state-file", default=None, help=argparse.SUPPRESS)
    p_precommit.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )

    p_triage = agent_sub.add_parser(
        "triage",
        help="Manage finding triage (suggest, dismiss, snooze, restore)",
    )
    triage_sub = p_triage.add_subparsers(dest="triage_cmd", required=True)

    t_suggest = triage_sub.add_parser(
        "suggest",
        help="Show auto-triage candidates based on learned patterns",
    )
    t_suggest.add_argument("path", nargs="?", default=".")
    t_suggest.add_argument("--state-file", default=None)
    t_suggest.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )

    t_dismiss = triage_sub.add_parser(
        "dismiss",
        help="Dismiss a ranked action",
    )
    t_dismiss.add_argument("path", nargs="?", default=".")
    t_dismiss.add_argument("action_id")
    t_dismiss.add_argument("--state-file", default=None)
    t_dismiss.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )
    t_dismiss.add_argument("--limit", type=int, default=10)

    t_snooze = triage_sub.add_parser(
        "snooze",
        help="Temporarily snooze a ranked action",
    )
    t_snooze.add_argument("path", nargs="?", default=".")
    t_snooze.add_argument("action_id")
    t_snooze.add_argument("--hours", type=float, default=24.0)
    t_snooze.add_argument("--state-file", default=None)
    t_snooze.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )
    t_snooze.add_argument("--limit", type=int, default=10)

    t_restore = triage_sub.add_parser(
        "restore",
        help="Restore a dismissed or snoozed action",
    )
    t_restore.add_argument("path", nargs="?", default=".")
    t_restore.add_argument("action_id")
    t_restore.add_argument("--state-file", default=None)
    t_restore.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )
    t_restore.add_argument("--limit", type=int, default=10)

    p_status = agent_sub.add_parser(
        "status",
        help="Show the latest active-agent summary",
    )
    p_status.add_argument("path", nargs="?", default=".")
    p_status.add_argument("--state-file", default=None)
    p_status.add_argument("--refresh", action="store_true")
    p_status.add_argument("--conf", type=int, default=80)
    p_status.add_argument("--no-baseline", action="store_true")
    p_status.add_argument(
        "--format",
        choices=["table", "json", "feed"],
        default="table",
    )
    p_status.add_argument("--limit", type=int, default=10)

    p_serve = agent_sub.add_parser(
        "serve",
        help="Run a local cross-platform HTTP API for the active-agent state",
    )
    p_serve.add_argument("path", nargs="?", default=".")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=5089)
    p_serve.add_argument("--token", default=None)
    p_serve.add_argument("--state-file", default=None)
    p_serve.add_argument("--conf", type=int, default=80)
    p_serve.add_argument("--no-baseline", action="store_true")
    p_serve.add_argument("--limit", type=int, default=10)
    p_serve.add_argument("--refresh-on-start", action="store_true")
    p_serve.add_argument(
        "--allowed-origin",
        dest="allowed_origins",
        action="append",
        default=None,
        help="Trusted browser origin for the agent API CORS allow-list. Repeatable.",
    )

    return agent_parser


def main() -> None:
    """
    Dispatch top-level skylos CLI command.

    Calls: skylos/cli_core/dispatch.py _dispatch_early_command;
        skylos/cli.py _build_agent_parser; skylos/cli.py _run_scan_command;
        skylos/cli.py _run_web_server_command; skylos/cli.py run_pipeline.

    Called from: pyproject.toml skylos; skylos/cli.py __main__.
    """
    dispatch_result = _dispatch_early_command(sys.argv[1:])
    if dispatch_result is not None:
        sys.exit(dispatch_result)

    if len(sys.argv) > 1 and sys.argv[1] == "agent":
        # from skylos.llm.merger import merge_findings
        agent_parser = _build_agent_parser()
        agent_args = agent_parser.parse_args(sys.argv[2:])
        console = Console()
        cmd = agent_args.agent_cmd
        if cmd == "security-quick":
            agent_args.security = True
            agent_args.agent_cmd = "scan"
            agent_args.security_workflow_alias = "security-quick"
            cmd = "scan"
        elif cmd == "security-deep":
            agent_args.deep = True
            agent_args.agent_cmd = "audit"
            agent_args.security_workflow_alias = "security-deep"
            cmd = "audit"

        if cmd in {"watch", "pre-commit", "triage", "status", "serve"}:
            from skylos.agents.center import (
                clear_action_triage,
                command_center_payload,
                load_agent_state,
                normalize_findings,
                refresh_agent_state,
                render_status_table,
                update_action_triage,
                watch_project,
            )

            def _print_agent_table(state, limit):
                rendered = render_status_table(state, limit=limit)
                console.print(f"[bold]{rendered['headline']}[/bold]")
                if rendered["subtitle"]:
                    console.print(f"[dim]{rendered['subtitle']}[/dim]")

                actions = rendered["actions"]
                if not actions:
                    console.print("[green]No ranked actions.[/green]")
                    return

                table = Table(title="Active Agent Queue", expand=True)
                table.add_column("#", style="dim", width=3)
                table.add_column("Severity", width=9)
                table.add_column("Category", width=10)
                table.add_column("Action")
                table.add_column("Location", style="dim", width=28)
                table.add_column("Reason", overflow="fold")

                for idx, action in enumerate(actions[:limit], 1):
                    table.add_row(
                        str(idx),
                        str(action.get("severity", "")),
                        str(action.get("category", "")),
                        str(action.get("title", "")),
                        f"{action.get('file', '?')}:{action.get('line', '?')}",
                        str(action.get("reason", "")),
                    )
                console.print(table)

            def _resolve_state(refresh=False):
                state = (
                    None
                    if refresh
                    else load_agent_state(
                        agent_args.path,
                        state_file=getattr(agent_args, "state_file", None),
                    )
                )
                if state is None:
                    state, _ = refresh_agent_state(
                        agent_args.path,
                        conf=getattr(agent_args, "conf", 80),
                        use_baseline=not getattr(agent_args, "no_baseline", False),
                        state_file=getattr(agent_args, "state_file", None),
                        force=True,
                    )
                return state

            if cmd == "watch":
                state = watch_project(
                    agent_args.path,
                    interval=agent_args.interval,
                    cycles=None if agent_args.cycles == 0 else agent_args.cycles,
                    once=agent_args.once,
                    conf=agent_args.conf,
                    use_baseline=not agent_args.no_baseline,
                    state_file=agent_args.state_file,
                    enable_learning=agent_args.learn,
                )
                if agent_args.format == "json":
                    print(json.dumps(state, indent=2, default=str))
                else:
                    _print_agent_table(state, agent_args.limit)
                sys.exit(0)

            if cmd == "pre-commit":
                import subprocess as _sp
                from skylos.core.baseline import filter_new_findings, load_baseline

                source_exts = {
                    ".py",
                    ".go",
                    ".ts",
                    ".tsx",
                    ".js",
                    ".jsx",
                    ".mts",
                    ".cts",
                    ".mjs",
                    ".cjs",
                    ".java",
                    ".php",
                    ".rs",
                    ".dart",
                    ".kt",
                    ".kts",
                }
                config_exts = {
                    ".yaml",
                    ".yml",
                    ".json",
                    ".toml",
                    ".ini",
                    ".cfg",
                    ".conf",
                }

                def _is_config_candidate(path: Path) -> bool:
                    name = path.name.lower()
                    if name == ".env" or name.startswith(".env."):
                        return True
                    return path.suffix.lower() in config_exts

                project_root = find_project_root(agent_args.path)
                staged_result = _sp.run(
                    ["git", "diff", "--cached", "--name-only"],
                    capture_output=True,
                    text=True,
                    cwd=project_root,
                )
                staged_candidates = [
                    f.strip()
                    for f in staged_result.stdout.strip().splitlines()
                    if f.strip()
                ]
                if not staged_candidates:
                    console.print("[good]No staged files to analyze[/good]")
                    sys.exit(0)

                staged_source_files = []
                staged_config_files = []
                staged_secret_only_files = {
                    "test": [],
                    "benchmark": [],
                    "example": [],
                }
                analyzer_targets = set()
                report_targets = set()
                skipped_staged_files = 0
                for relpath in staged_candidates:
                    relpath_obj = Path(relpath)
                    if relpath_obj.suffix.lower() in source_exts:
                        kind = get_non_library_dir_kind(relpath_obj, project_root)
                        if kind in staged_secret_only_files:
                            staged_secret_only_files[kind].append(relpath)
                            report_targets.add(str((project_root / relpath).resolve()))
                            continue
                        staged_source_files.append(relpath)
                        abs_path = str((project_root / relpath).resolve())
                        analyzer_targets.add(abs_path)
                        report_targets.add(abs_path)
                        continue
                    if _is_config_candidate(relpath_obj):
                        staged_config_files.append(relpath)
                        abs_path = str((project_root / relpath).resolve())
                        analyzer_targets.add(abs_path)
                        report_targets.add(abs_path)
                        continue
                    skipped_staged_files += 1

                if not report_targets:
                    notes = []
                    if skipped_staged_files:
                        notes.append(
                            f"skipped {skipped_staged_files} unsupported staged file(s)"
                        )
                    if notes:
                        console.print(
                            "[good]No staged source or config files to analyze[/good] "
                            f"[dim]({' ; '.join(notes)})[/dim]"
                        )
                    else:
                        console.print(
                            "[good]No staged source or config files to analyze[/good]"
                        )
                    sys.exit(0)

                changed_ranges = _get_cached_changed_line_ranges(
                    project_root,
                    staged_source_files
                    + staged_config_files
                    + [
                        relpath
                        for paths in staged_secret_only_files.values()
                        for relpath in paths
                    ],
                )
                snapshot_dir = None
                analysis_root = project_root
                analysis_targets = analyzer_targets
                analysis_source_paths = [
                    str((project_root / relpath).resolve())
                    for relpath in staged_source_files
                ]
                snapshot_note = ""

                def _is_relevant_analysis_path(path: Path) -> bool:
                    return path.suffix.lower() in source_exts or _is_config_candidate(
                        path
                    )

                if staged_source_files:
                    unstaged_relevant = _list_dirty_relevant_paths(
                        project_root, _is_relevant_analysis_path
                    )
                    if unstaged_relevant:
                        snapshot_dir, snapshot_root = _create_precommit_snapshot(
                            project_root
                        )
                        if snapshot_root is not None:
                            analysis_root = snapshot_root
                            analysis_targets = {
                                str((analysis_root / relpath).resolve())
                                for relpath in staged_source_files + staged_config_files
                            }
                            analysis_source_paths = [
                                str((analysis_root / relpath).resolve())
                                for relpath in staged_source_files
                            ]
                            snapshot_note = (
                                " Using staged git snapshot for exact commit results."
                            )
                        else:
                            snapshot_note = " Exact staged snapshot unavailable; using working tree context."

                exclude_folders = parse_exclude_folders(
                    use_defaults=True,
                    config_exclude_folders=load_config(analysis_root).get("exclude"),
                )
                baseline = load_baseline(project_root)
                analyzer_logger = logging.getLogger("Skylos")
                analyzer_logger_level = analyzer_logger.level

                try:
                    if agent_args.format != "json":
                        scope_parts = []
                        if staged_source_files:
                            scope_parts.append(f"{len(staged_source_files)} source")
                        if staged_config_files:
                            scope_parts.append(f"{len(staged_config_files)} config")
                        for kind in ("test", "benchmark", "example"):
                            paths = staged_secret_only_files[kind]
                            if paths:
                                scope_parts.append(f"{len(paths)} {kind}")
                        scope_desc = " and ".join(scope_parts)
                        skipped_note = (
                            f" Skipped {skipped_staged_files} unsupported staged file(s)."
                            if skipped_staged_files
                            else ""
                        )
                        secret_only_kinds = [
                            kind
                            for kind in ("test", "benchmark", "example")
                            if staged_secret_only_files[kind]
                        ]
                        staged_test_note = (
                            " Staged "
                            f"{_join_phrase(secret_only_kinds)} files are secrets-only in local commit checks."
                            if secret_only_kinds
                            else ""
                        )
                        baseline_note = (
                            " Baseline filtering is active." if baseline else ""
                        )
                        mode_note = (
                            " Running secrets check only."
                            if not staged_source_files
                            else ""
                        )
                        scope_note = (
                            "Checks security, secrets, and high-signal quality regressions on production source/config."
                            if staged_source_files
                            else "Checks secrets only."
                        )
                        console.print(
                            "[brand]Commit check:[/brand] "
                            f"reviewing {scope_desc} staged file(s). "
                            f"{scope_note}"
                            f"{mode_note}"
                            f"{snapshot_note}"
                            f"{staged_test_note}"
                            f"{skipped_note}"
                            f"{baseline_note}"
                        )

                    staged_secret_only_secrets = _scan_staged_secret_files(
                        project_root,
                        [
                            relpath
                            for paths in staged_secret_only_files.values()
                            for relpath in paths
                        ],
                        ignore_tests=False,
                    )

                    if not staged_source_files:
                        secrets = _scan_staged_secret_files(
                            project_root,
                            staged_config_files,
                            ignore_tests=True,
                        )
                        secrets.extend(staged_secret_only_secrets)
                        result = {
                            "unused_functions": [],
                            "unused_imports": [],
                            "unused_classes": [],
                            "unused_variables": [],
                            "unused_parameters": [],
                            "unused_files": [],
                            "danger": [],
                            "quality": [],
                            "secrets": secrets,
                            "custom_rules": [],
                        }
                    else:
                        progress_state = {"last": 0}

                        def _update_precommit_progress(current, total, file):
                            if agent_args.format == "json":
                                return
                            step = max(total // 10, 1)
                            should_print = (
                                total <= 20
                                or current == 1
                                or current == total
                                or current - progress_state["last"] >= step
                            )
                            if not should_print:
                                return
                            progress_state["last"] = current
                            console.print(
                                "[muted]Commit check progress:[/muted] "
                                f"[{current}/{total}] {file.name}"
                            )

                        analyzer_logger.setLevel(logging.WARNING)
                        raw_result = run_analyze(
                            analysis_source_paths,
                            conf=agent_args.conf,
                            enable_secrets=True,
                            enable_danger=True,
                            enable_quality=True,
                            exclude_folders=list(exclude_folders),
                            changed_files=analysis_targets,
                            grep_verify=False,
                            progress_callback=_update_precommit_progress,
                        )
                        result = (
                            json.loads(raw_result)
                            if isinstance(raw_result, str)
                            else raw_result
                        )
                        if staged_secret_only_secrets:
                            result["secrets"] = list(result.get("secrets") or [])
                            result["secrets"].extend(staged_secret_only_secrets)
                        result = _remap_precommit_result_files(
                            result, analysis_root, project_root
                        )
                finally:
                    analyzer_logger.setLevel(analyzer_logger_level)
                    if snapshot_dir is not None:
                        snapshot_dir.cleanup()

                if baseline is not None:
                    result = filter_new_findings(result, baseline)

                for category in [
                    "unused_functions",
                    "unused_imports",
                    "unused_classes",
                    "unused_variables",
                    "unused_parameters",
                    "unused_files",
                    "danger",
                    "quality",
                    "secrets",
                    "custom_rules",
                ]:
                    items = result.get(category, [])
                    if items:
                        result[category] = [
                            item
                            for item in items
                            if str((project_root / item.get("file", "")).resolve())
                            in report_targets
                        ]

                staged_findings = normalize_findings(
                    result,
                    project_root,
                    changed_files=(
                        staged_source_files
                        + staged_config_files
                        + [
                            relpath
                            for paths in staged_secret_only_files.values()
                            for relpath in paths
                        ]
                    ),
                    include_dead_code=False,
                )
                staged_findings = [
                    finding
                    for finding in staged_findings
                    if str(finding.get("category", "")).lower() != "debt"
                ]
                staged_findings = _filter_precommit_findings_to_changed_lines(
                    staged_findings, changed_ranges
                )
                staged_findings, suppressed_local_findings = (
                    _apply_precommit_gate_policy(staged_findings)
                )
                if staged_findings:
                    if agent_args.format == "json":
                        print(json.dumps(staged_findings, indent=2, default=str))
                    else:
                        category_counts = {"security": 0, "secrets": 0, "quality": 0}
                        for finding in staged_findings:
                            category = str(finding.get("category", "")).lower()
                            if category in category_counts:
                                category_counts[category] += 1
                        count_bits = [
                            f"{count} {name}"
                            for name, count in category_counts.items()
                            if count
                        ]
                        count_suffix = (
                            f" ({', '.join(count_bits)})" if count_bits else ""
                        )
                        console.print(
                            f"[warn]{len(staged_findings)} issue(s) found in staged files{count_suffix}:[/warn]"
                        )
                        for f in staged_findings[:20]:
                            sev = f.get("severity", "INFO")
                            console.print(
                                f"  [{sev.lower()}]{sev}[/{sev.lower()}] {f['file']}:{f['line']} {f['message']}"
                            )
                        console.print(
                            "[dim]Scope: staged files only. Full repo and diff-aware enforcement run in CI.[/dim]"
                        )
                        console.print(
                            "[dim]Next: fix the issues below and commit again. "
                            "Use `skylos .` for a full local scan when needed.[/dim]"
                        )
                        console.print(
                            "[dim]Note: this hook blocked the commit before Git created a new commit. "
                            "If you push now, GitHub will still show this branch as identical to main.[/dim]"
                        )
                    sys.exit(1)
                if suppressed_local_findings and agent_args.format != "json":
                    console.print(
                        "[dim]Local pre-commit suppressed "
                        f"{suppressed_local_findings} non-blocking quality finding(s); "
                        "full quality enforcement still runs in CI.[/dim]"
                    )
                console.print(
                    "[good]No staged security, secrets, or quality issues[/good]"
                )
                sys.exit(0)

            if cmd == "triage":
                tcmd = agent_args.triage_cmd

                if tcmd == "suggest":
                    from skylos.agents.triage_learner import TriageLearner

                    project_root = find_project_root(agent_args.path)
                    learner = TriageLearner()
                    learner.load(str(project_root))

                    state = load_agent_state(
                        project_root, state_file=agent_args.state_file
                    )
                    if not state:
                        console.print(
                            "[dim]No agent state found. Run 'skylos agent watch --once' first.[/dim]"
                        )
                        sys.exit(1)

                    findings = state.get("findings", [])
                    candidates = learner.get_auto_triage_candidates(findings)

                    if not candidates:
                        console.print(
                            "[dim]No auto-triage candidates (need more observations)[/dim]"
                        )
                        sys.exit(0)

                    if agent_args.format == "json":
                        out = [
                            {"finding": f, "action": a, "confidence": c}
                            for f, a, c in candidates
                        ]
                        print(json.dumps(out, indent=2, default=str))
                    else:
                        console.print(
                            f"[brand]Auto-triage candidates ({len(candidates)}):[/brand]"
                        )
                        for finding, action, confidence in candidates:
                            console.print(
                                f"  {action.upper()} ({confidence:.0%}) "
                                f"{finding.get('file', '?')}:{finding.get('line', '?')} "
                                f"{finding.get('message', '?')}"
                            )
                    sys.exit(0)

                if tcmd == "dismiss":
                    state = update_action_triage(
                        agent_args.path,
                        agent_args.action_id,
                        status="dismissed",
                        state_file=agent_args.state_file,
                    )
                elif tcmd == "snooze":
                    state = update_action_triage(
                        agent_args.path,
                        agent_args.action_id,
                        status="snoozed",
                        state_file=agent_args.state_file,
                        snooze_hours=agent_args.hours,
                    )
                elif tcmd == "restore":
                    state = clear_action_triage(
                        agent_args.path,
                        agent_args.action_id,
                        state_file=agent_args.state_file,
                    )

                if agent_args.format == "json":
                    print(json.dumps(state, indent=2, default=str))
                else:
                    _print_agent_table(state, agent_args.limit)
                sys.exit(0)

            if cmd == "status":
                state = _resolve_state(refresh=agent_args.refresh)
                if agent_args.format == "feed":
                    print(
                        json.dumps(
                            command_center_payload(state, limit=agent_args.limit),
                            indent=2,
                            default=str,
                        )
                    )
                elif agent_args.format == "json":
                    print(json.dumps(state, indent=2, default=str))
                else:
                    _print_agent_table(state, agent_args.limit)
                sys.exit(0)

            if cmd == "serve":
                from skylos.agents.service import create_agent_service

                token = agent_args.token or secrets_lib.token_urlsafe(24)
                server = create_agent_service(
                    agent_args.path,
                    host=agent_args.host,
                    port=agent_args.port,
                    token=token,
                    state_file=agent_args.state_file,
                    conf=agent_args.conf,
                    use_baseline=not agent_args.no_baseline,
                    default_limit=agent_args.limit,
                    refresh_on_start=agent_args.refresh_on_start,
                    allowed_origins=agent_args.allowed_origins,
                )
                address = server.server_address
                console.print(
                    f"[bold]Skylos Agent API[/bold] listening on http://{address[0]}:{address[1]}"
                )
                console.print(f"[dim]Repo:[/dim] {agent_args.path}")
                console.print("[dim]Auth header:[/dim] X-Skylos-Agent-Token")
                console.print(f"[dim]Session token:[/dim] {token}")
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    console.print("\n[dim]Stopping Skylos Agent API[/dim]")
                finally:
                    server.server_close()
                sys.exit(0)

        if cmd == "audit":
            if not getattr(agent_args, "deep", False):
                console.print(
                    "[bad]Deep audit is explicit. Re-run with `--deep`.[/bad]"
                )
                sys.exit(2)

            if getattr(agent_args, "scan_only", False) and getattr(
                agent_args, "resume", False
            ):
                console.print(
                    "[warn]Deep audit `--resume` requires processing mode, "
                    "not `--scan-only`.[/warn]"
                )
                sys.exit(2)

            if getattr(agent_args, "scan_only", False) and getattr(
                agent_args, "force", False
            ):
                console.print(
                    "[warn]Deep audit `--force` requires processing mode, "
                    "not `--scan-only`.[/warn]"
                )
                sys.exit(2)

            if getattr(agent_args, "scan_only", False) and getattr(
                agent_args, "revalidate", False
            ):
                console.print(
                    "[warn]Deep audit `--revalidate` requires revalidation mode, "
                    "not `--scan-only`.[/warn]"
                )
                sys.exit(2)

            if getattr(agent_args, "challenge", False) and not getattr(
                agent_args, "revalidate", False
            ):
                console.print(
                    "[warn]Deep audit `--challenge` requires `--revalidate`.[/warn]"
                )
                sys.exit(2)

            audit_path = pathlib.Path(agent_args.path)
            if not audit_path.exists():
                console.print(f"[bad]Path not found: {audit_path}[/bad]")
                sys.exit(1)

            changed_files = None
            changed_scope = bool(getattr(agent_args, "changed", False)) or bool(
                getattr(agent_args, "base", None)
            )
            if changed_scope:
                try:
                    changed_files = get_git_changed_files(
                        audit_path,
                        base_ref=getattr(agent_args, "base", None),
                        strict_base=bool(getattr(agent_args, "base", None)),
                        include_deleted=True,
                    )
                except ValueError as exc:
                    console.print(f"[bad]{exc}[/bad]")
                    sys.exit(2)
                if not changed_files:
                    sys.exit(
                        _handle_empty_changed_deep_audit(
                            agent_args,
                            audit_path,
                            console,
                        )
                    )

            from skylos.audit.candidates import scan_deep_audit_candidates

            output_exclude_paths = _deep_audit_output_exclude_paths(
                audit_path,
                getattr(agent_args, "output", None),
            )
            scan_kwargs = {"changed_files": changed_files}
            if output_exclude_paths:
                scan_kwargs["exclude_paths"] = output_exclude_paths
            summary, store = scan_deep_audit_candidates(
                audit_path,
                **scan_kwargs,
            )
            audit_project_root = pathlib.Path(summary.project_root)
            process_summary = None
            revalidation_summary = None
            ci_summary = None
            mode = "deep_scan_only"

            if not getattr(agent_args, "scan_only", False):
                if not _ensure_llm_support():
                    Console().print("[bold red]Agent module not available[/bold red]")
                    sys.exit(1)

                model = agent_args.model
                provider_override = getattr(agent_args, "provider", None)
                if provider_override and model == "gpt-4.1":
                    provider_default_models = {
                        "anthropic": "claude-sonnet-4-20250514",
                        "google": "gemini/gemini-2.0-flash",
                        "mistral": "mistral/mistral-large-latest",
                        "groq": "groq/llama3-70b-8192",
                        "deepseek": "deepseek/deepseek-chat",
                        "xai": "xai/grok-2",
                        "together": (
                            "together/meta-llama/Meta-Llama-3-70B-Instruct-Turbo"
                        ),
                        "ollama": "ollama/llama3",
                    }
                    if provider_override in provider_default_models:
                        model = provider_default_models[provider_override]

                provider, api_key, base_url, is_local = resolve_llm_runtime(
                    model=model,
                    provider_override=provider_override,
                    base_url_override=getattr(agent_args, "base_url", None),
                    console=console,
                    allow_prompt=_is_tty(),
                )
                if base_url:
                    os.environ["OPENAI_BASE_URL"] = base_url
                    os.environ["SKYLOS_LLM_BASE_URL"] = base_url
                if api_key is None or api_key == "":
                    if not is_local:
                        env_var = (
                            PROVIDERS.get(provider) or f"{provider.upper()}_API_KEY"
                        )
                        console.print(
                            f"[bad]No {env_var} configured. Run `skylos key` or "
                            "set the environment variable.[/bad]"
                        )
                        sys.exit(1)

                (
                    prompt_templates,
                    prompt_template_root,
                ) = _explicit_prompt_templates_from_args(agent_args, console)
                config = _build_analyzer_config(
                    model=model,
                    api_key=api_key,
                    provider=provider,
                    base_url=base_url,
                    quiet=getattr(agent_args, "quiet", False),
                    enable_security=True,
                    enable_quality=False,
                    prompt_templates=prompt_templates,
                    prompt_template_root=prompt_template_root,
                )
                analyzer = SkylosLLM(config)

                if getattr(agent_args, "revalidate", False):
                    from skylos.audit.revalidator import (
                        revalidate_deep_audit_findings,
                    )

                    revalidation_summary = revalidate_deep_audit_findings(
                        store=store,
                        verifier=analyzer,
                        model=model,
                        provider=provider,
                        limit=getattr(agent_args, "limit", None),
                        force=getattr(agent_args, "force", False),
                        challenge=getattr(agent_args, "challenge", False),
                        allowed_files=changed_files if changed_scope else None,
                    )
                    mode = (
                        "deep_challenge"
                        if getattr(agent_args, "challenge", False)
                        else "deep_revalidate"
                    )
                else:
                    from skylos.audit.processor import process_deep_audit_records

                    process_summary = process_deep_audit_records(
                        store=store,
                        analyzer=analyzer,
                        model=model,
                        provider=provider,
                        limit=getattr(agent_args, "limit", None),
                        force=getattr(agent_args, "force", False),
                        allowed_files=changed_files if changed_scope else None,
                    )
                    mode = "deep_process"

            if getattr(agent_args, "fail_on", None):
                from skylos.audit.ci import evaluate_deep_audit_ci_gate

                ci_summary = evaluate_deep_audit_ci_gate(
                    store=store,
                    fail_on=getattr(agent_args, "fail_on"),
                    model=locals().get("model"),
                    provider=locals().get("provider"),
                    allowed_files=changed_files if changed_scope else None,
                    process_summary=process_summary,
                )

            payload = {
                "mode": mode,
                "summary": summary.to_dict(),
                "audit_project_dir": str(store.project_dir),
            }
            if process_summary is not None:
                payload["processing"] = process_summary.to_dict()
            if revalidation_summary is not None:
                payload["revalidation"] = revalidation_summary.to_dict()
            if ci_summary is not None:
                payload["ci"] = ci_summary.to_dict()
            if getattr(agent_args, "security_workflow_alias", None) == "security-deep":
                payload["workflow"] = _security_deep_workflow_payload(
                    mode=mode,
                    summary=summary,
                    process_summary=process_summary,
                    revalidation_summary=revalidation_summary,
                )

            export_payload = None
            export_format = getattr(agent_args, "format", "table")
            if export_format in {"json", "sarif", "md", "markdown", "md-dir"}:
                iter_records = getattr(store, "iter_file_records", None)
                if callable(iter_records):
                    from skylos.audit.export import build_deep_audit_export

                    export_payload = build_deep_audit_export(
                        store=store,
                        min_severity=getattr(agent_args, "severity", None),
                        verdicts=getattr(agent_args, "verdict", None),
                        allowed_files=changed_files if changed_scope else None,
                        include_deleted=getattr(agent_args, "include_deleted", False),
                    )
                    payload["export"] = export_payload

            if export_format in {"sarif", "md", "markdown", "md-dir"}:
                if export_payload is None:
                    console.print(
                        "[bad]Deep audit export requires persisted audit state.[/bad]"
                    )
                    sys.exit(1)

                from skylos.audit.export import (
                    render_deep_audit_export,
                    write_deep_audit_export,
                )

                if agent_args.output:
                    written_paths = write_deep_audit_export(
                        export_payload,
                        agent_args.output,
                        export_format,
                    )
                    if not getattr(agent_args, "quiet", False):
                        console.print(
                            f"[dim]Written {len(written_paths)} export file(s) "
                            f"to {agent_args.output}[/dim]"
                        )
                elif export_format == "md-dir":
                    default_output = store.exports_dir / "markdown"
                    written_paths = write_deep_audit_export(
                        export_payload,
                        default_output,
                        export_format,
                    )
                    if not getattr(agent_args, "quiet", False):
                        console.print(
                            f"[dim]Written {len(written_paths)} export file(s) "
                            f"to {default_output}[/dim]"
                        )
                elif not getattr(agent_args, "quiet", False):
                    print(
                        render_deep_audit_export(export_payload, export_format),
                        end="",
                    )
            elif agent_args.output:
                pathlib.Path(agent_args.output).write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

            if export_format == "json":
                if not getattr(agent_args, "quiet", False):
                    print(json.dumps(payload, indent=2, sort_keys=True))
            elif export_format in {"sarif", "md", "markdown", "md-dir"}:
                pass
            elif not getattr(agent_args, "quiet", False):
                heading = "scan-only" if process_summary is None else "scan"
                if (
                    summary.candidate_count == 0
                    and process_summary is None
                    and revalidation_summary is None
                    and ci_summary is None
                ):
                    console.print(
                        f"[brand]Deep audit {heading}:[/brand] no candidates found"
                    )
                    console.print(f"  Files scanned: {summary.files_scanned}")
                    if summary.deleted_files:
                        console.print(f"  Deleted records: {summary.deleted_files}")
                    console.print(f"  Store: {store.project_dir}")
                else:
                    console.print(
                        f"[brand]Deep audit {heading}:[/brand] static queue updated"
                    )
                    console.print(f"  Project: {summary.project_root}")
                    console.print(f"  Files scanned: {summary.files_scanned}")
                    console.print(f"  Candidates: {summary.candidate_count}")
                    console.print(
                        f"  Redacted candidates: {summary.redacted_candidates}"
                    )
                    console.print(f"  Pending files: {summary.pending_files}")
                    console.print(f"  Processing files: {summary.processing_files}")
                    console.print(f"  Error files: {summary.error_files}")
                    console.print(f"  Not analyzed: {summary.not_analyzed_files}")
                    if summary.deleted_files:
                        console.print(f"  Deleted records: {summary.deleted_files}")
                if process_summary is not None:
                    console.print("[brand]Deep audit processing:[/brand] finished")
                    console.print(
                        f"  Processed files: {process_summary.processed_files}"
                    )
                    console.print(f"  Findings added: {process_summary.findings_added}")
                    console.print(
                        f"  Skipped secret files: "
                        f"{process_summary.skipped_secret_files}"
                    )
                    console.print(
                        f"  Unsupported files: {process_summary.unsupported_files}"
                    )
                    console.print(
                        f"  Remaining work: {process_summary.remaining_pending_files}"
                    )
                if revalidation_summary is not None:
                    console.print("[brand]Deep audit revalidation:[/brand] finished")
                    console.print(
                        f"  Revalidated findings: "
                        f"{revalidation_summary.revalidated_findings}"
                    )
                    console.print(
                        f"  Challenged findings: "
                        f"{revalidation_summary.challenged_findings}"
                    )
                    console.print(
                        f"  Uncertain verdicts: {revalidation_summary.uncertain}"
                    )
                if ci_summary is not None:
                    console.print(f"[brand]Deep audit CI:[/brand] {ci_summary.reason}")
                console.print(f"  Store: {store.project_dir}")
                if workflow := payload.get("workflow"):
                    _print_security_deep_workflow(console, workflow)
            sys.exit(ci_summary.exit_code if ci_summary is not None else 0)

        if not _ensure_llm_support():
            Console().print("[bold red]Agent module not available[/bold red]")
            sys.exit(1)

        model = agent_args.model

        _provider_override = getattr(agent_args, "provider", None)
        if _provider_override and model == "gpt-4.1":
            _provider_default_models = {
                "anthropic": "claude-sonnet-4-20250514",
                "google": "gemini/gemini-2.0-flash",
                "mistral": "mistral/mistral-large-latest",
                "groq": "groq/llama3-70b-8192",
                "deepseek": "deepseek/deepseek-chat",
                "xai": "xai/grok-2",
                "together": "together/meta-llama/Meta-Llama-3-70B-Instruct-Turbo",
                "ollama": "ollama/llama3",
            }
            if _provider_override in _provider_default_models:
                model = _provider_default_models[_provider_override]

        provider, api_key, base_url, _is_local = resolve_llm_runtime(
            model=model,
            provider_override=_provider_override,
            base_url_override=getattr(agent_args, "base_url", None),
            console=console,
            allow_prompt=_is_tty(),
        )

        if base_url:
            os.environ["OPENAI_BASE_URL"] = base_url
            os.environ["SKYLOS_LLM_BASE_URL"] = base_url

        if api_key is None or api_key == "":
            if not _is_local:
                env_var = PROVIDERS.get(provider) or f"{provider.upper()}_API_KEY"
                console.print(
                    f"[bad]No {env_var} configured. Run `skylos key` or set the environment variable.[/bad]"
                )
                sys.exit(1)

        agent_project_cfg = load_config(getattr(agent_args, "path", Path.cwd()))
        agent_exclude_folders = list(
            parse_exclude_folders(
                use_defaults=True,
                config_exclude_folders=agent_project_cfg.get("exclude"),
            )
        )

        if cmd == "scan":
            if getattr(agent_args, "security", False):
                path = pathlib.Path(agent_args.path)
                if not path.exists():
                    console.print(f"[bad]Path not found: {path}[/bad]")
                    sys.exit(1)

                if path.is_file():
                    files = [path]
                else:
                    files = discover_source_files(
                        path,
                        [".py"],
                        exclude_folders=agent_exclude_folders,
                    )

                if not files:
                    console.print("[warn]No Python files found[/warn]")
                    sys.exit(0)

                if (
                    INTERACTIVE_AVAILABLE
                    and getattr(agent_args, "interactive", False)
                    and len(files) > 1
                ):
                    prompt = _get_inquirer()
                    if prompt is None:
                        console.print(
                            "[bad]Interactive mode requires 'inquirer'. Install with: pip install inquirer[/bad]"
                        )
                        sys.exit(2)
                    choices = [
                        (f"{f.name} ({f.stat().st_size / 1024:.1f}KB)", f)
                        for f in files
                    ]
                    questions = [
                        prompt.Checkbox(
                            "files", message="Select files", choices=choices
                        )
                    ]
                    answers = prompt.prompt(questions)
                    if not answers or not answers["files"]:
                        sys.exit(0)
                    files = answers["files"]

                tokens, cost = llm_estimate_cost(files, model)
                console.print(
                    f"\n[brand]Security audit:[/brand] {len(files)} files, ~{tokens:,} tokens, ~${cost:.4f}"
                )

                if (
                    INTERACTIVE_AVAILABLE
                    and _is_tty()
                    and (prompt := _get_inquirer()) is not None
                    and not prompt.confirm("Proceed?", default=True)
                ):
                    sys.exit(0)

                (
                    prompt_templates,
                    prompt_template_root,
                ) = _explicit_prompt_templates_from_args(agent_args, console)
                config = _build_analyzer_config(
                    model=model,
                    api_key=api_key,
                    provider=provider,
                    base_url=base_url,
                    quiet=getattr(agent_args, "quiet", False),
                    prompt_templates=prompt_templates,
                    prompt_template_root=prompt_template_root,
                )
                analyzer = SkylosLLM(config)
                taskflow = run_security_taskflow(
                    path=path,
                    files=files,
                    analyzer=analyzer,
                    model=model,
                    api_key=api_key,
                    provider=provider,
                    base_url=base_url,
                )
                llm_result = taskflow.result
                analyzer.print_results(
                    llm_result, format=agent_args.format, output_file=agent_args.output
                )
                blockers_attr = getattr(llm_result, "has_blockers", False)
                has_blockers = (
                    blockers_attr() if callable(blockers_attr) else bool(blockers_attr)
                )
                sys.exit(1 if has_blockers else 0)

            changed_files = None
            if getattr(agent_args, "changed", False):
                path = pathlib.Path(agent_args.path)
                console.print("[brand]Finding git-changed files...[/brand]")
                changed_files = get_git_changed_files(path)

                if not changed_files:
                    console.print("[dim]No changed files[/dim]")
                    sys.exit(0)

                console.print(f"Found {len(changed_files)} changed files")

            agent_args.with_fixes = bool(getattr(agent_args, "with_fixes", False))
            if getattr(agent_args, "no_fixes", False):
                agent_args.with_fixes = False
            agent_args.skip_verification = not bool(
                getattr(agent_args, "verify_dead_code", False)
            )

            path = pathlib.Path(agent_args.path)
            if not path.exists():
                console.print(f"[bad]Path not found: {path}[/bad]")
                sys.exit(1)

            project_root = find_project_root(path)

            import time as _time

            _scan_start = _time.time()
            pipeline_stats = {}
            merged_findings = run_pipeline(
                path=str(path),
                model=model,
                api_key=api_key,
                agent_args=agent_args,
                console=console,
                changed_files=changed_files,
                exclude_folders=agent_exclude_folders,
                stats_out=pipeline_stats,
            )

            merged_findings = _normalize_agent_findings(merged_findings, project_root)

            static_only = 0
            llm_only = 0
            both = 0

            for f in merged_findings:
                source = f.get("_source")
                if source == "static":
                    static_only += 1
                elif source == "llm":
                    llm_only += 1
                elif source == "static+llm":
                    both += 1

            console.print("\n[brand]Results:[/brand]")
            console.print(f"  Total findings: {len(merged_findings)}")
            console.print(f"  [green]HIGH confidence (both agree):[/green] {both}")
            console.print(f"  [yellow]MEDIUM (static only):[/yellow] {static_only}")
            console.print(
                f"  [yellow]MEDIUM (LLM only, needs review):[/yellow] {llm_only}"
            )
            if pipeline_stats:
                console.print("[dim]Timings:[/dim]")
                console.print(
                    f"  static={pipeline_stats.get('phase_1_seconds', 0):.1f}s "
                    f"verify={pipeline_stats.get('phase_2a_seconds', 0):.1f}s "
                    f"audit={pipeline_stats.get('phase_2b_seconds', 0):.1f}s "
                    f"fixes={pipeline_stats.get('phase_3_seconds', 0):.1f}s "
                    f"total={pipeline_stats.get('elapsed_seconds', 0):.1f}s"
                )

            if agent_args.format == "json":
                output = json.dumps(merged_findings, indent=2, default=str)
                if agent_args.output:
                    pathlib.Path(agent_args.output).write_text(output)
                else:
                    print(output)
            else:
                title = (
                    "Hybrid Review Results (Changed Files)"
                    if changed_files
                    else "Hybrid Analysis Results"
                )
                if merged_findings:
                    table = Table(title=title, expand=True)
                    table.add_column("#", style="dim", width=3)
                    table.add_column("Conf", width=6)
                    table.add_column("Source", width=10)
                    table.add_column("Category", width=10)
                    table.add_column("Message", overflow="fold")
                    table.add_column("Location", style="dim", width=30)

                    for i, f in enumerate(merged_findings[:100], 1):
                        conf = f.get("_confidence", "?")
                        if conf == "high":
                            conf_style = "[green]HIGH[/green]"
                        else:
                            conf_style = "[yellow]MED[/yellow]"

                        source = f.get("_source", "?")
                        cat = f.get("_category", "?")
                        msg = (f.get("message", "?") or "?")[:120]
                        file_rel = f.get("file", "?")
                        loc = f"{file_rel}:{f.get('line', '?')}"

                        table.add_row(str(i), conf_style, source, cat, msg, loc)

                    console.print(table)
                else:
                    console.print("[good]No issues found![/good]")

            if getattr(agent_args, "upload", False) and merged_findings:
                result_for_upload = _agent_findings_to_result_json(merged_findings)
                upload_report(
                    result_for_upload,
                    is_forced=getattr(agent_args, "force", False),
                    strict=getattr(agent_args, "strict", False),
                    analysis_mode="hybrid",
                )

            _upload_agent_run_best_effort(
                "scan",
                {
                    "total": len(merged_findings),
                    "static_only": static_only,
                    "llm_only": llm_only,
                    "both": both,
                },
                model=model,
                provider=provider,
                duration_seconds=round(_time.time() - _scan_start, 1),
            )

            if merged_findings and getattr(agent_args, "strict", False):
                sys.exit(1)
            sys.exit(0)

        if cmd == "verify":
            path = pathlib.Path(agent_args.path)
            if not path.exists():
                console.print(f"[bad]Path not found: {path}[/bad]")
                sys.exit(1)

            console.print("[brand]Step 1/2: Running static analysis...[/brand]")

            from skylos.analyzer import analyze as run_static

            raw = run_static(
                str(path),
                conf=agent_args.conf,
                enable_danger=False,
                enable_quality=False,
                enable_secrets=False,
                exclude_folders=agent_exclude_folders,
            )
            static_result = json.loads(raw) if isinstance(raw, str) else raw

            from skylos.deadcode.collect import collect_dead_code_findings

            all_findings = collect_dead_code_findings(static_result)

            defs_map = static_result.get("definitions", {})

            if not all_findings:
                console.print("[good]No dead code findings to verify![/good]")
                sys.exit(0)

            console.print(f"  Found {len(all_findings)} dead code findings")

            console.print("\n[brand]Step 2/2: LLM verification (4-pass)...[/brand]")

            from skylos.llm.verify_orchestrator import run_verification

            result = run_verification(
                findings=all_findings,
                defs_map=defs_map,
                project_root=str(path if path.is_dir() else path.parent),
                model=model,
                api_key=api_key,
                provider=provider,
                base_url=base_url,
                max_verify=agent_args.max_verify,
                max_challenge=agent_args.max_challenge,
                enable_entry_discovery=not agent_args.no_entry_discovery,
                enable_survivor_challenge=not agent_args.no_survivor_challenge,
                quiet=getattr(agent_args, "quiet", False),
                verification_mode=getattr(agent_args, "verification_mode", "judge_all"),
                grep_workers=getattr(agent_args, "grep_workers", 4),
                parallel_grep=getattr(agent_args, "parallel_grep", False)
                or getattr(agent_args, "fix", False),
            )

            stats = result["stats"]
            verified = result["verified_findings"]
            new_dead = result["new_dead_code"]

            if agent_args.format == "json":
                output = json.dumps(result, indent=2, default=str)
                if agent_args.output:
                    pathlib.Path(agent_args.output).write_text(output)
                    console.print(f"[dim]Written to {agent_args.output}[/dim]")
                else:
                    print(output)
            else:
                console.print("\n[brand]Verification Summary[/brand]")
                summary_table = Table(expand=False)
                summary_table.add_column("Metric", style="cyan")
                summary_table.add_column("Value", style="bold")
                summary_table.add_row("Total findings", str(stats["total_findings"]))
                summary_table.add_row(
                    "Confirmed dead (TRUE_POSITIVE)",
                    f"[red]{stats['verified_true_positive']}[/red]",
                )
                summary_table.add_row(
                    "False positives removed",
                    f"[green]{stats['verified_false_positive']}[/green]",
                )
                summary_table.add_row("Uncertain", str(stats["uncertain"]))
                summary_table.add_row(
                    "Entry points discovered", str(stats["entry_points_discovered"])
                )
                summary_table.add_row(
                    "Survivors challenged", str(stats["survivors_challenged"])
                )
                summary_table.add_row(
                    "New dead code found",
                    f"[red]{stats['survivors_reclassified_dead']}[/red]",
                )
                summary_table.add_row("LLM calls", str(stats["llm_calls"]))
                summary_table.add_row("Time", f"{stats['elapsed_seconds']}s")
                console.print(summary_table)

                fps = [f for f in verified if f.get("_llm_verdict") == "FALSE_POSITIVE"]
                if fps:
                    console.print(
                        f"\n[green]False positives removed ({len(fps)}):[/green]"
                    )
                    fp_table = Table(expand=True)
                    fp_table.add_column("Name", style="green")
                    fp_table.add_column("File", style="dim")
                    fp_table.add_column("Rationale", overflow="fold")
                    for f in fps[:30]:
                        fp_table.add_row(
                            f.get("name", "?"),
                            f"{f.get('file', '?')}:{f.get('line', '?')}",
                            f.get("_llm_rationale", "")[:100],
                        )
                    console.print(fp_table)

                if new_dead:
                    console.print(
                        f"\n[red]New dead code discovered ({len(new_dead)}):[/red]"
                    )
                    nd_table = Table(expand=True)
                    nd_table.add_column("Name", style="red")
                    nd_table.add_column("File", style="dim")
                    nd_table.add_column("Rationale", overflow="fold")
                    for d in new_dead[:30]:
                        nd_table.add_row(
                            d.get("full_name", d.get("name", "?")),
                            f"{d.get('file', '?')}:{d.get('line', '?')}",
                            d.get("_llm_rationale", "")[:100],
                        )
                    console.print(nd_table)

                eps = result.get("entry_points", [])
                if eps:
                    console.print(
                        f"\n[cyan]Entry points discovered ({len(eps)}):[/cyan]"
                    )
                    for ep in eps:
                        console.print(f"  - {ep['name']} (from {ep['source']})")

            total_removed = stats["verified_false_positive"]
            total_added = stats["survivors_reclassified_dead"]
            net = stats["total_findings"] - total_removed + total_added

            console.print(
                f"\n[brand]Net result:[/brand] {stats['total_findings']} findings "
                f"→ [green]-{total_removed} FP[/green] "
                f"[red]+{total_added} new[/red] "
                f"= {net} verified findings"
            )

            if getattr(agent_args, "fix", False):
                from skylos.remediation.fixgen import (
                    generate_removal_plan,
                    generate_unified_diff,
                    apply_patches,
                    validate_patches,
                    generate_fix_summary,
                )

                dead_findings = [
                    f for f in verified if f.get("_llm_verdict") == "TRUE_POSITIVE"
                ] + (new_dead or [])

                if dead_findings:
                    fix_mode = getattr(agent_args, "fix_mode", "delete")
                    project_root_str = str(path if path.is_dir() else path.parent)
                    patches = generate_removal_plan(
                        dead_findings,
                        defs_map,
                        project_root_str,
                        mode=fix_mode,
                    )

                    if patches:
                        errors = validate_patches(patches, project_root_str)
                        if errors:
                            console.print("\n[warn]Patch validation warnings:[/warn]")
                            for err in errors:
                                console.print(f"  [yellow]! {err}[/yellow]")

                        summary = generate_fix_summary(patches)
                        console.print("\n[brand]Fix Plan:[/brand]")
                        console.print(f"  Patches: {summary['total_patches']}")
                        console.print(f"  Files affected: {summary['files_affected']}")
                        console.print(
                            f"  Lines to remove: {summary['total_lines_removed']}"
                        )
                        console.print(f"  Avg safety: {summary['avg_safety_score']}")

                        diff = generate_unified_diff(patches, project_root_str)
                        if diff:
                            console.print("\n[brand]Unified Diff:[/brand]")
                            print(diff)

                        if getattr(agent_args, "pr", False) and not errors:
                            import time as _time

                            branch_name = f"skylos/fix-deadcode-{int(_time.time())}"
                            try:
                                subprocess.run(
                                    ["git", "checkout", "-b", branch_name],
                                    cwd=project_root_str,
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                )
                                apply_patches(patches, project_root_str, dry_run=False)
                                subprocess.run(
                                    ["git", "add", "-A"],
                                    cwd=project_root_str,
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                )
                                commit_msg = (
                                    f"fix: remove {summary['total_patches']} dead code items "
                                    f"({summary['total_lines_removed']} lines)"
                                )
                                subprocess.run(
                                    ["git", "commit", "-m", commit_msg],
                                    cwd=project_root_str,
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                )
                                console.print(
                                    f"\n[good]Branch created: {branch_name}[/good]"
                                )
                                console.print(f"[good]Committed: {commit_msg}[/good]")
                                if shutil.which("gh"):
                                    console.print(
                                        f"\n[brand]Create PR with:[/brand]\n"
                                        f'  gh pr create --title "{commit_msg}" '
                                        f'--body "Automated dead code removal by Skylos"'
                                    )
                                else:
                                    console.print(
                                        f"\n[dim]Push and create PR:[/dim]\n"
                                        f"  git push -u origin {branch_name}\n"
                                        f"  # then open PR on GitHub"
                                    )
                            except subprocess.CalledProcessError as e:
                                console.print(
                                    f"\n[warn]Git operation failed: {e.stderr or e}[/warn]"
                                )
                        elif getattr(agent_args, "apply", False) and not errors:
                            apply_patches(patches, project_root_str, dry_run=False)
                            console.print(
                                "\n[good]Patches applied successfully![/good]"
                            )
                        elif (
                            getattr(agent_args, "apply", False)
                            or getattr(agent_args, "pr", False)
                        ) and errors:
                            console.print(
                                "\n[warn]Skipping apply due to validation errors[/warn]"
                            )
                    else:
                        console.print("\n[dim]No patches generated[/dim]")
                else:
                    console.print("\n[dim]No confirmed dead code to fix[/dim]")

            _upload_agent_run_best_effort(
                "verify",
                {
                    "total_findings": stats["total_findings"],
                    "verified_true_positive": stats["verified_true_positive"],
                    "verified_false_positive": stats["verified_false_positive"],
                    "entry_points_discovered": stats["entry_points_discovered"],
                    "llm_calls": stats["llm_calls"],
                    "elapsed_seconds": stats["elapsed_seconds"],
                },
                model=model,
                provider=provider,
                duration_seconds=stats.get("elapsed_seconds"),
            )

            sys.exit(0)

        if cmd == "remediate":
            standards_raw = getattr(agent_args, "standards", None)

            if standards_raw:
                standards_path = (
                    None if standards_raw == "__builtin__" else standards_raw
                )

                from skylos.llm.cleanup_orchestrator import CleanupOrchestrator

                test_cmd = getattr(agent_args, "test_cmd", None)
                auto_test = getattr(agent_args, "auto_test", False)
                orchestrator = CleanupOrchestrator(
                    model=model,
                    api_key=api_key,
                    provider=provider,
                    base_url=base_url,
                    test_cmd=test_cmd,
                    allow_test_execution=bool(test_cmd) or auto_test,
                    auto_detect_tests=auto_test,
                    standards_path=standards_path,
                )

                summary = orchestrator.run(
                    agent_args.path,
                    max_fixes=getattr(agent_args, "max_fixes", 20),
                    dry_run=getattr(agent_args, "dry_run", False),
                    quiet=getattr(agent_args, "quiet", False),
                )

                if getattr(agent_args, "quiet", False):
                    import json as _json_mod

                    print(_json_mod.dumps(summary, indent=2))

                _upload_agent_run_best_effort(
                    "cleanup",
                    {
                        "total_items": summary.get("total_items", 0),
                        "applied": summary.get("applied", 0),
                        "reverted": summary.get("reverted", 0),
                        "skipped": summary.get("skipped", 0),
                        "total_analyzed_files": summary.get("total_analyzed_files", 0),
                    },
                    model=model,
                    provider=provider,
                    duration_seconds=summary.get("elapsed_seconds"),
                )

                sys.exit(
                    0
                    if summary.get("applied", 0) > 0
                    or summary.get("total_items", 0) == 0
                    else 1
                )
            else:
                from skylos.llm.orchestrator import RemediationAgent

                test_cmd = getattr(agent_args, "test_cmd", None)
                auto_test = getattr(agent_args, "auto_test", False)
                agent = RemediationAgent(
                    model=model,
                    api_key=api_key,
                    test_cmd=test_cmd,
                    severity_filter=getattr(agent_args, "severity", None),
                    provider=provider,
                    base_url=base_url,
                    allow_test_execution=bool(test_cmd) or auto_test,
                    auto_detect_tests=auto_test,
                )

                summary = agent.run(
                    agent_args.path,
                    dry_run=getattr(agent_args, "dry_run", False),
                    max_fixes=getattr(agent_args, "max_fixes", 10),
                    auto_pr=getattr(agent_args, "auto_pr", False),
                    branch_prefix=getattr(agent_args, "branch_prefix", "skylos/fix"),
                    quiet=getattr(agent_args, "quiet", False),
                )

                if getattr(agent_args, "quiet", False):
                    import json as _json_mod

                    print(_json_mod.dumps(summary, indent=2))

                _upload_agent_run_best_effort(
                    "remediate",
                    {
                        "total_findings": summary.get("total_findings", 0),
                        "fixed": summary.get("fixed", 0),
                        "failed": summary.get("failed", 0),
                        "skipped": summary.get("skipped", 0),
                        "pr_url": summary.get("pr_url"),
                    },
                    model=model,
                    provider=provider,
                    duration_seconds=summary.get("elapsed_seconds"),
                )

                sys.exit(
                    0
                    if summary.get("fixed", 0) > 0
                    or summary.get("total_findings", 0) == 0
                    else 1
                )

    if len(sys.argv) > 1 and sys.argv[1] == "run":
        _run_web_server_command(sys.argv[2:])
        return

    _run_scan_command(sys.argv[1:])


if __name__ == "__main__":
    main()
