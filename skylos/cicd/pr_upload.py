"""Pull request uploads to Skylos Cloud for the ``skylos cicd init`` workflow.

Skylos Cloud trusts a pull request scan only from a ``pull_request_target``
run of ``.github/workflows/skylos.yml``. That event runs with the base
branch's workflow, token and secrets, so the work is split into three jobs
and none of them both reads pull request files and holds an upload
credential:

``skylos cicd pr-policy``
    GitHub OIDC, no checkout: saves the project's Skylos Cloud policy.
``skylos cicd pr-scan``
    Read-only token, no OIDC: scans the pull request head as data, with
    repository settings from the base commit and the saved Cloud policy.
``skylos cicd pr-publish``
    GitHub OIDC, no checkout: uploads that scan. Cloud then checks the run
    and the pull request's current head before it publishes the result.
"""

from __future__ import annotations

import dataclasses
import gzip
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from rich.console import Console
from rich.markup import escape

POLICY_CONFIG_NAME = "config.yaml"
POLICY_RULES_NAME = "rules.json"
MAX_POLICY_BYTES = 2_000_000
MAX_SCAN_RESULT_BYTES = 100_000_000
MAX_ARTIFACT_BYTES = 50_000_000
MAX_DECODED_ARTIFACT_BYTES = 200_000_000
INLINE_IGNORE_REASON = "inline ignore comment"
CATEGORY_FLAGS = ("--danger", "--quality", "--ai-defects", "--secrets", "--sca")

_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_PR_NUMBER_RE = re.compile(r"[1-9][0-9]{0,9}\Z")
_CATEGORY_SETTINGS = ("security_enabled", "secrets_enabled", "quality_enabled")
_SUPPRESSED_SECTIONS = {
    "security": "danger",
    "danger": "danger",
    "secret": "secrets",
    "secrets": "secrets",
    "quality": "quality",
    "reliability": "reliability",
    "ai_defect": "ai_defects",
    "ai_defects": "ai_defects",
    "custom": "custom_rules",
    "custom_rules": "custom_rules",
    "dependency": "dependency_vulnerabilities",
}


class PrUploadError(Exception):
    """A pull request upload step that must stop the job."""


def add_pr_upload_parsers(subparsers) -> None:
    policy = subparsers.add_parser(
        "pr-policy",
        help="Save the Skylos Cloud policy for a pull request scan (workflow step)",
        description=(
            "Read this repository's Skylos Cloud policy with GitHub Actions OIDC "
            "and save it to a folder for `skylos cicd pr-scan`. Run it in a "
            "pull_request_target job that never checks out pull request files."
        ),
    )
    policy.add_argument("--output", required=True, help="Folder to save the policy in")
    _add_project_root_argument(policy)

    scan = subparsers.add_parser(
        "pr-scan",
        help="Scan a pull request head as untrusted data for Skylos Cloud (workflow step)",
        description=(
            "Scan the checked-out pull request head without any upload "
            "credential. Every .skylos folder in the checkout is removed first; "
            "repository settings come from the base commit and Cloud policy from "
            "`skylos cicd pr-policy`. Inline ignore comments cannot hide "
            "security, secret or quality findings from Skylos Cloud, which "
            "gates the lines the pull request changes. Writes a prepared upload "
            "for `skylos cicd pr-publish`. Reads SKYLOS_COMMIT, SKYLOS_PR_NUMBER "
            "and SKYLOS_PR_BASE_SHA."
        ),
    )
    scan.add_argument("path", nargs="?", default=".")
    for flag in CATEGORY_FLAGS:
        scan.add_argument(flag, action="store_true", help=f"Pass {flag} to the scan")
    scan.add_argument(
        "--policy", required=True, help="Folder written by skylos cicd pr-policy"
    )
    scan.add_argument(
        "--output", required=True, help="Prepared upload to write (.json.gz)"
    )
    _add_project_root_argument(scan)

    publish = subparsers.add_parser(
        "pr-publish",
        help="Upload a prepared pull request scan to Skylos Cloud (workflow step)",
        description=(
            "Upload the scan written by `skylos cicd pr-scan` with GitHub "
            "Actions OIDC. Run it in a pull_request_target job that never checks "
            "out pull request files. Reads SKYLOS_COMMIT and SKYLOS_PR_NUMBER."
        ),
    )
    publish.add_argument("--input", required=True, help="Prepared upload (.json.gz)")
    _add_project_root_argument(publish)


def _add_project_root_argument(parser) -> None:
    parser.add_argument(
        "--project-root",
        default="",
        help="Skylos Cloud project folder in the repository (default: the repository root)",
    )


def run_pr_upload_command(args, *, console: Console | None = None) -> int:
    console = console or Console()
    try:
        project_root = _project_root(args.project_root)
        if args.cicd_cmd == "pr-policy":
            return fetch_pr_policy(
                Path(args.output), project_root=project_root, console=console
            )
        if args.cicd_cmd == "pr-scan":
            flags = [
                flag
                for flag in CATEGORY_FLAGS
                if getattr(args, flag.lstrip("-").replace("-", "_"))
            ]
            return run_pr_scan(
                args.path,
                flags,
                policy_dir=Path(args.policy),
                output=Path(args.output),
                project_root=project_root,
                console=console,
            )
        return publish_pr_scan(
            Path(args.input), project_root=project_root, console=console
        )
    except PrUploadError as exc:
        console.print(f"[bold red]{escape(str(exc))}[/bold red]", soft_wrap=True)
        return 1


def _project_root(value) -> str:
    from skylos.cloud.project_context import normalize_repo_subpath

    root = normalize_repo_subpath(value)
    if root is None:
        raise PrUploadError(
            "--project-root must be a folder inside the repository, e.g. apps/api"
        )
    return root


def _github_oidc_token() -> str:
    from skylos.api import _try_github_oidc_token

    token = _try_github_oidc_token()
    if not isinstance(token, str) or not token.startswith("oidc:"):
        raise PrUploadError(
            "No GitHub Actions OIDC token. Run this step in the generated workflow's "
            "pull_request_target job with permissions: id-token: write."
        )
    return token


def _required_env(name: str, pattern: re.Pattern) -> str:
    value = str(os.environ.get(name) or "").strip()
    if not pattern.match(value):
        raise PrUploadError(f"{name} is missing or invalid")
    return value


def _custom_rules_required(config: dict) -> bool:
    gate = config.get("gate")
    if not isinstance(gate, dict):
        return False
    coverage = gate.get("coverage")
    if not isinstance(coverage, dict):
        return False
    required = coverage.get("required")
    return isinstance(required, list) and "custom_rules" in required


def _valid_rules(rules) -> bool:
    return isinstance(rules, list) and all(isinstance(rule, dict) for rule in rules)


def _output_folder(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise PrUploadError(f"{path} must be a folder")
    path.mkdir(parents=True, exist_ok=True)
    return path


def fetch_pr_policy(output_dir: Path, *, project_root: str, console: Console) -> int:
    import yaml

    from skylos.cloud.sync import AuthError, _sync_config_payload, api_get
    from skylos.core.safe_cache_io import write_text_no_symlink

    token = _github_oidc_token()
    headers = {"X-Skylos-Project-Root": project_root}
    try:
        config = _sync_config_payload(
            api_get("/api/sync/config", token, extra_headers=headers)
        )
    except (AuthError, OSError, ValueError) as exc:
        raise PrUploadError(
            f"Skylos Cloud policy unavailable: {exc}. Install the Skylos GitHub App "
            "on this repository, or regenerate the workflow with: skylos cicd init --no-upload"
        ) from exc
    if not config.get("project_id"):
        raise PrUploadError("Skylos Cloud policy could not be verified (no project)")
    if any(type(config.get(key)) is not bool for key in _CATEGORY_SETTINGS):
        raise PrUploadError("Skylos Cloud policy category settings are invalid")

    folder = _output_folder(output_dir)
    text = yaml.safe_dump(config, default_flow_style=False)
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES or not write_text_no_symlink(
        folder / POLICY_CONFIG_NAME, text
    ):
        raise PrUploadError("Could not save the Skylos Cloud policy")

    try:
        response = api_get("/api/sync/rules", token, extra_headers=headers)
        rules = None
        if isinstance(response, dict):
            rules = response.get("rules")
        if not _valid_rules(rules):
            raise ValueError("Invalid custom rule response")
        rules_text = json.dumps(rules)
        if len(rules_text.encode("utf-8")) > MAX_POLICY_BYTES:
            raise ValueError("Custom rules exceed their size limit")
        if not write_text_no_symlink(folder / POLICY_RULES_NAME, rules_text):
            raise OSError("Could not save custom rules")
        rules_note = f"{len(rules)} custom rules"
    except (AuthError, OSError, ValueError) as exc:
        if _custom_rules_required(config):
            raise PrUploadError(
                f"Required Skylos custom rules could not be read: {exc}"
            ) from exc
        rules_note = (
            "custom rules unavailable, scan coverage reports them as not checked"
        )
    console.print(
        f"Saved the Skylos Cloud policy for {escape(str(config.get('project_name') or config['project_id']))} "
        f"({escape(rules_note)})",
        soft_wrap=True,
    )
    return 0


def _read_policy_file(path: Path) -> str | None:
    from skylos.core.safe_cache_io import read_text_no_symlink

    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise PrUploadError(f"Unsafe Skylos policy file: {path.name}")
    text = read_text_no_symlink(path, max_bytes=MAX_POLICY_BYTES)
    if text is None:
        raise PrUploadError(f"Could not read Skylos policy file: {path.name}")
    return text


def load_trusted_policy(policy_dir: Path) -> tuple[Path, list | None]:
    import yaml

    policy_dir = Path(os.path.abspath(policy_dir))
    if policy_dir.is_symlink() or not policy_dir.is_dir():
        raise PrUploadError("The trusted Skylos policy folder is missing")
    config_path = policy_dir / POLICY_CONFIG_NAME
    config_text = _read_policy_file(config_path)
    if config_text is None:
        raise PrUploadError("The trusted Skylos policy is missing")
    try:
        config = yaml.safe_load(config_text)
    except yaml.YAMLError as exc:
        raise PrUploadError("The trusted Skylos policy is invalid") from exc
    if not isinstance(config, dict) or not config.get("project_id"):
        raise PrUploadError("The trusted Skylos policy is invalid")
    rules_text = _read_policy_file(policy_dir / POLICY_RULES_NAME)
    if rules_text is None:
        if _custom_rules_required(config):
            raise PrUploadError("Required Skylos custom rules are missing")
        return config_path, None
    try:
        rules = json.loads(rules_text)
    except ValueError as exc:
        raise PrUploadError("Invalid Skylos custom rules") from exc
    if not _valid_rules(rules):
        raise PrUploadError("Invalid Skylos custom rules")
    return config_path, rules


def remove_checkout_skylos_folders(root: Path) -> int:
    """Delete every ``.skylos`` entry in a pull request checkout.

    Caches, baselines, links and synced policy there are pull request
    content; none of it may shape the scan that Skylos Cloud trusts.
    """
    removed = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        if Path(current) == root and ".git" in dirs:
            dirs.remove(".git")
        if ".skylos" not in dirs and ".skylos" not in files:
            continue
        if ".skylos" in dirs:
            dirs.remove(".skylos")
        entry = Path(current) / ".skylos"
        mode = os.lstat(entry).st_mode
        if stat.S_ISDIR(mode):
            shutil.rmtree(entry)
        else:
            entry.unlink()
        removed += 1
    return removed


def _outside(path: Path, root: Path, label: str) -> Path:
    resolved = Path(os.path.realpath(path))
    if resolved == root or resolved.is_relative_to(root):
        raise PrUploadError(f"{label} must be outside the pull request checkout")
    return Path(os.path.abspath(path))


def restore_inline_ignored_findings(result: dict) -> tuple[int, int]:
    """Put inline-ignored findings back for Skylos Cloud's policy review.

    A pull request author can add an inline ignore next to any finding. Dead
    code is the exception: ignoring an unused name waives no security, secret
    or quality result. Anything else that cannot be restored stops the job.
    """
    restored = 0
    dead_code = 0
    suppressed = result.get("suppressed") or []
    if not isinstance(suppressed, list):
        raise PrUploadError("The scan's suppressed findings are invalid")
    for finding in suppressed:
        if (
            not isinstance(finding, dict)
            or finding.get("reason") != INLINE_IGNORE_REASON
        ):
            raise PrUploadError(
                "Unsupported suppressed finding in the pull request scan"
            )
        category = str(finding.get("category") or "").lower()
        if category == "dead_code":
            dead_code += 1
            continue
        section = _SUPPRESSED_SECTIONS.get(category)
        if (
            section is None
            or not finding.get("rule_id")
            or not (finding.get("file") or finding.get("file_path"))
            or not finding.get("severity")
        ):
            raise PrUploadError(
                "Incomplete inline-ignored finding in the pull request scan; "
                "remove its inline ignore"
            )
        findings = result.setdefault(section, [])
        if not isinstance(findings, list):
            raise PrUploadError(f"The scan's {section} section is invalid")
        findings.append(finding)
        restored += 1
    return restored, dead_code


def _run_scan(target: str, flags: list[str], raw_output: Path, env: dict) -> None:
    import skylos.cli as cli_module
    from skylos.commands.scan_cmd import run_scan_command

    previous = {name: os.environ.get(name) for name in env}
    try:
        for name, value in env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        try:
            run_scan_command(
                [target, *flags, "--json", "-o", str(raw_output)],
                cli_module=cli_module,
            )
        except SystemExit as exc:
            if exc.code not in (None, 0):
                raise PrUploadError(
                    f"The pull request scan failed (exit {exc.code})"
                ) from exc
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _load_scan_result(path: Path) -> dict:
    from skylos.core.safe_cache_io import read_text_no_symlink

    text = read_text_no_symlink(path, max_bytes=MAX_SCAN_RESULT_BYTES)
    if text is None:
        raise PrUploadError("The pull request scan wrote no complete report")
    try:
        result = json.loads(text)
    except ValueError as exc:
        raise PrUploadError("The pull request scan report is invalid") from exc
    if not isinstance(result, dict):
        raise PrUploadError("The pull request scan report is invalid")
    return result


def _write_artifact(path: Path, payload: dict) -> None:
    folder = _output_folder(path.parent)
    destination = folder / path.name
    if os.path.lexists(destination):
        raise PrUploadError(f"{destination} already exists")
    descriptor = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with (
        os.fdopen(descriptor, "wb") as handle,
        gzip.GzipFile(fileobj=handle, mode="wb", compresslevel=6) as output,
    ):
        output.write(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    if destination.stat().st_size > MAX_ARTIFACT_BYTES:
        destination.unlink()
        raise PrUploadError("The prepared pull request scan exceeds the upload limit")


def run_pr_scan(
    target: str,
    flags: list[str],
    *,
    policy_dir: Path,
    output: Path,
    project_root: str,
    console: Console,
) -> int:
    from skylos.api import _prepare_report_upload, _print_preflight_notice
    from skylos.cicd.policy import resolve_policy_base
    from skylos.cloud.project_context import repo_subpath_for_project
    from skylos.config import (
        POLICY_BASE_ENV_VAR,
        SYNCED_POLICY_ENV_VAR,
        ConfigError,
    )
    from skylos.core.git_context import GitContext

    commit = _required_env("SKYLOS_COMMIT", _COMMIT_RE)
    pr_number = int(_required_env("SKYLOS_PR_NUMBER", _PR_NUMBER_RE))
    base_sha = _required_env("SKYLOS_PR_BASE_SHA", _COMMIT_RE)

    context = GitContext.from_path(Path.cwd())
    root = Path(context.root).resolve()
    head = context.run("rev-parse", "--verify", "HEAD")
    if head.returncode or head.stdout.strip() != commit:
        raise PrUploadError("The checkout is not the pull request head (SKYLOS_COMMIT)")
    policy_dir = _outside(policy_dir, root, "--policy")
    output = _outside(output, root, "--output")
    config_path, rules = load_trusted_policy(policy_dir)

    scan_dir = Path(os.path.realpath(target))
    if not scan_dir.is_dir() or not (scan_dir == root or scan_dir.is_relative_to(root)):
        raise PrUploadError("The scan path must be a folder inside the checkout")
    if repo_subpath_for_project(scan_dir, root) != project_root:
        raise PrUploadError(
            f"The scan path is not the Skylos Cloud project folder {project_root or '.'}"
        )

    removed = remove_checkout_skylos_folders(root)
    try:
        policy_base = resolve_policy_base(root, base_sha)
    except ConfigError as exc:
        raise PrUploadError(str(exc)) from exc

    custom_rules = None
    if rules is not None:
        custom_rules = json.dumps(rules)
    with tempfile.TemporaryDirectory(prefix="skylos-pr-scan-") as scratch:
        raw_output = Path(os.path.realpath(scratch)) / "scan.json"
        _run_scan(
            target,
            flags,
            raw_output,
            {
                POLICY_BASE_ENV_VAR: policy_base,
                SYNCED_POLICY_ENV_VAR: str(config_path),
                "SKYLOS_CUSTOM_RULES": custom_rules,
            },
        )
        result = _load_scan_result(raw_output)

    restored, ignored_dead_code = restore_inline_ignored_findings(result)
    result["project_root"] = project_root
    summary = result.setdefault("analysis_summary", {})
    if isinstance(summary, dict):
        summary["project_root"] = project_root
    prepared = _prepare_report_upload(result, analyzer_owned=True)
    _print_preflight_notice(prepared, quiet=False)
    metadata = prepared.metadata
    ci = metadata.get("ci")
    if (
        metadata.get("commit_hash") != commit
        or metadata.get("project_root") != project_root
        or not isinstance(ci, dict)
        or ci.get("pr_number") != pr_number
        or metadata.get("is_forced")
    ):
        raise PrUploadError("The prepared scan does not match this pull request")
    _write_artifact(
        output,
        dataclasses.asdict(
            dataclasses.replace(prepared, preflight=None, definitions_payload=None)
        ),
    )

    finding_count = prepared.scan_summary.get("finding_count")
    console.print(
        f"Scanned pull request #{pr_number} at {commit[:12]} "
        f"({escape(str(finding_count))} findings) for Skylos Cloud.",
        soft_wrap=True,
    )
    if removed:
        console.print(
            f"Removed {removed} .skylos folder(s) from the pull request checkout first."
        )
    if restored:
        console.print(
            f"Restored {restored} inline-ignored findings for Skylos Cloud's review."
        )
    if ignored_dead_code:
        console.print(f"{ignored_dead_code} dead-code items stay ignored inline.")
    return 0


def _read_artifact(path: Path) -> dict:
    path = Path(os.path.abspath(path))
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise PrUploadError("The prepared pull request scan is missing") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT_BYTES:
        raise PrUploadError("The prepared pull request scan is missing or too large")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with (
            os.fdopen(descriptor, "rb") as handle,
            gzip.GzipFile(fileobj=handle, mode="rb") as source,
        ):
            data = source.read(MAX_DECODED_ARTIFACT_BYTES + 1)
    except (OSError, EOFError) as exc:
        raise PrUploadError("The prepared pull request scan is not readable") from exc
    if len(data) > MAX_DECODED_ARTIFACT_BYTES:
        raise PrUploadError("The prepared pull request scan exceeds the upload limit")
    try:
        payload = json.loads(data)
    except ValueError as exc:
        raise PrUploadError("The prepared pull request scan is invalid") from exc
    if not isinstance(payload, dict):
        raise PrUploadError("The prepared pull request scan is invalid")
    return payload


def prepared_upload_from_artifact(
    payload: dict, *, commit: str, pr_number: int, project_root: str
):
    from skylos.api import PreparedReportUpload
    from skylos.api._payloads import _json_size_bytes

    metadata = payload.get("metadata")
    core = payload.get("core_payload")
    if not isinstance(metadata, dict) or not isinstance(core, dict):
        raise PrUploadError("The prepared pull request scan is invalid")
    for key in ("legacy_payload", "compatibility_payload", "scan_summary"):
        if not isinstance(payload.get(key), dict):
            raise PrUploadError("The prepared pull request scan is invalid")
    ci = metadata.get("ci")
    if (
        metadata.get("commit_hash") != commit
        or core.get("commit_hash") != commit
        or metadata.get("project_root") != project_root
        or core.get("project_root") != project_root
        or not isinstance(ci, dict)
        or ci.get("pr_number") != pr_number
        or metadata.get("is_forced")
        or core.get("is_forced")
    ):
        raise PrUploadError("The prepared scan does not match this pull request")
    grade_data = payload.get("grade_data")
    if not isinstance(grade_data, dict):
        grade_data = None
    return PreparedReportUpload(
        legacy_payload=payload["legacy_payload"],
        core_payload=core,
        compatibility_payload=payload["compatibility_payload"],
        definitions_payload=None,
        metadata=metadata,
        scan_summary=payload["scan_summary"],
        grade_data=grade_data,
        legacy_payload_size_bytes=_json_size_bytes(payload["legacy_payload"]),
        compatibility_payload_size_bytes=_json_size_bytes(
            payload["compatibility_payload"]
        ),
    )


def _failure_text(response, token: str) -> str:
    if not isinstance(response, dict):
        return "Skylos Cloud returned no result"
    failure = response.get("error")
    parts = [
        f"{key}={response[key]}"
        for key in ("code", "status", "request_id")
        if response.get(key) not in (None, "")
    ]
    for text in (failure, getattr(failure, "hint", None)):
        if text:
            parts.append(str(text))
    text = " ".join(" ".join(parts).split()) or "no reason returned"
    secret = token.split(":", 1)[-1]
    if secret:
        text = text.replace(secret, "[redacted]")
    return text[:1000]


def publish_pr_scan(input_path: Path, *, project_root: str, console: Console) -> int:
    from skylos.api import _FAILED_GATE_NOTE, BASE_URL, _send_prepared_upload
    from skylos.cloud.cloud_receipt import cloud_receipt_lines

    commit = _required_env("SKYLOS_COMMIT", _COMMIT_RE)
    pr_number = int(_required_env("SKYLOS_PR_NUMBER", _PR_NUMBER_RE))
    prepared = prepared_upload_from_artifact(
        _read_artifact(input_path),
        commit=commit,
        pr_number=pr_number,
        project_root=project_root,
    )
    token = _github_oidc_token()
    note = _FAILED_GATE_NOTE.set(False)
    try:
        response = _send_prepared_upload(
            token, prepared, kind="report", quiet=False, strict=False, is_forced=False
        )
    finally:
        _FAILED_GATE_NOTE.reset(note)
    sys.stdout.flush()
    if not isinstance(response, dict) or not response.get("success"):
        raise PrUploadError(
            "Skylos Cloud did not accept the pull request scan: "
            + _failure_text(response, token)
        )
    for line in cloud_receipt_lines(None, response, BASE_URL, ci_configured=True):
        console.print(escape(line), soft_wrap=True)
    return 0
