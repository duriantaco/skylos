"""Offline synthetic secrets contracts using native filesystem discovery.

Fixtures and expected answers belong to this harness, independently of the source
under test. No fixture contains an issued credential; verification is disabled.
The small capability suite is not a deployment precision/recall benchmark.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "benchmarks/secrets/manifest.json"
RECIPES = {
    "classic-keyed",
    "classic-unkeyed",
    "finegrain-keyed",
    "finegrain-unkeyed",
    "base64-once",
    "base64-twice",
    "json-unicode",
    "html-numeric",
    "env-generic",
    "env-reference",
    "public-hash",
    "public-sri",
    "prose-label",
    "placeholder",
    "public-url",
    "private-key-excerpt",
}
_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_ANCHOR = "benchmark_anchor.py"
TRUFFLEHOG_VERSION = "3.99.8"
_GIT_LOCAL = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_GRAFT_FILE",
    "GIT_INTERNAL_SUPER_PREFIX",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_IMPLICIT_WORK_TREE",
}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(_json(value))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _synthetic(label: str, length: int) -> str:
    """Produce deterministic alphanumeric material, never an issued credential."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    raw = hashlib.shake_256(("skylos-offline-shape:" + label).encode()).digest(length)
    return "".join(alphabet[value % len(alphabet)] for value in raw)


def fixture_content(recipe: str, *, seed: str = "default") -> bytes:
    classic = "gh" + "p_" + _synthetic(seed + ":classic", 36)
    finegrain = (
        "github"
        + "_pat_"
        + _synthetic(seed + ":fine-head", 22)
        + "_"
        + _synthetic(seed + ":fine-tail", 59)
    )
    if recipe in {"classic-keyed", "finegrain-keyed"}:
        token = classic if recipe == "classic-keyed" else finegrain
        return f'API_TOKEN = "{token}"\n'.encode()
    if recipe in {"classic-unkeyed", "finegrain-unkeyed"}:
        token = classic if recipe == "classic-unkeyed" else finegrain
        return f'payload = "{token}"\n'.encode()
    if recipe in {"base64-once", "base64-twice"}:
        encoded = base64.b64encode(classic.encode())
        if recipe == "base64-twice":
            encoded = base64.b64encode(encoded)
        return b'payload = "' + encoded + b'"\n'
    if recipe == "json-unicode":
        escaped = "".join("\\u%04x" % ord(character) for character in classic)
        return ('{"payload":"' + escaped + '"}\n').encode()
    if recipe == "html-numeric":
        escaped = "".join("&#%d;" % ord(character) for character in classic)
        return ('<div data-value="' + escaped + '">public fixture</div>\n').encode()
    if recipe == "env-generic":
        return ("PASSWORD=" + _synthetic(seed + ":generic", 36) + "\n").encode()
    if recipe == "env-reference":
        return b"API_TOKEN=${SERVICE_TOKEN}\n"
    if recipe == "public-hash":
        return (
            "hash: " + hashlib.sha256(b"public benchmark content").hexdigest() + "\n"
        ).encode()
    if recipe == "public-sri":
        digest = base64.b64encode(
            hashlib.sha512(b"public benchmark content").digest()
        ).decode()
        return (json.dumps({"integrity": "sha512-" + digest}) + "\n").encode()
    if recipe == "prose-label":
        return b'LABEL = "An access token is required for this request."\n'
    if recipe == "placeholder":
        return b'API_TOKEN = "your-api-key-here"\n'
    if recipe == "public-url":
        return b'endpoint = "https://api.example.invalid/v1/public/resource"\n'
    if recipe == "private-key-excerpt":
        return b'DOCUMENTATION = """-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"""\n'
    raise ValueError(f"unknown synthetic fixture recipe: {recipe}")


def load_manifest(
    path: Path, *, selected_cases: set[str] | None = None, track: str = "all"
) -> list[dict]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("expected a version 1 secrets manifest")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain cases")
    observed = set()
    for case in cases:
        if (
            not isinstance(case, dict)
            or not isinstance(case.get("id"), str)
            or not _ID.fullmatch(case["id"])
        ):
            raise ValueError("case requires a simple stable id")
        if case["id"] in observed:
            raise ValueError("duplicate case id")
        observed.add(case["id"])
        name = case.get("file")
        relative = Path(name) if isinstance(name, str) else Path("/")
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or "\\" in str(relative)
            or not relative.parts
            or str(relative) == _ANCHOR
        ):
            raise ValueError("fixture file must be a contained relative path")
        if case.get("recipe") not in RECIPES or case.get("track") not in {
            "regression",
            "capability",
        }:
            raise ValueError("unknown fixture recipe or track")
        expect = case.get("expect")
        if not isinstance(expect, dict) or type(expect.get("detected")) is not bool:
            raise ValueError("expected detection must be an explicit boolean")
        if expect["detected"] and expect.get("provider") not in {"github", "any"}:
            raise ValueError("positive case requires a supported provider expectation")
        if expect["detected"] and (
            type(expect.get("line")) is not int or expect["line"] < 1
        ):
            raise ValueError("positive case requires a reviewed source line")
    selected_cases = selected_cases or set()
    if selected_cases - observed:
        raise ValueError(
            "unknown selected secrets case: "
            + ", ".join(sorted(selected_cases - observed))
        )
    if track not in {"all", "regression", "capability"}:
        raise ValueError("unknown secrets track")
    selected = [
        case
        for case in cases
        if (not selected_cases or case["id"] in selected_cases)
        and (track == "all" or case["track"] == track)
    ]
    if not selected:
        raise ValueError("case selection is empty")
    return selected


def materialize(case: dict, directory: Path) -> dict[str, str]:
    """Create a fresh, identical filesystem input for either scanner."""
    relative = Path(case["file"])
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "\\" in str(relative)
        or not relative.parts
    ):
        raise ValueError("fixture file must stay within its private directory")
    directory.mkdir(parents=True, exist_ok=False)
    files = {
        _ANCHOR: b"BENCHMARK_ANCHOR = 1\n",
        case["file"]: fixture_content(case["recipe"], seed=case["id"]),
    }
    hashes = {}
    for name, content in files.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(content)
        target.chmod(0o444)
        hashes[name] = hashlib.sha256(content).hexdigest()
    return hashes


def source_identity(source: Path) -> dict:
    package = source / "skylos"
    if package.is_symlink() or not (package / "analyzer.py").is_file():
        raise ValueError("source must contain skylos/analyzer.py")
    files = {}
    for path in sorted(package.rglob("*")):
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise ValueError("analyzer source symlinks are unsupported")
        if path.is_file():
            files[path.relative_to(source).as_posix()] = _sha(path)
    process = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        env=_worker_environment(),
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "path": str(source),
        "git_commit": process.stdout.strip() if process.returncode == 0 else None,
        "sha256": _digest(files),
        "files": files,
    }


def worker(source: Path, fixture: Path, output: Path) -> int:
    """Only this isolated child imports the source-under-test analyzer."""
    from skylos.analyzer import analyze
    from skylos.benchmarks._analysis_validation import analysis_issues

    analyzer_path = Path(inspect.getsourcefile(analyze) or "").resolve(strict=True)
    if not analyzer_path.is_relative_to(source):
        raise ValueError("imported analyzer is outside requested source")
    raw = json.loads(
        analyze(
            str(fixture),
            conf=0,
            enable_secrets=True,
            enable_danger=False,
            enable_quality=False,
            enable_ai_defects=False,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )
    report = {
        "raw": raw,
        "errors": analysis_issues(raw, scanner="skylos"),
        "analyzer_path": str(analyzer_path),
        "analyzer_sha256": _sha(analyzer_path),
        "python": sys.version,
        "python_executable": sys.executable,
    }
    _write(output, report)
    return 0


def _relative(name: object, fixture: Path) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError("finding is missing a filename")
    path = Path(name)
    if path.is_absolute():
        try:
            return path.relative_to(fixture).as_posix()
        except ValueError:
            return "<outside-fixture>"
    if ".." in path.parts:
        return "<outside-fixture>"
    return path.as_posix()


def normalize(raw: object, *, scanner: str, fixture: Path) -> list[dict]:
    if scanner == "skylos":
        if not isinstance(raw, dict) or not isinstance(raw.get("secrets", []), list):
            raise ValueError("native secrets output is not a finding list")
        records = raw.get("secrets", [])
    else:
        if not isinstance(raw, list):
            raise ValueError("TruffleHog output is not a JSON record list")
        records = raw
    findings = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("finding is not an object")
        if scanner == "skylos":
            name, line, provider = (
                record.get("file"),
                record.get("line"),
                record.get("provider"),
            )
            rule = record.get("rule_id")
            col, end_col = record.get("col"), record.get("end_col")
        else:
            location = record
            for component in ("SourceMetadata", "Data", "Filesystem"):
                if not isinstance(location, dict):
                    raise ValueError("TruffleHog finding has invalid location metadata")
                location = location.get(component, {})
            if not isinstance(location, dict):
                raise ValueError("TruffleHog finding has invalid filesystem metadata")
            name, line = location.get("file"), location.get("line")
            provider, rule = (
                record.get("DetectorName"),
                str(record.get("DetectorType", "")),
            )
            col, end_col = None, None
        if (
            type(line) is not int
            or line < 1
            or not isinstance(provider, str)
            or not provider
        ):
            raise ValueError("finding requires a provider and positive line number")
        canonical = "github" if "github" in provider.casefold() else provider.casefold()
        findings.append(
            {
                "file": _relative(name, fixture),
                "line": line,
                "provider": canonical,
                "rule_id": rule,
                "col": col,
                "end_col": end_col,
            }
        )
    return findings


def grade(case: dict, findings: list[dict], errors: list[str]) -> dict:
    expected = case["expect"]
    target = [
        finding
        for finding in findings
        if finding["file"] == case["file"]
        and (not expected["detected"] or finding["line"] == expected["line"])
    ]
    detected = bool(target)
    provider = expected.get("provider")
    presence_passed = detected == expected["detected"]
    provider_passed = (
        not expected["detected"]
        or provider == "any"
        or any(f["provider"] == provider for f in target)
    )
    unexpected_locations = [f for f in findings if f not in target]
    identity_counts = Counter(_json(f) for f in findings)
    unique_locations = {(f["file"], f["line"]) for f in findings}
    status = (
        "incomplete"
        if errors
        else "passed"
        if presence_passed and provider_passed and not unexpected_locations
        else "failed"
    )
    return {
        "id": case["id"],
        "status": status,
        "expected": expected,
        "detected": detected,
        "presence_passed": presence_passed,
        "provider_passed": provider_passed,
        "classification_status": "not_applicable"
        if not expected["detected"] or provider == "any"
        else "matched"
        if provider_passed
        else "missing_expected_provider",
        "raw_finding_count": len(findings),
        "unique_finding_locations": len(unique_locations),
        "duplicate_identity_count": sum(
            count - 1 for count in identity_counts.values()
        ),
        "extra_findings_same_case": max(0, len(target) - int(detected)),
        "unexpected_locations": unexpected_locations,
        "findings": findings,
        "errors": list(dict.fromkeys(errors)),
    }


def _worker_environment() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("SKYLOS_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
        and key not in _GIT_LOCAL
    }
    env.update(
        SKYLOS_CUSTOM_RULES="[]",
        SKYLOS_NO_UPLOAD="1",
        SKYLOS_NO_TELEMETRY="1",
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONHASHSEED="0",
    )
    return env


def _run_scanner(
    scanner: str, fixture: Path, directory: Path, source: Path, trufflehog: Path | None
) -> tuple[list[dict], list[str], dict]:
    started = time.monotonic()
    errors = []
    metadata = {}
    if scanner == "skylos":
        command = [
            sys.executable,
            "-B",
            str(ROOT / "scripts/secrets_benchmark.py"),
            "--worker",
            "--source",
            str(source),
            "--fixture",
            str(fixture),
            "--worker-output",
            str(directory / "native.json"),
        ]
    else:
        if trufflehog is None:
            raise ValueError("--trufflehog is required for the TruffleHog scanner")
        command = [
            str(trufflehog),
            "filesystem",
            "--no-verification",
            "--no-update",
            "--json",
            "--results=verified,unverified,unknown",
            "--fail-on-scan-errors",
            str(fixture),
        ]
    metadata["command"] = command
    try:
        with (
            (directory / "stdout.txt").open("x") as stdout,
            (directory / "stderr.txt").open("x") as stderr,
        ):
            process = subprocess.run(
                command,
                cwd=fixture,
                env=_worker_environment(),
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=180,
            )
        metadata["returncode"] = process.returncode
        if process.returncode:
            errors.append(f"scanner exited with status {process.returncode}")
        if scanner == "skylos":
            native = json.loads((directory / "native.json").read_text())
            errors.extend(native["errors"])
            metadata.update(
                {
                    key: native[key]
                    for key in (
                        "analyzer_path",
                        "analyzer_sha256",
                        "python",
                        "python_executable",
                    )
                }
            )
            raw = native["raw"]
            metadata["native_analysis_summary"] = raw.get("analysis_summary", {})
        else:
            for line in (directory / "stderr.txt").read_text().splitlines():
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and str(
                    record.get("level", "")
                ).lower() in {"error", "fatal", "panic", "dpanic"}:
                    errors.append("TruffleHog reported an error in its stderr log")
            raw = [
                json.loads(line)
                for line in (directory / "stdout.txt").read_text().splitlines()
                if line.strip()
            ]
            _write(directory / "native.json", raw)
        findings = normalize(raw, scanner=scanner, fixture=fixture)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as error:
        errors.append(f"scanner evidence unavailable: {error}")
        findings = []
    metadata["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return findings, errors, metadata


def _harness_identity(manifest: Path) -> dict:
    return {
        "manifest_sha256": _sha(manifest),
        "module_sha256": _sha(Path(__file__)),
        "entry_sha256": _sha(ROOT / "scripts/secrets_benchmark.py"),
        "validation_sha256": _sha(ROOT / "skylos/benchmarks/_analysis_validation.py"),
    }


def run_manifest(
    manifest: Path = DEFAULT_MANIFEST,
    *,
    output: Path,
    scanner: str = "skylos",
    source: Path = ROOT,
    selected_cases: set[str] | None = None,
    track: str = "all",
    trufflehog: Path | None = None,
) -> dict:
    if scanner not in {"skylos", "trufflehog"}:
        raise ValueError("unsupported secrets scanner")
    source, manifest, output = (
        source.resolve(strict=True),
        manifest.resolve(strict=True),
        output.resolve(),
    )
    cases = load_manifest(manifest, selected_cases=selected_cases, track=track)
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    harness = _harness_identity(manifest)
    identity = source_identity(source) if scanner == "skylos" else None
    tool = {
        "name": scanner,
        "source": identity,
        "python": sys.version,
        "platform": platform.platform(),
        "verification": "disabled; no live credential claims",
        "distributions": sorted(
            {
                (d.metadata.get("Name", ""), d.version)
                for d in importlib.metadata.distributions()
            }
        ),
    }
    if scanner == "trufflehog":
        if trufflehog is None:
            raise ValueError("--trufflehog is required")
        trufflehog = trufflehog.resolve(strict=True)
        version = subprocess.run(
            [str(trufflehog), "--no-update", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if version.returncode:
            raise ValueError("could not identify the TruffleHog executable")
        version_text = (version.stdout + version.stderr).strip()
        if not re.search(r"\b" + re.escape(TRUFFLEHOG_VERSION) + r"\b", version_text):
            raise ValueError("this benchmark pins TruffleHog " + TRUFFLEHOG_VERSION)
        tool.update(
            binary=str(trufflehog),
            binary_sha256=_sha(trufflehog),
            version=version_text,
            detectors="default built-ins",
        )
    reports = []
    for case in cases:
        directory = output / case["id"]
        directory.mkdir()
        _write(directory / "expected.json", case)
        with tempfile.TemporaryDirectory(prefix="skylos-secrets-benchmark-") as temp:
            fixture = Path(temp) / "fixture"
            hashes = materialize(case, fixture)
            _write(directory / "inputs.json", hashes)
            findings, errors, execution = _run_scanner(
                scanner, fixture, directory, source, trufflehog
            )
            after = {name: _sha(fixture / name) for name in hashes}
            if hashes != after:
                errors.append("fixture bytes changed during execution")
            report = grade(case, findings, errors)
            report.update(
                input_sha256=_digest(hashes),
                input_files=hashes,
                execution=execution,
                coverage="native filesystem discovery; target read coverage is not inferred from the benign source anchor",
            )
            _write(directory / "case.json", report)
            reports.append(report)
    errors = []
    if identity is not None and source_identity(source) != identity:
        errors.append("analyzer source changed during the run")
    if harness != _harness_identity(manifest):
        errors.append("harness or expected manifest changed during the run")
    if scanner == "trufflehog" and _sha(trufflehog) != tool["binary_sha256"]:
        errors.append("TruffleHog executable changed during the run")
    summary = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scope": "20-case synthetic offline shape/discovery contracts; not live-secret precision or universal accuracy",
        "scanner": scanner,
        "tool": tool,
        "harness": harness,
        "track": track,
        "case_count": len(reports),
        "failure_count": sum(r["status"] == "failed" for r in reports),
        "incomplete_count": sum(r["status"] == "incomplete" for r in reports),
        "passed_count": sum(r["status"] == "passed" for r in reports),
        "positive_cases": sum(r["expected"]["detected"] for r in reports),
        "detected_positive_cases": sum(
            r["expected"]["detected"] and r["detected"] and not r["errors"]
            for r in reports
        ),
        "missed_positive_cases": sum(
            r["expected"]["detected"] and not r["detected"] and not r["errors"]
            for r in reports
        ),
        "classification_failure_count": sum(
            r["detected"] and not r["provider_passed"] and not r["errors"]
            for r in reports
        ),
        "unexpected_finding_cases": sum(
            not r["expected"]["detected"] and bool(r["findings"]) and not r["errors"]
            for r in reports
        ),
        "raw_finding_count": sum(r["raw_finding_count"] for r in reports),
        "extra_findings_same_case": sum(r["extra_findings_same_case"] for r in reports),
        "errors": errors,
        "cases": reports,
        "elapsed_seconds": round(time.monotonic() - started, 4),
    }
    summary["passed"] = (
        not errors and not summary["failure_count"] and not summary["incomplete_count"]
    )
    _write(output / "summary.json", summary)
    return summary


def format_summary(summary: dict) -> str:
    lines = [
        f"Secrets shape contracts ({summary['scanner']}): {summary['passed_count']}/{summary['case_count']} passed",
        f"Missed positives: {summary['missed_positive_cases']}; provider-label gaps: {summary['classification_failure_count']}; safe cases with findings: {summary['unexpected_finding_cases']}",
        f"Incomplete: {summary['incomplete_count']}; runtime/input errors: {len(summary['errors'])}",
        "Synthetic detection only; verification disabled, no live-secret accuracy claim.",
    ]
    lines.extend(
        f"  {case['id']}: {case['status']} (detected={case['detected']}, provider={case['classification_status']})"
        for case in summary["cases"]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--scanner", choices=("skylos", "trufflehog"), default="skylos")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--trufflehog", type=Path)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument(
        "--track", choices=("all", "regression", "capability"), default="all"
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--fixture", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        return worker(
            args.source.resolve(strict=True),
            args.fixture.resolve(strict=True),
            args.worker_output,
        )
    output = (
        args.output
        or ROOT / ".skylos/evals/secrets" / f"{time.time_ns()}-{args.scanner}"
    )
    try:
        summary = run_manifest(
            args.manifest,
            output=output,
            scanner=args.scanner,
            source=args.source,
            selected_cases=set(args.case),
            track=args.track,
            trufflehog=args.trufflehog,
        )
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        print(f"Secrets benchmark could not run: {error}", file=sys.stderr)
        return 2
    print(_json(summary) if args.json else format_summary(summary))
    return 0 if summary["passed"] else 1
