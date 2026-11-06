"""Offline checks of selected facts in caller-supplied pinned upstream trees.

These labels are an open set, so this runner deliberately computes no accuracy
score. It reads source and Git metadata; it never prepares or runs target code.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from skylos.analyzer import analyze
from skylos.benchmarks._analysis_validation import analysis_issues
from skylos.core.git_context import GitContext
from skylos.core.safe_cache_io import read_project_text_no_symlink


_KINDS = {"ruby_dead_code", "terraform_policy"}
_STATUSES = {"unsafe", "safe", "unknown", "not_applicable"}
_RULES = {"SKY-D400", "SKY-D401"}
_RESOURCE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]*\Z")
_MAX_SOURCE_BYTES = 16 * 1024 * 1024


def _relative(value, *, dot=False):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("expected a contained relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or (not dot and value == "."):
        raise ValueError("expected a contained relative path")
    return path


def load_manifest(path):
    """Validate frozen selected labels, without contacting their repositories."""
    path = Path(path).absolute()
    text = read_project_text_no_symlink(path.parent, path, max_bytes=2_000_000)
    if text is None:
        raise ValueError("manifest is missing, unreadable, oversized or a symlink")
    manifest = json.loads(text)
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != 1
        or manifest.get("label_scope") != "open"
        or not isinstance(manifest.get("targets"), list)
        or not manifest["targets"]
    ):
        raise ValueError("holdout manifest needs version 1, open labels and targets")
    ids = set()
    for target in manifest["targets"]:
        if not isinstance(target, dict):
            raise ValueError("target must be an object")
        ident = target.get("id")
        if not isinstance(ident, str) or not ident or ident in ids:
            raise ValueError("target ids must be unique nonempty strings")
        ids.add(ident)
        if target.get("kind") not in _KINDS or not re.fullmatch(
            r"[0-9a-f]{40}", str(target.get("ref", ""))
        ):
            raise ValueError(f"{ident}: unsupported kind or nonimmutable ref")
        if not isinstance(target.get("repo"), str) or not target["repo"].startswith(
            "https://"
        ):
            raise ValueError(f"{ident}: expected an HTTPS origin")
        _relative(target.get("checkout"))
        _relative(target.get("scan_root"), dot=True)
        sources = target.get("source_files")
        expected = target.get("expectations")
        if (
            not isinstance(sources, list)
            or not sources
            or not isinstance(expected, list)
            or not expected
        ):
            raise ValueError(f"{ident}: nonempty source hashes and labels required")
        paths = set()
        for source in sources:
            if not isinstance(source, dict):
                raise ValueError(f"{ident}: invalid source record")
            name = _relative(source.get("path")).as_posix()
            if name in paths or not re.fullmatch(
                r"[0-9a-f]{64}", str(source.get("sha256", ""))
            ):
                raise ValueError(f"{ident}: duplicate source or invalid SHA-256")
            paths.add(name)
        seen = set()
        for fact in expected:
            if not isinstance(fact, dict):
                raise ValueError(f"{ident}: invalid fact")
            name = _relative(fact.get("file")).as_posix()
            if (
                name not in paths
                or type(fact.get("line")) is not int
                or fact["line"] < 1
            ):
                raise ValueError(
                    f"{ident}: fact requires hashed source and positive line"
                )
            if target["kind"] == "ruby_dead_code":
                key = (name, fact.get("symbol"), fact["line"])
                valid = (
                    fact.get("kind") == "ruby_used"
                    and isinstance(fact.get("symbol"), str)
                    and bool(fact["symbol"])
                )
            else:
                key = (name, fact.get("rule_id"), fact.get("resource"), fact["line"])
                valid = (
                    fact.get("kind") == "terraform_policy"
                    and fact.get("rule_id") in {"SKY-D400", "SKY-D401"}
                    and fact.get("status") in _STATUSES
                    and isinstance(fact.get("resource"), str)
                    and bool(fact["resource"])
                )
            if not valid or key in seen:
                raise ValueError(f"{ident}: invalid or duplicate fact")
            seen.add(key)
    return manifest


def _contained(root, relative):
    current = root
    for part in _relative(relative, dot=True).parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"symlink input: {relative}")
    return current


def _git(context, *args):
    result = context.run(*args)
    if result.returncode:
        raise ValueError(f"read-only Git check failed: {args[0]}")
    return result.stdout.strip()


def _tracked_snapshot(context, checkout, ref):
    """Bypass Git's stat cache and compare all context bytes to pinned blobs."""
    tree, index = {}, {}
    for entry in _git(context, "ls-tree", "-r", "-z", "--full-tree", ref).split("\0"):
        if not entry:
            continue
        metadata, name = entry.split("\t", 1)
        mode, kind, digest = metadata.split()
        _relative(name)
        if (
            mode not in {"100644", "100755"}
            or kind != "blob"
            or not re.fullmatch(r"[0-9a-f]{40}", digest)
            or name in tree
        ):
            raise ValueError("unsupported or duplicate pinned Git tree entry")
        tree[name] = (mode, digest)
    for entry in _git(context, "ls-files", "--stage", "-z").split("\0"):
        if not entry:
            continue
        metadata, name = entry.split("\t", 1)
        mode, digest, stage = metadata.split()
        if stage != "0" or name in index:
            raise ValueError("unsupported or duplicate Git index stage")
        index[name] = (mode, digest)
    if not tree or index != tree:
        raise ValueError("Git index does not match the pinned tree")
    snapshot = {}
    for name, (mode, digest) in tree.items():
        path = _contained(checkout, name)
        content = read_project_text_no_symlink(
            checkout,
            path,
            max_bytes=_MAX_SOURCE_BYTES,
            encoding="utf-8",
            errors="surrogateescape",
            newline="",
        )
        if content is None:
            raise ValueError(f"tracked context is unreadable or not regular: {name}")
        data = content.encode("utf-8", "surrogateescape")
        actual = hashlib.sha1(
            b"blob " + str(len(data)).encode("ascii") + b"\0" + data,
            usedforsecurity=False,
        ).hexdigest()
        if actual != digest or bool(path.stat().st_mode & 0o111) != (mode == "100755"):
            raise ValueError(f"tracked context does not match pinned Git blob: {name}")
        snapshot[name] = digest
    return snapshot


def verify_checkout(target, checkout_root):
    """Require the exact clean upstream tree and unchanged bounded source bytes."""
    supplied = Path(checkout_root).absolute()
    # Check ancestors before canonicalizing: resolving must not hide symlinks.
    current = Path(supplied.anchor)
    for part in supplied.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("checkout root contains a symlink")
    supplied = supplied.resolve()
    checkout = _contained(supplied, target["checkout"])
    if not checkout.is_dir():
        raise ValueError("missing checkout directory")

    # Refuse special files before even asking Git to inspect worktree content.
    def unreadable(error):
        raise error

    for directory, dirs, files in os.walk(
        checkout, followlinks=False, onerror=unreadable
    ):
        if Path(directory) == checkout:
            dirs[:] = [name for name in dirs if name != ".git"]
        for name in (*dirs, *files):
            mode = (Path(directory) / name).lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError("checkout contains a symlink or special file")
    context = GitContext.from_path(checkout)
    if (
        Path(_git(context, "rev-parse", "--show-toplevel")).resolve()
        != checkout.resolve()
    ):
        raise ValueError("checkout is not its own Git worktree")
    if _git(context, "rev-parse", "HEAD") != target["ref"]:
        raise ValueError("checkout HEAD does not match pinned ref")
    origins = _git(context, "config", "--get-all", "remote.origin.url").splitlines()
    if len(origins) != 1 or origins[0].removesuffix(".git") != target[
        "repo"
    ].removesuffix(".git"):
        raise ValueError("checkout origin does not match expected upstream")
    # Git status deliberately trusts these index flags; do not let them hide
    # changed or absent sources. Submodules would require separate pins.
    if any(
        not entry.startswith("H ")
        for entry in _git(context, "ls-files", "-v", "-z").split("\0")
        if entry
    ):
        raise ValueError("checkout has assume-unchanged or sparse index entries")
    if any(
        entry.startswith("160000 ")
        for entry in _git(context, "ls-files", "--stage", "-z").split("\0")
        if entry
    ):
        raise ValueError("checkout contains separately unpinned submodules")
    if _git(
        context,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=none",
    ):
        raise ValueError("checkout has tracked, untracked or ignored changes")
    scan_root = _contained(checkout, target["scan_root"])
    if not scan_root.is_dir():
        raise ValueError("missing scan directory")
    hashes = {}
    for source in target["source_files"]:
        path = _contained(checkout, source["path"])
        content = read_project_text_no_symlink(
            checkout,
            path,
            max_bytes=_MAX_SOURCE_BYTES,
            encoding="utf-8",
            errors="surrogateescape",
            newline="",
        )
        if content is None:
            raise ValueError(
                f"source is missing, unreadable or not regular: {source['path']}"
            )
        digest = hashlib.sha256(content.encode("utf-8", "surrogateescape")).hexdigest()
        if digest != source["sha256"]:
            raise ValueError(f"source SHA-256 mismatch: {source['path']}")
        hashes[source["path"]] = digest
    snapshot = _tracked_snapshot(context, checkout, target["ref"])
    return checkout, scan_root, hashes, snapshot


@contextmanager
def _isolated_environment():
    # No source evaluation occurs, and optional services/custom rules stay off.
    original = dict(os.environ)
    try:
        for key in tuple(os.environ):
            upper = key.upper()
            if any(
                word in upper
                for word in ("TOKEN", "PASSWORD", "SECRET", "CREDENTIAL", "API_KEY")
            ) or upper.startswith(
                ("AWS_", "AZURE_", "GOOGLE_", "GITHUB_", "GH_", "SKYLOS_")
            ):
                os.environ.pop(key, None)
        os.environ.update({"SKYLOS_CUSTOM_RULES": "[]", "DO_NOT_TRACK": "1"})
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def scan_target(target, scan_root):
    """Static native analyzer only; no fetching, installing or target execution."""
    options = target.get("scan", {})
    with _isolated_environment():
        report = analyze(
            str(scan_root),
            conf=options.get("confidence", 0),
            enable_danger=target["kind"] == "terraform_policy",
            enable_quality=False,
            enable_secrets=False,
            enable_ai_defects=False,
            enable_sca=False,
            enable_dependency_hallucinations=False,
            custom_rules_data=[],
            grep_verify=options.get("grep_verify", False),
            grep_cache=False,
            trace_file=False,
            all_advice=True,
            # Suppression cannot silently win: selected definitions/checks must
            # still positively exist and unsafe findings must be present.
            project_config_overrides={"ignore": [], "exclude": []},
        )
    return json.loads(report) if isinstance(report, str) else report


def _file(record, checkout):
    value = record.get("file")
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        return None
    path = Path(value)
    if ".." in path.parts:
        return None
    if not path.is_absolute():
        path = checkout / path
    try:
        return path.absolute().relative_to(checkout).as_posix()
    except ValueError:
        return None


def _identity(record, checkout, *, ruby=False):
    return (
        (record.get("name"),)
        if ruby
        else (record.get("rule_id"), record.get("resource"))
    ) + (_file(record, checkout), record.get("line"))


def _text(value):
    return isinstance(value, str) and bool(value.strip()) and "\0" not in value


def _location_valid(record, checkout):
    return (
        isinstance(record, Mapping)
        and type(record.get("line")) is int
        and record["line"] > 0
        and _file(record, checkout) is not None
    )


def _ruby_identity_valid(record, checkout):
    return (
        _location_valid(record, checkout)
        and _text(record.get("name"))
        and ("full_name" not in record or _text(record["full_name"]))
    )


def _policy_identity_valid(record, checkout):
    return (
        _location_valid(record, checkout)
        and isinstance(record.get("rule_id"), str)
        and record.get("rule_id") in _RULES
        and isinstance(record.get("resource"), str)
        and _RESOURCE.fullmatch(record["resource"]) is not None
    )


def _terraform_coverage_issues(coverage, records, checkout):
    failures = []
    for key in (
        "files_discovered",
        "files_parsed",
        "resources",
        "checks_evaluated",
        "unsupported_resource_count",
        "unresolved_module_count",
        "modules",
        "resolution_attempts",
        "unresolved_resolution_attempts",
    ):
        if type(coverage.get(key)) is not int or coverage[key] < 0:
            failures.append(f"Terraform {key} must be a nonnegative exact integer")
    supported = coverage.get("supported_rules")
    if (
        not isinstance(supported, list)
        or not supported
        or any(not isinstance(rule, str) or rule not in _RULES for rule in supported)
        or len(set(supported)) != len(supported)
        or any(c["rule_id"] not in supported for c in records)
    ):
        failures.append("invalid or inconsistent supported Terraform rules")
    actual_counts = Counter(c["status"] for c in records)
    counts = coverage.get("evaluation_counts")
    if (
        not isinstance(counts, Mapping)
        or set(counts) != _STATUSES
        or any(
            type(counts.get(status)) is not int
            or counts[status] != actual_counts[status]
            for status in _STATUSES
        )
    ):
        failures.append("Terraform evaluation counts disagree with policy records")
    unsupported, modules = (
        coverage.get("unsupported_resources"),
        coverage.get("module_calls"),
    )
    for name, entries, count in (
        (
            "unsupported resources",
            unsupported,
            coverage.get("unsupported_resource_count"),
        ),
        ("module calls", modules, coverage.get("unresolved_module_count")),
    ):
        if (
            not isinstance(entries, list)
            or any(not _location_valid(e, checkout) for e in entries)
            or count != len(entries)
        ):
            failures.append(f"invalid or inconsistent Terraform {name}")
    if isinstance(unsupported, list) and any(
        not isinstance(e, Mapping)
        or not isinstance(e.get("resource"), str)
        or not _RESOURCE.fullmatch(e["resource"])
        for e in unsupported
    ):
        failures.append("invalid unsupported Terraform resource identity")
    if not failures:
        if (
            coverage["resources"] != len(records) + len(unsupported)
            or coverage["checks_evaluated"] != len(records)
            or coverage["modules"] < 1
            or coverage["unresolved_resolution_attempts"]
            > coverage["resolution_attempts"]
        ):
            failures.append("Terraform resource or resolution coverage is inconsistent")
        expected_status = (
            "partial"
            if actual_counts["unknown"] or unsupported or modules
            else "complete"
        )
        if coverage.get("evaluation_status") != expected_status:
            failures.append("Terraform evaluation status disagrees with coverage")
    return failures


def evaluate_target(target, report, checkout):
    """Match selected positive evidence; unreviewed output is not ground truth."""
    failures, facts, counts = [], [], Counter()
    if not isinstance(report, Mapping):
        return {
            "failures": ["analysis report is not an object"],
            "facts": [],
            "outcomes": {},
        }
    summary = report.get("analysis_summary")
    summary = summary if isinstance(summary, Mapping) else {}
    if target["kind"] == "ruby_dead_code":
        failures.extend(analysis_issues(report, scanner="skylos"))
        if (
            report.get("analysis_errors") != []
            or type(summary.get("analysis_error_count")) is not int
            or summary["analysis_error_count"] != 0
        ):
            failures.append("Ruby analysis must explicitly report zero errors")
        languages = summary.get("languages", {})
        if (
            not isinstance(languages, Mapping)
            or type(languages.get("Ruby")) is not int
            or languages["Ruby"] <= 0
        ):
            failures.append("positive Ruby language coverage is required")
        definitions = report.get("definitions")
        if not isinstance(definitions, Mapping) or any(
            not isinstance(d, Mapping) for d in definitions.values()
        ):
            failures.append("missing or invalid parsed definitions")
            definitions = {}
        records = []
        for symbol, definition in definitions.items():
            if (
                not _ruby_identity_valid(definition, checkout)
                or definition.get("name") != symbol
            ):
                failures.append("parsed definition name disagrees with identity")
            records.append(definition)
        unused = []
        for name in (
            "unused_functions",
            "unused_classes",
            "unused_imports",
            "unused_variables",
            "unused_parameters",
            "unused_files",
        ):
            entries = report.get(name, [])
            if not isinstance(entries, list) or any(
                not _ruby_identity_valid(e, checkout) for e in entries
            ):
                failures.append(f"invalid {name} collection")
            else:
                unused.extend(entries)
        for fact in target["expectations"]:
            key = (fact["symbol"], fact["file"], fact["line"])
            matches = [d for d in records if _identity(d, checkout, ruby=True) == key]
            okay = (
                len(matches) == 1
                and matches[0].get("name") == fact["symbol"]
                and matches[0].get("dead") is False
                and not any(
                    (
                        d.get("full_name", d["name"]) == fact["symbol"]
                        or d["name"] == fact["symbol"]
                    )
                    and _file(d, checkout) == fact["file"]
                    for d in unused
                )
            )
            facts.append(
                {"expected": fact, "matched": okay, "definition_matches": len(matches)}
            )
            if okay:
                counts["ruby_used"] += 1
            else:
                failures.append(f"missing, duplicate or unused Ruby definition: {key}")
        coverage = summary
        unreviewed = len(unused)
    else:
        configuration = summary.get("configuration_coverage", {})
        coverage = (
            configuration.get("terraform", {})
            if isinstance(configuration, Mapping)
            else {}
        )
        if not isinstance(coverage, Mapping):
            coverage = {}
        discovered, parsed, resources = (
            coverage.get(k) for k in ("files_discovered", "files_parsed", "resources")
        )
        if not (
            type(discovered) is int
            and discovered > 0
            and type(parsed) is int
            and parsed == discovered
            and type(resources) is int
            and resources >= len({f["resource"] for f in target["expectations"]})
            and coverage.get("status") == "complete"
            and report.get("analysis_errors") == []
            and type(summary.get("total_files")) is int
            and summary["total_files"] >= 0
            and type(summary.get("analysis_error_count")) is int
            and summary.get("analysis_error_count") == 0
            and coverage.get("discovery_errors") == []
        ):
            failures.append(
                "Terraform parsing/resource coverage is missing or incomplete"
            )
        records = coverage.get("checks", [])
        dangers = report.get("danger", [])
        if not isinstance(records, list) or any(
            not _policy_identity_valid(c, checkout)
            or not isinstance(c.get("status"), str)
            or c["status"] not in _STATUSES
            for c in records
        ):
            failures.append("invalid Terraform checks")
            records = []
        if coverage.get("checks_evaluated") != len(records):
            failures.append("Terraform check count does not match coverage")
        failures.extend(_terraform_coverage_issues(coverage, records, checkout))
        identities = [_identity(c, checkout) for c in records]
        if len(set(identities)) != len(identities):
            failures.append("duplicate Terraform policy identities")
        if not isinstance(dangers, list) or any(
            not _location_valid(d, checkout)
            or not _text(d.get("rule_id"))
            or (d["rule_id"] in _RULES and not _policy_identity_valid(d, checkout))
            for d in dangers
        ):
            failures.append("invalid danger collection")
            dangers = []
        for check in records:
            matches = [
                d
                for d in dangers
                if _identity(d, checkout) == _identity(check, checkout)
            ]
            if len(matches) != (1 if check["status"] == "unsafe" else 0):
                failures.append("Terraform finding/check agreement is inconsistent")
        if any(
            d["rule_id"] in _RULES and _identity(d, checkout) not in identities
            for d in dangers
        ):
            failures.append("Terraform finding lacks a corresponding policy check")
        selected = set()
        for fact in target["expectations"]:
            key = (fact["rule_id"], fact["resource"], fact["file"], fact["line"])
            selected.add(key)
            matches = [c for c in records if _identity(c, checkout) == key]
            findings = [d for d in dangers if _identity(d, checkout) == key]
            okay = (
                len(matches) == 1
                and matches[0].get("status") == fact["status"]
                and len(findings) == (1 if fact["status"] == "unsafe" else 0)
            )
            facts.append(
                {
                    "expected": fact,
                    "matched": okay,
                    "check_matches": len(matches),
                    "finding_matches": len(findings),
                    "actual_statuses": [c.get("status") for c in matches],
                }
            )
            if okay:
                counts[fact["status"]] += 1
            else:
                failures.append(
                    f"Terraform check/finding mismatch: {key}, expected {fact['status']}"
                )
        unreviewed = sum(_identity(d, checkout) not in selected for d in dangers)
    return {
        "failures": failures,
        "facts": facts,
        "outcomes": {} if failures else dict(counts),
        "coverage": coverage,
        "unreviewed_findings": unreviewed,
        "unreviewed_checks": sum(
            not any(
                _identity(c, checkout)
                == (f["rule_id"], f["resource"], f["file"], f["line"])
                for f in target["expectations"]
            )
            for c in records
        )
        if target["kind"] == "terraform_policy"
        else None,
    }


def run_manifest(path, *, checkout_root, selected_targets=None):
    """Run selected facts offline; absent or changed inputs are failed targets."""
    manifest = load_manifest(path)
    selected = set(selected_targets or ())
    if selected - {target["id"] for target in manifest["targets"]}:
        raise ValueError("unknown holdout target id")
    results = []
    for target in manifest["targets"]:
        if selected and target["id"] not in selected:
            continue
        result = {
            "id": target["id"],
            "ref": target["ref"],
            "limitations": target.get("limitations", []),
            "failures": [],
            "outcomes": {},
        }
        try:
            checkout, scan_root, before, snapshot_before = verify_checkout(
                target, checkout_root
            )
            result["source_hashes_before"] = before
            result["tracked_blob_snapshot_before"] = snapshot_before
            report = scan_target(target, scan_root)
            result["analysis"] = report
            # Recheck ref/origin/cleanliness/hashes even when the report is bad.
            _, _, after, snapshot_after = verify_checkout(target, checkout_root)
            result["source_hashes_after"] = after
            result["tracked_blob_snapshot_after"] = snapshot_after
            result.update(evaluate_target(target, report, checkout))
        except Exception as exc:
            result["failures"].append(f"{type(exc).__name__}: {exc}")
            result["outcomes"] = {}
        results.append(result)
    totals = Counter()
    for result in results:
        totals.update(result["outcomes"])
    return {
        "manifest": str(Path(path).absolute()),
        "label_scope": "open",
        "target_count": len(results),
        "pass_count": sum(not r["failures"] for r in results),
        "failure_count": sum(len(r["failures"]) for r in results),
        "selected_fact_outcomes": dict(totals),
        "targets": results,
        "note": "Selected facts only. Unknown and not_applicable are separate from safe. Unreviewed findings are not false positives; no whole-repository accuracy is measured.",
    }


def format_summary(result):
    lines = [
        f"Offline holdouts: {result['pass_count']}/{result['target_count']} selected target contracts passed; {result['failure_count']} failures",
        result["note"],
    ]
    for target in result["targets"]:
        lines.append(
            f"{target['id']}: outcomes={target['outcomes']}; unreviewed findings={target.get('unreviewed_findings', 'unavailable')}"
        )
        coverage = target.get("coverage", {})
        if "evaluation_status" in coverage:
            lines.append(
                f"Terraform evaluation={coverage['evaluation_status']}; unsupported resources={coverage.get('unsupported_resource_count')}; unresolved modules={coverage.get('unresolved_module_count')}"
            )
        lines.extend(f"  {failure}" for failure in target["failures"])
    return "\n".join(lines)
