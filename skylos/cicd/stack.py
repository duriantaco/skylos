"""Verify a declared Git stack using Done receipts from the customer's CI."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from skylos import __version__
from skylos.cicd.policy import _base_text
from skylos.config import ConfigError
from skylos.core.git_context import GitContext
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.done.config import (
    CHECK_IDS,
    CONFIG_FILE_NAMES,
    DoneConfig,
    parse_done_config,
)
from skylos.done.receipt import (
    MAX_RECEIPT_BYTES,
    validate_receipt,
)
from skylos.done.receipt import (
    SCHEMA as RECEIPT_SCHEMA,
)

SCHEMA = "skylos.stack/v1"
MAX_LAYERS = 20
_MAX_MANIFEST_BYTES = 64 * 1024
_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class StackError(Exception):
    """The stack or its pinned inputs could not be checked."""


@dataclass(frozen=True)
class Revision:
    sha: str
    tree: str


@dataclass(frozen=True)
class Stack:
    base: Revision
    layers: tuple[Revision, ...]
    original: Revision | None
    config: DoneConfig

    def manifest(self) -> dict:
        return {
            "schema": SCHEMA,
            "skylos_version": __version__,
            "base": asdict(self.base),
            "layers": [asdict(layer) for layer in self.layers],
            "original": asdict(self.original) if self.original else None,
            "config_digest": self.config.digest(),
        }


def _resolve(context: GitContext, ref: str) -> Revision:
    result = context.run(
        "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"
    )
    sha = result.stdout.strip()
    if result.returncode or not _OBJECT_ID.fullmatch(sha):
        raise StackError(
            f"Cannot resolve commit {ref!r}; fetch it before checking the stack"
        )
    result = context.run("rev-parse", "--verify", f"{sha}^{{tree}}")
    tree = result.stdout.strip()
    if result.returncode or not _OBJECT_ID.fullmatch(tree):
        raise StackError(f"Cannot read the Git tree of {sha}")
    return Revision(sha, tree)


def _require_ancestor(context: GitContext, lower: Revision, upper: Revision) -> None:
    result = context.run("merge-base", "--is-ancestor", lower.sha, upper.sha)
    if result.returncode not in (0, 1):
        raise StackError("Cannot check Git ancestry; fetch the complete stack history")
    if result.returncode == 1 or lower.sha == upper.sha:
        raise StackError(f"{upper.sha} must strictly descend from {lower.sha}")


def _load_policy(context: GitContext, base: Revision) -> DoneConfig:
    text = None
    try:
        for name in CONFIG_FILE_NAMES:
            text = _base_text(context, base.sha, name)
            if text is not None:
                break
    except (ConfigError, UnicodeError) as exc:
        raise StackError(
            f"Cannot read Done policy at stack base {base.sha}: {exc}"
        ) from exc
    config = parse_done_config(text)
    if config.problems:
        raise StackError(
            "Invalid Done policy at the stack base: " + "; ".join(config.problems)
        )
    if config.mode("tests_pass") != "block" or config.allow_preexisting_failures:
        raise StackError(
            "The stack base must require passing tests without a pre-existing-failure exception"
        )
    return config


def plan_stack(
    path: Path, base_ref: str, layer_refs: list[str], original_ref: str | None
) -> Stack:
    if not 2 <= len(layer_refs) <= MAX_LAYERS:
        raise StackError(f"Supply 2 to {MAX_LAYERS} ordered layer tips")
    context = GitContext.from_path(path)
    history = context.run("rev-parse", "--is-shallow-repository")
    if history.returncode or history.stdout.strip() != "false":
        raise StackError("Stack checks require a Git repository with complete history")
    base = _resolve(context, base_ref)
    layers = tuple(_resolve(context, ref) for ref in layer_refs)
    for lower, upper in zip((base, *layers[:-1]), layers):
        _require_ancestor(context, lower, upper)
    original = _resolve(context, original_ref) if original_ref is not None else None
    if original is not None:
        _require_ancestor(context, base, original)
        if original.tree != layers[-1].tree:
            raise StackError(
                "The stack tip's Git tree differs from the original commit's tree"
            )
    return Stack(base, layers, original, _load_policy(context, base))


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed = dict(pairs)
    if len(parsed) != len(pairs):
        raise ValueError("duplicate JSON key")
    return parsed


def _read_json(path: Path, limit: int) -> object:
    text = read_project_text_no_symlink(path.parent, path.name, max_bytes=limit)
    if text is None:
        raise StackError("File is missing, unreadable or oversized")
    try:
        return json.loads(text, object_pairs_hook=_unique_keys)
    except (ValueError, RecursionError) as exc:
        raise StackError("File is not valid JSON") from exc


def _manifest_commit(value: object) -> str:
    sha = value.get("sha") if isinstance(value, dict) else None
    if not isinstance(sha, str) or not _OBJECT_ID.fullmatch(sha):
        raise StackError("The stack manifest must pin full Git commit IDs")
    return sha


def read_manifest(path: Path, manifest_path: Path) -> Stack:
    data = _read_json(manifest_path, _MAX_MANIFEST_BYTES)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise StackError(f"Expected a {SCHEMA} manifest")
    if data.get("skylos_version") != __version__:
        raise StackError("Use the same Skylos version to plan and verify the stack")
    layers = data.get("layers")
    if not isinstance(layers, list) or not 2 <= len(layers) <= MAX_LAYERS:
        raise StackError(f"The stack manifest must contain 2 to {MAX_LAYERS} layers")
    original = data.get("original")
    stack = plan_stack(
        path,
        _manifest_commit(data.get("base")),
        [_manifest_commit(layer) for layer in layers],
        _manifest_commit(original) if original is not None else None,
    )
    if data != stack.manifest():
        raise StackError(
            "Stack manifest does not match the pinned Git objects and Done policy"
        )
    return stack


def _check_receipt(stack: Stack, layer: Revision, receipt: object) -> int:
    invalid = f"Invalid Done receipt; expected a valid {RECEIPT_SCHEMA} record"
    if not isinstance(receipt, dict):
        raise StackError(invalid)
    try:
        problems = validate_receipt(receipt)
    except RecursionError as exc:
        raise StackError(invalid) from exc
    if problems:
        raise StackError(invalid)
    if receipt["base"] != {"sha": stack.base.sha, "source": "merge_base"}:
        raise StackError("Done receipt is not for the pinned stack base")
    if receipt["head"] != {"sha": layer.sha, "dirty": False}:
        raise StackError("Done receipt is not for the exact clean layer commit")
    if receipt.get("skylos_version") != __version__:
        raise StackError("Done receipt was produced by a different Skylos version")
    if receipt.get("config_digest") != stack.config.digest():
        raise StackError("Done receipt did not use the pinned base policy")
    checks = {check["id"]: check for check in receipt["checks"]}
    if set(checks) != set(CHECK_IDS):
        raise StackError("Done receipt does not include the complete set of checks")
    for name, check in checks.items():
        if check["mode"] != stack.config.mode(name):
            raise StackError(f"Done receipt changed the policy for {name}")
        if check["mode"] == "block" and check["status"] != "pass":
            raise StackError(f"Required Done check {name} did not pass")
    if receipt["verdict"] != "pass":
        raise StackError("Done did not pass")
    evidence = checks["tests_pass"].get("evidence")
    counts = (
        "run",
        "passed",
        "skipped",
        "failed",
        "flaky",
        "not_run",
        "unknown_case_totals",
    )
    if not isinstance(evidence, dict) or any(
        type(evidence.get(key)) is not int or evidence[key] < 0 for key in counts
    ):
        raise StackError("Done receipt is missing valid test counts")
    if any(
        evidence[key] for key in ("failed", "flaky", "not_run", "unknown_case_totals")
    ):
        raise StackError("Done receipt records failed, flaky or missing tests")
    if (
        evidence["passed"] == 0
        or evidence["passed"] + evidence["skipped"] != evidence["run"]
    ):
        raise StackError("Done receipt does not show a completed passing test run")
    return evidence["passed"]


def verify_stack(stack: Stack, receipts_dir: Path) -> dict:
    results = []
    for layer in stack.layers:
        entry = asdict(layer)
        try:
            receipt = _read_json(receipts_dir / f"{layer.sha}.json", MAX_RECEIPT_BYTES)
            entry.update(
                status="passed", tests_passed=_check_receipt(stack, layer, receipt)
            )
        except StackError as exc:
            entry.update(status="not_verified", reason=str(exc))
        results.append(entry)
    return {
        "schema": "skylos.stack-result/v1",
        "outcome": "VERIFIED"
        if all(layer["status"] == "passed" for layer in results)
        else "NOT_VERIFIED",
        "base": asdict(stack.base),
        "config_digest": stack.config.digest(),
        "final_tree_matches_original": True if stack.original is not None else None,
        "original": asdict(stack.original) if stack.original else None,
        "evidence": "operator-supplied Done receipts; runner provenance not authenticated",
        "layers": results,
    }
