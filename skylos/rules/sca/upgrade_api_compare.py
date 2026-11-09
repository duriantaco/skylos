"""How one use of a package fares from the old release's surface to the new one's."""

from __future__ import annotations

from dataclasses import dataclass

from skylos.rules.sca.python_api_references import Reference
from skylos.rules.sca.python_package_keywords import ACCEPTED, PASSTHROUGH, REJECTED
from skylos.rules.sca.python_package_surface import PackageSurface


@dataclass(frozen=True)
class Verdict:
    status: str
    change: str = ""
    symbol: str = ""
    reason: str = ""


def reference_symbol(reference: Reference) -> str:
    tokens = [token for token in reference.path if token != "()"]
    return ".".join((reference.module, *tokens))


def _private_parts(reference: Reference) -> list[str]:
    parts = [*reference.module.split("."), *reference.path]
    return [part for part in parts if part.startswith("_")]


def _visibility(reference: Reference) -> str:
    private = _private_parts(reference)
    if not private:
        return ""
    if all(part.startswith("__") and part.endswith("__") for part in private):
        return "dunder"
    return "private"


def compare_reference(
    reference: Reference, old: PackageSurface, new: PackageSurface
) -> Verdict:
    """How one use of a package fares from the old surface to the new one."""
    symbol = reference_symbol(reference)
    visibility = _visibility(reference)
    if visibility:
        return Verdict(visibility, symbol=symbol)
    if reference.star:
        return _compare_star(reference, old, new, symbol)
    old_step = old.module_step(reference.module)
    if old_step.status == "missing":
        return Verdict("not_in_old", symbol=symbol)
    if old_step.status == "unknown":
        return Verdict("unknown", symbol=symbol, reason=old_step.reason)
    new_step = new.module_step(reference.module)
    if new_step.status == "missing":
        return Verdict("removed", "module", reference.module)
    if new_step.status == "unknown":
        return Verdict("unknown", symbol=symbol, reason=new_step.reason)
    return _compare_path(reference, old, new, (old_step.targets, new_step.targets))


def _compare_path(reference, old, new, targets) -> Verdict:
    symbol = reference_symbol(reference)
    old_targets, new_targets = targets
    walked = [reference.module]
    for token in reference.path:
        kinds = {target.kind for target in old_targets}
        before = old.step(old_targets, token)
        if before.status != "found":
            return _old_side_verdict(before, symbol)
        after = new.step(new_targets, token)
        if token != "()":
            walked.append(token)
        verdict = _new_side_verdict(after, token, kinds, walked, symbol)
        if verdict is not None:
            return verdict
        old_targets = before.targets
        new_targets = after.targets
    return _compare_keywords(reference, old, new, (old_targets, new_targets))


def _old_side_verdict(step, symbol: str) -> Verdict:
    if step.status == "missing":
        return Verdict("not_in_old", symbol=symbol)
    if step.status == "unknown":
        return Verdict("unknown", symbol=symbol, reason=step.reason)
    return Verdict("ok", symbol=symbol)


def _new_side_verdict(step, token, kinds, walked, symbol) -> Verdict | None:
    label = ".".join(walked)
    if step.status == "missing":
        change = "attribute"
        if "module" in kinds:
            change = "name"
        return Verdict("removed", change, label)
    if step.status == "unknown":
        return Verdict("unknown", symbol=symbol, reason=step.reason)
    if step.status == "stop" and token != "()":
        return Verdict(
            "unknown",
            symbol=symbol,
            reason=f"{label} cannot be read statically in the new version",
        )
    return None


def _keyword_verdict(before: str, after: str, symbol: str, keyword: str) -> Verdict | None:
    if before == REJECTED:
        return None
    if before == PASSTHROUGH and after == PASSTHROUGH:
        return Verdict("ok", change="keyword_not_followed", symbol=symbol)
    if before == ACCEPTED and after == REJECTED:
        return Verdict("removed", "parameter", f"{symbol}({keyword}=)")
    return Verdict(
        "unknown",
        symbol=f"{symbol}({keyword}=)",
        reason="its signature cannot be read statically on both versions",
    )


def _compare_keywords(reference, old, new, targets) -> Verdict:
    symbol = reference_symbol(reference)
    old_targets, new_targets = targets
    if {target.kind for target in old_targets} == {"external"}:
        return Verdict("ok", symbol=symbol)
    not_followed = None
    for keyword in reference.keywords:
        if keyword.startswith("_"):
            continue
        after = new.keyword_status(new_targets, keyword)
        if after == ACCEPTED:
            continue
        before = old.keyword_status(old_targets, keyword)
        verdict = _keyword_verdict(before, after, symbol, keyword)
        if verdict is None:
            continue
        if verdict.status != "ok":
            return verdict
        not_followed = verdict
    return not_followed or Verdict("ok", symbol=symbol)


def _compare_star(reference, old, new, symbol) -> Verdict:
    name = reference.path[0]
    before = old.public_names(reference.module)
    if before is None:
        reason = old.module_step(reference.module).reason
        return Verdict(
            "unknown",
            symbol=symbol,
            reason=reason or "the star import cannot be read statically",
        )
    if name not in before:
        return Verdict("not_in_old", symbol=symbol)
    after = new.public_names(reference.module)
    if after is None:
        return Verdict(
            "unknown",
            symbol=symbol,
            reason="the star import cannot be read statically in the new version",
        )
    if name not in after:
        return Verdict("removed", "name", symbol)
    return Verdict("ok", symbol=symbol)
