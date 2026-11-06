"""Supply-chain checks the pre-bash hook runs on an install before it runs.

:func:`check_supply_chain` adds to the install checker's result:

* **Malware.** Every version the command would install (pinned, or the
  version the manager resolves for an unpinned request) is looked up in one
  fresh OSV ``querybatch``. A record is malicious when its id or an alias is
  ``MAL-*``, it lists ``malicious-packages-origins``, or it carries CWE-506;
  withdrawn records are not. When OSV does not answer, the installed ca9 feed
  answers instead (``ca9.api.malware_matches``); with neither, the package
  is "could not verify". Ordinary CVEs are not the hook's business.
* **Release age.** A version published less than
  ``min_release_age_hours`` ago (default 48) is held, naming the newest older
  version that is not itself reported as malware (``ca9.api.check_release_age``).
* **npm provenance.** A version published without the provenance its earlier
  versions had (``ca9.api.check_provenance``) is held. "unknown" holds
  nothing.
* **Lockfile installs** (``npm ci``, ``uv sync``, ``pip install -r``...): the
  locked packages get the malware check, within the hook's time budget.

Packages routed elsewhere by the install checker (allowlisted, trusted or
private registries) never reach this module. Packages that may come from a
configured private registry only get the malware check, for pinned versions.

All network and ca9 access goes through :class:`Sources`, so tests replace it
and the hook never needs more than :data:`SUPPLY_CHAIN_SECONDS` of wall time.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.commands.hook_install_parse import MANIFEST, NPM, PYPI, InstallTarget
from skylos.commands.hook_locked_packages import (
    MAX_LOCKED_PACKAGES,
    LockContext,
    Locked,
    constraint_specs,
    exact_version,
    is_internal,
    read_locked,
)
from skylos.commands.hook_parallel import run_parallel
from skylos.rules.sca.advisory_metadata import MALICIOUS_ID_PREFIX, malicious_evidence

SUPPLY_CHAIN_SECONDS = 12.0
INSTALL_CHECK_SECONDS = 20.0
REQUEST_TIMEOUT_SECONDS = 5.0
MAX_OSV_QUERIES_PER_BATCH = 1000
MAX_ADVISORY_FETCHES = 400
MAX_PACKUMENT_BYTES = 64_000_000
MAX_PYPI_DOCUMENT_BYTES = 32_000_000
MAX_OSV_BATCH_BYTES = 8_000_000
MAX_OSV_RECORD_BYTES = 1_048_576
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
NPM_ORIGIN = "https://registry.npmjs.org"
PYPI_ORIGIN = "https://pypi.org/pypi"
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"
USER_AGENT = "skylos-hook/1.0"
CA9_UPGRADE = "pip install -U ca9"

KIND_MALWARE = "malware"
KIND_TOO_NEW = "too_new"
KIND_PROVENANCE = "provenance"
OUTCOME_UNREACHABLE = "unreachable"
OUTCOME_UNCHECKED = "unchecked"
OUTCOME_MALWARE_ALLOWED = "malware_allowed"

_CA9_ECOSYSTEMS = {NPM: "npm", PYPI: "pypi"}
Key = tuple[str, str, str]


class Sources:
    """OSV, the public registries and the ca9 engine. Every method returns
    ``None`` (or an ``unknown`` status) instead of raising."""

    def osv_batch(self, keys: list[Key], deadline: float) -> list[list[str] | None] | None:
        """Advisory ids per (ecosystem, name, version), in order. ``None``
        for the whole batch when OSV did not answer; ``None`` for one entry
        when its answer was cut short (pagination)."""
        from skylos.rules.sca.osv_client import is_valid_advisory_id

        queries = [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for ecosystem, name, version in keys
        ]
        payload = _post_json(OSV_BATCH_URL, {"queries": queries}, deadline, MAX_OSV_BATCH_BYTES)
        if not isinstance(payload, dict):
            return None
        results = payload.get("results")
        if not isinstance(results, list) or len(results) != len(keys):
            return None
        answers: list[list[str] | None] = []
        for entry in results:
            if not isinstance(entry, dict) or entry.get("next_page_token"):
                answers.append(None)
                continue
            vulns = entry.get("vulns", [])
            if not isinstance(vulns, list):
                answers.append(None)
                continue
            ids = [v.get("id") for v in vulns if isinstance(v, dict)]
            if not all(is_valid_advisory_id(i) for i in ids):
                answers.append(None)
                continue
            answers.append(ids)
        return answers

    def osv_record(self, advisory_id: str, deadline: float) -> dict[str, Any] | None:
        from skylos.rules.sca.osv_client import is_valid_advisory_id

        if not is_valid_advisory_id(advisory_id):
            return None
        document = _get_json(OSV_VULN_URL + advisory_id, deadline, MAX_OSV_RECORD_BYTES)
        if not isinstance(document, dict) or document.get("id") != advisory_id:
            return None
        return document

    def npm_packument(self, name: str, deadline: float) -> dict[str, Any] | None:
        from skylos.rules.ai_defect.manifest_dependency_hallucination import (
            _safe_npm_package_path,
        )

        path = _safe_npm_package_path(name)
        if path is None:
            return None
        return _get_json(f"{NPM_ORIGIN}/{path}", deadline, MAX_PACKUMENT_BYTES,
                         accept=NPM_ABBREVIATED)  # fmt: skip

    def pypi_project(self, name: str, deadline: float) -> dict[str, Any] | None:
        from skylos.rules.ai_defect.manifest_dependency_hallucination import (
            _safe_pypi_package_path,
        )

        path = _safe_pypi_package_path(name)
        if path is None:
            return None
        return _get_json(f"{PYPI_ORIGIN}/{path}/json", deadline, MAX_PYPI_DOCUMENT_BYTES)

    def release_age(self, ecosystem: str, name: str, version: str, min_hours: int) -> dict[str, Any]:
        function = _ca9_function("check_release_age")
        if function is None:
            return {"status": "engine_missing"}
        try:
            answer = function(_CA9_ECOSYSTEMS[ecosystem], name, version, min_hours=min_hours)
        except Exception:  # noqa: BLE001
            return {"status": "unknown"}
        if not isinstance(answer, dict):
            return {"status": "unknown"}
        if answer.get("status") == "unknown" and "not available" in str(answer.get("reason")):
            return {"status": "engine_missing"}
        return answer

    def provenance(self, ecosystem: str, name: str, version: str) -> dict[str, Any]:
        function = _ca9_function("check_provenance")
        if function is None:
            return {"status": "engine_missing"}
        try:
            answer = function(_CA9_ECOSYSTEMS[ecosystem], name, version)
        except Exception:  # noqa: BLE001
            return {"status": "unknown"}
        if not isinstance(answer, dict):
            return {"status": "unknown"}
        return answer

    def feed_malware(self, keys: list[Key]) -> dict[str, Any] | None:
        """``{"state": feed state, "matches": [finding dicts]}`` from the
        installed ca9 feed, or ``None`` when ca9 cannot answer."""
        function = _ca9_function("malware_matches")
        if function is None:
            return None
        state = _feed_state()
        if state not in ("ready", "stale"):
            return {"state": state or "missing", "matches": []}
        packages = [_ca9_package(key) for key in keys]
        try:
            matches = function(packages)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(matches, list):
            return None
        return {"state": state, "matches": [m for m in matches if isinstance(m, dict)]}


@dataclass
class _Verdict:
    state: str = "unknown"
    ids: tuple[str, ...] = ()
    source: str = "OSV"


@dataclass
class _Explicit:
    package: dict[str, Any]
    version: str = ""
    resolve: bool = False
    gated: bool = False
    reasons: list[str] | None = None
    network: bool = False
    constraint: str = ""


def check_supply_chain(
    result: dict[str, Any],
    targets: list[InstallTarget],
    *,
    root: Path | None,
    sources: Sources | None = None,
    record: dict[str, Any] | None = None,
    seconds: float = SUPPLY_CHAIN_SECONDS,
    deadline: float | None = None,
    policy: Any = None,
    trusted: tuple[str, ...] = (),
) -> None:
    """Add malware, release-age and provenance outcomes to ``result``.

    ``deadline`` (``time.monotonic()``) is shared with the rest of the
    install check; ``trusted`` lists the declared registries; ``policy`` is
    the loaded :class:`~skylos.supply_chain.policy.SupplyChainPolicy`."""
    from skylos.rules.ai_defect.install_command import (
        package_allowed,
        user_allowed_packages,
    )
    from skylos.supply_chain.policy import SOURCE_CLOUD, load_supply_chain_policy

    sources = sources or Sources()
    if record is None:
        record = {}
    if deadline is None:
        deadline = time.monotonic() + seconds
    if policy is None:
        policy = load_supply_chain_policy(root)
    age_hours = policy.hook_release_age_hours()
    cloud_malware = policy.block_malware and SOURCE_CLOUD in policy.sources
    allowed = user_allowed_packages(root)
    if cloud_malware:
        allowed = set()
    if policy.problems:
        result["supply_chain_problems"] = list(policy.problems)
    explicit = _explicit_items(result, policy, cloud_malware)
    _apply_constraints(explicit, root)
    ctx = LockContext(root, tuple(trusted), tuple(policy.internal_packages), allowed,
                      package_allowed)  # fmt: skip
    locked = []
    for target in targets:
        if target.kind != MANIFEST or not target.lockfile:
            continue
        item = read_locked(target, ctx, result)
        if item is not None:
            locked.append(item)
    if not explicit and not locked:
        return

    verdicts: dict[Key, _Verdict] = {}
    pinned = [_key(item.package["ecosystem"], item.package["name"], item.version)
              for item in explicit if item.version]  # fmt: skip
    locked_keys = [key for item in locked for key in item.keys]
    resolving = [item for item in explicit if item.resolve]
    first_keys = _unique(pinned + locked_keys)
    tasks: list[Callable[[], Any]] = [lambda: _malware_lookup(sources, first_keys, deadline)]
    tasks += [lambda item=item: _resolve(sources, item, deadline) for item in resolving]
    first = run_parallel(tasks, deadline)
    if isinstance(first[0], dict):
        verdicts.update(first[0])
    for item, version in zip(resolving, first[1:]):
        if isinstance(version, str) and version:
            item.version = version
            item.package["resolved"] = version
        else:
            _note(item, "could not tell which version would install", network=True)

    resolved = [_key(i.package["ecosystem"], i.package["name"], i.version)
                for i in resolving if i.version]  # fmt: skip
    gated = [i for i in explicit if i.gated and i.version]
    second_keys = _unique(resolved)
    second: list[Callable[[], Any]] = [lambda: _malware_lookup(sources, second_keys, deadline)]
    if age_hours > 0:
        second += [lambda i=i: sources.release_age(i.package["ecosystem"], i.package["name"],
                                                   i.version, age_hours) for i in gated]  # fmt: skip
    npm_gated = [i for i in gated if i.package["ecosystem"] == NPM]
    if policy.check_provenance:
        second += [lambda i=i: sources.provenance(NPM, i.package["name"], i.version)
                   for i in npm_gated]  # fmt: skip
    answers = run_parallel(second, deadline)
    if isinstance(answers[0], dict):
        verdicts.update(answers[0])
    ages: dict[int, Any] = {}
    provenance: dict[int, Any] = {}
    offset = 1
    if age_hours > 0:
        ages = {id(i): answers[offset + n] for n, i in enumerate(gated)}
        offset += len(gated)
    if policy.check_provenance:
        provenance = {id(i): answers[offset + n] for n, i in enumerate(npm_gated)}

    suggestions = {
        _key(i.package["ecosystem"], i.package["name"], str(answer.get("suggested_version")))
        for i in gated
        for answer in [ages.get(id(i))]
        if isinstance(answer, dict)
        and answer.get("status") == "too_new"
        and isinstance(answer.get("suggested_version"), str)
        and answer.get("suggested_version")
    }
    if suggestions:
        third_keys = sorted(suggestions)
        third = run_parallel([lambda: _malware_lookup(sources, third_keys, deadline)], deadline)
        if isinstance(third[0], dict):
            verdicts.update(third[0])
    _feed_fallback(sources, verdicts, pinned + resolved + locked_keys)

    findings = result.setdefault("findings", [])
    unverified = result.setdefault("unverified", [])
    counts = {KIND_MALWARE: 0, KIND_TOO_NEW: 0, KIND_PROVENANCE: 0}
    for item in explicit:
        _explicit_outcome(item, verdicts, ages.get(id(item)), provenance.get(id(item)),
                          age_hours, policy.block_malware, findings, unverified, counts)  # fmt: skip
    for item in locked:
        _locked_outcome(item, verdicts, policy.block_malware, findings, unverified, counts)
    result["release_age_hours"] = age_hours
    for kind, count in counts.items():
        if count:
            record[kind] = count
    if locked:
        record["locked_packages"] = sum(len(item.keys) for item in locked)


def _explicit_items(result: dict[str, Any], policy: Any, cloud_malware: bool) -> list[_Explicit]:
    items = []
    notes = result.setdefault("notes", [])
    for package in result.get("checked") or []:
        ecosystem = package.get("ecosystem")
        if ecosystem not in _CA9_ECOSYSTEMS:
            continue
        state = package.get("state")
        if package.get("alternate"):
            if package.get("alternate_declared"):
                if is_internal(ecosystem, package["name"], tuple(policy.internal_packages)):
                    continue
            elif state != "present":
                continue
            elif package.get("version"):
                items.append(_Explicit(package=package, version=package["version"], reasons=[]))
                notes.append(_undeclared_note(package, "release age not checked"))
                continue
            else:
                notes.append(_undeclared_note(package, "not checked for malware or release age"))
                continue
        item = _Explicit(package=package, reasons=[])
        if package.get("version"):
            item.version = package["version"]
        elif state == "present":
            item.resolve = True
        else:
            continue
        item.gated = state == "present" and not package.get("flagged")
        items.append(item)
    for entry in result.get("unverified") or []:
        if entry.get("ecosystem") not in _CA9_ECOSYSTEMS:
            continue
        outcome = entry.get("outcome")
        if outcome == "registry_override" and entry.get("version"):
            items.append(_Explicit(package=entry, version=entry["version"], reasons=[]))
        elif outcome == "allowlisted" and cloud_malware:
            item = _Explicit(package=entry, reasons=[])
            if entry.get("version"):
                item.version = entry["version"]
            else:
                item.resolve = True
            items.append(item)
    return items


def _undeclared_note(package: dict[str, Any], what: str) -> str:
    from skylos.commands.hook_install_parse import registry_host

    registry = registry_host(str((package.get("alternate") or [""])[0])) or "a configured registry"
    return (f"{package.get('tool', 'install')} {package['name']}: {what}; {registry} is "
            "not a declared registry (trusted_registries)")  # fmt: skip


def _apply_constraints(items: list[_Explicit], root: Path | None) -> None:
    for item in items:
        package = item.package
        paths = tuple(package.get("constraints") or ())
        if package["ecosystem"] != PYPI or not paths:
            continue
        specs, unreadable, files = constraint_specs(paths, root)
        writes = package.get("writes")
        if writes is not None and any(writes.covers(path) for path in files):
            _note(item, "an earlier part of this command may rewrite its constraints file")
            continue
        for label in unreadable:
            _note(item, f"{label} could not be read")
        spec = specs.get(_key(PYPI, package["name"], "")[1], "")
        if not spec or item.version:
            continue
        pinned = exact_version(spec)
        if pinned:
            item.version = pinned
            item.resolve = False
        else:
            item.constraint = spec


def _resolve(sources: Sources, item: _Explicit, deadline: float) -> str | None:
    from skylos.commands.hook_package_versions import (
        pick_npm_version,
        pick_pypi_version,
    )

    package = item.package
    requested = str(package.get("requested") or "")
    if package["ecosystem"] == NPM:
        document = sources.npm_packument(package["name"], deadline)
        if not isinstance(document, dict):
            return None
        return pick_npm_version(document, requested)
    document = sources.pypi_project(package["name"], deadline)
    if not isinstance(document, dict):
        return None
    return pick_pypi_version(document, requested, pre=bool(package.get("pre")),
                             constraint=item.constraint)  # fmt: skip


def _malware_lookup(sources: Sources, keys: list[Key], deadline: float) -> dict[Key, _Verdict]:
    verdicts = {key: _Verdict() for key in keys}
    if not keys:
        return verdicts
    batches = [keys[n : n + MAX_OSV_QUERIES_PER_BATCH]
               for n in range(0, len(keys), MAX_OSV_QUERIES_PER_BATCH)]  # fmt: skip
    answers = run_parallel([lambda b=b: sources.osv_batch(b, deadline) for b in batches], deadline)
    found: dict[Key, list[str]] = {}
    for batch, answer in zip(batches, answers):
        if not isinstance(answer, list) or len(answer) != len(batch):
            continue
        for key, ids in zip(batch, answer):
            if isinstance(ids, list):
                found[key] = ids
    wanted = sorted({advisory for ids in found.values() for advisory in ids},
                    key=lambda advisory: (not advisory.startswith("MAL-"), advisory))  # fmt: skip
    wanted = wanted[:MAX_ADVISORY_FETCHES]
    fetched = run_parallel([lambda a=a: sources.osv_record(a, deadline) for a in wanted], deadline)
    records = {a: r for a, r in zip(wanted, fetched) if isinstance(r, dict)}
    for key, ids in found.items():
        malicious = []
        unsure = False
        for advisory in ids:
            kind = _classify(advisory, records.get(advisory))
            if kind == "malicious":
                malicious.append(advisory)
            elif kind == "unknown":
                unsure = True
        if malicious:
            ordered = sorted(malicious, key=lambda a: (not a.startswith("MAL-"), a))
            verdicts[key] = _Verdict("malicious", tuple(ordered))
        elif unsure:
            verdicts[key] = _Verdict("unsure")
        else:
            verdicts[key] = _Verdict("clean")
    return verdicts


def advisory_is_malicious(record: dict[str, Any]) -> bool:
    """MAL-* id or alias, malicious-packages origins, or CWE-506; never a
    withdrawn record."""
    return _classify(str(record.get("id") or ""), record) == "malicious"


def _classify(advisory: str, record: dict[str, Any] | None) -> str:
    if record is not None and record.get("withdrawn"):
        return "benign"
    if advisory.upper().startswith(MALICIOUS_ID_PREFIX):
        return "malicious"
    if record is None:
        return "unknown"
    affected = record.get("affected")
    if not isinstance(affected, list):
        affected = []
    entries = [entry for entry in affected if isinstance(entry, dict)]
    if malicious_evidence(record, entries):
        return "malicious"
    return "benign"


def _feed_fallback(sources: Sources, verdicts: dict[Key, _Verdict], keys: list[Key]) -> None:
    pending = _unique([key for key in keys if verdicts.get(key, _Verdict()).state == "unknown"])
    if not pending:
        return
    answer = sources.feed_malware(pending)
    if not isinstance(answer, dict):
        return
    matched: dict[Key, list[str]] = {}
    for finding in answer.get("matches") or []:
        if finding.get("signal_type") != "malware" and finding.get("action") != "block":
            continue
        ecosystem = {"npm": NPM, "pypi": PYPI}.get(str(finding.get("ecosystem", "")).lower())
        if ecosystem is None:
            continue
        key = _key(ecosystem, str(finding.get("name") or ""), str(finding.get("version") or ""))
        evidence = finding.get("evidence")
        label = "ca9 feed"
        if isinstance(evidence, dict) and isinstance(evidence.get("malware_id"), str):
            label = evidence["malware_id"]
        matched.setdefault(key, []).append(label)
    for key in pending:
        if key in matched:
            verdicts[key] = _Verdict("malicious", tuple(matched[key]), source="ca9 feed")
        elif answer.get("state") == "ready":
            verdicts[key] = _Verdict("clean", source="ca9 feed")


def _explicit_outcome(item, verdicts, age, provenance, age_hours, block, findings, unverified,
                      counts) -> None:  # fmt: skip
    package = item.package
    ecosystem, name = package["ecosystem"], package["name"]
    if item.version:
        verdict = verdicts.get(_key(ecosystem, name, item.version), _Verdict())
        if verdict.state == "malicious":
            message = (f"{ecosystem} package '{name}' {item.version} is known malware "
                       f"({_ids(verdict)}).")  # fmt: skip
            _drop_findings(findings, package)
            _report_malware(package, item.version, message, verdict, block, findings,
                            unverified, counts)  # fmt: skip
            return
        if verdict.state == "unknown":
            _note(item, "malware check unavailable (OSV did not answer and no current "
                        "ca9 feed)", network=True)  # fmt: skip
        elif verdict.state == "unsure":
            _note(item, "malware check incomplete (OSV advisory details did not load)",
                  network=True)  # fmt: skip
    if isinstance(age, dict):
        status = age.get("status")
        if status == "too_new":
            findings.append(_too_new(package, item.version, age, age_hours, verdicts))
            counts[KIND_TOO_NEW] += 1
        elif status == "engine_missing":
            _note(item, f"release age not checked (the installed ca9 cannot check it: {CA9_UPGRADE})")
        elif status != "old_enough":
            _note(item, "release date unknown", network=True)
    elif item.gated and item.version and age_hours > 0:
        _note(item, "release age check timed out", network=True)
    if isinstance(provenance, dict):
        status = provenance.get("status")
        if status == "regressed":
            findings.append(_provenance(package, item.version, provenance))
            counts[KIND_PROVENANCE] += 1
        elif status == "engine_missing":
            _note(item, f"provenance not checked (the installed ca9 cannot check it: {CA9_UPGRADE})")
    if item.reasons and not package.get("flagged") and package.get("state") != "unknown":
        outcome = OUTCOME_UNREACHABLE
        if not item.network:
            outcome = OUTCOME_UNCHECKED
        unverified.append(
            {**_entry(package), "version": item.version, "outcome": outcome,
             "reason": "; ".join(dict.fromkeys(item.reasons))}
        )  # fmt: skip


def _locked_outcome(item: Locked, verdicts, block, findings, unverified, counts) -> None:
    unknown = 0
    for key in item.keys:
        verdict = verdicts.get(key, _Verdict())
        if verdict.state == "malicious":
            ecosystem, _query, version = key
            name, line, label = item.entries[key]
            package = {"ecosystem": ecosystem, "name": name, "version": version,
                       "tool": item.target.tool, "file": label, "line": line}  # fmt: skip
            message = (f"{ecosystem} package '{name}' {version} in {label} is known "
                       f"malware ({_ids(verdict)}).")  # fmt: skip
            _report_malware(package, version, message, verdict, block, findings,
                            unverified, counts)  # fmt: skip
        elif verdict.state in ("unknown", "unsure"):
            unknown += 1
    missing = unknown + item.skipped
    if missing:
        total = len(item.keys) + item.skipped
        reason = (f"{missing} of {total} locked packages not checked for malware "
                  "(OSV did not answer in time and no current ca9 feed)")  # fmt: skip
        if item.skipped and not unknown:
            reason = (f"{missing} of {total} locked packages not checked for malware "
                      f"(the hook checks at most {MAX_LOCKED_PACKAGES})")  # fmt: skip
        unverified.append({"ecosystem": item.target.ecosystem, "name": item.label,
                           "tool": item.target.tool, "reason": reason,
                           "outcome": OUTCOME_UNREACHABLE})  # fmt: skip


def _report_malware(package, version, message, verdict, block, findings, unverified,
                    counts) -> None:  # fmt: skip
    counts[KIND_MALWARE] += 1
    if block:
        rule_id = "SKY-SCA-MAL"
        if verdict.ids:
            rule_id = f"SKY-SCA-{verdict.ids[0]}"
        findings.append({**package, "version": version, "kind": KIND_MALWARE,
                         "rule_id": rule_id, "advisories": list(verdict.ids),
                         "message": message})  # fmt: skip
        return
    unverified.append({**_entry(package), "version": version,
                       "outcome": OUTCOME_MALWARE_ALLOWED,
                       "reason": f"reported as malware ({_ids(verdict)}); block_malware is off"})  # fmt: skip


def _too_new(package, version, age, age_hours, verdicts) -> dict[str, Any]:
    ecosystem, name = package["ecosystem"], package["name"]
    published = _age_text(age.get("age_hours"))
    message = (f"{ecosystem} package '{name}' {version} was published {published}; new "
               f"versions wait {age_hours} hours.")  # fmt: skip
    suggested = age.get("suggested_version")
    safe = None
    if isinstance(suggested, str) and suggested:
        verdict = verdicts.get(_key(ecosystem, name, suggested), _Verdict())
        if verdict.state != "malicious":
            safe = suggested
    if safe:
        message += f" Install {_spec(ecosystem, name, safe)} instead."
    elif isinstance(suggested, str) and suggested:
        message += " There is no older version without a malware report to suggest."
    else:
        message += " There is no older version to suggest."
    return {**package, "version": version, "kind": KIND_TOO_NEW, "rule_id": "SKY-SCA-AGE001",
            "suggested_version": safe, "age_hours": age.get("age_hours"), "message": message}  # fmt: skip


def _provenance(package, version, answer) -> dict[str, Any]:
    name = package["name"]
    evidence = answer.get("evidence")
    previous: list[str] = []
    if isinstance(evidence, dict) and isinstance(evidence.get("previous_with_provenance"), list):
        previous = [v for v in evidence["previous_with_provenance"] if isinstance(v, str)]
    message = (f"npm package '{name}' {version} has no provenance attestation, but "
               "earlier versions were published with one; the publishing account may be "
               "compromised.")  # fmt: skip
    if previous:
        message += f" The newest earlier version with provenance is {name}@{previous[0]}."
    return {**package, "version": version, "kind": KIND_PROVENANCE, "message": message}


def _get_json(url: str, deadline: float, max_bytes: int, *, accept: str = "application/json"):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    timeout = min(REQUEST_TIMEOUT_SECONDS, remaining)
    return _request("GET", url, deadline, max_bytes, timeout=(timeout, timeout),
                    headers={"User-Agent": USER_AGENT, "Accept": accept})  # fmt: skip


def _post_json(url: str, body: dict[str, Any], deadline: float, max_bytes: int):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    timeout = (min(REQUEST_TIMEOUT_SECONDS, remaining), min(REQUEST_TIMEOUT_SECONDS * 2, remaining))
    return _request("POST", url, deadline, max_bytes, timeout=timeout,
                    headers={"User-Agent": USER_AGENT}, json=body)  # fmt: skip


def _request(method: str, url: str, deadline: float, max_bytes: int, **kwargs: Any):
    import requests

    from skylos.rules.sca.osv_client import OsvResponseError, read_json_response

    try:
        response = requests.request(  # skylos: ignore[SKY-D216] fixed registry and OSV hosts
            method, url, stream=True, allow_redirects=False, **kwargs
        )
        return read_json_response(response, max_bytes=max_bytes, deadline=deadline)
    except (requests.RequestException, OsvResponseError, OSError, ValueError):
        return None


def _ca9_function(name: str):
    try:
        from ca9 import api
    except Exception:  # noqa: BLE001
        return None
    version = getattr(api, "API_VERSION", 0)
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        return None
    function = getattr(api, name, None)
    if callable(function):
        return function
    return None


def _feed_state() -> str | None:
    status_function = _ca9_function("feed_status")
    if status_function is None:
        try:
            from ca9.package_feed import feed_status as status_function
        except Exception:  # noqa: BLE001
            return None
    try:
        status = status_function()
    except Exception:  # noqa: BLE001
        return None
    if isinstance(status, dict):
        state = status.get("state")
    else:
        state = getattr(status, "state", None)
    if isinstance(state, str):
        return state
    return None


def _ca9_package(key: Key) -> dict[str, Any]:
    ecosystem, name, version = key
    return {"ecosystem": _CA9_ECOSYSTEMS[ecosystem], "name": name, "version": version,
            "direct": True, "dev": False, "registry": None, "registry_mode": None,
            "source_kind": "registry", "source_url": None, "integrity": None,
            "file": None, "line": None}  # fmt: skip


def _key(ecosystem: str, name: str, version: str) -> Key:
    if ecosystem == PYPI:
        name = re.sub(r"[-_.]+", "-", name.strip().lower())
    return ecosystem, name, version


def _unique(keys: list[Key]) -> list[Key]:
    return list(dict.fromkeys(keys))


def _note(item: _Explicit, reason: str, *, network: bool = False) -> None:
    if item.reasons is None:
        item.reasons = []
    item.reasons.append(reason)
    item.network = item.network or network


def _drop_findings(findings: list[dict[str, Any]], package: dict[str, Any]) -> None:
    findings[:] = [
        f for f in findings
        if not (f.get("ecosystem") == package["ecosystem"] and f.get("name") == package["name"]
                and f.get("version") == package.get("version"))
    ]  # fmt: skip




def _entry(package: dict[str, Any]) -> dict[str, Any]:
    return {"ecosystem": package["ecosystem"], "name": package["name"],
            "tool": package.get("tool", "install")}  # fmt: skip


def _ids(verdict: _Verdict) -> str:
    text = ", ".join(verdict.ids[:2])
    if verdict.source != "OSV":
        text += f"; from the {verdict.source}, OSV did not answer"
    return text


def _spec(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == PYPI:
        return f"{name}=={version}"
    return f"{name}@{version}"


def _age_text(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return "recently"
    if value < 1:
        return _plural(max(1, int(value * 60)), "minute") + " ago"
    return _plural(int(value), "hour") + " ago"


def _plural(count: int, word: str) -> str:
    if count == 1:
        return f"1 {word}"
    return f"{count} {word}s"








__all__ = [
    "KIND_MALWARE",
    "KIND_PROVENANCE",
    "KIND_TOO_NEW",
    "SUPPLY_CHAIN_SECONDS",
    "Sources",
    "advisory_is_malicious",
    "check_supply_chain",
]
