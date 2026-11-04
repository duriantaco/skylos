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
  ``min_release_age_hours`` ago (default 24) is held, naming the newest older
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

import queue
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.commands.hook_install_parse import MANIFEST, NPM, PYPI, InstallTarget

SUPPLY_CHAIN_SECONDS = 12.0
REQUEST_TIMEOUT_SECONDS = 5.0
MAX_OSV_QUERIES_PER_BATCH = 1000
MAX_LOCKED_PACKAGES = 5000
MAX_ADVISORY_FETCHES = 400
MAX_PARALLEL = 16
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
MALICIOUS_CWE = "CWE-506"

KIND_MALWARE = "malware"
KIND_TOO_NEW = "too_new"
KIND_PROVENANCE = "provenance"
OUTCOME_UNREACHABLE = "unreachable"
OUTCOME_UNCHECKED = "unchecked"
OUTCOME_MALWARE_ALLOWED = "malware_allowed"

_CA9_ECOSYSTEMS = {NPM: "npm", PYPI: "pypi"}
_PENDING = object()
_LOCKFILES = {
    "npm": ("npm-shrinkwrap.json", "package-lock.json"),
    "pnpm": ("pnpm-lock.yaml",),
    "yarn": ("yarn.lock",),
    "bun": ("bun.lock",),
    "uv": ("uv.lock",),
    "poetry": ("poetry.lock",),
    "pipenv": ("Pipfile.lock",),
}
_EXACT_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*"
    r"(?P<version>[0-9][A-Za-z0-9._+!-]*)\s*(?:;.*)?$"
)

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


@dataclass
class _Locked:
    target: InstallTarget
    label: str
    keys: list[Key]
    entries: dict[Key, tuple[str, int, str]]
    skipped: int = 0


def check_supply_chain(
    result: dict[str, Any],
    targets: list[InstallTarget],
    *,
    root: Path | None,
    sources: Sources | None = None,
    record: dict[str, Any] | None = None,
    seconds: float = SUPPLY_CHAIN_SECONDS,
) -> None:
    """Add malware, release-age and provenance outcomes to ``result``."""
    from skylos.rules.ai_defect.install_command import (
        package_allowed,
        user_allowed_packages,
    )
    from skylos.supply_chain.policy import load_supply_chain_policy

    sources = sources or Sources()
    if record is None:
        record = {}
    deadline = time.monotonic() + seconds
    policy = load_supply_chain_policy(root)
    age_hours = policy.hook_release_age_hours()
    allowed = user_allowed_packages(root)
    if policy.problems:
        result["supply_chain_problems"] = list(policy.problems)
    explicit = _explicit_items(result.get("checked") or [])
    locked = []
    for target in targets:
        if target.kind != MANIFEST or not target.lockfile:
            continue
        item = _read_locked(target, root, allowed, package_allowed, result)
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
    first = _run_parallel(tasks, deadline)
    if isinstance(first[0], dict):
        verdicts.update(first[0])
    for item, version in zip(resolving, first[1:]):
        if isinstance(version, str) and version:
            item.version = version
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
    answers = _run_parallel(second, deadline)
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
        third = _run_parallel([lambda: _malware_lookup(sources, third_keys, deadline)], deadline)
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


def _explicit_items(checked: list[dict[str, Any]]) -> list[_Explicit]:
    items = []
    for package in checked:
        if package.get("ecosystem") not in _CA9_ECOSYSTEMS:
            continue
        state = package.get("state")
        public = not package.get("alternate")
        if not public and state != "present":
            continue
        item = _Explicit(package=package, reasons=[])
        if package.get("version"):
            item.version = package["version"]
        elif state == "present" and public:
            item.resolve = True
        else:
            continue
        item.gated = state == "present" and public and not package.get("flagged")
        items.append(item)
    return items


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
    return pick_pypi_version(document, requested)


def _malware_lookup(sources: Sources, keys: list[Key], deadline: float) -> dict[Key, _Verdict]:
    verdicts = {key: _Verdict() for key in keys}
    if not keys:
        return verdicts
    batches = [keys[n : n + MAX_OSV_QUERIES_PER_BATCH]
               for n in range(0, len(keys), MAX_OSV_QUERIES_PER_BATCH)]  # fmt: skip
    answers = _run_parallel([lambda b=b: sources.osv_batch(b, deadline) for b in batches], deadline)
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
    fetched = _run_parallel([lambda a=a: sources.osv_record(a, deadline) for a in wanted], deadline)
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
    if advisory.startswith("MAL-"):
        return "malicious"
    if record is None:
        return "unknown"
    aliases = record.get("aliases")
    if isinstance(aliases, list) and any(
        isinstance(alias, str) and alias.startswith("MAL-") for alias in aliases
    ):
        return "malicious"
    specific = record.get("database_specific")
    if isinstance(specific, dict):
        if specific.get("malicious-packages-origins"):
            return "malicious"
        cwes = specific.get("cwe_ids")
        if isinstance(cwes, list) and MALICIOUS_CWE in cwes:
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


def _locked_outcome(item: _Locked, verdicts, block, findings, unverified, counts) -> None:
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


def _read_locked(target, root, allowed, package_allowed, result) -> _Locked | None:
    if target.lockfile == "requirements":
        return _read_requirements(target, root, allowed, package_allowed, result)
    base = Path(target.cwd or target.spec)
    names = _LOCKFILES.get(target.lockfile, ())
    path = _find_lockfile(base, names, root)
    if path is None:
        binary = None
        if target.lockfile == "bun":
            binary = _find_lockfile(base, ("bun.lockb",), root)
        if binary is not None:
            _unverified(result, target, binary.name, "bun.lockb is binary; Skylos reads "
                        "only the text bun.lock (bun install --save-text-lockfile)")  # fmt: skip
        elif target.preceded:
            _unverified(result, target, names[-1], f"no {names[-1]} yet; an earlier part "
                        "of this command may write it, and Skylos reads lockfiles before "
                        "the command runs")  # fmt: skip
        return None
    label = _label(path, root)
    try:
        inventory = _parse_lockfile(target.lockfile, path)
    except Exception as exc:  # noqa: BLE001
        reason = str(exc) or type(exc).__name__
        _unverified(result, target, label, f"could not read it ({reason[:120]})")
        return None
    deps = [(d.get("ecosystem"), d.get("name"), d.get("version"), d.get("line"), label)
            for d in inventory.dependencies]  # fmt: skip
    return _locked_item(target, label, deps, allowed, package_allowed)


def _read_requirements(target, root, allowed, package_allowed, result) -> _Locked | None:
    from skylos.core.python_requirements import read_requirements_tree

    path = Path(target.spec).expanduser()
    if not path.is_absolute():
        path = Path(target.cwd or ".") / path
    label = _label(path, root)
    if not path.is_file():
        if target.preceded:
            _unverified(result, target, label, "the file does not exist yet; an earlier "
                        "part of this command may write it, and Skylos reads it before "
                        "the command runs")  # fmt: skip
        return None
    bound = path.parent
    if root is not None and _inside(path, root):
        bound = root
    tree = read_requirements_tree(path, root=bound)
    if not tree.files:
        _unverified(result, target, label, "could not read it")
        return None
    for include in tree.unresolved_includes[:3]:
        _unverified(result, target, label, f"includes {include}, which Skylos could not read")
    if tree.limit_reached:
        _unverified(result, target, label, "includes more files than Skylos follows")
    if any(parsed.private_index for parsed in tree.files):
        return None
    deps = []
    for line in tree.requirements(include_constraints=False):
        match = _EXACT_PIN_RE.match(line.spec)
        if match and not line.url:
            deps.append((PYPI, line.name, match.group("version"), line.line,
                         _label(Path(line.path), root)))  # fmt: skip
    return _locked_item(target, label, deps, allowed, package_allowed)


def _locked_item(target, label, deps, allowed, package_allowed) -> _Locked:
    entries: dict[Key, tuple[str, int, str]] = {}
    for ecosystem, name, version, line, file_label in deps:
        if ecosystem not in _CA9_ECOSYSTEMS or not isinstance(name, str) or not name:
            continue
        if not isinstance(version, str) or not version:
            continue
        if package_allowed({"ecosystem": ecosystem, "name": name}, allowed):
            continue
        if not isinstance(line, int):
            line = 0
        entries.setdefault(_key(ecosystem, name, version), (name, line, file_label))
    keys = sorted(entries)
    skipped = max(0, len(keys) - MAX_LOCKED_PACKAGES)
    return _Locked(target, label, keys[:MAX_LOCKED_PACKAGES], entries, skipped)


def _parse_lockfile(manager: str, path: Path):
    if manager == "npm":
        from skylos.rules.sca.npm_lockfile import parse_package_lock as parse
    elif manager == "pnpm":
        from skylos.rules.sca.pnpm_lockfile import parse_pnpm_lock as parse
    elif manager == "yarn":
        from skylos.rules.sca.yarn_lockfile import parse_yarn_lock as parse
    elif manager == "bun":
        from skylos.rules.sca.bun_lockfile import parse_bun_lock as parse
    elif manager == "uv":
        from skylos.rules.sca.uv_lockfile import parse_uv_lock as parse
    elif manager == "poetry":
        from skylos.rules.sca.poetry_lockfile import parse_poetry_lock as parse
    else:
        from skylos.rules.sca.pipfile_lockfile import parse_pipfile_lock as parse
    return parse(path, max_packages=MAX_LOCKED_PACKAGES * 4)


def _find_lockfile(base: Path, names: tuple[str, ...], root: Path | None) -> Path | None:
    current = base
    while True:
        for name in names:
            candidate = current / name
            if candidate.is_file():
                return candidate
        if root is None or not _inside(current, root) or _same(current, root):
            return None
        if current.parent == current:
            return None
        current = current.parent


def _run_parallel(tasks: list[Callable[[], Any]], deadline: float) -> list[Any]:
    """Run ``tasks`` on daemon threads until done or ``deadline``; a task
    still running then reads as ``_PENDING``, and its thread cannot keep the
    hook process alive."""
    results: list[Any] = [_PENDING] * len(tasks)
    if not tasks:
        return results
    jobs: queue.Queue = queue.Queue()
    for index, task in enumerate(tasks):
        jobs.put((index, task))
    lock = threading.Lock()
    finished = threading.Event()
    left = [len(tasks)]

    def work() -> None:
        while True:
            try:
                index, task = jobs.get_nowait()
            except queue.Empty:
                return
            value = _PENDING
            if time.monotonic() < deadline:
                try:
                    value = task()
                except Exception:  # noqa: BLE001
                    value = None
            with lock:
                results[index] = value
                left[0] -= 1
                if left[0] == 0:
                    finished.set()

    for _ in range(min(MAX_PARALLEL, len(tasks))):
        threading.Thread(target=work, daemon=True).start()
    finished.wait(max(0.0, deadline - time.monotonic()))
    with lock:
        return list(results)


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


def _unverified(result: dict[str, Any], target: InstallTarget, name: str, reason: str) -> None:
    result.setdefault("unverified", []).append(
        {"ecosystem": target.ecosystem, "name": name, "tool": target.tool,
         "reason": reason, "outcome": OUTCOME_UNCHECKED}
    )  # fmt: skip


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


def _label(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            pass
    return str(path)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _same(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return False


__all__ = [
    "KIND_MALWARE",
    "KIND_PROVENANCE",
    "KIND_TOO_NEW",
    "SUPPLY_CHAIN_SECONDS",
    "Sources",
    "advisory_is_malicious",
    "check_supply_chain",
]
