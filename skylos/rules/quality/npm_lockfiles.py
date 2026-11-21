"""Binary names and peer relationships read from npm lockfiles, as data.

Without ``node_modules`` the dependency rules cannot read installed
manifests, so a binary provided by a differently named package (``ngc`` from
``@angular/compiler-cli``) or a peer a framework needs looks unexplained.
Lockfiles record both:

* ``package-lock.json`` v2/v3 and ``npm-shrinkwrap.json``:
  ``packages["node_modules/x"].bin`` and ``.peerDependencies``;
* ``pnpm-lock.yaml`` v6-v9: ``packages`` entries' ``peerDependencies``
  (pnpm records only ``hasBin``, not the names, so bins stay unknown);
* Yarn Berry ``yarn.lock``: ``bin:`` and ``peerDependencies:`` of each entry
  (Yarn 1 records neither);
* ``bun.lock``: the metadata object's ``bin`` and ``peerDependencies``.

The facts are used only to *credit*: a binary maps to the package whose lock
entry lists it, and a used host's peers count as used. A missing or partial
lockfile never removes a hold or adds a finding.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache

from skylos.core.safe_cache_io import read_text_no_symlink

MAX_LOCKFILE_BYTES = 64 * 1024 * 1024
LOCKFILE_NAMES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
)


@dataclass
class LockFacts:
    """Per package name: binaries it provides and packages it peers on."""

    bins: dict[str, set[str]] = field(default_factory=dict)
    peers: dict[str, set[str]] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    def add(self, name: str | None, bins=(), peers=()) -> None:
        if not name:
            return
        if bins:
            self.bins.setdefault(name, set()).update(b for b in bins if isinstance(b, str) and b)
        if peers:
            self.peers.setdefault(name, set()).update(p for p in peers if isinstance(p, str) and p)

    def providers(self, command: str) -> set[str]:
        return {name for name, bins in self.bins.items() if command in bins}


def _bin_names(name: str, value) -> list[str]:
    if isinstance(value, dict):
        return [key for key in value if isinstance(key, str)]
    if isinstance(value, str) and name:
        return [name.rsplit("/", 1)[-1]]
    return []


# ----------------------------------------------------------------------- npm


def _package_lock(text: str, facts: LockFacts) -> None:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return
    for location, entry in packages.items():
        if not isinstance(location, str) or not isinstance(entry, dict):
            continue
        marker = location.rfind("node_modules/")
        if marker == -1:
            continue
        name = entry.get("name") if isinstance(entry.get("name"), str) else location[marker + len("node_modules/") :]
        peers = entry.get("peerDependencies")
        facts.add(
            name,
            _bin_names(name, entry.get("bin")),
            peers.keys() if isinstance(peers, dict) else (),
        )


# ---------------------------------------------------------------------- pnpm

_PNPM_KEY = re.compile(r"^  (?P<q>['\"]?)(?P<key>/?(?:@[^@/\s'\"]+/)?[^@\s'\"]+)@[^\s'\"]*(?P=q):\s*$")
_YAML_ENTRY = re.compile(r"^(?P<indent> +)(?P<q>['\"]?)(?P<name>[^'\":\s][^'\":]*?)(?P=q):\s*(?P<rest>.*)$")


def _pnpm_lock(text: str, facts: LockFacts) -> None:
    section = False
    current: str | None = None
    in_peers = False
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            section = line.rstrip() == "packages:"
            current, in_peers = None, False
            continue
        if not section:
            continue
        match = _PNPM_KEY.match(line)
        if match:
            current = match.group("key").lstrip("/")
            in_peers = False
            continue
        if current is None:
            continue
        if line.startswith("    ") and not line.startswith("     "):
            in_peers = line.strip() == "peerDependencies:"
            continue
        if in_peers and line.startswith("      "):
            entry = _YAML_ENTRY.match(line)
            if entry:
                facts.add(current, peers=[entry.group("name")])


# ---------------------------------------------------------------- yarn berry

_YARN_HEADER = re.compile(r"^(?P<q>\"?)(?P<specs>[^\s].*?)(?P=q):\s*$")


def _yarn_entry_name(specs: str) -> str | None:
    first = specs.split(",", 1)[0].strip().strip('"')
    if first.startswith("@"):
        index = first.find("@", 1)
    else:
        index = first.find("@")
    return first[:index] if index > 0 else None


def _yarn_lock(text: str, facts: LockFacts) -> None:
    if "__metadata:" not in text:
        return  # Yarn 1 records neither bins nor peers.
    current: str | None = None
    block: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            header = _YARN_HEADER.match(line)
            current = _yarn_entry_name(header.group("specs")) if header else None
            block = None
            continue
        if current is None:
            continue
        if line.startswith("  ") and not line.startswith("   "):
            stripped = line.strip()
            block = stripped[:-1] if stripped.endswith(":") else None
            continue
        if block in {"bin", "peerDependencies"} and line.startswith("    "):
            entry = _YAML_ENTRY.match(line)
            if not entry:
                continue
            if block == "bin":
                facts.add(current, bins=[entry.group("name")])
            else:
                facts.add(current, peers=[entry.group("name")])


# ----------------------------------------------------------------------- bun


def _bun_lock(text: str, facts: LockFacts) -> None:
    from skylos.visitors.languages.typescript.static_config import _parse_json

    data = _parse_json(text)
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return
    for entry in packages.values():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        label = entry[0]
        index = label.find("@", 1) if label.startswith("@") else label.find("@")
        name = label[:index] if index > 0 else None
        metadata = next((item for item in entry[1:] if isinstance(item, dict)), None)
        if name is None or metadata is None:
            continue
        peers = metadata.get("peerDependencies")
        facts.add(
            name,
            _bin_names(name, metadata.get("bin")),
            peers.keys() if isinstance(peers, dict) else (),
        )


_PARSERS = {
    "package-lock.json": _package_lock,
    "npm-shrinkwrap.json": _package_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "yarn.lock": _yarn_lock,
    "bun.lock": _bun_lock,
}


@lru_cache(maxsize=256)
def _read(path: str, mtime_ns: int, size: int) -> LockFacts:
    facts = LockFacts()
    if size > MAX_LOCKFILE_BYTES:
        return facts
    text = read_text_no_symlink(path, max_bytes=MAX_LOCKFILE_BYTES, errors="replace")
    if text is None:
        return facts
    try:
        _PARSERS[os.path.basename(path)](text, facts)
    except (RecursionError, ValueError, KeyError):
        return LockFacts()
    facts.sources.append(path)
    return facts


def lockfile_facts(directory: str | os.PathLike[str]) -> LockFacts | None:
    """Bins and peers from the lockfiles in ``directory``, or None."""
    directory = os.fspath(directory)
    merged: LockFacts | None = None
    for name in LOCKFILE_NAMES:
        path = os.path.join(directory, name)
        try:
            stat = os.stat(path)
        except OSError:
            continue
        facts = _read(path, stat.st_mtime_ns, stat.st_size)
        if not facts.sources:
            continue
        if merged is None:
            merged = LockFacts()
        for package, bins in facts.bins.items():
            merged.add(package, bins=bins)
        for package, peers in facts.peers.items():
            merged.add(package, peers=peers)
        merged.sources.extend(facts.sources)
    return merged
