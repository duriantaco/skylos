"""Supply-chain policy for scans and the install hook.

```toml
[tool.skylos.supply_chain]
block_malware = true
min_release_age_hours = 48
internal_packages = ["acme-*", "@acme/*"]
private_registries = ["https://npm.acme.dev"]
trusted_registries = []
check_provenance = true
```

The synced Skylos Cloud policy (``.skylos/config.yaml`` or
``SKYLOS_SYNCED_POLICY_FILE``) carries the same keys under ``supply_chain``.
Cloud values only tighten the repository's values: booleans are combined
with OR, the release age takes the larger value, internal package patterns
are combined, and registry lists set in Cloud replace the repository's lists
because a repository-added registry would widen what is trusted.

``registries_from_cloud`` says Cloud set a registry list; the install hook
then uses Cloud's lists instead of ``[tool.skylos.hooks] trusted_registries``.

Under ``SKYLOS_POLICY_BASE`` (pull-request CI) both layers come from the base
commit, like the rest of the configuration, so a pull request cannot relax
its own supply-chain policy. A ``SKYLOS_SYNCED_POLICY_FILE`` that cannot be
read raises ``ConfigError`` instead of being dropped.

``min_release_age_hours`` is ``None`` when nobody set it. Callers choose the
default: the install hook holds new versions for
``DEFAULT_HOOK_RELEASE_AGE_HOURS``, scans skip the age check.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink

DEFAULT_HOOK_RELEASE_AGE_HOURS = 48
MAX_RELEASE_AGE_HOURS = 24 * 365
MAX_PATTERNS = 200
MAX_PATTERN_LENGTH = 200
MAX_PYPROJECT_BYTES = 2_000_000
SOURCE_PYPROJECT = "pyproject"
SOURCE_CLOUD = "cloud"


@dataclass(frozen=True)
class SupplyChainPolicy:
    block_malware: bool = True
    min_release_age_hours: int | None = None
    internal_packages: tuple[str, ...] = ()
    private_registries: tuple[str, ...] = ()
    trusted_registries: tuple[str, ...] = ()
    check_provenance: bool = True
    registries_from_cloud: bool = False
    sources: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()

    def hook_release_age_hours(self) -> int:
        if self.min_release_age_hours is None:
            return DEFAULT_HOOK_RELEASE_AGE_HOURS
        return self.min_release_age_hours

    def scan_release_age_hours(self) -> int | None:
        if not self.min_release_age_hours:
            return None
        return self.min_release_age_hours


@dataclass(frozen=True)
class _Layer:
    values: dict[str, Any]
    problems: tuple[str, ...]


def load_supply_chain_policy(root: str | Path | None) -> SupplyChainPolicy:
    base = _policy_base_tables(root)
    if base is None:
        local_table = _pyproject_table(root)
        synced_table = _synced_table(root)
    else:
        local_table, synced_table = base
    local = _parse_layer(local_table, "pyproject")
    synced = _parse_layer(synced_table, "Skylos Cloud")
    sources: list[str] = []
    if local_table:
        sources.append(SOURCE_PYPROJECT)
    if synced_table:
        sources.append(SOURCE_CLOUD)
    return _combine(local, synced, tuple(sources))


def _combine(local: _Layer, synced: _Layer, sources: tuple[str, ...]) -> SupplyChainPolicy:
    lv = local.values
    sv = synced.values
    block_malware = _either_true(lv.get("block_malware"), sv.get("block_malware"), True)
    check_provenance = _either_true(
        lv.get("check_provenance"), sv.get("check_provenance"), True
    )
    ages = [value for value in (lv.get("min_release_age_hours"), sv.get("min_release_age_hours")) if value is not None]
    min_age = None
    if ages:
        min_age = max(ages)
    internal = _union(lv.get("internal_packages", ()), sv.get("internal_packages", ()))
    private = lv.get("private_registries", ())
    if "private_registries" in sv:
        private = sv["private_registries"]
    trusted = lv.get("trusted_registries", ())
    if "trusted_registries" in sv:
        trusted = sv["trusted_registries"]
    return SupplyChainPolicy(
        block_malware=block_malware,
        min_release_age_hours=min_age,
        internal_packages=internal,
        private_registries=tuple(private),
        trusted_registries=tuple(trusted),
        check_provenance=check_provenance,
        registries_from_cloud="private_registries" in sv or "trusted_registries" in sv,
        sources=sources,
        problems=local.problems + synced.problems,
    )


def _either_true(local: Any, synced: Any, default: bool) -> bool:
    if synced is True or local is True:
        return True
    if synced is None and local is None:
        return default
    return False


def _union(*groups: tuple[str, ...]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for group in groups:
        for item in group:
            seen.setdefault(item, None)
    return tuple(seen)


def _parse_layer(table: dict[str, Any], label: str) -> _Layer:
    values: dict[str, Any] = {}
    problems: list[str] = []
    for key in ("block_malware", "check_provenance"):
        if key not in table:
            continue
        if isinstance(table[key], bool):
            values[key] = table[key]
        else:
            problems.append(f"{label}: {key} must be true or false")
    if "min_release_age_hours" in table:
        age = _age(table["min_release_age_hours"])
        if age is None:
            problems.append(
                f"{label}: min_release_age_hours must be a whole number from 0 to {MAX_RELEASE_AGE_HOURS}"
            )
        else:
            values["min_release_age_hours"] = age
    for key in ("internal_packages", "private_registries", "trusted_registries"):
        if key not in table:
            continue
        items = _patterns(table[key])
        if items is None:
            problems.append(f"{label}: {key} must be a list of strings")
        else:
            values[key] = items
    return _Layer(values=values, problems=tuple(problems))


def _age(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > MAX_RELEASE_AGE_HOURS:
        return None
    return value


def _patterns(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    items: list[str] = []
    for item in value[:MAX_PATTERNS]:
        if not isinstance(item, str):
            return None
        text = item.strip()
        if text and len(text) <= MAX_PATTERN_LENGTH:
            items.append(text)
    return tuple(dict.fromkeys(items))


def _pyproject_table(root: str | Path | None) -> dict[str, Any]:
    if root is None:
        return {}
    try:
        text = read_project_text_no_symlink(
            Path(root), "pyproject.toml", max_bytes=MAX_PYPROJECT_BYTES
        )
        if text is None:
            return {}
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads(text)
    except (OSError, ValueError, ImportError):
        return {}
    return _table(data, ("tool", "skylos", "supply_chain"))


def _policy_base_tables(
    root: str | Path | None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    from skylos import config as skylos_config

    commit = str(os.environ.get(skylos_config.POLICY_BASE_ENV_VAR) or "").strip()
    if not commit or root is None:
        return None
    from skylos.cicd.policy import load_base_policy

    layers, synced = load_base_policy(Path(root), commit)
    local: dict[str, Any] = {}
    for layer in layers:
        table = _table(layer, ("supply_chain",))
        if table:
            local = table
    operator = skylos_config.load_operator_synced_policy()
    if operator is not None:
        synced = operator
    return local, _table(synced, ("supply_chain",))


def _synced_table(root: str | Path | None) -> dict[str, Any]:
    from skylos import config as skylos_config

    synced = skylos_config.load_operator_synced_policy()
    if synced is None:
        if root is None:
            return {}
        try:
            _layers, sync_path = skylos_config._find_config_layers(Path(root).resolve())
        except OSError:
            return {}
        if sync_path is None:
            return {}
        synced = skylos_config._load_synced_config(sync_path)
    return _table(synced, ("supply_chain",))


def _table(data: Any, path: tuple[str, ...]) -> dict[str, Any]:
    table = data
    for key in path:
        if not isinstance(table, dict):
            return {}
        table = table.get(key)
    if isinstance(table, dict):
        return table
    return {}


__all__ = [
    "DEFAULT_HOOK_RELEASE_AGE_HOURS",
    "SupplyChainPolicy",
    "load_supply_chain_policy",
]
