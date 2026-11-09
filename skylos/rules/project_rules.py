"""YAML rule packs a project keeps in ``.skylos/rules/`` (``skylos rules init``).

Every folder from the scanned file up to the repository root may hold one;
all of them apply and the nearest pack wins for a rule ID. In PR CI
(``SKYLOS_POLICY_BASE`` set) the packs come from that base commit only, like
``[tool.skylos]`` settings, so a pull request cannot remove or change the
rules its own gate runs.
"""

from __future__ import annotations

import functools
import os
import stat
from pathlib import Path, PurePosixPath

RULES_DIR = PurePosixPath(".skylos/rules")
PACK_SUFFIXES = (".yml", ".yaml")
MAX_PACK_BYTES = 1_000_000


def load_project_rules(start_path) -> list[dict]:
    """Rule configs for ``load_custom_rules`` from every usable project pack."""
    rules = []
    seen = set()
    for pack in project_rule_packs(start_path):
        for rule in pack["rules"]:
            if rule["rule_id"] in seen:
                continue
            seen.add(rule["rule_id"])
            rules.append(rule)
    return rules


def project_rule_warnings(start_path) -> list[str]:
    """Plain-text warnings for project packs that will not load."""
    from skylos.config import printable_text

    return [
        f"Rule pack {printable_text(pack['path'])} is not used: "
        f"{printable_text(pack['problem'])}."
        for pack in project_rule_packs(start_path, include_unusable=True)
        if pack.get("problem")
    ]


def project_rule_packs(start_path, *, include_unusable=False) -> list[dict]:
    """Packs nearest first: ``path``, ``rules`` and, when unusable, ``problem``."""
    from skylos.config import POLICY_BASE_ENV_VAR

    start = Path(start_path).resolve()
    if start.is_file() or not start.exists():
        start = start.parent
    policy_base = os.environ.get(POLICY_BASE_ENV_VAR)
    if policy_base:
        packs = _base_packs(str(start), policy_base)
    else:
        packs = _working_tree_packs(start)
    if include_unusable:
        return list(packs)
    return [pack for pack in packs if not pack.get("problem")]


def _working_tree_packs(start: Path) -> list[dict]:
    packs = []
    current = start
    while True:
        folder = current / RULES_DIR
        if folder.is_dir() and not folder.is_symlink():
            packs.extend(_folder_packs(folder))
        if (current / ".git").exists() or current.parent == current:
            break
        current = current.parent
    return packs


def _folder_packs(folder: Path) -> list[dict]:
    try:
        entries = sorted(folder.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        return [{"path": str(folder), "rules": [], "problem": str(exc)}]
    packs = []
    for path in entries:
        if path.suffix.lower() not in PACK_SUFFIXES:
            continue
        try:
            info = path.lstat()
        except OSError as exc:
            packs.append({"path": str(path), "rules": [], "problem": str(exc)})
            continue
        if not stat.S_ISREG(info.st_mode):
            packs.append(
                {"path": str(path), "rules": [], "problem": "not a regular file"}
            )
            continue
        if info.st_size > MAX_PACK_BYTES:
            packs.append(
                {"path": str(path), "rules": [], "problem": "larger than 1 MB"}
            )
            continue
        packs.append(
            _cached_file_pack(str(folder), path.name, info.st_mtime_ns, info.st_size)
        )
    return packs


@functools.lru_cache(maxsize=64)
def _cached_file_pack(folder: str, name: str, _mtime_ns: int, _size: int) -> dict:
    base = Path(folder).resolve()
    target = (base / name).resolve()
    display = str(Path(folder) / name)
    if not target.is_relative_to(base):
        return {"path": display, "rules": [], "problem": "outside the rules folder"}
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {"path": display, "rules": [], "problem": str(exc)}
    return _parse_pack(display, text)


@functools.lru_cache(maxsize=256)
def _base_packs(start: str, commit: str) -> list[dict]:
    from skylos.cicd.policy import base_rule_pack_texts

    packs = []
    for display, text, problem in base_rule_pack_texts(start, commit, RULES_DIR):
        if problem:
            packs.append({"path": display, "rules": [], "problem": problem})
        else:
            packs.append(_parse_pack(display, text))
    return packs


def _parse_pack(path: str, text: str) -> dict:
    import yaml

    try:
        if any(isinstance(event, yaml.AliasEvent) for event in yaml.parse(text)):
            return {
                "path": path,
                "rules": [],
                "problem": "YAML aliases are not allowed",
            }
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        problem = "invalid YAML"
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            problem = f"invalid YAML at line {mark.line + 1}"
        return {"path": path, "rules": [], "problem": problem}
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        return {"path": path, "rules": [], "problem": "no 'rules' list"}
    rules = []
    for rule_def in data["rules"]:
        if not isinstance(rule_def, dict):
            continue
        rule_id = rule_def.get("id")
        name = rule_def.get("name")
        pattern = rule_def.get("pattern", {})
        if (
            not isinstance(rule_id, str)
            or not isinstance(name, str)
            or not isinstance(pattern, dict)
        ):
            continue
        rules.append(
            {
                "rule_id": rule_id,
                "name": name,
                "rule_type": "yaml",
                "enabled": True,
                "severity": rule_def.get("severity", "MEDIUM"),
                "category": rule_def.get("category", "custom"),
                "yaml_config": {
                    "pattern": pattern,
                    "message": rule_def.get("message", "Custom rule violation"),
                },
            }
        )
    return {"path": path, "rules": rules}
