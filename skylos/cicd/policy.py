"""Read PR policy from a fixed base commit without checking out target code."""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from pathlib import Path

from skylos.core.git_context import GitContext

_COMMIT = re.compile(r"[0-9a-fA-F]{40,64}\Z")
_MAX_POLICY_BYTES = 2 * 1024 * 1024


def resolve_policy_base(path, ref):
    from skylos.config import ConfigError

    context = GitContext.from_path(path)
    if not ref or str(ref).startswith("-") or any(ord(c) < 32 for c in str(ref)):
        raise ConfigError("A valid PR base ref is required")
    result = context.run("merge-base", str(ref), "HEAD")
    commit = result.stdout.strip()
    if result.returncode or not _COMMIT.fullmatch(commit):
        raise ConfigError(f"Could not resolve PR policy base: {ref}")
    return commit


@contextmanager
def base_policy_context(path, ref):
    from skylos.config import POLICY_BASE_ENV_VAR

    if not ref:
        yield
        return
    previous = os.environ.get(POLICY_BASE_ENV_VAR)
    os.environ[POLICY_BASE_ENV_VAR] = resolve_policy_base(path, ref)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(POLICY_BASE_ENV_VAR, None)
        else:
            os.environ[POLICY_BASE_ENV_VAR] = previous


def _base_text(context, commit, relative):
    from skylos.config import ConfigError

    listing = context.run("ls-tree", "-z", commit, "--", relative)
    if listing.returncode:
        raise ConfigError("Could not inspect base policy")
    if not listing.stdout:
        return None
    records = listing.stdout.rstrip("\0").split("\0")
    if len(records) != 1:
        raise ConfigError("Ambiguous base policy path")
    header, _, name = records[0].partition("\t")
    parts = header.split()
    if len(parts) != 3 or parts[0] not in {"100644", "100755"} or name != relative:
        raise ConfigError("Base policy must be a regular tracked file")
    size = context.run("cat-file", "-s", parts[2])
    if (
        size.returncode
        or not size.stdout.strip().isdigit()
        or int(size.stdout) > _MAX_POLICY_BYTES
    ):
        raise ConfigError("Base policy is unavailable or too large")
    content = context.run("cat-file", "blob", parts[2])
    if content.returncode or len(content.stdout.encode("utf-8")) > _MAX_POLICY_BYTES:
        raise ConfigError("Could not read base policy")
    return content.stdout


def is_untracked_worktree_file(start_path, path):
    """Whether Git lists ``path`` as an untracked file of this worktree.

    ``skylos sync pull`` writes ``.skylos/config.yaml`` without committing it.
    A file a commit carries, a file inside a submodule and a path through a
    symlinked folder are never listed, so pull request content cannot pass.
    """
    context = GitContext.from_path(start_path)
    try:
        relative = Path(path).absolute().relative_to(context.root).as_posix()
    except ValueError:
        return False
    listing = context.run("ls-files", "-z", "--others", "--", relative)
    if listing.returncode:
        return False
    return [name for name in listing.stdout.split("\0") if name] == [relative]


def base_rule_pack_texts(start_path, commit, rules_dir):
    """(display path, text, problem) per rule pack in ``rules_dir`` at ``commit``.

    Folders from ``start_path`` up to the repository root, nearest first;
    ``.yml``/``.yaml`` files directly in the folder. A pack that is not a
    regular tracked file or is too large has no text and names the problem.
    """
    from skylos.config import ConfigError

    if not _COMMIT.fullmatch(str(commit)):
        raise ConfigError("PR policy base must be a resolved commit")
    context = GitContext.from_path(start_path)
    current = Path(start_path).resolve()
    if current.is_file():
        current = current.parent
    if not current.is_relative_to(context.root):
        raise ConfigError("PR policy scope must be inside the repository")
    packs = []
    while True:
        folder = (current.relative_to(context.root) / rules_dir).as_posix()
        listing = context.run(
            "ls-tree", "-z", "--name-only", commit, "--", f"{folder}/"
        )
        if listing.returncode:
            raise ConfigError("Could not inspect base rule packs")
        for name in sorted(filter(None, listing.stdout.split("\0"))):
            if not name.lower().endswith((".yml", ".yaml")):
                continue
            if name.rpartition("/")[0] != folder:
                continue
            display = f"{name} (base {commit[:12]})"
            try:
                text = _base_text(context, commit, name)
            except ConfigError as exc:
                packs.append((display, None, str(exc)))
                continue
            if text is not None:
                packs.append((display, text, None))
        if current == context.root:
            break
        current = current.parent
    return packs


def load_base_policy(start_path, commit):
    """Config layers (root first) and synced policy, read from ``commit``.

    The same discovery as ``load_config``: per folder, ``.skylos.toml``, then
    ``skylos.toml``, then a ``pyproject.toml`` with ``[tool.skylos]``; walk up
    to the repository root; the nearest file wins per key; a file with
    ``root = true`` stops the walk. Only files at the base commit count.
    """
    from skylos.config import (
        CONFIG_FILE_NAMES,
        INHERITANCE_ROOT_SETTING,
        ConfigError,
        _normalize_synced_config,
        _select_skylos_toml_config,
    )

    if not _COMMIT.fullmatch(str(commit)):
        raise ConfigError("PR policy base must be a resolved commit")
    context = GitContext.from_path(start_path)
    current = Path(start_path).resolve()
    if current.is_file():
        current = current.parent
    if not current.is_relative_to(context.root):
        raise ConfigError("PR policy scope must be inside the repository")
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        import yaml

        layers = []
        synced_text = None
        stopped = False  # root = true ends inheritance, never synced policy
        while True:
            relative = current.relative_to(context.root)
            if synced_text is None:
                synced_text = _base_text(
                    context, commit, (relative / ".skylos/config.yaml").as_posix()
                )
            for name in () if stopped else CONFIG_FILE_NAMES:
                text = _base_text(context, commit, (relative / name).as_posix())
                if text is None:
                    continue
                data = tomllib.loads(text)
                if name == "pyproject.toml" and not (
                    isinstance(data.get("tool"), dict) and "skylos" in data["tool"]
                ):
                    continue
                layers.append(
                    _select_skylos_toml_config(data, explicit=False, file_name=name)
                )
                stopped = layers[-1].get(INHERITANCE_ROOT_SETTING) is True
                break
            if current == context.root:
                break
            current = current.parent
        synced = yaml.safe_load(synced_text) if synced_text is not None else {}
        if synced is None:
            synced = {}
        if not isinstance(synced, dict):
            raise ValueError("synced policy must be a mapping")
        return list(reversed(layers)), _normalize_synced_config(synced)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError("Could not parse base-controlled PR policy") from exc
