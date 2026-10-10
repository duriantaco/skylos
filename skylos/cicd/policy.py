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


def load_base_policy(start_path, commit):
    from skylos.config import (
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
    user_text = synced_text = None
    while True:
        relative = current.relative_to(context.root)
        if synced_text is None:
            synced_text = _base_text(
                context, commit, (relative / ".skylos/config.yaml").as_posix()
            )
        user_text = _base_text(
            context, commit, (relative / "pyproject.toml").as_posix()
        )
        if user_text is not None or current == context.root:
            break
        current = current.parent
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        import yaml

        user = (
            _select_skylos_toml_config(tomllib.loads(user_text), explicit=False)
            if user_text is not None
            else {}
        )
        synced = yaml.safe_load(synced_text) if synced_text is not None else {}
        if synced is None:
            synced = {}
        if not isinstance(synced, dict):
            raise ValueError("synced policy must be a mapping")
        return user, _normalize_synced_config(synced)
    except Exception as exc:
        raise ConfigError("Could not parse base-controlled PR policy") from exc
