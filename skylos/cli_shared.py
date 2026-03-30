from __future__ import annotations

import os
import pathlib
import shlex
import subprocess
from pathlib import Path


def get_git_changed_files(root_path):
    supported_exts = {".py", ".go", ".ts", ".tsx", ".js", ".jsx", ".java"}

    def _collect_supported(output, repo_root):
        files = []
        for line in output.splitlines():
            full_path = pathlib.Path(repo_root) / line
            if full_path.suffix.lower() not in supported_exts:
                continue
            if full_path.exists():
                files.append(full_path)
        return files

    try:
        repo_root = pathlib.Path(
            subprocess.check_output(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=root_path,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            .decode("utf-8")
            .strip()
        )
        output = subprocess.check_output(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=repo_root,
            timeout=30,
        ).decode("utf-8")
        files = _collect_supported(output, repo_root)
        if files:
            return files

        base_ref = os.environ.get("GITHUB_BASE_REF")
        if base_ref:
            cmd = ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"]
        else:
            cmd = ["git", "diff", "--name-only", "origin/main...HEAD"]
        try:
            output = subprocess.check_output(
                cmd, cwd=repo_root, stderr=subprocess.DEVNULL, timeout=30
            ).decode("utf-8")
            return _collect_supported(output, repo_root)
        except Exception:
            return []
    except Exception:
        return []


def estimate_cost(files):
    total_chars = 0
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            total_chars += len(content)
        except Exception:
            pass
    est_tokens = total_chars / 4
    est_cost_usd = (est_tokens / 1_000_000) * 2.50
    return est_tokens, est_cost_usd


def load_addopts(start_path: Path | None = None):
    current = (start_path or Path.cwd()).resolve()
    while True:
        toml_path = current / "pyproject.toml"
        if toml_path.exists():
            try:
                try:
                    import tomllib
                except ImportError:
                    import tomli as tomllib

                with open(toml_path, "rb") as f:
                    data = tomllib.load(f)
                addopts = data.get("tool", {}).get("skylos", {}).get("addopts", [])
                if isinstance(addopts, str):
                    return shlex.split(addopts)
                if isinstance(addopts, list):
                    return list(addopts)
            except Exception:
                pass
            break
        if current.parent == current:
            break
        current = current.parent
    return []
