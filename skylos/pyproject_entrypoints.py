from __future__ import annotations

try:
    import tomllib
except Exception:
    tomllib = None

try:
    import tomli
except Exception:
    tomli = None


def _to_qname(target):
    if not isinstance(target, str) or ":" not in target:
        return None
    mod, func = target.split(":", 1)
    mod = mod.strip()
    func = func.strip()
    if not mod or not func:
        return None
    return f"{mod}.{func}"


def extract_entrypoints(project_root):
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        return set()

    raw = pyproject.read_text(encoding="utf-8")

    if tomllib is not None:
        data = tomllib.loads(raw)
    elif tomli is not None:
        data = tomli.loads(raw)
    else:
        return set()

    out: set[str] = set()

    # PEP 621
    scripts = (data.get("project") or {}).get("scripts") or {}
    if isinstance(scripts, dict):
        for _, target in scripts.items():
            q = _to_qname(target)
            if q:
                out.add(q)

    poetry_scripts = (
        ((data.get("tool") or {}).get("poetry") or {}).get("scripts")
    ) or {}
    if isinstance(poetry_scripts, dict):
        for _, target in poetry_scripts.items():
            q = _to_qname(target)
            if q:
                out.add(q)

    return out
