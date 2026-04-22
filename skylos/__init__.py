from importlib import metadata
from pathlib import Path
import re


def _version_from_pyproject() -> str | None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        contents = pyproject.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', contents)
    return match.group(1) if match else None


def _resolve_version() -> str:
    local_version = _version_from_pyproject()
    if local_version:
        return local_version
    try:
        return metadata.version("skylos")
    except metadata.PackageNotFoundError:
        return "0+unknown"


__version__ = _resolve_version()


def analyze(*args, **kwargs):
    from .analyzer import analyze as _analyze

    return _analyze(*args, **kwargs)


def debug_test():
    return "debug-ok"


__all__ = ["analyze", "debug_test", "__version__"]
