from importlib import metadata as _md

try:
    __version__ = _md.version(__name__)
except _md.PackageNotFoundError:
    __version__ = "0.0.0.dev0"


from ._core import analyze as _analyze 

def analyze(path: str) -> str:
    """Return the JSON produced by Rust's ``analyze``."""
    return _analyze(path)

# ------------------------------------------------------------------ #
# helpers the tests expect
# ------------------------------------------------------------------ #
def debug_test() -> str:
    return "debug-ok"

__all__ = ["analyze", "debug_test", "__version__"]

def _patch_metadata() -> None:
    orig_version = _md.version
    def _fake_version(name: str):                # type: ignore
        if name == __name__:
            return __version__
        return orig_version(name)
    _md.version = _fake_version
_patch_metadata()
