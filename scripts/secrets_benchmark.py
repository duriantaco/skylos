#!/usr/bin/env python3
"""Run offline synthetic secrets contracts against an explicitly selected source."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    arguments = sys.argv[1:]
    if "--worker" in arguments:
        try:
            source = Path(arguments[arguments.index("--source") + 1]).resolve(
                strict=True
            )
            package = source / "skylos"
            if package.is_symlink() or any(
                path.is_symlink() for path in package.rglob("*")
            ):
                raise ValueError("analyzer source must not contain symlinks")
            for relative in ("__init__.py", "analyzer.py"):
                if not (package / relative).resolve(strict=True).is_relative_to(source):
                    raise ValueError("analyzer source escapes requested checkout")
            sys.path.insert(0, str(source))
            import skylos
            import skylos.benchmarks

            if not Path(skylos.__file__).resolve().is_relative_to(source):
                raise ValueError("worker loaded Skylos outside requested source")
            skylos.benchmarks.__path__ = [str(ROOT / "skylos/benchmarks")]
            for name in list(sys.modules):
                if name.startswith("skylos.benchmarks."):
                    del sys.modules[name]
        except (OSError, ValueError, IndexError) as error:
            print(f"Secrets worker source unavailable: {error}", file=sys.stderr)
            return 2
    else:
        sys.path.insert(0, str(ROOT))
    from skylos.benchmarks.secrets import main as run

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
