#!/usr/bin/env python3
"""Run internal push checks against committed snapshots, using a pinned grader."""

from __future__ import annotations

import sys
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    arguments = sys.argv[1:]
    options = arguments[: arguments.index("--")] if "--" in arguments else arguments
    try:
        if "--worker" in options:
            index = options.index("--snapshot")
            snapshot = Path(options[index + 1]).resolve(strict=True)
            package = snapshot / "skylos"
            # A checked-out symlink stores only its target spelling in Git. Its
            # bytes can change outside this commit, so reject it before importing
            # any candidate package code and keep the verdict bound to this tree.
            for candidate in (package, *package.rglob("*")):
                if candidate.is_symlink():
                    raise ValueError(
                        "committed Skylos source contains a symbolic link: "
                        + candidate.relative_to(snapshot).as_posix()
                    )
            for required in (package / "__init__.py", package / "analyzer.py"):
                if not required.is_file() or not required.resolve().is_relative_to(
                    snapshot
                ):
                    raise ValueError(
                        "committed snapshot has no contained Skylos analyzer"
                    )
            sys.path.insert(0, str(snapshot))
            import skylos
            import skylos.benchmarks

            if not Path(skylos.__file__).resolve().is_relative_to(snapshot):
                raise ValueError("worker imported Skylos outside the pushed snapshot")
            # Keep every analyzer/core import in the candidate snapshot. Only
            # evaluation code comes from the independently installed harness.
            skylos.benchmarks.__path__ = [str(HARNESS_ROOT / "skylos/benchmarks")]
            for name in list(sys.modules):
                if name.startswith("skylos.benchmarks."):
                    del sys.modules[name]
        else:
            sys.path.insert(0, str(HARNESS_ROOT))

        from skylos.benchmarks.eval_push import main as run

        return run()
    except Exception as error:
        print(f"Skylos pre-push check could not run: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
