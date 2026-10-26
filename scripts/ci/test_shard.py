"""Split test files into balanced shards for parallel CI jobs."""

from __future__ import annotations

import sys
from pathlib import Path


def shard_files(paths: list[Path], total: int) -> list[list[str]]:
    buckets: list[list[str]] = [[] for _ in range(total)]
    loads = [0] * total
    for path in sorted(paths, key=lambda p: (-p.stat().st_size, p.as_posix())):
        target = loads.index(min(loads))
        buckets[target].append(path.as_posix())
        loads[target] += path.stat().st_size
    return [sorted(bucket) for bucket in buckets]


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1].count("/") != 1:
        print("usage: test_shard.py INDEX/TOTAL", file=sys.stderr)
        return 2
    index, total = (int(part) for part in argv[1].split("/"))
    if total < 1 or not 1 <= index <= total:
        print("INDEX must be between 1 and TOTAL", file=sys.stderr)
        return 2
    files = list(Path("test").glob("test_*.py"))
    print(" ".join(shard_files(files, total)[index - 1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
