from pathlib import Path

from scripts.ci.test_shard import main, shard_files


def _files(tmp_path: Path, sizes: dict[str, int]) -> list[Path]:
    paths = []
    for name, size in sizes.items():
        path = tmp_path / name
        path.write_text("x" * size)
        paths.append(path)
    return paths


def test_every_file_lands_in_exactly_one_shard(tmp_path: Path):
    paths = _files(tmp_path, {f"test_{i}.py": 100 + i * 37 for i in range(23)})
    shards = shard_files(paths, 4)
    flat = [name for shard in shards for name in shard]
    assert sorted(flat) == sorted(p.as_posix() for p in paths)
    assert len(flat) == len(set(flat))


def test_heavy_files_are_spread_across_shards(tmp_path: Path):
    paths = _files(tmp_path, {"test_a.py": 900, "test_b.py": 800, "test_c.py": 100, "test_d.py": 100})
    shards = shard_files(paths, 2)
    heavy = [next(i for i, shard in enumerate(shards) if name in " ".join(shard)) for name in ("test_a.py", "test_b.py")]
    assert heavy[0] != heavy[1]


def test_the_repository_split_covers_the_whole_suite():
    files = list(Path("test").glob("test_*.py"))
    shards = shard_files(files, 4)
    assert sum(len(shard) for shard in shards) == len(files)
    assert all(shard for shard in shards)


def test_bad_arguments_are_refused(capsys):
    assert main(["test_shard.py", "5/4"]) == 2
    assert main(["test_shard.py", "two"]) == 2
