from pathlib import Path

from skylos.visitors.languages.typescript.safe_glob import safe_glob_paths


def test_safe_glob_rejects_parent_traversal(tmp_path):
    root = tmp_path / "project"
    outside = tmp_path / "outside" / "leak.ts"

    root.mkdir()
    outside.parent.mkdir()
    outside.write_text("export const leak = true;\n", encoding="utf-8")

    matches = safe_glob_paths(
        str(root),
        "../outside/**/*.ts",
        allowed_suffixes={".ts"},
    )

    assert matches == []


def test_safe_glob_caps_matches(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    for index in range(8):
        path = root / f"entry_{index}.ts"
        path.write_text("export const value = true;\n", encoding="utf-8")

    matches = safe_glob_paths(
        str(root),
        "*.ts",
        allowed_suffixes={".ts"},
        max_matches=3,
    )

    assert len(matches) == 3
    assert all(Path(match).suffix == ".ts" for match in matches)
