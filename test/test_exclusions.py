import os
import tempfile
import unittest
from pathlib import Path
from skylos.analyzer import Skylos


def _posix(p):
    return str(p).replace(os.sep, "/")


class TestPathExclusion(unittest.TestCase):
    def setUp(self):
        self.analyzer = Skylos()
        self.root = Path(".")

    def test_exclude_nested_folder_regression(self):
        excludes = ["src/legacy"]

        file_path = Path("src/legacy/old_main.py")
        self.assertTrue(
            self.analyzer._should_exclude_file(file_path, self.root, excludes),
            "Failed to exclude file inside nested folder 'src/legacy'",
        )

        deep_file = Path("src/legacy/utils/helpers.py")
        self.assertTrue(
            self.analyzer._should_exclude_file(deep_file, self.root, excludes),
            "Failed to exclude file deeply nested inside 'src/legacy'",
        )

    def test_exclude_nested_folder_false_positives(self):
        excludes = ["src/legacy"]

        similar_path = Path("src/legacy_v2/new.py")
        self.assertFalse(
            self.analyzer._should_exclude_file(similar_path, self.root, excludes),
            "Incorrectly excluded a folder sharing a prefix ('src/legacy_v2')",
        )

        diff_path = Path("src/modern/main.py")
        self.assertFalse(
            self.analyzer._should_exclude_file(diff_path, self.root, excludes),
            "Incorrectly excluded a non-matching sibling folder",
        )

    def test_windows_path_normalization(self):
        excludes = ["src/legacy"]

        file_path = Path("src") / "legacy" / "windows.py"

        self.assertTrue(
            self.analyzer._should_exclude_file(file_path, self.root, excludes),
            "Failed to exclude path constructed with OS separators",
        )

    def test_existing_wildcard_logic(self):
        excludes = ["*pycache__"]
        file_path = Path("src/__pycache__/cache.py")

        self.assertTrue(
            self.analyzer._should_exclude_file(file_path, self.root, excludes),
            "Regression: Wildcard exclusion failed",
        )

    def test_multiple_excludes_logic(self):
        excludes = ["src/legacy", "venv"]

        file_path = Path("venv/lib/site-packages/pkg.py")

        self.assertTrue(
            self.analyzer._should_exclude_file(file_path, self.root, excludes),
            "Regression: Loop stopped prematurely (did not check second exclude item)",
        )

    def test_trailing_slash_stripped(self):
        excludes = ["src/legacy/"]

        file_path = Path("src") / "legacy" / "old_main.py"
        self.assertTrue(
            self.analyzer._should_exclude_file(file_path, self.root, excludes),
            "Failed to exclude file when exclude path has trailing slash",
        )

        deep_file = Path("src") / "legacy" / "utils" / "helpers.py"
        self.assertTrue(
            self.analyzer._should_exclude_file(deep_file, self.root, excludes),
            "Failed to exclude deeply nested file when exclude path has trailing slash",
        )

    def test_trailing_slash_no_false_positive(self):
        excludes = ["src/legacy/"]

        similar_path = Path("src") / "legacy_v2" / "new.py"
        self.assertFalse(
            self.analyzer._should_exclude_file(similar_path, self.root, excludes),
            "Trailing-slash stripping widened the match to a prefix sibling",
        )

    def test_cwd_relative_exclude_with_target_prefix(self):
        tmpdir = tempfile.mkdtemp()
        try:
            versions_dir = Path(tmpdir) / "app" / "alembic" / "versions"
            versions_dir.mkdir(parents=True)
            (versions_dir / "001.py").touch()
            (Path(tmpdir) / "app" / "alembic" / "env.py").touch()

            ok_dir = Path(tmpdir) / "app" / "models"
            ok_dir.mkdir(parents=True, exist_ok=True)
            (ok_dir / "user.py").touch()

            target_root = Path(tmpdir) / "app"
            excludes = ["app/alembic"]

            self.assertTrue(
                self.analyzer._should_exclude_file(
                    target_root / "alembic" / "versions" / "001.py",
                    target_root,
                    excludes,
                ),
                f"app/alembic exclude failed on nested file "
                f"(rel={_posix(Path('alembic/versions/001.py'))})",
            )
            self.assertTrue(
                self.analyzer._should_exclude_file(
                    target_root / "alembic" / "env.py",
                    target_root,
                    excludes,
                ),
                f"app/alembic exclude failed on direct child "
                f"(rel={_posix(Path('alembic/env.py'))})",
            )
            self.assertFalse(
                self.analyzer._should_exclude_file(
                    target_root / "models" / "user.py",
                    target_root,
                    excludes,
                ),
                "app/alembic exclude incorrectly excluded models/user.py",
            )
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_cwd_relative_exclude_with_trailing_slash(self):
        tmpdir = tempfile.mkdtemp()
        try:
            versions_dir = Path(tmpdir) / "app" / "alembic" / "versions"
            versions_dir.mkdir(parents=True)
            (versions_dir / "001_init.py").touch()
            (Path(tmpdir) / "app" / "alembic" / "env.py").touch()
            (Path(tmpdir) / "app" / "alembic" / "__init__.py").touch()

            ok_dir = Path(tmpdir) / "app" / "models"
            ok_dir.mkdir(parents=True, exist_ok=True)
            (ok_dir / "user.py").touch()

            target_root = Path(tmpdir) / "app"
            excludes = ["app/alembic/"]

            for rel in [
                Path("alembic") / "versions" / "001_init.py",
                Path("alembic") / "env.py",
                Path("alembic") / "__init__.py",
            ]:
                self.assertTrue(
                    self.analyzer._should_exclude_file(
                        target_root / rel,
                        target_root,
                        excludes,
                    ),
                    f"app/alembic/ exclude failed on {_posix(rel)}",
                )

            self.assertFalse(
                self.analyzer._should_exclude_file(
                    target_root / "models" / "user.py",
                    target_root,
                    excludes,
                ),
                "app/alembic/ exclude incorrectly excluded models/user.py",
            )
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_exclude_normalization_uses_forward_slashes(self):
        excludes = ["src/legacy"]
        file_path = Path("src") / "legacy" / "deep" / "file.py"
        self.assertTrue(
            self.analyzer._should_exclude_file(file_path, self.root, excludes),
            f"Exclude failed after Path normalization: {_posix(file_path)}",
        )


if __name__ == "__main__":
    unittest.main()
