import unittest
from pathlib import Path
from skylos.analyzer import Skylos


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


if __name__ == "__main__":
    unittest.main()
