import unittest
import tempfile
from pathlib import Path
from skylos.config import (
    load_config,
    DEFAULTS,
    is_path_excluded,
    is_whitelisted,
    get_expired_whitelists,
    get_all_ignore_lines,
    suggest_pattern,
)


class TestSkylosConfig(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.test_dir.name).resolve()

    def tearDown(self):
        self.test_dir.cleanup()

    def test_load_config_defaults(self):
        config = load_config(self.root)
        self.assertEqual(config["complexity"], DEFAULTS["complexity"])
        self.assertEqual(config["ignore"], [])

    def test_load_config_traversal(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text("[tool.skylos]\ncomplexity = 99", encoding="utf-8")

        nested_path = self.root / "a" / "b" / "c"
        nested_path.mkdir(parents=True)

        config = load_config(nested_path)

        self.assertEqual(config["complexity"], 99)
        self.assertEqual(config["nesting"], DEFAULTS["nesting"])

    def test_load_config_with_gate_logic(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos]
complexity = 15
[tool.skylos.gate]
strict = true
""",
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(config["complexity"], 15)
        self.assertIn("gate", config)
        self.assertTrue(config["gate"]["strict"])

    def test_load_config_invalid_toml(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            '[tool.skylos]\ncomplexity = "invalid_string_no_quote', encoding="utf-8"
        )

        config = load_config(self.root)
        self.assertEqual(config["complexity"], DEFAULTS["complexity"])

    def test_load_config_from_file_path(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text("[tool.skylos]\nmax_args = 2", encoding="utf-8")

        dummy_file = self.root / "script.py"
        dummy_file.write_text("print(1)")

        config = load_config(dummy_file)
        self.assertEqual(config["max_args"], 2)

    def test_load_config_merges_masking_defaults(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos]
complexity = 12

[tool.skylos.masking]
names = ["SECRET_*"]
keep_docstring = false
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(config["complexity"], 12)
        self.assertIn("masking", config)
        self.assertEqual(config["masking"]["names"], ["SECRET_*"])
        self.assertEqual(config["masking"]["decorators"], [])
        self.assertEqual(config["masking"]["bases"], [])
        self.assertFalse(config["masking"]["keep_docstring"])

    def test_load_config_whitelist_list_backcompat(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos]
whitelist = ["handle_*", "legacy_*"]
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(config["whitelist"], ["handle_*", "legacy_*"])
        self.assertEqual(config["whitelist_documented"], {})
        self.assertEqual(config["whitelist_temporary"], {})
        self.assertEqual(config["lower_confidence"], [])

    def test_load_config_whitelist_dict_new_style(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos.whitelist]
names = ["handle_*"]
lower_confidence = ["dynamic_*"]

[tool.skylos.whitelist.documented]
"handle_*" = "called via getattr"

[tool.skylos.whitelist.temporary]
"legacy_*" = { reason = "migration", expires = "2099-01-01" }
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(config["whitelist"], ["handle_*"])
        self.assertEqual(config["lower_confidence"], ["dynamic_*"])
        self.assertEqual(
            config["whitelist_documented"]["handle_*"], "called via getattr"
        )
        self.assertIn("legacy_*", config["whitelist_temporary"])
        self.assertEqual(
            config["whitelist_temporary"]["legacy_*"]["reason"], "migration"
        )

    def test_load_config_reads_overrides(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos.overrides."src/*.py"]
whitelist = ["special_*"]
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertIn("overrides", config)
        self.assertIn("src/*.py", config["overrides"])
        self.assertEqual(config["overrides"]["src/*.py"]["whitelist"], ["special_*"])

    def test_is_path_excluded_glob_path_match(self):
        cfg = {"exclude": ["src/**/gen_*.py"]}
        self.assertTrue(is_path_excluded("src/a/gen_file.py", cfg))
        self.assertFalse(is_path_excluded("src/a/not_gen.py", cfg))

    def test_is_path_excluded_basename_pattern(self):
        cfg = {"exclude": ["__pycache__"]}
        self.assertTrue(is_path_excluded("src/__pycache__/x.py", cfg))
        self.assertFalse(is_path_excluded("src/cache/x.py", cfg))

    def test_is_path_excluded_windows_slashes_normalized(self):
        cfg = {"exclude": ["src/**/*.py"]}
        self.assertTrue(is_path_excluded(r"src\pkg\m.py", cfg))

    def test_is_whitelisted_temporary_valid(self):
        cfg = {
            "whitelist_temporary": {
                "legacy_*": {"reason": "old", "expires": "2099-01-01"}
            },
            "whitelist_documented": {},
            "whitelist": [],
            "overrides": {},
            "lower_confidence": [],
        }

        ok, reason, penalty = is_whitelisted("legacy_handler", None, cfg)

        self.assertTrue(ok)
        self.assertIn("old", reason)
        self.assertEqual(penalty, 0)

    def test_is_whitelisted_temporary_expired(self):
        cfg = {
            "whitelist_temporary": {
                "legacy_*": {"reason": "old", "expires": "2000-01-01"}
            },
            "whitelist_documented": {},
            "whitelist": [],
            "overrides": {},
            "lower_confidence": [],
        }

        ok, reason, penalty = is_whitelisted("legacy_handler", None, cfg)

        self.assertFalse(ok)
        self.assertIsNone(reason)
        self.assertEqual(penalty, 0)

    def test_is_whitelisted_documented(self):
        cfg = {
            "whitelist_temporary": {},
            "whitelist_documented": {"handle_*": "called via getattr"},
            "whitelist": [],
            "overrides": {},
            "lower_confidence": [],
        }

        ok, reason, penalty = is_whitelisted("handle_secret", None, cfg)

        self.assertTrue(ok)
        self.assertEqual(reason, "called via getattr")
        self.assertEqual(penalty, 0)

    def test_is_whitelisted_simple_list(self):
        cfg = {
            "whitelist_temporary": {},
            "whitelist_documented": {},
            "whitelist": ["foo_*"],
            "overrides": {},
            "lower_confidence": [],
        }

        ok, reason, penalty = is_whitelisted("foo_bar", None, cfg)

        self.assertTrue(ok)
        self.assertIn("matches", reason)
        self.assertEqual(penalty, 0)

    def test_is_whitelisted_per_file_override(self):
        cfg = {
            "whitelist_temporary": {},
            "whitelist_documented": {},
            "whitelist": [],
            "overrides": {"src/*.py": {"whitelist": ["special_*"]}},
            "lower_confidence": [],
        }

        ok, reason, penalty = is_whitelisted("special_case", "src/a.py", cfg)

        self.assertTrue(ok)
        self.assertIn("per-file: src/*.py", reason)
        self.assertEqual(penalty, 0)

    def test_is_whitelisted_lower_confidence_returns_penalty(self):
        cfg = {
            "whitelist_temporary": {},
            "whitelist_documented": {},
            "whitelist": [],
            "overrides": {},
            "lower_confidence": ["dyn_*"],
        }

        ok, reason, penalty = is_whitelisted("dyn_dispatch", None, cfg)

        self.assertFalse(ok)
        self.assertIn("lower_confidence", reason)
        self.assertEqual(penalty, 30)

    def test_get_expired_whitelists_returns_only_expired(self):
        cfg = {
            "whitelist_temporary": {
                "old_*": {"reason": "expired", "expires": "2000-01-01"},
                "new_*": {"reason": "valid", "expires": "2099-01-01"},
                "bad_date_*": {"reason": "ignore", "expires": "not-a-date"},
            }
        }

        expired = get_expired_whitelists(cfg)

        self.assertIn(("old_*", "expired", "2000-01-01"), expired)
        self.assertNotIn(("new_*", "valid", "2099-01-01"), expired)

    def test_get_all_ignore_lines_marks_decorator_next_line(self):
        source = "\n".join(
            [
                "@app.get('/x')  # skylos: ignore",
                "def x():",
                "    return 1",
            ]
        )

        ignore_lines = get_all_ignore_lines(source)

        self.assertIn(1, ignore_lines)
        self.assertIn(2, ignore_lines)

    def test_get_all_ignore_lines_ignore_block_marks_all_lines(self):
        source = "\n".join(
            [
                "a = 1",
                "# skylos: ignore-start",
                "b = 2",
                "c = 3",
                "# skylos: ignore-end",
                "d = 4",
            ]
        )

        ignore_lines = get_all_ignore_lines(source)

        self.assertIn(2, ignore_lines)
        self.assertIn(3, ignore_lines)
        self.assertIn(4, ignore_lines)
        self.assertIn(5, ignore_lines)
        self.assertNotIn(1, ignore_lines)
        self.assertNotIn(6, ignore_lines)

    def test_suggest_pattern_common_cases(self):
        self.assertEqual(suggest_pattern("handle_foo"), "handle_*")
        self.assertEqual(suggest_pattern("on_click"), "on_*")
        self.assertEqual(suggest_pattern("test_config"), "test_*")
        self.assertEqual(suggest_pattern("abc_handler"), "*_handler")
        self.assertEqual(suggest_pattern("abc_callback"), "*_callback")
        self.assertEqual(suggest_pattern("MyPlugin"), "*Plugin")
        self.assertEqual(suggest_pattern("MyHandler"), "*Handler")
        self.assertEqual(suggest_pattern("MyFactory"), "*Factory")
        self.assertEqual(suggest_pattern("plain_name"), "plain_name")
