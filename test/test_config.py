import unittest
import tempfile
import os
from pathlib import Path
from skylos.config import (
    CONFIG_FILE_ENV_VAR,
    ConfigError,
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

    def test_load_config_explicit_file_replaces_pyproject_discovery(self):
        (self.root / "pyproject.toml").write_text(
            "[tool.skylos]\ncomplexity = 99\nmax_args = 2",
            encoding="utf-8",
        )
        quality_dir = self.root / "quality"
        quality_dir.mkdir()
        (quality_dir / "skylos.toml").write_text(
            """
[skylos]
complexity = 7
ignore = ["SKY-Q301"]
""".strip(),
            encoding="utf-8",
        )
        nested_path = self.root / "a" / "b"
        nested_path.mkdir(parents=True)

        old_cwd = os.getcwd()
        os.chdir(self.root)
        try:
            config = load_config(nested_path, config_file="quality/skylos.toml")
        finally:
            os.chdir(old_cwd)

        self.assertEqual(config["complexity"], 7)
        self.assertEqual(config["max_args"], DEFAULTS["max_args"])
        self.assertEqual(config["ignore"], ["SKY-Q301"])

    def test_load_config_explicit_file_accepts_tool_skylos_table(self):
        config_path = self.root / "quality.toml"
        config_path.write_text(
            """
[tool.skylos]
max_lines = 42

[tool.skylos.gate]
strict = true
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root, config_file=config_path)

        self.assertEqual(config["max_lines"], 42)
        self.assertTrue(config["gate"]["strict"])

    def test_load_config_env_config_file(self):
        config_path = self.root / "skylos.toml"
        config_path.write_text("[skylos]\nnesting = 5", encoding="utf-8")
        old_value = os.environ.get(CONFIG_FILE_ENV_VAR)
        os.environ[CONFIG_FILE_ENV_VAR] = str(config_path)
        try:
            config = load_config(self.root)
        finally:
            if old_value is None:
                os.environ.pop(CONFIG_FILE_ENV_VAR, None)
            else:
                os.environ[CONFIG_FILE_ENV_VAR] = old_value

        self.assertEqual(config["nesting"], 5)

    def test_load_config_explicit_file_requires_skylos_table(self):
        config_path = self.root / "skylos.toml"
        config_path.write_text("[tool.other]\ncomplexity = 1", encoding="utf-8")

        with self.assertRaises(ConfigError):
            load_config(self.root, config_file=config_path)

    def test_load_config_explicit_file_preserves_synced_policy_precedence(self):
        skylos_dir = self.root / ".skylos"
        skylos_dir.mkdir()
        (skylos_dir / "config.yaml").write_text(
            """
security_contracts:
  - framework: fastapi
    file: app/api/routes.py
    handler: list_users
    guards:
      - require_admin
""".strip(),
            encoding="utf-8",
        )
        config_path = self.root / "quality" / "skylos.toml"
        config_path.parent.mkdir()
        config_path.write_text(
            """
[skylos]
ignore = ["SKY-SC001"]
exclude = ["app/**"]
security_contracts = []
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root, config_file=config_path)

        self.assertEqual(config["exclude"], [])
        self.assertNotIn("SKY-SC001", config["ignore"])
        self.assertEqual(len(config["security_contracts"]), 1)
        self.assertEqual(config["security_contracts"][0]["handler"], "list_users")

    def test_load_config_ignores_symlinked_pyproject(self):
        with tempfile.TemporaryDirectory() as outside_dir:
            outside_toml = Path(outside_dir) / "outside.toml"
            outside_toml.write_text("[tool.skylos]\ncomplexity = 99", encoding="utf-8")
            (self.root / "pyproject.toml").symlink_to(outside_toml)

            config = load_config(self.root)

        self.assertEqual(config["complexity"], DEFAULTS["complexity"])

    def test_load_config_reads_synced_yaml_without_pyproject(self):
        skylos_dir = self.root / ".skylos"
        skylos_dir.mkdir()
        (skylos_dir / "config.yaml").write_text(
            """
complexity_threshold: 12
function_length_threshold: 40
exclude_paths:
  - generated/**
security_contracts:
  - framework: fastapi
    file: app/api/routes.py
    handler: list_users
    guards:
      - require_admin
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(config["complexity"], 12)
        self.assertEqual(config["max_lines"], 40)
        self.assertEqual(config["exclude"], ["generated/**"])
        self.assertEqual(len(config["security_contracts"]), 1)
        self.assertEqual(config["security_contracts"][0]["handler"], "list_users")

    def test_load_config_local_pyproject_cannot_override_synced_security_policy(self):
        skylos_dir = self.root / ".skylos"
        skylos_dir.mkdir()
        (skylos_dir / "config.yaml").write_text(
            """
complexity_threshold: 12
exclude_paths:
  - generated/**
security_contracts:
  - framework: fastapi
    file: app/api/routes.py
    handler: list_users
    guards:
      - require_admin
""".strip(),
            encoding="utf-8",
        )
        (self.root / "pyproject.toml").write_text(
            """
[tool.skylos]
complexity = 99
exclude = ["local/**"]
ignore = ["SKY-SC001"]
security_contracts = []
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(config["complexity"], 99)
        self.assertEqual(config["exclude"], ["generated/**"])
        self.assertNotIn("SKY-SC001", config["ignore"])
        self.assertEqual(len(config["security_contracts"]), 1)
        self.assertEqual(config["security_contracts"][0]["handler"], "list_users")

    def test_load_config_synced_security_policy_rejects_repo_ignore_and_exclude(self):
        skylos_dir = self.root / ".skylos"
        skylos_dir.mkdir()
        (skylos_dir / "config.yaml").write_text(
            """
security_contracts:
  - framework: fastapi
    file: app/routes/admin.py
    handler: list_users
    guards:
      - require_admin
""".strip(),
            encoding="utf-8",
        )
        (self.root / "pyproject.toml").write_text(
            """
[tool.skylos]
ignore = ["SKY-SC001", "SKY-D000"]
exclude = ["app/**"]
security_enabled = false
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(config["exclude"], [])
        self.assertEqual(config["ignore"], [])
        self.assertEqual(config["security_contracts"][0]["handler"], "list_users")

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

    def test_load_config_ignores_malformed_value_types(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos]
ignore = 1
exclude = "build"
complexity = "boom"
max_args = false
security_contracts = "not-a-list"

[tool.skylos.masking]
names = "SECRET_*"
keep_docstring = "false"

[tool.skylos.architecture]
strict = "true"
layers = ["api"]
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(config["ignore"], DEFAULTS["ignore"])
        self.assertEqual(config["exclude"], DEFAULTS["exclude"])
        self.assertEqual(config["complexity"], DEFAULTS["complexity"])
        self.assertEqual(config["max_args"], DEFAULTS["max_args"])
        self.assertEqual(config["security_contracts"], DEFAULTS["security_contracts"])
        self.assertEqual(config["masking"]["names"], DEFAULTS["masking"]["names"])
        self.assertEqual(
            config["masking"]["keep_docstring"],
            DEFAULTS["masking"]["keep_docstring"],
        )
        self.assertEqual(config["architecture"]["strict"], DEFAULTS["architecture"]["strict"])
        self.assertEqual(config["architecture"]["layers"], DEFAULTS["architecture"]["layers"])

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

    def test_load_config_merges_template_and_vibe_defaults(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos.templates]
security = ".skylos/templates/security.md"

[tool.skylos.vibe]
extra_phantom_names = ["verify_enterprise_auth"]
extra_credential_names = ["tenant_signing_secret"]
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)

        self.assertEqual(
            config["templates"]["security"], ".skylos/templates/security.md"
        )
        self.assertIsNone(config["templates"]["quality"])
        self.assertEqual(
            config["vibe"]["extra_phantom_names"], ["verify_enterprise_auth"]
        )
        self.assertEqual(
            config["vibe"]["extra_credential_names"], ["tenant_signing_secret"]
        )
        self.assertEqual(config["vibe"]["extra_network_timeout_calls"], [])

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

    def test_load_config_rejects_scalar_temporary_whitelist_entries(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos.whitelist.temporary]
"*" = "boom"
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)
        ok, reason, penalty = is_whitelisted("any_definition", "app.py", config)
        expired = get_expired_whitelists(config)

        self.assertEqual(config["whitelist_temporary"], {})
        self.assertFalse(ok)
        self.assertIsNone(reason)
        self.assertEqual(penalty, 0)
        self.assertEqual(expired, [])

    def test_load_config_rejects_scalar_override_entries(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos.overrides]
"src/*.py" = "boom"
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)
        ok, reason, penalty = is_whitelisted("special_case", "src/a.py", config)

        self.assertEqual(config["overrides"], {})
        self.assertFalse(ok)
        self.assertIsNone(reason)
        self.assertEqual(penalty, 0)

    def test_load_config_rejects_malformed_whitelist_lists_and_maps(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text(
            """
[tool.skylos.whitelist]
names = ["safe_*", 123]
lower_confidence = "boom"

[tool.skylos.whitelist.documented]
"doc_*" = 123
"kept_*" = "reason"

[tool.skylos.whitelist.temporary]
"legacy_*" = { reason = 123, expires = 456 }
""".strip(),
            encoding="utf-8",
        )

        config = load_config(self.root)
        ok, reason, penalty = is_whitelisted("kept_name", None, config)
        legacy_ok, legacy_reason, _ = is_whitelisted("legacy_name", None, config)

        self.assertEqual(config["whitelist"], ["safe_*"])
        self.assertEqual(config["lower_confidence"], [])
        self.assertEqual(config["whitelist_documented"], {"kept_*": "reason"})
        self.assertEqual(config["whitelist_temporary"], {"legacy_*": {}})
        self.assertTrue(ok)
        self.assertEqual(reason, "reason")
        self.assertEqual(penalty, 0)
        self.assertTrue(legacy_ok)
        self.assertIn("temporary whitelist", legacy_reason)

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

    def test_get_all_ignore_lines_noqa_blanket(self):
        source = "\n".join(
            [
                "import os  # noqa",
                "import sys",
            ]
        )

        ignore_lines = get_all_ignore_lines(source)

        self.assertIn(1, ignore_lines)
        self.assertNotIn(2, ignore_lines)

    def test_get_all_ignore_lines_noqa_with_code(self):
        source = "\n".join(
            [
                "import pandas  # noqa: F401",
                "import sys",
            ]
        )

        ignore_lines = get_all_ignore_lines(source)

        self.assertIn(1, ignore_lines)
        self.assertNotIn(2, ignore_lines)

    def test_get_all_ignore_lines_noqa_multiple_codes(self):
        source = "\n".join(
            [
                "from pydantic import BaseModel, ValidationError  # noqa: F401, F402",
                "import sys",
            ]
        )

        ignore_lines = get_all_ignore_lines(source)

        self.assertIn(1, ignore_lines)
        self.assertNotIn(2, ignore_lines)

    def test_get_all_ignore_lines_noqa_no_space(self):
        source = "\n".join(
            [
                "import os  #noqa",
                "import sys",
            ]
        )

        ignore_lines = get_all_ignore_lines(source)

        self.assertIn(1, ignore_lines)
        self.assertNotIn(2, ignore_lines)

    def test_get_all_ignore_lines_noqa_uppercase(self):
        source = "\n".join(
            [
                "import os  # NOQA",
                "import sys",
            ]
        )

        ignore_lines = get_all_ignore_lines(source)

        self.assertIn(1, ignore_lines)
        self.assertNotIn(2, ignore_lines)

    def test_get_all_ignore_lines_noqa_with_other_comment(self):
        source = "\n".join(
            [
                "x = foo()  # type: ignore # noqa",
                "y = bar()",
            ]
        )

        ignore_lines = get_all_ignore_lines(source)

        self.assertIn(1, ignore_lines)
        self.assertNotIn(2, ignore_lines)
