import unittest
import tempfile
from pathlib import Path
from skylos.config import load_config, DEFAULTS

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
        toml_path.write_text('[tool.skylos]\ncomplexity = 99', encoding="utf-8")
        
        nested_path = self.root / "a" / "b" / "c"
        nested_path.mkdir(parents=True)

        config = load_config(nested_path)
        
        self.assertEqual(config["complexity"], 99)
        self.assertEqual(config["nesting"], DEFAULTS["nesting"])

    def test_load_config_with_gate_logic(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text('''
[tool.skylos]
complexity = 15
[tool.skylos.gate]
strict = true
''', encoding="utf-8")

        config = load_config(self.root)
        
        self.assertEqual(config["complexity"], 15)
        self.assertIn("gate", config)
        self.assertTrue(config["gate"]["strict"])

    def test_load_config_invalid_toml(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text('[tool.skylos]\ncomplexity = "invalid_string_no_quote', encoding="utf-8")
        
        config = load_config(self.root)
        self.assertEqual(config["complexity"], DEFAULTS["complexity"])

    def test_load_config_from_file_path(self):
        toml_path = self.root / "pyproject.toml"
        toml_path.write_text('[tool.skylos]\nmax_args = 2', encoding="utf-8")
        
        dummy_file = self.root / "script.py"
        dummy_file.write_text("print(1)")
        
        config = load_config(dummy_file)
        self.assertEqual(config["max_args"], 2)