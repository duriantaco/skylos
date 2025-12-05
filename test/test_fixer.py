import unittest
from unittest.mock import MagicMock, patch
from skylos.fixer import Fixer


class TestFixer(unittest.TestCase):
    def setUp(self):
        self.mock_defs = {
            "used_function": {"name": "used_function", "type": "function", "line": 10},
            "unused_class": {"name": "UnusedClass", "type": "class", "line": 20},
        }
        self.source_code = """
import os
def main():
    used_function()
"""

    @patch("skylos.fixer.get_adapter")
    def test_initialization(self, mock_get_adapter):
        mock_adapter_instance = MagicMock()
        mock_get_adapter.return_value = mock_adapter_instance

        fixer = Fixer(api_key="sk-test", model="gpt-4.1")

        mock_get_adapter.assert_called_with("gpt-4.1", "sk-test")
        self.assertIsNotNone(fixer.adapter)

    def test_line_number_injection(self):
        with patch("skylos.fixer.get_adapter"):
            fixer = Fixer(api_key="test")

            code = "line1\nline2"
            numbered = fixer._add_line_numbers(code)

            expected = "   1 | line1\n   2 | line2"
            self.assertEqual(numbered, expected)

    def test_context_retrieval(self):
        with patch("skylos.fixer.get_adapter"):
            fixer = Fixer(api_key="test")

            context = fixer._get_relevant_context(self.source_code, self.mock_defs)

            self.assertIn("used_function", context)
            self.assertNotIn("UnusedClass", context)

    @patch("skylos.fixer.get_adapter")
    def test_audit_file_flow(self, mock_get_adapter):
        mock_adapter = MagicMock()
        mock_adapter.complete.return_value = "[SECURITY] Line 10: Bad stuff"
        mock_get_adapter.return_value = mock_adapter

        fixer = Fixer(api_key="test")
        result = fixer.audit_file(self.source_code, self.mock_defs)

        self.assertEqual(result, "[SECURITY] Line 10: Bad stuff")

        call_args = mock_adapter.complete.call_args
        sent_prompt = call_args[0][1]
        self.assertIn("   1 |", sent_prompt)
        self.assertIn("used_function", sent_prompt)

    @patch("skylos.fixer.get_adapter")
    def test_fix_bug_parsing(self, mock_get_adapter):
        mock_adapter = MagicMock()
        mock_adapter.complete.return_value = """
---PROBLEM---
It was broken
---CHANGE---
Fixed it
---CODE---
def main():
    print("fixed")
"""
        mock_get_adapter.return_value = mock_adapter

        fixer = Fixer(api_key="test")
        result = fixer.fix_bug("bad_code", 1, "Error", self.mock_defs)

        self.assertEqual(result["problem"], "It was broken")
        self.assertEqual(result["change"], "Fixed it")
        self.assertEqual(result["code"], 'def main():\n    print("fixed")')

    @patch("skylos.fixer.get_adapter")
    def test_fix_bug_parsing_fallback(self, mock_get_adapter):
        mock_adapter = MagicMock()
        mock_adapter.complete.return_value = "print('just code')"
        mock_get_adapter.return_value = mock_adapter

        fixer = Fixer(api_key="test")
        result = fixer.fix_bug("bad_code", 1, "Error", self.mock_defs)

        self.assertEqual(result["problem"], "Issue detected")
        self.assertEqual(result["code"], "print('just code')")


if __name__ == "__main__":
    unittest.main()
