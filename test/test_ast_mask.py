import unittest
import ast
import textwrap

from skylos.ast_mask import MaskSpec, apply_body_mask


class TestBodyMasker(unittest.TestCase):
    def _get_masked_code(self, source, **spec_kwargs):
        tree = ast.parse(textwrap.dedent(source))
        spec = MaskSpec(**spec_kwargs)
        new_tree, count = apply_body_mask(tree, spec)
        return ast.unparse(new_tree).strip(), count

    def test_mask_function_by_name(self):
        source = """
            def secret_function():
                do_dangerous_things()
            def public_function():
                return 42
        """
        result, count = self._get_masked_code(source, names=["secret_*"])
        self.assertIn("def secret_function():\n    pass", result)
        self.assertIn("return 42", result)
        self.assertEqual(count, 1)

    def test_mask_by_decorator(self):
        source = """
            @internal.mask
            def hidden():
                secret_code()
            
            def visible():
                pass
        """
        result, count = self._get_masked_code(source, decorators=["internal.mask"])
        self.assertIn("def hidden():\n    pass", result)
        self.assertEqual(count, 1)

    def test_mask_class_by_base(self):
        source = """
            class InternalService(BaseService, HiddenMixin):
                def run(self):
                    pass
            class AppService(BaseService):
                def start(self):
                    pass
        """
        result, count = self._get_masked_code(source, bases=["HiddenMixin"])
        self.assertIn(
            "class InternalService(BaseService, HiddenMixin):\n    pass", result
        )
        self.assertIn("def start(self):", result)
        self.assertEqual(count, 1)

    def test_docstring_preservation(self):
        source = """
            def documented():
                \"\"\"Keep this docstring.\"\"\"
                remove_this_logic()
        """
        result, _ = self._get_masked_code(
            source, names=["documented"], keep_docstring=True
        )
        expected = 'def documented():\n    """Keep this docstring."""\n    pass'
        self.assertEqual(result, expected)

    def test_docstring_removal(self):
        source = """
            def documented():
                \"\"\"Remove this docstring.\"\"\"
                remove_this_logic()
        """
        result, _ = self._get_masked_code(
            source, names=["documented"], keep_docstring=False
        )
        self.assertEqual(result, "def documented():\n    pass")

    def test_async_function_masking(self):
        source = """
            async def secret_async():
                await sensitive_call()
        """
        result, count = self._get_masked_code(source, names=["secret_async"])
        self.assertIn("async def secret_async():\n    pass", result)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
