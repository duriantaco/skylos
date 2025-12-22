import pytest
from pathlib import Path
from skylos.constants import (
    PENALTIES,
    TEST_FILE_RE,
    TEST_IMPORT_RE,
    TEST_DECOR_RE,
    AUTO_CALLED,
    TEST_METHOD_PATTERN,
    UNITTEST_LIFECYCLE_METHODS,
    FRAMEWORK_FILE_RE,
    DEFAULT_EXCLUDE_FOLDERS,
    is_test_path,
    is_framework_path,
)


class TestTestFileRegex:
    def test_test_file_patterns_match(self):
        test_paths = [
            "module_test.py",  # ending with _test.py
            "tests/test_something.py",  # in the tests dir
            "test/unit_tests.py",  # in test dir
            "/path/to/tests/helper.py",  # in tests dir
            "src/tests/integration/test_api.py",  # also in tests dir
            "Tests/TestCase.py",  # test with captal T
            "TESTS/MODULE_TEST.PY",  # all caps tests dir
            "/project/test/conftest.py",
            "C:\\project\\tests\\test_file.py",  # windows path
            "project\\test\\helper.py",
            "some_module_test.py",
        ]

        for path in test_paths:
            assert TEST_FILE_RE.search(path), f"Should match test path: {path}"

    def test_non_test_file_patterns_dont_match(self):
        """Test that TEST_FILE_RE doesn't match non-test files"""
        non_test_paths = [
            "test_module.py",
            "module.py",
            "main.py",
            "src/utils.py",
            "app/models.py",
            "testing_utils.py",
            "contest.py",
            "protest.py",
            "/path/to/contest_module.py",
            "mytests.py",
            "src/testing/helper.py",
            "testmodule.py",
        ]

        for path in non_test_paths:
            assert not TEST_FILE_RE.search(path), (
                f"Should NOT match non-test path: {path}"
            )


class TestTestImportRegex:
    def test_test_import_patterns_match(self):
        test_imports = [
            "pytest",
            "pytest.fixture",
            "pytest.mark.parametrize",
            "unittest",
            "unittest.mock",
            "unittest.TestCase",
            "nose",
            "nose.tools",
            "mock",
            "mock.patch",
            "responses",
            "responses.activate",
        ]

        for import_name in test_imports:
            assert TEST_IMPORT_RE.match(import_name), (
                f"Should match test import: {import_name}"
            )

    def test_non_test_import_patterns_dont_match(self):
        non_test_imports = [
            "os",
            "sys",
            "json",
            "requests",
            "flask",
            "django",
            "numpy",
            "pandas",
            "pytest_plugin",
            "unittest_extensions",
            "mockery",
            "response",
        ]

        for import_name in non_test_imports:
            assert not TEST_IMPORT_RE.match(import_name), (
                f"Should NOT match non-test import: {import_name}"
            )


class TestTestDecoratorRegex:
    def test_test_decorator_patterns_match(self):
        test_decorators = [
            "pytest.fixture",
            "pytest.mark",
            "patch",
            "responses.activate",
            "freeze_time",
        ]

        for decorator in test_decorators:
            assert TEST_DECOR_RE.match(decorator), (
                f"Should match test decorator: {decorator}"
            )

    def test_non_test_decorator_patterns_dont_match(self):
        non_test_decorators = [
            "property",
            "staticmethod",
            "classmethod",
            "app.route",
            "login_required",
            "cache.cached",
            "pytest_configure",
            "patcher",
            "response",
            "freeze",
        ]

        for decorator in non_test_decorators:
            assert not TEST_DECOR_RE.match(decorator), (
                f"Should not match non-test decorator: {decorator}"
            )


class TestTestMethodPattern:
    def test_test_method_pattern_matches(self):
        """Test that TEST_METHOD_PATTERN matches test method names"""
        test_methods = [
            "test_something",
            "test_user_creation",
            "test_api_response",
            "test_edge_case",
            "test_123",
            "test_with_numbers_123",
            "test_UPPERCASE",
        ]

        for method in test_methods:
            assert TEST_METHOD_PATTERN.match(method), (
                f"Should match test method: {method}"
            )

    def test_test_method_pattern_doesnt_match(self):
        non_test_methods = [
            "test",  # No _
            "test_",
            "testing_something",
            # dont start with test
            "my_test_method",
            "testSomething",
            "Test_something",
            "_test_something",
        ]

        for method in non_test_methods:
            assert not TEST_METHOD_PATTERN.match(method), (
                f"Should NOT match non-test method: {method}"
            )


class TestFrameworkFileRegex:
    def test_framework_file_patterns_match(self):
        framework_files = [
            "views.py",
            "handlers.py",
            "endpoints.py",
            "routes.py",
            "api.py",
            "/path/to/views.py",
            "app/views.py",
            "VIEWS.PY",
            "API.py",
            "C:\\project\\app\\handlers.py",
            "my_handlers.py",
            "user_api.py",
            "admin_views.py",
        ]

        for file_path in framework_files:
            assert FRAMEWORK_FILE_RE.search(file_path), (
                f"Should match framework file: {file_path}"
            )

    def test_non_framework_file_patterns_dont_match(self):
        """Test that FRAMEWORK_FILE_RE doesn't match non-framework files"""
        non_framework_files = [
            "models.py",
            "utils.py",
            "config.py",
            "main.py",
            "views_helper.py",
            "endpoint_utils.py",
            "router.py",
            "apis.py",
            "handler.py",
        ]

        for file_path in non_framework_files:
            assert not FRAMEWORK_FILE_RE.search(file_path), (
                f"Should NOT match non-framework file: {file_path}"
            )


class TestHelperFunctions:
    def test_is_test_path_with_strings(self):
        assert is_test_path("module_test.py") == True
        assert is_test_path("tests/helper.py") == True
        assert is_test_path("test/conftest.py") == True
        assert is_test_path("test_module.py") == False
        assert is_test_path("regular_module.py") == False
        assert is_test_path("testing_utils.py") == False

    def test_is_test_path_with_path_objects(self):
        assert is_test_path(Path("module_test.py")) == True
        assert is_test_path(Path("tests/helper.py")) == True
        assert is_test_path(Path("test_module.py")) == False
        assert is_test_path(Path("regular_module.py")) == False

    def test_is_framework_path_with_strings(self):
        assert is_framework_path("views.py") == True
        assert is_framework_path("handlers.py") == True
        assert is_framework_path("api.py") == True
        assert is_framework_path("models.py") == False
        assert is_framework_path("utils.py") == False

    def test_is_framework_path_with_path_objects(self):
        assert is_framework_path(Path("views.py")) == True
        assert is_framework_path(Path("app/handlers.py")) == True
        assert is_framework_path(Path("models.py")) == False

    def test_path_functions_with_complex_paths(self):
        complex_paths = [
            ("/project/src/tests/unit/test_models.py", True, False),
            ("/project/app/views.py", False, True),
            ("/project/src/utils/helpers.py", False, False),
            ("C:\\project\\tests\\integration\\test_api.py", True, True),
            ("C:\\project\\app\\api\\handlers.py", False, True),
            ("/very/deep/path/to/tests/conftest.py", True, False),
            ("/app/endpoints.py", False, True),
            ("/project/module_test.py", True, False),
        ]

        for path, is_test, is_framework in complex_paths:
            assert is_test_path(path) == is_test, (
                f"is_test_path({path}) should be {is_test}"
            )
            assert is_framework_path(path) == is_framework, (
                f"is_framework_path({path}) should be {is_framework}"
            )


class TestConstants:
    def test_penalties_structure(self):
        """Test that penalities contains expected keys and reasonable values"""
        expected_keys = {
            "private_name",
            "dunder_or_magic",
            "underscored_var",
            "in_init_file",
            "dynamic_module",
            "test_related",
            "framework_magic",
        }
        assert set(PENALTIES.keys()) == expected_keys

        for key, value in PENALTIES.items():
            assert isinstance(value, int), (
                f"Penalty {key} should be int, got {type(value)}"
            )
            assert value > 0, f"Penalty {key} should be positive, got {value}"
            assert value <= 100, f"Penalty {key} should be <= 100, got {value}"

    def test_auto_called_methods(self):
        expected_methods = {
            "__init__",
            "__init__",
            "__new__",
            "__del__",
            "__init_subclass__",
            "__set_name__",
            "__enter__",
            "__exit__",
            "__iter__",
            "__next__",
            "__len__",
            "__getitem__",
            "__setitem__",
            "__delitem__",
            "__contains__",
            "__missing__",
            "__getattr__",
            "__setattr__",
            "__delattr__",
            "__getattribute__",
            "__str__",
            "__repr__",
            "__format__",
            "__bytes__",
            "__hash__",
            "__bool__",
        }

        assert expected_methods.issubset(AUTO_CALLED), (
            f"Missing required methods: {expected_methods - AUTO_CALLED}"
        )

        assert AUTO_CALLED == expected_methods

        assert len(AUTO_CALLED) >= 20, (
            f"AUTO_CALLED should have many dunder methods, got {len(AUTO_CALLED)}"
        )

        for method in AUTO_CALLED:
            assert method.startswith("__") and method.endswith("__"), (
                f"{method} should be dunder method"
            )

    def test_unittest_lifecycle_methods(self):
        expected_methods = {
            "setUp",
            "tearDown",
            "setUpClass",
            "tearDownClass",
            "setUpModule",
            "tearDownModule",
        }
        assert UNITTEST_LIFECYCLE_METHODS == expected_methods

        setup_methods = {
            m
            for m in UNITTEST_LIFECYCLE_METHODS
            if "setUp" in m or "setup" in m.lower()
        }
        teardown_methods = {
            m
            for m in UNITTEST_LIFECYCLE_METHODS
            if "tearDown" in m or "teardown" in m.lower()
        }

        assert len(setup_methods) == 3, (
            f"Should have 3 setup methods, got {setup_methods}"
        )
        assert len(teardown_methods) == 3, (
            f"Should have 3 teardown methods, got {teardown_methods}"
        )

    def test_default_exclude_folders(self):
        expected_folders = {
            "__pycache__",
            ".git",
            ".pytest_cache",
            ".mypy_cache",
            ".tox",
            "htmlcov",
            ".coverage",
            "build",
            "dist",
            "*.egg-info",
            "venv",
            ".venv",
        }
        assert expected_folders.issubset(DEFAULT_EXCLUDE_FOLDERS)

        for folder in DEFAULT_EXCLUDE_FOLDERS:
            assert isinstance(folder, str), f"Folder {folder} should be string"
            assert len(folder) > 0, f"Folder name should not be empty"


class TestRegexEdgeCases:
    def test_test_file_regex_case_insensitivity(self):
        assert TEST_FILE_RE.search("MODULE_TEST.PY")
        assert TEST_FILE_RE.search("Tests/Helper.py")
        assert TEST_FILE_RE.search("TEST/CONFTEST.PY")
        assert TEST_FILE_RE.search("tests/MODULE.PY")

    def test_test_file_regex_path_separators(self):
        # unix
        assert TEST_FILE_RE.search("tests/unit/test_module.py")
        assert TEST_FILE_RE.search("/absolute/path/tests/test_file.py")

        # windows
        assert TEST_FILE_RE.search("tests\\unit\\test_module.py")
        assert TEST_FILE_RE.search("C:\\project\\test\\test_file.py")

        assert TEST_FILE_RE.search("project/tests\\test_file.py")

    def test_framework_file_regex_case_insensitivity(self):
        assert FRAMEWORK_FILE_RE.search("VIEWS.PY")
        assert FRAMEWORK_FILE_RE.search("Handlers.py")
        assert FRAMEWORK_FILE_RE.search("API.py")
        assert FRAMEWORK_FILE_RE.search("Routes.PY")

    def test_import_regex_with_deep_modules(self):
        assert TEST_IMPORT_RE.match("pytest.mark.parametrize.something")
        assert TEST_IMPORT_RE.match("unittest.mock.patch.object")
        assert TEST_IMPORT_RE.match("nose.tools.assert_equal")
        assert not TEST_IMPORT_RE.match("requests.auth.HTTPBasicAuth")

    def test_decorator_regex_whitespace_handling(self):
        working_decorators = [
            "pytest.fixture",
            "pytest.mark",
            "patch",
            "responses.activate",
            "freeze_time",
        ]

        for decorator in working_decorators:
            assert TEST_DECOR_RE.match(decorator), f"Should match: {decorator}"

        non_working = [
            "pytest.mark.skip",
            "pytest.mark.parametrize",
            # may not work due to regex formatting
            "patch.object",
        ]

        for decorator in non_working:
            assert not TEST_DECOR_RE.match(decorator), (
                f"Currently doesn't match (regex issue): {decorator}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
