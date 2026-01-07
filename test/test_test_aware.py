import pytest
import ast
from unittest.mock import patch
from skylos.visitors.test_aware import TestAwareVisitor


class TestTestAwareVisitor:
    def test_init_without_filename(self):
        visitor = TestAwareVisitor()
        assert visitor.is_test_file == False
        assert visitor.test_decorated_lines == set()

    def test_init_with_non_test_filename(self):
        visitor = TestAwareVisitor(filename="mymodule.py")
        assert visitor.is_test_file == False
        assert visitor.test_decorated_lines == set()

    @patch("skylos.visitors.test_aware.TEST_FILE_RE")
    def test_init_with_test_filename(self, mock_test_file_re):
        mock_test_file_re.search.return_value = True

        visitor = TestAwareVisitor(filename="test_module.py")
        assert visitor.is_test_file == True
        assert visitor.test_decorated_lines == set()
        mock_test_file_re.search.assert_called_once_with("test_module.py")

    def test_test_function_name_patterns(self):
        code = """
def test_something():
    pass

def another_test():
    pass

def setup_method():
    pass

def teardown_function():
    pass

def setUp(self):
    pass

def tearDown(self):
    pass

def setUpClass(cls):
    pass

def tearDownClass(cls):
    pass

def setUpModule():
    pass

def tearDownModule():
    pass

def regular_function():
    pass
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.visit(tree)

        assert 2 in visitor.test_decorated_lines
        assert 5 in visitor.test_decorated_lines
        assert 8 in visitor.test_decorated_lines
        assert 11 in visitor.test_decorated_lines
        assert 14 in visitor.test_decorated_lines
        assert 17 in visitor.test_decorated_lines  # tearDown
        assert 20 in visitor.test_decorated_lines  # setUpClass
        assert 23 in visitor.test_decorated_lines  # tearDownClass
        assert 26 in visitor.test_decorated_lines  # setUpModule
        assert 29 in visitor.test_decorated_lines  # tearDownModule
        assert 32 not in visitor.test_decorated_lines  # gd ol regular_function

    @patch("skylos.visitors.test_aware.TEST_DECOR_RE")
    def test_test_decorator_detection(self, mock_test_decor_re):
        mock_test_decor_re.match.return_value = True

        code = """
@pytest.mark.parametrize('a,b', [(1,2), (3,4)])
def test_with_parametrize():
    pass

@mock.patch('module.function')
def test_with_mock():
    pass

@unittest.skip("reason")
def test_with_skip():
    pass
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.visit(tree)

        assert 3 in visitor.test_decorated_lines
        assert 7 in visitor.test_decorated_lines
        assert 11 in visitor.test_decorated_lines

    def test_pytest_fixture_detection(self):
        code = """
@pytest.fixture
def sample_data():
    return {"key": "value"}

@pytest.fixture(scope="session")
def database():
    return create_test_db()

@fixture
def simple_fixture():
    return "test"
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.visit(tree)

        assert 3 in visitor.test_decorated_lines
        assert 11 in visitor.test_decorated_lines

    def test_async_test_function_detection(self):
        code = """
async def test_async_function():
    await some_async_operation()

@pytest.mark.asyncio
async def test_with_asyncio_decorator():
    await another_operation()
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.visit(tree)

        assert 2 in visitor.test_decorated_lines
        assert 6 in visitor.test_decorated_lines

    def test_decorator_name_extraction(self):
        visitor = TestAwareVisitor()

        node = ast.parse("@decorator\ndef func(): pass").body[0].decorator_list[0]
        result = visitor._decorator_name(node)
        assert result == "decorator"

        node = (
            ast.parse("@pytest.mark.skip\ndef func(): pass").body[0].decorator_list[0]
        )
        result = visitor._decorator_name(node)
        assert result == "pytest.mark.skip"

        node = ast.parse("@fixture\ndef func(): pass").body[0].decorator_list[0]
        result = visitor._decorator_name(node)
        assert result == "fixture"

    def test_multiple_decorators_on_function(self):
        """testing function with couple of  decorators"""
        code = """
@pytest.mark.parametrize('x', [1, 2, 3])
@pytest.mark.slow
@mock.patch('module.function')
def test_multiple_decorators():
    pass
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.visit(tree)

        # should be detected as test
        assert 5 in visitor.test_decorated_lines

    @patch("skylos.visitors.test_aware.TEST_IMPORT_RE")
    def test_test_import_detection_when_test_file(self, mock_test_import_re):
        mock_test_import_re.match.return_value = True

        code = """
import pytest
import unittest
from mock import Mock
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.is_test_file = True
        visitor.visit(tree)

        assert mock_test_import_re.match.call_count >= 2

    @patch("skylos.visitors.test_aware.TEST_IMPORT_RE")
    def test_test_import_detection_when_not_test_file(self, mock_test_import_re):
        code = """
import pytest
import unittest
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.is_test_file = False
        visitor.visit(tree)

        #  no call regex match for imports
        assert mock_test_import_re.match.call_count == 0

    @patch("skylos.visitors.test_aware.TEST_IMPORT_RE")
    def test_import_from_detection_when_test_file(self, mock_test_import_re):
        mock_test_import_re.match.return_value = True

        code = """
from pytest import fixture
from unittest.mock import Mock
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.is_test_file = True
        visitor.visit(tree)

        # should call regex match from-imports
        assert mock_test_import_re.match.call_count >= 2

    def test_complex_test_class(self):
        code = """
class TestUserModel:
    def setUp(self):
        self.user = User()
    
    def test_user_creation(self):
        assert self.user.name == "test"
    
    def test_user_validation(self):
        assert self.user.is_valid()
    
    def tearDown(self):
        self.user.delete()
    
    def helper_method(self):
        return "not a test"
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.visit(tree)

        assert 3 in visitor.test_decorated_lines  # setUp
        assert 6 in visitor.test_decorated_lines  # test_user_creation
        assert 9 in visitor.test_decorated_lines  # test_user_validation
        assert 12 in visitor.test_decorated_lines  # tearDown
        assert 15 not in visitor.test_decorated_lines  # helper_method

    def test_edge_case_function_names(self):
        code = """
def test():  # 'test', no underscore
    pass

def testing_function():  # 'test' but not test_
    pass

def function_test():  # ending with _test
    pass

def setuptools_install():  # 'setup' but starts with setup
    pass
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.visit(tree)

        assert 2 not in visitor.test_decorated_lines
        assert 5 not in visitor.test_decorated_lines
        assert 8 in visitor.test_decorated_lines
        assert 11 in visitor.test_decorated_lines

    def test_nested_functions(self):
        code = """
def outer_function():
    def test_nested():
        pass
    
    def setup_nested():
        pass
    
    return test_nested
"""
        tree = ast.parse(code)
        visitor = TestAwareVisitor()
        visitor.visit(tree)

        assert 3 in visitor.test_decorated_lines
        assert 6 in visitor.test_decorated_lines
        assert 2 not in visitor.test_decorated_lines


class TestTestAwareVisitorIntegration:
    @patch("skylos.visitors.test_aware.TEST_FILE_RE")
    def test_full_test_file_analysis(self, mock_test_file_re):
        mock_test_file_re.search.return_value = True

        code = """
import pytest
from unittest.mock import Mock

class TestCalculator:
    @pytest.fixture
    def calculator(self):
        return Calculator()
    
    def setUp(self):
        self.mock_logger = Mock()
    
    def test_addition(self, calculator):
        result = calculator.add(2, 3)
        assert result == 5
    
    @pytest.mark.parametrize('a,b,expected', [(1,2,3), (4,5,9)])
    def test_addition_parametrized(self, calculator, a, b, expected):
        assert calculator.add(a, b) == expected
    
    def helper_method(self):
        return "utility function"
"""
        visitor = TestAwareVisitor(filename="test_calculator.py")
        tree = ast.parse(code)
        visitor.visit(tree)

        assert visitor.is_test_file == True
        assert 7 in visitor.test_decorated_lines
        assert 10 in visitor.test_decorated_lines
        assert 13 in visitor.test_decorated_lines
        assert 18 in visitor.test_decorated_lines
        assert 21 not in visitor.test_decorated_lines


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
