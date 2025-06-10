import re

AUTO_CALLED={"__init__","__enter__","__exit__"}
TEST_METHOD_PATTERN = re.compile(r"^test_\w+$")
MAGIC_METHODS={f"__{n}__"for n in["init","new","call","getattr","getattribute","enter","exit","str","repr","hash","eq","ne","lt","gt","le","ge","iter","next","contains","len","getitem","setitem","delitem","iadd","isub","imul","itruediv","ifloordiv","imod","ipow","ilshift","irshift","iand","ixor","ior","round","format","dir","abs","complex","int","float","bool","bytes","reduce","await","aiter","anext","add","sub","mul","truediv","floordiv","mod","divmod","pow","lshift","rshift","and","or","xor","radd","rsub","rmul","rtruediv","rfloordiv","rmod","rdivmod","rpow","rlshift","rrshift","rand","ror","rxor"]}
TEST_LIFECYCLE_METHODS = {
    "setUp", "tearDown", "setUpClass", "tearDownClass", 
    "setUpModule", "tearDownModule", "setup_method", "teardown_method",
    "setup_class", "teardown_class", "setup_function", "teardown_function"
}
TEST_IMPORT_PATTERNS = {
    "unittest", "unittest.mock", "mock", "pytest", "nose", "nose2",
    "responses", "requests_mock", "freezegun", "factory_boy", 
    "hypothesis", "sure", "expects", "testfixtures", "faker"
}

TEST_DECORATORS = {
    "patch", "mock", "pytest.fixture", "pytest.mark", "given",
    "responses.activate", "freeze_time", "patch.object", "patch.dict"
}

DEFAULT_EXCLUDE_FOLDERS = {
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
    ".venv"
}
