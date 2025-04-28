import re
from pathlib import Path

PENALTIES = {
    "private_name": 80,   
    "dunder_or_magic": 100, 
    "underscored_var": 100, 
    "in_init_file": 15, 
    "dynamic_module": 40,
    "test_related": 100,
    "framework_magic": 40,
}

TEST_FILE_RE = re.compile(r"(?:^|[/\\])tests?[/\\]|_test\.py$", re.I)
TEST_IMPORT_RE = re.compile(r"^(pytest|unittest|nose|mock|responses)(\.|$)")
TEST_DECOR_RE = re.compile(r"""^(
    pytest\.(fixture|mark) |
    patch(\.|$) |
    responses\.activate |
    freeze_time
)$""", re.X)

AUTO_CALLED = {"__init__", "__enter__", "__exit__"}
TEST_METHOD_PATTERN = re.compile(r"^test_\w+$")

UNITTEST_LIFECYCLE_METHODS = {
    'setUp', 'tearDown', 'setUpClass', 'tearDownClass', 
    'setUpModule', 'tearDownModule'
}

FRAMEWORK_FILE_RE = re.compile(r"(?:views|handlers|endpoints|routes|api)\.py$", re.I)

DEFAULT_EXCLUDE_FOLDERS = {
    "__pycache__", ".git", ".pytest_cache", ".mypy_cache", ".tox",
    "htmlcov", ".coverage", "build", "dist", "*.egg-info", "venv", ".venv"
}

def is_test_path(p: Path | str) -> bool:
    return bool(TEST_FILE_RE.search(str(p)))

def is_framework_path(p: Path | str) -> bool:
    return bool(FRAMEWORK_FILE_RE.search(str(p)))