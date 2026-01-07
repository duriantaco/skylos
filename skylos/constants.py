import re

PENALTIES = {
    "private_name": 80,
    "dunder_or_magic": 100,
    "underscored_var": 100,
    "in_init_file": 15,
    "dynamic_module": 10,
    "test_related": 100,
    "framework_magic": 40,
}

TEST_FILE_RE = re.compile(r"(?:^|[/\\])tests?[/\\]|_test\.py$", re.I)
TEST_IMPORT_RE = re.compile(r"^(pytest|unittest|nose|mock|responses)(\.|$)")
TEST_DECOR_RE = re.compile(
    r"""^(
    pytest\.(fixture|mark) |
    patch(\.|$) |
    responses\.activate |
    freeze_time
)$""",
    re.X,
)

AUTO_CALLED = {
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

TEST_METHOD_PATTERN = re.compile(r"^test_\w+$")

UNITTEST_LIFECYCLE_METHODS = {
    "setUp",
    "tearDown",
    "setUpClass",
    "tearDownClass",
    "setUpModule",
    "tearDownModule",
}

FRAMEWORK_FILE_RE = re.compile(r"(?:views|handlers|endpoints|routes|api)\.py$", re.I)

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
    ".venv",
}


def is_test_path(p):
    return bool(TEST_FILE_RE.search(str(p)))


def is_framework_path(p):
    return bool(FRAMEWORK_FILE_RE.search(str(p)))


def parse_exclude_folders(
    user_exclude_folders=None, use_defaults=True, include_folders=None
):
    exclude_folders = set()

    if use_defaults:
        exclude_folders.update(DEFAULT_EXCLUDE_FOLDERS)

    if user_exclude_folders:
        exclude_folders.update(user_exclude_folders)

    if include_folders:
        for folder in include_folders:
            exclude_folders.discard(folder)

    return exclude_folders
