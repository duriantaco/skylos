import re
from pathlib import Path

PENALTIES = {
    "private_name": 10,
    "dunder_or_magic": 100,
    "in_init_file": 15,
    "dynamic_module": 10,
    "test_related": 100,
    "framework_magic": 40,
}

# timeout const
SUBPROCESS_TIMEOUT = 10
NETWORK_TIMEOUT_SHORT = 5
NETWORK_TIMEOUT_DEFAULT = 15
NETWORK_TIMEOUT_LONG = 30
UPLOAD_TIMEOUT = 60

# safety score const
SAFETY_VERY_HIGH = 0.95
SAFETY_HIGH = 0.90
SAFETY_MEDIUM = 0.85
SAFETY_LOW = 0.70
SAFETY_MINIMAL = 0.60
SAFETY_BUMP = 0.05

# detection thresholds
MIN_SECRET_LENGTH = 16
MIN_LONG_SECRET_LENGTH = 20
ENTROPY_THRESHOLD = 4.5

# magic numbers
MARKREFS_TICK_DEFAULT = 5000
SNIPPET_CONTEXT_LINES = 3

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

NON_LIBRARY_DIR_KINDS = {
    "test": "test",
    "tests": "test",
    "__tests__": "test",
    "example": "example",
    "examples": "example",
    "benchmark": "benchmark",
    "benchmarks": "benchmark",
    "bench": "benchmark",
    "docs_src": "example",
    "doc_src": "example",
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
    ".venv",
    "node_modules",
    ".hg",
    ".svn",
    "vendor",
    ".next",
    ".nuxt",
    ".turbo",
    ".idea",
    ".vscode",
}


def is_test_path(p) -> bool:
    return bool(TEST_FILE_RE.search(str(p)))


def is_framework_path(p) -> bool:
    return bool(FRAMEWORK_FILE_RE.search(str(p)))


def get_non_library_dir_kind(p, project_root=None, extra_dirs=None) -> str | None:
    merged = dict(NON_LIBRARY_DIR_KINDS)
    if extra_dirs:
        for folder, role in extra_dirs.items():
            merged[folder.lower()] = role

    parts = None
    if project_root is not None:
        try:
            rel = Path(p).resolve().relative_to(Path(project_root).resolve())
            parts = rel.parts
        except (TypeError, ValueError, OSError):
            parts = None

    if parts is None:
        parts = str(p).replace("\\", "/").split("/")

    for part in parts:
        kind = merged.get(part.lower())
        if kind:
            return kind

    basename = str(p).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if (
        basename == "conftest.py"
        or basename.startswith("test_")
        or basename.endswith("_test.py")
        or ".test." in basename
        or ".spec." in basename
        or basename.endswith("_test.go")
    ):
        return "test"

    return None


def parse_exclude_folders(
    user_exclude_folders=None, use_defaults=True, include_folders=None
) -> set[str]:
    exclude_folders = set()

    if use_defaults:
        exclude_folders.update(DEFAULT_EXCLUDE_FOLDERS)

    if user_exclude_folders:
        exclude_folders.update(user_exclude_folders)

    if include_folders:
        for folder in include_folders:
            exclude_folders.discard(folder)

    return exclude_folders
