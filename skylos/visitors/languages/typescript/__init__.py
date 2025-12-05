from .core import TypeScriptCore
from .danger import scan_danger
from .quality import scan_quality


class DummyVisitor:
    def __init__(self):
        self.is_test_file = False
        self.test_decorated_lines = set()
        self.dataclass_fields = set()
        self.pydantic_models = set()
        self.class_defs = {}
        self.first_read_lineno = {}
        self.framework_decorated_lines = set()


def scan_typescript_file(file_path, config=None):
    if config is None:
        config = {}

    try:
        with open(file_path, "rb") as f:
            source = f.read()
    except Exception:
        return ([], [], set(), set(), DummyVisitor(), DummyVisitor(), [], [], [])

    complexity_limit = config.get("complexity", 10)

    lang_overrides = config.get("languages", {}).get("typescript", {})
    complexity_limit = lang_overrides.get("complexity", complexity_limit)

    core = TypeScriptCore(file_path, source)
    core.scan()

    d_findings = scan_danger(core.root_node, file_path)
    q_findings = scan_quality(
        core.root_node, source, file_path, threshold=complexity_limit
    )

    return (
        core.defs,
        core.refs,
        set(),
        set(),
        DummyVisitor(),
        DummyVisitor(),
        q_findings,
        d_findings,
        [],
    )
