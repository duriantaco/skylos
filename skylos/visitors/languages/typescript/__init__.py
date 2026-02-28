from __future__ import annotations

from .core import TypeScriptCore
from .danger import scan_danger
from .quality import scan_quality
from .framework import TSFrameworkVisitor


class DummyVisitor:
    """Placeholder visitor for non-Python files to satisfy the pipeline tuple format."""

    def __init__(self) -> None:
        self.is_test_file: bool = False
        self.test_decorated_lines: set[int] = set()
        self.dataclass_fields: set[str] = set()
        self.pydantic_models: set[str] = set()
        self.class_defs: dict = {}
        self.first_read_lineno: dict = {}
        self.framework_decorated_lines: set[int] = set()


def scan_typescript_file(file_path: str, config: dict | None = None) -> tuple:
    if config is None:
        config = {}

    try:
        with open(file_path, "rb") as f:
            source = f.read()
    except Exception:
        return (
            [],
            [],
            set(),
            set(),
            DummyVisitor(),
            DummyVisitor(),
            [],
            [],
            [],
            None,
            None,
            config,
        )

    complexity_limit: int = config.get("complexity", 10)

    lang_overrides: dict = config.get("languages", {}).get("typescript", {})
    complexity_limit = lang_overrides.get("complexity", complexity_limit)

    core = TypeScriptCore(file_path, source)
    core.scan()

    fw = TSFrameworkVisitor()
    fw.scan(file_path, core.root_node, source, core.lang)

    d_findings: list[dict] = scan_danger(core.root_node, file_path, lang=core.lang)
    q_findings: list[dict] = scan_quality(
        core.root_node, source, file_path, threshold=complexity_limit, lang=core.lang
    )

    return (
        core.defs,
        core.refs,
        set(),
        set(),
        DummyVisitor(),
        fw,
        q_findings,
        d_findings,
        [],
        None,
        None,
        config,
        core.raw_imports,
    )
