from __future__ import annotations

from pathlib import Path

from .core import PhpCore
from .danger import scan_danger


class DummyVisitor:
    def __init__(
        self,
        *,
        is_test_file: bool = False,
        test_decorated_lines: set[int] | None = None,
    ) -> None:
        self.is_test_file = is_test_file
        self.test_decorated_lines = test_decorated_lines or set()
        self.dataclass_fields: set[str] = set()
        self.pydantic_models: set[str] = set()
        self.class_defs: dict = {}
        self.first_read_lineno: dict = {}
        self.framework_decorated_lines: set[int] = set()
        self.detected_frameworks: set[str] = set()


def scan_php_file(file_path: str, config: dict | None = None) -> tuple:
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() != ".php":
            raise ValueError("unsupported PHP path")
        source = path.read_bytes()
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
            [],
        )

    core = PhpCore(str(path), source)
    core.scan()

    visitor = DummyVisitor(
        is_test_file=core.is_test_file,
        test_decorated_lines=core.test_decorated_lines,
    )
    findings = scan_danger(core.root_node, str(path), source)

    return (
        core.defs,
        core.refs,
        set(),
        set(),
        visitor,
        DummyVisitor(),
        [],
        findings,
        [],
        None,
        None,
        config,
        core.raw_imports,
    )


__all__ = ["scan_php_file"]
