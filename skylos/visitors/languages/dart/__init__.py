from __future__ import annotations

from pathlib import Path

from .core import DartCore
from .danger import scan_danger
from .tls import scan_bad_certificate_callbacks


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


def _empty_result(config: dict) -> tuple:
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


def scan_dart_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
) -> tuple:
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() != ".dart":
            raise ValueError("unsupported Dart path")
        source = path.read_bytes()  # skylos: ignore[SKY-D215]
    except Exception:
        return _empty_result(config)

    core = DartCore(str(path), source)
    core.scan()

    visitor = DummyVisitor(
        is_test_file=core.is_test_file,
        test_decorated_lines=core.test_decorated_lines,
    )
    visitor.dart_bindings = core.binding_metadata
    findings = (
        scan_danger(core.root_node, str(path), source) if enable_danger_rules else []
    )
    if enable_danger_rules:
        findings.extend(scan_bad_certificate_callbacks(core))

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


__all__ = ["scan_dart_file"]
