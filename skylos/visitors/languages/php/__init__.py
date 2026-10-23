from __future__ import annotations

from pathlib import Path

from .blade import blade_template_refs
from .core import PhpCore
from .danger import scan_danger
from .drupal import drupal_entrypoint_lines
from .laravel import laravel_convention_class_lines


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


def _framework_visitor(file_path: str, core: PhpCore, source: bytes) -> DummyVisitor:
    """Lines the framework (Laravel, Drupal) calls without a PHP reference."""
    framework = DummyVisitor()
    for name, lines in (
        (
            "laravel",
            laravel_convention_class_lines(
                file_path, core.defs, core.class_typed_first_parameter_methods
            ),
        ),
        (
            "drupal",
            drupal_entrypoint_lines(file_path, core.defs, core.root_node, source),
        ),
    ):
        if lines:
            framework.detected_frameworks.add(name)
            framework.framework_decorated_lines.update(lines)
    return framework


def scan_php_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
) -> tuple:
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() != ".php":
            raise ValueError("unsupported PHP path")
        source = path.read_bytes()
    except Exception:
        return _empty_result(config)

    core = PhpCore(str(path), source)
    core.scan()
    if path.name.lower().endswith(".blade.php"):
        core.refs.extend(
            (name, str(path))
            for name in blade_template_refs(source.decode("utf-8", errors="replace"))
        )

    visitor = DummyVisitor(
        is_test_file=core.is_test_file,
        test_decorated_lines=core.test_decorated_lines,
    )
    framework = _framework_visitor(str(path), core, source)
    findings = (
        scan_danger(core.root_node, str(path), source) if enable_danger_rules else []
    )

    return (
        core.defs,
        core.refs,
        set(),
        set(),
        visitor,
        framework,
        [],
        findings,
        [],
        None,
        None,
        config,
        core.raw_imports,
    )


__all__ = ["scan_php_file"]
