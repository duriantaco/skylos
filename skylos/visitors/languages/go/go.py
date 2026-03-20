from pathlib import Path
from skylos.engines.go_runner import run_go_engine_for_module
from skylos.visitor import Definition
from skylos.visitors.languages.go.quality import scan_go_quality, GO_LANG

try:
    from tree_sitter import Parser
except ImportError:
    Parser = None


class _GoDummyVisitor:
    def __init__(self):
        self.is_test_file = False
        self.test_decorated_lines = set()
        self.dataclass_fields = set()
        self.pydantic_models = set()
        self.class_defs = {}
        self.first_read_lineno = {}
        self.framework_decorated_lines = set()


_GO_RULE_REMAP = {
    "SKY-G211": "SKY-D211",  # SQL injection
    "SKY-G212": "SKY-D212",  # Command injection
    "SKY-G215": "SKY-D215",  # Path traversal
    "SKY-G216": "SKY-D216",  # SSRF
    "SKY-G207": "SKY-D207",  # Weak hash MD5
    "SKY-G208": "SKY-D208",  # Weak hash SHA1
    "SKY-G210": "SKY-D210",  # TLS verification disabled
    "SKY-G220": "SKY-D230",  # Open redirect
}

_go_module_cache = {}


def clear_go_cache():
    _go_module_cache.clear()


def _get_module_result(module_root):
    key = str(module_root)
    if key not in _go_module_cache:
        try:
            _go_module_cache[key] = run_go_engine_for_module(module_root)
        except Exception as e:
            import os

            if os.getenv("SKYLOS_DEBUG"):
                print(f"Go analysis failed: {e}")
            _go_module_cache[key] = {"findings": [], "symbols": None}
    return _go_module_cache[key]


def _convert_symbols(symbols_data, file_path):
    if not symbols_data:
        return [], []

    file_str = str(file_path)
    defs = []
    refs = []

    for d in symbols_data.get("defs", []):
        if d.get("file") != file_str:
            continue
        defn = Definition(
            name=d["name"],
            t=d["type"],
            filename=file_path,
            line=d.get("line", 0),
        )
        defn.is_exported = d.get("is_exported", False)
        if defn.is_exported:
            defn.references = 1
        defs.append(defn)

    for r in symbols_data.get("refs", []):
        if r.get("file") == file_str:
            refs.append((r["name"], r["file"]))

    return defs, refs


def scan_go_file(file_path, cfg):
    file_path = Path(file_path)

    module_root = _find_module_root(file_path)

    if not module_root:
        module_root = file_path.parent

    result = _get_module_result(module_root)

    findings = result.get("findings", [])
    file_findings = [
        f for f in findings if Path(f.get("file", "")).resolve() == file_path.resolve()
    ]

    for f in file_findings:
        rid = f.get("rule_id", "")
        if rid in _GO_RULE_REMAP:
            f["rule_id"] = _GO_RULE_REMAP[rid]

    symbols_data = result.get("symbols")
    defs, refs = _convert_symbols(symbols_data, str(file_path.resolve()))

    # Run tree-sitter-based quality checks
    quality_findings = []
    if Parser is not None and GO_LANG is not None:
        try:
            source = file_path.read_bytes()
            parser = Parser(GO_LANG)
            tree = parser.parse(source)
            quality_findings = scan_go_quality(
                tree.root_node,
                source,
                str(file_path),
            )
        except Exception:
            import os

            if os.getenv("SKYLOS_DEBUG"):
                import traceback

                print(
                    f"Go quality scan failed for {file_path}: {traceback.format_exc()}"
                )

    return (
        defs,  # 0: definitions
        refs,  # 1: references
        set(),  # 2: dynamic refs
        set(),  # 3: exports
        _GoDummyVisitor(),  # 4: test_flags
        _GoDummyVisitor(),  # 5: framework_flags
        quality_findings,  # 6: quality findings
        file_findings,  # 7: danger/security findings
        [],  # 8: pro_finds
        None,  # 9: pattern_tracker
        None,  # 10: empty_file_finding
        cfg,  # 11: config
        [],  # 12: raw_imports
    )


def _find_module_root(file_path):
    current = Path(file_path).parent
    while current != current.parent:
        if (current / "go.mod").exists():
            return current
        current = current.parent
    return None
