from pathlib import Path
from skylos.analysis.errors import analysis_error_payload
from skylos.analysis.language_errors import (
    tree_sitter_analysis_error,
    with_analysis_error,
)
from skylos.core.safe_cache_io import read_bytes_no_symlink
from skylos.engines.go_runner import run_go_engine_for_module
from skylos.visitors.base import Definition
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
    "SKY-G305": "SKY-D215",  # Archive extraction path traversal
    "SKY-G216": "SKY-D216",  # SSRF
    "SKY-G207": "SKY-D207",  # Weak hash MD5
    "SKY-G208": "SKY-D208",  # Weak hash SHA1
    "SKY-G209": "SKY-D250",  # Weak random source
    "SKY-G210": "SKY-D210",  # TLS verification disabled
    "SKY-G221": "SKY-D252",  # Insecure cookie flags
    "SKY-G220": "SKY-D230",  # Open redirect
}

_go_module_cache = {}
MAX_GO_SOURCE_BYTES = 2_000_000


def clear_go_cache():
    _go_module_cache.clear()


def get_go_engine_failures():
    failures = []
    for module_root in sorted(_go_module_cache):
        entry = _go_module_cache[module_root]
        failure = entry.get("failure") if isinstance(entry, dict) else None
        if not isinstance(failure, dict):
            continue
        failures.append(
            {
                **failure,
                "files": sorted(str(path) for path in entry.get("files", set())),
            }
        )
    return failures


def _get_module_result(module_root, file_path=None):
    resolved_root = Path(module_root).resolve()
    key = str(resolved_root)
    if key not in _go_module_cache:
        try:
            result = run_go_engine_for_module(resolved_root)
            if not isinstance(result, dict):
                raise TypeError("Go engine returned a non-object result")
            _go_module_cache[key] = {
                "result": result,
                "failure": None,
                "files": set(),
            }
        except Exception as e:
            import os

            if os.getenv("SKYLOS_DEBUG"):
                print(f"Go analysis failed: {e}")
            _go_module_cache[key] = {
                "result": {"findings": [], "symbols": None},
                "failure": {
                    "module_root": key,
                    "error_type": type(e).__name__,
                    "reason": str(e) or type(e).__name__,
                },
                "files": set(),
            }
    entry = _go_module_cache[key]
    if file_path is not None:
        entry["files"].add(str(Path(file_path)))
    return entry["result"]


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

    definitions_by_name = {definition.name: definition for definition in defs}
    for pair in symbols_data.get("call_pairs") or ():
        caller = definitions_by_name.get(pair.get("caller"))
        callee_name = pair.get("callee")
        if caller is None or not isinstance(callee_name, str) or not callee_name:
            continue
        caller.calls.add(callee_name)
        callee = definitions_by_name.get(callee_name)
        if callee is not None:
            callee.called_by.add(caller.name)

    return defs, refs


def scan_go_file(
    file_path,
    cfg,
    *,
    enable_quality_rules=True,
    enable_danger_rules=True,
    project_root=None,
):
    file_path = Path(file_path)

    module_root = _find_module_root(file_path)

    if not module_root:
        module_root = file_path.parent

    if not _is_safe_go_file(file_path, module_root):
        return with_analysis_error(
            _empty_go_scan_result(cfg),
            analysis_error_payload(
                file_path, OSError("Go source path is unsafe"), kind="source_read_error"
            ),
        )

    source = read_bytes_no_symlink(
        file_path, max_bytes=MAX_GO_SOURCE_BYTES, project_root=project_root
    )
    if source is None:
        return with_analysis_error(
            _empty_go_scan_result(cfg),
            analysis_error_payload(
                file_path,
                OSError("Go source is unreadable, unsafe, or exceeds the size limit"),
                kind="source_read_error",
            ),
        )

    tree = None
    analysis_error = None
    try:
        if Parser is not None and GO_LANG is not None:
            tree = Parser(GO_LANG).parse(source)
        analysis_error = tree_sitter_analysis_error(
            file_path, tree.root_node if tree is not None else None, "go"
        )
    except Exception as error:
        analysis_error = analysis_error_payload(
            file_path, error, kind="processing_error"
        )

    result = _get_module_result(module_root, file_path)
    is_generated = _is_generated_go_file(file_path, source)

    findings = result.get("findings", [])
    file_findings = (
        [
            f
            for f in findings
            if Path(f.get("file", "")).resolve() == file_path.resolve()
        ]
        if enable_danger_rules
        else []
    )

    for f in file_findings:
        rid = f.get("rule_id", "")
        if rid in _GO_RULE_REMAP:
            f["rule_id"] = _GO_RULE_REMAP[rid]

    symbols_data = result.get("symbols")
    if is_generated:
        defs, refs = [], []
    else:
        defs, refs = _convert_symbols(symbols_data, str(file_path.resolve()))

    # Run tree-sitter-based quality checks
    quality_findings = []
    if enable_quality_rules and not is_generated and tree is not None:
        try:
            language_config = cfg.get("languages", {}).get("go", {})
            quality_findings = scan_go_quality(
                tree.root_node,
                source,
                str(file_path),
                threshold=language_config.get("complexity", cfg.get("complexity", 10)),
                max_nesting=language_config.get("nesting", cfg.get("nesting", 4)),
                max_length=language_config.get("max_lines", cfg.get("max_lines", 50)),
                max_params=language_config.get("max_args", cfg.get("max_args", 5)),
            )
        except Exception as error:
            if analysis_error is None:
                analysis_error = analysis_error_payload(
                    file_path, error, kind="quality_scan_error"
                )
            import os

            if os.getenv("SKYLOS_DEBUG"):
                import traceback

                print(
                    f"Go quality scan failed for {file_path}: {traceback.format_exc()}"
                )

    scan_result = (
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
    return with_analysis_error(scan_result, analysis_error)


def _empty_go_scan_result(cfg):
    return (
        [],  # 0: definitions
        [],  # 1: references
        set(),  # 2: dynamic refs
        set(),  # 3: exports
        _GoDummyVisitor(),  # 4: test_flags
        _GoDummyVisitor(),  # 5: framework_flags
        [],  # 6: quality findings
        [],  # 7: danger/security findings
        [],  # 8: pro_finds
        None,  # 9: pattern_tracker
        None,  # 10: empty_file_finding
        cfg,  # 11: config
        [],  # 12: raw_imports
    )


def _is_safe_go_file(file_path, module_root):
    try:
        if file_path.is_symlink():
            return False
        resolved_file = file_path.resolve()
        resolved_root = Path(module_root).resolve()
        resolved_file.relative_to(resolved_root)
        return True
    except (OSError, ValueError):
        return False


def _find_module_root(file_path):
    current = Path(file_path).parent
    while current != current.parent:
        if (current / "go.mod").exists():
            return current
        current = current.parent
    return None


def _is_generated_go_file(file_path: Path, source: bytes | None = None) -> bool:
    if file_path.name.endswith(".pb.go"):
        return True
    if source is None:
        source = read_bytes_no_symlink(file_path, max_bytes=MAX_GO_SOURCE_BYTES)
    if source is None:
        return False
    prefix = source[:4096].decode("utf-8", errors="ignore")
    normalized = prefix.lower()
    return "code generated" in normalized and "do not edit" in normalized
