from pathlib import Path
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
    "SKY-G226": "SKY-D226",  # XSS: untrusted value marked safe for html/template
    "SKY-G228": "SKY-D228",  # XSS: request input written to an HTML response
}

_go_module_cache = {}
_go_scope_cache = {}


def clear_go_cache():
    _go_module_cache.clear()
    _go_scope_cache.clear()


def get_go_engine_failures():
    failures = []
    for cache_key in sorted(_go_module_cache, key=str):
        entry = _go_module_cache[cache_key]
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


def _get_module_result(module_root, file_path=None, *, source_files=None):
    resolved_root = Path(module_root).resolve()
    key = str(resolved_root)
    if source_files is not None:
        key = (key, source_files)
    if key not in _go_module_cache:
        try:
            if source_files is None:
                result = run_go_engine_for_module(resolved_root)
            else:
                result = run_go_engine_for_module(
                    resolved_root, source_files=source_files
                )
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
                    "module_root": str(resolved_root),
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

    unreachable = {
        d["name"]
        for d in symbols_data.get("defs", [])
        if d.get("reachability") == "unreachable"
    }

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
        defn.go_proven_unused_test_helper = (
            d["type"] == "function"
            and file_str.endswith("_test.go")
            and not defn.is_exported
            and d.get("reachability") == "unreachable"
        )
        if defn.is_exported or d.get("reachability") == "reachable":
            defn.references = 1
        defs.append(defn)

    for r in symbols_data.get("refs", []):
        if r.get("file") == file_str and r.get("name") not in unreachable:
            refs.append((r["name"], r["file"]))

    return defs, refs


def scan_go_file(file_path, cfg, *, go_scan_scope=None):
    file_path = Path(file_path)

    module_root = _find_module_root(file_path)

    if not module_root:
        module_root = file_path.parent

    source_files = None
    if go_scan_scope is not None:
        module_root, source_files = _scoped_go_context(
            file_path, module_root, go_scan_scope
        )

    if not _is_safe_go_file(file_path, module_root):
        return _empty_go_scan_result(cfg)

    result = _get_module_result(module_root, file_path, source_files=source_files)
    is_generated = _is_generated_go_file(file_path)

    findings = result.get("findings", [])
    file_findings = [
        f for f in findings if Path(f.get("file", "")).resolve() == file_path.resolve()
    ]

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
    if not is_generated and Parser is not None and GO_LANG is not None:
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


def _scoped_go_context(file_path, module_root, scope):
    """Admit workspace siblings only through the caller's source inventory."""
    from skylos.engines.go_runner import GoEngineError

    try:
        root, paths = scope
        root = Path(root).resolve(strict=True)
        if not root.is_dir() or not isinstance(paths, tuple):
            raise ValueError("invalid inventory")
        file_path = Path(file_path).absolute()
        cache_key = (str(root), paths)
        admitted = _go_scope_cache.get(cache_key)
        if admitted is None:
            if len(paths) > 32768:
                raise ValueError("oversized source inventory")
            admitted = set()
            for value in paths:
                path = Path(value)
                if not path.is_absolute() or path.suffix != ".go":
                    raise ValueError("invalid file")
                relative = path.relative_to(root)
                current = root
                for part in relative.parts:
                    current /= part
                    if current.is_symlink():
                        raise ValueError("symlink source")
                if not path.is_file() or path.resolve() != path:
                    raise ValueError("non-regular source")
                admitted.add(path)
            admitted = frozenset(admitted)
            _go_scope_cache[cache_key] = admitted
        if file_path not in admitted:
            raise ValueError("file is outside admitted inventory")

        workspace = _scoped_workspace_root(file_path, root)
        engine_root = workspace or Path(module_root).resolve()
        if workspace is None:
            # This change admits workspace context only. The ordinary module
            # scanner retains its existing invocation and discovery policy.
            return engine_root, None
        engine_root.relative_to(root)
        selected = tuple(
            sorted({str(path) for path in admitted if path.is_relative_to(engine_root)})
        )
        return engine_root, selected
    except (OSError, TypeError, ValueError) as exc:
        raise GoEngineError("Invalid admitted Go source scope") from exc


def _scoped_workspace_root(file_path, scan_root):
    import os

    workspace = os.getenv("GOWORK", "")
    if workspace == "off":
        return None
    if workspace:
        path = Path(workspace)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            return None
        candidate = path.parent.resolve()
        return candidate if candidate.is_relative_to(scan_root) else None
    current = Path(file_path).parent
    while current.is_relative_to(scan_root):
        path = current / "go.work"
        if path.exists() or path.is_symlink():
            return current if path.is_file() and not path.is_symlink() else None
        if current == scan_root:
            break
        current = current.parent
    return None


def _is_generated_go_file(file_path: Path) -> bool:
    if file_path.name.endswith(".pb.go"):
        return True
    try:
        if file_path.is_symlink() or not file_path.is_file():
            return False
        with file_path.open("rb") as handle:
            prefix = handle.read(4096).decode("utf-8", errors="ignore")
    except Exception:
        return False
    normalized = prefix.lower()
    return "code generated" in normalized and "do not edit" in normalized
