"""SKY-D207/D208: a weak-hash helper whose callers hash credentials.

``export const hash = (data) => createHash('md5').update(data).digest('hex')``
hashes whatever it is given. The per-file check sees only the parameter name
``data`` and lists the finding as a low-risk hash of non-secret data. This
pass reads the calls to the helper across the scanned JS/TS files: when a
call passes a credential (``security.hash(req.body.password)``) or its result
is stored under a credential name (``setDataValue('password', hash(x))``,
``password: hash(x)``), the low-risk context is removed and the finding is
listed with that call as evidence. A helper whose callers pass only other
data (checksums, cache keys) keeps its low-risk context.

Calls are matched by import: a relative ``import``/``require`` of the
helper's module (named, default or namespace) or a call inside the module
itself. Path aliases and re-exports are not followed, so the pass can only
remove a demotion, never add one.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.security.sensitive_data import first_sensitive_name

_WEAK_HASH_RULES = frozenset({"SKY-D207", "SKY-D208"})
_LOW_RISK_REASON = "non-sensitive-hash-input"
_JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_MODULE_SUFFIXES = _JS_SUFFIXES + (".d.ts",)
_MAX_FILES = 20_000
_MAX_FILE_BYTES = 2_000_000
_MAX_ARGUMENT_CHARS = 400
_MAX_EVIDENCE = 3
_MAX_STORED_AS_PREFIX = 120

_ES_IMPORT_RE = re.compile(
    r"\bimport\s{1,40}(?:type\s{1,40})?(?P<clause>[\w$*{},\s]{1,400}?)\s{1,40}from\s{0,40}"
    r"['\"](?P<spec>[^'\"\n]{1,400})['\"]"
)
_TS_IMPORT_REQUIRE_RE = re.compile(
    r"\bimport\s{1,40}(?P<name>[A-Za-z_$][\w$]{0,200})\s*=\s*require\(\s*"
    r"['\"](?P<spec>[^'\"\n]{1,400})['\"]\s*\)"
)
_REQUIRE_RE = re.compile(
    r"\b(?:const|let|var)\s{1,40}(?P<lhs>[A-Za-z_$][\w$]{0,200}|\{[^}]{0,400}\})\s*=\s*"
    r"require\(\s*['\"](?P<spec>[^'\"\n]{1,400})['\"]\s*\)"
)
_STRING_RE = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"|`(?:[^`\\]|\\.)*`")
_NAME_RE = re.compile(r"[A-Za-z_$][\w$]*")
# What the result is stored as: ``password: hash(x)``, ``user.password =
# hash(x)``, ``setDataValue('password', hash(x))``.
_STORED_AS_RE = re.compile(
    r"(?:(?P<key>[A-Za-z_$][\w$]*)['\"]?\s*[:=]|['\"](?P<field>[A-Za-z_$][\w$]*)['\"]\s*,)"
    r"\s*(?:await\s+)?$"
)


def _module_key(path: Path) -> str:
    text = str(path)
    for suffix in sorted(_MODULE_SUFFIXES, key=len, reverse=True):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
            break
    return text.removesuffix(os.sep + "index")


def _resolved(path_text: str, root: Path) -> Path | None:
    path = Path(path_text)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return None


def _helper_aliases(text: str, caller: Path, module: str, function: str):
    """Names that call the helper in ``caller``: ``(namespaces, functions)``."""
    namespaces: set[str] = set()
    functions: set[str] = set()

    def targets_module(spec: str) -> bool:
        if not spec.startswith("."):
            return False
        joined = os.path.normpath(os.path.join(str(caller.parent), spec))
        return _module_key(Path(joined)) == module

    for match in _ES_IMPORT_RE.finditer(text):
        if not targets_module(match.group("spec")):
            continue
        clause = match.group("clause")
        named = re.search(r"\{([^}]*)\}", clause)
        if named:
            for spec in named.group(1).split(","):
                parts = spec.split()
                if not parts or parts[0] in {"type"}:
                    continue
                if parts[0] == function:
                    functions.add(
                        parts[-1] if len(parts) == 3 and parts[1] == "as" else function
                    )
            clause = clause.replace(named.group(0), "")
        star = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", clause)
        if star:
            namespaces.add(star.group(1))
            clause = clause.replace(star.group(0), "")
        default = _NAME_RE.search(clause)
        if default:
            namespaces.add(default.group(0))
    for match in _TS_IMPORT_REQUIRE_RE.finditer(text):
        if targets_module(match.group("spec")):
            namespaces.add(match.group("name"))
    for match in _REQUIRE_RE.finditer(text):
        if not targets_module(match.group("spec")):
            continue
        lhs = match.group("lhs")
        if not lhs.startswith("{"):
            namespaces.add(lhs)
            continue
        for spec in lhs.strip("{}").split(","):
            key, _, local = spec.partition(":")
            if key.strip() == function:
                functions.add((local or key).strip())
    return namespaces, functions


def _call_arguments(text: str, open_paren: int) -> str:
    depth = 0
    end = min(len(text), open_paren + _MAX_ARGUMENT_CHARS)
    for index in range(open_paren, end):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index]
    return text[open_paren + 1 : end]


def _credential_in_call(text: str, start: int, open_paren: int) -> str | None:
    """The credential name a call passes or stores its result under."""
    arguments = _STRING_RE.sub(" ", _call_arguments(text, open_paren))
    passed = first_sensitive_name(_NAME_RE.findall(arguments))
    if passed:
        return passed
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[max(line_start, start - _MAX_STORED_AS_PREFIX) : start]
    stored = _STORED_AS_RE.search(prefix)
    if stored:
        name = stored.group("key") or stored.group("field")
        return first_sensitive_name([name])
    return None


def _calls(text: str, namespaces, functions, function: str, *, own_module: bool):
    patterns = []
    for namespace in namespaces:
        patterns.append(
            rf"(?<![\w$.]){re.escape(namespace)}\s*\.\s*{re.escape(function)}\s*\("
        )
    names = set(functions)
    if own_module:
        names.add(function)
    for name in names:
        patterns.append(rf"(?<![\w$.]){re.escape(name)}\s*\(")
    if not patterns:
        return
    for match in re.finditer("|".join(patterns), text):
        before = text[max(0, match.start() - 24) : match.start()]
        if own_module and re.search(r"(?:function|const|let|var)\s+$", before):
            continue  # the definition, not a call
        yield match.start(), match.end() - 1


def list_weak_hashes_of_credentials(dangers, files, project_root) -> int:
    """Remove the low-risk context of weak-hash findings whose helper is
    called with credentials; return how many were changed."""
    candidates = []
    for finding in dangers or ():
        if (
            not isinstance(finding, dict)
            or finding.get("rule_id") not in _WEAK_HASH_RULES
        ):
            continue
        context = finding.get("low_risk_context")
        if not isinstance(context, dict) or context.get("reason") != _LOW_RISK_REASON:
            continue
        helper = context.get("caller_supplied")
        if isinstance(helper, dict) and isinstance(helper.get("function"), str):
            candidates.append(finding)
    if not candidates or project_root is None:
        return 0
    root = Path(project_root)
    sources = []
    for file in list(files or ())[:_MAX_FILES]:
        if str(file).endswith(_JS_SUFFIXES):
            resolved = _resolved(str(file), root)
            if resolved is not None:
                sources.append(resolved)
    texts: dict[Path, str | None] = {}

    def read(path: Path) -> str | None:
        if path not in texts:
            try:
                texts[path] = read_project_text_no_symlink(
                    root,
                    path,
                    max_bytes=_MAX_FILE_BYTES,
                    encoding="utf-8",
                    errors="replace",
                )
            except (OSError, ValueError, RuntimeError):
                texts[path] = None
        return texts[path]

    changed = 0
    for finding in candidates:
        helper_path = _resolved(str(finding.get("file") or ""), root)
        if helper_path is None:
            continue
        module = _module_key(helper_path)
        function = finding["low_risk_context"]["caller_supplied"]["function"]
        evidence = []
        for path in sources:
            text = read(path)
            if not text or function not in text:
                continue
            own = path == helper_path
            namespaces, functions = (
                (set(), set()) if own else _helper_aliases(text, path, module, function)
            )
            if not (own or namespaces or functions):
                continue
            for start, open_paren in _calls(
                text, namespaces, functions, function, own_module=own
            ):
                name = _credential_in_call(text, start, open_paren)
                if name is None:
                    continue
                try:
                    shown = str(path.relative_to(root.resolve()))
                except ValueError:
                    shown = str(path)
                evidence.append(
                    {
                        "file": shown,
                        "line": text.count("\n", 0, start) + 1,
                        "credential": name,
                    }
                )
                break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if evidence:
            finding.pop("low_risk_context", None)
            finding["hash_input_evidence"] = {
                "kind": "callers_pass_credentials",
                "function": function,
                "calls": evidence,
            }
            changed += 1
    return changed
