from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from skylos.rules.quality.standards import security_cwe_entries
from skylos.visitors.languages.csharp import models
from skylos.visitors.languages.csharp._lex import (
    _TOKEN_RE,
    _RawTokenMatch,
    mask_comments_and_strings,
    matching_brace,
)
from skylos.visitors.languages.csharp.models import Rule

_ASSIGN_RE = re.compile(
    r"\b(?:(?P<decl_type>[\w.:<>\[\],?]+)\s+)?"
    r"(?P<lhs>@?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*=(?!=)\s*(?P<rhs>.+?);?\s*$",
    re.DOTALL,
)
_COMPOUND_ASSIGN_RE = re.compile(
    r"^(?:this\s*\.\s*)?(?P<lhs>@?[A-Za-z_]\w*)\s*\+=\s*(?P<rhs>.+?);?\s*$",
    re.DOTALL,
)
_BUILDER_APPEND_RE = re.compile(
    r"^(?P<owner>@?[A-Za-z_]\w*)\s*\.\s*(?:Append|AppendLine|AppendFormat|Insert)\s*\("
)
_FOREACH_RE = re.compile(
    r"^foreach\s*\(\s*(?:var|[\w.<>\[\],?]+)\s+@?(?P<name>[A-Za-z_]\w*)\s+in\s+(?P<source>.+)\)",
    re.DOTALL,
)
_METHOD_RE = re.compile(
    r"(?m)(?:^|(?<=[;{}]))\s*(?P<attrs>(?:\[[^\]\n]+\]\s*)*)"
    r"(?P<mods>(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|abstract|extern|partial|unsafe|new)\s+)*)"
    r"(?P<rtype>(?:[A-Za-z_][\w.<>\[\],?]*\s+)+)"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:<[^;{}()]+>)?\s*"
    r"\((?P<params>(?:[^;{}()]|\([^;{}()]*\))*)\)\s*"
    r"(?:where\s+[^{=>]+)?(?P<opener>\{|=>)"
)
_CONSTRUCTOR_RE = re.compile(
    r"(?m)(?:^|(?<=[;{}]))\s*(?P<attrs>(?:\[[^\]\n]+\]\s*)*)"
    r"(?P<mods>(?:(?:public|private|protected|internal|static|extern|unsafe)\s+)*)"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>(?:[^;{}()]|\([^;{}()]*\))*)\)\s*"
    r"(?::\s*(?:base|this)\s*\((?:[^;{}()]|\([^;{}()]*\))*\)\s*)?(?P<opener>\{|=>)"
)
_CLASS_RE = re.compile(
    r"(?P<attrs>(?:\[[^\]]*\]\s*)*)"
    r"(?P<mods>(?:(?:public|private|protected|internal|static|sealed|abstract|partial|file|unsafe|new|readonly)\s+)*)"
    r"\b(?P<kind>class|record(?:\s+class|\s+struct)?|struct|interface)\s+(?P<name>[A-Za-z_]\w*)"
)
_MEMBER_DECL_RE = re.compile(
    r"^(?P<attrs>(?:\[[^\]]*\]\s*)*)"
    r"(?P<mods>(?:(?:public|private|protected|internal|static|readonly|const|volatile|new|required|virtual|override|abstract|sealed|unsafe|extern)\s+)*)"
    r"(?P<type>[A-Za-z_][\w.:]*(?:\s*<[^;{}()=]*>)?(?:\s*\[\s*\])*\??)\s+"
    r"@?(?P<name>[A-Za-z_]\w*)\s*(?P<tail>(?:=(?!=)|=>|,)[\s\S]*)?$"
)
_MAP_CALL_RE = re.compile(
    r"\.\s*Map(?:Get|Post|Put|Delete|Patch|Methods|Fallback)\s*(?:<[^;{}()]*>)?\s*\("
)
_CALL_NAME_RE = re.compile(r"(?P<name>[A-Za-z_]\w*)\s*(?:<[^;{}()]*>)?\s*\(")
_MODIFIERS = frozenset(
    {
        "public",
        "private",
        "protected",
        "internal",
        "static",
        "async",
        "virtual",
        "override",
        "sealed",
        "abstract",
        "extern",
        "partial",
        "unsafe",
        "new",
        "readonly",
    }
)
_STATEMENT_WORDS = frozenset(
    {
        "return",
        "new",
        "else",
        "await",
        "throw",
        "yield",
        "case",
        "goto",
        "var",
        "using",
        "lock",
        "in",
        "is",
        "as",
        "out",
        "when",
        "not",
        "and",
        "or",
        "operator",
        "implicit",
        "explicit",
        "delegate",
        "event",
    }
)
_NON_METHOD_NAMES = frozenset(
    {
        "if",
        "while",
        "for",
        "foreach",
        "switch",
        "using",
        "lock",
        "catch",
        "fixed",
        "return",
        "nameof",
        "typeof",
        "sizeof",
        "default",
        "when",
        "checked",
        "unchecked",
    }
)
_TEXT_PRESERVING_CALLS = frozenset(
    {
        "Format",
        "Concat",
        "Join",
        "ToString",
        "Trim",
        "TrimStart",
        "TrimEnd",
        "ToUpper",
        "ToLower",
        "ToUpperInvariant",
        "ToLowerInvariant",
        "Replace",
        "Substring",
        "PadLeft",
        "PadRight",
        "Append",
        "AppendLine",
        "AppendFormat",
        "Insert",
    }
)
_TYPE_KEYWORDS = frozenset(
    {"class", "struct", "interface", "record", "enum", "namespace", "delegate"}
)
_COMMAND_SINK_RE = re.compile(r"\b(?:Process\.Start|new\s+ProcessStartInfo)\s*\(")
_COMMAND_PROPERTY_RE = re.compile(
    r"\b(?P<owner>@?[A-Za-z_]\w*)\.(?:FileName|Arguments)\s*=(?!=)"
)
_START_INFO_PROPERTY_RE = re.compile(
    r"\.\s*StartInfo\s*\.\s*(?:FileName|Arguments)\s*=(?!=)"
)
_PATH_SINK_RE = re.compile(
    r"\b(?:File|Directory)\.(?:Open|OpenRead|OpenWrite|OpenText|Create|CreateText|"
    r"AppendText|ReadAllText|ReadAllTextAsync|ReadAllBytes|ReadAllBytesAsync|"
    r"ReadAllLines|ReadAllLinesAsync|ReadLines|WriteAllText|WriteAllTextAsync|"
    r"WriteAllBytes|WriteAllBytesAsync|WriteAllLines|WriteAllLinesAsync|"
    r"AppendAllText|AppendAllTextAsync|AppendAllLines|AppendAllLinesAsync|Delete|"
    r"Copy|Move|Replace|Exists|GetFiles|GetDirectories|EnumerateFiles|"
    r"EnumerateDirectories|EnumerateFileSystemEntries|GetFileSystemEntries|"
    r"CreateDirectory)\s*\("
)
_PATH_CONSTRUCTOR_RE = re.compile(
    r"\bnew\s+(?:System\.IO\.)?(?P<type>FileStream|FileInfo|DirectoryInfo|"
    r"StreamReader|StreamWriter)\s*\("
)
_PHYSICAL_FILE_RE = re.compile(r"(?<![\w.])(?:this\s*\.\s*)?PhysicalFile\s*\(")
_STREAM_ARGUMENT_RE = re.compile(
    r"\b(?:Body|BodyReader|InputStream|OpenReadStream|Stream|BaseStream|GetStream|"
    r"Content)\b"
)
_PATH_COMBINE_RE = re.compile(r"\s*(?P<qualified>System\.IO\.)?Path\.Combine\s*\(")
_PATH_BASENAME_RE = re.compile(r"\s*(?P<qualified>System\.IO\.)?Path\.GetFileName\s*\(")
_FIXED_DIRECTORY_RE = re.compile(r'"(?P<path>[A-Za-z0-9_./-]+)"')
_PATH_SHADOW_RE = re.compile(
    r"\b(?:class|record|struct|interface)\s+Path\b"
    r"|\busing\s+Path\s*="
    r"|\b(?:var|[A-Za-z_]\w*)\s+Path\s*(?:=|[,;)])"
)
_RECEIVER_METHOD_RE = re.compile(
    r"\.\s*(?P<method>[A-Za-z_]\w*)\s*(?:<[^;{}()]*>)?\s*\("
)
_STATIC_SSRF_RE = re.compile(
    r"\b(?:Http)?WebRequest\s*\.\s*(?:Create|CreateHttp|CreateDefault)\s*\("
)
_SSRF_CONSTRUCTOR_RE = re.compile(
    r"\bnew\s+(?P<type>HttpRequestMessage|RestClient|RestClientOptions|RestRequest)\s*\("
)
_BASE_ADDRESS_RE = re.compile(r"\.\s*(?:BaseAddress|RequestUri)\s*=(?!=)")
_SQL_CONSTRUCTOR_RE = re.compile(
    r"\bnew\s+(?P<type>"
    + "|".join(sorted(models.SQL_COMMAND_TYPES | models.SQL_ADAPTER_TYPES))
    + r")\s*\("
)
_SQL_COMMAND_TYPE_RE = re.compile(
    r"\b(?:" + "|".join(sorted(models.SQL_COMMAND_TYPES)) + r")\b"
)
_EF_SQL_RE = re.compile(
    r"\b(?P<method>"
    + "|".join(sorted(models.EF_RAW_SQL_METHODS | models.EF_FORMATTABLE_SQL_METHODS))
    + r")\s*(?:<[^;{}()]*>)?\s*\("
)
_OBJECT_INIT_RE = re.compile(
    r"\bnew\s+(?P<type>ProcessStartInfo|"
    + "|".join(sorted(models.SQL_COMMAND_TYPES))
    + r")\s*(?:\([^{};]*\))?\s*\{$"
)
_TARGET_TYPED_INIT_RE = re.compile(r"\bnew\s*\([^{};]*\)\s*\{$")
_COMMAND_TEXT_RE = re.compile(r"\b(?P<owner>@?[A-Za-z_]\w*)\.CommandText\s*=(?!=)")
_REDIRECT_RE = re.compile(
    r"(?<![\w.])(?:this\s*\.\s*)?(?:Redirect|RedirectPermanent|RedirectPreserveMethod|"
    r"RedirectPermanentPreserveMethod)\s*\("
    r"|\bResponse\s*\.\s*Redirect\s*\("
    r"|\b(?:Results|TypedResults)\s*\.\s*Redirect\s*\("
    r"|\bnew\s+RedirectResult\s*\("
)
_LOCATION_PROPERTY_RE = re.compile(r"\bHeaders\s*\.\s*Location\s*=(?!=)")
_LOCATION_INDEX_RE = re.compile(r'\bHeaders\s*\[\s*"Location"\s*\]\s*=(?!=)', re.I)
_LOCATION_CALL_RE = re.compile(
    r"\b(?:Headers\s*\.\s*(?:Add|Append)|AddHeader|AppendHeader)\s*\("
)
_LOCAL_URL_GUARD_RE = re.compile(
    r"(?<![\w.])(?P<receiver>(?:(?:this|base)\s*\.\s*)?@?[A-Za-z_]\w*)\s*\.\s*"
    r"IsLocalUrl\s*\(\s*@?(?P<var>[A-Za-z_]\w*)\s*\)"
)
_BOOL_SUFFIX_RE = re.compile(
    r"(?:(?P<op>==|!=)\s*|(?<![\w.])is\s+(?:(?P<not>not)\s+)?)(?P<value>true|false)\s*\Z"
)
_BOOL_PREFIX_RE = re.compile(r"\s*(?P<value>true|false)\s*(?P<op>==|!=)")
_EXPRESSION_KEYWORDS = frozenset(
    {"return", "throw", "yield", "else", "case", "when", "in", "do"}
)
_IF_RE = re.compile(r"\bif\s*\(")
_GOTO_RE = re.compile(r"\bgoto\b")
_WORD_RE = re.compile(r"[A-Za-z_]\w*")
_EXPRESSION_HEAD_WORDS = frozenset(
    {
        "new",
        "switch",
        "with",
        "is",
        "return",
        "throw",
        "await",
        "yield",
        "delegate",
        "stackalloc",
    }
)
_LOOP_WORDS = frozenset({"for", "foreach", "while"})
_WRAPPER_WORDS = frozenset({"using", "lock", "fixed"})
_BLOCK_WORDS = frozenset({"checked", "unchecked", "unsafe"})
_PROVIDER_TYPE_TEXT = r"(?:global\s*::\s*)?[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*"
_TYPE_NAME_HANDLING_RE = re.compile(
    r"\bTypeNameHandling\s*=(?!=)\s*(?:"
    rf"(?P<enum>{_PROVIDER_TYPE_TEXT})\s*\.\s*(?P<value>[A-Za-z]\w*)"
    rf"|\(\s*(?P<number_type>{_PROVIDER_TYPE_TEXT})\s*\)\s*(?P<number>\d+))"
)
_BINDER_RE = re.compile(r"\b(?:SerializationBinder|Binder)\s*=(?!=)")
_TYPE_RESOLVER_RE = re.compile(
    r"\bnew\s+JavaScriptSerializer\s*\(\s*new\s+SimpleTypeResolver\s*\("
)
_HTML_STRING_RE = re.compile(r"\bnew\s+(?:HtmlString|MarkupString)\s*\(")
_HTML_RAW_RE = re.compile(r"\b\w*[Hh]tml\w*\s*\.\s*Raw\s*\(")
_MARKUP_CAST_RE = re.compile(r"\(\s*MarkupString\s*\)")
_CONTENT_RE = re.compile(
    r"(?<![\w.])(?:this\s*\.\s*)?Content\s*\(|\b(?:Results|TypedResults)\s*\.\s*Content\s*\("
)
_RESPONSE_WRITE_RE = re.compile(
    r"(?<![\w.:])(?P<receiver>(?:@?[A-Za-z_][\w:]*\s*\.\s*)*Response)"
    r"\s*\.\s*Write\s*\("
)
_CONTENT_TYPE_RE = re.compile(
    r"(?<![\w.:])(?P<receiver>(?:@?[A-Za-z_][\w:]*(?:\s*\.\s*))+)?ContentType\s*=(?!=)"
)
_CONTENT_TYPE_VALUE_RE = re.compile(r'\s*@?"(?P<type>[^"]*)"\s*(?=[;,)}]|\Z)')
_CONTENT_TYPE_STATEMENT_RE = re.compile(
    r"(?:@?[A-Za-z_][\w:]*\s*\??\.\s*)*ContentType\s*=(?!=)[^;]*;"
)
_HTML_TYPE = "html"
_OTHER_TYPE = "other"
_ResponseRecord = tuple[
    int, int, frozenset[str], tuple[tuple[int, frozenset[str]], ...]
]
_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_MAX_ROUNDS = 4


@dataclass(frozen=True)
class _Param:
    name: str
    type: str
    attrs: frozenset[str]
    optional: bool
    variadic: bool
    raw_type: str = ""


@dataclass
class _ClassInfo:
    name: str
    open: int
    close: int
    attrs: frozenset[str]
    mods: frozenset[str]
    bases: tuple[str, ...]
    raw_bases: tuple[str, ...] = ()
    member_types: dict[str, set[str]] = field(default_factory=dict)
    proof_types: dict[str, set[str]] = field(default_factory=dict)
    bound_properties: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)


@dataclass
class _Scope:
    body: str
    body_offset: int
    start_line: int
    name: str
    kind: str
    owner: _ClassInfo | None
    params: tuple[_Param, ...] = ()
    mods: frozenset[str] = frozenset()
    attrs: frozenset[str] = frozenset()
    entry: bool = False
    local_names: frozenset[str] | None = None


@dataclass
class _FileContext:
    source: str
    masked: str
    classes: list[_ClassInfo]
    scopes: list[_Scope]
    path_type_shadowed: bool
    ef6: bool
    methods_by_class: dict[str | None, dict[str, list[int]]]
    classes_by_name: dict[str, _ClassInfo]
    constructors_by_class: dict[str, list[int]]
    callable_names: frozenset[str]
    type_aliases: dict[str, str]
    project_types: frozenset[str]


@dataclass
class _ScopeState:
    tainted_vars: dict[str, set[str]]
    path_type_shadowed: bool = False
    basename_vars: set[str] = field(default_factory=set)
    assigned_vars: set[str] = field(default_factory=set)
    process_info_vars: set[str] = field(default_factory=set)
    sql_command_vars: set[str] = field(default_factory=set)
    param_vars: set[str] = field(default_factory=set)
    built_vars: set[str] = field(default_factory=set)
    request_vars: set[str] = field(default_factory=set)
    types: dict[str, set[str]] = field(default_factory=dict)
    ef6: bool = False
    response_types: dict[str, list[_ResponseRecord]] = field(default_factory=dict)
    proof_types: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class _Statement:
    kind: str
    start: int
    end: int
    parts: list[_Statement | None] = field(default_factory=list)


@dataclass
class _Flow:
    body: str
    masked: str
    records: list[_ResponseRecord]
    response_receivers: frozenset[str]
    context: _FileContext


@dataclass
class _Collector:
    file_path: str
    by_key: dict[tuple[str, int], dict] = field(default_factory=dict)

    def add(self, rule: Rule, line: int) -> None:
        key = (rule.rule_id, line)
        current = self.by_key.get(key)
        if (
            current is not None
            and _SEVERITY_ORDER[current["severity"]] >= (_SEVERITY_ORDER[rule.severity])
        ):
            return
        self.by_key[key] = {
            "rule_id": rule.rule_id,
            "severity": rule.severity,
            "message": rule.message,
            "file": str(Path(self.file_path)),
            "line": line,
            "col": 0,
            "category": "danger",
            "cwe": security_cwe_entries(rule.rule_id),
        }

    def findings(self) -> list[dict]:
        return [
            self.by_key[key] for key in sorted(self.by_key, key=lambda k: (k[1], k[0]))
        ]


def scan_danger(file_path: str, source: str) -> list[dict]:
    context = _file_context(source)
    extra: dict[int, dict[str, set[str]]] = {}
    collector = _Collector(file_path)
    for _ in range(_MAX_ROUNDS):
        collector = _Collector(file_path)
        calls: list[tuple[int, str, str]] = []
        for index, scope in enumerate(context.scopes):
            _scan_scope(context, index, scope, extra.get(index, {}), collector, calls)
        changed = False
        for callee, key, name in calls:
            bucket = extra.setdefault(callee, {}).setdefault(key, set())
            if name not in bucket:
                bucket.add(name)
                changed = True
        if not changed:
            break
    _scan_file_patterns(context, collector)
    return collector.findings()


def _file_context(source: str) -> _FileContext:
    masked = mask_comments_and_strings(source)
    classes = _classes(masked)
    classes_by_name: dict[str, _ClassInfo] = {}
    for info in classes:
        classes_by_name.setdefault(info.name, info)
    _mark_class_kinds(classes, classes_by_name)
    scopes, spans = _member_scopes(source, masked, classes)
    for scope in scopes:
        if scope.kind == "constructor" and scope.owner is not None:
            for param in scope.params:
                scope.owner.member_types.setdefault(param.name, set()).add(param.type)
                scope.owner.proof_types.setdefault(param.name, set()).add(
                    param.raw_type
                )
    handlers: set[tuple[str | None, str]] = set()
    scopes.extend(_minimal_api_scopes(source, masked, classes, handlers))
    for scope in scopes:
        if scope.kind != "method":
            continue
        for qualifier, name in handlers:
            if scope.name == name and (
                qualifier is None
                or (scope.owner is not None and scope.owner.name == qualifier)
            ):
                scope.entry = True
        if not scope.entry:
            scope.entry = _is_entry_method(scope)
    scopes.append(
        _Scope(
            body=_blank_spans(source, spans),
            body_offset=0,
            start_line=1,
            name="",
            kind="file",
            owner=None,
        )
    )
    methods_by_class: dict[str | None, dict[str, list[int]]] = {}
    constructors_by_class: dict[str, list[int]] = {}
    for index, scope in enumerate(scopes):
        owner_name = _owner_name(scope)
        if scope.kind in {"method", "local"}:
            methods_by_class.setdefault(owner_name, {}).setdefault(
                scope.name, []
            ).append(index)
        elif scope.kind == "constructor" and owner_name is not None:
            constructors_by_class.setdefault(owner_name, []).append(index)
    return _FileContext(
        source=source,
        masked=masked,
        classes=classes,
        scopes=scopes,
        path_type_shadowed=bool(_PATH_SHADOW_RE.search(masked)),
        ef6=bool(re.search(r"\busing\s+System\.Data\.Entity\s*;", masked)),
        methods_by_class=methods_by_class,
        classes_by_name=classes_by_name,
        constructors_by_class=constructors_by_class,
        callable_names=frozenset(
            {name for methods in methods_by_class.values() for name in methods}
            | set(constructors_by_class)
        ),
        type_aliases={
            match.group("name"): match.group("type")
            for match in re.finditer(
                r"\busing\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<type>[\w.:]+)\s*;",
                masked,
            )
        },
        project_types=_project_type_names(masked, classes),
    )


def _classes(masked: str) -> list[_ClassInfo]:
    classes: list[_ClassInfo] = []
    for match in _CLASS_RE.finditer(masked):
        body_start = re.compile(r"[;{]").search(masked, match.end())
        if body_start is None or body_start.group() != "{":
            continue
        close = matching_brace(masked, body_start.start())
        if close == -1:
            continue
        header = masked[match.end() : body_start.start()]
        info = _ClassInfo(
            name=match.group("name"),
            open=body_start.start(),
            close=close,
            attrs=_attribute_names(match.group("attrs")),
            mods=frozenset(match.group("mods").split()),
            bases=_base_names(header),
            raw_bases=_raw_base_names(header),
        )
        primary = re.match(r"\s*(?:<[^{}()]*>)?\s*\(", header)
        if primary:
            open_paren = header.index("(", primary.start())
            close_paren = _matching_paren(header, open_paren)
            if close_paren > open_paren:
                for param in _parse_params(header[open_paren + 1 : close_paren]):
                    info.member_types.setdefault(param.name, set()).add(param.type)
                    info.proof_types.setdefault(param.name, set()).add(param.raw_type)
        classes.append(info)
    for info in classes:
        _collect_members(masked, info)
    return classes


def _project_type_names(masked: str, classes: list[_ClassInfo]) -> frozenset[str]:
    namespaces = []
    for match in re.finditer(r"\bnamespace\s+([\w.]+)\s*([;{])", masked):
        end = len(masked)
        if match.group(2) == "{":
            end = matching_brace(masked, match.end() - 1)
        namespaces.append((match.end(), end, match.group(1)))
    names = set()
    for info in classes:
        parts = [name for start, end, name in namespaces if start <= info.open < end]
        parts.extend(
            parent.name for parent in classes if parent.open < info.open < parent.close
        )
        names.add(".".join([*parts, info.name]))
    return frozenset(names)


def _base_names(header: str) -> tuple[str, ...]:
    text = re.sub(r"^\s*<[^{}()]*>", "", header)
    if text.lstrip().startswith("("):
        open_paren = text.index("(")
        close_paren = _matching_paren(text, open_paren)
        if close_paren > 0:
            text = text[close_paren + 1 :]
        else:
            text = ""
    text = re.split(r"\bwhere\b", text, maxsplit=1)[0]
    if ":" not in text:
        return ()
    names = []
    for part in _split_top_level(text.split(":", 1)[1]):
        simple = _simple_type(re.sub(r"\([^)]*\)", "", part))
        if simple:
            names.append(simple)
    return tuple(names)


def _raw_base_names(header: str) -> tuple[str, ...]:
    # Keep provider qualifications for D233; the general type-name index keeps
    # its existing simple-name behavior for other rules.
    separator = re.search(r"(?<!:):(?!:)", header)
    if separator is None:
        return ()
    tail = re.split(r"\bwhere\b", header[separator.end() :], maxsplit=1)[0]
    return tuple(part.strip() for part in _split_top_level(tail) if part.strip())


def _collect_members(masked: str, info: _ClassInfo) -> None:
    bind_all = "BindProperties" in info.attrs
    depth = 0
    start = info.open + 1
    for index in range(info.open + 1, info.close):
        char = masked[index]
        if char == "{":
            if depth == 0:
                _record_member(masked[start:index], info, bind_all)
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                start = index + 1
        elif char == ";" and depth == 0:
            _record_member(masked[start:index], info, bind_all)
            start = index + 1


def _record_member(text: str, info: _ClassInfo, bind_all: bool) -> None:
    match = _MEMBER_DECL_RE.match(text.strip())
    if not match:
        return
    type_name = _simple_type(match.group("type"))
    if not type_name or type_name in _STATEMENT_WORDS or type_name in _TYPE_KEYWORDS:
        return
    name = match.group("name")
    types = info.member_types.setdefault(name, set())
    types.add(type_name)
    info.proof_types.setdefault(name, set()).add(match.group("type"))
    tail = match.group("tail") or ""
    created = re.match(r"=\s*new\s+(?P<type>[A-Za-z_][\w.:]*)", tail)
    if created:
        types.add(_simple_type(created.group("type")))
        info.proof_types[name].add(created.group("type"))
    attrs = _attribute_names(match.group("attrs"))
    mods = set(match.group("mods").split())
    if attrs & models.BOUND_PROPERTY_ATTRIBUTES or (
        bind_all and "public" in mods and "static" not in mods
    ):
        info.bound_properties.add(name)


def _mark_class_kinds(
    classes: list[_ClassInfo], classes_by_name: dict[str, _ClassInfo]
) -> None:
    for info in classes:
        if "NonController" in info.attrs:
            continue
        if (
            info.attrs & models.CONTROLLER_ATTRIBUTES
            or _is_poco_controller(info)
            or _derives(
                info,
                classes_by_name,
                lambda base: (
                    base in models.CONTROLLER_BASES
                    or base.endswith(("Controller", "ControllerBase"))
                ),
            )
        ):
            info.kinds.add("controller")
        if _derives(info, classes_by_name, lambda base: base.endswith("PageModel")):
            info.kinds.add("page")
        if _derives(info, classes_by_name, lambda base: base == "Hub"):
            info.kinds.add("hub")
    changed = True
    while changed:
        changed = False
        for info in classes:
            if "controller" in info.kinds or "NonController" in info.attrs:
                continue
            for base in info.bases:
                parent = classes_by_name.get(base)
                if parent is not None and "controller" in parent.kinds:
                    info.kinds.add("controller")
                    changed = True
                    break


def _is_poco_controller(info: _ClassInfo) -> bool:
    """ASP.NET Core's name convention, but not a ``PlayerController :
    MonoBehaviour``: every base must be an interface or controller-named."""
    if "public" not in info.mods or not info.name.endswith("Controller"):
        return False
    return all(
        re.fullmatch(r"I[A-Z]\w*", base)
        or base.endswith(("Controller", "ControllerBase"))
        for base in info.bases
    )


def _derives(info: _ClassInfo, classes_by_name, predicate) -> bool:
    seen = {info.name}
    pending = list(info.bases)
    while pending:
        base = pending.pop()
        if predicate(base):
            return True
        parent = classes_by_name.get(base)
        if parent is not None and parent.name not in seen:
            seen.add(parent.name)
            pending.extend(parent.bases)
    return False


def _member_scopes(
    source: str, masked: str, classes: list[_ClassInfo]
) -> tuple[list[_Scope], list[tuple[int, int]]]:
    scopes: list[_Scope] = []
    spans: list[tuple[int, int]] = []
    seen: set[int] = set()
    matches = [(match, False) for match in _METHOD_RE.finditer(masked)]
    matches.extend((match, True) for match in _CONSTRUCTOR_RE.finditer(masked))
    for match, constructor_form in sorted(
        matches, key=lambda item: item[0].start("name")
    ):
        name = match.group("name")
        if match.start("name") in seen or name in _NON_METHOD_NAMES:
            continue
        owner = _owner_at(classes, match.start("name"))
        direct = owner is not None and _is_direct_member(masked, owner, match.start())
        if constructor_form:
            if not direct or owner is None or name != owner.name:
                continue
            kind = "constructor"
            mods = frozenset(match.group("mods").split())
        else:
            tokens = (match.group("mods") + match.group("rtype")).split()
            mods = frozenset(token for token in tokens if token in _MODIFIERS)
            return_tokens = [token for token in tokens if token not in _MODIFIERS]
            if any(token in _STATEMENT_WORDS for token in return_tokens):
                continue
            if owner is not None and name == owner.name and direct:
                kind = "constructor"
            elif not return_tokens:
                continue
            elif direct:
                kind = "method"
            else:
                kind = "local"
        span = _scope_span(masked, match)
        if span is None:
            continue
        seen.add(match.start("name"))
        body_start, body_end = span
        scopes.append(
            _Scope(
                body=source[body_start:body_end],
                body_offset=body_start,
                start_line=source.count("\n", 0, body_start) + 1,
                name=name,
                kind=kind,
                owner=owner,
                params=tuple(_parse_params(match.group("params"))),
                mods=mods,
                attrs=_attribute_names(match.group("attrs")),
            )
        )
        spans.append(span)
    return scopes, spans


def _scope_span(masked: str, match: re.Match[str]) -> tuple[int, int] | None:
    if match.group("opener") == "{":
        open_brace = match.end() - 1
        close_brace = matching_brace(masked, open_brace)
        if close_brace == -1:
            return None
        return open_brace + 1, close_brace
    expression_start = match.end()
    expression_end = masked.find(";", expression_start)
    if expression_end == -1:
        return None
    return expression_start, expression_end + 1


def _minimal_api_scopes(
    source: str,
    masked: str,
    classes: list[_ClassInfo],
    handlers: set[tuple[str | None, str]],
) -> list[_Scope]:
    scopes: list[_Scope] = []
    for match in _MAP_CALL_RE.finditer(masked):
        open_paren = match.end() - 1
        close_paren = _matching_paren(masked, open_paren)
        if close_paren < 0:
            continue
        pieces = _argument_spans(masked, open_paren + 1, close_paren)
        if len(pieces) < 2:
            continue
        start, end = pieces[-1]
        handler = masked[start:end]
        group = re.fullmatch(
            r"\s*(?:(?P<cls>[A-Za-z_]\w*)\s*\.\s*)?(?P<name>[A-Za-z_]\w*)\s*", handler
        )
        if group:
            handlers.add((group.group("cls"), group.group("name")))
            continue
        scope = _lambda_scope(source, masked, start, end, classes)
        if scope is not None:
            scopes.append(scope)
    return scopes


def _lambda_scope(
    source: str, masked: str, start: int, end: int, classes: list[_ClassInfo]
) -> _Scope | None:
    text = masked[start:end]
    arrow = _top_level_arrow(text)
    if arrow < 0:
        return None
    head = re.sub(r"\[[^\]]*\]", " ", text[:arrow])
    head = re.sub(r"\b(?:static|async)\b", " ", head).strip()
    if not (head.startswith("(") and head.endswith(")")):
        return None
    params = _parse_params(head[1:-1])
    body_start = start + arrow + 2
    while body_start < end and masked[body_start].isspace():
        body_start += 1
    if body_start < end and masked[body_start] == "{":
        close = matching_brace(masked, body_start)
        if close == -1:
            return None
        span = (body_start + 1, close)
    else:
        span = (body_start, end)
    return _Scope(
        body=source[span[0] : span[1]],
        body_offset=span[0],
        start_line=source.count("\n", 0, span[0]) + 1,
        name="<lambda>",
        kind="lambda",
        owner=_owner_at(classes, start),
        params=tuple(params),
        entry=True,
    )


def _top_level_arrow(text: str) -> int:
    depth = 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "=" and depth == 0 and text.startswith("=>", index):
            return index
    return -1


def _is_entry_method(scope: _Scope) -> bool:
    owner = scope.owner
    if owner is None or scope.kind != "method":
        return False
    if (
        "public" not in scope.mods
        or scope.mods & {"static", "override", "abstract"}
        or scope.attrs & models.NON_ACTION_ATTRIBUTES
    ):
        return False
    if "controller" in owner.kinds or "hub" in owner.kinds:
        return True
    return "page" in owner.kinds and bool(re.match(r"On[A-Z]", scope.name))


def _parse_params(params: str) -> list[_Param]:
    parsed: list[_Param] = []
    masked = mask_comments_and_strings(params)
    for piece in _split_top_level(masked, angle_brackets=True):
        text = piece.strip()
        attrs: set[str] = set()
        while text.startswith("["):
            close = _matching_bracket(text, 0)
            if close < 0:
                break
            attrs |= _attribute_names(text[: close + 1])
            text = text[close + 1 :].strip()
        optional = "=" in text
        text = text.split("=", 1)[0].strip()
        tokens = text.split()
        variadic = "params" in tokens
        tokens = [
            token
            for token in tokens
            if token not in {"this", "params", "ref", "out", "in", "scoped", "readonly"}
        ]
        if len(tokens) < 2:
            continue
        name = tokens[-1].lstrip("@")
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        parsed.append(
            _Param(
                name=name,
                type=_simple_type(" ".join(tokens[:-1])),
                attrs=frozenset(attrs),
                optional=optional,
                variadic=variadic,
                raw_type=" ".join(tokens[:-1]),
            )
        )
    return parsed


def _attribute_names(text: str) -> frozenset[str]:
    names: set[str] = set()
    for group in re.finditer(r"\[(?P<body>[^\]]*)\]", text or ""):
        for part in _split_top_level(group.group("body")):
            match = re.match(r"\s*(?:\w+\s*:\s*)?(?P<name>[A-Za-z_][\w.]*)", part)
            if match:
                name = match.group("name").rsplit(".", 1)[-1]
                if name.endswith("Attribute") and len(name) > len("Attribute"):
                    name = name[: -len("Attribute")]
                names.add(name)
    return frozenset(names)


def _simple_type(text: str) -> str:
    cleaned = re.sub(r"<.*>", "", text or "", flags=re.DOTALL)
    cleaned = re.sub(r"[\[\]?\s]", "", cleaned)
    return cleaned.rsplit(".", 1)[-1]


def _param_is_service(param: _Param) -> bool:
    if param.attrs & models.SERVICE_ATTRIBUTES:
        return True
    type_name = param.type
    if type_name in models.NON_INPUT_TYPES or type_name in models.REQUEST_OBJECT_TYPES:
        return True
    if param.attrs & models.BINDING_ATTRIBUTES:
        return False
    if (
        re.fullmatch(r"I[A-Z]\w*", type_name)
        and type_name not in models.INPUT_INTERFACES
    ):
        return True
    return type_name.endswith(models.SERVICE_TYPE_SUFFIXES) or (
        type_name.endswith("Context") and type_name != "Context"
    )


def _source_params(scope: _Scope) -> set[str]:
    sources: set[str] = set()
    for param in scope.params:
        if param.type in models.SCALAR_TYPES or _param_is_service(param):
            continue
        if scope.entry or param.attrs & models.BINDING_ATTRIBUTES:
            sources.add(param.name)
    return sources


def _scan_scope(
    context: _FileContext,
    index: int,
    scope: _Scope,
    extra: dict[str, set[str]],
    collector: _Collector,
    calls: list[tuple[int, str, str]],
) -> None:
    body = scope.body
    masked_body = mask_comments_and_strings(body)
    sources = _source_params(scope)
    if scope.kind == "file":
        sources = {"args"}
    bound = set()
    if (
        scope.owner is not None
        and scope.kind in {"method", "local", "lambda"}
        and "static" not in scope.mods
    ):
        bound = set(scope.owner.bound_properties)
    param_names = {param.name for param in scope.params}
    state = _ScopeState(
        tainted_vars={
            key: sources | bound | extra.get(key, set()) for key in models.TAINT_KEYS
        },
        path_type_shadowed=context.path_type_shadowed,
        assigned_vars=set(param_names),
        param_vars={
            param.name
            for param in scope.params
            if param.type not in models.SCALAR_TYPES
        },
        request_vars={
            param.name
            for param in scope.params
            if param.type in models.REQUEST_OBJECT_TYPES
        },
        types={param.name: {param.type} for param in scope.params},
        ef6=context.ef6,
        response_types=_response_types(body, masked_body, scope, context),
        proof_types={param.name: {param.raw_type} for param in scope.params},
    )
    guard_candidates = _redirect_guards(masked_body)
    initializer_end = -1
    for offset, statement in _iter_statements(body):
        guards = [
            (name, start, end)
            for name, start, end, receiver in guard_candidates
            if _is_url_helper(receiver, state, scope, context)
        ]
        opening_initializer = False
        for rule, position in _findings_for_sinks(
            statement, state, scope, context, guards, offset
        ):
            collector.add(
                rule, scope.start_line + body.count("\n", 0, offset + position)
            )
        _record_calls(statement, state, scope, context, guards, offset, calls, index)
        if statement.endswith("{"):
            open_brace = masked_body.find("{", offset)
            if open_brace >= 0:
                initializer_type = _object_initializer_type(statement)
                if initializer_type:
                    close_brace = matching_brace(masked_body, open_brace)
                    if close_brace >= 0:
                        opening_initializer = True
                        initializer_end = close_brace
                        for rule, property_offset in _object_initializer_findings(
                            body,
                            masked_body,
                            open_brace,
                            close_brace,
                            initializer_type,
                            state,
                        ):
                            collector.add(
                                rule,
                                scope.start_line + body.count("\n", 0, property_offset),
                            )
        if opening_initializer or offset >= initializer_end:
            _handle_assignment(statement, state, scope, context)


def _object_initializer_type(statement: str) -> str | None:
    code = _masked_code(statement)
    explicit = _OBJECT_INIT_RE.search(code)
    if explicit:
        return explicit.group("type")
    if _TARGET_TYPED_INIT_RE.search(code):
        assignment = _ASSIGN_RE.search(code)
        if assignment:
            declared = assignment.group("decl_type")
            if declared == "ProcessStartInfo" or (
                declared and _SQL_COMMAND_TYPE_RE.fullmatch(declared)
            ):
                return declared
    return None


def _object_initializer_findings(
    body: str,
    masked_body: str,
    open_brace: int,
    close_brace: int,
    initializer_type: str,
    state: _ScopeState,
) -> list[tuple[Rule, int]]:
    inner_start = open_brace + 1
    code = masked_body[inner_start:close_brace]
    spans: list[tuple[int, int]] = []
    start = 0
    depth = 0
    for index, char in enumerate(code):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            spans.append((start, index))
            start = index + 1
    spans.append((start, len(code)))

    is_process = initializer_type == "ProcessStartInfo"
    if is_process:
        property_pattern = r"\s*(?P<name>FileName|Arguments)\s*=(?!=)\s*"
    else:
        property_pattern = r"\s*(?P<name>CommandText)\s*=(?!=)\s*"
    matches: list[tuple[Rule, int]] = []
    for start, end in spans:
        match = re.match(property_pattern, code[start:end])
        if not match:
            continue
        rhs = body[inner_start + start + match.end() : inner_start + end]
        position = inner_start + start + match.start("name")
        if is_process:
            if _is_tainted(
                rhs, state.tainted_vars[models.COMMAND.rule_id], state.request_vars
            ):
                matches.append((models.COMMAND, position))
        else:
            rule = _sql_rule(rhs, state)
            if rule is not None:
                matches.append((rule, position))
    return matches


def _handle_assignment(
    statement: str, state: _ScopeState, scope: _Scope, context: _FileContext
) -> None:
    code = _masked_code(statement)
    _invalidate_basename_writes(code, state.basename_vars)
    if _handle_compound_assignment(statement, code, state):
        return
    if _handle_builder_append(statement, code, state):
        return
    if _handle_foreach(statement, code, state):
        return
    match = _ASSIGN_RE.search(code)
    if not match:
        return
    lhs = match.group("lhs").lstrip("@")
    if lhs.endswith(
        (
            ".CommandText",
            ".FileName",
            ".Arguments",
            ".BaseAddress",
            ".RequestUri",
            ".Location",
        )
    ):
        return

    name = lhs.rsplit(".", 1)[-1]
    rhs = re.sub(r"^\s*=\s*|\s*;?\s*$", "", statement[match.end("lhs") :])
    rhs_code = _masked_code(rhs)
    if name not in state.assigned_vars and _is_basename_call(
        rhs,
        state.tainted_vars[models.PATH.rule_id],
        state.path_type_shadowed,
        state.request_vars,
    ):
        state.basename_vars.add(name)
    else:
        state.basename_vars.discard(name)
    state.assigned_vars.add(name)
    declared_type = match.group("decl_type")
    _track_typed_variable(
        name, rhs_code, "ProcessStartInfo", state.process_info_vars, declared_type
    )
    _track_typed_variable(
        name, rhs_code, _SQL_COMMAND_TYPE_RE, state.sql_command_vars, declared_type
    )
    _track_types(name, rhs_code, declared_type, state)
    if "." not in lhs:
        _track_proof_types(name, rhs_code, declared_type, state, scope, context)
    if re.fullmatch(
        r"\s*(?:\(\s*)?(?:[\w.]+\s*\??\.\s*)?Request\s*\)?\s*;?\s*", rhs_code
    ):
        state.request_vars.add(name)
    scalar = bool(
        declared_type and _simple_type(declared_type) in models.SCALAR_TYPES
    ) or bool(models.SCALAR_CONVERSION_RE.match(rhs_code))
    if not scalar:
        for key, tainted_vars in state.tainted_vars.items():
            if _carries_taint(rhs, tainted_vars, state.request_vars, key):
                tainted_vars.add(name)
        if _mentions_as_text(rhs, state.param_vars):
            state.param_vars.add(name)
    if not scalar and (
        (_is_string_built(rhs) and _mentions_as_text(rhs, state.param_vars))
        or _mentions(rhs, state.built_vars)
    ):
        state.built_vars.add(name)
    else:
        state.built_vars.discard(name)


def _handle_compound_assignment(statement: str, code: str, state: _ScopeState) -> bool:
    match = _COMPOUND_ASSIGN_RE.match(code)
    if not match:
        return False
    name = match.group("lhs").lstrip("@")
    rhs = statement[match.start("rhs") : match.end("rhs")]
    for key, tainted_vars in state.tainted_vars.items():
        if _carries_taint(rhs, tainted_vars, state.request_vars, key):
            tainted_vars.add(name)
    if _mentions_as_text(rhs, state.param_vars):
        state.param_vars.add(name)
        state.built_vars.add(name)
    return True


def _handle_builder_append(statement: str, code: str, state: _ScopeState) -> bool:
    match = _BUILDER_APPEND_RE.match(code)
    if not match:
        return False
    owner = match.group("owner").lstrip("@")
    rest = statement[match.end() - 1 :]
    for key, tainted_vars in state.tainted_vars.items():
        if _carries_taint(rest, tainted_vars, state.request_vars, key):
            tainted_vars.add(owner)
    if _mentions_as_text(rest, state.param_vars):
        state.param_vars.add(owner)
        state.built_vars.add(owner)
    return True


def _handle_foreach(statement: str, code: str, state: _ScopeState) -> bool:
    match = _FOREACH_RE.match(code)
    if not match:
        return False
    name = match.group("name")
    source = statement[match.start("source") : match.end("source")]
    for key, tainted_vars in state.tainted_vars.items():
        if _carries_taint(source, tainted_vars, state.request_vars, key):
            tainted_vars.add(name)
    return True


def _carries_taint(
    rhs: str, tainted_vars: set[str], request_vars: set[str], key: str
) -> bool:
    if key == models.XSS_KEY:
        rhs = _without_encoder_calls(rhs)
    return _is_tainted(rhs, tainted_vars, request_vars)


def _track_types(
    name: str, rhs: str, declared_type: str | None, state: _ScopeState
) -> None:
    types: set[str] = set()
    if declared_type and declared_type not in {"var", "dynamic", "using", "await"}:
        types.add(_simple_type(declared_type))
    created = re.match(r"\s*(?:await\s+)?new\s+(?P<type>[A-Za-z_][\w.]*)", rhs)
    if created:
        types.add(_simple_type(created.group("type")))
    if re.search(r"\.\s*CreateClient\s*\(", rhs) or re.match(
        r"\s*HttpClientFactory\s*\.\s*Create\s*\(", rhs
    ):
        types.add("HttpClient")
    if models.CONNECTION_FACTORY_RE.search(rhs):
        types.add("IDbConnection")
    if types:
        state.types[name] = types


def _invalidate_basename_writes(code: str, basename_vars: set[str]) -> None:
    """A mutable local stops proving containment after any observed write."""
    for name in set(basename_vars):
        escaped = re.escape(name)
        if re.search(
            rf"\b@?{escaped}\s*(?:\+\+|--|\?\?=|[+*/%&|^-]=|=(?!=))"
            rf"|\b(?:ref|out)\s+@?{escaped}\b",
            code,
        ):
            basename_vars.discard(name)


def _track_typed_variable(
    name: str,
    rhs: str,
    type_hint: str | re.Pattern[str],
    tracked: set[str],
    declared_type: str | None,
) -> None:
    if isinstance(type_hint, str):
        matched = type_hint in rhs
    else:
        matched = bool(type_hint.search(rhs))
    if declared_type and re.match(r"\s*new\s*\(", rhs):
        if isinstance(type_hint, str):
            matched |= declared_type == type_hint
        else:
            matched |= bool(type_hint.fullmatch(declared_type))
    if matched:
        tracked.add(name)
    else:
        tracked.discard(name)


def _findings_for_sinks(
    statement: str,
    state: _ScopeState,
    scope: _Scope,
    context: _FileContext,
    guards: list[tuple[str, int, int]],
    offset: int,
) -> list[tuple[Rule, int]]:
    code = _masked_code(statement)
    findings: list[tuple[Rule, int]] = []
    findings.extend(_command_sinks(statement, code, state))
    findings.extend(_path_sinks(statement, state))
    findings.extend(_ssrf_sinks(statement, code, state, scope, context))
    findings.extend(_sql_sinks(statement, code, state, scope, context))
    findings.extend(_redirect_sinks(statement, code, state, guards, offset))
    findings.extend(_deserialization_sinks(statement, code, state, scope, context))
    findings.extend(_type_name_handling_sinks(statement, code, state, scope, context))
    findings.extend(_xss_sinks(statement, code, state, offset))
    return findings


def _command_sinks(
    statement: str, code: str, state: _ScopeState
) -> list[tuple[Rule, int]]:
    tainted = state.tainted_vars[models.COMMAND.rule_id]
    findings = []
    for match, args in _call_arguments(statement, _COMMAND_SINK_RE):
        if any(_is_tainted(arg, tainted, state.request_vars) for arg in args):
            findings.append((models.COMMAND, match.start()))
    for match in _COMMAND_PROPERTY_RE.finditer(code):
        if match.group("owner").lstrip("@") in state.process_info_vars and _is_tainted(
            statement[match.end() :], tainted, state.request_vars
        ):
            findings.append((models.COMMAND, match.start()))
    for match in _START_INFO_PROPERTY_RE.finditer(code):
        if _is_tainted(statement[match.end() :], tainted, state.request_vars):
            findings.append((models.COMMAND, match.start()))
    return findings


def _path_sinks(statement: str, state: _ScopeState) -> list[tuple[Rule, int]]:
    tainted = state.tainted_vars[models.PATH.rule_id]
    findings = []
    for match, args in _call_arguments(statement, _PATH_SINK_RE):
        relevant = args[:1]
        if re.search(r"\b(?:Copy|Move|Replace)\s*\($", match.group()):
            relevant = args[:2]
        if any(
            _is_tainted(arg, tainted, state.request_vars)
            and not (
                match.group().startswith("File.")
                and _is_contained_basename_path(arg, state)
            )
            for arg in relevant
        ):
            findings.append((models.PATH, match.start()))
    for match, args in _call_arguments(statement, _PATH_CONSTRUCTOR_RE):
        if not args:
            continue
        arg = args[0]
        if match.group("type") in {"StreamReader", "StreamWriter"} and (
            _STREAM_ARGUMENT_RE.search(_masked_code(arg))
            or any(
                "Stream" in type_name
                for type_name in state.types.get(_masked_code(arg).strip(), ())
            )
        ):
            continue
        if _is_tainted(arg, tainted, state.request_vars) and not (
            _is_contained_basename_path(arg, state)
        ):
            findings.append((models.PATH, match.start()))
    for match, args in _call_arguments(statement, _PHYSICAL_FILE_RE):
        if (
            args
            and _is_tainted(args[0], tainted, state.request_vars)
            and not (_is_contained_basename_path(args[0], state))
        ):
            findings.append((models.PATH, match.start()))
    return findings


def _ssrf_sinks(
    statement: str,
    code: str,
    state: _ScopeState,
    scope: _Scope,
    context: _FileContext,
) -> list[tuple[Rule, int]]:
    findings = []
    for match in _RECEIVER_METHOD_RE.finditer(code):
        method = match.group("method")
        if method in models.HTTP_CLIENT_URL_METHODS:
            allowed = models.HTTP_CLIENT_TYPES
        elif method in models.WEB_CLIENT_URL_METHODS:
            allowed = models.WEB_CLIENT_TYPES
        else:
            continue
        receiver = _receiver_before(code, match.start())
        if not _receiver_types(receiver, state, scope, context) & allowed:
            continue
        args = _arguments_at(statement, code, match.end() - 1)
        if args and _url_tainted(args[0], state, models.SSRF.rule_id):
            findings.append((models.SSRF, match.start()))
    for match, args in _call_arguments(statement, _STATIC_SSRF_RE):
        if args and _url_tainted(args[0], state, models.SSRF.rule_id):
            findings.append((models.SSRF, match.start()))
    for match, args in _call_arguments(statement, _SSRF_CONSTRUCTOR_RE):
        position = 0
        if match.group("type") == "HttpRequestMessage":
            position = 1
        if len(args) > position and _url_tainted(
            args[position], state, models.SSRF.rule_id
        ):
            findings.append((models.SSRF, match.start()))
    for match in _BASE_ADDRESS_RE.finditer(code):
        receiver = _receiver_before(code, match.start())
        types = _receiver_types(receiver, state, scope, context)
        if types & (
            models.HTTP_CLIENT_TYPES | models.WEB_CLIENT_TYPES | {"HttpRequestMessage"}
        ) and _url_tainted(statement[match.end() :], state, models.SSRF.rule_id):
            findings.append((models.SSRF, match.start()))
    return findings


def _sql_sinks(
    statement: str,
    code: str,
    state: _ScopeState,
    scope: _Scope,
    context: _FileContext,
) -> list[tuple[Rule, int]]:
    findings = []
    for match, args in _call_arguments(statement, _SQL_CONSTRUCTOR_RE):
        rule = _sql_rule(_first_argument(args), state)
        if rule is not None:
            findings.append((rule, match.start()))
    for match, args in _call_arguments(statement, _EF_SQL_RE):
        method = match.group("method")
        arg = _first_argument(args)
        if method in models.EF_FORMATTABLE_SQL_METHODS and _is_interpolated_literal(
            arg
        ):
            if not (state.ef6 and method in models.EF6_STRING_SQL_METHODS):
                continue
        rule = _sql_rule(arg, state)
        if rule is not None:
            findings.append((rule, match.start()))
    for match in _RECEIVER_METHOD_RE.finditer(code):
        if match.group("method") not in models.DAPPER_METHODS:
            continue
        receiver = _receiver_before(code, match.start())
        if not _receiver_types(receiver, state, scope, context) & (
            models.DB_CONNECTION_TYPES
        ):
            continue
        args = _arguments_at(statement, code, match.end() - 1)
        rule = _sql_rule(_first_argument(args), state)
        if rule is not None:
            findings.append((rule, match.start()))
    for match in _COMMAND_TEXT_RE.finditer(code):
        owner = match.group("owner").lstrip("@")
        if owner in state.sql_command_vars or state.types.get(owner, set()) & (
            models.SQL_COMMAND_TYPES
        ):
            rule = _sql_rule(statement[match.end() :], state)
            if rule is not None:
                findings.append((rule, match.start()))
    return findings


def _sql_rule(arg: str, state: _ScopeState) -> Rule | None:
    if not arg.strip():
        return None
    if _is_tainted(arg, state.tainted_vars[models.SQL.rule_id], state.request_vars):
        return models.SQL
    if (
        _is_string_built(arg) and _mentions_as_text(arg, state.param_vars)
    ) or _mentions(arg, state.built_vars):
        return models.SQL_BUILT
    return None


def _redirect_sinks(
    statement: str,
    code: str,
    state: _ScopeState,
    guards: list[tuple[str, int, int]],
    offset: int,
) -> list[tuple[Rule, int]]:
    findings = []
    for match, args in _call_arguments(statement, _REDIRECT_RE):
        if args and _redirect_tainted(args[0], state, guards, offset + match.start()):
            findings.append((models.REDIRECT, match.start()))
    for regex, source_text in (
        (_LOCATION_PROPERTY_RE, code),
        (_LOCATION_INDEX_RE, statement),
    ):
        for match in regex.finditer(source_text):
            if _redirect_tainted(
                statement[match.end() :], state, guards, offset + match.start()
            ):
                findings.append((models.REDIRECT, match.start()))
    for match, args in _call_arguments(statement, _LOCATION_CALL_RE):
        if (
            len(args) >= 2
            and re.fullmatch(r'\s*"Location"\s*', args[0], re.I)
            and _redirect_tainted(args[1], state, guards, offset + match.start())
        ):
            findings.append((models.REDIRECT, match.start()))
    return findings


def _deserialization_sinks(
    statement: str,
    code: str,
    state: _ScopeState,
    scope: _Scope,
    context: _FileContext,
) -> list[tuple[Rule, int]]:
    findings = []
    for match in _RECEIVER_METHOD_RE.finditer(code):
        method = match.group("method")
        if method in models.UNSAFE_FORMATTER_METHODS:
            allowed = models.UNSAFE_FORMATTER_TYPES
        elif method == "ReadObject":
            allowed = frozenset({"NetDataContractSerializer"})
        else:
            continue
        receiver = _receiver_before(code, match.start())
        if not _formatter_receiver_types(receiver, state, scope, context) & allowed:
            continue
        args = _arguments_at(statement, code, match.end() - 1)
        if not args or not args[0].strip():
            continue
        if _is_tainted(
            args[0], state.tainted_vars[models.DESERIALIZE.rule_id], state.request_vars
        ):
            findings.append((models.DESERIALIZE_REQUEST, match.start()))
        else:
            findings.append((models.DESERIALIZE, match.start()))
    return findings


_FORMATTER_PROVIDERS = frozenset(
    {
        "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
        "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
        "System.Runtime.Serialization.NetDataContractSerializer",
        "System.Web.UI.LosFormatter",
        "System.Web.UI.ObjectStateFormatter",
    }
)
_JSON_SETTINGS_PROVIDERS = frozenset(
    {"Newtonsoft.Json.JsonSerializerSettings", "Newtonsoft.Json.JsonSerializer"}
)
_TYPE_NAME_HANDLING_PROVIDER = frozenset({"Newtonsoft.Json.TypeNameHandling"})


def _formatter_receiver_types(receiver, state, scope, context):
    created = re.fullmatch(
        rf"new\s+(?P<type>{_PROVIDER_TYPE_TEXT})\s*\([\s\S]*\)", receiver.strip()
    )
    types = (
        {created.group("type")}
        if created
        else _proof_receiver_types(receiver, state, scope)
    )
    if not types:
        types = _receiver_types(receiver, state, scope, context)
    return {
        _expanded_type(name, context).rsplit(".", 1)[-1]
        for name in types
        if _provider_type(name, context, _FORMATTER_PROVIDERS)
    }


def _json_settings_type(name, context):
    pending = [name]
    seen = set()
    while pending:
        current = pending.pop()
        expanded = _expanded_type(current, context)
        if expanded in seen:
            continue
        seen.add(expanded)
        if _provider_type(current, context, _JSON_SETTINGS_PROVIDERS):
            return True
        info = context.classes_by_name.get(expanded.rsplit(".", 1)[-1])
        if info is not None and "TypeNameHandling" not in info.member_types:
            pending.extend(info.raw_bases)
    return False


def _type_name_handling_rule(match, context, block):
    enum = match.group("enum") or match.group("number_type")
    if not _provider_type(enum, context, _TYPE_NAME_HANDLING_PROVIDER):
        return None
    if match.group("value") == "None" or (
        match.group("number") is not None and int(match.group("number")) == 0
    ):
        return None
    return (
        models.TYPE_NAME_HANDLING_BOUND
        if _BINDER_RE.search(block)
        else models.TYPE_NAME_HANDLING
    )


def _type_name_handling_sinks(statement, code, state, scope, context):
    findings = []
    for match in _TYPE_NAME_HANDLING_RE.finditer(code):
        prefix = code[: match.start()].rstrip()
        if not prefix.endswith("."):
            continue
        receiver = _receiver_before(code, len(prefix) - 1)
        if not any(
            _json_settings_type(name, context)
            for name in _proof_receiver_types(receiver, state, scope)
        ):
            continue
        rule = _type_name_handling_rule(match, context, code)
        if rule:
            findings.append((rule, match.start()))
    return findings


def _xss_sinks(
    statement: str, code: str, state: _ScopeState, offset: int
) -> list[tuple[Rule, int]]:
    tainted = state.tainted_vars[models.XSS_KEY]
    findings = []
    for regex in (_HTML_STRING_RE, _HTML_RAW_RE):
        for match, args in _call_arguments(statement, regex):
            if args and _xss_tainted(args[0], tainted, state):
                findings.append((models.XSS_TRUSTED, match.start()))
    for match in _MARKUP_CAST_RE.finditer(code):
        operand = _cast_operand(statement, code, match.end())
        if _xss_tainted(operand, tainted, state):
            findings.append((models.XSS_TRUSTED, match.start()))
    for match, args in _call_arguments(statement, _CONTENT_RE):
        if (
            len(args) >= 2
            and re.search(r"text/html", args[1], re.I)
            and _xss_tainted(args[0], tainted, state)
        ):
            findings.append((models.XSS_RESPONSE, match.start()))
    for match, args in _call_arguments(statement, _RESPONSE_WRITE_RE):
        if (
            args
            and not _non_html_response_at(
                state.response_types.get(_compact_name(match.group("receiver")), []),
                offset + match.start(),
            )
            and _xss_tainted(args[0], tainted, state)
        ):
            findings.append((models.XSS_RESPONSE, match.start()))
    return findings


def _xss_tainted(expr: str, tainted: set[str], state: _ScopeState) -> bool:
    return _is_tainted(_without_encoder_calls(expr), tainted, state.request_vars)


def _cast_operand(statement: str, code: str, start: int) -> str:
    depth = 0
    for index in range(start, len(code)):
        char = code[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return statement[start:index]
            depth -= 1
        elif char in ",;?:" and depth == 0:
            return statement[start:index]
    return statement[start:]


def _without_encoder_calls(expr: str) -> str:
    code = _masked_code(expr)
    pieces = []
    cursor = 0
    for match in models.ENCODER_CALL_RE.finditer(code):
        if match.start() < cursor:
            continue
        close = _matching_paren(code, match.end() - 1)
        if close < 0:
            continue
        pieces.append(expr[cursor : match.start()])
        pieces.append(" " * (close + 1 - match.start()))
        cursor = close + 1
    pieces.append(expr[cursor:])
    return "".join(pieces)


def _record_calls(
    statement: str,
    state: _ScopeState,
    scope: _Scope,
    context: _FileContext,
    guards: list[tuple[str, int, int]],
    offset: int,
    calls: list[tuple[int, str, str]],
    caller: int,
) -> None:
    code = _masked_code(statement)
    for match in _CALL_NAME_RE.finditer(code):
        name = match.group("name")
        if name not in context.callable_names:
            continue
        before = code[: match.start()].rstrip()
        callees: list[int] = []
        if re.search(r"(?<![\w.])new$", before):
            callees = context.constructors_by_class.get(name, [])
        elif before.endswith("."):
            receiver = _receiver_before(code, len(before) - 1)
            callees = _resolve_member_call(name, receiver, state, scope, context)
        else:
            callees = context.methods_by_class.get(_owner_name(scope), {}).get(name, [])
        if not callees:
            continue
        args = _arguments_at(statement, code, match.end() - 1)
        if args == [""]:
            args = []
        position = offset + match.start()
        for callee in callees:
            if callee == caller:
                continue
            params = context.scopes[callee].params
            if not _arity_matches(params, len(args)):
                continue
            for arg_index, arg in enumerate(args):
                param = params[min(arg_index, len(params) - 1)]
                for key, tainted in state.tainted_vars.items():
                    if key == models.REDIRECT.rule_id:
                        carried = _redirect_tainted(arg, state, guards, position)
                    elif key == models.XSS_KEY:
                        carried = _xss_tainted(arg, tainted, state)
                    else:
                        carried = _is_tainted(arg, tainted, state.request_vars)
                    if carried:
                        calls.append((callee, key, param.name))


def _resolve_member_call(
    name: str,
    receiver: str,
    state: _ScopeState,
    scope: _Scope,
    context: _FileContext,
) -> list[int]:
    stripped = receiver.strip()
    if stripped in {"this", "base"}:
        return context.methods_by_class.get(_owner_name(scope), {}).get(name, [])
    callees: list[int] = []
    for type_name in _receiver_types(receiver, state, scope, context):
        if type_name in context.classes_by_name:
            callees.extend(context.methods_by_class.get(type_name, {}).get(name, []))
    return callees


def _owner_name(scope: _Scope) -> str | None:
    if scope.owner is None:
        return None
    return scope.owner.name


def _first_argument(args: list[str]) -> str:
    if args:
        return args[0]
    return ""


def _arity_matches(params: tuple[_Param, ...], count: int) -> bool:
    required = sum(1 for param in params if not param.optional and not param.variadic)
    if count < required:
        return False
    if params and params[-1].variadic:
        return True
    return count <= len(params)


def _receiver_before(code: str, dot: int) -> str:
    index = dot - 1
    if index >= 0 and code[index] == "?":
        index -= 1
    while index >= 0 and code[index].isspace():
        index -= 1
    end = index + 1
    while index >= 0:
        char = code[index]
        if char == ")":
            depth = 0
            while index >= 0:
                if code[index] == ")":
                    depth += 1
                elif code[index] == "(":
                    depth -= 1
                    if depth == 0:
                        break
                index -= 1
            index -= 1
            while index >= 0 and code[index].isspace():
                index -= 1
            continue
        if char == ">":
            depth = 0
            while index >= 0:
                if code[index] == ">":
                    depth += 1
                elif code[index] == "<":
                    depth -= 1
                    if depth == 0:
                        break
                index -= 1
            index -= 1
            continue
        if char.isalnum() or char in "_@":
            index -= 1
            continue
        if char == ".":
            index -= 1
            while index >= 0 and code[index].isspace():
                index -= 1
            if index >= 0 and code[index] == "?":
                index -= 1
            continue
        break
    start = index + 1
    text = code[start:end].strip()
    prefix = code[:start].rstrip()
    if re.search(r"(?<![\w.])new$", prefix):
        text = "new " + text
    return text


def _receiver_types(
    receiver: str, state: _ScopeState, scope: _Scope, context: _FileContext
) -> set[str]:
    text = re.sub(r"\s+", " ", receiver.strip())
    if text.startswith("this."):
        text = text[5:].strip()
    created = re.fullmatch(r"new (?P<type>[A-Za-z_][\w.]*)\s*(?:<.*>)?\s*\(.*\)", text)
    if created:
        return {_simple_type(created.group("type"))}
    if re.search(r"\.\s*CreateClient\s*\(.*\)$", text) or re.fullmatch(
        r"HttpClientFactory\s*\.\s*Create\s*\(.*\)", text
    ):
        return {"HttpClient"}
    if re.search(r"\b(?:GetDbConnection|Create\w*Connection)\s*\(.*\)$", text):
        return {"IDbConnection"}
    if not re.fullmatch(r"@?[A-Za-z_]\w*", text):
        return set()
    name = text.lstrip("@")
    if name in state.types:
        return set(state.types[name])
    owner = scope.owner
    while owner is not None:
        if name in owner.member_types:
            return set(owner.member_types[name])
        owner = _owner_at(context.classes, owner.open - 1)
    if name[:1].isupper():
        return {name}
    return set()


def _redirect_tainted(
    arg: str, state: _ScopeState, guards: list[tuple[str, int, int]], position: int
) -> bool:
    tainted = state.tainted_vars[models.REDIRECT.rule_id]
    if not _url_tainted(arg, state, models.REDIRECT.rule_id):
        return False
    code = _masked_code(arg)
    if models.SOURCE_HINT_RE.search(code) or _uses_request_var(
        code, state.request_vars
    ):
        return True
    names = [name for name in tainted if _name_pattern((name,)).search(code)]
    return any(
        not any(
            guard_name == name and start <= position < end
            for guard_name, start, end in guards
        )
        for name in names
    )


def _url_tainted(arg: str, state: _ScopeState, key: str) -> bool:
    tainted = state.tainted_vars[key]
    if not _is_tainted(arg, tainted, state.request_vars):
        return False
    return not _has_fixed_prefix(
        arg, lambda part: _is_tainted(part, tainted, state.request_vars)
    )


def _has_fixed_prefix(expr: str, is_tainted) -> bool:
    """CodeQL's fixed-host barrier: text before the first tainted part already
    chooses the host or path (``https://api.example.com/``, ``/orders/``,
    ``users/``, anything after ``?`` or ``#``)."""
    text = expr.strip()
    code = _masked_code(text)
    wrapper = re.match(
        r"(?:new\s+(?:System\s*\.\s*)?Uri|(?:string|String)\s*\.\s*Format)\s*\(", code
    )
    if wrapper:
        close = _matching_paren(code, wrapper.end() - 1)
        if close < 0:
            return False
        args = _split_arguments(text, code, wrapper.end(), close)
        if not args:
            return False
        text = args[0].strip()
    prefix: list[str] = []
    for kind, value in _url_segments(text):
        if kind == "expr" and is_tainted(value):
            break
        if kind == "lit":
            prefix.append(value)
        else:
            prefix.append("x")
    else:
        return False
    literal = "".join(prefix)
    if literal.startswith("~"):
        literal = literal[1:]
    if "?" in literal or "#" in literal:
        return True
    return bool(re.search(r"[^?#:/\\][/\\]", literal))


def _url_segments(text: str) -> list[tuple[str, str]]:
    code = _masked_code(text)
    segments: list[tuple[str, str]] = []
    depth = 0
    start = 0
    parts: list[tuple[int, int]] = []
    for index, char in enumerate(code):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "+" and depth == 0:
            parts.append((start, index))
            start = index + 1
    parts.append((start, len(code)))
    for part_start, part_end in parts:
        raw = text[part_start:part_end].strip()
        literal = _literal_segments(raw)
        if literal is None:
            segments.append(("expr", raw))
        else:
            segments.extend(literal)
    return segments


def _literal_segments(raw: str) -> list[tuple[str, str]] | None:
    match = re.match(r'(?P<prefix>\$@|@\$|\$|@)?"', raw)
    if not match or raw.startswith('"""') or raw[match.end() :].startswith('""'):
        return None
    prefix = match.group("prefix") or ""
    verbatim = "@" in prefix
    interpolated = "$" in prefix
    segments: list[tuple[str, str]] = []
    buffer: list[str] = []
    index = match.end()
    while index < len(raw):
        char = raw[index]
        if verbatim and raw.startswith('""', index):
            buffer.append('"')
            index += 2
            continue
        if not verbatim and char == "\\":
            buffer.append(raw[index : index + 2])
            index += 2
            continue
        if char == '"':
            break
        if interpolated and raw.startswith("{{", index):
            buffer.append("{")
            index += 2
            continue
        if interpolated and raw.startswith("}}", index):
            buffer.append("}")
            index += 2
            continue
        if interpolated and char == "{":
            segments.append(("lit", "".join(buffer)))
            buffer = []
            depth = 1
            hole_start = index + 1
            index += 1
            while index < len(raw) and depth:
                if raw[index] == "{":
                    depth += 1
                elif raw[index] == "}":
                    depth -= 1
                index += 1
            segments.append(("expr", raw[hole_start : index - 1]))
            continue
        buffer.append(char)
        index += 1
    segments.append(("lit", "".join(buffer)))
    return segments


def _redirect_guards(masked_body: str) -> list[tuple[str, int, int, str]]:
    """Ranges where an ``IsLocalUrl(x)`` call has returned true for ``x``.

    The receiver is kept so the caller can accept only the framework helper.
    """
    guards: list[tuple[str, int, int, str]] = []
    for match in _LOCAL_URL_GUARD_RE.finditer(masked_body):
        call = (match.start(), match.end())
        spans = _ternary_guard_spans(masked_body, call)
        if not spans:
            spans = _if_guard_spans(masked_body, call)
        for start, end in spans:
            guards.append((match.group("var"), start, end, match.group("receiver")))
    return guards


def _is_url_helper(
    receiver: str, state: _ScopeState, scope: _Scope, context: _FileContext
) -> bool:
    types = _proof_receiver_types(receiver, state, scope)
    if types:
        return all(_provider_type(item, context, _URL_PROVIDER_TYPES) for item in types)
    text = _compact_name(receiver)
    if text not in {"Url", "this.Url", "base.Url"}:
        return False
    if text == "Url" and "Url" in _local_names(scope):
        return False
    return "Url" not in context.classes_by_name


_URL_PROVIDER_TYPES = frozenset(
    {
        "System.Web.Mvc.UrlHelper",
        "Microsoft.AspNetCore.Mvc.IUrlHelper",
        "Microsoft.AspNetCore.Mvc.Routing.UrlHelper",
    }
)
_URL_FACTORY_TYPES = frozenset(
    {
        "Microsoft.AspNetCore.Mvc.Routing.IUrlHelperFactory",
        "Microsoft.AspNetCore.Mvc.Routing.UrlHelperFactory",
    }
)


def _compact_name(text: str) -> str:
    return re.sub(r"\s+", "", text).replace("@", "")


def _expanded_type(text: str, context: _FileContext) -> str:
    text = _compact_name(text).removesuffix("?")
    if text.startswith("global::"):
        return text.removeprefix("global::")
    seen = set()
    while text:
        first, dot, rest = text.partition(".")
        if first not in context.type_aliases or first in seen:
            break
        seen.add(first)
        text = context.type_aliases[first] + dot + rest
        if text.startswith("global::"):
            return text.removeprefix("global::")
    return text


def _provider_type(text: str, context: _FileContext, providers: frozenset[str]) -> bool:
    text = _expanded_type(text, context)
    if text in context.project_types:
        return False
    if "." in text:
        return text in providers
    return text not in context.classes_by_name and text in {
        item.rsplit(".", 1)[-1] for item in providers
    }


def _proof_receiver_types(receiver: str, state: _ScopeState, scope: _Scope) -> set[str]:
    text = _compact_name(receiver)
    if text.startswith("base."):
        return set()
    explicit = text.startswith("this.")
    name = text.removeprefix("this.")
    if not explicit and name in state.proof_types:
        return state.proof_types[name]
    if scope.owner is not None:
        return scope.owner.proof_types.get(name, set())
    return set()


def _track_proof_types(name, rhs, declared_type, state, scope, context) -> None:
    types = set()
    if not declared_type:
        types |= _proof_receiver_types(name, state, scope)
    if declared_type and declared_type not in {"var", "dynamic", "using", "await"}:
        types.add(declared_type)
    created = re.match(rf"\s*new\s+(?P<type>{_PROVIDER_TYPE_TEXT})", rhs)
    if created:
        types.add(created.group("type"))
    expression = rhs.strip().rstrip(";").strip()
    if re.fullmatch(r"(?:this\s*\.\s*|base\s*\.\s*)?@?[A-Za-z_]\w*", expression):
        types |= _proof_receiver_types(expression, state, scope)
        if _is_url_helper(expression, state, scope, context):
            types.add("Microsoft.AspNetCore.Mvc.IUrlHelper")
    factory = re.fullmatch(
        r"\s*(?P<receiver>(?:this\s*\.\s*)?@?[A-Za-z_]\w*)\s*\.\s*"
        r"GetUrlHelper\s*\([\s\S]*\)\s*;?\s*",
        rhs,
    )
    if factory:
        owners = _proof_receiver_types(factory.group("receiver"), state, scope)
        if owners and all(
            _provider_type(item, context, _URL_FACTORY_TYPES) for item in owners
        ):
            types.add("Microsoft.AspNetCore.Mvc.IUrlHelper")
    # Unknown or conflicting writes cannot establish a safety proof. Retaining
    # every possible provider is conservative across this scanner's flat joins.
    state.proof_types.setdefault(name, set()).update(types or {"<unknown>"})


def _local_names(scope: _Scope) -> frozenset[str]:
    if scope.local_names is not None:
        return scope.local_names
    names = {param.name for param in scope.params}
    for match in re.finditer(
        r"(?<![\w.])(?P<type>[A-Za-z_][\w.:<>\[\]?]*)\s+"
        r"@?(?P<name>[A-Za-z_]\w*)\s*(?=[=;,])",
        mask_comments_and_strings(scope.body),
    ):
        if match.group("type") not in _STATEMENT_WORDS or match.group("type") in {
            "var",
            "dynamic",
        }:
            names.add(match.group("name"))
    scope.local_names = frozenset(names)
    return scope.local_names


def _response_receivers(
    scope: _Scope, context: _FileContext, target: str = "Response"
) -> frozenset[str]:
    if scope.owner is None:
        return frozenset()
    local = _local_names(scope)
    members = scope.owner.member_types
    receivers = {"base.Response", "System.Web.HttpContext.Current.Response"}
    if "Response" not in members:
        receivers.add("this.Response")
        if "Response" not in local:
            receivers.add("Response")
    if "HttpContext" not in members:
        receivers.add("this.HttpContext.Response")
        if "HttpContext" not in local:
            receivers.add("HttpContext.Response")
    if not _response_reference(target, receivers, context):
        receivers = set()
        for param in scope.params:
            if target == f"{param.name}.Response" and _provider_type(
                param.raw_type,
                context,
                frozenset(
                    {
                        "System.Web.HttpContext",
                        "System.Web.HttpContextBase",
                        "Microsoft.AspNetCore.Http.HttpContext",
                    }
                ),
            ):
                receivers.add(target)
    writes: dict[str, list[str]] = {}
    for _, statement in _iter_statements(scope.body):
        match = _ASSIGN_RE.search(_masked_code(statement))
        if match and "." not in match.group("lhs"):
            name = match.group("lhs").lstrip("@")
            rhs = match.group("rhs").strip().rstrip(";").strip()
            writes.setdefault(name, []).append(_compact_name(rhs))
    params = {param.name for param in scope.params}
    for _ in range(len(writes)):
        added = {
            name
            for name, values in writes.items()
            if name not in params
            and values
            and all(_response_reference(value, receivers, context) for value in values)
        }
        if added <= receivers:
            break
        receivers |= added
    return frozenset(receivers)


def _response_reference(text, receivers, context) -> bool:
    text = _compact_name(text)
    if "." not in text or text.startswith(("this.", "base.")):
        return text in receivers
    expanded = _expanded_type(text, context)
    if expanded == "System.Web.HttpContext.Current.Response" and (
        "System.Web.HttpContext" in context.project_types
    ):
        return False
    return expanded in receivers


def _ternary_guard_spans(masked: str, call: tuple[int, int]) -> list[tuple[int, int]]:
    question = _ternary_question(masked, call[1])
    start = _expression_start(masked, call[0])
    if question < 0 or start < 0:
        return []
    colon = _ternary_colon(masked, question + 1)
    polarity = _condition_polarity(masked, start, question, call)
    if colon < 0 or polarity is None:
        return []
    if polarity > 0:
        return [(question, colon)]
    return [(colon, _expression_end(masked, colon))]


def _if_guard_spans(masked: str, call: tuple[int, int]) -> list[tuple[int, int]]:
    condition = _enclosing_if(masked, call[0])
    if condition is None:
        return []
    if_start, open_paren, close_paren = condition
    polarity = _condition_polarity(masked, open_paren + 1, close_paren, call)
    statement = _parse_statement(masked, if_start, len(masked))
    if polarity is None or statement is None or statement.kind != "if":
        return []
    then = statement.parts[0]
    if polarity > 0:
        return [(then.start, then.end)]
    if not _always_exits(then) or _GOTO_RE.search(masked):
        return []
    block_start, block_end = _enclosing_block(masked, if_start)
    previous = _previous_code_char(masked, if_start)
    if masked[block_start : block_start + 1] == "{" and _opens_switch(
        masked, block_start
    ):
        if previous not in {"{", "}", ";", ":"}:
            return []
        for section in _parse_block(masked, block_start + 1, block_end):
            if section.kind == "label" and section.start >= then.end:
                return [(then.end, section.start)]
        return [(then.end, block_end)]
    if previous not in {"", "{", "}", ";"}:
        return []
    return [(then.end, block_end)]


def _condition_polarity(
    masked: str, start: int, end: int, call: tuple[int, int]
) -> int | None:
    """1 when the condition being true proves the call returned true, -1 when
    the condition being false proves it, None when neither is proven."""
    terms = _condition_terms(masked, start, end)
    if terms is None:
        return None
    operator, spans = terms
    for term_start, term_end in spans:
        if term_start <= call[0] and call[1] <= term_end:
            polarity = _call_polarity(masked, term_start, term_end, call)
            if polarity == 1 and operator != "||":
                return 1
            if polarity == -1 and operator != "&&":
                return -1
            return None
    return None


def _condition_terms(
    masked: str, start: int, end: int
) -> tuple[str, list[tuple[int, int]]] | None:
    depth = 0
    operators: set[str] = set()
    spans: list[tuple[int, int]] = []
    term_start = start
    index = start
    while index < end:
        char = masked[index]
        pair = masked[index : index + 2]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and pair in ("&&", "||"):
            operators.add(pair)
            spans.append((term_start, index))
            index += 2
            term_start = index
            continue
        elif depth == 0 and (
            pair == "=>" or (char == "?" and pair not in ("?.", "?["))
        ):
            return None
        index += 1
    spans.append((term_start, end))
    if len(operators) > 1:
        return None
    if operators:
        return operators.pop(), spans
    return "", spans


def _call_polarity(
    masked: str, start: int, end: int, call: tuple[int, int]
) -> int | None:
    while start < end and masked[start].isspace():
        start += 1
    while end > start and masked[end - 1].isspace():
        end -= 1
    if (start, end) == call:
        return 1
    if start >= end:
        return None
    suffix = _BOOL_SUFFIX_RE.search(masked, start, end)
    if suffix and suffix.start() >= call[1]:
        return _compared_polarity(
            _call_polarity(masked, start, suffix.start(), call),
            suffix.group("value"),
            suffix.group("op") == "!=" or bool(suffix.group("not")),
        )
    prefix = _BOOL_PREFIX_RE.match(masked, start, end)
    if prefix and prefix.end() <= call[0]:
        return _compared_polarity(
            _call_polarity(masked, prefix.end(), end, call),
            prefix.group("value"),
            prefix.group("op") == "!=",
        )
    if masked[start] == "!" and not masked.startswith("!=", start):
        inner = _call_polarity(masked, start + 1, end, call)
        if inner is None:
            return None
        return -inner
    if masked[start] == "(" and _matching_paren(masked, start) == end - 1:
        return _call_polarity(masked, start + 1, end - 1, call)
    return None


def _compared_polarity(polarity: int | None, value: str, negated: bool) -> int | None:
    if polarity is None:
        return None
    if (value == "false") != negated:
        return -polarity
    return polarity


def _ternary_question(masked: str, position: int) -> int:
    depth = 0
    for index in range(position, len(masked)):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return -1
            depth -= 1
        elif depth == 0 and (char in ";,:" or masked.startswith(("=>", "??"), index)):
            return -1
        elif depth == 0 and char == "?" and not masked.startswith(("?.", "?["), index):
            return index
    return -1


def _expression_start(masked: str, position: int) -> int:
    index = position - 1
    while index >= 0:
        char = masked[index]
        if char in ")]":
            index = _matching_open(masked, index) - 1
            if index < -1:
                return -1
            continue
        if char == "}":
            return -1
        if char in "([{;,:":
            return index + 1
        if char == "?":
            if "?" in (masked[index - 1 : index], masked[index + 1 : index + 2]):
                return -1
            if masked[index + 1 : index + 2] not in {".", "["}:
                return index + 1
        if char == "=":
            if masked.startswith("=>", index):
                return index + 2
            if not masked.startswith("==", index) and masked[index - 1 : index] not in {
                "=",
                "!",
                "<",
                ">",
            }:
                return index + 1
        if char.isalnum() or char == "_":
            word_end = index + 1
            while index >= 0 and (masked[index].isalnum() or masked[index] == "_"):
                index -= 1
            if masked[index + 1 : word_end] in _EXPRESSION_KEYWORDS:
                return word_end
            continue
        index -= 1
    return 0


def _matching_open(masked: str, close: int) -> int:
    depth = 0
    for index in range(close, -1, -1):
        char = masked[index]
        if char in ")]":
            depth += 1
        elif char in "([":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _enclosing_if(masked: str, position: int) -> tuple[int, int, int] | None:
    best = None
    for match in _IF_RE.finditer(masked, 0, position):
        open_paren = match.end() - 1
        close_paren = _matching_paren(masked, open_paren)
        if open_paren < position < close_paren:
            best = (match.start(), open_paren, close_paren)
    return best


def _previous_code_char(masked: str, position: int) -> str:
    index = position - 1
    while index >= 0:
        if masked[index].isspace():
            index -= 1
            continue
        line_start = masked.rfind("\n", 0, index) + 1
        if masked[line_start : index + 1].lstrip().startswith("#"):
            index = line_start - 1
            continue
        return masked[index]
    return ""


def _opens_switch(masked: str, brace: int) -> bool:
    head = masked[:brace].rstrip()
    if head.endswith(")"):
        opener = _matching_open(masked, len(head) - 1)
        if opener < 0:
            return False
        head = masked[:opener].rstrip()
    return bool(re.search(r"\bswitch$", head))


def _always_exits(statement: _Statement) -> bool:
    parts = statement.parts
    if statement.kind == "exit":
        return True
    if statement.kind == "block":
        return any(_always_exits(child) for child in parts)
    if statement.kind == "if":
        return (
            parts[1] is not None and _always_exits(parts[0]) and _always_exits(parts[1])
        )
    if statement.kind == "wrapper":
        return _always_exits(parts[0])
    if statement.kind == "try":
        return _always_exits(parts[0]) and all(
            _always_exits(handler) for handler in parts[2:]
        )
    return False


def _skip_space(masked: str, index: int, limit: int) -> int:
    while index < limit:
        if masked[index].isspace():
            index += 1
            continue
        if (
            masked[index] == "#"
            and not masked[masked.rfind("\n", 0, index) + 1 : index].strip()
        ):
            line_end = masked.find("\n", index, limit)
            if line_end < 0:
                return limit
            index = line_end
            continue
        return index
    return limit


def _parse_block(masked: str, start: int, end: int) -> list[_Statement]:
    statements: list[_Statement] = []
    index = start
    while True:
        statement = _parse_statement(masked, index, end)
        if statement is None:
            return statements
        statements.append(statement)
        index = max(statement.end, index + 1)


def _parse_statement(masked: str, index: int, limit: int) -> _Statement | None:
    """One C# statement of masked code: blocks, if/else, loops, using/lock,
    try/catch/finally, switch sections and return/throw are structured; any
    other statement ends at its top-level semicolon."""
    index = _skip_space(masked, index, limit)
    if index >= limit:
        return None
    if masked[index] == "{":
        close = matching_brace(masked, index)
        if close < 0 or close >= limit:
            return _Statement("simple", index, limit)
        return _Statement(
            "block", index, close + 1, _parse_block(masked, index + 1, close)
        )
    word = _WORD_RE.match(masked, index, limit)
    keyword = ""
    after = index
    if word:
        keyword = word.group()
        after = word.end()
    if keyword in {"if", "switch"} | _LOOP_WORDS | _WRAPPER_WORDS:
        statement = _parenthesized_statement(masked, index, keyword, after, limit)
        if statement is not None:
            return statement
    following = _skip_space(masked, after, limit)
    if keyword == "do" or (
        keyword in _BLOCK_WORDS and masked[following : following + 1] == "{"
    ):
        body = _parse_statement(masked, after, limit)
        if body is not None and keyword == "do":
            end, _ = _simple_statement_end(masked, body.end, limit)
            return _Statement("loop", index, end, [body])
        if body is not None:
            return _Statement("wrapper", index, body.end, [body])
    if keyword == "try":
        statement = _try_statement(masked, index, after, limit)
        if statement is not None:
            return statement
    if keyword == "case" or (
        keyword == "default" and masked[following : following + 1] == ":"
    ):
        colon = _label_colon(masked, after, limit)
        if colon >= 0:
            return _Statement("label", index, colon + 1)
    end, declaration = _simple_statement_end(masked, index, limit)
    if keyword in {"return", "throw"}:
        return _Statement("exit", index, end)
    if declaration:
        return _Statement("decl", index, end)
    return _Statement("simple", index, end)


def _parenthesized_statement(
    masked: str, index: int, keyword: str, after: int, limit: int
) -> _Statement | None:
    paren = _skip_space(masked, after, limit)
    if paren >= limit or masked[paren] != "(":
        return None
    close = _matching_paren(masked, paren)
    if close < 0 or close >= limit:
        return None
    if keyword == "switch":
        brace = _skip_space(masked, close + 1, limit)
        end_brace = -1
        if brace < limit and masked[brace] == "{":
            end_brace = matching_brace(masked, brace)
        if end_brace < 0 or end_brace >= limit:
            return None
        return _Statement(
            "switch", index, end_brace + 1, _parse_block(masked, brace + 1, end_brace)
        )
    body = _parse_statement(masked, close + 1, limit)
    if body is None:
        return None
    if keyword != "if":
        kind = "wrapper"
        if keyword in _LOOP_WORDS:
            kind = "loop"
        return _Statement(kind, index, body.end, [body])
    otherwise = None
    else_at = _skip_space(masked, body.end, limit)
    else_word = _WORD_RE.match(masked, else_at, limit)
    if else_word and else_word.group() == "else":
        otherwise = _parse_statement(masked, else_word.end(), limit)
    end = body.end
    if otherwise is not None:
        end = otherwise.end
    return _Statement("if", index, end, [body, otherwise])


def _try_statement(
    masked: str, index: int, after: int, limit: int
) -> _Statement | None:
    block = _parse_statement(masked, after, limit)
    if block is None or block.kind != "block":
        return None
    handlers: list[_Statement] = []
    final = None
    cursor = block.end
    while True:
        position = _skip_space(masked, cursor, limit)
        word = _WORD_RE.match(masked, position, limit)
        name = ""
        if word:
            name = word.group()
        if name == "finally":
            final = _parse_statement(masked, word.end(), limit)
            if final is not None:
                cursor = final.end
            break
        if name != "catch":
            break
        position = _skip_space(masked, word.end(), limit)
        if masked[position : position + 1] == "(":
            position = _matching_paren(masked, position) + 1
        position = _skip_space(masked, position, limit)
        when = _WORD_RE.match(masked, position, limit)
        if when and when.group() == "when":
            paren = _skip_space(masked, when.end(), limit)
            if masked[paren : paren + 1] == "(":
                position = _matching_paren(masked, paren) + 1
        handler = _parse_statement(masked, max(position, cursor), limit)
        if handler is None or handler.kind != "block":
            break
        handlers.append(handler)
        cursor = handler.end
    return _Statement("try", index, cursor, [block, final, *handlers])


def _label_colon(masked: str, start: int, limit: int) -> int:
    depth = 0
    for index in range(start, limit):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and char == ";":
            return -1
        elif (
            depth == 0
            and char == ":"
            and masked[index + 1 : index + 2] != ":"
            and masked[index - 1 : index] != ":"
        ):
            return index
    return -1


def _simple_statement_end(masked: str, index: int, limit: int) -> tuple[int, bool]:
    """End of a statement at its top-level semicolon, and whether it is a
    declaration (local function, type, accessor) that ends at its brace."""
    depth = 0
    expression = False
    position = index
    while position < limit:
        char = masked[position]
        if char in "([":
            depth += 1
        elif char in ")]":
            if depth == 0:
                return position, False
            depth -= 1
        elif depth == 0 and char == "}":
            return position, False
        elif depth == 0 and char == ";":
            return position + 1, False
        elif depth == 0 and char == "{":
            close = matching_brace(masked, position)
            if close < 0 or close >= limit:
                return limit, False
            if not expression:
                return close + 1, True
            position = close + 1
            continue
        elif depth == 0 and char == "=":
            expression = True
        elif depth == 0 and (char.isalpha() or char == "_"):
            word = _WORD_RE.match(masked, position, limit)
            if (
                word.group() in _EXPRESSION_HEAD_WORDS
                and masked[position - 1 : position] != "@"
            ):
                expression = True
            position = word.end()
            continue
        position += 1
    return limit, False


def _response_types(
    body: str, masked: str, scope: _Scope, context: _FileContext
) -> dict[str, list[_ResponseRecord]]:
    """Possible response content kinds before each statement, joined over
    if/else, loops, switch sections and try blocks."""
    if (
        not _CONTENT_TYPE_RE.search(masked)
        or not _RESPONSE_WRITE_RE.search(masked)
        or _GOTO_RE.search(masked)
    ):
        return {}
    root = _Statement("block", 0, len(masked), _parse_block(masked, 0, len(masked)))
    records = {}
    for match in _RESPONSE_WRITE_RE.finditer(masked):
        receiver = _compact_name(match.group("receiver"))
        if receiver in records:
            continue
        flow = _Flow(
            body, masked, [], _response_receivers(scope, context, receiver), context
        )
        _flow(root, frozenset({_HTML_TYPE}), flow)
        records[receiver] = flow.records
    return records


def _flow(statement: _Statement, states: frozenset[str], flow: _Flow) -> frozenset[str]:
    assigned = tuple(
        (match.start(), _assigned_kinds(flow.body, match.end(), statement.end))
        for match in _CONTENT_TYPE_RE.finditer(
            flow.masked, statement.start, statement.end
        )
        if _response_reference(
            (match.group("receiver") or "").rstrip("."),
            flow.response_receivers,
            flow.context,
        )
    )
    flow.records.append((statement.start, statement.end, states, assigned))
    if not states or statement.kind == "label":
        return states
    if statement.kind == "exit":
        return frozenset()
    compound = _COMPOUND_FLOWS.get(statement.kind)
    if compound is not None:
        return compound(statement, states, flow)
    kinds = frozenset().union(*(item for _, item in assigned))
    if assigned and _CONTENT_TYPE_STATEMENT_RE.fullmatch(
        flow.masked, statement.start, statement.end
    ):
        return kinds
    return states | kinds


def _flow_block(
    statement: _Statement, states: frozenset[str], flow: _Flow
) -> frozenset[str]:
    for child in statement.parts:
        states = _flow(child, states, flow)
    return states


def _flow_if(
    statement: _Statement, states: frozenset[str], flow: _Flow
) -> frozenset[str]:
    then, otherwise = statement.parts
    result = _flow(then, states, flow)
    if otherwise is None:
        return result | states
    return result | _flow(otherwise, states, flow)


def _flow_wrapper(
    statement: _Statement, states: frozenset[str], flow: _Flow
) -> frozenset[str]:
    return _flow(statement.parts[0], states, flow)


def _flow_loop(
    statement: _Statement, states: frozenset[str], flow: _Flow
) -> frozenset[str]:
    """The body may run zero or more times: run it once, widen the entry state
    with everything it produced, and keep only the second pass."""
    mark = len(flow.records)
    result = _flow(statement.parts[0], states, flow)
    widened = states | result | _recorded_states(flow.records, mark)
    del flow.records[mark:]
    result = _flow(statement.parts[0], widened, flow)
    return widened | result | _recorded_states(flow.records, mark)


def _flow_switch(
    statement: _Statement, states: frozenset[str], flow: _Flow
) -> frozenset[str]:
    mark = len(flow.records)
    current = states
    for child in statement.parts:
        if child.kind == "label":
            current = states
        current = _flow(child, current, flow)
    return states | current | _recorded_states(flow.records, mark)


def _flow_try(
    statement: _Statement, states: frozenset[str], flow: _Flow
) -> frozenset[str]:
    block, final, *handlers = statement.parts
    mark = len(flow.records)
    result = _flow(block, states, flow)
    seen = states | result | _recorded_states(flow.records, mark)
    for handler in handlers:
        result = result | _flow(handler, seen, flow)
    if final is None:
        return result
    return _flow(final, seen | result | _recorded_states(flow.records, mark), flow)


def _flow_declaration(
    statement: _Statement, states: frozenset[str], flow: _Flow
) -> frozenset[str]:
    brace = flow.masked.find("{", statement.start, statement.end)
    if brace >= 0:
        inner = _parse_block(flow.masked, brace + 1, statement.end - 1)
        _flow(
            _Statement("block", brace, statement.end, inner),
            frozenset({_HTML_TYPE}),
            flow,
        )
    return states


_COMPOUND_FLOWS = {
    "block": _flow_block,
    "if": _flow_if,
    "wrapper": _flow_wrapper,
    "loop": _flow_loop,
    "switch": _flow_switch,
    "try": _flow_try,
    "decl": _flow_declaration,
}


def _recorded_states(records: list[_ResponseRecord], mark: int) -> frozenset[str]:
    return frozenset().union(*(record[2] for record in records[mark:]))


def _assigned_kinds(body: str, start: int, end: int) -> frozenset[str]:
    value = _CONTENT_TYPE_VALUE_RE.match(body, start, end)
    if value is None:
        return frozenset({_HTML_TYPE, _OTHER_TYPE})
    if (
        value.group("type")
        .strip()
        .lower()
        .startswith(("text/html", "application/xhtml"))
    ):
        return frozenset({_HTML_TYPE})
    return frozenset({_OTHER_TYPE})


def _non_html_response_at(records: list[_ResponseRecord], position: int) -> bool:
    best = None
    for record in records:
        if record[0] <= position < record[1] and (
            best is None or (record[0], -record[1]) > (best[0], -best[1])
        ):
            best = record
    if best is None:
        return False
    states = set(best[2])
    for assigned_at, kinds in best[3]:
        if assigned_at < position:
            states |= kinds
    return states == {_OTHER_TYPE}


def _ternary_colon(masked: str, start: int) -> int:
    depth = 0
    nested = 0
    for index in range(start, len(masked)):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return -1
            depth -= 1
        elif depth == 0 and char == "?" and not masked.startswith(("?.", "??"), index):
            nested += 1
        elif depth == 0 and char == ":":
            if nested == 0:
                return index
            nested -= 1
        elif depth == 0 and char == ";":
            return -1
    return -1


def _expression_end(masked: str, start: int) -> int:
    depth = 0
    for index in range(start, len(masked)):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return index
            depth -= 1
        elif char in ";," and depth == 0:
            return index
    return len(masked)


def _scan_file_patterns(context: _FileContext, collector: _Collector) -> None:
    masked = context.masked
    source = context.source
    for match in _TYPE_NAME_HANDLING_RE.finditer(masked):
        block_start, block_end = _enclosing_block(masked, match.start())
        header = masked[:block_start]
        created = re.search(
            rf"\bnew\s+(?P<type>{_PROVIDER_TYPE_TEXT})\s*(?:\([^{{}};]*\))?\s*$",
            header,
        )
        target_typed = None
        if created is None:
            target_typed = re.search(
                rf"\b(?P<type>{_PROVIDER_TYPE_TEXT})\s+@?[A-Za-z_]\w*"
                r"\s*=\s*new\s*\([^{};]*\)\s*$",
                header,
            )
        owner = created or target_typed
        if owner is None or not _json_settings_type(owner.group("type"), context):
            continue
        rule = _type_name_handling_rule(match, context, masked[block_start:block_end])
        if rule:
            collector.add(rule, source.count("\n", 0, match.start()) + 1)
    for match in _TYPE_RESOLVER_RE.finditer(masked):
        if _provider_type(
            "JavaScriptSerializer",
            context,
            frozenset({"System.Web.Script.Serialization.JavaScriptSerializer"}),
        ) and _provider_type(
            "SimpleTypeResolver",
            context,
            frozenset({"System.Web.Script.Serialization.SimpleTypeResolver"}),
        ):
            collector.add(
                models.TYPE_RESOLVER, source.count("\n", 0, match.start()) + 1
            )


def _enclosing_block(masked: str, position: int) -> tuple[int, int]:
    depth = 0
    for index in range(position - 1, -1, -1):
        char = masked[index]
        if char == "}":
            depth += 1
        elif char == "{":
            if depth == 0:
                close = matching_brace(masked, index)
                if close == -1:
                    return index, len(masked)
                return index, close
            depth -= 1
    return 0, len(masked)


def _is_basename_call(
    expr: str,
    tainted_vars: set[str],
    path_type_shadowed: bool,
    request_vars: set[str] = frozenset(),
) -> bool:
    """Recognize only a complete System.IO.Path.GetFileName expression."""
    code = _masked_code(expr)
    match = _PATH_BASENAME_RE.match(code)
    if not match or (path_type_shadowed and not match.group("qualified")):
        return False
    close = _matching_paren(code, match.end() - 1)
    if close < 0 or code[close + 1 :].strip():
        return False
    arguments = _split_arguments(expr, code, match.end(), close)
    return len(arguments) == 1 and _is_tainted(arguments[0], tainted_vars, request_vars)


def _is_contained_basename_path(expr: str, state: _ScopeState) -> bool:
    """A basename is path-contained only when joined to a directory that is
    neither request data, a root or ``.`` literal, nor the bare working or
    application directory (which hold ``appsettings.json``).

    A bare basename can still select arbitrary local files. Directory APIs
    are deliberately excluded: GetFileName("..") remains ".." and may cause
    a directory operation to escape the base directory.
    """
    tainted = state.tainted_vars[models.PATH.rule_id]
    code = _masked_code(expr)
    match = _PATH_COMBINE_RE.match(code)
    if not match or (state.path_type_shadowed and not match.group("qualified")):
        return False
    close = _matching_paren(code, match.end() - 1)
    if close < 0 or code[close + 1 :].strip():
        return False
    arguments = _split_arguments(expr, code, match.end(), close)
    if len(arguments) < 2:
        return False
    directories = arguments[:-1]
    for directory in directories:
        if _is_tainted(directory, tainted, state.request_vars):
            return False
        if directory.strip().startswith(('"', '@"', '$"')) and not _is_fixed_directory(
            directory
        ):
            return False
    if len(directories) == 1 and models.APP_ROOT_RE.search(
        _masked_code(directories[0])
    ):
        return False
    basename = _masked_code(arguments[-1]).strip()
    if re.fullmatch(r"@?[A-Za-z_]\w*", basename):
        return basename.lstrip("@") in state.basename_vars
    return _is_basename_call(
        arguments[-1], tainted, state.path_type_shadowed, state.request_vars
    )


def _is_fixed_directory(expr: str) -> bool:
    """Accept a simple non-root literal directory, never input-derived paths."""
    match = _FIXED_DIRECTORY_RE.fullmatch(expr.strip())
    if not match:
        return False
    components = [part for part in match.group("path").split("/") if part]
    return bool(components) and all(part not in {".", ".."} for part in components)


def _is_interpolated_literal(arg: str) -> bool:
    text = arg.strip()
    if not re.match(r'(?:\$@|@\$|\$)"', text):
        return False
    token = next(iter(_TOKEN_RE.finditer(text)), None)
    return token is not None and token.start() == 0 and token.end() == len(text)


def _is_string_built(expr: str) -> bool:
    code = _masked_code(expr)
    if re.search(r'(?:\$@?|@\$)"', expr):
        return True
    if "+" in code and '"' in expr:
        return True
    return bool(
        re.search(r"\b(?:string|String)\s*\.\s*(?:Format|Concat|Join)\s*\(", code)
    )


def _call_arguments(statement: str, regex: re.Pattern[str]):
    code = _masked_code(statement)
    for match in regex.finditer(code):
        open_paren = match.end() - 1
        close_paren = _matching_paren(code, open_paren)
        if close_paren < 0:
            continue
        yield match, _split_arguments(statement, code, open_paren + 1, close_paren)


def _arguments_at(statement: str, code: str, open_paren: int) -> list[str]:
    close_paren = _matching_paren(code, open_paren)
    if close_paren < 0:
        return []
    return _split_arguments(statement, code, open_paren + 1, close_paren)


def _argument_spans(masked: str, start: int, end: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    depth = 0
    begin = start
    for index in range(start, end):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            spans.append((begin, index))
            begin = index + 1
    spans.append((begin, end))
    return spans


def _matching_paren(code: str, open_paren: int) -> int:
    depth = 0
    for index in range(open_paren, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _matching_bracket(code: str, open_bracket: int) -> int:
    depth = 0
    for index in range(open_bracket, len(code)):
        if code[index] == "[":
            depth += 1
        elif code[index] == "]":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_arguments(statement: str, code: str, start: int, end: int) -> list[str]:
    return [
        statement[begin:finish] for begin, finish in _argument_spans(code, start, end)
    ]


def _split_top_level(text: str, *, angle_brackets: bool = False) -> list[str]:
    pieces: list[str] = []
    depth = 0
    begin = 0
    openers = "([{"
    closers = ")]}"
    if angle_brackets:
        openers = "([{<"
        closers = ")]}>"
    for index, char in enumerate(text):
        if char in openers:
            depth += 1
        elif char in closers and depth:
            depth -= 1
        elif char == "," and depth == 0:
            pieces.append(text[begin:index])
            begin = index + 1
    pieces.append(text[begin:])
    return pieces


@lru_cache(maxsize=4096)
def _name_pattern(names: tuple[str, ...]) -> re.Pattern[str]:
    alternatives = "|".join(re.escape(name) for name in names)
    return re.compile(
        rf"(?<![\w.])@?(?:{alternatives})\b|\bthis\s*\.\s*(?:{alternatives})\b"
    )


def _mentions(expr: str, names: set[str]) -> bool:
    if not expr or not names:
        return False
    return bool(_name_pattern(tuple(sorted(names))).search(_masked_code(expr)))


def _mentions_as_text(expr: str, names: set[str]) -> bool:
    """Mentions that carry the value's text: an argument to an unknown call
    (``Encode(password)``, ``ClauseFor(option)``) returns something else."""
    if not expr or not names:
        return False
    code = _masked_code(expr)
    chars = list(code)
    for match in _CALL_NAME_RE.finditer(code):
        if match.group("name") in _TEXT_PRESERVING_CALLS:
            continue
        close = _matching_paren(code, match.end() - 1)
        if close < 0:
            continue
        chars[match.end() : close] = " " * (close - match.end())
    return bool(_name_pattern(tuple(sorted(names))).search("".join(chars)))


def _uses_request_var(code: str, request_vars: set[str]) -> bool:
    for name in request_vars:
        if re.search(
            rf"(?<![\w.])@?{re.escape(name)}\s*(?:\??\.\s*{models.REQUEST_MEMBERS}\b|\[)",
            code,
        ):
            return True
    return False


def _is_tainted(
    expr: str, tainted_vars: set[str], request_vars: set[str] = frozenset()
) -> bool:
    if not expr:
        return False
    code = _masked_code(expr)
    if models.SOURCE_HINT_RE.search(code):
        return True
    if request_vars and _uses_request_var(code, request_vars):
        return True
    if not tainted_vars:
        return False
    return bool(_name_pattern(tuple(sorted(tainted_vars))).search(code))


@lru_cache(maxsize=8192)
def _masked_code(expr: str) -> str:
    """Mask literals, retaining only expressions inside interpolated strings."""
    chars = list(mask_comments_and_strings(expr))
    for match in _TOKEN_RE.finditer(expr):
        if isinstance(match, _RawTokenMatch):
            continue
        token = match.group()
        if not token.startswith(('$"', '$@"', '@$"')):
            continue
        index = token.find('"') + 1
        while index < len(token) - 1:
            if token[index : index + 2] in ("{{", "}}"):
                index += 2
                continue
            if token[index] != "{":
                index += 1
                continue
            start = index + 1
            depth = 1
            index = start
            while index < len(token) - 1 and depth:
                if token[index] == "{":
                    depth += 1
                elif token[index] == "}":
                    depth -= 1
                index += 1
            if depth == 0:
                hole = mask_comments_and_strings(token[start : index - 1])
                chars[match.start() + start : match.start() + index - 1] = hole
    return "".join(chars)


def _owner_at(classes: list[_ClassInfo], position: int) -> _ClassInfo | None:
    candidates = [info for info in classes if info.open < position < info.close]
    if not candidates:
        return None
    return max(candidates, key=lambda info: info.open)


def _is_direct_member(masked: str, owner: _ClassInfo, position: int) -> bool:
    body_start = owner.open + 1
    return masked.count("{", body_start, position) == masked.count(
        "}", body_start, position
    )


def _blank_spans(source: str, spans: list[tuple[int, int]]) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        if end <= cursor:
            continue
        start = max(start, cursor)
        pieces.append(source[cursor:start])
        pieces.append(_blank_non_newlines(source[start:end]))
        cursor = end
    pieces.append(source[cursor:])
    return "".join(pieces)


def _blank_non_newlines(text: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in text)


def _iter_statements(body: str):
    masked = mask_comments_and_strings(body)
    start = 0
    for match in re.finditer(r"[;{}]", masked):
        end = match.end()
        code_start = re.search(r"\S", masked[start:end])
        if code_start:
            offset = start + code_start.start()
            yield offset, body[offset:end].rstrip()
        start = end
    code_start = re.search(r"\S", masked[start:])
    if code_start:
        offset = start + code_start.start()
        yield offset, body[offset:].rstrip()
