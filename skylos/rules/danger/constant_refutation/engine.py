"""Constant-argument refutation engine for Skylos danger findings (vendored).

Vendored from the research technique
``benchmarks/fp_research_2026_11_21/techniques/sec_sccp_fx/sccp_engine.py``
(revision 7, SHA-256 531534703e23ccb9365596a48845a41419bcb4d71323071a79039c323030a426).
Changes from the research file: this header; the harness glue ``apply(raw, repo, ctx, cfg)``
replaced by :func:`refute`, which returns kept findings plus drop certificates instead of
calling the benchmark harness normaliser; and one narrowing (it can only keep more findings):
a shell command text or argv containing `$` or a backquote never closes a shell site
(:func:`_expands_parameters`, used in ``Engine.site_closed``). Further scope limits live in the
pipeline wrapper. Entry point for the scan pipeline:
``skylos.rules.danger.constant_refutation.refute_constant_argument_findings``.

Original description: value and identity refutation of Skylos 5.7.0 security findings.

Deterministic, stdlib-only, ast-only. Never imports or executes scanned code.

The engine refutes a Skylos finding only by replacing an over-approximated
VALUE (parameter = unknown, branch join, whole-container taint) or IDENTITY
(callee guessed from a name, method bound by name) with a proven one, and then
applying Skylos 5.7.0's OWN sink model, sanitizer set and provenance policy
("specialisation principle", council/proposal__sec-sccp.md section 0).
It never adds sanitizer, guard or source knowledge of its own.

Mechanisms (each switchable through Config):
  F0     Skylos's own ValueFlow literal proofs (low_risk_context constant-*)
  core   intraprocedural sparse conditional constant propagation
         (Wegman & Zadeck 1991): dead branches folded on FUNCTION-LOCAL
         literals only, element-precise list/dict/ConfigParser, strong updates,
         project return summaries (depth <= 3)
  ipcp   interprocedural constant propagation by jump functions
         (Callahan, Cooper, Kennedy & Torczon 1986) for underscore-private or
         nested functions under closed-world gates C1-C7 + G6
  repo   repository-anchored code content (__file__-anchored, build script or
         statically imported module source), code sinks only
  d228   XSS: Skylos's own hole decomposition (html_context.split_parts) and
         first-failure order, with holes proven constant
  s2b    YAML identity: PyYAML Loader in {Safe,CSafe,Base,CBase}Loader,
         ruamel YAML() with typ in {rt, safe, base}; project tamper scan
  s2c    provenance witness-chain refutation (strict: residual status safe)
  s2a    D216 receivers whose identity is a builtin container (json.loads,
         dict/list displays): these objects have no network methods

Unknown => keep. Any exception => keep (fail closed).
"""
from __future__ import annotations

import ast
import base64
import html as _html
import posixpath
import re
import shlex
import string
import warnings
from pathlib import Path

MAX_SET = 32
MAX_LEN = 10000
MAX_DEPTH = 3
MAX_INT_BITS = 4096
MAX_CHAINS = 4                 # Skylos 5.7.0 path_provenance._MAX_CHAINS (path_provenance.py:111)
REPO_TOKEN = "/__sccp_repo__"  # stands for the checkout root inside folded path strings
BIG_TEXT = 4_000_000           # non-Python files above this size are searched by bytes, not tokenised


class Config:
    """Switches. Defaults = the registered primary arm `sec_sccp`."""

    def __init__(self, **kw):
        self.f0 = True
        self.s1 = True       # value refutation of the claimed operand (core / ipcp / repofile / d228)
        self.core = True
        self.ipcp = True
        self.repofile = True
        self.d228 = True
        self.s2b = True
        self.s2c = True
        self.s2a = True
        self.mssa = "bs"   # "bs" = binding-stability standard (README), "strict" = proposal section 3.5 (iv)/(v) literally
        for k, v in kw.items():
            if not hasattr(self, k):
                raise ValueError(f"unknown switch {k}")
            setattr(self, k, v)


# ---------------------------------------------------------------------------
# rule scope (council/proposal__sec-sccp.md section 3.1)
# ---------------------------------------------------------------------------

S1_RULES = {"SKY-D201", "SKY-D202", "SKY-D203", "SKY-D204", "SKY-D205", "SKY-D206", "SKY-D209",
            "SKY-D212", "SKY-D215", "SKY-D324", "SKY-D325", "SKY-D326", "SKY-D216", "SKY-D226",
            "SKY-D228", "SKY-D230", "SKY-D233"}
S1_INTRA_ONLY = {"SKY-D211", "SKY-D217"}
F0_RULES = S1_RULES | S1_INTRA_ONLY
F0_REASONS = {"constant-argument", "constant-shell-command"}
CODE_RULES = {"SKY-D201", "SKY-D202"}
FAMILIES_DOC = "families are used for documentation only: no finding is dropped because a sibling was dropped"
FAMILIES = [
    {"SKY-D203", "SKY-D209", "SKY-D212"},
    {"SKY-D215", "SKY-D324", "SKY-D325", "SKY-D326"},
    {"SKY-D204", "SKY-D205", "SKY-D206", "SKY-D233"},
    {"SKY-D201", "SKY-D202"},
]
PROV_KEYS = {"SKY-D215": "path_provenance", "SKY-D324": "path_provenance", "SKY-D325": "path_provenance",
             "SKY-D326": "path_provenance", "SKY-D211": "sql_provenance", "SKY-D230": "redirect_provenance"}
PATH_FAMILY = {"SKY-D215", "SKY-D324", "SKY-D325", "SKY-D326"}

# rule -> (callee final names used to locate the call when col does not match, operand positions/keywords)
SINK_SPECS = {
    "SKY-D201": ({"eval"}, 0, ("source", "expression")),
    "SKY-D202": ({"exec"}, 0, ("source", "object")),
    "SKY-D203": ({"system", "popen"}, 0, ("command", "cmd")),
    "SKY-D204": ({"load", "read_pickle", "Unpickler"}, 0, ("file", "filepath_or_buffer")),
    "SKY-D205": ({"loads"}, 0, ("data", "s")),
    "SKY-D206": ({"load", "load_all", "unsafe_load", "unsafe_load_all", "full_load", "full_load_all"}, 0, ("stream",)),
    "SKY-D233": ({"loads", "load"}, 0, ("data", "bytes")),
    "SKY-D209": ({"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput",
                  "create_subprocess_shell"}, 0, ("args", "cmd")),
    "SKY-D212": ({"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput",
                  "create_subprocess_shell", "system", "popen"}, 0, ("args", "cmd", "command")),
    "SKY-D230": ({"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse",
                  "HTTPFound"}, 0, ("location", "to", "url", "redirect_to")),
    "SKY-D215": ({"open", "send_file", "remove", "unlink", "rmtree", "listdir", "rename", "copy", "copyfile",
                  "move", "Path", "makedirs", "mkdir", "FileResponse"}, 0, ("file", "path", "filename")),
    "SKY-D226": ({"mark_safe", "Markup", "SafeString"}, 0, ("s", "value")),
    "SKY-D216": ({"get", "post", "put", "delete", "head", "options", "patch", "request", "urlopen", "fetch",
                  "Request"}, 0, ("url",)),
}
for _r in ("SKY-D324", "SKY-D325", "SKY-D326"):
    SINK_SPECS[_r] = SINK_SPECS["SKY-D215"]
SHELL_NAMES = SINK_SPECS["SKY-D203"][0] | SINK_SPECS["SKY-D209"][0] | SINK_SPECS["SKY-D212"][0]
CODE_NAMES = {"eval", "exec"}

# Skylos 5.7.0 rules/danger/taint.py:12 XSS_SANITIZERS
XSS_SANITIZERS = {"html.escape", "markupsafe.escape", "markupsafe.Markup.escape", "Markup.escape", "bleach.clean"}
RAW_XSS_MESSAGE = "XSS (HTML built from unescaped user input)"   # xss_flow._unescaped_message(RAW)

# PyYAML documentation: loaders that construct only standard YAML tags
PYYAML_SAFE_LOADERS = {"yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader", "yaml.CBaseLoader",
                       "yaml.loader.SafeLoader", "yaml.loader.BaseLoader", "yaml.cyaml.CSafeLoader",
                       "yaml.cyaml.CBaseLoader"}
RUAMEL_YAML_CLASSES = {"ruamel.yaml.YAML", "ruamel.yaml.main.YAML"}
RUAMEL_SAFE_TYP = {"rt", "safe", "base"}
RUAMEL_OK_METHODS = {"load", "load_all", "dump", "dump_all", "indent", "compose", "compose_all", "parse",
                     "scan", "serialize", "serialize_all", "emit"}
RUAMEL_OK_SETTINGS = {"width", "indent", "default_flow_style", "explicit_start", "explicit_end", "allow_unicode",
                      "encoding", "line_break", "top_level_colon_align", "prefix_colon", "map_indent",
                      "sequence_indent", "sequence_dash_offset", "compact_seq_seq", "compact_seq_map",
                      "brace_single_entry_mapping_in_flow_sequence", "boolean_representation", "canonical",
                      "default_style", "preserve_quotes", "allow_duplicate_keys", "version", "tags"}
RUAMEL_TAMPER_ATTRS = {"Constructor", "constructor", "typ", "Resolver", "resolver", "Loader", "loader",
                       "Parser", "parser", "Composer", "composer", "Scanner", "scanner", "Reader", "reader",
                       "plug_ins"}
YAML_TAMPER_WORDS = {"add_constructor", "add_multi_constructor", "yaml_constructors", "yaml_multi_constructors",
                     "YAMLObject", "yaml_object", "yaml_loader", "register_class", "add_path_resolver"}

LOADER_METHODS = {"load_module", "exec_module", "create_module"}
# the process environment as a mapping (os docs: os.environ, os.environb); writes go to the C environment (putenv)
ENV_MAPPINGS = {"os.environ", "os.environb"}
ENV_READ_METHODS = {"get", "copy", "items", "keys", "values", "__contains__", "__getitem__", "__len__", "__iter__",
                    "__or__", "__ror__", "pop", "popitem", "clear", "__delitem__", "unsetenv"}
ENV_WRITE_METHODS = {"update", "setdefault", "__setitem__", "__ior__"}
ENV_READ_FUNCS = {"dict", "len", "list", "sorted", "iter", "repr", "str", "print", "set", "tuple", "copy.copy",
                  "copy.deepcopy", "json.dumps"}
# attributes that expose a namespace mapping or a by-name attribute lookup (Python data model: __dict__,
# function __globals__, frame f_globals/f_locals, object.__getattribute__)
NS_ATTRS = {"__dict__", "__globals__", "f_globals", "f_locals", "__getattribute__"}

# ---- site closure for shell and code sinks (ported from techniques/cpm_sec/technique.py SC1r, cross-certified
# lens, after the SC1/F0 counterexamples in council/review__cross-certified__by__sec-sccp.md and ..._by__sec-recall.md):
# a constant command or code text closes the sink only if no other channel carries data into it.
SHELL_SINK_RULES = {"SKY-D203", "SKY-D209", "SKY-D212"}
# Environment variables that change what a fixed command line executes (ld.so(8) LD_PRELOAD/LD_LIBRARY_PATH; dyld(1);
# POSIX sh ENV/IFS/PATH/PS4; bash(1) BASH_ENV/SHELLOPTS/BASHOPTS; python(1) PYTHON*; perl(1) PERL5*; ruby(1) RUBY*;
# node(1) NODE_OPTIONS; git(1) GIT_SSH_COMMAND/GIT_EXEC_PATH/GIT_CONFIG*). A non-literal write to one of them, or to a
# non-literal key, opens every constant shell site; a non-literal write to any other variable opens only command texts
# that expand parameters ($, backquote).
PROCESS_CONTROL_ENV = {"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES",
                       "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "IFS",
                       "PS4", "CDPATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONINSPECT", "PERL5LIB",
                       "PERL5OPT", "PERLLIB", "RUBYLIB", "RUBYOPT", "NODE_OPTIONS", "NODE_PATH", "GIT_SSH_COMMAND",
                       "GIT_SSH", "GIT_EXEC_PATH", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                       "GIT_CONFIG_PARAMETERS", "GIT_ASKPASS", "SSH_ASKPASS", "EDITOR", "VISUAL", "PAGER", "TMPDIR"}
CODE_SINK_RULES = {"SKY-D201", "SKY-D202"}
F0_SHELL = {"SKY-D203", "SKY-D209"}
F0_CODE = {"SKY-D201", "SKY-D202"}
F0_DATA = {"SKY-D205", "SKY-D206"}
# subprocess keywords that cannot carry data into the child (Python docs, subprocess); stdin only None/DEVNULL
SHELL_SAFE_KW = {"args", "shell", "stdout", "stderr", "text", "universal_newlines", "encoding", "errors", "check",
                 "capture_output", "timeout", "bufsize", "close_fds", "start_new_session", "restore_signals"}
CODE_SAFE_NODES = (ast.Module, ast.Expression, ast.Interactive, ast.Expr, ast.Assign, ast.AugAssign, ast.AnnAssign,
                   ast.Name, ast.Constant, ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.Tuple,
                   ast.List, ast.Set, ast.Dict, ast.Subscript, ast.Slice, ast.Pass, ast.JoinedStr, ast.FormattedValue,
                   ast.operator, ast.unaryop, ast.boolop, ast.cmpop, ast.expr_context)
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "csh", "tcsh", "fish", "busybox"}
SCRIPT_INTERPRETERS = {"perl", "ruby", "node", "nodejs", "php", "lua", "tclsh", "wish", "Rscript", "R",
                       "osascript", "pwsh", "powershell", "awk", "gawk", "bc", "dc"}
SQL_SHELLS = {"psql": ("-c", "--command", "-f", "--file"), "mysql": ("-e", "--execute"),
              "mariadb": ("-e", "--execute"), "sqlplus": ("@",), "sqlite3": ()}
WRAPPERS = {"env", "sudo", "nice", "nohup", "exec", "command", "time", "timeout", "stdbuf", "ionice",
            "doas", "setsid", "chrt", "taskset"}
_PY_RE = re.compile(r"^(python|pypy)(\d+(\.\d+)*)?[mwd]?$")
_SHELL_OPS = {"|", "||", "&&", ";", "&", ";;", "|&", "(", ")"}
_REDIR_RE = re.compile(r"^(\d*|&)([<>]{1,2}|[<>]&|&>{1,2}|<>)$")


def _simple_commands(text):
    text = text.replace("\r", "\n").replace("\n", " ; ")
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        return None
    cmds, cur, skip = [], [], False
    i = 0
    while i < len(toks):
        t = toks[i]
        i += 1
        if skip:
            skip = False
            continue
        if t in _SHELL_OPS or (t and set(t) <= set("|&;()")):
            if cur:
                cmds.append(cur)
            cur = []
            continue
        if t and set(t) <= set("<>&") or _REDIR_RE.match(t or ""):
            if cur and cur[-1].isdigit():
                cur.pop()
            if t.startswith("<"):
                cur.append("<")
            skip = True
            continue
        cur.extend(x for x in t.split("\n") if x)
    if cur:
        cmds.append(cur)
    return cmds


def _argv_reads_stdin(argv):
    argv = [a for a in argv if a != ""]
    while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
        argv = argv[1:]
    while argv and posixpath.basename(argv[0]) in WRAPPERS:
        argv = argv[1:]
        while argv and (argv[0].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0])
                        or re.match(r"^\d+(\.\d+)?[smhd]?$", argv[0])):
            argv = argv[1:]
    if not argv:
        return False
    prog = posixpath.basename(argv[0])
    rest = [a for a in argv[1:] if a != "<"]
    operands = [a for a in rest if not a.startswith("-")]
    if prog == "xargs":
        return True
    if prog in SQL_SHELLS:
        flags = SQL_SHELLS[prog]
        if prog == "sqlite3":
            return len(operands) < 2
        return not any(a == f or a.startswith(f) for a in rest for f in flags)
    if prog in SHELLS or prog in SCRIPT_INTERPRETERS or _PY_RE.match(prog):
        if "-" in rest or "-s" in rest or "/dev/stdin" in rest:
            return True
        has_c = any(a in ("-c", "-e", "-m", "-E", "-r") or (a.startswith("-") and not a.startswith("--")
                                                            and "c" in a[1:] and prog in SHELLS) for a in rest)
        return not operands and not has_c
    return False


def interpreter_reads_stdin(text):
    """True if some simple command runs an interpreter with no program operand (it executes its stdin).
    Unparseable text: True (keep)."""
    cmds = _simple_commands(text)
    if cmds is None:
        return True
    return any(_argv_reads_stdin(argv) for argv in cmds)


# ---- programs whose behaviour is NOT fixed by a constant command text (red team F4, council/redteam__security.md
# section 2.1): they execute a FILE (a script, module, makefile or path program) that the application itself may
# write, or inline code in a language this engine does not analyse. Sources: sh(1)/bash(1) (`-c`, script operand,
# `.`/`source`, `eval`, command substitution), python(1) (`-c`, `-m`, script), perl(1)/ruby(1)/node(1)/php(1)/
# awk(1) (program text or file), make(1) (makefile in the working directory or `-f`/`-C`), find(1) (`-exec`,
# `-execdir`, `-ok`, `-okdir`), env(1) (`-S`), psql(1) (`-f`, `\i`), mysql(1) (`source`). Used only in the keep
# direction. POSIX host semantics are assumed (A9): a bare program name is looked up in PATH (whose writes are the
# environment channel), never in the working directory.
SOURCE_BUILTINS = {".", "source", "eval"}
MAKE_PROGRAMS = {"make", "gmake", "bmake", "pmake", "remake"}
FIND_EXEC_FLAGS = {"-exec", "-execdir", "-ok", "-okdir"}
MAX_SHELL_NESTING = 3


def _strip_prefix(argv):
    """Drop leading NAME=value assignments and wrapper programs (with their options). None if a wrapper splits a
    string into further arguments (env -S), which this parser does not model."""
    argv = [a for a in argv if a != ""]
    while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
        argv = argv[1:]
    while argv and posixpath.basename(argv[0]) in WRAPPERS:
        argv = argv[1:]
        while argv and (argv[0].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0])
                        or re.match(r"^\d+(\.\d+)?[smhd]?$", argv[0])):
            if argv[0] in ("-S", "--split-string") or argv[0].startswith("--split-string=") \
                    or (argv[0].startswith("-S") and len(argv[0]) > 2):
                return None
            argv = argv[1:]
    return argv


def _runs_named_program(tok):
    b = posixpath.basename(tok)
    return (b in SHELLS or b in SCRIPT_INTERPRETERS or b in SQL_SHELLS or b in MAKE_PROGRAMS or b == "xargs"
            or b in ("source", "eval") or bool(_PY_RE.match(b)))


def _argv_runs_unfixed(argv, depth=0):
    """True if this simple command may execute code that the constant text does not fix: a path program, a script
    or module FILE, a makefile, inline code of an unanalysed language, a nested program named in its arguments
    (find -exec, ssh/su/watch/parallel ...), or code produced at run time. Shell `-c` code is checked recursively;
    python `-c` code must be closed literal code (code_literal_closed). Unknown: True."""
    if depth > MAX_SHELL_NESTING:
        return True
    argv = _strip_prefix(argv)
    if argv is None:
        return True
    argv = [a for a in argv if a != "<"]
    if not argv:
        return False
    prog0 = argv[0]
    prog = posixpath.basename(prog0)
    rest = argv[1:]
    if "/" in prog0 or "\\" in prog0:
        return True                      # path program (./x, /abs/x, dir/x): a file the project may write
    if prog in SOURCE_BUILTINS or prog in MAKE_PROGRAMS or prog in SCRIPT_INTERPRETERS or prog in SQL_SHELLS \
            or prog == "xargs":
        return True
    if any(a in FIND_EXEC_FLAGS for a in rest):
        return True
    if prog in SHELLS:
        has_c = False
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--":
                i += 1
                break
            if a in ("-o", "+o", "-O", "+O"):
                i += 2
                continue
            if (a.startswith("-") or a.startswith("+")) and len(a) > 1:
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                    has_c = True
                i += 1
                continue
            break
        operands = rest[i:]
        if not has_c or not operands:
            return True                  # a script FILE operand, or commands read from stdin
        return text_runs_unfixed(operands[0], depth + 1)
    if _PY_RE.match(prog):
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "-c":
                return i + 1 >= len(rest) or not code_literal_closed(rest[i + 1], "exec")
            if a.startswith("-c") and len(a) > 2:
                return not code_literal_closed(a[2:], "exec")
            if a in ("-W", "-X", "--check-hash-based-pycs"):
                i += 2
                continue
            if a.startswith("-") and a != "-" and not a.startswith("-m"):
                i += 1
                continue
            return True                  # -m MODULE, a script FILE, or `-` (stdin)
        return True                      # no program operand: stdin
    if any(_runs_named_program(a) for a in rest):
        return True                      # a program run by this one (ssh host sh x, su -c, watch, nohup-likes ...)
    return False


def text_runs_unfixed(text, depth=0):
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            return True
    if not isinstance(text, str):
        return True
    if "`" in text or "$(" in text or "<(" in text or ">(" in text:
        return True                      # command or process substitution: run-time output becomes code or input
    cmds = _simple_commands(text)
    if cmds is None:
        return True
    return any(_argv_reads_stdin(argv) or _argv_runs_unfixed(argv, depth) for argv in cmds)


def code_literal_closed(code, mode):
    if isinstance(code, bytes):
        try:
            code = code.decode("utf-8")
        except UnicodeDecodeError:
            return False
    if not isinstance(code, str):
        return False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            t = ast.parse(code, mode=mode)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            return False
    return all(isinstance(n, CODE_SAFE_NODES) for n in ast.walk(t))   # PEP 302 / PEP 451 loader protocol
DYNAMIC_CODE_CALLS = {"eval", "exec", "compile", "__import__", "importlib.import_module", "importlib.__import__",
                      "runpy.run_path", "runpy.run_module", "import_module"}
JSON_LOADERS = {"json.loads", "json.load"}
BUILTIN_TYPE_METHODS = {"get", "pop", "setdefault", "copy", "keys", "values", "items", "index", "count"}


# ---------------------------------------------------------------------------
# abstract values (ported from dev/owasp_fp_probe/probe.py, with repairs)
# ---------------------------------------------------------------------------

class V:
    __slots__ = ("k", "x", "facts")

    def __init__(self, k, x=None, facts=frozenset()):
        self.k = k
        self.x = x
        self.facts = facts

    def __repr__(self):
        if self.k == "exact":
            return f"exact({sorted(map(repr, self.x))[:4]})"
        if self.k == "top":
            return f"top({sorted(self.facts)})"
        if self.k in ("fh", "repo", "inst", "ext", "mod", "builtin"):
            return f"{self.k}({self.x!r})"
        return f"{self.k}"


TOP = V("top")
OPAQUE = V("opaque")
SCALAR_SAFE = ("exact", "opaque")
CONTAINERS = ("list", "dict", "cfg")
IDENTITY_KINDS = ("mod", "ext", "pclass", "pfunc", "builtin", "obj", "inst")
BUILTIN_TYPED = frozenset({"builtin_type"})


def _scalar_ok(v) -> bool:
    if isinstance(v, bool) or v is None or isinstance(v, float):
        return True
    if isinstance(v, int):
        return v.bit_length() <= MAX_INT_BITS
    if isinstance(v, (str, bytes)):
        return len(v) <= MAX_LEN
    if isinstance(v, tuple):
        return len(v) <= MAX_SET * 4 and all(_scalar_ok(x) for x in v)
    return False


def _tkey(v):
    """Type-aware identity of a literal value. Python equality and hashing conflate values that print and behave
    differently: True == 1 == 1.0, False == 0 == 0.0 == -0.0, (True,) == (1,). A frozenset (or a join of two)
    keeps only one of them, so str()/repr()/format() of the survivor can fold a branch the wrong way (red team F1,
    council/redteam__security.md section 2.1)."""
    if isinstance(v, tuple):
        return ("tuple",) + tuple(_tkey(x) for x in v)
    if isinstance(v, float):
        return ("float", repr(v))
    return (type(v).__name__, v)


def _tkeys(vals):
    return {_tkey(v) for v in vals}


def exact(*vals):
    try:
        s = frozenset(vals)
        if _tkeys(s) != _tkeys(vals):
            return OPAQUE   # equal values of different types (or 0.0 / -0.0) would be merged into one
    except TypeError:
        return OPAQUE
    if len(s) > MAX_SET:
        return OPAQUE
    for v in s:
        if not _scalar_ok(v):
            return OPAQUE
    return V("exact", s)


class _Acc:
    """Accumulator of literal results keyed by type-aware identity (_tkey), so that exact() sees True and 1 (or
    0.0 and -0.0) as two values instead of a set silently keeping one of them (red team F1)."""
    __slots__ = ("d",)

    def __init__(self):
        self.d = {}

    def add(self, v):
        self.d.setdefault(_tkey(v), v)

    def values(self):
        return list(self.d.values())

    def __len__(self):
        return len(self.d)

    def __bool__(self):
        return bool(self.d)


def exact_set(vals):
    return exact(*list(vals))


def _dict_store(items, k, v):
    """d[k] = v on an element-precise dict: Python keeps the ORIGINAL key object and its insertion position when an
    equal key exists ({1: 'a', True: 'b'} == {1: 'b'}), so iteration and str() of keys see the first key."""
    out = list(items)
    for j, (kk, vv) in enumerate(out):
        if kk is not None and kk == k:
            out[j] = (kk, v)
            return tuple(out)
    return tuple(out + [(k, v)])


def top(facts=frozenset()):
    return TOP if not facts else V("top", None, frozenset(facts))


def untainted(v) -> bool:
    if v is None:
        return True
    if v.k in SCALAR_SAFE:
        return True
    if v.k == "list":
        return all(untainted(e) for e in v.x)
    if v.k == "dict":
        return all(untainted(e) for _, e in v.x)
    if v.k == "cfg":
        return not v.x[1] and all(untainted(e) for _, e in v.x[0])
    return False


def builtin_typed(v) -> bool:
    return v is not None and (v.k in ("exact", "opaque", "list", "dict")
                              or (v.k == "top" and "builtin_type" in v.facts))


def join(a, b):
    if a is None:
        return b
    if b is None or a is b:
        return a
    if a.k == "exact" and b.k == "exact":
        u = a.x | b.x
        if len(u) > MAX_SET:
            return OPAQUE
        try:
            if _tkeys(u) != _tkeys(a.x) | _tkeys(b.x):
                return OPAQUE   # F1: {True} | {1} == {True}; the joined value is not a precise literal set
        except TypeError:
            return OPAQUE
        return V("exact", u)
    if a.k in SCALAR_SAFE and b.k in SCALAR_SAFE:
        return OPAQUE
    if a.k == "top" or b.k == "top":
        if a.k == "top" and b.k == "top":
            return top(a.facts & b.facts)
        other = b if a.k == "top" else a
        t = a if a.k == "top" else b
        if other.k in SCALAR_SAFE:
            return t  # literal values are builtin-typed and carry no outside data
        return TOP
    if a.k == b.k == "list" and len(a.x) == len(b.x):
        return V("list", tuple(join(p, q) for p, q in zip(a.x, b.x)))
    if a.k == b.k == "dict" and [_tkey(k) for k, _ in a.x] == [_tkey(k) for k, _ in b.x]:
        return V("dict", tuple((k, join(p, q)) for (k, p), (_, q) in zip(a.x, b.x)))
    if a.k == b.k == "cfg":
        ka = [k for k, _ in a.x[0]]
        kb = [k for k, _ in b.x[0]]
        if ka == kb and a.x[2] == b.x[2]:
            return V("cfg", (tuple((k, join(p, q)) for (k, p), (_, q) in zip(a.x[0], b.x[0])),
                             a.x[1] or b.x[1], a.x[2]))
        return TOP
    if a.k == b.k and a.k in ("mod", "ext", "builtin", "fh", "repo", "inst") and a.x == b.x:
        return a
    if a.k == b.k and a.k in ("pfunc", "pclass", "obj") and a.x[1] is b.x[1]:
        return a
    if a.k == b.k == "bmeth" and a.x[1] is b.x[1] and a.x[0].x[1] is b.x[0].x[1]:
        return a
    if a.k == b.k == "url" and a.x[1] == b.x[1] and a.x[0] is b.x[0]:
        return a
    return TOP


def join_env(envs):
    envs = [e for e in envs if e is not None]
    if not envs:
        return None
    if len(envs) == 1:
        return dict(envs[0])
    keys = []
    seen = set()
    for e in envs:
        for k in e:
            if k not in seen:
                seen.add(k)
                keys.append(k)
    out = {}
    for k in keys:
        acc = None
        missing = False
        for e in envs:
            if k in e:
                acc = join(acc, e[k])
            else:
                missing = True
        out[k] = TOP if missing else acc
    return out


def truth(v):
    if v is None or v.k != "exact" or not v.x:
        return None
    ts = {bool(x) for x in v.x}
    return ts.pop() if len(ts) == 1 else None


class PathRaise(Exception):
    """The current path definitely raises."""


# ---------------------------------------------------------------------------
# library knowledge (documented stdlib behaviour only)
# ---------------------------------------------------------------------------

PURE_EXT = {
    "base64.b64encode": base64.b64encode, "base64.b64decode": base64.b64decode,
    "base64.urlsafe_b64encode": base64.urlsafe_b64encode, "base64.urlsafe_b64decode": base64.urlsafe_b64decode,
    "base64.standard_b64encode": base64.standard_b64encode, "base64.standard_b64decode": base64.standard_b64decode,
    "html.escape": _html.escape, "html.unescape": _html.unescape,
}


def _abspath(p):
    if not isinstance(p, str) or not p.startswith("/"):
        raise ValueError("cwd-relative")
    return posixpath.normpath(p)


# POSIX os.path semantics (Python docs, os.path / posixpath)
OS_PATH = {
    "os.path.join": posixpath.join, "os.path.dirname": posixpath.dirname, "os.path.basename": posixpath.basename,
    "os.path.normpath": posixpath.normpath, "os.path.abspath": _abspath, "os.path.realpath": _abspath,
    "posixpath.join": posixpath.join, "posixpath.dirname": posixpath.dirname,
}
ENV_EXT_CALLS = {"platform.system", "platform.machine", "platform.release"}
ENV_EXT_ATTRS = {"os.name", "sys.platform", "os.sep", "os.linesep", "os.pathsep", "sys.prefix", "sys.base_prefix",
                 "sys.exec_prefix", "sys.base_exec_prefix", "sys.executable"}   # Python docs: host/installation values
URLPARSE = {"urllib.parse.urlparse", "urllib.parse.urlsplit"}
# urllib.parse.quote/unquote are pure too, but are not folded exactly: they return a value built only from their
# arguments, so untainted arguments give an untainted (opaque) result (rule in Interp.apply)
STRING_PURE_EXT = {"urllib.parse.quote", "urllib.parse.quote_plus", "urllib.parse.unquote",
                   "urllib.parse.unquote_plus"}
CONFIGPARSER = {"configparser.ConfigParser", "configparser.RawConfigParser", "configparser.SafeConfigParser"}
STR_METHODS = {
    "capitalize", "casefold", "center", "count", "encode", "decode", "endswith", "find", "index",
    "isalnum", "isalpha", "isdigit", "isnumeric", "isdecimal", "isidentifier", "islower", "isupper",
    "isspace", "ljust", "lower", "lstrip", "partition", "removeprefix", "removesuffix", "replace",
    "rfind", "rindex", "rjust", "rpartition", "rsplit", "rstrip", "split", "splitlines", "startswith",
    "strip", "swapcase", "title", "upper", "zfill", "join", "format",
}
SCALAR_RESULT_METHODS = {
    "count", "endswith", "find", "index", "isalnum", "isalpha", "isdigit", "isnumeric", "isdecimal",
    "isidentifier", "islower", "isupper", "isspace", "rfind", "rindex", "startswith",
}
SAFE_BUILTINS = {"str", "int", "float", "bool", "len", "repr", "list", "dict", "tuple", "isinstance",
                 "abs", "min", "max", "ord", "chr", "hex", "range", "sorted", "print", "type", "open"}
READ_MODES = {"r", "rt", "tr", "rb", "br"}

_PERCENT_DIRECTIVE = re.compile(
    r"%(?:\((?P<key>[^)]*)\))?[#0\- +]*(?P<width>\*|\d+)?"
    r"(?:\.(?P<precision>\*|\d+))?[hlL]?(?P<kind>[diouxXeEfFgGcrsa%])")
_NUMERIC_FORMAT_SPEC = re.compile(r"(?:.?[<>=^])?[+\- ]?z?#?0?\d*[,_]?(?:\.\d+)?[bdoxXeEfFgGn%]", re.S)
_NUMERIC_PERCENT_KINDS = frozenset("diouxXeEfFgG")
_FIELD_HEAD = re.compile(r"[^.\[]*")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DIGITS = re.compile(r"\d+")


def _bounded_mod(fmt, args):
    """Refuse '%' formatting that could allocate more than MAX_LEN before evaluation."""
    text = fmt if isinstance(fmt, str) else fmt.decode("latin-1")
    for m in _PERCENT_DIRECTIVE.finditer(text):
        for g in (m.group("width"), m.group("precision")):
            if g == "*" or (g and int(g) > MAX_LEN):
                raise ValueError("unbounded width")
    return fmt % args


def _bounded_format(fmt, *a, **k):
    try:
        fields = list(string.Formatter().parse(fmt))
    except ValueError:
        raise ValueError("bad format")
    for _, field, spec, _ in fields:
        if spec and ("{" in spec or any(int(d) > MAX_LEN for d in _DIGITS.findall(spec))):
            raise ValueError("unbounded spec")
    return fmt.format(*a, **k)


def _str_method_bounded(x, m, args, kws):
    if m in ("center", "ljust", "rjust", "zfill"):
        if not args or not isinstance(args[0], int) or args[0] > MAX_LEN:
            raise ValueError("unbounded width")
    if m == "join":
        seq = args[0] if args else ()
        if not isinstance(seq, (tuple, str, bytes)):
            raise ValueError("join")
        total = len(x) * max(len(seq) - 1, 0) + sum(len(s) if isinstance(s, (str, bytes)) else 0 for s in seq)
        if total > MAX_LEN:
            raise ValueError("join too long")
    if m == "replace" and len(args) >= 2 and isinstance(args[0], (str, bytes)) and isinstance(args[1], (str, bytes)):
        count = (len(x) + 1) if len(args[0]) == 0 else x.count(args[0])
        if len(x) + count * max(len(args[1]) - len(args[0]), 0) > MAX_LEN:
            raise ValueError("replace too long")
    if m == "format":
        return _bounded_format(x, *args, **kws)
    return getattr(x, m)(*args, **kws)


def _product(lists):
    out = [()]
    for lst in lists:
        out = [o + (x,) for o in out for x in lst]
        if len(out) > MAX_SET:
            raise ValueError("too many")
    return out


def _cmp(op, a, b):
    if isinstance(op, ast.Eq):
        return a == b
    if isinstance(op, ast.NotEq):
        return a != b
    if isinstance(op, ast.Lt):
        return a < b
    if isinstance(op, ast.LtE):
        return a <= b
    if isinstance(op, ast.Gt):
        return a > b
    if isinstance(op, ast.GtE):
        return a >= b
    if isinstance(op, ast.In):
        return a in b
    if isinstance(op, ast.NotIn):
        return a not in b
    if isinstance(op, (ast.Is, ast.IsNot)):
        # identity is defined by the language only for the singletons None/True/False/Ellipsis; for ints and strings
        # it depends on CPython caching and interning, which differ between this process and the analysed program
        singletons = (type(None), bool, type(Ellipsis))
        if not (isinstance(a, singletons) or isinstance(b, singletons)):
            raise ValueError("identity of non-singleton literals is implementation-defined")
        return (a is b) if isinstance(op, ast.Is) else (a is not b)
    raise ValueError


def _binop(op, a, b):
    import operator as o
    if isinstance(op, ast.Mult):
        if isinstance(a, int) and isinstance(b, int) and not isinstance(a, bool) and not isinstance(b, bool):
            if a.bit_length() + b.bit_length() > MAX_INT_BITS:
                raise ValueError("big int")
        for s, n in ((a, b), (b, a)):
            if isinstance(s, (str, bytes, tuple)):
                if not isinstance(n, int) or n * max(len(s), 1) > MAX_LEN:
                    raise ValueError("too long")
    if isinstance(op, ast.Add) and isinstance(a, (str, bytes, tuple)) and isinstance(b, (str, bytes, tuple)):
        if len(a) + len(b) > MAX_LEN:
            raise ValueError("too long")
    if isinstance(op, ast.Mod) and isinstance(a, (str, bytes)):
        return _bounded_mod(a, b)
    table = {ast.Add: o.add, ast.Sub: o.sub, ast.Mult: o.mul, ast.Div: o.truediv, ast.FloorDiv: o.floordiv,
             ast.Mod: o.mod, ast.BitAnd: o.and_, ast.BitOr: o.or_, ast.BitXor: o.xor}
    r = table[type(op)](a, b)
    if isinstance(r, (str, bytes)) and len(r) > MAX_LEN:
        raise ValueError
    if isinstance(r, int) and not isinstance(r, bool) and r.bit_length() > MAX_INT_BITS:
        raise ValueError
    return r


def literal_value(node):
    """Immutable literal (str/bytes/int/float/bool/None/tuple of those) as exact, else None."""
    try:
        v = ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return None
    if isinstance(v, (str, bytes, int, float, bool, type(None))):
        return exact(v)
    if isinstance(v, tuple) and all(isinstance(x, (str, bytes, int, float, bool, type(None))) for x in v):
        return exact(v)
    return None


def dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        b = dotted_name(node.value)
        return f"{b}.{node.attr}" if b else None
    return None


def chain_root(node):
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _call_name(call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _parents(tree):
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node


def enclosing_scope(node):
    """Innermost FunctionDef/AsyncFunctionDef or the Module; None inside class bodies, lambdas, comprehensions."""
    cur = getattr(node, "parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return cur
        if isinstance(cur, (ast.Lambda, ast.ClassDef, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return None
        cur = getattr(cur, "parent", None)
    return None


def is_dunder(name):
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def mangle_sensitive(name):
    """A private name `__x` (mangled to `_C__x` inside class C) or a spelling `_C__x` that `__x` inside class C
    refers to (Python Language Reference, "Identifiers (Names)", private name mangling). Dunders are never mangled."""
    if is_dunder(name):
        return False
    return name.startswith("__") or "__" in name.lstrip("_")


# ---------------------------------------------------------------------------
# Skylos 5.7.0 html_context.split_parts (ported verbatim in behaviour)
# ---------------------------------------------------------------------------

def _is_literal(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_literal_format(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
            and _is_literal(node.func.value))


def _numeric_spec(spec):
    if not isinstance(spec, ast.JoinedStr):
        return False
    if not all(_is_literal(v) for v in spec.values):
        return False
    return bool(_NUMERIC_FORMAT_SPEC.fullmatch("".join(v.value for v in spec.values)))


def _joined_parts(node):
    parts = []
    for value in node.values:
        if _is_literal(value):
            parts.append(("text", value.value))
        elif isinstance(value, ast.FormattedValue):
            parts.append(("value", (value.value,), value.conversion == -1 and _numeric_spec(value.format_spec)))
    return parts


def _percent_parts(template, operand):
    positional = None
    if isinstance(operand, ast.Tuple) and not any(isinstance(e, ast.Starred) for e in operand.elts):
        positional = list(operand.elts)
    keyed = None
    if isinstance(operand, ast.Dict) and all(k is not None and _is_literal(k) for k in operand.keys):
        keyed = {k.value: v for k, v in zip(operand.keys, operand.values)}
    parts = []
    index = 0
    position = 0
    for match in _PERCENT_DIRECTIVE.finditer(template):
        literal = template[position:match.start()]
        if "%" in literal:
            return [("text", template), ("value", (operand,), False)]
        parts.append(("text", literal))
        position = match.end()
        kind = match.group("kind")
        if kind == "%":
            parts.append(("text", "%"))
            continue
        index += [match.group("width"), match.group("precision")].count("*")
        key = match.group("key")
        node = operand
        if key is not None and keyed is not None:
            node = keyed.get(key, operand)
        elif key is None and positional is not None and index < len(positional):
            node = positional[index]
        index += 1
        parts.append(("value", (node,), kind in _NUMERIC_PERCENT_KINDS))
    if "%" in template[position:]:
        return [("text", template), ("value", (operand,), False)]
    parts.append(("text", template[position:]))
    return parts


def _format_parts(template, call):
    every = [a.value if isinstance(a, ast.Starred) else a for a in call.args] + [kw.value for kw in call.keywords]
    splatted = any(isinstance(a, ast.Starred) for a in call.args) or any(kw.arg is None for kw in call.keywords)
    try:
        fields = list(string.Formatter().parse(template))
    except ValueError:
        return [("text", template), ("value", tuple(every), False)]
    parts = []
    automatic = 0
    for literal, field, spec, conversion in fields:
        if literal:
            parts.append(("text", literal))
        if field is None:
            continue
        head = _FIELD_HEAD.match(field).group(0)
        node = None
        args = call.args
        if head == "" and automatic < len(args):
            node = args[automatic]
        elif head.isdigit() and int(head) < len(args):
            node = args[int(head)]
        else:
            for kw in call.keywords:
                if head and kw.arg == head:
                    node = kw.value
        if head == "":
            automatic += 1
        nodes = every
        if node is not None and not splatted:
            nodes = [node.value if isinstance(node, ast.Starred) else node]
        numeric = conversion is None and bool(spec) and "{" not in spec and bool(_NUMERIC_FORMAT_SPEC.fullmatch(spec))
        parts.append(("value", tuple(nodes), numeric))
    return parts


def _builds_string(node):
    return (isinstance(node, ast.JoinedStr)
            or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))
            or _is_literal_format(node))


def _expand(item, stack):
    if _is_literal(item):
        return [("text", item.value)]
    if isinstance(item, ast.JoinedStr):
        return _joined_parts(item)
    if _is_literal_format(item):
        return _format_parts(item.func.value.value, item)
    if isinstance(item, ast.BinOp) and isinstance(item.op, ast.Mod):
        if _is_literal(item.left):
            return _percent_parts(item.left.value, item.right)
        stack.append(("value", (item.right,), False))
        stack.append(item.left)
        return []
    if isinstance(item, ast.BinOp) and isinstance(item.op, ast.Add):
        stack.append(item.right)
        stack.append(item.left)
        return []
    return [("value", (item,), False)]


def split_parts(node):
    if not _builds_string(node):
        return None
    parts = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, tuple):
            parts.append(item)
        else:
            parts.extend(_expand(item, stack))
    return parts


# ---------------------------------------------------------------------------
# project index
# ---------------------------------------------------------------------------

class ModInfo:
    __slots__ = ("globals", "star", "dyn", "dels", "exec_default")

    def __init__(self):
        self.globals = set()      # names declared global/nonlocal in any function of the module
        self.star = False         # from x import *
        self.dyn = False          # globals()/vars()/locals() anywhere in the module
        self.dels = set()         # del NAME at module level
        self.exec_default = False  # exec/eval without an explicit namespace (runs in this module's globals)


class Index:
    def __init__(self):
        self.attr_stores_nonself = {}   # attr name -> count (receiver not the self/cls parameter)
        self.attr_stores_all = {}       # attr name -> count (any receiver)
        self.setattr_const = set()      # literal names passed to setattr/delattr (any receiver)
        self.setattr_dynamic = []       # (rel, call, selflike) setattr/delattr with a non-literal name
        self.dict_writes_nonself = 0    # mutation through X.__dict__ / vars(X)
        self.dict_writes_self = 0
        self.dict_writes_loader = 0     # inside PEP 302/451 loader methods (namespace of the module being loaded)
        self.dict_dynamic_loads = 0     # X.__dict__[non-literal] / vars(X)[non-literal]
        self.reload_calls = 0
        self.sysmod_stores = []         # (rel, line, in_loader)
        self.exec_ns = []               # (rel, line, in_loader, ns_class)
        self.dynamic_code = []          # (rel, line, callee)
        self.getattr_dynamic = []       # (rel, call)
        self.str_words = set()
        self.mod_info = {}
        self.class_defs = {}            # class name -> [(rel, ClassDef)]
        self.import_targets = set()     # rels of project modules named by an import statement
        self.yaml_tamper = []           # (rel, line, why)
        self.globals_anywhere = False   # globals()/vars() anywhere (strict mode)
        self.dunder_dict_anywhere = 0   # any X.__dict__ use (strict mode)
        self.ext_mut = set()            # dotted paths of imported objects stored to / mutated in place
        self.env_writes = []            # (rel, key node or None, value node or None) with a non-literal value
        self.setattr_unknown = 0        # X.__setattr__(...) / aliased setattr: name not analysable
        self.getattr_alias = 0          # getattr / attrgetter used as a value
        self.ns_reflect = []            # (rel, line, why): a namespace read by computed name (IPCP gate C8)


class Project:
    def __init__(self, repo, cfg):
        self.repo = Path(repo)
        self.root = self.repo.resolve()
        self.cfg = cfg
        self._ast = {}
        self._mods = {}
        self._files = None
        self._index = None
        self._ref_cache = {}
        self._text_words = None
        self._gv_cache = {}
        self._gv_stack = set()
        self._setattr_names_cache = None
        self._text_cache = {}
        self._ext_cache = {}
        self._bind_cache = {}
        self.engine = None

    # ---- files ----
    def py_files(self):
        if self._files is None:
            out = []
            for p in sorted(self.root.rglob("*.py")):
                rel = p.relative_to(self.root)
                if any(part.startswith(".") for part in rel.parts[:-1]):
                    continue
                if p.is_file():
                    out.append(rel.as_posix())
            self._files = out
        return self._files

    def rel(self, path):
        p = Path(path)
        if not p.is_absolute():
            p = self.root / p
        try:
            return p.resolve().relative_to(self.root).as_posix()
        except (ValueError, OSError):
            return None

    def parse(self, rel):
        if rel not in self._ast:
            tree = None
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    tree = ast.parse((self.root / rel).read_text(encoding="utf-8", errors="replace"))
                _parents(tree)
            except (SyntaxError, ValueError, OSError, RecursionError, MemoryError):
                tree = None
            self._ast[rel] = tree
        return self._ast[rel]

    def text(self, rel):
        if rel not in self._text_cache:
            try:
                self._text_cache[rel] = (self.root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                self._text_cache[rel] = ""
        return self._text_cache[rel]

    # ---- modules ----
    def resolve_module(self, dotted):
        """('file', rel) | ('pkg', reldir) | None, searching the import roots '' and 'src'."""
        if not dotted:
            return None
        if dotted in self._mods:
            return self._mods[dotted]
        out = None
        parts = dotted.split(".")
        for root in ("", "src"):
            base = self.root.joinpath(root, *parts) if root else self.root.joinpath(*parts)
            if base.with_suffix(".py").is_file():
                out = ("file", self.rel(base.with_suffix(".py")))
            elif (base / "__init__.py").is_file():
                out = ("file", self.rel(base / "__init__.py"))
            elif base.is_dir():
                out = ("pkg", self.rel(base))
            if out:
                break
        self._mods[dotted] = out
        return out

    def module_name(self, rel):
        parts = list(Path(rel).with_suffix("").parts)
        if parts and parts[0] == "src" and len(parts) > 1:
            parts = parts[1:]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)

    def absolute_import(self, rel, module, level):
        if not level:
            return module or ""
        pkg = self.module_name(rel).split(".") if self.module_name(rel) else []
        if not rel.endswith("__init__.py"):
            pkg = pkg[:-1]
        if level - 1 > len(pkg):
            return None
        base = pkg[:len(pkg) - (level - 1)] if level > 1 else pkg
        return ".".join(base + ([module] if module else []))

    def shadowed(self, dotted):
        """Conservative loadable-shadow test: any file in the checkout that could be imported as `dotted`
        or as one of its parent packages, from any directory (sys.path may point anywhere in the checkout)."""
        parts = dotted.split(".")
        cands = {"/".join(parts[:i]) for i in range(1, len(parts) + 1)}
        for rel in self.py_files():
            stem = rel[:-3]
            if stem == "__init__":
                continue
            if stem.endswith("/__init__"):
                stem = stem[: -len("/__init__")]
            for c in cands:
                if stem == c or stem.endswith("/" + c):
                    return True
        for pattern in ("*.so", "*.pyd"):
            for p in sorted(self.root.rglob(pattern)):
                if p.name.split(".")[0] == parts[0]:
                    return True
        return False

    # ---- index ----
    def index(self):
        if self._index is None:
            idx = Index()
            for rel in self.py_files():
                tree = self.parse(rel)
                if tree is None:
                    continue
                _Indexer(self, rel, idx).run(tree)
            self._index = idx
        return self._index

    def setattr_dynamic_names(self):
        """Union of the names a non-literal setattr/delattr can write (bs mode, evaluated by SCCP), or
        None when one of them is not an exact set."""
        if self._setattr_names_cache == "computing":
            return None
        if self._setattr_names_cache is None:
            self._setattr_names_cache = "computing"
            idx = self.index()
            names = set()
            ok = True
            for rel, call, selflike in idx.setattr_dynamic:
                if selflike:
                    continue
                v = self.engine.eval_at(rel, call.args[1]) if len(call.args) >= 2 else TOP
                if v is None or v.k != "exact" or not all(isinstance(x, str) for x in v.x):
                    ok = False
                    break
                names |= set(v.x)
            self._setattr_names_cache = (names if ok else None,)
        return self._setattr_names_cache[0]

    # ---- binding stability (README "BS standard") ----
    def project_name_stable(self, name):
        """No code in the project can rebind attribute `name` of a module object."""
        idx = self.index()
        if idx.attr_stores_nonself.get(name) or name in idx.setattr_const:
            return False
        if idx.reload_calls or idx.dict_writes_nonself or idx.setattr_unknown:
            return False
        if self.cfg.mssa == "strict":
            if idx.sysmod_stores or idx.globals_anywhere or idx.dunder_dict_anywhere or idx.dict_writes_loader:
                return False
            if any(not sl for _, _, sl in idx.setattr_dynamic):
                return False
            if any(c not in ("fresh",) for _, _, _, c in idx.exec_ns):
                return False
            return True
        if any(not inl for _, _, inl in idx.sysmod_stores):
            return False
        if any((c in ("module_dict", "unknown")) and not inl for _, _, inl, c in idx.exec_ns):
            return False
        names = self.setattr_dynamic_names()
        if names is None or name in names:
            return False
        return True

    def module_stable(self, rel, name):
        idx = self.index()
        mi = idx.mod_info.get(rel)
        if mi is None or mi.star or mi.dyn or mi.exec_default:
            return False
        if name in mi.globals or name in mi.dels:
            return False
        if any(r == rel and c == "globals" for r, _, _, c in idx.exec_ns):
            return False
        return self.project_name_stable(name)

    def method_name_stable(self, name):
        """No instance or class attribute named `name` can be stored anywhere (shadowing a method)."""
        idx = self.index()
        if idx.attr_stores_all.get(name) or name in idx.setattr_const or idx.setattr_unknown:
            return False
        if idx.dict_writes_nonself or idx.dict_writes_self or idx.dict_writes_loader or idx.reload_calls:
            return False
        if idx.setattr_dynamic:
            if self.cfg.mssa == "strict":
                return False
            for rel, call, selflike in idx.setattr_dynamic:
                v = self.engine.eval_at(rel, call.args[1]) if len(call.args) >= 2 else TOP
                if v is None or v.k != "exact" or name in v.x or not all(isinstance(x, str) for x in v.x):
                    return False
        return True

    def module_bindings(self, rel, name):
        key = (rel, name)
        if key not in self._bind_cache:
            self._bind_cache[key] = self._module_bindings(rel, name)
        return self._bind_cache[key]

    def _module_bindings(self, rel, name):
        tree = self.parse(rel)
        if tree is None:
            return None
        binds = []
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and stmt.name == name:
                binds.append(("func" if not isinstance(stmt, ast.ClassDef) else "class", stmt))
            elif isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del)):
                            binds.append(("assign", stmt) if isinstance(t, ast.Name) else ("other", stmt))
            elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)) and isinstance(stmt.target, ast.Name) \
                    and stmt.target.id == name:
                if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                    binds.append(("assign", stmt))
                elif isinstance(stmt, ast.AugAssign):
                    binds.append(("other", stmt))
            elif isinstance(stmt, ast.Import):
                for a in stmt.names:
                    local = a.asname or a.name.split(".")[0]
                    if local == name:
                        binds.append(("import", a.name if a.asname else a.name.split(".")[0]))
            elif isinstance(stmt, ast.ImportFrom):
                for a in stmt.names:
                    if a.name == "*":
                        continue
                    if (a.asname or a.name) == name:
                        binds.append(("from", (self.absolute_import(rel, stmt.module, stmt.level), a.name)))
            else:
                for n in ast.walk(stmt):
                    if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del)):
                        binds.append(("other", stmt))
                    elif isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and n.name == name:
                        binds.append(("other", stmt))
                    elif isinstance(n, (ast.Import, ast.ImportFrom)):
                        for a in n.names:
                            if (a.asname or a.name.split(".")[0]) == name:
                                binds.append(("other", stmt))
                    elif isinstance(n, ast.NamedExpr) and n.target.id == name:
                        binds.append(("other", stmt))
        return binds

    def global_value(self, rel, name):
        """Value of module global `name` of module `rel` under binding stability, else TOP.
        None when the module has no binding at all (builtin lookup applies)."""
        key = (rel, name)
        if key in self._gv_cache:
            return self._gv_cache[key]
        if key in self._gv_stack:
            return TOP
        self._gv_stack.add(key)
        try:
            v = self._global_value(rel, name)
        finally:
            self._gv_stack.discard(key)
        self._gv_cache[key] = v
        return v

    def _global_value(self, rel, name):
        binds = self.module_bindings(rel, name)
        if binds is None:
            return TOP
        if not binds:
            return None
        if len(binds) > 1 and all(k == "import" for k, _ in binds) and len({o for _, o in binds}) == 1:
            binds = binds[:1]   # import a.b; import a.c  both bind `a` to the same package object
        if len(binds) != 1 or not self.module_stable(rel, name):
            return TOP
        kind, obj = binds[0]
        modname = self.module_name(rel)
        if kind == "func":
            return V("pfunc", (modname, obj, rel))
        if kind == "class":
            return V("pclass", (modname, obj, rel))
        if kind == "import":
            return self.import_value(obj)
        if kind == "from":
            mod, attr = obj
            if mod is None:
                return TOP
            return self.from_value(mod, attr)
        if kind == "assign":
            value = obj.value
            lv = literal_value(value)
            if lv is not None:
                # T8 (sec-context review): module constants feed operands but never fold branches
                return OPAQUE
            if isinstance(value, ast.Call) and not any(isinstance(a, ast.Starred) for a in value.args):
                callee = self.static_identity(rel, value.func)
                if callee is not None and callee.k == "ext" and callee.x in RUAMEL_YAML_CLASSES:
                    if self.ruamel_global_uses_ok(rel, name):
                        return V("inst", ("ruamel.yaml.YAML", ruamel_ctor_ok(value)))
                    return TOP
            return TOP
        return TOP

    def import_value(self, dotted):
        if self.resolve_module(dotted.split(".")[0]):
            return V("mod", dotted) if self.resolve_module(dotted) else TOP
        if not self.ext_attr_stable(dotted):
            return TOP
        return V("ext", dotted)

    def from_value(self, mod, attr):
        if self.resolve_module(mod.split(".")[0]):
            mf = self.resolve_module(mod)
            if mf is None:
                return TOP
            if self.resolve_module(f"{mod}.{attr}"):
                return V("mod", f"{mod}.{attr}")
            if mf[0] == "file":
                v = self.global_value(mf[1], attr)
                return TOP if v is None else v
            return TOP
        dotted = f"{mod}.{attr}"
        if not self.ext_attr_stable(dotted):
            return TOP
        return V("ext", dotted)

    def ext_attr_stable(self, dotted):
        """An imported object `dotted` (e.g. yaml.SafeLoader, html.escape, os.path.join) is trusted only if no
        project store or in-place mutation targets it, one of its prefixes, or (for non-module attributes,
        two or more components) one of its own attributes."""
        if dotted in self._ext_cache:
            return self._ext_cache[dotted]
        ok = True
        for t in self.index().ext_mut:
            if t.endswith(".*"):
                b = t[:-2]
                if dotted == b or dotted.startswith(b + ".") or (b.startswith(dotted + ".") and "." in dotted):
                    ok = False
                    break
            elif t == dotted or dotted.startswith(t + ".") or (t.startswith(dotted + ".") and "." in dotted):
                ok = False
                break
        self._ext_cache[dotted] = ok
        return ok

    def static_identity(self, rel, node):
        """Identity of a module-level expression (Name / dotted Attribute) by module bindings only."""
        if isinstance(node, ast.Name):
            v = self.global_value(rel, node.id)
            return v
        if isinstance(node, ast.Attribute):
            b = self.static_identity(rel, node.value)
            if b is None:
                return None
            if b.k == "ext":
                d = f"{b.x}.{node.attr}"
                return V("ext", d) if self.ext_attr_stable(d) else TOP
            if b.k == "mod":
                d = f"{b.x}.{node.attr}"
                if self.resolve_module(d):
                    return V("mod", d)
                mf = self.resolve_module(b.x)
                if mf and mf[0] == "file":
                    v = self.global_value(mf[1], node.attr)
                    return TOP if v is None else v
            return TOP
        return None

    def ruamel_global_uses_ok(self, rel, name):
        """A module-global ruamel YAML instance is used only through documented, non-loading-configuring
        methods and output settings, and no other module reaches it."""
        tree = self.parse(rel)
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load):
                par = getattr(n, "parent", None)
                if not (isinstance(par, ast.Attribute) and par.value is n):
                    return False
                gp = getattr(par, "parent", None)
                if isinstance(par.ctx, ast.Store):
                    if par.attr not in RUAMEL_OK_SETTINGS:
                        return False
                elif isinstance(gp, ast.Call) and gp.func is par:
                    if par.attr not in RUAMEL_OK_METHODS:
                        return False
                else:
                    return False
        modname = self.module_name(rel)
        for other in self.py_files():
            if other == rel:
                continue
            t = self.parse(other)
            if t is None:
                continue
            for n in ast.walk(t):
                if isinstance(n, ast.ImportFrom):
                    target = self.absolute_import(other, n.module, n.level)
                    if target == modname and any(a.name in (name, "*") for a in n.names):
                        return False
                elif isinstance(n, ast.Attribute) and n.attr == name:
                    d = dotted_name(n.value)
                    if d and (d == modname or d.endswith("." + modname.split(".")[-1])):
                        return False
        return True

    # ---- IPCP helpers ----
    def name_refs(self, name):
        """(callee_only, call_sites) over all Python files: every Name/Attribute named `name` must be the
        func of a Call (or the def itself); also returns every such Call."""
        if name in self._ref_cache:
            return self._ref_cache[name]
        ok = True
        sites = []
        for rel in self.py_files():
            tree = self.parse(rel)
            if tree is None:
                if name in self.text(rel):
                    ok = False
                continue
            for n in ast.walk(tree):
                if isinstance(n, ast.Name) and n.id == name:
                    par = getattr(n, "parent", None)
                    if isinstance(par, ast.Call) and par.func is n and isinstance(n.ctx, ast.Load):
                        sites.append((rel, par))
                    else:
                        ok = False
                elif isinstance(n, ast.Attribute) and n.attr == name:
                    par = getattr(n, "parent", None)
                    if isinstance(par, ast.Call) and par.func is n and isinstance(n.ctx, ast.Load):
                        sites.append((rel, par))
                    else:
                        ok = False
                elif isinstance(n, ast.alias) and (n.name.split(".")[-1] == name or n.asname == name):
                    if n.asname and n.asname != name:
                        ok = False
                elif isinstance(n, ast.keyword) and n.arg == name:
                    pass
        self._ref_cache[name] = (ok, sites)
        return self._ref_cache[name]

    def word_in_non_python(self, word):
        if self._text_words is None:
            words = []
            for p in sorted(self.root.rglob("*")):
                try:
                    rel = p.relative_to(self.root)
                except ValueError:
                    continue
                if any(part.startswith(".") for part in rel.parts[:-1]) or p.suffix == ".py" or not p.is_file():
                    continue
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                if size > BIG_TEXT:
                    words.append((p, None))
                    continue
                try:
                    data = p.read_bytes()
                except OSError:
                    continue
                if b"\x00" in data[:8192]:
                    continue
                words.append((p, set(_WORD.findall(data.decode("utf-8", errors="replace")))))
            self._text_words = words
        pat = re.compile(rb"(?<![A-Za-z0-9_])" + re.escape(word.encode()) + rb"(?![A-Za-z0-9_])")
        for p, ws in self._text_words:
            if ws is None:
                try:
                    if pat.search(p.read_bytes()):
                        return True
                except OSError:
                    return True
            elif word in ws:
                return True
        return False


class _Indexer:
    """One pass over a module collecting the facts the stability and closed-world gates need."""

    MUTATORS = {"update", "setdefault", "pop", "popitem", "clear", "append", "extend", "insert", "remove",
                "add", "discard", "__setitem__", "__delitem__", "__setattr__", "__delattr__"}

    def __init__(self, project, rel, idx):
        self.p = project
        self.rel = rel
        self.idx = idx
        self.mi = ModInfo()
        idx.mod_info[rel] = self.mi
        self.yaml_roots = set()
        self.import_map = {}      # local name -> dotted module path it is bound to by an import

    def run(self, tree):
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    local = a.asname or a.name.split(".")[0]
                    self.import_map[local] = a.name if a.asname else a.name.split(".")[0]
                    if a.name.split(".")[0] in ("yaml", "ruamel"):
                        self.yaml_roots.add(local)
                    mf = self.p.resolve_module(a.name)
                    if mf and mf[0] == "file":
                        self.idx.import_targets.add(mf[1])
            elif isinstance(n, ast.ImportFrom):
                mod = self.p.absolute_import(self.rel, n.module, n.level)
                for a in n.names:
                    if a.name != "*" and mod:
                        self.import_map[a.asname or a.name] = f"{mod}.{a.name}"
                if mod and mod.split(".")[0] in ("yaml", "ruamel"):
                    for a in n.names:
                        self.yaml_roots.add(a.asname or a.name)
                if mod:
                    mf = self.p.resolve_module(mod)
                    if mf and mf[0] == "file":
                        self.idx.import_targets.add(mf[1])
                    for a in n.names:
                        sub = self.p.resolve_module(f"{mod}.{a.name}")
                        if sub and sub[0] == "file":
                            self.idx.import_targets.add(sub[1])
                if any(a.name == "*" for a in n.names):
                    self.mi.star = True
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for m in ast.walk(n):
                    if isinstance(m, (ast.Global, ast.Nonlocal)):
                        self.mi.globals.update(m.names)
        self.visit(tree, func=None, selfname=None, in_loader=False)

    def visit(self, node, func, selfname, in_loader):
        """`func`, `selfname`, `in_loader` describe the scope that CONTAINS `node`'s children."""
        for child in ast.iter_child_nodes(node):
            self.check(child, node, func, selfname, in_loader)
            c_func, c_self, c_loader = func, selfname, in_loader
            if isinstance(child, ast.ClassDef):
                self.idx.class_defs.setdefault(child.name, []).append((self.rel, child))
                c_func, c_self, c_loader = None, None, False
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                c_func = child
                params = [p.arg for p in child.args.posonlyargs + child.args.args + child.args.kwonlyargs]
                if isinstance(node, ast.ClassDef):
                    deco = {dotted_name(d) for d in child.decorator_list}
                    c_self = params[0] if params and "staticmethod" not in deco else None
                    c_loader = child.name in LOADER_METHODS
                else:
                    # closure: the enclosing method's self stays visible unless shadowed by a parameter
                    c_self = selfname if selfname not in params else None
            elif isinstance(child, ast.Lambda):
                params = [p.arg for p in child.args.args]
                c_self = selfname if selfname not in params else None
            self.visit(child, c_func, c_self, c_loader)

    def _ext_path(self, expr):
        """Dotted path of the object an Attribute/Subscript chain denotes, when rooted at an import-bound
        name; subscripts denote elements, so the mutated object is the container."""
        parts = []
        node = expr
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            if isinstance(node, ast.Subscript):
                parts = []
            else:
                parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name) and node.id in self.import_map:
            return ".".join([self.import_map[node.id]] + list(reversed(parts)))
        return None

    def _env_write(self, key, value):
        if value is not None and self._literalish(value):
            return
        self.idx.env_writes.append((self.rel, key, value))

    @staticmethod
    def _literalish(node):
        try:
            ast.literal_eval(node)
            return True
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            return False

    def _mut(self, path):
        if path:
            self.idx.ext_mut.add(path)

    def _selflike(self, expr, selfname):
        return selfname is not None and isinstance(expr, ast.Name) and expr.id == selfname

    def _env_use(self, n):
        """A Load of os.environ / os.environb (or an import alias of it). Reads, copies and the documented write
        methods (handled in _check_call) are classified; any other use lets the mapping escape (an alias, an
        argument to a helper that stores into it, a return value): the environment is then written by code this
        index does not see, recorded as a write of an unknown key from unknown data."""
        par = getattr(n, "parent", None)
        if isinstance(par, ast.Subscript) and par.value is n:
            return
        if isinstance(par, ast.Attribute) and par.value is n:
            if par.attr in ENV_READ_METHODS or par.attr in ENV_WRITE_METHODS:
                return
            self._env_write(None, None)
            return
        if isinstance(par, (ast.Compare, ast.comprehension, ast.For, ast.AsyncFor)):
            return
        if isinstance(par, ast.BinOp) and isinstance(par.op, ast.BitOr):
            return   # os.environ | {...} builds a new dict
        if isinstance(par, ast.Dict) and any(k is None and v is n for k, v in zip(par.keys, par.values)):
            return   # {**os.environ, ...} copies
        if isinstance(par, ast.keyword) and par.arg == "env":
            return   # subprocess env=os.environ: the child gets a copy
        if isinstance(par, ast.Call) and n in par.args and dotted_name(par.func) in ENV_READ_FUNCS:
            return
        if isinstance(par, ast.AugAssign) and par.target is n:
            return   # handled as a write below
        self._env_write(None, None)

    def check(self, n, parent, func, selfname, in_loader):
        idx = self.idx
        if isinstance(n, (ast.Attribute, ast.Name)) and isinstance(n.ctx, ast.Load) \
                and self._ext_path(n) in ENV_MAPPINGS:
            self._env_use(n)
        if isinstance(n, ast.AugAssign) and isinstance(n.target, (ast.Attribute, ast.Name)) \
                and self._ext_path(n.target) in ENV_MAPPINGS:
            # os.environ |= mapping (PEP 584): a write of every key of the mapping
            if isinstance(n.op, ast.BitOr) and isinstance(n.value, ast.Dict) and all(k is not None for k in n.value.keys):
                for k, v in zip(n.value.keys, n.value.values):
                    self._env_write(k, v)
            else:
                self._env_write(None, None)
        if isinstance(n, ast.Attribute):
            if isinstance(n.ctx, (ast.Store, ast.Del)):
                self._mut(self._ext_path(n))
                idx.attr_stores_all[n.attr] = idx.attr_stores_all.get(n.attr, 0) + 1
                if not self._selflike(n.value, selfname):
                    idx.attr_stores_nonself[n.attr] = idx.attr_stores_nonself.get(n.attr, 0) + 1
                root = chain_root(n.value)
                if root in self.yaml_roots:
                    idx.yaml_tamper.append((self.rel, n.lineno, "store on yaml module attribute"))
                if n.attr in RUAMEL_TAMPER_ATTRS and not self._selflike(n.value, selfname):
                    idx.yaml_tamper.append((self.rel, n.lineno, f"store to .{n.attr}"))
            if n.attr in ("__globals__", "f_globals"):
                # a function's / frame's module namespace: any non-read use may rebind module globals
                idx.dunder_dict_anywhere += 1
                if self._dict_mutated(n):
                    idx.dict_writes_nonself += 1
            if n.attr in ("__setattr__", "__delattr__") and isinstance(n.ctx, ast.Load):
                idx.setattr_unknown += 1
            if isinstance(n.ctx, ast.Load) and n.attr in NS_ATTRS and self._ns_read(n):
                idx.ns_reflect.append((self.rel, n.lineno, n.attr))
            if n.attr == "__dict__":
                idx.dunder_dict_anywhere += 1
                if self._dict_mutated(n):
                    if self._selflike(n.value, selfname):
                        idx.dict_writes_self += 1
                    elif in_loader:
                        idx.dict_writes_loader += 1
                    else:
                        idx.dict_writes_nonself += 1
                if self._dynamic_subscript_load(n):
                    idx.dict_dynamic_loads += 1
            if n.attr in YAML_TAMPER_WORDS:
                idx.yaml_tamper.append((self.rel, n.lineno, n.attr))
        elif isinstance(n, ast.Name):
            if n.id in YAML_TAMPER_WORDS:
                idx.yaml_tamper.append((self.rel, n.lineno, n.id))
            if isinstance(n.ctx, ast.Load) and n.id in ("setattr", "delattr", "getattr", "exec", "eval", "compile",
                                                        "__import__", "globals", "vars", "locals"):
                callee = isinstance(parent, ast.Call) and parent.func is n
                if not callee:
                    # a reflective builtin used as a value: its later calls are not analysable
                    if n.id in ("setattr", "delattr"):
                        idx.setattr_unknown += 1
                    elif n.id == "getattr":
                        idx.getattr_alias += 1
                    elif n.id in ("globals", "vars", "locals"):
                        self.mi.dyn = True
                        idx.globals_anywhere = True
                        idx.ns_reflect.append((self.rel, n.lineno, n.id + " as a value"))
                    else:
                        idx.dynamic_code.append((self.rel, n.lineno, n.id))
        elif isinstance(n, ast.alias):
            for w in (n.name.split(".")[-1], n.asname):
                if w in YAML_TAMPER_WORDS:
                    idx.yaml_tamper.append((self.rel, 0, w))
        elif isinstance(n, ast.Subscript) and isinstance(n.ctx, (ast.Store, ast.Del)):
            self._mut(self._ext_path(n.value))
            if isinstance(n.ctx, ast.Store) and self._ext_path(n.value) in ENV_MAPPINGS:
                self._env_write(n.slice, getattr(parent, "value", None))
            root = chain_root(n.value)
            if root in self.yaml_roots:
                idx.yaml_tamper.append((self.rel, n.lineno, "subscript store on yaml module attribute"))
            if dotted_name(n.value) == "sys.modules" and isinstance(n.ctx, ast.Store):
                idx.sysmod_stores.append((self.rel, n.lineno, in_loader))
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            ws = set(_WORD.findall(n.value)) if len(n.value) <= 200000 else set()
            idx.str_words.update(ws)
            for w in sorted(ws & YAML_TAMPER_WORDS):
                idx.yaml_tamper.append((self.rel, n.lineno, w))
        elif isinstance(n, ast.Delete) and isinstance(parent, ast.Module):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    self.mi.dels.add(t.id)
        elif isinstance(n, ast.Call):
            self._check_call(n, func, selfname, in_loader)

    def _dict_mutated(self, attr_node):
        par = getattr(attr_node, "parent", None)
        if isinstance(par, ast.Subscript) and par.value is attr_node and isinstance(par.ctx, (ast.Store, ast.Del)):
            return True
        if isinstance(par, ast.Attribute) and par.value is attr_node:
            gp = getattr(par, "parent", None)
            if par.attr in ("update", "setdefault", "pop", "popitem", "clear", "__setitem__", "__delitem__") \
                    and isinstance(gp, ast.Call) and gp.func is par:
                return True
            if par.attr in ("get", "items", "keys", "values", "copy", "__contains__", "__getitem__"):
                return False
            return True
        if isinstance(par, ast.Call) and attr_node in par.args:
            fn = dotted_name(par.func)
            if fn in ("exec", "eval"):
                return False   # classified through exec_ns
            if fn in ("dict", "list", "len", "sorted", "repr", "str", "print", "isinstance", "id", "iter"):
                return False
            return True
        if isinstance(par, (ast.Compare, ast.For, ast.comprehension)):
            return False
        if isinstance(par, ast.Subscript) and par.value is attr_node:
            return False
        return True

    @staticmethod
    def _ns_read(node):
        """`node` evaluates to a namespace mapping (globals(), locals(), vars(x), x.__dict__, f.__globals__,
        frame.f_globals/f_locals) or to the bound lookup x.__getattribute__. True unless the use can only yield
        names or booleans, or only write: a constant-key subscript (a constant that names a function is caught by C1:
        the name occurs in a string), a comparison or membership test, .keys()/.update()/.clear()/__setitem__/
        __delitem__/__contains__, len()/sorted()/list()/set()/tuple()/iter() (keys only), subscript store/delete.
        Everything else (computed-key subscript, .get/.items/.values/.pop/.setdefault/.copy, iteration of items,
        passing the mapping on, calling __getattribute__) can hand out a function object under a computed name."""
        if getattr(node, "attr", None) == "__getattribute__":
            return True
        par = getattr(node, "parent", None)
        if isinstance(par, ast.Subscript) and par.value is node:
            return isinstance(par.ctx, ast.Load) and not isinstance(par.slice, ast.Constant)
        if isinstance(par, ast.Compare):
            return False
        if isinstance(par, ast.Attribute) and par.value is node:
            gp = getattr(par, "parent", None)
            called = isinstance(gp, ast.Call) and gp.func is par
            return not (called and par.attr in ("keys", "update", "clear", "__setitem__", "__delitem__",
                                                "__contains__"))
        if isinstance(par, ast.Call) and node in par.args and isinstance(par.func, ast.Name) \
                and par.func.id in ("len", "sorted", "list", "set", "tuple", "iter", "bool"):
            return False
        return True

    def _dynamic_subscript_load(self, attr_node):
        par = getattr(attr_node, "parent", None)
        return (isinstance(par, ast.Subscript) and par.value is attr_node and isinstance(par.ctx, ast.Load)
                and not isinstance(par.slice, ast.Constant))

    def _ns_class(self, node, func):
        if isinstance(node, (ast.Dict, ast.DictComp)):
            return "fresh"
        if isinstance(node, ast.Call):
            fn = dotted_name(node.func)
            if fn == "dict":
                return "fresh"
            if fn == "globals":
                return "globals"
            if fn == "vars" and node.args:
                return "module_dict"
            if fn == "locals":
                return "fresh"
            return "unknown"
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            return "module_dict"
        if isinstance(node, ast.Name):
            where = func.body if func is not None else self.p.parse(self.rel).body
            binds = []
            for st in where:
                for m in ast.walk(st):
                    if isinstance(m, ast.Name) and m.id == node.id and isinstance(m.ctx, (ast.Store, ast.Del)):
                        par = getattr(m, "parent", None)
                        if isinstance(par, ast.Assign) and len(par.targets) == 1 and par.targets[0] is m:
                            binds.append(par.value)
                        else:
                            binds.append(None)
            if len(binds) == 1 and binds[0] is not None and not isinstance(binds[0], ast.Name):
                c = self._ns_class(binds[0], func)
                return c if c in ("fresh", "globals", "module_dict") else "unknown"
            return "unknown"
        return "unknown"

    def _check_call(self, n, func, selfname, in_loader):
        idx = self.idx
        fn = dotted_name(n.func)
        if isinstance(n.func, ast.Attribute) and n.func.attr in ("update", "setdefault", "__setitem__", "__ior__") \
                and self._ext_path(n.func.value) in ENV_MAPPINGS:
            if n.func.attr in ("update", "__ior__"):
                for a in n.args:
                    if isinstance(a, ast.Dict) and all(k is not None for k in a.keys):
                        for k, v in zip(a.keys, a.values):
                            self._env_write(k, v)
                    else:
                        self._env_write(None, None)
                for kw in n.keywords:
                    self._env_write(ast.Constant(kw.arg) if kw.arg else None, kw.value)
            else:
                self._env_write(n.args[0] if n.args else None, n.args[1] if len(n.args) > 1 else ast.Constant(""))
        if fn and fn.split(".")[-1] == "putenv" and (fn == "putenv" or self._ext_path(n.func) == "os.putenv"):
            self._env_write(n.args[0] if n.args else None, n.args[1] if len(n.args) > 1 else None)
        if isinstance(n.func, ast.Attribute) and n.func.attr in self.MUTATORS:
            path = self._ext_path(n.func.value)
            if path and "." in path:
                # in-place mutation of an attribute of an import (sys.path.append, X.yaml_constructors.update);
                # a mutator-named call on a bare module (os.remove) is a module function call
                self._mut(path)
        if fn in ("setattr", "delattr"):
            if n.args:
                root = chain_root(n.args[0])
                if root in self.yaml_roots:
                    idx.yaml_tamper.append((self.rel, n.lineno, "setattr on yaml module"))
                base = self._ext_path(n.args[0])
                if base:
                    if len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str):
                        self._mut(f"{base}.{n.args[1].value}")
                    else:
                        self._mut(f"{base}.*")
            if len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str):
                idx.setattr_const.add(n.args[1].value)
                if n.args[1].value in RUAMEL_TAMPER_ATTRS:
                    idx.yaml_tamper.append((self.rel, n.lineno, "setattr ruamel attribute"))
            else:
                idx.setattr_dynamic.append((self.rel, n, bool(n.args) and self._selflike(n.args[0], selfname)))
        elif fn in ("globals", "locals") or (fn == "vars" and not n.args):
            self.mi.dyn = True
            idx.globals_anywhere = True
            if self._ns_read(n):
                idx.ns_reflect.append((self.rel, n.lineno, fn + "()"))
        elif fn == "vars" and n.args:
            idx.dunder_dict_anywhere += 1
            if self._ns_read(n):
                idx.ns_reflect.append((self.rel, n.lineno, "vars(x)"))
            par = getattr(n, "parent", None)
            if isinstance(par, ast.Subscript) and par.value is n and isinstance(par.ctx, (ast.Store, ast.Del)):
                idx.dict_writes_nonself += 1
            elif isinstance(par, ast.Attribute) and par.attr in ("update", "setdefault", "pop", "popitem", "clear"):
                idx.dict_writes_nonself += 1
            if isinstance(par, ast.Subscript) and par.value is n and isinstance(par.ctx, ast.Load) \
                    and not isinstance(par.slice, ast.Constant):
                idx.dict_dynamic_loads += 1
        elif fn in ("importlib.reload", "imp.reload", "reload"):
            idx.reload_calls += 1
        elif fn and fn.split(".")[-1] in ("getmembers", "getmembers_static"):
            idx.ns_reflect.append((self.rel, n.lineno, fn))   # inspect docs: (name, value) pairs of any object
        elif fn == "getattr" and len(n.args) >= 2 and not isinstance(n.args[1], ast.Constant):
            idx.getattr_dynamic.append((self.rel, n))
        elif fn in ("operator.attrgetter", "operator.methodcaller", "attrgetter", "methodcaller") and n.args \
                and not isinstance(n.args[0], ast.Constant):
            idx.getattr_dynamic.append((self.rel, n))
        if fn in ("exec", "eval"):
            ns = n.args[1] if len(n.args) >= 2 else None
            for kw in n.keywords:
                if kw.arg in ("globals", "locals"):
                    ns = kw.value
            if ns is None:
                if not (n.args and isinstance(n.args[0], ast.Constant)):
                    self.mi.exec_default = True
            else:
                idx.exec_ns.append((self.rel, n.lineno, in_loader, self._ns_class(ns, func)))
        if fn in DYNAMIC_CODE_CALLS or (fn and fn.endswith(".import_module")):
            if not (n.args and isinstance(n.args[0], ast.Constant)):
                idx.dynamic_code.append((self.rel, n.lineno, fn))
        if isinstance(n.func, ast.Attribute) and n.func.attr == "register_class":
            idx.yaml_tamper.append((self.rel, n.lineno, "register_class"))


def ruamel_ctor_ok(call):
    """ruamel.yaml YAML(typ=..., pure=..., output=...) builds a loader whose constructor derives from
    SafeConstructor (ruamel.yaml docs: typ 'rt' default / 'safe' / 'base'). Anything else: not credited."""
    if call.args:
        return False
    for kw in call.keywords:
        if kw.arg is None or kw.arg not in ("typ", "pure", "output"):
            return False
        if kw.arg == "typ":
            v = kw.value
            if isinstance(v, ast.Constant) and (v.value is None or v.value in RUAMEL_SAFE_TYP):
                continue
            if isinstance(v, (ast.List, ast.Tuple)) and v.elts and all(
                    isinstance(e, ast.Constant) and e.value in RUAMEL_SAFE_TYP | {"pure"} for e in v.elts) \
                    and any(e.value in RUAMEL_SAFE_TYP for e in v.elts):
                continue
            return False
        if kw.arg == "pure" and not (isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool)):
            return False
    return True


# ---------------------------------------------------------------------------
# interpreter
# ---------------------------------------------------------------------------

class Interp:
    def __init__(self, engine, rel, tree, scope, depth=0, stack=(), watch=None, module_mode=False):
        self.E = engine
        self.p = engine.p
        self.cfg = engine.cfg
        self.rel = rel
        self.tree = tree
        self.func = scope
        self.modname = self.p.module_name(rel)
        self.depth = depth
        self.stack = stack + (id(scope),)
        self.watch = watch or set()
        self.recorded = {}
        self.prevalue = {}      # watched names: value before an argument escape turned a container into TOP
        self.skipped = set()
        self.returns = None
        self.collectors = []
        self.module_mode = module_mode
        self.clobbered = False
        self.volatile = set()
        self.always_top = set()
        self.locals = set()
        body_nodes = list(ast.walk(scope))
        for n in body_nodes:
            if isinstance(n, (ast.Global, ast.Nonlocal)):
                # names this scope shares with others: any call may rebind them
                self.always_top.update(n.names)
        for n in body_nodes:
            if n is scope:
                continue
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
                              ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for m in ast.walk(n):
                    if isinstance(m, ast.Name):
                        self.volatile.add(m.id)
                    elif isinstance(m, ast.Nonlocal):
                        self.always_top.update(m.names)        # C3: nested scope writes this local
                    elif isinstance(m, ast.NamedExpr):
                        self.always_top.add(m.target.id)        # C4: comprehension walrus binds here
        for n in body_nodes:
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                self.locals.add(n.id)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    self.locals.add(a.asname or a.name.split(".")[0])
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not scope:
                self.locals.add(n.name)
        if not module_mode:
            a = scope.args
            for arg in a.posonlyargs + a.args + a.kwonlyargs:
                self.locals.add(arg.arg)
            if a.vararg:
                self.locals.add(a.vararg.arg)
            if a.kwarg:
                self.locals.add(a.kwarg.arg)
        else:
            mi = self.p.index().mod_info.get(rel)
            if mi is not None:
                self.always_top |= mi.globals
            for name in list(self.locals):
                if not self.p.project_name_stable(name):
                    self.always_top.add(name)

    # ---------------- names -----------------
    def lookup(self, name, env):
        if name in self.always_top or (self.clobbered and name not in env):
            return TOP
        if name in self.volatile:
            v = env.get(name, TOP)
            return TOP if v.k in CONTAINERS else v
        if name in env:
            return env[name]
        if name in self.locals:
            return TOP
        cur = getattr(self.func, "parent", None)
        while cur is not None and not isinstance(cur, ast.Module):
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for n in ast.walk(cur):
                    if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store):
                        return TOP
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
                        return TOP
                if name in [x.arg for x in cur.args.args + cur.args.kwonlyargs + cur.args.posonlyargs]:
                    return TOP
            cur = getattr(cur, "parent", None)
        if name == "__name__":
            return OPAQUE
        binds = self.p.module_bindings(self.rel, name)
        if name == "__file__" and not binds:
            return exact(f"{REPO_TOKEN}/{self.rel}")
        if self.module_mode:
            if binds:
                return TOP   # bound later in the module: unbound here
        else:
            sym = self.p.global_value(self.rel, name)
            if sym is not None:
                return sym
        if name in SAFE_BUILTINS and self.p.ext_attr_stable("builtins." + name):
            return V("builtin", name)
        return TOP

    def load_name_generic(self, name, env):
        v = self.lookup(name, env)
        if v.k in CONTAINERS:
            env[name] = TOP
            return TOP
        return v

    # ---------------- statements -----------------
    def exec_block(self, stmts, env):
        for s in stmts:
            if env is None:
                self.mark_skipped(s)
                continue
            for c in self.collectors:
                c.append(dict(env))
            try:
                env = self.exec_stmt(s, env)
            except PathRaise:
                env = None
            if env is not None:
                for c in self.collectors:
                    c.append(dict(env))
        return env

    def mark_skipped(self, node):
        for n in ast.walk(node):
            self.skipped.add(id(n))

    def mark_list(self, stmts):
        for st in stmts:
            self.mark_skipped(st)

    def exec_stmt(self, s, env):
        env = dict(env)
        if isinstance(s, ast.Expr):
            self.ev(s.value, env)
            return env
        if isinstance(s, ast.Assign):
            v = self.ev(s.value, env, keep_container=True)
            for t in s.targets:
                self.assign(t, v, env, s.value)
            return env
        if isinstance(s, ast.AnnAssign):
            if s.value is not None:
                v = self.ev(s.value, env, keep_container=True)
                self.assign(s.target, v, env, s.value)
            return env
        if isinstance(s, ast.AugAssign):
            rhs = self.ev(s.value, env)
            if isinstance(s.target, ast.Name):
                cur = self.lookup(s.target.id, env)
                env[s.target.id] = TOP if cur.k in CONTAINERS else self.binop(s.op, cur, rhs)
            else:
                self.assign(s.target, TOP, env, None)
            return env
        if isinstance(s, ast.Return):
            v = self.ev(s.value, env) if s.value is not None else exact(None)
            self.returns = join(self.returns, v)
            return None
        if isinstance(s, ast.Raise):
            if s.exc is not None:
                self.ev(s.exc, env)
            return None
        if isinstance(s, ast.If):
            tv = self.ev(s.test, env)
            t = truth(tv) if self.cfg.core else None
            if t is True:
                self.mark_list(s.orelse)
                return self.exec_block(s.body, env)
            if t is False:
                self.mark_list(s.body)
                return self.exec_block(s.orelse, env)
            a = self.exec_block(s.body, env)
            b = self.exec_block(s.orelse, env)
            return join_env([a, b])
        if isinstance(s, ast.Match):
            return self.exec_match(s, env)
        if isinstance(s, ast.Try) or s.__class__.__name__ == "TryStar":
            return self.exec_try(s, env)
        if isinstance(s, (ast.For, ast.AsyncFor, ast.While)):
            return self.exec_loop(s, env)
        if isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                cv = self.ev(item.context_expr, env)
                if item.optional_vars is not None:
                    bound = cv if (cv.k == "fh" and isinstance(s, ast.With)) else TOP
                    self.assign(item.optional_vars, bound, env, None)
            coll = []
            self.collectors.append(coll)
            out = self.exec_block(s.body, env)
            self.collectors.pop()
            for c in self.collectors:
                c.extend(coll)
            return join_env([out] + coll)
        if isinstance(s, ast.Import):
            for a in s.names:
                if a.asname:
                    env[a.asname] = self.p.import_value(a.name)
                else:
                    root = a.name.split(".")[0]
                    env[root] = self.p.import_value(root)
            return env
        if isinstance(s, ast.ImportFrom):
            mod = self.p.absolute_import(self.rel, s.module, s.level)
            for a in s.names:
                if a.name == "*":
                    raise _Abort("star import")
                local = a.asname or a.name
                env[local] = self.p.from_value(mod, a.name) if mod else TOP
            return env
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if self.module_mode and not s.decorator_list:
                kind = "pclass" if isinstance(s, ast.ClassDef) else "pfunc"
                env[s.name] = V(kind, (self.modname, s, self.rel))
            else:
                env[s.name] = TOP
            return env
        if isinstance(s, ast.Delete):
            for t in s.targets:
                if isinstance(t, ast.Name):
                    env.pop(t.id, None)
                else:
                    self.assign(t, TOP, env, None)
            return env
        if isinstance(s, ast.Assert):
            self.ev(s.test, env)
            return env
        if isinstance(s, (ast.Pass, ast.Break, ast.Continue, ast.Global, ast.Nonlocal)):
            return env
        for n in ast.walk(s):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                env[n.id] = TOP
        return env

    def exec_match(self, s, env):
        subj = self.ev(s.subject, env)
        if self.cfg.core and subj.k == "exact":
            idx = set()
            fallthrough = False
            for value in subj.x:
                matched = False
                for i, case in enumerate(s.cases):
                    r = self.pattern_matches(case.pattern, value)
                    if r is False:
                        continue
                    idx.add(i)
                    if r is True and case.guard is None:
                        matched = True
                        break
                if not matched:
                    fallthrough = True
            reach = idx
        else:
            reach = set(range(len(s.cases)))
            fallthrough = True
        outs = []
        for i, case in enumerate(s.cases):
            if i not in reach:
                self.mark_list(case.body)
                continue
            e = dict(env)
            for n in ast.walk(case.pattern):
                nm = getattr(n, "name", None)
                if isinstance(n, (ast.MatchAs, ast.MatchStar)) and nm:
                    e[nm] = subj if subj.k not in CONTAINERS else TOP
                elif isinstance(n, ast.MatchMapping) and n.rest:
                    e[n.rest] = TOP
            if case.guard is not None:
                self.ev(case.guard, e)
            outs.append(self.exec_block(case.body, e))
        if fallthrough:
            outs.append(env)
        return join_env(outs)

    def pattern_matches(self, pat, value):
        if isinstance(pat, ast.MatchAs) and pat.pattern is None:
            return True
        if isinstance(pat, ast.MatchValue) and isinstance(pat.value, ast.Constant):
            try:
                return bool(value == pat.value.value)
            except Exception:
                return None
        if isinstance(pat, ast.MatchSingleton):
            return value is pat.value
        if isinstance(pat, ast.MatchOr):
            rs = [self.pattern_matches(p, value) for p in pat.patterns]
            if any(r is True for r in rs):
                return True
            if all(r is False for r in rs):
                return False
            return None
        return None

    def exec_try(self, s, env):
        coll = []
        self.collectors.append(coll)
        body_out = self.exec_block(s.body, env)
        self.collectors.pop()
        for c in self.collectors:
            c.extend(coll)
        entry = join_env([env] + coll)
        outs = []
        if s.orelse:
            outs.append(self.exec_block(s.orelse, body_out) if body_out is not None else None)
        else:
            outs.append(body_out)
        for h in s.handlers:
            e = dict(entry) if entry is not None else dict(env)
            if h.type is not None:
                self.ev(h.type, e)
            if h.name:
                e[h.name] = TOP
            outs.append(self.exec_block(h.body, e))
        normal = join_env(outs)
        if s.finalbody:
            fin_in = join_env([normal, entry])
            fin_out = self.exec_block(s.finalbody, fin_in)
            if fin_out is None or normal is None:
                return None
            return join_env([fin_out])
        return normal

    def exec_loop(self, s, env):
        e = dict(env)
        assigned = set()
        mutated = set()
        for n in ast.walk(s):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                assigned.add(n.id)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
                mutated.add(n.func.value.id)
            if isinstance(n, ast.Subscript) and isinstance(n.ctx, (ast.Store, ast.Del)):
                r = chain_root(n.value)
                if r:
                    mutated.add(r)
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)):
                r = chain_root(n.value)
                if r:
                    mutated.add(r)
        for nm in assigned:
            e[nm] = TOP
        for nm in mutated:
            if nm in e and e[nm].k in CONTAINERS + ("inst",):
                e[nm] = TOP
        if isinstance(s, ast.While):
            self.ev(s.test, e)
        else:
            if isinstance(s.iter, ast.Name):
                it = self.lookup(s.iter.id, e)
                if id(s.iter) in self.watch:
                    self.recorded[id(s.iter)] = join(self.recorded.get(id(s.iter)), it)
            else:
                it = self.ev(s.iter, e, keep_container=True)
            if it.k == "exact" and all(isinstance(x, (str, tuple)) for x in it.x):
                elem = exact_set(c for x in it.x for c in x)
            elif it.k == "list" and it.x and all(v.k == "exact" for v in it.x):
                acc = None
                for v in it.x:
                    acc = join(acc, v)
                elem = acc
            elif it.k == "dict" and it.x and all(k is not None for k, _ in it.x):
                elem = exact_set(k for k, _ in it.x)
            else:
                elem = OPAQUE if untainted(it) else TOP
            self.assign(s.target, elem, e, None)
        out = self.exec_block(s.body, e)
        res = join_env([e, out])
        if s.orelse:
            res = join_env([res, self.exec_block(s.orelse, res)]) if res is not None else None
        return res

    def assign(self, target, v, env, value_node):
        if isinstance(target, ast.Name):
            env[target.id] = v
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value_node, (ast.Tuple, ast.List)) and len(value_node.elts) == len(target.elts) \
                    and not any(isinstance(x, ast.Starred) for x in target.elts + value_node.elts):
                vals = [self.ev(x, env, keep_container=True) for x in value_node.elts]
                for t, x in zip(target.elts, vals):
                    self.assign(t, x, env, None)
                return
            if v.k == "list" and len(v.x) == len(target.elts) and not any(isinstance(x, ast.Starred) for x in target.elts):
                for t, x in zip(target.elts, v.x):
                    self.assign(t, x, env, None)
                return
            elem = OPAQUE if untainted(v) else TOP
            for t in target.elts:
                self.assign(t.value if isinstance(t, ast.Starred) else t, elem, env, None)
            return
        if isinstance(target, ast.Subscript):
            if isinstance(target.value, ast.Name):
                name = target.value.id
                base = self.lookup(name, env)
                key = self.ev(target.slice, env)
                if base.k in ("dict", "list") and self.cfg.core and name not in self.volatile:
                    if key.k == "exact" and len(key.x) == 1:
                        k = next(iter(key.x))
                        if base.k == "dict":
                            env[name] = V("dict", _dict_store(base.x, k, v))
                            return
                        if isinstance(k, int) and not isinstance(k, bool) and -len(base.x) <= k < len(base.x):
                            lst = list(base.x)
                            lst[k] = v
                            env[name] = V("list", tuple(lst))
                            return
                    env[name] = TOP
                    return
                if base.k in CONTAINERS:
                    env[name] = TOP      # includes ConfigParser mapping-protocol stores (C1)
                    return
                if base.k not in IDENTITY_KINDS:
                    env[name] = OPAQUE if (untainted(base) and untainted(v)) else TOP
                return
            # nested store x[a][b] = v / x.y[k] = v: the root container is no longer precise
            root = chain_root(target.value)
            self.ev(target.value, env)
            self.ev(target.slice, env)
            if root and root in env and env[root].k in CONTAINERS + ("inst",):
                env[root] = TOP
            return
        if isinstance(target, ast.Attribute):
            self.ev(target.value, env)
            if isinstance(target.value, ast.Name) and target.value.id in env:
                b = env[target.value.id]
                if b.k == "inst" and target.attr in RUAMEL_OK_SETTINGS:
                    return
                if b.k not in ("mod", "ext", "pclass", "pfunc", "builtin", "obj"):
                    env[target.value.id] = OPAQUE if (untainted(b) and untainted(v)) else TOP
            else:
                root = chain_root(target.value)
                if root and root in env and env[root].k in CONTAINERS + ("inst",):
                    env[root] = TOP
            return
        if isinstance(target, ast.Starred):
            self.assign(target.value, TOP, env, None)

    # ---------------- expressions -----------------
    def ev(self, node, env, keep_container=False):
        v = self._ev(node, env, keep_container)
        if node is not None and id(node) in self.watch:
            self.recorded[id(node)] = join(self.recorded.get(id(node)), v)
        return v

    def _ev(self, node, env, keep_container=False):
        if node is None:
            return exact(None)
        if isinstance(node, ast.Constant):
            return exact(node.value)
        if isinstance(node, ast.Name):
            if id(node) in self.watch:
                self.prevalue[id(node)] = join(self.prevalue.get(id(node)), self.lookup(node.id, env))
            if keep_container:
                v = self.lookup(node.id, env)
                if v.k in CONTAINERS:
                    env[node.id] = TOP
                    return TOP
                return v
            return self.load_name_generic(node.id, env)
        if isinstance(node, ast.JoinedStr):
            return self.joined(node, env)
        if isinstance(node, ast.FormattedValue):
            return self.ev(node.value, env)
        if isinstance(node, ast.BinOp):
            return self.binop(node.op, self.ev(node.left, env), self.ev(node.right, env))
        if isinstance(node, ast.UnaryOp):
            v = self.ev(node.operand, env)
            if v.k == "exact":
                try:
                    ops = {ast.Not: lambda x: not x, ast.USub: lambda x: -x, ast.UAdd: lambda x: +x,
                           ast.Invert: lambda x: ~x}
                    return exact_set(ops[type(node.op)](x) for x in v.x)
                except Exception:
                    return OPAQUE
            return OPAQUE
        if isinstance(node, ast.Compare):
            vals = [self.ev(node.left, env)] + [self.ev(c, env) for c in node.comparators]
            if all(v.k == "exact" for v in vals) and len(node.ops) == 1:
                res = _Acc()
                try:
                    for a in vals[0].x:
                        for b in vals[1].x:
                            res.add(_cmp(node.ops[0], a, b))
                    return exact_set(res.values())
                except Exception:
                    return OPAQUE
            return OPAQUE
        if isinstance(node, ast.BoolOp):
            vals = []
            for sub in node.values:
                v = self.ev(sub, env)
                vals.append(v)
                t = truth(v) if self.cfg.core else None
                if isinstance(node.op, ast.Or) and t is True:
                    break
                if isinstance(node.op, ast.And) and t is False:
                    break
            acc = None
            for v in vals:
                acc = join(acc, v)
            return acc
        if isinstance(node, ast.IfExp):
            tv = self.ev(node.test, env)
            t = truth(tv) if self.cfg.core else None
            if t is True:
                self.mark_skipped(node.orelse)
                return self.ev(node.body, env)
            if t is False:
                self.mark_skipped(node.body)
                return self.ev(node.orelse, env)
            return join(self.ev(node.body, env), self.ev(node.orelse, env))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            elts = []
            for e in node.elts:
                if isinstance(e, ast.Starred):
                    self.ev(e.value, env)
                    return TOP
                elts.append(self.ev(e, env))
            if isinstance(node, ast.List):
                return V("list", tuple(elts)) if keep_container else (OPAQUE if all(untainted(e) for e in elts) else top(BUILTIN_TYPED))
            if isinstance(node, ast.Tuple) and all(e.k == "exact" and len(e.x) == 1 for e in elts):
                return exact(tuple(next(iter(e.x)) for e in elts))
            return OPAQUE if all(untainted(e) for e in elts) else top(BUILTIN_TYPED)
        if isinstance(node, ast.Dict):
            items = []
            ok = True
            for k, v in zip(node.keys, node.values):
                if k is None:
                    self.ev(v, env)
                    ok = False
                    continue
                kv = self.ev(k, env)
                vv = self.ev(v, env)
                if kv.k == "exact" and len(kv.x) == 1:
                    kk = next(iter(kv.x))
                    items = list(_dict_store(items, kk, vv))
                else:
                    ok = False
            if ok and keep_container:
                return V("dict", tuple(items))
            return OPAQUE if ok and all(untainted(b) for _, b in items) else top(BUILTIN_TYPED)
        if isinstance(node, ast.Subscript):
            return self.subscript(node, env)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in env and env[node.value.id].k == "inst" \
                    and node.attr not in RUAMEL_OK_METHODS | RUAMEL_OK_SETTINGS:
                env[node.value.id] = TOP
                return TOP
            return self.attribute(node, env)
        if isinstance(node, ast.Call):
            return self.call(node, env)
        if isinstance(node, ast.NamedExpr):
            v = self.ev(node.value, env)
            env[node.target.id] = v
            return v
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Lambda)):
            for n in ast.walk(node):
                if isinstance(n, ast.Name) and n.id in env and env[n.id].k in CONTAINERS + ("inst",):
                    env[n.id] = TOP
            return TOP
        if isinstance(node, ast.Starred):
            return self.ev(node.value, env)
        return TOP

    def joined(self, node, env):
        parts = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                parts.append(exact(part.value))
            elif isinstance(part, ast.FormattedValue):
                v = self.ev(part.value, env)
                if part.format_spec is not None:
                    self.ev(part.format_spec, env)
                    v = OPAQUE if untainted(v) else TOP
                elif part.conversion not in (-1, None) and v.k == "exact":
                    try:
                        fn = {ord("r"): repr, ord("a"): ascii, ord("s"): str}[part.conversion]
                        v = exact_set(fn(x) for x in v.x)
                    except Exception:
                        v = OPAQUE
                elif v.k == "exact":
                    try:
                        v = exact_set(format(x) for x in v.x)
                    except Exception:
                        v = OPAQUE
                parts.append(v)
            else:
                parts.append(TOP)
        return self.concat(parts)

    def concat(self, parts):
        if all(p.k == "exact" for p in parts):
            texts = [""]
            for p in parts:
                nxt = []
                for t in texts:
                    for x in p.x:
                        if not isinstance(x, str) or len(t) + len(x) > MAX_LEN:
                            return OPAQUE
                        nxt.append(t + x)
                        if len(nxt) > MAX_SET:
                            return OPAQUE
                texts = nxt
            return exact_set(texts)
        if all(untainted(p) for p in parts):
            return OPAQUE
        return TOP

    def binop(self, op, a, b):
        if a.k == "exact" and b.k == "exact":
            res = _Acc()
            try:
                if isinstance(op, ast.Pow):
                    return OPAQUE
                if isinstance(op, ast.Div) and all(isinstance(x, str) for x in a.x) and all(isinstance(y, str) for y in b.x):
                    return OPAQUE
                for x in a.x:
                    for y in b.x:
                        res.add(_binop(op, x, y))
                        if len(res) > MAX_SET:
                            return OPAQUE
                return exact_set(res.values())
            except Exception:
                return OPAQUE
        if isinstance(op, ast.Add):
            return self.concat([a, b])
        if untainted(a) and untainted(b):
            return OPAQUE
        if isinstance(op, (ast.Sub, ast.Div, ast.FloorDiv, ast.Pow, ast.BitAnd, ast.BitOr, ast.BitXor,
                           ast.LShift, ast.RShift)) and a.k != "top" and b.k != "top":
            return OPAQUE
        return TOP

    def subscript(self, node, env):
        base_node = node.value
        if isinstance(base_node, ast.Name):
            base = self.lookup(base_node.id, env)
            if id(base_node) in self.watch:
                self.recorded[id(base_node)] = join(self.recorded.get(id(base_node)), base)
        else:
            base = self.ev(base_node, env)
        sl = node.slice
        if isinstance(sl, ast.Slice):
            lo = self.ev(sl.lower, env) if sl.lower is not None else exact(None)
            hi = self.ev(sl.upper, env) if sl.upper is not None else exact(None)
            st = self.ev(sl.step, env) if sl.step is not None else exact(None)
            if base.k == "exact" and all(x.k == "exact" and len(x.x) == 1 for x in (lo, hi, st)):
                cut = slice(next(iter(lo.x)), next(iter(hi.x)), next(iter(st.x)))
                try:
                    return exact_set(x[cut] for x in base.x)
                except Exception:
                    return OPAQUE
            if base.k == "list" and all(x.k == "exact" and len(x.x) == 1 for x in (lo, hi, st)):
                try:
                    return V("list", base.x[slice(next(iter(lo.x)), next(iter(hi.x)), next(iter(st.x)))])
                except Exception:
                    return TOP
            if base.k == "top" and "builtin_type" in base.facts:
                return top(BUILTIN_TYPED)
            return OPAQUE if untainted(base) else TOP
        key = self.ev(sl, env)
        if base.k == "exact":
            if key.k == "exact":
                res = _Acc()
                try:
                    for x in base.x:
                        for k in key.x:
                            res.add(x[k])
                    return exact_set(res.values())
                except Exception:
                    return OPAQUE
            return OPAQUE
        if base.k == "list":
            if key.k == "exact" and len(key.x) == 1:
                k = next(iter(key.x))
                if isinstance(k, int) and not isinstance(k, bool):
                    if -len(base.x) <= k < len(base.x):
                        el = base.x[k]
                        if el.k in CONTAINERS:
                            if isinstance(base_node, ast.Name):
                                env[base_node.id] = TOP
                            return TOP
                        return el
                    raise PathRaise()
            return self.smashed(base)
        if base.k == "dict":
            if key.k == "exact" and len(key.x) == 1:
                k = next(iter(key.x))
                for kk, vv in base.x:
                    if kk == k and kk is not None:
                        if vv.k in CONTAINERS:
                            return TOP
                        return vv
                if any(kk is None for kk, _ in base.x):
                    return self.smashed(base)
                raise PathRaise()
            return self.smashed(base)
        if base.k == "cfg":
            return TOP
        if base.k in SCALAR_SAFE:
            return OPAQUE
        if base.k == "top" and "builtin_type" in base.facts:
            return top(BUILTIN_TYPED)
        return TOP

    def smashed(self, base):
        acc = None
        vals = base.x if base.k == "list" else [v for _, v in base.x]
        for v in vals:
            acc = join(acc, v)
        if acc is None:
            return TOP
        return OPAQUE if untainted(acc) else (top(BUILTIN_TYPED) if builtin_typed(acc) else TOP)

    def attr_of(self, base, attr):
        if base.k == "mod":
            dotted = f"{base.x}.{attr}"
            if self.p.resolve_module(dotted):
                return V("mod", dotted)
            mf = self.p.resolve_module(base.x)
            if mf and mf[0] == "file":
                sym = self.p.global_value(mf[1], attr)
                return sym if sym is not None else TOP
            return TOP
        if base.k == "ext":
            dotted = f"{base.x}.{attr}"
            if dotted in ENV_EXT_ATTRS:
                return OPAQUE
            if not self.p.ext_attr_stable(dotted):
                return TOP
            return V("ext", dotted)
        if base.k == "url":
            return OPAQUE if untainted(base.x[0]) else TOP
        if base.k == "obj":
            meth = self.E.find_method(base.x, attr)
            if meth is not None:
                return V("bmeth", (base, meth[1], meth[0]))
            return TOP
        if base.k in SCALAR_SAFE:
            return OPAQUE
        return TOP

    def attribute(self, node, env):
        base = self.ev(node.value, env)
        return self.attr_of(base, node.attr)

    # ---------------- calls -----------------
    def call(self, node, env):
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            recv = self.lookup(f.value.id, env)
            if recv.k in CONTAINERS and f.value.id not in self.volatile:
                if id(f.value) in self.watch:
                    self.recorded[id(f.value)] = join(self.recorded.get(id(f.value)), recv)
                return self.container_method(node, f.value.id, recv, f.attr, env)
        recv = None
        if isinstance(f, ast.Attribute):
            recv = self.ev(f.value, env)
        args = [self.ev(a.value if isinstance(a, ast.Starred) else a, env) for a in node.args]
        kws = {k.arg: self.ev(k.value, env) for k in node.keywords}
        if isinstance(f, ast.Attribute):
            if recv.k == "fh" and f.attr == "read" and not node.args and not node.keywords:
                return V("repo", recv.x)
            if recv.k == "inst":
                if f.attr not in RUAMEL_OK_METHODS and isinstance(f.value, ast.Name):
                    env[f.value.id] = TOP
                self.escape_args(node, env)
                return TOP
            if recv.k in ("mod", "ext", "obj", "pclass"):
                callee = self.attr_of(recv, f.attr)
                return self.apply(callee, node, args, kws, env)
            if recv.k == "top" and "builtin_type" in recv.facts and f.attr in BUILTIN_TYPE_METHODS | STR_METHODS:
                return OPAQUE if f.attr in SCALAR_RESULT_METHODS else top(BUILTIN_TYPED)
            res = self.value_method(recv, f.attr, args, kws, node)
            if isinstance(f.value, ast.Name) and f.attr not in STR_METHODS \
                    and env.get(f.value.id) is not None and env[f.value.id].k in SCALAR_SAFE \
                    and env[f.value.id].k != "exact":
                env[f.value.id] = OPAQUE if all(untainted(a) for a in args + list(kws.values())) else TOP
            if not (recv.k in SCALAR_SAFE and f.attr in STR_METHODS):
                self.escape_args(node, env)
            return res
        callee = self.ev(f, env)
        if isinstance(f, ast.Name) and f.id in ("exec", "eval") and callee.k != "builtin" \
                and len(node.args) < 2 and not any(k.arg in ("globals", "locals") for k in node.keywords):
            if self.module_mode:
                # exec/eval without a namespace runs in this module's globals: every name may change
                for k in list(env):
                    env[k] = TOP
                self.clobbered = True
        return self.apply(callee, node, args, kws, env)

    def escape_args(self, node, env):
        for a in list(node.args) + [k.value for k in node.keywords]:
            if isinstance(a, ast.Starred):
                a = a.value
            if isinstance(a, ast.Name) and a.id in env:
                k = env[a.id].k
                if k in CONTAINERS or k in ("opaque", "inst"):
                    env[a.id] = TOP

    def open_value(self, node, args, kws):
        if not self.cfg.repofile or not args:
            return TOP
        p = args[0]
        if p.k != "exact" or len(p.x) != 1:
            return TOP
        path = next(iter(p.x))
        mode = args[1] if len(args) > 1 else kws.get("mode")
        if mode is not None and not (mode.k == "exact" and len(mode.x) == 1 and next(iter(mode.x)) in READ_MODES):
            return TOP
        if any(k not in ("mode", "encoding", "errors", "newline", "buffering") for k in kws):
            return TOP
        rel = self.E.repo_path(path)
        return V("fh", rel) if rel else TOP

    def apply(self, callee, node, args, kws, env):
        allv = args + list(kws.values())
        if callee.k == "builtin":
            if callee.x == "open":
                return self.open_value(node, args, kws)
            return self.builtin(callee.x, args, kws)
        if callee.k == "ext":
            name = callee.x
            if name in PURE_EXT or name in OS_PATH:
                fn = PURE_EXT.get(name) or OS_PATH.get(name)
                if all(a.k == "exact" for a in allv) and not kws:
                    res = _Acc()
                    try:
                        for combo in _product([a.x for a in args]):
                            res.add(fn(*combo))
                        return exact_set(res.values())
                    except Exception:
                        return OPAQUE
                return OPAQUE if all(untainted(a) for a in allv) else TOP
            if name in ENV_EXT_CALLS:
                return OPAQUE
            if name in STRING_PURE_EXT:
                return OPAQUE if all(untainted(a) for a in allv) else TOP
            if name in URLPARSE and args:
                srcname = node.args[0].id if isinstance(node.args[0], ast.Name) else None
                return V("url", (args[0], srcname))
            if name in CONFIGPARSER:
                if node.args or node.keywords:
                    return TOP   # C1/C2: defaults=, interpolation=, converters= ... are not modelled
                return V("cfg", ((), False, ()))
            if name in JSON_LOADERS and not self.p.resolve_module("json"):
                self.escape_args(node, env)
                if node.keywords or len(node.args) != 1:
                    return TOP   # object_hook / cls / parse_* may build arbitrary objects (json docs)
                return OPAQUE if all(untainted(a) for a in allv) else top(BUILTIN_TYPED)
            if name in RUAMEL_YAML_CLASSES:
                return V("inst", ("ruamel.yaml.YAML", ruamel_ctor_ok(node)))
            if name in ("io.open",):
                return self.open_value(node, args, kws)
            self.escape_args(node, env)
            return TOP
        if callee.k in ("pfunc", "bmeth", "pclass"):
            self.escape_args(node, env)
            if not self.cfg.core:
                return TOP
            if callee.k == "pclass":
                if self.E.class_stable(callee.x):
                    return V("obj", callee.x)
                return TOP
            if callee.k == "pfunc":
                modname, fn, rel = callee.x
                return self.invoke(rel, fn, None, args, kws)
            obj, fn, rel = callee.x
            return self.invoke(rel, fn, obj, args, kws)
        self.escape_args(node, env)
        return TOP

    def invoke(self, rel, fn, selfv, args, kws):
        if self.depth >= MAX_DEPTH or id(fn) in self.stack or fn.decorator_list:
            return TOP
        if any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(fn)):
            return TOP
        if isinstance(fn, ast.AsyncFunctionDef):
            return TOP
        tree = self.p.parse(rel)
        if tree is None:
            return TOP
        a = fn.args
        params = a.posonlyargs + a.args
        env = {}
        vals = list(args)
        if selfv is not None:
            vals = [selfv] + vals
        defaults = [None] * (len(params) - len(a.defaults)) + list(a.defaults)
        for i, p in enumerate(params):
            if i < len(vals):
                env[p.arg] = vals[i]
            elif p.arg in kws:
                env[p.arg] = kws[p.arg]
            elif defaults[i] is not None:
                lv = literal_value(defaults[i])
                env[p.arg] = lv if lv is not None else TOP
            else:
                return TOP
        for p, d in zip(a.kwonlyargs, a.kw_defaults):
            if p.arg in kws:
                env[p.arg] = kws[p.arg]
            elif d is not None:
                lv = literal_value(d)
                env[p.arg] = lv if lv is not None else TOP
            else:
                return TOP
        if a.vararg:
            env[a.vararg.arg] = TOP
        if a.kwarg:
            env[a.kwarg.arg] = TOP
        sub = Interp(self.E, rel, tree, fn, self.depth + 1, self.stack)
        try:
            out = sub.exec_block(fn.body, env)
        except (RecursionError, _Abort):
            return TOP
        ret = sub.returns
        if out is not None:
            ret = join(ret, exact(None))
        if ret is None:
            raise PathRaise()
        if ret.k in CONTAINERS:
            return OPAQUE if untainted(ret) else TOP
        return ret

    def builtin(self, name, args, kws):
        if name in ("str", "repr") and len(args) == 1 and not kws:
            a = args[0]
            if a.k == "exact":
                try:
                    return exact_set((str if name == "str" else repr)(x) for x in a.x)
                except Exception:
                    return OPAQUE
            return a if a.k in ("top", "opaque") and name == "str" else (OPAQUE if untainted(a) else TOP)
        if name == "type":
            return TOP   # a class object: its attributes are arbitrary code (not a builtin-typed value)
        if name in ("int", "float", "bool", "len", "abs", "ord", "hex", "isinstance"):
            if len(args) == 1 and args[0].k == "exact" and name in ("int", "float", "bool", "len", "abs", "ord", "hex"):
                try:
                    fn = {"int": int, "float": float, "bool": bool, "len": len, "abs": abs, "ord": ord, "hex": hex}[name]
                    return exact_set(fn(x) for x in args[0].x)
                except Exception:
                    return OPAQUE
            return OPAQUE
        if name == "chr":
            return OPAQUE
        if name in ("list", "dict", "tuple", "sorted", "range", "min", "max"):
            if name == "list" and not args:
                return V("list", ())
            if name == "dict" and not args and not kws:
                return V("dict", ())
            if all(untainted(a) for a in args + list(kws.values())):
                return OPAQUE
            return top(BUILTIN_TYPED) if name in ("list", "dict", "tuple", "sorted") else TOP
        if name == "print":
            return exact(None)
        return TOP

    def value_method(self, recv, m, args, kws, node):
        if recv.k == "exact" and m in STR_METHODS and all(isinstance(x, (str, bytes)) for x in recv.x):
            if all(a.k == "exact" and len(a.x) == 1 for a in args) and all(v.k == "exact" and len(v.x) == 1 for v in kws.values()):
                res = _Acc()
                lists = []
                try:
                    for x in recv.x:
                        r = _str_method_bounded(x, m, [next(iter(a.x)) for a in args],
                                                {k: next(iter(v.x)) for k, v in kws.items()})
                        if isinstance(r, list):
                            lists.append(r)
                        else:
                            res.add(r)
                    if lists:
                        if len(lists) == 1 and not res:
                            return exact(tuple(lists[0]))
                        return OPAQUE
                    return exact_set(res.values())
                except Exception:
                    return OPAQUE
            return OPAQUE if all(untainted(a) for a in args + list(kws.values())) else (
                OPAQUE if m in SCALAR_RESULT_METHODS else TOP)
        if recv.k == "url":
            return OPAQUE if untainted(recv.x[0]) else TOP
        if recv.k in SCALAR_SAFE:
            if all(untainted(a) for a in args + list(kws.values())):
                return OPAQUE
            return OPAQUE if m in SCALAR_RESULT_METHODS else TOP
        if recv.k == "top" and m in SCALAR_RESULT_METHODS:
            return OPAQUE
        return TOP

    def container_method(self, node, name, recv, m, env):
        args = [self.ev(a, env, keep_container=False) for a in node.args]
        kws = {k.arg: self.ev(k.value, env) for k in node.keywords}
        if recv.k == "list":
            elts = list(recv.x)
            if m == "append" and len(args) == 1 and not kws:
                env[name] = V("list", tuple(elts + [args[0]]))
                return exact(None)
            if m == "pop" and not kws:
                if not elts:
                    raise PathRaise()
                if not args:
                    v = elts.pop()
                elif args[0].k == "exact" and len(args[0].x) == 1 and isinstance(next(iter(args[0].x)), int) \
                        and not isinstance(next(iter(args[0].x)), bool):
                    i = next(iter(args[0].x))
                    if not -len(elts) <= i < len(elts):
                        raise PathRaise()
                    v = elts.pop(i)
                else:
                    env[name] = TOP
                    return TOP
                env[name] = V("list", tuple(elts))
                return v
            if m == "insert" and len(args) == 2 and args[0].k == "exact" and len(args[0].x) == 1:
                i = next(iter(args[0].x))
                if isinstance(i, int) and not isinstance(i, bool):
                    elts.insert(i, args[1])
                    env[name] = V("list", tuple(elts))
                    return exact(None)
            if m == "clear" and not args:
                env[name] = V("list", ())
                return exact(None)
            if m == "reverse" and not args:
                env[name] = V("list", tuple(reversed(elts)))
                return exact(None)
            if m in ("index", "count"):
                return OPAQUE
            if m == "copy":
                return self.smashed(recv)
        if recv.k == "dict":
            items = list(recv.x)
            if m == "get" and args and args[0].k == "exact" and len(args[0].x) == 1 and not kws:
                k = next(iter(args[0].x))
                default = args[1] if len(args) > 1 else exact(None)
                for kk, vv in items:
                    if kk == k and kk is not None:
                        return vv if vv.k not in CONTAINERS else TOP
                if any(kk is None for kk, _ in items):
                    return TOP
                return default
            if m in ("keys", "values", "items", "copy") and not args:
                return self.smashed(recv) if items else OPAQUE
            if m == "setdefault" and args and args[0].k == "exact" and len(args[0].x) == 1:
                k = next(iter(args[0].x))
                for kk, vv in items:
                    if kk == k:
                        return vv
                v = args[1] if len(args) > 1 else exact(None)
                env[name] = V("dict", tuple(items + [(k, v)]))
                return v
            if m == "clear" and not args:
                env[name] = V("dict", ())
                return exact(None)
        if recv.k == "cfg":
            entries, unknown, sections = recv.x
            entries = list(entries)
            if m == "add_section" and len(args) == 1 and args[0].k == "exact" and len(args[0].x) == 1:
                env[name] = V("cfg", (tuple(entries), unknown, sections + (next(iter(args[0].x)),)))
                return exact(None)
            if m == "set" and len(args) == 3 and all(a.k == "exact" and len(a.x) == 1 for a in args[:2]):
                sec = next(iter(args[0].x))
                opt = next(iter(args[1].x))
                if not isinstance(opt, str):
                    env[name] = TOP
                    return TOP
                key = (sec, opt.lower())   # default optionxform lower-cases option names
                entries = [(k, v) for k, v in entries if k != key] + [(key, args[2])]
                env[name] = V("cfg", (tuple(entries), unknown, sections))
                return exact(None)
            if m == "get" and len(args) >= 2 and all(a.k == "exact" and len(a.x) == 1 for a in args[:2]):
                sec = next(iter(args[0].x))
                opt = next(iter(args[1].x))
                if unknown or not isinstance(opt, str) or any(k not in ("raw", "fallback", "vars") for k in kws) \
                        or "vars" in kws or len(args) > 2:
                    return TOP
                raw = kws.get("raw")
                found = None
                for k, v in entries:
                    if k == (sec, opt.lower()):
                        found = v
                if found is None:
                    for k, v in entries:
                        if k == ("DEFAULT", opt.lower()):
                            found = v
                if found is None:
                    return kws.get("fallback", TOP)
                interp_safe = (raw is not None and truth(raw) is True) or (
                    found.k == "exact" and not any(isinstance(x, str) and "%" in x for x in found.x))
                if not interp_safe:
                    others = [v for k, v in entries if k[0] in (sec, "DEFAULT")]
                    if not all(untainted(v) for v in others):
                        return TOP
                return found
            if m in ("has_section", "has_option", "sections", "options"):
                return OPAQUE
            if m in ("read", "read_string", "read_file", "read_dict", "readfp"):
                env[name] = V("cfg", (tuple(entries), True, sections))
                return exact(None) if m != "read" else OPAQUE
        env[name] = TOP
        self.escape_args(node, env)
        return TOP


class _Abort(Exception):
    pass


def _expands_parameters(v):
    """Skylos port: True when a command value (literal text, or literal argv elements) contains `$` or a backquote."""
    if v is None:
        return False
    if v.k == "exact":
        items = v.x
    elif v.k == "list":
        items = [x for e in v.x if getattr(e, "k", None) == "exact" for x in e.x]
    else:
        return False
    for x in items:
        if isinstance(x, bytes):
            x = x.decode("latin-1")
        if isinstance(x, str) and ("$" in x or "`" in x):
            return True
    return False


# ---------------------------------------------------------------------------
# engine: decisions per finding
# ---------------------------------------------------------------------------

_STEP_CALL = re.compile(r"^(?P<file>.+?):(?P<line>\d+) call `(?P<recv>[A-Za-z_][A-Za-z0-9_.]*)\.(?P<meth>[A-Za-z_][A-Za-z0-9_]*)\(\.\.\.\)` binds `[^`]+`$")
_STEP_ANY = re.compile(r"^(?P<file>.+?\.py):(?P<line>\d+) ")


class Engine:
    def __init__(self, repo, cfg, log):
        self.cfg = cfg
        self.p = Project(repo, cfg)
        self.p.engine = self
        self.log = log
        self._eval_cache = {}
        self._jump_cache = {}
        self._class_cache = {}

    # ---- helpers ----
    def repo_path(self, path):
        if not isinstance(path, str) or not path.startswith(REPO_TOKEN + "/"):
            return None
        rel = posixpath.normpath(path[len(REPO_TOKEN) + 1:])
        if rel.startswith("..") or rel.startswith("/"):
            return None
        p = self.p.root / rel
        cur = self.p.root
        for part in Path(rel).parts:
            cur = cur / part
            if cur.is_symlink():
                return None
        return rel if p.is_file() else None

    def interp(self, rel, scope, watch, env0=None, depth=0):
        tree = self.p.parse(rel)
        module_mode = isinstance(scope, ast.Module)
        if module_mode:
            mi = self.p.index().mod_info.get(rel)
            if mi is None or mi.star or mi.dyn:
                return None
        it = Interp(self, rel, tree, scope, depth=depth, watch=watch, module_mode=module_mode)
        env = {}
        if not module_mode:
            a = scope.args
            for arg in a.posonlyargs + a.args + a.kwonlyargs:
                env[arg.arg] = TOP
            if a.vararg:
                env[a.vararg.arg] = TOP
            if a.kwarg:
                env[a.kwarg.arg] = TOP
            if env0:
                env.update(env0)
        try:
            it.exec_block(scope.body, env)
        except (RecursionError, _Abort, MemoryError):
            return None
        return it

    def eval_at(self, rel, node):
        """Value of expression `node` (all reaching evaluations joined), parameters unknown."""
        key = (rel, id(node))
        if key in self._eval_cache:
            return self._eval_cache[key]
        self._eval_cache[key] = None
        scope = enclosing_scope(node)
        v = None
        if scope is not None:
            it = self.interp(rel, scope, {id(node)})
            if it is not None:
                v = it.recorded.get(id(node))
                if v is None and id(node) not in it.skipped:
                    v = TOP
        self._eval_cache[key] = v if v is not None else TOP
        return self._eval_cache[key]

    def resolve_base(self, rel, expr):
        if isinstance(expr, ast.Name) and expr.id == "object":
            return "object"
        v = self.p.static_identity(rel, expr)
        if v is not None and v.k == "pclass":
            return v.x
        return None

    def class_stable(self, cref, seen=None):
        """Instances of project class `cref` behave as their class bodies say: every base is a project class
        (or object) with the same property, no metaclass, no class decorator, no __getattribute__/__new__/
        __init_subclass__ anywhere in the MRO."""
        key = id(cref[1])
        if key in self._class_cache:
            return self._class_cache[key]
        seen = set() if seen is None else seen
        if key in seen:
            return False
        seen.add(key)
        modname, cls, rel = cref
        ok = not cls.decorator_list and not any(kw.arg == "metaclass" for kw in cls.keywords)
        if ok:
            for st in cls.body:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and st.name in (
                        "__getattribute__", "__new__", "__init_subclass__", "__class_getitem__"):
                    ok = False
                if isinstance(st, (ast.Assign, ast.AnnAssign)):
                    targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                    if any(isinstance(t, ast.Name) and t.id in ("__getattribute__", "__class__", "__slots__") for t in targets):
                        ok = False
        if ok:
            for b in cls.bases:
                r = self.resolve_base(rel, b)
                if r == "object":
                    continue
                if r is None or not self.class_stable(r, seen):
                    ok = False
                    break
        self._class_cache[key] = ok
        return ok

    def find_method(self, cref, name, depth=0):
        """(rel, FunctionDef) that attribute `name` of an instance of `cref` resolves to, or None."""
        if depth > 8 or not self.class_stable(cref) or not self.p.method_name_stable(name):
            return None
        if mangle_sensitive(name):
            return None   # private name mangling: the runtime attribute depends on the class of the access site
        modname, cls, rel = cref
        for st in cls.body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and st.name == name:
                if st.decorator_list:
                    return None
                return (rel, st)
            if isinstance(st, (ast.Assign, ast.AnnAssign)):
                targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                for t in targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name) and n.id == name:
                            return None
        for b in cls.bases:
            r = self.resolve_base(rel, b)
            if r == "object":
                continue
            if r is None:
                return None
            res = self.find_method(r, name, depth + 1)
            if res is not None:
                return res
            # not found in this base: continue MRO (single-inheritance chains only)
            if len(cls.bases) > 1:
                return None
        return None

    # ---- finding location ----
    def find_call(self, tree, line, col, names):
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line]
        exact_col = [c for c in calls if c.col_offset == col]
        named = [c for c in exact_col if _call_name(c) in names]
        if named:
            # chained calls share a column (os.popen(x).read()): the innermost rule-named one is the sink
            return [min(named, key=lambda c: (c.end_lineno - c.lineno, c.end_col_offset))]
        if exact_col:
            return [min(exact_col, key=lambda c: (c.end_lineno - c.lineno, c.end_col_offset))]
        return [c for c in calls if _call_name(c) in names]

    def find_span(self, tree, span):
        if not isinstance(span, dict):
            return None
        for n in ast.walk(tree):
            if isinstance(n, ast.expr) and getattr(n, "lineno", None) == span.get("line") \
                    and n.col_offset == span.get("col") and getattr(n, "end_lineno", None) == span.get("end_line") \
                    and getattr(n, "end_col_offset", None) == span.get("end_col"):
                return n
        return None

    def call_operand(self, call, rule):
        names, pos, kwnames = SINK_SPECS[rule]
        if rule == "SKY-D216" and _call_name(call) == "request":
            pos, kwnames = 1, ("url",)
        if len(call.args) > pos:
            a = call.args[pos]
            if any(isinstance(x, ast.Starred) for x in call.args[:pos + 1]):
                return None
            return a
        for kw in call.keywords:
            if kw.arg in kwnames:
                return kw.value
        return None

    def operands(self, f, rel, tree, rule):
        """(kind, nodes, scope): kind 'plain' or 'd228'; nodes are the claimed operand expressions."""
        line = int(f.get("line") or 0)
        col = f.get("col")
        md = f.get("metadata") or {}
        if rule == "SKY-D228":
            rets = [n for n in ast.walk(tree) if isinstance(n, ast.Return) and n.lineno == line
                    and (col is None or n.col_offset == col) and n.value is not None]
            if len(rets) != 1:
                return None
            parts = split_parts(rets[0].value)
            if parts is None:
                return None
            return ("d228", parts, rets[0])
        if rule in S1_INTRA_ONLY:
            node = self.find_span(tree, md.get("sql_operand"))
            return ("plain", [node], node) if node is not None else None
        if rule in PATH_FAMILY and md.get("path_operand"):
            node = self.find_span(tree, md.get("path_operand"))
            if node is not None:
                return ("plain", [node], node)
        if rule not in SINK_SPECS:
            return None
        calls = self.find_call(tree, line, col, SINK_SPECS[rule][0])
        if not calls:
            return None
        if rule in SHELL_SINK_RULES | CODE_SINK_RULES:
            # every sink-family call on the finding's line or nested in it must be closed: Skylos keys some
            # findings and proofs by line (council/review__cross-certified__by__sec-sccp.md, same-line twins)
            fam = SHELL_NAMES if rule in SHELL_SINK_RULES else CODE_NAMES
            sib = {id(c): c for c in calls}
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and _call_name(n) in fam and n.lineno == line:
                    sib[id(n)] = n
            for c in list(sib.values()):
                for n in ast.walk(c):
                    if isinstance(n, ast.Call) and _call_name(n) in fam:
                        sib[id(n)] = n
            pairs = []
            for c in sorted(sib.values(), key=lambda c: (c.lineno, c.col_offset)):
                o = self.call_operand(c, rule)
                if o is None:
                    return None
                pairs.append((c, o))
            return ("site", pairs, calls[0])
        ops = []
        for c in calls:
            o = self.call_operand(c, rule)
            if o is None:
                return None
            ops.append(o)
        return ("plain", ops, calls[0])

    # ---- decisions ----
    def decide(self, f, rel):
        rule = f.get("rule_id")
        lrc = (f.get("low_risk_context") or {}).get("reason")
        if not rel.endswith(".py"):
            return None
        tree = self.p.parse(rel)
        if tree is None:
            return None
        res = None
        if self.cfg.f0 and lrc in F0_REASONS and rule in F0_SHELL | F0_CODE | F0_DATA:
            res = self.f0(f, rel, tree, rule, lrc)
            if res is not None:
                return res
        if self.cfg.s1 and rule in S1_RULES | S1_INTRA_ONLY:
            res = self.s1(f, rel, tree, rule)
        if res is None and self.cfg.s2b and rule == "SKY-D206":
            res = self.s2b(f, rel, tree)
        if res is None and self.cfg.s2a and rule == "SKY-D216":
            res = self.s2a(f, rel, tree)
        if res is None and self.cfg.s2c and rule in PROV_KEYS:
            res = self.s2c(f, rel, tree, rule)
        return res

    def f0(self, f, rel, tree, rule, lrc):
        """Skylos's own ValueFlow literal tag, admitted only under the SC1r site conditions of the
        cross-certified lens (techniques/cpm_sec): shell and code literals are re-derived here and must close
        the site; data sinks need a single data channel and no parameter read in it. No sibling cover."""
        line, col = int(f.get("line") or 0), f.get("col")
        if col is None:
            return None
        names = SINK_SPECS[rule][0] if rule in SINK_SPECS else set()
        cands = [c for c in ast.walk(tree) if isinstance(c, ast.Call) and c.lineno == line and c.col_offset == col
                 and _call_name(c) in names]
        if len(cands) != 1:
            return None
        call = cands[0]
        if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
            return None
        if rule in F0_DATA:
            if (rule == "SKY-D205" and len(call.args) > 1) or (rule == "SKY-D206" and len(call.args) > 2):
                return None
            data = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg in ("data", "stream")), None)
            if data is None:
                return None
            scope = enclosing_scope(call)
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = scope.args
                params = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
                params |= {x.arg for x in (a.vararg, a.kwarg) if x is not None}
                if any(isinstance(n, ast.Name) and n.id in params for n in ast.walk(data)):
                    return None
            return ("F0", {"reason": lrc, "sc1r": "data"})
        op = self.operands(f, rel, tree, rule)
        if op is None or op[0] != "site":
            return None
        pairs = op[1]
        scope = enclosing_scope(call)
        if scope is None:
            return None
        it = self.interp(rel, scope, {id(o) for _, o in pairs})
        for c, o in pairs:
            v = it.recorded.get(id(o)) if it is not None else None
            if v is None or v.k != "exact":
                lit = self.syntactic_literal(o, c)
                v = exact(lit) if lit is not None else None
            if not self.site_closed(c, rule, v, rel):
                return None
        return ("F0", {"reason": lrc, "sc1r": "shell" if rule in F0_SHELL else "code"})

    def syntactic_literal(self, expr, call):
        """A str/bytes constant, or a local name whose only binding in the enclosing function is
        `name = <str/bytes literal>` (cpm_sec resolve_literal)."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, (str, bytes)):
            return expr.value
        if not isinstance(expr, ast.Name):
            return None
        scope = enclosing_scope(call)
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        binds = []
        for n in ast.walk(scope):
            if isinstance(n, ast.Name) and n.id == expr.id and isinstance(n.ctx, (ast.Store, ast.Del)):
                binds.append(n)
            elif isinstance(n, ast.arg) and n.arg == expr.id:
                return None
            elif isinstance(n, (ast.Global, ast.Nonlocal)) and expr.id in n.names:
                return None
            elif isinstance(n, (ast.Import, ast.ImportFrom)) and any((al.asname or al.name.split(".")[0]) == expr.id for al in n.names):
                return None
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not scope and n.name == expr.id:
                return None
        if len(binds) != 1:
            return None
        asg = getattr(binds[0], "parent", None)
        if isinstance(asg, ast.Assign) and len(asg.targets) == 1 and asg.targets[0] is binds[0] \
                and isinstance(asg.value, ast.Constant) and isinstance(asg.value.value, (str, bytes)):
            return asg.value.value
        return None

    def s1(self, f, rel, tree, rule):
        if rule == "SKY-D228" and not self.cfg.d228:
            return None
        op = self.operands(f, rel, tree, rule)
        if op is None:
            return None
        kind, nodes, anchor = op
        if kind == "d228":
            watch_nodes = [n for part in nodes if part[0] == "value" for n in part[1]]
        elif kind == "site":
            watch_nodes = [o for _, o in nodes] + [a for c, _ in nodes for a in list(c.args[1:])
                                                   + [k.value for k in c.keywords]]
        else:
            watch_nodes = list(nodes)
        scopes = {id(enclosing_scope(n)): enclosing_scope(n) for n in watch_nodes + [anchor]}
        if len(scopes) != 1 or None in scopes.values():
            return None
        scope = next(iter(scopes.values()))
        watch = {id(n) for n in watch_nodes}
        it = self.interp(rel, scope, watch)
        if it is not None:
            ok, why = self.judge(it, rule, kind, nodes, f, rel, scope)
            if ok:
                return ("S1:" + why, {})
        if self.cfg.ipcp and rule not in S1_INTRA_ONLY and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            jv = self.jump_values(rel, scope)
            if jv is not None:
                it2 = self.interp(rel, scope, watch, env0=jv)
                if it2 is not None:
                    ok, why = self.judge(it2, rule, kind, nodes, f, rel, scope)
                    if ok:
                        return ("S1-ipcp:" + why, {"params": {k: repr(v) for k, v in sorted(jv.items())}})
        return None

    def _value_ok(self, it, node, rule, rel, scope):
        nid = id(node)
        if nid in it.recorded:
            v = it.recorded[nid]
            if untainted(v):
                return "const"
            if rule in CODE_RULES and v.k == "repo" and self.repo_content_ok(v.x, rel, scope):
                return "repofile"
            return None
        if nid in it.skipped:
            return "dead_sink"
        return None

    def judge(self, it, rule, kind, nodes, f, rel, scope):
        if kind == "site":
            whys = []
            for call, op in nodes:
                if id(call) in it.skipped and id(op) not in it.recorded:
                    whys.append("dead_sink")
                    continue
                w = self._value_ok(it, op, rule, rel, scope)
                if w is None:
                    return False, "may_be_tainted"
                if w == "const" and not self.site_closed(call, rule, it.recorded[id(op)], rel, it):
                    return False, "site_open"
                if w == "repofile" and not self.namespace_untainted(call, it):
                    return False, "namespace"
                whys.append(w)
            return True, "+".join(sorted(set(whys)))
        if kind == "plain":
            whys = []
            for n in nodes:
                w = self._value_ok(it, n, rule, rel, scope)
                if w is None:
                    return False, "may_be_tainted"
                whys.append(w)
            return True, "+".join(sorted(set(whys)))
        # D228: Skylos reports the FIRST hole whose level is below what its spot needs (html_context /
        # xss_flow._context_failure). Holes before the first non-escaped hole passed Skylos's own check.
        holes = [p for p in nodes if p[0] == "value"]
        raw_message = (f.get("message") or "") == RAW_XSS_MESSAGE
        first_plain = None
        status = []
        for i, (_, hn, numeric) in enumerate(holes):
            proved = numeric or all(self._value_ok(it, n, rule, rel, scope) in ("const", "dead_sink") for n in hn)
            escaped = numeric or all(self.is_escaped(n, scope, rel) for n in hn)
            status.append((proved, escaped))
            if not escaped and first_plain is None:
                first_plain = i
        if not raw_message:
            ok = all(p for p, _ in status)
            return ok, "d228_all_const" if ok else "d228_context"
        if first_plain is None:
            return False, "d228_no_plain_hole"
        for i, (proved, escaped) in enumerate(status):
            if proved:
                continue
            if escaped and i < first_plain:
                continue
            return False, "d228_hole"
        return True, "d228_raw_holes_const"

    @staticmethod
    def _stdin_ok(val):
        if isinstance(val, ast.Constant) and val.value is None:
            return True
        d = dotted_name(val)
        return bool(d) and d.split(".")[-1] == "DEVNULL"

    @staticmethod
    def _read_mode(val):
        return (isinstance(val, ast.Constant) and isinstance(val.value, str) and val.value.startswith("r")
                and not any(ch in val.value for ch in "wa+x"))

    @staticmethod
    def shell_value_closed(v):
        """The command value is literal text (or a literal argv) that runs no interpreter on its stdin."""
        if v is None:
            return False
        if v.k == "exact":
            texts = []
            for x in v.x:
                if isinstance(x, bytes):
                    try:
                        x = x.decode("utf-8")
                    except UnicodeDecodeError:
                        return False
                if not isinstance(x, str):
                    return False
                texts.append(x)
            return bool(texts) and not any(interpreter_reads_stdin(t) or text_runs_unfixed(t) for t in texts)
        if v.k == "list":
            argv = []
            for e in v.x:
                if e.k != "exact" or len(e.x) != 1 or not isinstance(next(iter(e.x)), str):
                    return False
                argv.append(next(iter(e.x)))
            if not argv or _argv_reads_stdin(argv) or _argv_runs_unfixed(argv):
                return False
            return True
        return False

    def site_closed(self, call, rule, v, rel, it=None):
        """SC1r-style closure (techniques/cpm_sec): the proven operand is the call's only data channel."""
        if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
            return False
        name = _call_name(call)
        if rule in SHELL_SINK_RULES:
            env_tainted, env_expand_tainted = self.env_state()
            if env_tainted:
                return False   # the child inherits a process-control environment the project writes from data
            if env_expand_tainted and v is not None and v.k == "exact" and any(
                    isinstance(x, (str, bytes)) and any(ch in (x if isinstance(x, str) else x.decode("latin-1"))
                                                        for ch in "$`") for x in v.x):
                return False   # the command text expands variables the project sets from data
            if _expands_parameters(v):
                # Skylos port narrowing: the environment is also set by whoever starts the process (a CGI server
                # copies request headers into HTTP_*), so a `$`/backquote text is never closed, as in Skylos's own
                # constant-command policy (docs/handbook/rules/SKY-D203.yaml severity_note).
                return False
            kws = {k.arg: k.value for k in call.keywords}
            if name == "popen":
                if len(call.args) > 2 or (len(call.args) == 2 and not self._read_mode(call.args[1])):
                    return False
                for k, val in kws.items():
                    if not ((k == "mode" and self._read_mode(val)) or k == "buffering"):
                        return False
            else:
                if len(call.args) > 1:
                    return False
                for k, val in kws.items():
                    if k == "stdin" and self._stdin_ok(val):
                        continue
                    if k not in SHELL_SAFE_KW:
                        return False
            return self.shell_value_closed(v)
        if rule in CODE_SINK_RULES:
            if len(call.args) != 1 or call.keywords:
                return False   # a namespace can supply names to the code
            if v is None or v.k != "exact":
                return False
            mode = "eval" if name == "eval" else "exec"
            return all(code_literal_closed(x, mode) for x in v.x)
        return True

    def env_state(self):
        """(process-control env possibly written from outside data, any env possibly written from outside data).
        Each non-literal write is evaluated by this engine; a value proven untainted carries no outside data."""
        if getattr(self, "_env_state", None) is None:
            self._env_state = (True, True)   # re-entrancy guard: unknown while computing
            ctl = expand = False
            for rel, key, value in self.p.index().env_writes:
                v = self.eval_at(rel, value) if value is not None else TOP
                if v is not None and untainted(v):
                    continue
                expand = True
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)) or key.value in PROCESS_CONTROL_ENV:
                    ctl = True
            self._env_state = (ctl, expand)
        return self._env_state

    def namespace_untainted(self, call, it):
        for a in list(call.args[1:]) + [k.value for k in call.keywords]:
            v = it.prevalue.get(id(a), it.recorded.get(id(a)))
            if v is None or not untainted(v):
                return False
        return True

    def is_escaped(self, node, scope, rel, depth=0):
        """Value of a Skylos XSS sanitizer call (taint.XSS_SANITIZERS), directly or through a single local binding."""
        if isinstance(node, ast.Call):
            callee = self.static_callee(node.func, scope, rel)
            return callee in XSS_SANITIZERS
        if isinstance(node, ast.Name) and depth == 0 and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            binds = []
            for n in ast.walk(scope):
                if isinstance(n, ast.Name) and n.id == node.id and isinstance(n.ctx, (ast.Store, ast.Del)):
                    par = getattr(n, "parent", None)
                    binds.append(par.value if isinstance(par, ast.Assign) and len(par.targets) == 1 and par.targets[0] is n else None)
                elif isinstance(n, ast.arg) and n.arg == node.id:
                    binds.append(None)
            return len(binds) == 1 and binds[0] is not None and self.is_escaped(binds[0], scope, rel, depth + 1)
        return False

    def static_callee(self, func, scope, rel):
        d = dotted_name(func)
        if not d:
            return None
        root = d.split(".")[0]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(scope):
                if isinstance(n, ast.Name) and n.id == root and isinstance(n.ctx, ast.Store):
                    return None
                if isinstance(n, ast.arg) and n.arg == root:
                    return None
        v = self.p.static_identity(rel, func)
        if v is not None and v.k == "ext" and v.x in XSS_SANITIZERS:
            return v.x
        return None

    def repo_content_ok(self, path_rel, sink_rel, scope):
        """Repository code content may reach a code sink when the sink runs at module level of a build script on the
        source checkout (PyPA 'Single-sourcing the package version'): the build reads the operator's checkout, not
        the deployed application's files. The former case (b), 'the file is the source of a statically imported
        project module', is withdrawn (revision 7): an application that can overwrite its own module source (an
        upload saved over it, an archive extracted into its package) makes the exec run attacker content
        immediately, and proving that no project write can target the file needs a complete write-set model of
        every library the project calls (red team F4 is the same flaw for shell commands)."""
        if not path_rel.endswith(".py"):
            return False
        base = posixpath.basename(sink_rel)
        if base in ("setup.py", "noxfile.py") and isinstance(scope, ast.Module):
            tree = self.p.parse(sink_rel)
            if base == "noxfile.py" or any(isinstance(n, ast.Call) and _call_name(n) == "setup" for n in ast.walk(tree)):
                return True
        return False

    # ---- IPCP ----
    def jump_values(self, rel, fn):
        key = (rel, id(fn))
        if key in self._jump_cache:
            return self._jump_cache[key]
        self._jump_cache[key] = None
        try:
            jv = self._jump_values(rel, fn)
        except (RecursionError, _Abort, MemoryError):
            jv = None
        self._jump_cache[key] = jv
        if jv is not None:
            self.log.append({"mechanism": "ipcp-gates-passed", "function": f"{rel}:{fn.lineno} {fn.name}"})
        return jv

    def _jump_values(self, rel, fn):
        name = fn.name
        idx = self.p.index()
        parent = getattr(fn, "parent", None)
        cur = parent
        while cur is not None and not isinstance(cur, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            cur = getattr(cur, "parent", None)
        nested = isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef))
        is_method = isinstance(parent, ast.ClassDef)
        if not nested and not is_method and not isinstance(cur, ast.Module):
            return None
        # C4 (repaired): underscore-private non-dunder, or nested
        if is_dunder(name) or not (name.startswith("_") or nested):
            return None
        # C2
        deco = [dotted_name(d) for d in fn.decorator_list]
        if any(d not in ("staticmethod", "classmethod") for d in deco):
            return None
        kind = "static" if "staticmethod" in deco else ("class" if "classmethod" in deco else ("method" if is_method else "func"))
        # C3: methods of classes whose MRO is project-only, undecorated, without metaclass
        if is_method:
            cref = (self.p.module_name(rel), parent, rel)
            if not self.class_stable(cref):
                return None
        # C5: no dynamic code anywhere
        if idx.dynamic_code:
            return None
        # C6 / G6: reflective attribute access
        if idx.dict_dynamic_loads or idx.getattr_alias:
            return None
        # C8 (red team F2): a namespace read by computed name anywhere in the project (globals()/locals()/vars()
        # subscripted with a non-literal, x.__dict__.get(name), f.__globals__, inspect.getmembers, ...) can reach the
        # function without any Name occurrence, so C1's caller set is not closed
        if idx.ns_reflect:
            return None
        for grel, call in idx.getattr_dynamic:
            if not call.args:
                return None
            recv = self.p.static_identity(grel, call.args[0]) if isinstance(call.args[0], (ast.Name, ast.Attribute)) else None
            if recv is None or recv.k != "mod":
                return None
            mf = self.p.resolve_module(recv.x)
            if mf and mf[0] == "file" and mf[1] == rel and isinstance(parent, ast.Module):
                return None
        # C9 (red team F3): private name mangling (Language Reference, "Identifiers", private name mangling).
        # A method `__x` of class C is also the attribute `_C__x`, reachable from outside the class under that
        # spelling, so both spellings are searched. A function spelled `_C__x` is reachable as `__x` from inside
        # the body of a class named C (or _C, __C), which a name search for `_C__x` cannot see: refused.
        spellings = [name]
        if "__" in name.lstrip("_"):
            return None   # a `_C__x` spelling (or any name with an inner double underscore)
        if name.startswith("__") and is_method:
            cls = parent.name.lstrip("_")
            if cls:
                spellings.append(f"_{cls}{name}")
        # C1: every reference is a call; no string, no non-Python occurrence (each spelling)
        sites = []
        seen_calls = set()
        for spelling in spellings:
            ok, found = self.p.name_refs(spelling)
            if not ok or spelling in idx.str_words or self.p.word_in_non_python(spelling):
                return None
            for srel, call in found:
                if id(call) not in seen_calls:
                    seen_calls.add(id(call))
                    sites.append((srel, call))
        a = fn.args
        params = [p.arg for p in a.posonlyargs + a.args]
        if kind in ("method", "class"):
            implicit = params[:1]
            params = params[1:]
        else:
            implicit = []
        if a.vararg or a.kwarg or not (params or a.kwonlyargs):
            return None   # C7
        if not sites:
            return None   # C7
        kwonly = [p.arg for p in a.kwonlyargs]
        defaults = {}
        pos_defaults = list(a.defaults)
        allpos = [p.arg for p in a.posonlyargs + a.args]
        for p, d in zip(allpos[len(allpos) - len(pos_defaults):], pos_defaults):
            defaults[p] = d
        for p, d in zip(a.kwonlyargs, a.kw_defaults):
            if d is not None:
                defaults[p.arg] = d
        acc = {p: None for p in params + kwonly}
        for srel, call in sites:
            if enclosing_scope(call) is fn:
                return None   # recursion: arguments derive from the unknown parameters
            mappings = self._bindings(kind, call, srel)
            for shift in mappings:
                vals = self._call_arg_values(srel, call, params, kwonly, defaults, shift)
                if vals is None:
                    return None
                for p, v in vals.items():
                    acc[p] = join(acc[p], v)
        out = {}
        for p, v in acc.items():
            out[p] = v if v is not None else TOP
        for p in implicit:
            out[p] = TOP
        return out

    def _bindings(self, kind, call, srel):
        """Possible numbers of leading positional arguments consumed by an implicit self (0) or not (-1)."""
        if kind in ("static", "func", "class"):
            return [0]
        f = call.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            scope = enclosing_scope(call)
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and isinstance(getattr(scope, "parent", None), ast.ClassDef):
                ps = scope.args.posonlyargs + scope.args.args
                deco = {dotted_name(d) for d in scope.decorator_list}
                if ps and ps[0].arg == f.value.id and "staticmethod" not in deco and "classmethod" not in deco:
                    return [0]
            v = self.p.static_identity(srel, f.value)
            if v is not None and v.k == "pclass":
                return [-1]
        return [0, -1]

    def _call_arg_values(self, srel, call, params, kwonly, defaults, shift):
        if any(isinstance(x, ast.Starred) for x in call.args) or any(k.arg is None for k in call.keywords):
            return {p: TOP for p in params + kwonly}
        args = list(call.args)
        if shift == -1:
            if not args:
                return {p: TOP for p in params + kwonly}
            args = args[1:]
        nodes = {}
        for i, a in enumerate(args):
            if i < len(params):
                nodes[params[i]] = a
            else:
                return {p: TOP for p in params + kwonly}
        for kw in call.keywords:
            if kw.arg in params or kw.arg in kwonly:
                nodes[kw.arg] = kw.value
            else:
                return {p: TOP for p in params + kwonly}
        out = {}
        scope = enclosing_scope(call)
        it = None
        if scope is not None:
            it = self.interp(srel, scope, {id(n) for n in nodes.values()}, depth=1)
        dead = it is not None and id(call) in it.skipped
        for p in params + kwonly:
            if p in nodes:
                if it is None:
                    out[p] = TOP
                    continue
                n = nodes[p]
                if id(n) in it.recorded:
                    v = it.recorded[id(n)]
                    out[p] = v if v.k not in CONTAINERS else (OPAQUE if untainted(v) else TOP)
                elif dead or id(n) in it.skipped:
                    out[p] = None
                else:
                    out[p] = TOP
            elif p in defaults:
                lv = literal_value(defaults[p])
                out[p] = lv if lv is not None else TOP
            else:
                out[p] = TOP
        return {p: v for p, v in out.items() if v is not None}

    # ---- S2b ----
    def s2b(self, f, rel, tree):
        line, col = int(f.get("line") or 0), f.get("col")
        calls = self.find_call(tree, line, col, {"load", "load_all"})
        calls = [c for c in calls if isinstance(c.func, ast.Attribute) and c.func.attr in ("load", "load_all")]
        if len(calls) != 1:
            return None
        call = calls[0]
        scope = enclosing_scope(call)
        if scope is None:
            return None
        loader = None
        for kw in call.keywords:
            if kw.arg == "Loader":
                loader = kw.value
        if loader is None and len(call.args) >= 2:
            loader = call.args[1]
        watch = {id(call.func.value)} | ({id(loader)} if loader is not None else set())
        it = self.interp(rel, scope, watch)
        if it is None:
            return None
        recv = it.recorded.get(id(call.func.value))
        if recv is None:
            return None
        if self.p.index().yaml_tamper:
            return None
        if recv.k == "ext" and recv.x == "yaml":
            if loader is None:
                return None
            lv = it.recorded.get(id(loader))
            if lv is not None and lv.k == "ext" and lv.x in PYYAML_SAFE_LOADERS and not self.p.shadowed("yaml"):
                return ("S2b-pyyaml", {"loader": lv.x})
            return None
        if recv.k == "inst" and recv.x == ("ruamel.yaml.YAML", True) and not self.p.shadowed("ruamel.yaml"):
            return ("S2b-ruamel", {})
        return None

    # ---- S2a (builtin receivers) ----
    def s2a(self, f, rel, tree):
        line, col = int(f.get("line") or 0), f.get("col")
        calls = self.find_call(tree, line, col, SINK_SPECS["SKY-D216"][0])
        if len(calls) != 1 or not isinstance(calls[0].func, ast.Attribute):
            return None
        call = calls[0]
        scope = enclosing_scope(call)
        if scope is None:
            return None
        it = self.interp(rel, scope, {id(call.func.value)})
        if it is None:
            return None
        v = it.recorded.get(id(call.func.value))
        if v is not None and builtin_typed(v):
            return ("S2a-builtin-receiver", {"receiver": v.k})
        return None

    # ---- S2c ----
    def _chain_rel(self, path_text):
        cand = self.p.rel(path_text)
        if cand and (self.p.root / cand).is_file():
            return cand
        hits = [r for r in self.p.py_files() if r == path_text or r.endswith("/" + path_text)]
        return hits[0] if len(hits) == 1 else None

    def s2c(self, f, rel, tree, rule):
        prov = (f.get("metadata") or {}).get(PROV_KEYS[rule])
        if not isinstance(prov, dict) or prov.get("status") != "untrusted" or prov.get("limits"):
            return None
        chains = prov.get("untrusted") or []
        if not chains or len(chains) >= MAX_CHAINS:
            return None
        target = prov.get("function") or ""
        if target.count(".") != 1:
            return None
        for chain in chains:
            if not self.chain_infeasible(chain, target):
                return None
        if prov.get("unknown"):
            return None   # strict: never inherit Skylos's 'unknown -> suppressed' as a proof
        if rule not in PATH_FAMILY and prov.get("operator"):
            return None
        return ("S2c-chain", {"chains": len(chains)})

    def chain_infeasible(self, chain, target):
        for step in chain:
            if not isinstance(step, str):
                return False
            m = _STEP_CALL.match(step)
            if m is None:
                continue
            srel = self._chain_rel(m.group("file"))
            if srel is None:
                continue
            tree = self.p.parse(srel)
            if tree is None:
                continue
            line = int(m.group("line"))
            recv_text, meth = m.group("recv"), m.group("meth")
            calls = [c for c in ast.walk(tree) if isinstance(c, ast.Call) and c.lineno == line
                     and isinstance(c.func, ast.Attribute) and c.func.attr == meth
                     and dotted_name(c.func.value) == recv_text]
            if len(calls) != 1:
                continue
            call = calls[0]
            scope = enclosing_scope(call)
            if scope is None:
                continue
            it = self.interp(srel, scope, {id(call.func.value)})
            if it is None:
                continue
            if id(call) in it.skipped and id(call.func.value) not in it.recorded:
                return True   # the binding call is on an unexecutable edge
            v = it.recorded.get(id(call.func.value))
            if v is None or v.k != "obj":
                continue
            res = self.find_method(v.x, meth)
            if res is None:
                continue
            mrel, mdef = res
            owner = getattr(mdef, "parent", None)
            if not isinstance(owner, ast.ClassDef):
                continue
            if f"{owner.name}.{mdef.name}" == target:
                continue
            return True   # the call binds another class's method: this witness chain is infeasible
        return False

    # ---- driver ----
    def run(self, raw):
        findings = list(raw.get("danger", []) or [])
        decisions = []
        for f in findings:
            rel = self.p.rel(f.get("file") or "")
            d = None
            if rel is not None:
                try:
                    d = self.decide(f, rel)
                except (RecursionError, MemoryError) as exc:
                    self.log.append({"error": type(exc).__name__, "rule_id": f.get("rule_id"), "file": rel,
                                     "line": f.get("line")})
                    d = None
                except Exception as exc:  # fail closed
                    self.log.append({"error": f"{type(exc).__name__}: {exc}"[:300], "rule_id": f.get("rule_id"),
                                     "file": rel, "line": f.get("line")})
                    d = None
            decisions.append((rel, d))
        kept = []
        for f, (rel, d) in zip(findings, decisions):
            if d is None:
                kept.append(f)
            else:
                self.log.append({"drop": True, "mechanism": d[0], "rule_id": f.get("rule_id"), "file": rel,
                                 "line": f.get("line"), "col": f.get("col"), "detail": d[1]})
        return kept


def refute(findings, repo, cfg=None):
    """Run the engine over ``findings`` (Skylos danger dicts) for the checkout ``repo``.

    Returns ``(kept, log)``: ``kept`` is the list of findings that were not refuted (same dict objects, same
    order) and ``log`` holds one ``{"drop": True, "mechanism", "rule_id", "file", "line", "col", "detail"}``
    certificate per refuted finding, in input order, plus ``{"error": ...}`` entries for findings the engine
    failed closed on (those are kept).
    """
    log = []
    eng = Engine(Path(repo), cfg if cfg is not None else Config(), log)
    kept = eng.run({"danger": list(findings)})
    return kept, log
