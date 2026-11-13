"""Regular expressions whose matching time explodes on crafted input.

Each pattern written as a string in a ``re`` call is parsed, and a small
backtracking matcher inside Skylos counts the steps it needs on generated
inputs of growing length. A pattern is reported only when the step count
itself grows exponentially, or at least cubically, so every finding carries
the input shape that shows it. Nothing from the scanned project is executed.
"""

from __future__ import annotations

import ast
import math
import re
import sys

try:
    import re._constants as _constants
    import re._parser as _parser
except ImportError:
    _constants = None
    _parser = None

RULE_ID = "SKY-D379"
SEVERITY = "MEDIUM"
_SIZES = (2, 3, 4, 6, 8, 12, 16, 24, 32)
_RUN_STEPS = 60_000
_PATTERN_STEPS = 1_000_000
_FILE_STEPS = 3_000_000
_MAX_VERDICTS = 4_096
_MAX_REPEATS = 8
_MAX_PUMPS = 10
_MAX_REJECTED = 4
_MAX_NAMED = 4
_MAX_PATTERN_LENGTH = 10_000
_PUMP_WIDTHS = (1, 2, 3)
_RECURSION_LIMIT = 6_000
_SUFFIXES = ("\x00", "!", "")
_PREFERRED = "a0 _-./:,;=<>\"'@#%&()[]{}|\\+*?^$~`\t\n"
_LINEAR_DEGREE = 1.6
_POLYNOMIAL_DEGREE = 2.7
_POLYNOMIAL_PREVIOUS = 2.4
_EXPONENTIAL_DEGREE = 5.5
_EXPONENTIAL_PREVIOUS = 4.0
_SEARCH_FUNCTIONS = frozenset({"search", "sub", "subn", "split", "findall", "finditer"})
_MODES = {"compile": "match", "match": "match", "fullmatch": "fullmatch"}
_FLAG_POSITION = {
    "compile": 1,
    "match": 2,
    "fullmatch": 2,
    "search": 2,
    "findall": 2,
    "finditer": 2,
    "split": 3,
    "sub": 4,
    "subn": 4,
}
_FLAG_NAMES = {
    "A": re.ASCII,
    "ASCII": re.ASCII,
    "I": re.IGNORECASE,
    "IGNORECASE": re.IGNORECASE,
    "L": re.LOCALE,
    "LOCALE": re.LOCALE,
    "M": re.MULTILINE,
    "MULTILINE": re.MULTILINE,
    "S": re.DOTALL,
    "DOTALL": re.DOTALL,
    "U": re.UNICODE,
    "UNICODE": re.UNICODE,
    "X": re.VERBOSE,
    "VERBOSE": re.VERBOSE,
    "NOFLAG": 0,
}


_VERDICTS = {}


class _Budget(Exception):
    pass


class _Unsupported(Exception):
    pass


def _category(code, char):
    if code is _constants.CATEGORY_DIGIT:
        return char.isdigit()
    if code is _constants.CATEGORY_NOT_DIGIT:
        return not char.isdigit()
    if code is _constants.CATEGORY_SPACE:
        return char.isspace()
    if code is _constants.CATEGORY_NOT_SPACE:
        return not char.isspace()
    if code is _constants.CATEGORY_WORD:
        return char.isalnum() or char == "_"
    if code is _constants.CATEGORY_NOT_WORD:
        return not (char.isalnum() or char == "_")
    raise _Unsupported


def _in_set(items, char):
    negate = False
    found = False
    code = ord(char)
    for op, value in items:
        if op is _constants.NEGATE:
            negate = True
        elif op is _constants.LITERAL:
            found = found or value == code
        elif op is _constants.RANGE:
            found = found or value[0] <= code <= value[1]
        elif op is _constants.CATEGORY:
            found = found or _category(value, char)
        else:
            raise _Unsupported
    return found != negate


class _Run:
    """One match attempt over ``text`` that counts its steps."""

    def __init__(self, text, flags, limit):
        self.text = text
        self.size = len(text)
        self.limit = limit
        self.steps = 0
        self.dotall = bool(flags & re.DOTALL)
        self.multiline = bool(flags & re.MULTILINE)
        self.ignorecase = bool(flags & re.IGNORECASE)

    def tick(self):
        self.steps += 1
        if self.steps > self.limit:
            raise _Budget

    def single(self, op, value, char):
        if op is _constants.LITERAL:
            return self.same(chr(value), char)
        if op is _constants.NOT_LITERAL:
            return not self.same(chr(value), char)
        if op is _constants.ANY:
            return self.dotall or char != "\n"
        if op is _constants.IN:
            if _in_set(value, char):
                return True
            if not self.ignorecase:
                return False
            return _in_set(value, char.lower()) or _in_set(value, char.upper())
        return None

    def same(self, left, right):
        if left == right:
            return True
        return self.ignorecase and left.lower() == right.lower()

    def word(self, pos):
        if pos < 0 or pos >= self.size:
            return False
        char = self.text[pos]
        return char.isalnum() or char == "_"

    def at(self, code, pos):
        text = self.text
        if code is _constants.AT_BEGINNING:
            if pos == 0:
                return True
            return self.multiline and text[pos - 1] == "\n"
        if code is _constants.AT_BEGINNING_STRING:
            return pos == 0
        if code is _constants.AT_END:
            if pos == self.size:
                return True
            if pos == self.size - 1 and text[pos] == "\n":
                return True
            return self.multiline and text[pos] == "\n"
        if code is _constants.AT_END_STRING:
            return pos == self.size
        if code is _constants.AT_BOUNDARY:
            return self.word(pos - 1) != self.word(pos)
        if code is _constants.AT_NON_BOUNDARY:
            return self.word(pos - 1) == self.word(pos)
        raise _Unsupported

    def seq(self, items, index, pos, then):
        self.tick()
        if index == len(items):
            return then(pos)
        op, value = items[index]
        if pos < self.size:
            matched = self.single(op, value, self.text[pos])
        else:
            matched = self.single(op, value, "\x00")
            if matched is not None:
                matched = False
        if matched is not None:
            return matched and self.seq(items, index + 1, pos + 1, then)

        def rest(after):
            return self.seq(items, index + 1, after, then)

        if op is _constants.AT:
            return self.at(value, pos) and rest(pos)
        if op is _constants.SUBPATTERN:
            _group, add_flags, del_flags, body = value
            if add_flags or del_flags:
                raise _Unsupported
            return self.seq(body, 0, pos, rest)
        if op is _constants.BRANCH:
            for alternative in value[1]:
                if self.seq(alternative, 0, pos, rest):
                    return True
            return False
        if op is _constants.MAX_REPEAT:
            return self.repeat(value[2], value[0], value[1], True, 0, pos, rest)
        if op is _constants.MIN_REPEAT:
            return self.repeat(value[2], value[0], value[1], False, 0, pos, rest)
        if op is _constants.POSSESSIVE_REPEAT:
            return self.atomic(
                lambda stop: self.repeat(
                    value[2], value[0], value[1], True, 0, pos, stop
                ),
                rest,
            )
        if op is _constants.ATOMIC_GROUP:
            return self.atomic(lambda stop: self.seq(value, 0, pos, stop), rest)
        if op in (_constants.ASSERT, _constants.ASSERT_NOT):
            direction, body = value
            if direction != 1:
                raise _Unsupported
            ahead = self.seq(body, 0, pos, lambda _after: True)
            if op is _constants.ASSERT_NOT:
                ahead = not ahead
            return ahead and rest(pos)
        raise _Unsupported

    def atomic(self, attempt, then):
        ends = []

        def stop(after):
            ends.append(after)
            return True

        if not attempt(stop):
            return False
        return then(ends[0])

    def repeat(self, body, low, high, greedy, count, pos, then):
        self.tick()

        def again(after):
            if after == pos and count >= low:
                return False
            return self.repeat(body, low, high, greedy, count + 1, after, then)

        if count < low:
            return self.seq(body, 0, pos, again)
        if greedy:
            if count < high and self.seq(body, 0, pos, again):
                return True
            return then(pos)
        if then(pos):
            return True
        return count < high and self.seq(body, 0, pos, again)


def _steps(tree, flags, text, mode, limit):
    """Steps one ``re`` call of this kind needs on ``text``; None above the limit."""
    run = _Run(text, flags, limit)

    def accept(after):
        return mode != "fullmatch" or after == run.size

    try:
        if mode == "search":
            for start in range(run.size + 1):
                if run.seq(tree, 0, start, accept):
                    break
        else:
            run.seq(tree, 0, 0, accept)
    except _Budget:
        return None
    return run.steps


def _sample(op, value):
    probe = _Run("", 0, 10)
    for char in _PREFERRED:
        if probe.single(op, value, char):
            return char
    for code in range(33, 127):
        if probe.single(op, value, chr(code)):
            return chr(code)
    raise _Unsupported


def _witness(items, width=1):
    """A short text the items match; unbounded repeats run ``width`` times."""
    parts = []
    for op, value in items:
        if op in (
            _constants.LITERAL,
            _constants.NOT_LITERAL,
            _constants.ANY,
            _constants.IN,
        ):
            parts.append(_sample(op, value))
        elif op is _constants.SUBPATTERN:
            parts.append(_witness(value[3], width))
        elif op is _constants.BRANCH:
            parts.append(_witness(value[1][0], width))
        elif _is_repeat(op):
            count = value[0]
            if value[1] is _constants.MAXREPEAT:
                count = max(count, width)
            if count > 64:
                raise _Unsupported
            parts.append(_witness(value[2], width) * count)
        elif op is _constants.ATOMIC_GROUP:
            parts.append(_witness(value, width))
        elif op in (_constants.AT, _constants.ASSERT, _constants.ASSERT_NOT):
            continue
        else:
            raise _Unsupported
    return "".join(parts)


def _is_repeat(op):
    return op in (
        _constants.MAX_REPEAT,
        _constants.MIN_REPEAT,
        _constants.POSSESSIVE_REPEAT,
    )


def _unbounded_repeats(items, prefix, found):
    """``(prefix, body)`` of each unbounded repeat, with a text that leads to it."""
    before = prefix
    for op, value in items:
        if len(found) >= _MAX_REPEATS:
            return
        if _is_repeat(op):
            if value[1] is _constants.MAXREPEAT:
                found.append((before, value[2]))
            _unbounded_repeats(value[2], before, found)
        elif op is _constants.SUBPATTERN:
            _unbounded_repeats(value[3], before, found)
        elif op is _constants.ATOMIC_GROUP:
            _unbounded_repeats(value, before, found)
        elif op is _constants.BRANCH:
            for alternative in value[1]:
                _unbounded_repeats(alternative, before, found)
        try:
            before += _witness([(op, value)])
        except _Unsupported:
            return


def _shape(items, counts):
    """Counts of repeats, unbounded repeats and risky nesting in the pattern."""
    for op, value in items:
        if _is_repeat(op):
            if value[1] is _constants.MAXREPEAT or value[1] > 1:
                counts["repeats"] += 1
            if value[1] is _constants.MAXREPEAT:
                counts["unbounded"] += 1
            _shape(value[2], counts)
        elif op is _constants.SUBPATTERN:
            _shape(value[3], counts)
        elif op is _constants.ATOMIC_GROUP:
            _shape(value, counts)
        elif op is _constants.BRANCH:
            counts["branches"] += 1
            for alternative in value[1]:
                _shape(alternative, counts)
        elif op in (_constants.ASSERT, _constants.ASSERT_NOT):
            _shape(value[1], counts)


def _worth_measuring(tree):
    counts = {"repeats": 0, "unbounded": 0, "branches": 0}
    _shape(tree, counts)
    if not counts["unbounded"]:
        return False
    return counts["repeats"] >= 2 or counts["branches"] >= 1


def _literal_chars(items, chars, rejected):
    """Characters the pattern names, and those a negated class refuses."""
    for op, value in items:
        if op is _constants.LITERAL:
            chars.append(chr(value))
        elif op is _constants.NOT_LITERAL:
            rejected.append(chr(value))
        elif op is _constants.IN:
            target = chars
            if value and value[0][0] is _constants.NEGATE:
                target = rejected
            for inner, inner_value in value:
                if inner is _constants.LITERAL:
                    target.append(chr(inner_value))
        elif _is_repeat(op):
            _literal_chars(value[2], chars, rejected)
        elif op is _constants.SUBPATTERN:
            _literal_chars(value[3], chars, rejected)
        elif op is _constants.ATOMIC_GROUP:
            _literal_chars(value, chars, rejected)
        elif op is _constants.BRANCH:
            for alternative in value[1]:
                _literal_chars(alternative, chars, rejected)


def _pumps(body, flags, literals):
    """Texts one pass of a repeat body can match, most telling first."""
    pumps = []
    for width in _PUMP_WIDTHS:
        try:
            whole = _witness(body, width)
        except _Unsupported:
            break
        if whole and whole not in pumps:
            pumps.append(whole)
    for char in [*literals, *_PREFERRED[:3]]:
        if len(pumps) >= _MAX_PUMPS:
            break
        if char in pumps:
            continue
        run = _Run(char, flags, 200)
        try:
            matched = run.seq(body, 0, 0, lambda after: after == 1)
        except (_Budget, _Unsupported):
            matched = False
        if matched:
            pumps.append(char)
    return pumps


def _degree(small, large, small_size, large_size):
    return math.log(large / small) / math.log(large_size / small_size)


def _growth(tree, flags, mode, prefix, pump, suffix, spent):
    """``exponential``, ``polynomial`` or None for one input shape."""
    degrees = []
    bound = None
    previous = None
    previous_size = None
    for size in _SIZES:
        if len(prefix) + len(pump) * size + len(suffix) > 400:
            break
        steps = _steps(tree, flags, prefix + pump * size + suffix, mode, _RUN_STEPS)
        if steps is None:
            spent[0] += _RUN_STEPS
            if previous is not None:
                bound = _degree(previous, _RUN_STEPS, previous_size, size)
            break
        spent[0] += steps
        if previous is not None:
            degrees.append(_degree(previous, steps, previous_size, size))
            if len(degrees) >= 4 and max(degrees) < _LINEAR_DEGREE:
                return None
        previous = steps
        previous_size = size
    capped = bound is not None
    if degrees and degrees[-1] >= _EXPONENTIAL_DEGREE:
        if capped or (len(degrees) >= 2 and degrees[-2] >= _EXPONENTIAL_PREVIOUS):
            return "exponential"
    if capped and bound >= _EXPONENTIAL_DEGREE:
        if not degrees or degrees[-1] >= _EXPONENTIAL_PREVIOUS:
            return "exponential"
    if len(degrees) < 2:
        return None
    if degrees[-1] >= _POLYNOMIAL_DEGREE and degrees[-2] >= _POLYNOMIAL_PREVIOUS:
        return "polynomial"
    return None


def _parse(pattern, flags):
    if _parser is None or len(pattern) > _MAX_PATTERN_LENGTH:
        return None
    if not any(mark in pattern for mark in "*+{"):
        return None
    try:
        tree = _parser.parse(pattern, flags)
    except (re.error, RecursionError, OverflowError, ValueError):
        return None
    return tree


def analyze_pattern(pattern, flags, mode, spent=None):
    """How matching time explodes for ``pattern``, or None.

    The answer names the growth and the input shape ``prefix + pump * n +
    suffix`` that shows it.
    """
    if spent is None:
        spent = [0]
    tree = _parse(pattern, flags)
    if tree is None:
        return None
    flags = tree.state.flags
    previous_limit = sys.getrecursionlimit()
    if previous_limit < _RECURSION_LIMIT:
        sys.setrecursionlimit(_RECURSION_LIMIT)
    try:
        return _analyze(tree, flags, mode, spent)
    except (_Unsupported, RecursionError):
        return None
    finally:
        sys.setrecursionlimit(previous_limit)


def _analyze(tree, flags, mode, spent):
    if not _worth_measuring(tree):
        return None
    repeats = []
    _unbounded_repeats(tree, "", repeats)
    named = []
    rejected = []
    _literal_chars(tree, named, rejected)
    rejected = [char for char in dict.fromkeys(rejected) if not char.isspace()]
    literals = [*rejected[:_MAX_REJECTED], *list(dict.fromkeys(named))[:_MAX_NAMED]]
    literals = list(dict.fromkeys(literals))
    suffixes = list(dict.fromkeys([*_SUFFIXES, *rejected[:_MAX_REJECTED]]))
    start = spent[0]
    polynomial = None
    tried = set()
    for prefix, body in repeats:
        for pump in _pumps(body, flags, literals):
            for suffix in suffixes:
                shape = (prefix, pump, suffix)
                if shape in tried:
                    continue
                tried.add(shape)
                if spent[0] - start > _PATTERN_STEPS:
                    return polynomial
                try:
                    growth = _growth(tree, flags, mode, prefix, pump, suffix, spent)
                except _Unsupported:
                    continue
                if growth is None:
                    continue
                verdict = {
                    "growth": growth,
                    "prefix": prefix,
                    "pump": pump,
                    "suffix": suffix,
                }
                if growth == "exponential":
                    return verdict
                if polynomial is None:
                    polynomial = verdict
    return polynomial


def _bound_names(tree):
    """How often each name is bound in the file by something other than an import."""
    counts = {}

    def bind(name):
        counts[name] = counts.get(name, 0) + 1

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(node.name)
        elif isinstance(node, ast.arg):
            bind(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bind(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bind(node.name)
    return counts


class _Checker:
    def __init__(self, tree, file_path, findings):
        self.tree = tree
        self.file_path = file_path
        self.findings = findings
        self.modules = set()
        self.functions = {}
        self.constants = {}
        self.spent = [0]

    def collect(self):
        imported = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    imported[name] = imported.get(name, 0) + 1
                    if alias.name == "re":
                        self.modules.add(name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported[name] = imported.get(name, 0) + 1
                    if (
                        node.module == "re"
                        and node.level == 0
                        and alias.name in _FLAG_POSITION
                    ):
                        self.functions[name] = alias.name
        bound = _bound_names(self.tree)
        for name in [*self.modules]:
            if bound.get(name) or imported.get(name, 0) > 1:
                self.modules.discard(name)
        for name in [*self.functions]:
            if bound.get(name) or imported.get(name, 0) > 1:
                del self.functions[name]
        for node in self.tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name) or bound.get(target.id) != 1:
                continue
            if imported.get(target.id):
                continue
            if isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            ):
                self.constants[target.id] = node.value.value

    def function_of(self, call):
        func = call.func
        if isinstance(func, ast.Name):
            return self.functions.get(func.id)
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in self.modules
            and func.attr in _FLAG_POSITION
        ):
            return func.attr
        return None

    def text_of(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.constants.get(node.id)
        return None

    def flags_of(self, node):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
        ):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self.flags_of(node.left)
            right = self.flags_of(node.right)
            if left is None or right is None:
                return None
            return left | right
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in self.modules
        ):
            return _FLAG_NAMES.get(node.attr)
        return None

    def argument(self, call, position, keyword):
        if any(isinstance(arg, ast.Starred) for arg in call.args):
            return None, False
        if any(item.arg is None for item in call.keywords):
            return None, False
        for item in call.keywords:
            if item.arg == keyword:
                return item.value, True
        if position < len(call.args):
            return call.args[position], True
        return None, True

    def check(self, call, symbol):
        name = self.function_of(call)
        if name is None:
            return
        pattern_node, known = self.argument(call, 0, "pattern")
        if not known or pattern_node is None:
            return
        pattern = self.text_of(pattern_node)
        if pattern is None:
            return
        flags_node, known = self.argument(call, _FLAG_POSITION[name], "flags")
        if not known:
            return
        flags = 0
        if flags_node is not None:
            flags = self.flags_of(flags_node)
            if flags is None:
                return
        mode = _MODES.get(name, "search")
        key = (pattern, flags, mode)
        if key not in _VERDICTS:
            if self.spent[0] > _FILE_STEPS:
                return
            if len(_VERDICTS) >= _MAX_VERDICTS:
                _VERDICTS.clear()
            _VERDICTS[key] = analyze_pattern(pattern, flags, mode, self.spent)
        verdict = _VERDICTS[key]
        if verdict is None:
            return
        shape = (
            f"{verdict['prefix']!r} + {verdict['pump']!r} * n + {verdict['suffix']!r}"
        )
        speed = "exponentially"
        if verdict["growth"] == "polynomial":
            speed = "in cubic or worse time"
        self.findings.append(
            {
                "rule_id": RULE_ID,
                "severity": SEVERITY,
                "message": (
                    f"Catastrophic regex backtracking: this pattern slows down {speed} on input "
                    f"shaped like {shape}. Rewrite the nested or adjacent repeats so they cannot "
                    "match the same text, or limit the input length before matching."
                ),
                "file": self.file_path,
                "line": call.lineno,
                "col": call.col_offset,
                "symbol": symbol,
                "metadata": {"regex_attack": dict(verdict)},
            }
        )

    def visit(self, node, symbol):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbol = node.name
        if isinstance(node, ast.Call):
            self.check(node, symbol)
        for child in ast.iter_child_nodes(node):
            self.visit(child, symbol)


def scan(tree, file_path, findings):
    if _parser is None:
        return
    checker = _Checker(tree, str(file_path), findings)
    checker.collect()
    if not checker.modules and not checker.functions:
        return
    try:
        checker.visit(tree, "<module>")
    except RecursionError:
        return
