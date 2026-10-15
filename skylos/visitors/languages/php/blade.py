"""References from Blade templates and from class names written as strings.

tree-sitter-php sees a ``.blade.php`` template as HTML text: ``{{ versioned_asset('x') }}``,
``@if(userCanOnAny('view'))``, ``{{ (new \\App\\TagClassGenerator($x))->generate() }}``,
``@inject('head', 'App\\Theming\\HeadContent')`` and ``$book->getUrl()`` never reach
the PHP reference pass, so helpers, classes and methods used only by views looked
unused. These patterns turn template text into the same dotted names the PHP
analyzer emits. Extra names only keep code alive; they never create findings.

PHP code also names classes in strings: Laravel container keys and config
arrays (``'App\\Services\\Foo'``) and Blade directives that generate PHP
(``"<?php echo (new \\App\\Util\\SvgIcon($e))->toHtml(); ?>"``).
"""

from __future__ import annotations

import re

# ``\App\Util\SvgIcon``, ``App\\Models\\User`` (escaped), at least one
# namespace separator; the first segment starts upper-case like a namespace.
_FQN_RE = re.compile(
    r"(?<![\w\\])\\{0,2}([A-Z][A-Za-z0-9_]*(?:\\{1,2}[A-Za-z_][A-Za-z0-9_]*)+)"
)
_FUNCTION_CALL_RE = re.compile(r"(?<![\w$\\>:])([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_MEMBER_RE = re.compile(r"(?:->|\?->)\s*([A-Za-z_][A-Za-z0-9_]*)")
_NEW_RE = re.compile(r"\bnew\s+\\?([A-Za-z_][A-Za-z0-9_\\]*)")
_STATIC_RE = re.compile(
    r"(?<![\w\\$])\\?([A-Z][A-Za-z0-9_\\]*)::\$?([A-Za-z_][A-Za-z0-9_]*)"
)
_MAX_TEMPLATE_CHARS = 2_000_000


def _dotted(name: str) -> str:
    return re.sub(r"\\{1,2}", ".", name).strip(".")


def php_string_class_refs(text: str) -> list[str]:
    """Fully qualified class names written inside a PHP string."""
    if "\\" not in text:
        return []
    return list(dict.fromkeys(_dotted(match) for match in _FQN_RE.findall(text)))


def blade_template_refs(text: str) -> list[str]:
    """Function, class and member names a Blade template uses."""
    text = text[:_MAX_TEMPLATE_CHARS]
    names: dict[str, None] = {}
    for match in _FQN_RE.findall(text):
        names[_dotted(match)] = None
    for match in _NEW_RE.findall(text):
        names[_dotted(match)] = None
    for owner, member in _STATIC_RE.findall(text):
        dotted_owner = _dotted(owner)
        names[dotted_owner] = None
        names[f"{dotted_owner}.{member}"] = None
        names[member] = None
    for match in _FUNCTION_CALL_RE.findall(text):
        names[match] = None
    for match in _MEMBER_RE.findall(text):
        names[match] = None
    return list(names)
