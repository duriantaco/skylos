import re

import pytest

from skylos.rules.danger.danger_web.url_patterns import url_pattern_is_safe


@pytest.mark.parametrize(
    ("pattern", "flags", "method"),
    [
        (r"https?://\S+", re.I, "fullmatch"),
        (r"https?://", 0, "match"),
        (r"(https?|ftp)://", 0, "match"),
        (r"[jh]ttps://", 0, "match"),
        (r"^https?://", 0, "search"),
        (r"\Ahttps://", re.M, "search"),
        (r"/[^/].*", 0, "match"),
        (r"/|https?://", 0, "match"),
        (r"(?i:H)ttps", 0, "match"),
        (r"mailto:", 0, "match"),
        (r"#.*", 0, "match"),
        (r"h t t p s", re.X, "match"),
        (r"(?=javascript)https://", 0, "match"),
        ("ſx", re.I, "match"),
    ],
)
def test_patterns_that_only_admit_safe_schemes(pattern, flags, method):
    assert url_pattern_is_safe(pattern, flags, method)


@pytest.mark.parametrize(
    ("pattern", "flags", "method"),
    [
        (r"[a-z]+://.*", 0, "match"),
        (r"(https://)?.*", 0, "match"),
        (r"https?://", 0, "search"),
        (r"^https?://", re.M, "search"),
        (r"javascript:.*", 0, "match"),
        (r"(?i)JAVA", 0, "match"),
        (r".*", 0, "match"),
        (r"d(?:ata)?", 0, "match"),
        (r"[^j].*", 0, "match"),
        (r"x{0}javascript:", 0, "match"),
        (b"https://", 0, "match"),
        (r"(", 0, "match"),
        (r"\x00javascript:", 0, "match"),
        (r"\tjavascript:", 0, "match"),
        (r"java\nscript:", 0, "match"),
        (r"(?:https?|data):", 0, "match"),
        (r"https?://|", 0, "match"),
        (r"v", re.I, "match"),
    ],
)
def test_patterns_that_admit_a_script_scheme_or_cannot_be_spelled(pattern, flags, method):
    assert not url_pattern_is_safe(pattern, flags, method)


@pytest.mark.parametrize(
    ("pattern", "flags", "matches_script", "safe"),
    [
        (r"(?ui:javaſcript):", re.ASCII, True, False),
        (r"(?u:javaſcript):", re.ASCII | re.I, True, False),
        (r"(?ui:(?a:javaſcript):)", re.ASCII, False, True),
        (r"(?ai:javaſcript):", 0, False, True),
        (r"(?u-i:javaſcript):", re.ASCII | re.I, False, True),
        (r"(?ui:httpſ://)", re.ASCII, False, True),
    ],
)
def test_scoped_character_modes_follow_python_regex_semantics(pattern, flags, matches_script, safe):
    assert bool(re.match(pattern, "javascript:alert(1)", flags)) is matches_script
    assert url_pattern_is_safe(pattern, flags, "match") is safe
