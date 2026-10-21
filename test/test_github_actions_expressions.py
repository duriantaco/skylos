import pytest

from skylos.rules.config.cicd import actions_expressions as expressions


def _dataflow(source):
    return [
        reference.span.text
        for reference in expressions.flowing_references(expressions.parse_expression(source))
    ]


@pytest.mark.parametrize(
    ("source", "flows"),
    [
        ("github.event.issue.title", ["github.event.issue.title"]),
        ("github['event']['issue']['title']", ["github['event']['issue']['title']"]),
        ("format('{0}', github.event.comment.body)", ["github.event.comment.body"]),
        ("toJSON(github.event)", ["github.event"]),
        ("join(github.event.pull_request.labels.*.name, ',')", ["github.event.pull_request.labels.*.name"]),
        ("fromJSON(github.event.issue.body)", ["github.event.issue.body"]),
        ("a.b == 'x' && github.event.issue.title || ''", ["github.event.issue.title"]),
        ("github.event.issue.title || github.event.issue.body", ["github.event.issue.title", "github.event.issue.body"]),
        ("github.event.issue.title == 'x'", []),
        ("contains(github.event.issue.title, 'x')", []),
        ("startsWith(github.event.issue.title, 'x')", []),
        ("!github.event.issue.title", []),
        ("case(github.event.issue.locked, github.event.issue.title, 'none')", ["github.event.issue.title"]),
        ("'literal'", []),
        ("(github.event.issue.title)", ["(github.event.issue.title)"]),
    ],
)
def test_dataflow_contexts(source, flows):
    assert _dataflow(source) == flows


@pytest.mark.parametrize(
    ("source", "pattern"),
    [
        ("github.event.issue.title", "github.event.issue.title"),
        ("GitHub.Event['Issue'].title", "github.event.issue.title"),
        ("github.event.pull_request.labels[0].name", "github.event.pull_request.labels.*.name"),
        ("github.event.pull_request.labels[x.y].name", "github.event.pull_request.labels.*.name"),
        ("fromJSON(x).y", None),
    ],
)
def test_context_patterns(source, pattern):
    assert expressions.parse_expression(source).key() == pattern


def test_context_matching():
    reference = expressions.parse_reference("needs.build.result")
    assert reference.is_exactly("needs.*.result")
    assert reference.under("needs")
    assert not reference.is_exactly("needs.*")
    assert expressions.parse_reference("env['FOO']").only_member() == "FOO"
    assert expressions.parse_reference("env.foo.bar").only_member() is None


@pytest.mark.parametrize(
    "source",
    [
        "",
        "a = b",
        "a & b",
        "'unterminated",
        "unknown(1)",
        "contains(a)",
        "case(a, b)",
        "foo(",
        "a.",
        "1 2",
        "!" * 60 + "true",
        "0X1",
        "0O7",
        "1_000",
    ],
)
def test_invalid_expressions(source):
    with pytest.raises(expressions.ExpressionError):
        expressions.parse_expression(source)


@pytest.mark.parametrize(
    ("source", "value"),
    [("0x10", 16.0), ("-1.5e2", -150.0), ("Infinity", float("inf")), ("'it''s'", "it's"), ("true", True), ("null", None)],
)
def test_literals(source, value):
    assert expressions.parse_expression(source).value == value


def test_nan_is_a_literal_and_long_chains_do_not_recurse():
    value = expressions.parse_expression("NaN").value
    assert value != value
    chain = "||".join(["0"] * 5000 + ["github.event.issue.title"])
    assert _dataflow(chain) == ["github.event.issue.title"]


def test_keywords_after_a_dot_are_members():
    reference = expressions.parse_expression("github.event.true")
    assert isinstance(reference, expressions.Reference)
    assert reference.key() == "github.event.true"


def test_fenced_expressions_skip_braces_inside_strings():
    text = "echo ${{ format('}}', a.b) }} and ${{ c.d }} ${{ open"
    assert [body.strip() for body, _start, _end in expressions.template_spans(text)] == [
        "format('}}', a.b)",
        "c.d",
    ]
