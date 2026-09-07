import pytest

from skylos.rules.config.cicd.yaml_source import load_yaml_with_locations


def _load(text, **limits):
    result = load_yaml_with_locations(text, **limits)
    assert result is not None
    return result


def test_locations_follow_scopes_and_ignore_textual_lookalikes():
    data, source = _load(
        "# label: ignored\n"
        "name: 'label: ignored'\n"
        "notes: |\n"
        "  label: ignored\n"
        "groups:\n"
        "  first:\n"
        "    label: repeated\n"
        "  second:\n"
        "    'label': repeated\n"
    )
    assert data["groups"]["second"]["label"] == "repeated"
    assert source.line_for_path(("groups", "first", "label")) == 7
    assert source.line_for_path(("groups", "second", "label")) == 9
    assert source.line_for_path(("label",)) is None


def test_mapping_sequence_and_scalar_values_have_distinct_paths():
    _, source = _load(
        '"events":\n'
        "  - alpha\n"
        "  - beta\n"
        "groups:\n"
        "  sample:\n"
        "    entries:\n"
        "      - label:\n"
        "          text: example\n"
    )
    assert source.line_for_path(("events",)) == 1
    assert source.line_for_path(("events",), key=False) == 2
    assert source.line_for_path(("events", 1)) == 3
    assert source.line_for_path(("groups", "sample")) == 5
    assert source.line_for_path(("groups", "sample"), key=False) == 6
    assert (
        source.line_for_path(("groups", "sample", "entries", 0, "label", "text")) == 8
    )


def test_flow_collections_and_quoted_keys():
    data, source = _load(
        '"groups": {first: {"label": alpha},\n  second: {label: beta}}\n'
    )
    assert data["groups"]["second"]["label"] == "beta"
    assert source.line_for_path(("groups", "first", "label")) == 1
    assert source.line_for_path(("groups", "second", "label")) == 2


def test_duplicate_keys_follow_safe_loader_last_wins_behavior():
    data, source = _load("group:\n  label: old\ngroup:\n  label: new\n")
    assert data == {"group": {"label": "new"}}
    assert source.line_for_path(("group",)) == 3
    assert source.line_for_path(("group", "label")) == 4


def test_boolean_key_semantics_are_preserved():
    data, source = _load("on: alpha\ntrue: beta\n'on': gamma\n")
    assert data == {True: "beta", "on": "gamma"}
    assert source.line_for_path((True,)) == 2
    assert source.line_for_path(("on",)) == 3


def test_mapping_alias_uses_local_reference_for_descendants():
    data, source = _load(
        "base: &base\n  nested:\n    label: example\ngroup:\n  *base\n"
    )
    assert data["group"] == data["base"]
    assert source.line_for_path(("base", "nested", "label")) == 3
    assert source.line_for_path(("group",)) == 4
    assert source.line_for_path(("group",), key=False) == 5
    assert source.line_for_path(("group", "nested", "label")) == 5


def test_scalar_and_sequence_aliases_use_local_references():
    _, source = _load(
        "label: &label sample\n"
        "items: &items\n"
        "  - nested: value\n"
        "groups:\n"
        "  - *label\n"
        "  - *items\n"
    )
    assert source.line_for_path(("groups", 0)) == 5
    assert source.line_for_path(("groups", 1, 0, "nested")) == 6


def test_alias_keys_use_local_key_reference():
    data, source = _load("key: &name label\ngroup:\n  *name: example\n")
    assert data["group"] == {"label": "example"}
    assert source.line_for_path(("group", "label")) == 3


def test_merges_use_local_merge_lines_but_keep_explicit_overrides():
    data, source = _load(
        "base: &base\n"
        "  nested:\n"
        "    label: inherited\n"
        "  title: old\n"
        "group:\n"
        "  <<: *base\n"
        "  title: new\n"
    )
    assert data["group"] == {"nested": {"label": "inherited"}, "title": "new"}
    assert source.line_for_path(("group", "nested")) == 6
    assert source.line_for_path(("group", "nested", "label")) == 6
    assert source.line_for_path(("group", "title")) == 7


def test_merge_sequence_precedence_matches_constructed_data():
    data, source = _load(
        "first: &first {label: first}\n"
        "second: &second {label: second, title: title}\n"
        "group:\n"
        "  <<: [*first, *second]\n"
    )
    assert data["group"] == {"label": "first", "title": "title"}
    assert source.line_for_path(("group", "label")) == 4
    assert source.line_for_path(("group", "title")) == 4


def test_nested_merges_keep_outer_use_site():
    data, source = _load(
        "base: &base {label: sample}\n"
        "middle: &middle\n"
        "  <<: *base\n"
        "group:\n"
        "  <<: *middle\n"
    )
    assert data["group"]["label"] == "sample"
    assert source.line_for_path(("group", "label")) == 5


def test_scalar_spans_distinguish_comments_from_text():
    _, source = _load(
        "# document comment\n"
        "plain: word#part # plain comment\n"
        'quoted: "# quoted text" # quoted comment\n'
        "block: | # block header comment\n"
        "  # block text\n"
        "  more # block text\n"
        "folded: >\n"
        "  # folded text\n"
        "empty: # empty comment\n"
    )
    assert source.comment_on_line(1) == "# document comment"
    assert source.comment_on_line(2) == "# plain comment"
    assert source.comment_on_line(3) == "# quoted comment"
    assert source.comment_on_line(4) == "# block header comment"
    assert source.comment_on_line(5) is None
    assert source.comment_on_line(6) is None
    assert source.comment_on_line(8) is None
    assert source.comment_on_line(9) == "# empty comment"
    assert source.comment_on_line(0) is None
    assert source.comment_on_line(10) is None


def test_multiline_quoted_scalars_do_not_supply_comments():
    _, source = _load('text: "first\n  # still quoted\n  last" # actual comment\n')
    assert source.comment_on_line(2) is None
    assert source.comment_on_line(3) == "# actual comment"


@pytest.mark.parametrize(
    "path",
    [("missing",), ("items", -1), ("items", 2), ("items", "0"), ("label", "nested")],
)
def test_invalid_paths_return_none(path):
    _, source = _load("items: [a, b]\nlabel: example\n")
    assert source.line_for_path(path) is None


@pytest.mark.parametrize(
    "text",
    [
        "",
        "- entry\n",
        "label: [\n",
        "label: !widget example\n",
        "label: !!timestamp arbitrary\n",
        "? [first, second]\n: example\n",
        "? {label: example}\n: value\n",
        "label: *missing\n",
        "label: first\n---\nlabel: second\n",
    ],
)
def test_invalid_or_non_mapping_documents_fail_closed(text):
    assert load_yaml_with_locations(text) is None


def test_cyclic_alias_graphs_fail_closed():
    assert load_yaml_with_locations("group: &group {child: *group}\n") is None


def test_depth_and_node_bounds_apply_before_construction():
    assert (
        load_yaml_with_locations("outer: {inner: {label: value}}", max_depth=2) is None
    )
    assert load_yaml_with_locations("a: 1\nb: 2\n", max_nodes=4) is None
    assert load_yaml_with_locations("a: 1\nb: 2\n", max_nodes=5) is not None


def test_alias_reuse_still_checks_longest_graph_path():
    text = "base: &base {label: value}\ngroup: {nested: *base}\n"
    assert load_yaml_with_locations(text, max_depth=2) is None
    assert load_yaml_with_locations(text, max_depth=3) is not None


def test_repeated_merge_expansion_is_bounded():
    text = (
        "base: &base {a: 1, b: 2, c: 3}\n"
        "group: {<<: [*base, *base, *base, *base, *base, *base, *base, *base]}\n"
    )
    assert load_yaml_with_locations(text, max_nodes=25) is None
    assert load_yaml_with_locations(text, max_nodes=50) is not None
