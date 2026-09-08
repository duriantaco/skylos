"""Load YAML and retain locations for semantic paths through the document."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    import yaml
    from yaml.events import AliasEvent
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
except ImportError:  # pragma: no cover - PyYAML is a runtime dependency.
    yaml = None


_MERGE_TAG = "tag:yaml.org,2002:merge"


if yaml is not None:

    class _LocationLoader(yaml.SafeLoader):
        def __init__(self, text: str, max_depth: int, max_nodes: int):
            super().__init__(text)
            self.alias_lines: dict[tuple[Node, str, int], int] = {}
            self.text_lines = text.splitlines()
            self.max_depth = max_depth
            self.max_nodes = max_nodes
            self._depth = -1
            self._nodes = 0

        def compose_node(self, parent, index):
            self._depth += 1
            self._nodes += 1
            try:
                if self._depth > self.max_depth or self._nodes > self.max_nodes:
                    raise ValueError("YAML resource limit exceeded")
                if parent is not None and self.check_event(AliasEvent):
                    if isinstance(parent, MappingNode):
                        edge = (
                            parent,
                            "key" if index is None else "value",
                            len(parent.value),
                        )
                    else:
                        edge = (parent, "item", index)
                    self.alias_lines[edge] = self.peek_event().start_mark.line + 1
                return super().compose_node(parent, index)
            finally:
                self._depth -= 1


@dataclass(frozen=True)
class _Entry:
    node: Node
    key_line: int
    value_line: int
    fallback_line: int | None = None


class YamlSource:
    """Source locations using the same resolved keys as the loaded mapping.

    Descendants reached through an alias or a merge use its local reference
    line. This keeps annotations at the use site when a value is reused.
    """

    def __init__(self, root: Node, loader: Any):
        self._root = root
        self._aliases = loader.alias_lines
        self._pairs: dict[Node, list[tuple[Node, Node]]] = {}
        self._items: dict[Node, list[Node]] = {}
        self._entries: dict[Node, dict[Any, _Entry]] = {}
        self._expanded_sizes: dict[Node, int] = {}
        self._expanded_total = 0
        self._lines = loader.text_lines
        self._scalar_spans: dict[int, list[tuple[int, int]]] = {}
        self._comments: dict[int, str | None] = {}
        self.data: dict[Any, Any] = {}
        self._snapshot(root, loader.max_depth, loader.max_nodes)
        for node in self._pairs:
            self._mapping_entries(node, loader)

    def _snapshot(self, root: Node, max_depth: int, max_nodes: int) -> None:
        active: set[Node] = set()
        heights: dict[Node, int] = {}
        stack = [(root, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                children = self._children(node)
                height = 1 + max((heights[child] for child in children), default=-1)
                if height > max_depth:
                    raise ValueError("YAML graph is too deep")
                heights[node] = height
                active.remove(node)
                continue
            if node in active:
                raise ValueError("Cyclic YAML graph")
            if node in heights:
                continue
            if len(active) > max_depth or len(active) + len(heights) >= max_nodes:
                raise ValueError("YAML graph resource limit exceeded")
            if isinstance(node, MappingNode):
                self._pairs[node] = list(node.value)
            elif isinstance(node, SequenceNode):
                self._items[node] = list(node.value)
            elif isinstance(node, ScalarNode):
                self._record_scalar_span(node)
            active.add(node)
            stack.append((node, True))
            stack.extend((child, False) for child in reversed(self._children(node)))

    def _children(self, node: Node) -> list[Node]:
        if node in self._pairs:
            return [child for pair in self._pairs[node] for child in pair]
        return self._items.get(node, [])

    def _record_scalar_span(self, node: ScalarNode) -> None:
        for index in range(node.start_mark.line, node.end_mark.line + 1):
            if index >= len(self._lines):
                break
            if index == node.start_mark.line and node.style in {"|", ">"}:
                # Comments after a block indicator belong to YAML, not its text.
                continue
            start = node.start_mark.column if index == node.start_mark.line else 0
            end = (
                node.end_mark.column
                if index == node.end_mark.line
                else len(self._lines[index])
            )
            if end > start:
                self._scalar_spans.setdefault(index, []).append((start, end))

    def comment_on_line(self, line: int) -> str | None:
        """Return the YAML comment (including '#'), excluding scalar text."""
        index = line - 1
        if index < 0 or index >= len(self._lines):
            return None
        if index in self._comments:
            return self._comments[index]
        text = self._lines[index]
        offset = text.find("#")
        for start, end in sorted(self._scalar_spans.get(index, [])):
            if offset < 0 or offset < start:
                break
            if offset < end:
                offset = text.find("#", end)
        comment = text[offset:] if offset >= 0 else None
        self._comments[index] = comment
        return comment

    def _mapping_entries(self, node: Node, loader: Any) -> dict[Any, _Entry]:
        if node in self._entries:
            return self._entries[node]

        merged: dict[Any, _Entry] = {}
        explicit: dict[Any, _Entry] = {}
        expanded_size = 0
        for position, (key_node, value_node) in enumerate(self._pairs[node]):
            if not isinstance(key_node, ScalarNode):
                # SafeLoader collections cannot be mapping keys. Reject them
                # before their constructors can flatten nested mappings.
                raise ValueError("YAML mapping keys must be scalars")
            key_line = self._aliases.get(
                (node, "key", position), key_node.start_mark.line + 1
            )
            alias_line = self._aliases.get((node, "value", position))
            if key_node.tag == _MERGE_TAG:
                merge_line = alias_line or key_line
                if isinstance(value_node, MappingNode):
                    sources = [value_node]
                elif isinstance(value_node, SequenceNode):
                    sources = list(reversed(self._items[value_node]))
                else:
                    raise ValueError("Invalid YAML merge")
                for source in sources:
                    if not isinstance(source, MappingNode):
                        raise ValueError("Invalid YAML merge source")
                    source_entries = self._mapping_entries(source, loader)
                    expanded_size += self._expanded_sizes[source]
                    if expanded_size > loader.max_nodes:
                        raise ValueError("YAML merge expansion limit exceeded")
                    merged.update(
                        (key, _Entry(entry.node, merge_line, merge_line, merge_line))
                        for key, entry in source_entries.items()
                    )
                continue

            # SafeConstructor applies this normalization while flattening maps.
            if key_node.tag == "tag:yaml.org,2002:value":
                key_node.tag = "tag:yaml.org,2002:str"
            key = loader.construct_object(key_node, deep=True)
            explicit[key] = _Entry(
                value_node,
                key_line,
                alias_line or value_node.start_mark.line + 1,
                alias_line,
            )
            expanded_size += 1

        self._expanded_total += expanded_size
        if self._expanded_total > loader.max_nodes:
            raise ValueError("YAML merge expansion limit exceeded")
        merged.update(explicit)
        self._entries[node] = merged
        self._expanded_sizes[node] = expanded_size
        return merged

    def line_for_path(self, path: tuple[Any, ...], *, key: bool = True) -> int | None:
        """Return a one-based key/value line, or None when the path is absent."""
        node = self._root
        key_line = value_line = node.start_mark.line + 1
        fallback_line = None
        for part in path:
            if isinstance(node, MappingNode):
                try:
                    entry = self._entries[node].get(part)
                except TypeError:
                    return None
                if entry is None:
                    return None
                key_line = fallback_line or entry.key_line
                value_line = fallback_line or entry.value_line
                fallback_line = fallback_line or entry.fallback_line
                node = entry.node
            elif isinstance(node, SequenceNode):
                items = self._items[node]
                if not isinstance(part, int) or part < 0 or part >= len(items):
                    return None
                alias_line = self._aliases.get((node, "item", part))
                node = items[part]
                key_line = value_line = (
                    fallback_line or alias_line or node.start_mark.line + 1
                )
                fallback_line = fallback_line or alias_line
            else:
                return None
        return key_line if key else value_line


def load_yaml_with_locations(
    text: str,
    *,
    max_depth: int = 100,
    max_nodes: int = 50_000,
) -> tuple[dict[Any, Any], YamlSource] | None:
    """Safely parse a mapping once, with bounded composition and merge graphs."""
    if yaml is None or max_depth < 0 or max_nodes < 1:
        return None
    loader = None
    try:
        loader = _LocationLoader(text, max_depth, max_nodes)
        root = loader.get_single_node()
        if not isinstance(root, MappingNode):
            return None
        source = YamlSource(root, loader)
        data = loader.construct_document(root)
        if not isinstance(data, dict):
            return None
        source.data = data
        return data, source
    except Exception:
        # Some SafeLoader scalar constructors raise ordinary Python errors.
        return None
    finally:
        if loader is not None:
            loader.dispose()
