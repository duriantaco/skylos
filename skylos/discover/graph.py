from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    INPUT_SOURCE = "input_source"
    PROMPT_SITE = "prompt_site"
    LLM_CALL = "llm_call"
    OUTPUT_SINK = "output_sink"
    TOOL_DEF = "tool_def"
    VALIDATION = "validation"


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    location: str
    label: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "location": self.location,
            "label": self.label,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: str
    label: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type,
            "label": self.label,
        }


class AIIntegrationGraph:
    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._edge_set: set[tuple[str, str, str]] = set()
        self._adj_from: dict[str, list[GraphEdge]] = defaultdict(list)
        self._adj_to: dict[str, list[GraphEdge]] = defaultdict(list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        key = (edge.source_id, edge.target_id, edge.edge_type)
        if key not in self._edge_set:
            self._edge_set.add(key)
            self.edges.append(edge)
            self._adj_from[edge.source_id].append(edge)
            self._adj_to[edge.target_id].append(edge)

    def get_nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_edges_from(self, node_id: str) -> list[GraphEdge]:
        return self._adj_from.get(node_id, [])

    def get_edges_to(self, node_id: str) -> list[GraphEdge]:
        return self._adj_to.get(node_id, [])

    def has_path(self, source_id: str, target_id: str) -> bool:
        visited = set()
        queue = deque([source_id])
        while queue:
            current = queue.popleft()
            if current == target_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            for edge in self.get_edges_from(current):
                queue.append(edge.target_id)
        return False

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }
