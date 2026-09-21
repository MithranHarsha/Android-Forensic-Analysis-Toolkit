"""The evidence graph (Phase 7): entities as nodes, typed relationships as edges, held in memory and queryable.

Nodes are identified by ``(EntityKind, ref)``; the ref says which one (``phone:2025550101``, ``artifact:12``, ``database:3``).
An edge reads ``source --relation--> target`` and is exactly the persisted ``CorrelationEdge`` model, so what is queried here
is what is stored. Adding an edge that already exists (same source, relation and target) keeps the first and returns ``None``:
the graph never holds two edges for one fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from android_forensics.models import CorrelationEdge, EntityKind, Relation

Key = tuple[EntityKind, str]


@dataclass
class Node:
    kind: EntityKind
    ref: str
    label: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> Key:
        return (self.kind, self.ref)


class EvidenceGraph:
    def __init__(self) -> None:
        self._nodes: dict[Key, Node] = {}
        self._edges: list[CorrelationEdge] = []
        self._seen: set[tuple[Key, Relation, Key]] = set()
        self._out: dict[Key, list[int]] = {}
        self._in: dict[Key, list[int]] = {}

    # ------------------------------------------------------------------ building

    def node(self, kind: EntityKind, ref: str, label: str | None = None, **attrs: Any) -> Node:
        """The node ``(kind, ref)``, created on first use. A later call may add attributes but never renames it."""
        key = (kind, ref)
        node = self._nodes.get(key)
        if node is None:
            node = self._nodes[key] = Node(kind, ref, label if label is not None else ref, dict(attrs))
        else:
            node.attrs.update({k: v for k, v in attrs.items() if k not in node.attrs})
        return node

    def add_edge(self, source: Node, relation: Relation, target: Node, explanation: str, *, strength: float = 1.0,
                 **evidence: Any) -> CorrelationEdge | None:
        fact = (source.key, relation, target.key)
        if fact in self._seen:
            return None
        edge = CorrelationEdge(source_kind=source.kind, source_ref=source.ref, target_kind=target.kind, target_ref=target.ref,
                               relation=relation, strength=strength, explanation=explanation, evidence=evidence)
        self._seen.add(fact)
        index = len(self._edges)
        self._edges.append(edge)
        self._out.setdefault(source.key, []).append(index)
        self._in.setdefault(target.key, []).append(index)
        return edge

    # ------------------------------------------------------------------ querying

    def find(self, kind: EntityKind, ref: str) -> Node | None:
        return self._nodes.get((kind, ref))

    def nodes(self, kind: EntityKind | None = None) -> list[Node]:
        return sorted((n for n in self._nodes.values() if kind is None or n.kind is kind), key=lambda n: (n.kind.value, n.ref))

    @property
    def edges(self) -> list[CorrelationEdge]:
        return list(self._edges)

    def edges_from(self, node: Node, relation: Relation | None = None) -> list[CorrelationEdge]:
        return [e for e in (self._edges[i] for i in self._out.get(node.key, ())) if relation is None or e.relation is relation]

    def edges_to(self, node: Node, relation: Relation | None = None) -> list[CorrelationEdge]:
        return [e for e in (self._edges[i] for i in self._in.get(node.key, ())) if relation is None or e.relation is relation]

    def query(self, *, source: Key | None = None, relation: Relation | None = None, target: Key | None = None,
              source_kind: EntityKind | None = None, target_kind: EntityKind | None = None) -> list[CorrelationEdge]:
        """Edges matching every given criterion, in the order they were added."""
        return [
            e for e in self._edges
            if (source is None or (e.source_kind, e.source_ref) == source)
            and (target is None or (e.target_kind, e.target_ref) == target)
            and (relation is None or e.relation is relation)
            and (source_kind is None or e.source_kind is source_kind)
            and (target_kind is None or e.target_kind is target_kind)
        ]

    def neighbours(self, node: Node, relation: Relation | None = None, direction: str = "both") -> list[Node]:
        """Nodes one edge away, in a stable order. ``direction`` is ``out``, ``in`` or ``both``."""
        found: dict[Key, Node] = {}
        if direction in ("out", "both"):
            for e in self.edges_from(node, relation):
                found.setdefault((e.target_kind, e.target_ref), self._nodes[(e.target_kind, e.target_ref)])
        if direction in ("in", "both"):
            for e in self.edges_to(node, relation):
                found.setdefault((e.source_kind, e.source_ref), self._nodes[(e.source_kind, e.source_ref)])
        return sorted(found.values(), key=lambda n: (n.kind.value, n.ref))

    def __len__(self) -> int:
        return len(self._edges)

    def summary(self) -> dict[str, Any]:
        nodes: dict[str, int] = {}
        for n in self._nodes.values():
            nodes[n.kind.value] = nodes.get(n.kind.value, 0) + 1
        edges: dict[str, int] = {}
        for e in self._edges:
            edges[e.relation.value] = edges.get(e.relation.value, 0) + 1
        return {"nodes": dict(sorted(nodes.items())), "edges": dict(sorted(edges.items())), "node_count": len(self._nodes),
                "edge_count": len(self._edges)}


def edges_of(graph: EvidenceGraph, kinds: Iterable[Relation]) -> list[CorrelationEdge]:
    wanted = set(kinds)
    return [e for e in graph.edges if e.relation in wanted]
