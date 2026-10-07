"""The evidence graph (Phase 7): entities as nodes, typed relationships as edges, held in memory and queryable.

Nodes are identified by ``(EntityKind, ref)``; the ref says which one (``phone:2025550101``, ``artifact:12``, ``database:3``).
An edge reads ``source --relation--> target`` and is exactly the persisted ``CorrelationEdge`` model, so what is queried here
is what is stored. Internally an edge is a plain tuple (a pydantic model costs ~1 KB, and a large case has millions of edges);
``CorrelationEdge`` objects are built on demand, validated exactly as before (no self-loops, non-blank explanation). Adding an edge that already exists (same source, relation and target) keeps the first and returns ``None``:
the graph never holds two edges for one fact.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from android_forensics.models import CorrelationEdge, EntityKind, Relation

Key = tuple[EntityKind, str]
_Row = tuple[EntityKind, str, EntityKind, str, Relation, float, str, dict[str, Any]]  # source kind/ref, target kind/ref, relation, strength, why, evidence


def _edge(r: _Row) -> CorrelationEdge:
    return CorrelationEdge(source_kind=r[0], source_ref=r[1], target_kind=r[2], target_ref=r[3], relation=r[4], strength=r[5],
                           explanation=r[6], evidence=r[7])


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
        self._edges: list[_Row] = []
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
                 **evidence: Any) -> bool:
        """Add ``source --relation--> target``. False (and nothing added) if that fact is already in the graph."""
        fact = (source.key, relation, target.key)
        if fact in self._seen:
            return False
        if source.key == target.key:
            raise ValueError("an entity cannot correlate with itself")
        if not explanation or not explanation.strip() or not 0.0 <= strength <= 1.0:
            raise ValueError("an edge needs a non-blank explanation and a strength between 0 and 1")
        self._seen.add(fact)
        index = len(self._edges)
        self._edges.append((source.kind, source.ref, target.kind, target.ref, relation, strength, explanation, evidence))
        self._out.setdefault(source.key, []).append(index)
        self._in.setdefault(target.key, []).append(index)
        return True

    # ------------------------------------------------------------------ querying

    def find(self, kind: EntityKind, ref: str) -> Node | None:
        return self._nodes.get((kind, ref))

    def nodes(self, kind: EntityKind | None = None) -> list[Node]:
        return sorted((n for n in self._nodes.values() if kind is None or n.kind is kind), key=lambda n: (n.kind.value, n.ref))

    @property
    def edges(self) -> list[CorrelationEdge]:
        return [_edge(r) for r in self._edges]

    def iter_edges(self) -> Iterable[CorrelationEdge]:
        """Every edge, built one at a time (use this to persist a large graph without materialising all the models)."""
        return (_edge(r) for r in self._edges)

    def edges_from(self, node: Node, relation: Relation | None = None) -> list[CorrelationEdge]:
        return [_edge(r) for r in (self._edges[i] for i in self._out.get(node.key, ())) if relation is None or r[4] is relation]

    def edges_to(self, node: Node, relation: Relation | None = None) -> list[CorrelationEdge]:
        return [_edge(r) for r in (self._edges[i] for i in self._in.get(node.key, ())) if relation is None or r[4] is relation]

    def query(self, *, source: Key | None = None, relation: Relation | None = None, target: Key | None = None,
              source_kind: EntityKind | None = None, target_kind: EntityKind | None = None) -> list[CorrelationEdge]:
        """Edges matching every given criterion, in the order they were added."""
        return [
            _edge(r) for r in self._edges
            if (source is None or (r[0], r[1]) == source)
            and (target is None or (r[2], r[3]) == target)
            and (relation is None or r[4] is relation)
            and (source_kind is None or r[0] is source_kind)
            and (target_kind is None or r[2] is target_kind)
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
        for r in self._edges:
            edges[r[4].value] = edges.get(r[4].value, 0) + 1
        return {"nodes": dict(sorted(nodes.items())), "edges": dict(sorted(edges.items())), "node_count": len(self._nodes),
                "edge_count": len(self._edges)}


def edges_of(graph: EvidenceGraph, kinds: Iterable[Relation]) -> list[CorrelationEdge]:
    wanted = set(kinds)
    return [e for e in graph.edges if e.relation in wanted]
