"""T161 — tree_of_thought_search: branching exploration with explicit backtrack.

At each decision point, the loop:
  1. generates N candidate branches
  2. evaluates each (model scoring or simulated rollout)
  3. commits to the best, keeps siblings as fallbacks
  4. backtracks to the best unexplored sibling on dead-end

Used by other v7 loops (T155 ROP composition, T156 code_intent, T158 heap_layout)
when they need to weigh several next-step options.

Public API:
  - ToTSearch(...).expand(branches)
  - search.commit(node_id)
  - search.backtrack()
  - search.snapshot() -> dict (for loop_state ticks)
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToTNode:
    node_id: str
    parent_id: Optional[str]
    payload: Dict[str, Any]
    score: float = 0.0
    status: str = "pending"   # pending | committed | abandoned | exhausted
    children: List[str] = field(default_factory=list)


class ToTSearch:
    """In-memory tree of thought. Cheap; the tree itself isn't persisted —
    the parent loop's `state` snapshot captures whatever subset matters."""

    def __init__(
        self,
        *,
        max_depth: int = 6,
        max_breadth: int = 5,
        scorer: Optional[Callable[[Dict[str, Any]], Awaitable[float]]] = None,
    ) -> None:
        self.max_depth = max_depth
        self.max_breadth = max_breadth
        self.scorer = scorer
        self.nodes: Dict[str, ToTNode] = {}
        root = ToTNode(node_id="root", parent_id=None, payload={}, status="committed")
        self.nodes["root"] = root
        self._cursor: str = "root"

    @property
    def cursor(self) -> ToTNode:
        return self.nodes[self._cursor]

    def depth(self, node_id: str = "") -> int:
        nid = node_id or self._cursor
        depth = 0
        while True:
            n = self.nodes.get(nid)
            if n is None or n.parent_id is None:
                return depth
            nid = n.parent_id
            depth += 1

    async def expand(self, branches: List[Dict[str, Any]]) -> List[ToTNode]:
        """Add up to `max_breadth` candidate child nodes under the cursor.

        If a `scorer` was provided, score each branch eagerly so `pick_best`
        can sort. Branches are dicts; the scorer is given the dict.
        """
        cursor = self.cursor
        if self.depth() >= self.max_depth:
            cursor.status = "exhausted"
            return []

        chosen = branches[: self.max_breadth]
        new_nodes: List[ToTNode] = []
        for payload in chosen:
            nid = f"n-{uuid.uuid4().hex[:8]}"
            node = ToTNode(node_id=nid, parent_id=cursor.node_id, payload=dict(payload))
            if self.scorer is not None:
                try:
                    node.score = float(await self.scorer(payload))
                except Exception as exc:
                    logger.debug("ToT scorer raised: %s", exc)
                    node.score = 0.0
            else:
                node.score = float(payload.get("_score", 0.0))
            self.nodes[nid] = node
            cursor.children.append(nid)
            new_nodes.append(node)
        return new_nodes

    def pick_best(self) -> Optional[ToTNode]:
        """Return the highest-scoring pending child of the cursor."""
        cursor = self.cursor
        pending = [self.nodes[c] for c in cursor.children if self.nodes[c].status == "pending"]
        if not pending:
            return None
        return max(pending, key=lambda n: n.score)

    def commit(self, node_id: str) -> ToTNode:
        """Walk into a node, marking siblings still pending as fallbacks."""
        if node_id not in self.nodes:
            raise KeyError(f"unknown ToT node {node_id}")
        node = self.nodes[node_id]
        node.status = "committed"
        self._cursor = node_id
        return node

    def abandon(self, node_id: str) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].status = "abandoned"

    def backtrack(self) -> Optional[ToTNode]:
        """Return to the parent, marking the current cursor abandoned, and
        pick the next best pending sibling there. Returns the new cursor or
        None if the root is exhausted."""
        cur = self.cursor
        if cur.parent_id is None:
            return None
        cur.status = "abandoned"
        self._cursor = cur.parent_id
        nxt = self.pick_best()
        if nxt is not None:
            self.commit(nxt.node_id)
            return nxt
        # Walk up further if this level is exhausted.
        return self.backtrack()

    def snapshot(self, max_nodes: int = 40) -> Dict[str, Any]:
        """Compact view of the tree for `loop_state` ticks."""
        nodes = list(self.nodes.values())[:max_nodes]
        return {
            "cursor": self._cursor,
            "depth": self.depth(),
            "node_count": len(self.nodes),
            "nodes": [
                {
                    "node_id": n.node_id,
                    "parent_id": n.parent_id,
                    "score": round(n.score, 4),
                    "status": n.status,
                    "summary": _short(n.payload),
                }
                for n in nodes
            ],
        }


def _short(payload: Dict[str, Any], width: int = 120) -> str:
    if not payload:
        return ""
    keys = list(payload.keys())[:3]
    parts = []
    for k in keys:
        v = payload[k]
        if isinstance(v, str):
            parts.append(f"{k}={v[:40]}")
        else:
            parts.append(f"{k}={str(v)[:40]}")
    s = ", ".join(parts)
    return s[:width]
