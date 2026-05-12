"""T162 — long_context_code_harness: reason over 1M+ token codebases.

Strategy: segment-summarise-recurse.
  1. Split the corpus into segments (function / file / chunk).
  2. Summarise each segment.
  3. Group summaries; summarise the groups.
  4. Recurse until a single root summary remains.
  5. Queries descend the tree, fetching only relevant subtrees.

This is the canonical version of the recursive summarisation idea that already
exists in compact form inside ai_orchestrator.py (the every-15-iterations
message compaction). Future work can route the orchestrator's compaction
through this module so there's a single implementation.

Public API:
  - SummaryTree.build(segments, llm_call) — returns the tree
  - SummaryTree.query(tree, question, llm_call) — returns answer + path
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

DEFAULT_GROUP_FANOUT = 6     # how many children per parent summary node
DEFAULT_SUMMARY_TOKENS = 250


@dataclass
class SummaryNode:
    node_id: str
    text: str               # the segment OR its summary
    is_leaf: bool
    children: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SummaryTree:
    nodes: Dict[str, SummaryNode] = field(default_factory=dict)
    root_id: Optional[str] = None

    def get(self, nid: str) -> Optional[SummaryNode]:
        return self.nodes.get(nid)


_SUMMARY_SYSTEM = (
    "You are a CODE SUMMARISER (GENESIS v7 T162). "
    "Given a code segment OR a list of child summaries, produce a single "
    "concise summary (≤ 200 words) that preserves: function/class names, "
    "data flows, security-relevant calls (auth, crypto, deserialisation, "
    "shell/eval, file/network IO), and any obvious invariants. Be terse."
)

_QUERY_SYSTEM = (
    "You are a CODE QUERIER (GENESIS v7 T162). "
    "Given a question and a node summary, output STRICT JSON: "
    '{"relevant": true|false, "answer": "...", "drill_into_children": true|false, '
    '"reason": "..."}'
)


async def build_summary_tree(
    segments: Sequence[Dict[str, Any]],
    llm_call: Callable[..., Awaitable[Dict[str, Any]]],
    *,
    fanout: int = DEFAULT_GROUP_FANOUT,
) -> SummaryTree:
    """Build a summary tree from leaf segments.

    `segments` is a sequence of dicts shaped like
        {"id": "src/foo.py:bar", "text": "...code...", "metadata": {...}}.
    """
    tree = SummaryTree()

    # Layer 0 — leaves
    leaves: List[str] = []
    for seg in segments:
        nid = str(seg.get("id") or f"leaf-{len(tree.nodes)}")
        node = SummaryNode(
            node_id=nid,
            text=str(seg.get("text", "")),
            is_leaf=True,
            metadata=dict(seg.get("metadata", {}) or {}),
        )
        tree.nodes[nid] = node
        leaves.append(nid)

    if not leaves:
        return tree

    # If only one leaf, it's the root.
    if len(leaves) == 1:
        tree.root_id = leaves[0]
        return tree

    # Build summaries upward.
    layer = leaves
    layer_idx = 0
    while len(layer) > 1:
        layer_idx += 1
        next_layer: List[str] = []
        groups = _chunk(layer, fanout)
        for gi, group in enumerate(groups):
            child_summaries = "\n\n".join(
                f"[{cid}] {tree.nodes[cid].text[:1500]}" for cid in group
            )
            user_msg = (
                f"Summarise these {len(group)} code segments / sub-summaries "
                f"into one ≤200-word summary:\n\n{child_summaries}"
            )
            try:
                result = await llm_call(
                    system=_SUMMARY_SYSTEM,
                    user=user_msg,
                    max_tokens=DEFAULT_SUMMARY_TOKENS,
                )
                summary_text = (result or {}).get("text", "").strip() or "(empty summary)"
            except Exception as exc:
                logger.warning("summary tree layer %d group %d llm failed: %s", layer_idx, gi, exc)
                summary_text = _fallback_summary(group, tree)

            nid = f"sum-L{layer_idx}-G{gi}"
            tree.nodes[nid] = SummaryNode(
                node_id=nid,
                text=summary_text,
                is_leaf=False,
                children=list(group),
            )
            next_layer.append(nid)
        layer = next_layer

    tree.root_id = layer[0]
    return tree


async def query_tree(
    tree: SummaryTree,
    question: str,
    llm_call: Callable[..., Awaitable[Dict[str, Any]]],
    *,
    max_visit: int = 24,
) -> Dict[str, Any]:
    """Descend the tree to answer `question`. Returns:
       {"answer": str, "path": [node_ids], "visited": int, "drilled": bool}.

    BFS-with-pruning: at each node, ask the LLM whether to drill into its
    children. If `relevant=False`, prune the subtree. If `drill_into_children
    =True`, enqueue children. If we hit a leaf or `drill_into_children=False`,
    that node's answer becomes a candidate. Best candidate at the end wins.
    """
    if tree.root_id is None:
        return {"answer": "", "path": [], "visited": 0, "drilled": False}

    import json
    import re

    visited = 0
    queue: List[str] = [tree.root_id]
    path: List[str] = []
    candidates: List[Dict[str, Any]] = []
    drilled = False

    while queue and visited < max_visit:
        nid = queue.pop(0)
        node = tree.get(nid)
        if node is None:
            continue
        visited += 1
        path.append(nid)

        try:
            result = await llm_call(
                system=_QUERY_SYSTEM,
                user=(
                    f"Question: {question}\n\nNode summary:\n{node.text[:2000]}"
                ),
                max_tokens=300,
            )
            raw = (result or {}).get("text", "")
            match = re.search(r"\{[\s\S]*\}", raw)
            parsed = json.loads(match.group(0)) if match else {}
        except Exception as exc:
            logger.debug("query_tree llm failed at %s: %s", nid, exc)
            parsed = {"relevant": True, "drill_into_children": not node.is_leaf, "answer": "", "reason": ""}

        if not parsed.get("relevant", True):
            continue
        if parsed.get("answer"):
            candidates.append({"node_id": nid, "answer": parsed["answer"], "is_leaf": node.is_leaf})
        if parsed.get("drill_into_children") and node.children:
            queue.extend(node.children)
            drilled = True

    if not candidates:
        return {"answer": "(no relevant evidence found)", "path": path, "visited": visited, "drilled": drilled}

    # Prefer leaf-level answers since they cite concrete code.
    candidates.sort(key=lambda c: (0 if c["is_leaf"] else 1))
    best = candidates[0]
    return {
        "answer": best["answer"],
        "path": path,
        "visited": visited,
        "drilled": drilled,
    }


def _chunk(seq: List[str], n: int) -> List[List[str]]:
    if n <= 0:
        n = 1
    return [list(seq[i : i + n]) for i in range(0, len(seq), n)]


def _fallback_summary(group: List[str], tree: SummaryTree) -> str:
    """No-LLM summary: concatenate truncated child texts. Used on llm errors."""
    head = " | ".join(tree.nodes[c].text[:200] for c in group[:3])
    return f"[fallback summary of {len(group)} segments] {head}"


def estimate_segments_for_tokens(token_count: int) -> int:
    """Rough heuristic: a 1M token corpus → ~1000 segments at ~1k tokens each."""
    return max(1, math.ceil(token_count / 1024))


# ---------------------------------------------------------------------------
# DeliberationLoop wrapper — `deliberate(loop_type=long_context_code, inputs=...)`
# ---------------------------------------------------------------------------

from app.services.reasoning.framework import DeliberationLoop, TickOutcome  # noqa: E402


class LongContextCodeLoop(DeliberationLoop):
    """Two-phase loop:
       1. Build the summary tree from `inputs.segments`. (1 tick)
       2. For each `inputs.questions[]`, descend the tree and answer. (1 tick each)
    """

    loop_type = "long_context_code"

    async def setup(self) -> None:
        segments = list(self.inputs.get("segments", []) or [])
        questions = list(self.inputs.get("questions", []) or [])
        self.state["segment_count"] = len(segments)
        self.state["pending_questions"] = questions
        self.state["answers"] = []
        self.state["tree_built"] = False
        self.state["_segments"] = segments  # internal — stripped from snapshot

    async def tick(self) -> TickOutcome:
        if self._llm_call is None:
            return TickOutcome(done=True, reasoning="no llm_call provided",
                               result={"answers": [], "error": "missing llm_call"})

        # Phase 1: build tree
        if not self.state.get("tree_built"):
            segments = self.state.pop("_segments", [])
            if not segments:
                return TickOutcome(done=True, reasoning="no segments provided",
                                   result={"answers": [], "error": "missing segments"})
            tree = await build_summary_tree(segments, self._llm_call)
            self.state["tree"] = tree
            self.state["tree_built"] = True
            return TickOutcome(
                state_delta={"tree_built": True},
                reasoning=f"built {len(tree.nodes)}-node summary tree from {len(segments)} segments",
                tokens=600,
            )

        # Phase 2: answer next pending question
        pending: List[str] = self.state.get("pending_questions", [])
        if not pending:
            answers = self.state.get("answers", [])
            return TickOutcome(done=True, reasoning="all questions answered",
                               result={"answers": answers, "tree_size": len(self.state.get("tree").nodes)})

        question = pending.pop(0)
        tree = self.state["tree"]
        answer_obj = await query_tree(tree, question, self._llm_call)
        answers = self.state.get("answers", [])
        answers.append({"question": question, **answer_obj})
        self.state["answers"] = answers
        self.state["pending_questions"] = pending

        return TickOutcome(
            state_delta={"answers": answers, "pending_questions": pending},
            chosen=answer_obj.get("path", [None])[0] if answer_obj.get("path") else None,
            reasoning=f"answered '{question[:80]}' visiting {answer_obj.get('visited', 0)} nodes",
            tokens=400,
        )
