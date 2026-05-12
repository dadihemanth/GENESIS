"""T165 — counterfactual_exploration_deep.

Extends v6 T128 (counterfactual reasoner — currently a one-line system-prompt
injection that asks 'if this defense were absent, would my attack succeed?')
into a multi-step counterfactual *tree*.

  Depth 0:  baseline observation (e.g. SQLi blocked by WAF)
  Depth 1:  if we had a leak primitive → what attacks open up?
  Depth 2:  if we ALSO had an arbitrary-write primitive → what then?
  Depth 3:  if we ALSO had RCE → end-state?

Tree is built via BFS with per-node LLM expansion. Hypothetical primitives
are pulled from a small canonical set; the model can emit new ones too.

Inputs:
  {
    "baseline":           "SQLi attempt blocked by WAF on /login",
    "starting_primitives": ["unauth_get"],
    "max_depth":          3,    # default 3
    "max_breadth":        3,    # default 3
    "context":            str   # optional free-form
  }

Result:
  {
    "tree": {
      "root": {"primitives": [...], "outcome": "...", "children": [...]}
    },
    "highest_impact_path": [{"primitive": "...", "rationale": "..."}],
    "actionable_next_step": str,
  }
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.services.reasoning.framework import DeliberationLoop, TickOutcome

logger = logging.getLogger(__name__)


_CF_SYSTEM = (
    "You are a COUNTERFACTUAL EXPLORER (GENESIS v7 T165). "
    "Given the attacker's current set of hypothetical primitives and the "
    "target context, propose 1-3 NEW primitives that would meaningfully "
    "expand the attack surface, AND for each propose what it would unlock. "
    "Stay grounded in the target context — don't invent random primitives. "
    "Return STRICT JSON: "
    '{"branches": [{"primitive": "...", "unlocks": "...", '
    '"impact": "low|medium|high|critical", "rationale": "..."}], '
    '"end_state_if_continued": "..."}'
)

_CANONICAL_PRIMITIVES = (
    "info_leak", "arbitrary_read", "arbitrary_write", "auth_bypass",
    "session_fixation", "sql_oracle", "blind_rce", "xxe_oob",
    "ssrf_internal", "deserialization_gadget",
)


class CounterfactualLoop(DeliberationLoop):
    loop_type = "counterfactual"

    async def setup(self) -> None:
        self.state["baseline"] = str(self.inputs.get("baseline", "")).strip()
        self.state["context"] = str(self.inputs.get("context", "") or "")[:1500]
        self.state["max_depth"] = max(1, min(int(self.inputs.get("max_depth", 3)), 4))
        self.state["max_breadth"] = max(1, min(int(self.inputs.get("max_breadth", 3)), 4))
        starting = list(self.inputs.get("starting_primitives", []) or [])
        # Tree root
        self.state["tree"] = {
            "id": "root",
            "primitives": list(starting),
            "outcome": self.state["baseline"] or "(no baseline given)",
            "depth": 0,
            "impact": "low",
            "children": [],
        }
        # BFS frontier
        self.state["frontier"] = [self.state["tree"]]
        self.state["paths_seen"] = 0

    async def tick(self) -> TickOutcome:
        if self._llm_call is None:
            return TickOutcome(done=True, reasoning="no llm_call provided",
                               result={"tree": self.state["tree"], "error": "missing llm_call"})

        if not self.state["baseline"]:
            return TickOutcome(
                done=True,
                reasoning=(
                    "Counterfactual reasoning needs a baseline observation "
                    "(e.g. 'SQLi attempt blocked by WAF on /login'). The agent "
                    "called deliberate(loop_type='counterfactual') without an "
                    "'inputs.baseline' string — pass the obstacle text as "
                    "'baseline' next time."
                ),
                result={
                    "tree": self.state["tree"],
                    "error": "missing baseline",
                    "hint": "set inputs.baseline to a one-line description of what's blocking you",
                },
            )

        frontier: List[Dict[str, Any]] = self.state["frontier"]
        if not frontier:
            return self._finalize()

        # Pop one frontier node per tick (keeps each tick ~ 1 LLM call).
        node = frontier.pop(0)
        self.state["frontier"] = frontier

        if node["depth"] >= self.state["max_depth"]:
            # leaf — don't expand further
            if not frontier:
                return self._finalize()
            return TickOutcome(
                state_delta={"frontier": frontier},
                chosen=node["id"],
                reasoning=f"reached max_depth at node {node['id']}",
                tokens=0,
            )

        branches = await self._expand_node(node)
        for i, br in enumerate(branches[: self.state["max_breadth"]]):
            child_id = f"{node['id']}.{i+1}"
            child = {
                "id": child_id,
                "primitives": list(node["primitives"]) + [br.get("primitive", "")],
                "outcome": br.get("unlocks", "")[:300],
                "rationale": br.get("rationale", "")[:300],
                "impact": br.get("impact", "medium"),
                "depth": node["depth"] + 1,
                "children": [],
            }
            node["children"].append(child)
            frontier.append(child)
            self.state["paths_seen"] += 1

        if not frontier:
            return self._finalize()

        return TickOutcome(
            state_delta={"frontier": frontier, "tree": self.state["tree"]},
            chosen=node["id"],
            reasoning=f"expanded {node['id']} into {len(branches)} branches",
            tokens=550,
        )

    # ------------------------------------------------------------------

    async def _expand_node(self, node: Dict[str, Any]) -> List[Dict[str, Any]]:
        primitives_block = ", ".join(node["primitives"]) or "(none yet)"
        canonical_block = ", ".join(_CANONICAL_PRIMITIVES)
        user = (
            f"Baseline observation:\n{self.state['baseline']}\n\n"
            f"Current hypothetical primitives: {primitives_block}\n"
            f"Current outcome at this node: {node['outcome']}\n"
            f"Depth: {node['depth']} of max {self.state['max_depth']}\n"
            f"Canonical primitive vocabulary (you may reuse or invent): {canonical_block}\n\n"
            f"Context: {self.state['context']}\n\n"
            f"Return JSON only. Propose at most {self.state['max_breadth']} branches."
        )
        try:
            result = await self._llm_call(system=_CF_SYSTEM, user=user, max_tokens=550)
            parsed = _extract_json(result.get("text", ""))
            return list(parsed.get("branches", []) or [])
        except Exception as exc:
            logger.warning("counterfactual expand failed at %s: %s", node["id"], exc)
            return []

    def _finalize(self) -> TickOutcome:
        # Walk the tree to find the highest-impact path.
        impact_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        def walk(node: Dict[str, Any], path: List[Dict[str, str]]) -> List[Dict[str, str]]:
            here = path + [{
                "primitive": node["primitives"][-1] if node["primitives"] else "(root)",
                "rationale": node.get("rationale", node.get("outcome", "")),
                "impact": node.get("impact", "low"),
            }]
            if not node.get("children"):
                return here
            best = here
            best_score = sum(impact_rank.get(p.get("impact", "low"), 1) for p in here)
            for c in node["children"]:
                cand = walk(c, here)
                cand_score = sum(impact_rank.get(p.get("impact", "low"), 1) for p in cand)
                if cand_score > best_score:
                    best, best_score = cand, cand_score
            return best

        best_path = walk(self.state["tree"], [])
        actionable = ""
        if best_path:
            terminal = best_path[-1]
            actionable = (
                f"Try to acquire primitive '{terminal['primitive']}' next — "
                f"this path reaches {terminal['impact']} impact: {terminal['rationale'][:150]}"
            )

        return TickOutcome(
            done=True,
            reasoning=f"explored {self.state['paths_seen']} branches; best impact path = {len(best_path)}",
            tokens=200,
            result={
                "tree": self.state["tree"],
                "highest_impact_path": best_path,
                "actionable_next_step": actionable,
            },
        )


def _extract_json(text: str) -> Dict[str, Any]:
    if not text:
        return {}
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return {}
    try:
        return json.loads(match.group(0))
    except Exception:
        return {}
