"""
T11 · Tier-3 persistent plan-tree planner.

Replaces the flat iterate-and-react loop for long-horizon engagements with a
tree of plans — root strategic plan → phase sub-plans → action nodes. Each
node records goal, evidence required, status, and outcome.

The orchestrator calls:
    tree = PlanTree(session_id)
    await tree.seed(model, client, brief, target)   # once at session start
    summary = await tree.snapshot_for_prompt()       # every iteration
    await tree.mark_action(node_id, status, outcome) # after each tool result
    await tree.replan_if_stuck(iteration, client, model)  # periodic

The tree lives in Mongo (`plan_trees` collection) so it survives context
compression — the model can "forget" what it did six messages ago, but the
tree still has a coherent record and can re-inject the right sub-plan as the
next iteration's focus.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.mongodb import get_plan_trees_collection

logger = logging.getLogger(__name__)

_ANTHROPIC_TIMEOUT = 90.0
_MAX_PHASES = 5
_MAX_ACTIONS_PER_PHASE = 6
# A phase is considered "stuck" after this many iterations without a successful
# action transition. Triggers a re-plan call.
_STUCK_THRESHOLD_ITERATIONS = 8

Status = str  # "pending" | "in_progress" | "done" | "abandoned" | "blocked"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


class PlanTree:
    """Session-scoped plan tree, persisted to Mongo and rebuilt from it."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._tree: Optional[Dict[str, Any]] = None
        self._col = get_plan_trees_collection()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _load(self) -> Optional[Dict[str, Any]]:
        doc = await self._col.find_one({"session_id": self.session_id})
        if doc:
            doc.pop("_id", None)
            self._tree = doc
        return self._tree

    async def _save(self) -> None:
        if self._tree is None:
            return
        self._tree["updated_at"] = _now()
        await self._col.replace_one(
            {"session_id": self.session_id},
            self._tree,
            upsert=True,
        )

    # ------------------------------------------------------------------
    # Seed (one-shot LLM plan-generation at session start)
    # ------------------------------------------------------------------

    async def seed(
        self,
        client: Any,
        model: str,
        target: str,
        scan_profile: str,
        brief: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Ask the model to decompose this engagement into a plan tree.

        Called once at session start. Failures are non-fatal — the orchestrator
        still runs the flat loop if no tree is produced. The function enforces
        a strict JSON schema so downstream reads never have to defend against
        arbitrary model output.
        """
        existing = await self._load()
        if existing:
            # Resume a prior tree if the session restarts — don't double-plan.
            return existing

        system = (
            "You are the strategic planner for an autonomous security assessor. "
            "Given a target, a scan profile, and an optional Target Intent Brief, "
            "decompose the engagement into a plan tree with these strict constraints:\n"
            f"  - 1 root goal (1 sentence)\n"
            f"  - 2 to {_MAX_PHASES} phases, each with a name, goal, and 2-{_MAX_ACTIONS_PER_PHASE} actions\n"
            "  - Each action has: {name, description, tool_preference (optional), "
            "evidence_required (string describing what success looks like)}\n"
            "Return ONLY JSON: "
            "{ root_goal, phases: [{name, goal, actions: [{name, description, "
            "tool_preference, evidence_required}]}] } — no prose."
        )

        user_lines: List[str] = [
            f"Target: {target}",
            f"Scan profile: {scan_profile}",
        ]
        if brief:
            user_lines.append("\nTarget Intent Brief (from pre-scan reasoning):")
            user_lines.append(json.dumps(brief, indent=2)[:3000])

        try:
            resp = await client.messages.create(
                model=model,
                max_tokens=3000,
                timeout=_ANTHROPIC_TIMEOUT,
                system=system,
                messages=[{"role": "user", "content": "\n".join(user_lines)}],
            )
        except Exception as exc:
            logger.warning("[plan_tree] seed LLM call failed for %s: %s", self.session_id, exc)
            return None

        raw = ""
        for block in resp.content:
            if hasattr(block, "text") and block.text:
                raw += block.text
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.lower().startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1 or end <= start:
            logger.warning("[plan_tree] seed produced no JSON object for %s", self.session_id)
            return None

        try:
            parsed = json.loads(raw[start : end + 1])
        except json.JSONDecodeError as exc:
            logger.warning("[plan_tree] seed JSON parse failed for %s: %s", self.session_id, exc)
            return None

        tree = self._build_tree_from_plan(parsed)
        self._tree = tree
        await self._save()
        return tree

    @staticmethod
    def _build_tree_from_plan(parsed: Dict[str, Any]) -> Dict[str, Any]:
        root_goal = str(parsed.get("root_goal") or "").strip() or "Complete security assessment of target."
        raw_phases = parsed.get("phases") or []
        phases: List[Dict[str, Any]] = []
        for ph in raw_phases[:_MAX_PHASES]:
            if not isinstance(ph, dict):
                continue
            name = str(ph.get("name") or "Phase").strip()[:80]
            goal = str(ph.get("goal") or "").strip()[:400]
            raw_actions = ph.get("actions") or []
            actions: List[Dict[str, Any]] = []
            for act in raw_actions[:_MAX_ACTIONS_PER_PHASE]:
                if not isinstance(act, dict):
                    continue
                actions.append(
                    {
                        "id": _new_id(),
                        "name": str(act.get("name") or "Action").strip()[:80],
                        "description": str(act.get("description") or "").strip()[:500],
                        "tool_preference": str(act.get("tool_preference") or "").strip()[:60],
                        "evidence_required": str(act.get("evidence_required") or "").strip()[:500],
                        "status": "pending",
                        "outcome": "",
                        "updated_at": _now(),
                    }
                )
            if not actions:
                continue
            phases.append(
                {
                    "id": _new_id(),
                    "name": name,
                    "goal": goal,
                    "status": "pending",
                    "actions": actions,
                }
            )
        return {
            "session_id": "",  # filled by seed
            "root_goal": root_goal,
            "phases": phases,
            "replan_count": 0,
            "last_progress_iteration": 0,
            "created_at": _now(),
            "updated_at": _now(),
        }

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    async def mark_action(
        self,
        action_id: str,
        status: Status,
        outcome: str = "",
        iteration: int = 0,
    ) -> None:
        if self._tree is None:
            await self._load()
        if self._tree is None:
            return
        mutated = False
        for phase in self._tree.get("phases", []):
            for act in phase.get("actions", []):
                if act.get("id") == action_id:
                    act["status"] = status
                    if outcome:
                        act["outcome"] = outcome[:500]
                    act["updated_at"] = _now()
                    mutated = True
                    break
            # Roll phase status up from its actions.
            statuses = {a.get("status") for a in phase.get("actions", [])}
            if statuses == {"done"}:
                phase["status"] = "done"
            elif "in_progress" in statuses:
                phase["status"] = "in_progress"
            elif statuses and statuses.issubset({"done", "abandoned"}):
                phase["status"] = "done"
        if status == "done":
            self._tree["last_progress_iteration"] = iteration
        if mutated:
            await self._save()

    async def next_pending_action(self) -> Optional[Dict[str, Any]]:
        if self._tree is None:
            await self._load()
        if self._tree is None:
            return None
        for phase in self._tree.get("phases", []):
            for act in phase.get("actions", []):
                if act.get("status") == "pending":
                    return {"phase": phase.get("name"), **act}
        return None

    # ------------------------------------------------------------------
    # Prompt-facing summary
    # ------------------------------------------------------------------

    async def snapshot_for_prompt(self, max_chars: int = 1800) -> str:
        """Condensed text block re-injected on every iteration.

        This is what survives context compression. Even if the model loses
        its scratchpad, the next iteration's user-turn gets a fresh readable
        plan summary with phase statuses and which action is up next.
        """
        if self._tree is None:
            await self._load()
        if self._tree is None:
            return ""
        lines: List[str] = []
        lines.append(f"[PLAN] Root: {self._tree.get('root_goal', '')}")
        for phase in self._tree.get("phases", []):
            name = phase.get("name", "Phase")
            status = phase.get("status", "pending")
            lines.append(f"  [{status.upper()}] Phase · {name}")
            for act in phase.get("actions", []):
                marker = {
                    "done": "✓",
                    "in_progress": "→",
                    "abandoned": "×",
                    "blocked": "!",
                }.get(act.get("status", "pending"), "·")
                extra = f" — {act.get('outcome')}" if act.get("outcome") else ""
                lines.append(
                    f"    {marker} {act.get('name', 'action')} :: "
                    f"{act.get('description', '')[:120]}{extra}"
                )
        text = "\n".join(lines)
        if len(text) > max_chars:
            text = text[: max_chars - 20] + "\n  ...[truncated]"
        return text

    # ------------------------------------------------------------------
    # Re-plan trigger
    # ------------------------------------------------------------------

    def is_stuck(self, iteration: int) -> bool:
        if self._tree is None:
            return False
        last = int(self._tree.get("last_progress_iteration") or 0)
        return (iteration - last) >= _STUCK_THRESHOLD_ITERATIONS

    async def replan_if_stuck(
        self,
        iteration: int,
        client: Any,
        model: str,
        findings_summary: str = "",
    ) -> bool:
        """If no action has flipped to 'done' in a while, ask the model to rebalance.

        Returns True if the tree was rewritten. The orchestrator can surface a
        `plan_replan` event on the live feed when this returns True.
        """
        if not self.is_stuck(iteration):
            return False
        if self._tree is None:
            return False
        replan_count = int(self._tree.get("replan_count") or 0)
        if replan_count >= 3:
            # Give up on re-planning; three rewrites is enough.
            return False

        current_summary = await self.snapshot_for_prompt(max_chars=4000)
        system = (
            "You are the strategic re-planner for a stuck autonomous security "
            "session. Given the current plan tree and recent findings, rewrite "
            "the tree with the same schema as the original plan. Mark clearly-"
            "failed actions abandoned, reshape remaining phases around what is "
            "actually working, and keep the tree size small. Return ONLY JSON."
        )
        user_lines = [
            f"Iteration: {iteration}",
            f"Current tree:\n{current_summary}",
        ]
        if findings_summary:
            user_lines.append(f"Findings so far:\n{findings_summary[:1500]}")

        try:
            resp = await client.messages.create(
                model=model,
                max_tokens=3000,
                timeout=_ANTHROPIC_TIMEOUT,
                system=system,
                messages=[{"role": "user", "content": "\n".join(user_lines)}],
            )
        except Exception as exc:
            logger.warning("[plan_tree] replan LLM call failed for %s: %s", self.session_id, exc)
            return False

        raw = ""
        for block in resp.content:
            if hasattr(block, "text") and block.text:
                raw += block.text
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return False
        try:
            parsed = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            return False

        new_tree = self._build_tree_from_plan(parsed)
        new_tree["replan_count"] = replan_count + 1
        new_tree["last_progress_iteration"] = iteration
        new_tree["created_at"] = self._tree.get("created_at", _now())
        self._tree = new_tree
        await self._save()
        logger.info("[plan_tree] session=%s replanned (count=%d)", self.session_id, replan_count + 1)
        return True
