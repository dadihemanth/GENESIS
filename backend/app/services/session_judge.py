"""v8 — SessionJudge: independent per-round LLM evaluator.

Fires after each Phase-2 round in MultiAgentOrchestrator and every 25
iterations in solo mode. Makes a single Claude Haiku call with the full
session state and returns a structured verdict that drives:

  1. The ≥80% kill-chain coverage gate (blocks session termination).
  2. The SessionSupervisor directive dispatch (redirects subagents to gaps).

Failure is always non-fatal — any exception produces a minimal pass-through
verdict so the calling orchestrator is never blocked.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

PublishFn = Callable[[str, Dict[str, Any]], Awaitable[None]]

_JUDGE_SYSTEM = """\
You are GENESIS SessionJudge — an independent evaluator of an autonomous \
security research session. You receive the current session state in JSON and \
must produce a structured assessment.

Your output MUST be valid JSON and nothing else — no markdown, no commentary, \
no code fences. The exact schema you must follow:

{
  "overall_score": <float 0.0-1.0>,
  "coverage_pct": <float 0.0-100.0>,
  "killchain_phase_scores": {
    "recon": <int 0-100>,
    "weaponization": <int 0-100>,
    "delivery": <int 0-100>,
    "exploitation": <int 0-100>,
    "installation": <int 0-100>,
    "c2": <int 0-100>,
    "actions_on_objectives": <int 0-100>
  },
  "goals_met": ["<sub_goal_description>", ...],
  "goals_not_met": ["<sub_goal_description>", ...],
  "hypothesis_resolution_rate": <float 0.0-1.0>,
  "finding_quality_summary": "<1-2 sentences on finding quality>",
  "gap_list": [
    {
      "rank": <int starting at 1>,
      "phase": "<kill_chain_phase>",
      "class": "<attack_class>",
      "reason": "<why this was missed or is insufficient>",
      "target_agents": ["<agent_type>", ...],
      "directive": "<specific actionable instruction for the target agent>"
    }
  ],
  "coverage_gate_passed": <true|false>,
  "verdict": "<pass|needs_work|critical_gaps>"
}

Rules:
- gap_list must be sorted by rank (1 = most critical gap).
- coverage_gate_passed is true only if all phases with 80% threshold are ≥80%
  and all phases with 50% threshold are ≥50%.
- verdict="pass" means overall_score ≥ 0.75 and coverage_gate_passed=true.
- verdict="needs_work" means some gaps remain but nothing critical is missing.
- verdict="critical_gaps" means a critical kill-chain phase (exploitation,
  delivery, recon) is below threshold or all goals are unmet.
- directive must be a concrete, tool-level instruction, e.g.:
  "Run sqlmap_test and second_order_sqli_probe against /api/users/login.
   Also probe /api/search with nosql_probe. Priority: before next FINAL_REPORT."
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionJudge:
    """Single Haiku LLM call per invocation; routes via the 'judge' role."""

    def __init__(self, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    async def evaluate(
        self,
        *,
        session_id: str,
        round_idx: int,
        killchain_coverage: Dict[str, Any],
        tools_used: Set[str],
        goal_tree: Optional[Dict[str, Any]],
        goal_progress: Optional[Dict[str, Any]],
        hypothesis_stats: Dict[str, int],
        finding_count: int,
        confirmed_finding_count: int,
        coverage_pct: float,
        publish_fn: Optional[PublishFn] = None,
    ) -> Dict[str, Any]:
        """Run the judge LLM call and persist the verdict.

        Returns the parsed verdict dict. On any error returns a minimal
        non-blocking verdict so the orchestrator can continue unimpeded.
        """
        try:
            context = self._build_context(
                session_id=session_id,
                round_idx=round_idx,
                killchain_coverage=killchain_coverage,
                tools_used=tools_used,
                goal_tree=goal_tree,
                goal_progress=goal_progress,
                hypothesis_stats=hypothesis_stats,
                finding_count=finding_count,
                confirmed_finding_count=confirmed_finding_count,
                coverage_pct=coverage_pct,
            )

            response = await self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=_JUDGE_SYSTEM,
                messages=[{"role": "user", "content": context}],
            )

            raw_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    raw_text += block.text

            verdict = self._parse_verdict(raw_text)
            if verdict is None:
                logger.warning(
                    "[JUDGE] session=%s round=%d failed to parse LLM verdict — "
                    "using pass-through",
                    session_id, round_idx,
                )
                verdict = self._passthrough_verdict(coverage_pct, finding_count)

            verdict_id = await self._persist_verdict(session_id, round_idx, verdict)
            verdict["_id"] = verdict_id

            if publish_fn:
                try:
                    await publish_fn(session_id, {
                        "type": "judge_verdict",
                        "data": {
                            "round_idx": round_idx,
                            "verdict": verdict.get("verdict", "needs_work"),
                            "overall_score": verdict.get("overall_score", 0.0),
                            "coverage_pct": verdict.get("coverage_pct", coverage_pct),
                            "coverage_gate_passed": verdict.get("coverage_gate_passed", False),
                            "gap_count": len(verdict.get("gap_list", [])),
                            "verdict_id": verdict_id,
                        },
                        "timestamp": _now_iso(),
                    })
                except Exception as pub_exc:
                    logger.debug("[JUDGE] publish failed (non-fatal): %s", pub_exc)

            logger.info(
                "[JUDGE] session=%s round=%d verdict=%s coverage_pct=%.1f "
                "gate=%s gaps=%d",
                session_id, round_idx,
                verdict.get("verdict"), verdict.get("coverage_pct", coverage_pct),
                verdict.get("coverage_gate_passed"), len(verdict.get("gap_list", [])),
            )
            return verdict

        except Exception as exc:
            logger.warning("[JUDGE] session=%s round=%d evaluation failed: %s", session_id, round_idx, exc)
            return self._passthrough_verdict(coverage_pct, finding_count)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        *,
        session_id: str,
        round_idx: int,
        killchain_coverage: Dict[str, Any],
        tools_used: Set[str],
        goal_tree: Optional[Dict[str, Any]],
        goal_progress: Optional[Dict[str, Any]],
        hypothesis_stats: Dict[str, int],
        finding_count: int,
        confirmed_finding_count: int,
        coverage_pct: float,
    ) -> str:
        """Serialize session state into a compact JSON context for the LLM."""
        # Summarize kill-chain coverage — just pct + missing per phase
        kc_summary: Dict[str, Any] = {}
        for phase, data in killchain_coverage.items():
            if isinstance(data, dict):
                kc_summary[phase] = {
                    "pct": data.get("pct", 0),
                    "threshold": data.get("threshold", 80),
                    "missing": [
                        c for c in data.get("required", [])
                        if c not in data.get("covered", [])
                    ],
                }

        # Flatten goal tree to sub-goals with their progress
        goal_summary: List[Dict[str, Any]] = []
        if goal_tree and isinstance(goal_tree, dict):
            for phase_idx, phase in enumerate(goal_tree.get("phases", [])):
                for sg_idx, sg in enumerate(phase.get("sub_goals", [])):
                    key = f"{phase_idx}.{sg_idx}"
                    progress_entry = (
                        (goal_progress or {}).get("progress", {}).get(key, {})
                        if goal_progress else {}
                    )
                    goal_summary.append({
                        "id": key,
                        "description": sg.get("description", ""),
                        "status": progress_entry.get("status", "pending"),
                    })

        payload = {
            "session_id": session_id,
            "round_idx": round_idx,
            "overall_coverage_pct": round(coverage_pct, 1),
            "killchain_coverage": kc_summary,
            "tools_used_count": len(tools_used),
            "tools_sample": sorted(tools_used)[:30],
            "findings": {
                "total": finding_count,
                "confirmed": confirmed_finding_count,
                "confirmation_rate": round(
                    confirmed_finding_count / finding_count, 2
                ) if finding_count else 0.0,
            },
            "hypotheses": hypothesis_stats,
            "goals": goal_summary or None,
        }
        return json.dumps(payload, default=str)

    @staticmethod
    def _parse_verdict(text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON verdict from LLM output. Returns None on failure."""
        text = text.strip()
        # Try direct parse first
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and "verdict" in obj:
                return obj
        except json.JSONDecodeError:
            pass
        # Fall back to extracting the first JSON object from the text
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            try:
                obj = json.loads(match.group())
                if isinstance(obj, dict) and "verdict" in obj:
                    return obj
            except json.JSONDecodeError:
                pass
        return None

    @staticmethod
    async def _persist_verdict(
        session_id: str,
        round_idx: int,
        verdict: Dict[str, Any],
    ) -> str:
        """Insert verdict into the `judge_verdicts` MongoDB collection."""
        verdict_id = f"jv-{uuid.uuid4().hex[:12]}"
        try:
            from app.database.mongodb import get_judge_verdicts_collection
            col = get_judge_verdicts_collection()
            doc = {
                "_id": verdict_id,
                "session_id": session_id,
                "round_idx": round_idx,
                **{
                    k: verdict.get(k)
                    for k in (
                        "overall_score", "coverage_pct", "killchain_phase_scores",
                        "goals_met", "goals_not_met", "hypothesis_resolution_rate",
                        "finding_quality_summary", "gap_list",
                        "coverage_gate_passed", "verdict",
                    )
                },
                "created_at": datetime.now(timezone.utc),
            }
            await col.insert_one(doc)
        except Exception as exc:
            logger.debug("[JUDGE] persist failed (non-fatal): %s", exc)
        return verdict_id

    @staticmethod
    def _passthrough_verdict(coverage_pct: float, finding_count: int) -> Dict[str, Any]:
        """Minimal non-blocking verdict returned when judge evaluation fails."""
        gate_passed = coverage_pct >= 80.0
        return {
            "overall_score": min(1.0, finding_count / 10.0) if finding_count else 0.0,
            "coverage_pct": round(coverage_pct, 1),
            "killchain_phase_scores": {},
            "goals_met": [],
            "goals_not_met": [],
            "hypothesis_resolution_rate": 0.0,
            "finding_quality_summary": "Judge evaluation unavailable.",
            "gap_list": [],
            "coverage_gate_passed": gate_passed,
            "verdict": "pass" if gate_passed else "needs_work",
        }
