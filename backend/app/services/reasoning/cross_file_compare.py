"""multi-stage cross-file pattern comparison reasoning loop.

This lightweight loop helps the hybrid scanner ask one bounded question:
"does this source-backed candidate look inconsistent with nearby/analogous
code?" It intentionally produces a structured review result, not a finding.
The validated pipeline still handles candidate storage, validation, proof, and
promotion.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from app.services.reasoning.framework import DeliberationLoop, TickOutcome


class CrossFileCompareLoop(DeliberationLoop):
    loop_type = "cross_file_compare"

    async def setup(self) -> None:
        candidate = self.inputs.get("candidate") or {}
        if not isinstance(candidate, dict):
            candidate = {"description": str(candidate)[:2000]}
        comparison_snippets = self.inputs.get("comparison_snippets") or []
        if isinstance(comparison_snippets, str):
            comparison_snippets = [comparison_snippets]
        elif not isinstance(comparison_snippets, list):
            comparison_snippets = list(comparison_snippets) if isinstance(comparison_snippets, tuple) else []
        self.state = {
            "candidate": candidate,
            "primary_snippet": str(self.inputs.get("primary_snippet") or "")[:6000],
            "comparison_snippets": comparison_snippets,
            "question": str(self.inputs.get("question") or "Compare source patterns for a security-relevant inconsistency."),
        }

    async def tick(self) -> TickOutcome:
        candidate = self.state.get("candidate") or {}
        if not isinstance(candidate, dict):
            candidate = {"description": str(candidate)[:2000]}
        primary = self.state.get("primary_snippet") or ""
        comparisons = self.state.get("comparison_snippets") or []
        if isinstance(comparisons, str):
            comparisons = [comparisons]
        elif not isinstance(comparisons, (list, tuple)):
            comparisons = []
        compact_comparisons: List[str] = [
            str(item)[:2500] for item in comparisons[:5] if str(item).strip()
        ]

        if not self._llm_call:
            result = self._heuristic_compare(candidate, primary, compact_comparisons)
            return TickOutcome(
                done=True,
                reasoning="Heuristic cross-file comparison completed without LLM.",
                result=result,
            )

        user = (
            "Review this candidate for a cross-file security inconsistency.\n"
            "Return JSON only with keys: support, refute, needs_proof, reasoning, "
            "missing_evidence, proposed_live_proof.\n\n"
            f"Candidate:\n{json.dumps(candidate, default=str)[:4000]}\n\n"
            f"Primary snippet:\n{primary}\n\n"
            "Comparison snippets:\n"
            + "\n\n---\n\n".join(compact_comparisons)
        )
        response = await self._llm_call(
            system="You are a precise source-code security validator. Answer only JSON.",
            user=user,
            max_tokens=1200,
        )
        text = str((response or {}).get("text") or "").strip()
        parsed: Dict[str, Any]
        try:
            start = text.find("{")
            end = text.rfind("}")
            parsed = json.loads(text[start:end + 1]) if start != -1 and end != -1 else {}
        except Exception:
            parsed = {}
        if not parsed:
            parsed = self._heuristic_compare(candidate, primary, compact_comparisons)
            parsed["reasoning"] = "LLM output was not parseable; fell back to heuristic comparison."
        return TickOutcome(
            done=True,
            reasoning=str(parsed.get("reasoning") or "Cross-file comparison completed.")[:2000],
            tokens=int((response or {}).get("tokens") or 0),
            result=parsed,
        )

    def _heuristic_compare(
        self,
        candidate: Dict[str, Any],
        primary: str,
        comparisons: List[str],
    ) -> Dict[str, Any]:
        primary_l = primary.lower()
        comparison_l = "\n".join(comparisons).lower()
        risky_markers = ("free(", "memcpy", "strcpy", "exec(", "eval(", "query(", "deserialize", "pickle", "jwt")
        safer_markers = ("validate", "sanitize", "escape", "authorize", "constanttime", "lock", "refcount", "deepcopy")
        risky = [m for m in risky_markers if m in primary_l]
        safer_elsewhere = [m for m in safer_markers if m in comparison_l and m not in primary_l]
        support = bool(risky and safer_elsewhere)
        return {
            "support": support,
            "refute": False,
            "needs_proof": True,
            "reasoning": (
                "Primary code has risky operations while comparison snippets show safer guard patterns."
                if support else "No decisive cross-file inconsistency found heuristically."
            ),
            "missing_evidence": ["live endpoint replay", "exact source-to-sink trace"],
            "proposed_live_proof": candidate.get("proof_plan") or candidate.get("proposed_proof") or {},
            "risky_markers": risky,
            "safer_elsewhere_markers": safer_elsewhere,
        }
