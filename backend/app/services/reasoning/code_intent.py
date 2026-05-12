"""T156 — code_intent_loop (multi-zoom).

Reads code at five zoom levels and emits an intent hypothesis at each level.
Subsequent levels confirm or refute upstream hypotheses; a discrepancy
between zoom levels (e.g. function-level "this validates length" vs
architectural-level "renegotiation path is attacker-reachable") flags a
candidate vulnerability — the Heartbleed-shaped pattern from the manual.

Zoom levels (in order):
  1. function       — single function body
  2. file           — surrounding file context
  3. module         — package / directory
  4. cross_module   — call sites in other modules
  5. architectural  — system role of the module (delegates to architectural_reasoner)

Inputs:
  {
    "function_text":  str,                  # required — the focal function
    "file_text":      str,                  # optional, the enclosing file
    "module_summary": str,                  # optional, the module's purpose
    "callers_summary": str,                 # optional, who calls this and why
    "function_name":  str,
    "file_path":      str,
  }

Result:
  {
    "intents":     [{"level": "function", "intent": "...", "confidence": 0.0-1.0}, ...],
    "discrepancies": [{"between": ["function","cross_module"], "note": "..."}],
    "vuln_candidate": bool,
    "candidate_summary": str,
  }
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.services.reasoning.framework import DeliberationLoop, TickOutcome
from app.services.hypothesis_market import submit_hypothesis

logger = logging.getLogger(__name__)


_INTENT_SYSTEM = (
    "You are a CODE INTENT ANALYST (GENESIS v7 T156). "
    "Given a code artifact at a specific zoom level, state the AUTHOR'S "
    "INTENT — what they meant the code to do — in ONE sentence. "
    "Then rate your confidence. Return STRICT JSON: "
    '{"intent": "...", "confidence": 0.0-1.0, "security_relevant": true|false, '
    '"observations": ["..."]}'
)

_DISCREPANCY_SYSTEM = (
    "You are a CODE DISCREPANCY DETECTOR (GENESIS v7 T156). "
    "Given two zoom-level intent statements, decide whether they are "
    "CONSISTENT or whether the lower-zoom statement assumes something the "
    "higher-zoom statement contradicts (a Heartbleed-class smell). "
    "Return STRICT JSON: "
    '{"consistent": true|false, "smell": "none|reachability|trust|sanitization|state", '
    '"explanation": "..."}'
)

ZOOM_LEVELS = ("function", "file", "module", "cross_module", "architectural")


class CodeIntentLoop(DeliberationLoop):
    loop_type = "code_intent"

    async def setup(self) -> None:
        self.state["function_name"] = str(self.inputs.get("function_name", "<anon>"))
        self.state["file_path"] = str(self.inputs.get("file_path", "<unknown>"))
        self.state["zoom_index"] = 0
        self.state["intents"] = []
        self.state["discrepancies"] = []
        # Map zoom level -> input text. Missing inputs -> empty string -> level skipped.
        self.state["zoom_inputs"] = {
            "function":      str(self.inputs.get("function_text", "") or ""),
            "file":          str(self.inputs.get("file_text", "") or ""),
            "module":        str(self.inputs.get("module_summary", "") or ""),
            "cross_module":  str(self.inputs.get("callers_summary", "") or ""),
            "architectural": str(self.inputs.get("architectural_note", "") or ""),
        }

    async def tick(self) -> TickOutcome:
        if self._llm_call is None:
            return TickOutcome(done=True, reasoning="no llm_call provided",
                               result={"intents": [], "error": "missing llm_call"})

        idx = self.state.get("zoom_index", 0)
        if idx >= len(ZOOM_LEVELS):
            return self._finalize()

        level = ZOOM_LEVELS[idx]
        artifact = self.state["zoom_inputs"].get(level, "")
        self.state["zoom_index"] = idx + 1

        if not artifact.strip():
            # Skip empty zoom; still log a tick so the trace is honest.
            return TickOutcome(
                state_delta={"zoom_index": idx + 1},
                reasoning=f"skipped zoom level '{level}' (no input)",
                tokens=0,
                chosen=level,
            )

        intent = await self._extract_intent(level, artifact)
        intents: List[Dict[str, Any]] = self.state.get("intents", [])
        intents.append(intent)
        self.state["intents"] = intents

        # Compare to the prior level's intent for discrepancy.
        if len(intents) >= 2:
            prior = intents[-2]
            disc = await self._compare_intents(prior, intent)
            if disc and not disc.get("consistent", True):
                self.state["discrepancies"].append({
                    "between": [prior["level"], intent["level"]],
                    "smell": disc.get("smell"),
                    "explanation": disc.get("explanation", ""),
                })

        # If we've completed all levels, finalize.
        if self.state["zoom_index"] >= len(ZOOM_LEVELS):
            return self._finalize()

        return TickOutcome(
            state_delta={"zoom_index": self.state["zoom_index"]},
            chosen=level,
            reasoning=f"zoom '{level}' → {intent.get('intent','')[:120]}",
            tokens=350,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _extract_intent(self, level: str, artifact: str) -> Dict[str, Any]:
        user = (
            f"Zoom level: {level}\n"
            f"Function: {self.state['function_name']}\n"
            f"File: {self.state['file_path']}\n\n"
            f"Code / context:\n{artifact[:6000]}\n\nReturn JSON only."
        )
        try:
            result = await self._llm_call(system=_INTENT_SYSTEM, user=user, max_tokens=400)
            parsed = _extract_json(result.get("text", ""))
            return {
                "level": level,
                "intent": parsed.get("intent", "")[:400],
                "confidence": float(parsed.get("confidence", 0.5)),
                "security_relevant": bool(parsed.get("security_relevant", False)),
                "observations": list(parsed.get("observations", []))[:5],
            }
        except Exception as exc:
            logger.debug("code_intent extract at %s failed: %s", level, exc)
            return {"level": level, "intent": "", "confidence": 0.0, "security_relevant": False, "observations": []}

    async def _compare_intents(self, prior: Dict[str, Any], current: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not prior.get("intent") or not current.get("intent"):
            return None
        user = (
            f"Lower zoom ({prior['level']}): {prior['intent']}\n"
            f"Higher zoom ({current['level']}): {current['intent']}\n\n"
            f"Return JSON only."
        )
        try:
            result = await self._llm_call(system=_DISCREPANCY_SYSTEM, user=user, max_tokens=300)
            return _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.debug("code_intent compare failed: %s", exc)
            return None

    def _finalize(self) -> TickOutcome:
        intents: List[Dict[str, Any]] = self.state.get("intents", [])
        discrepancies: List[Dict[str, Any]] = self.state.get("discrepancies", [])
        vuln_candidate = bool(discrepancies)
        candidate_summary = ""
        if vuln_candidate:
            d = discrepancies[0]
            candidate_summary = (
                f"Discrepancy between {'/'.join(d['between'])} zoom levels — "
                f"{d.get('smell')}: {d.get('explanation','')[:200]}"
            )
            # Ship a market hypothesis so the rest of the platform sees it.
            try:
                # Fire-and-forget; errors are non-fatal.
                import asyncio
                asyncio.create_task(submit_hypothesis(
                    session_id=self.session_id,
                    text=(
                        f"Code-intent multi-zoom discrepancy in "
                        f"{self.state.get('file_path')}:{self.state.get('function_name')} "
                        f"({d.get('smell')}): {d.get('explanation','')[:300]}"
                    ),
                    proposer_agent="code_intent_t156",
                    hypothesis_type="code_intent_discrepancy",
                    confidence_stake=0.6,
                ))
            except Exception:
                pass

        return TickOutcome(
            done=True,
            reasoning=(
                f"completed {len([i for i in intents if i.get('intent')])} non-empty zoom levels, "
                f"{len(discrepancies)} discrepancies"
            ),
            tokens=200,
            result={
                "intents": intents,
                "discrepancies": discrepancies,
                "vuln_candidate": vuln_candidate,
                "candidate_summary": candidate_summary,
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
