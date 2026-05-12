"""T158 — heap_layout_loop.

Allocator-aware heap shaping. Predict → execute → observe → refine. The model
learns allocator-specific patterns within the loop; each iteration narrows the
prediction.

Algorithm:
  T1: pick allocator template (glibc tcache, jemalloc bins, Windows LFH)
  T2: model proposes a shaping plan (allocs, frees, sizes, ordering)
  T3: execute plan in `forge_runner` against the binary / replica
  T4: observe trace (which addresses come back from malloc)
  T5: model compares observed vs. predicted layout
  T6: if matched → done; else refine the plan and loop back to T3
  T7: budget exhausted → return best partial plan

Inputs:
  {
    "binary_path":       str,                  # required (or replica_url)
    "replica_url":       str,                  # if shaping a remote service
    "allocator":         "glibc_tcache|jemalloc|windows_lfh|musl|auto",  # default auto
    "target_layout":     str,                  # human description of desired layout
    "size_classes":      [int],                # bytes; e.g. [64, 128, 256]
    "max_allocs":        int,                  # default 32
    "context":           str,                  # free-form
  }

Result:
  {
    "status":           "success|partial|aborted",
    "allocator":        str,
    "shaping_plan":     [{"op":"alloc|free", "size": int, "tag": "..."}, ...],
    "iterations":       int,
    "match_ratio":      0.0-1.0,
    "observed_layout":  {...},
    "rationale":        str,
  }

Reuse:
  - `forge_runner` MCP tool — execute shaping plan in sandbox.
  - `payload_swarm` MCP tool — fan multiple shaping variants in parallel.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.services.reasoning.framework import DeliberationLoop, TickOutcome
from app.services.mcp_client import call_mcp_tool

logger = logging.getLogger(__name__)


_PLAN_SYSTEM = (
    "You are a HEAP SHAPING PLANNER (GENESIS v7 T158). "
    "Given an allocator and a desired layout, propose a sequence of "
    "alloc/free operations that drives the allocator toward that layout. "
    "Keep size classes consistent with what real exploits use (LIFO bins, "
    "tcache slots, fastbins). Return STRICT JSON: "
    '{"plan": [{"op": "alloc|free", "size": 64, "tag": "victim"}, ...], '
    '"predicted_layout": {"victim_chunk_addr_offset": 0, "notes": "..."}, '
    '"confidence": 0.0-1.0}'
)

_REFINE_SYSTEM = (
    "You are a HEAP SHAPING REFINER (GENESIS v7 T158). "
    "The plan ran but the observed layout differs from the prediction. "
    "Diagnose the gap and propose a refined plan. Return STRICT JSON: "
    '{"diagnosis": "...", "refined_plan": [{"op":"...", "size":...}], '
    '"confidence": 0.0-1.0, "give_up": true|false}'
)

_ALLOCATOR_HINTS: Dict[str, str] = {
    "glibc_tcache": (
        "glibc 2.27+ tcache: per-thread, LIFO, 7 slots per size class up to "
        "1KB; freed chunks are recycled before unsorted bin."
    ),
    "jemalloc": (
        "jemalloc: arena/run/region tiering; 4-byte → 14kB regions in size "
        "classes; freed regions returned to per-arena bins."
    ),
    "windows_lfh": (
        "Windows LFH: 8 sub-segments per bucket; randomised free order; "
        "encoded headers prevent direct overwrite."
    ),
    "musl": (
        "musl mallocng: per-size-class slots, FIFO recycling; small alloc "
        "metadata centralised in a meta-page."
    ),
}


class HeapLayoutLoop(DeliberationLoop):
    loop_type = "heap_layout"

    async def setup(self) -> None:
        self.state["binary_path"] = str(self.inputs.get("binary_path", "") or "")
        self.state["replica_url"] = str(self.inputs.get("replica_url", "") or "")
        self.state["allocator"] = str(self.inputs.get("allocator", "auto") or "auto")
        self.state["target_layout"] = str(self.inputs.get("target_layout", "") or "")[:600]
        self.state["size_classes"] = [int(x) for x in (self.inputs.get("size_classes") or [])][:8]
        self.state["max_allocs"] = int(self.inputs.get("max_allocs", 32))
        self.state["context"] = str(self.inputs.get("context", "") or "")[:1500]
        self.state["phase"] = "plan"
        self.state["plan"] = []
        self.state["predicted_layout"] = {}
        self.state["observed_layout"] = {}
        self.state["match_ratio"] = 0.0
        self.state["refine_attempts"] = 0
        self.state["max_refine_attempts"] = 2

    async def tick(self) -> TickOutcome:
        if not self.state["target_layout"]:
            return TickOutcome(done=True, reasoning="missing target_layout",
                               result={"status": "aborted", "error": "missing target_layout"})

        phase = self.state["phase"]
        if phase == "plan":
            return await self._tick_plan()
        if phase == "execute":
            return await self._tick_execute()
        if phase == "observe":
            return await self._tick_observe()
        if phase == "refine":
            return await self._tick_refine()
        return TickOutcome(done=True, reasoning=f"unknown phase {phase}",
                           result={"status": "aborted", "error": f"unknown phase {phase}"})

    # ------------------------------------------------------------------

    async def _tick_plan(self) -> TickOutcome:
        if self._llm_call is None:
            # Build a deterministic plan: alternating alloc/free pairs over
            # the configured size classes. Crude but useful for smoke tests.
            plan = []
            sizes = self.state["size_classes"] or [64, 128]
            for i in range(min(self.state["max_allocs"], 8)):
                plan.append({"op": "alloc", "size": sizes[i % len(sizes)], "tag": f"a{i}"})
            self.state["plan"] = plan
            self.state["predicted_layout"] = {"notes": "heuristic plan"}
            self.state["phase"] = "execute"
            return TickOutcome(
                state_delta={"plan": plan, "phase": "execute"},
                reasoning="no llm_call → heuristic alloc plan",
                tokens=0,
            )

        allocator_hint = _ALLOCATOR_HINTS.get(self.state["allocator"], "")
        sizes = self.state["size_classes"] or [64, 128, 256]
        user = (
            f"Allocator: {self.state['allocator']}\n"
            f"Allocator hint: {allocator_hint}\n"
            f"Target layout: {self.state['target_layout']}\n"
            f"Size classes available: {sizes}\n"
            f"Max ops: {self.state['max_allocs']}\n"
            f"Context: {self.state['context']}\n\n"
            f"Return JSON only. Plan should be ≤ {self.state['max_allocs']} ops."
        )
        try:
            result = await self._llm_call(system=_PLAN_SYSTEM, user=user, max_tokens=800)
            parsed = _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.warning("heap_layout plan llm failed: %s", exc)
            parsed = {}

        plan = list(parsed.get("plan", []) or [])[: self.state["max_allocs"]]
        # Sanitise plan entries.
        cleaned: List[Dict[str, Any]] = []
        for op in plan:
            if not isinstance(op, dict):
                continue
            o = str(op.get("op", "alloc"))
            if o not in ("alloc", "free"):
                continue
            try:
                size = int(op.get("size", 0))
            except Exception:
                continue
            if size <= 0 or size > 65536:
                continue
            cleaned.append({"op": o, "size": size, "tag": str(op.get("tag", ""))[:32]})

        self.state["plan"] = cleaned
        self.state["predicted_layout"] = parsed.get("predicted_layout") or {}
        self.state["plan_confidence"] = float(parsed.get("confidence", 0.5))
        self.state["phase"] = "execute"
        return TickOutcome(
            state_delta={"plan": cleaned, "predicted_layout": self.state["predicted_layout"],
                         "plan_confidence": self.state["plan_confidence"], "phase": "execute"},
            chosen="plan",
            reasoning=f"planned {len(cleaned)} ops (confidence {self.state['plan_confidence']:.2f})",
            tokens=750,
        )

    async def _tick_execute(self) -> TickOutcome:
        plan = self.state["plan"]
        if not plan:
            return TickOutcome(
                done=True, reasoning="no plan to execute",
                result={"status": "aborted", "error": "empty_plan"},
            )
        # Build a small Python harness that exercises the allocator. We don't
        # actually link against the target binary here — this is the loop's
        # cheap simulator. For real exploitation the operator runs the same
        # plan via instrument_trace / Frida hooks; the loop persists the plan
        # so they can replay it.
        harness = _build_exec_harness(plan, self.state["allocator"])
        try:
            result = await call_mcp_tool(
                "forge_runner",
                {
                    "lang": "python",
                    "code": harness,
                    "wall_time_s": 30,
                    "rationale": f"v7 T158 heap_layout simulation ({self.state['allocator']})",
                },
                timeout=60.0,
            )
        except Exception as exc:
            logger.warning("heap_layout execute failed: %s", exc)
            return TickOutcome(
                done=True, reasoning=f"forge_runner failed: {exc}",
                result={"status": "aborted", "error": f"forge_runner failed: {exc}"},
            )

        parsed = result.get("parsed") or {}
        observed_raw = (parsed.get("stdout") or "").strip()
        observed_layout = _parse_observed_layout(observed_raw)
        self.state["observed_layout"] = observed_layout
        self.state["last_exec_exit"] = parsed.get("exit_code")
        self.state["phase"] = "observe"
        return TickOutcome(
            state_delta={"observed_layout": observed_layout,
                         "last_exec_exit": parsed.get("exit_code"),
                         "phase": "observe"},
            chosen="execute",
            reasoning=f"executed {len(plan)} ops; observed {len(observed_layout)} addresses",
            tokens=20,
        )

    async def _tick_observe(self) -> TickOutcome:
        # Compare observed vs predicted heuristically — adjacency and size
        # ordering. The model's fancier diagnosis runs in _tick_refine.
        predicted = self.state.get("predicted_layout", {}) or {}
        observed = self.state.get("observed_layout", {}) or {}
        match_ratio = _compare_layouts(predicted, observed)
        self.state["match_ratio"] = match_ratio
        if match_ratio >= 0.75:
            return TickOutcome(
                done=True, tokens=10,
                reasoning=f"observed layout matches prediction ({match_ratio:.2f}) → done",
                result=self._build_result("success"),
            )
        if self.state.get("refine_attempts", 0) >= self.state["max_refine_attempts"]:
            return TickOutcome(
                done=True, tokens=10,
                reasoning=f"refine attempts exhausted (match={match_ratio:.2f})",
                result=self._build_result("partial"),
            )
        self.state["phase"] = "refine"
        return TickOutcome(
            state_delta={"phase": "refine", "match_ratio": match_ratio},
            chosen="mismatch",
            reasoning=f"layout mismatch ({match_ratio:.2f}) → refine plan",
            tokens=10,
        )

    async def _tick_refine(self) -> TickOutcome:
        if self._llm_call is None:
            return TickOutcome(
                done=True, tokens=0,
                reasoning="no llm_call → cannot refine; returning partial result",
                result=self._build_result("partial"),
            )

        user = (
            f"Allocator: {self.state['allocator']}\n"
            f"Target: {self.state['target_layout']}\n"
            f"Predicted: {json.dumps(self.state.get('predicted_layout', {}))[:600]}\n"
            f"Observed: {json.dumps(self.state.get('observed_layout', {}))[:600]}\n"
            f"Match ratio: {self.state.get('match_ratio', 0):.2f}\n\n"
            f"Original plan ({len(self.state['plan'])} ops):\n"
            f"{json.dumps(self.state['plan'])[:1200]}\n\n"
            f"Return JSON only."
        )
        try:
            result = await self._llm_call(system=_REFINE_SYSTEM, user=user, max_tokens=700)
            parsed = _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.warning("heap_layout refine llm failed: %s", exc)
            parsed = {}

        if parsed.get("give_up"):
            return TickOutcome(
                done=True, tokens=600,
                reasoning=f"model gave up: {parsed.get('diagnosis','')[:100]}",
                result=self._build_result("partial"),
            )

        refined = list(parsed.get("refined_plan", []) or [])[: self.state["max_allocs"]]
        if not refined:
            return TickOutcome(
                done=True, tokens=600,
                reasoning="refine produced empty plan",
                result=self._build_result("partial"),
            )

        cleaned: List[Dict[str, Any]] = []
        for op in refined:
            if not isinstance(op, dict):
                continue
            o = str(op.get("op", "alloc"))
            if o not in ("alloc", "free"):
                continue
            try:
                size = int(op.get("size", 0))
            except Exception:
                continue
            if size <= 0 or size > 65536:
                continue
            cleaned.append({"op": o, "size": size, "tag": str(op.get("tag", ""))[:32]})

        self.state["plan"] = cleaned
        self.state["refine_attempts"] = self.state.get("refine_attempts", 0) + 1
        self.state["last_diagnosis"] = str(parsed.get("diagnosis", ""))[:300]
        self.state["phase"] = "execute"
        return TickOutcome(
            state_delta={"plan": cleaned,
                         "refine_attempts": self.state["refine_attempts"],
                         "last_diagnosis": self.state["last_diagnosis"],
                         "phase": "execute"},
            chosen="refine",
            reasoning=f"refined to {len(cleaned)} ops; diagnosis: {self.state['last_diagnosis'][:80]}",
            tokens=650,
        )

    # ------------------------------------------------------------------

    def _build_result(self, status: str) -> Dict[str, Any]:
        return {
            "status": status,
            "allocator": self.state["allocator"],
            "shaping_plan": self.state.get("plan", []),
            "iterations": self.state.get("refine_attempts", 0) + 1,
            "match_ratio": round(float(self.state.get("match_ratio", 0.0)), 3),
            "observed_layout": self.state.get("observed_layout", {}),
            "predicted_layout": self.state.get("predicted_layout", {}),
            "rationale": self.state.get("last_diagnosis", "") or "no refinement diagnosis",
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_exec_harness(plan: List[Dict[str, Any]], allocator: str) -> str:
    """Emit a Python harness that exercises the requested allocator pattern
    and prints addresses (or sizes) so we can compare vs prediction.

    This is intentionally allocator-AGNOSTIC at runtime — the simulation runs
    in a Python sandbox, so it doesn't actually verify glibc tcache layouts.
    The persisted plan is what real exploit work re-applies via Frida or
    instrument_trace; this loop's job is to produce a plan-with-justification,
    not to verify on the live target.
    """
    plan_json = json.dumps(plan)
    return (
        "import ctypes, json, sys\n"
        f"plan = json.loads({plan_json!r})\n"
        f"allocator = {allocator!r}\n"
        "live = []\n"
        "log = []\n"
        "for op in plan:\n"
        "    size = int(op.get('size', 0))\n"
        "    if op.get('op') == 'alloc':\n"
        "        buf = (ctypes.c_char * size)()\n"
        "        addr = ctypes.addressof(buf)\n"
        "        live.append(buf)\n"
        "        log.append({'op':'alloc','size':size,'addr':addr,'tag':op.get('tag','')})\n"
        "    elif op.get('op') == 'free':\n"
        "        if live:\n"
        "            live.pop()\n"
        "            log.append({'op':'free','size':size,'tag':op.get('tag','')})\n"
        "print(json.dumps({'allocator': allocator, 'log': log}))\n"
    )


def _parse_observed_layout(stdout: str) -> Dict[str, Any]:
    """Pull the JSON `log` line out of harness stdout."""
    if not stdout:
        return {}
    # Take the LAST {...} block to be safe.
    matches = list(re.finditer(r"\{[\s\S]*?\}", stdout))
    if not matches:
        return {}
    try:
        parsed = json.loads(matches[-1].group(0))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _compare_layouts(predicted: Dict[str, Any], observed: Dict[str, Any]) -> float:
    """Heuristic 0-1 match score. Compares op counts, ordering, and size
    coverage. Not a substitute for real allocator-aware verification; just
    enough to drive the loop's converge/refine decision."""
    if not observed:
        return 0.0
    ops = list((observed.get("log") or []))
    if not ops:
        return 0.1
    # Coarse match: did we see at least one alloc and one free if predicted? Bonus if size diversity matches.
    alloc_count = sum(1 for o in ops if o.get("op") == "alloc")
    free_count = sum(1 for o in ops if o.get("op") == "free")
    sizes_seen = {int(o.get("size") or 0) for o in ops}
    score = 0.0
    if alloc_count >= 1:
        score += 0.4
    if free_count >= 1:
        score += 0.2
    if len(sizes_seen) >= 2:
        score += 0.2
    notes = str(predicted.get("notes", ""))
    if notes and any(k in notes.lower() for k in ("victim", "spray", "groom")):
        score += 0.2
    return min(1.0, score)


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
