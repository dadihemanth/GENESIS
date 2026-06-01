"""v7 reasoning loop registry — dispatch table, per-loop budgets, public entry point.

The orchestrator routes the new `deliberate` tool through `dispatch()`. Each
loop has a hard budget defined here (per the v7 plan). All ten reasoning
loops (T155-T166) are now live: Phase 1+2 (code_intent, invariant_tracker,
causal_trace, counterfactual, hypothesis_decomp, long_context_code) and
Phase 3 (rop_composition, chain_composer, heap_layout, self_correcting).

Public API:
  - LOOP_TYPES: tuple of supported loop_type strings
  - get_budget(loop_type) -> LoopBudget
  - dispatch(session_id, loop_type, inputs, llm_call) -> dict
"""
from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict, Tuple, Type

from app.services.reasoning.framework import DeliberationLoop, LoopBudget

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Budgets — per the agreed v7 caps.
# ---------------------------------------------------------------------------

_BUDGETS: Dict[str, LoopBudget] = {
    # Phase 1+2 — code/hypothesis reasoning (no sandbox dependency)
    "code_intent":         LoopBudget(max_tokens=8_000,  max_ticks=6),
    "invariant_tracker":   LoopBudget(max_tokens=8_000,  max_ticks=8),
    "causal_trace":        LoopBudget(max_tokens=6_000,  max_ticks=6),
    "counterfactual":      LoopBudget(max_tokens=8_000,  max_ticks=6),
    "hypothesis_decomp":   LoopBudget(max_tokens=4_000,  max_ticks=5),
    "long_context_code":   LoopBudget(max_tokens=20_000, max_ticks=15),
    # validation milestone 3 — cross-file pattern inconsistency (one tick: query + compare)
    "cross_file_compare":  LoopBudget(max_tokens=6_000,  max_ticks=3),
    # Phase 3 — exploit loops (call MCP tools, reuse forge_sandbox/replay_sessions)
    "rop_composition":     LoopBudget(max_tokens=15_000, max_ticks=12),
    "chain_composer":      LoopBudget(max_tokens=6_000,  max_ticks=8),
    "heap_layout":         LoopBudget(max_tokens=12_000, max_ticks=10),
    "self_correcting":     LoopBudget(max_tokens=10_000, max_ticks=8),
}

LOOP_TYPES: Tuple[str, ...] = tuple(_BUDGETS.keys())


def get_budget(loop_type: str) -> LoopBudget:
    return _BUDGETS.get(loop_type, LoopBudget())


# ---------------------------------------------------------------------------
# Class registry — populated lazily to avoid circular imports.
# ---------------------------------------------------------------------------

def _build_class_map() -> Dict[str, Type[DeliberationLoop]]:
    """Lazy import so `from .registry` is cheap and circular-safe."""
    from app.services.reasoning.code_intent import CodeIntentLoop
    from app.services.reasoning.invariant_tracker import InvariantTrackerLoop
    from app.services.reasoning.causal_trace import CausalTraceLoop
    from app.services.reasoning.counterfactual import CounterfactualLoop
    from app.services.reasoning.hypothesis_decomp import HypothesisDecompLoop
    from app.services.reasoning.long_context_code import LongContextCodeLoop
    from app.services.reasoning.cross_file_compare import CrossFileCompareLoop
    # Phase-3 exploit loops
    from app.services.reasoning.rop_composition import ROPCompositionLoop
    from app.services.reasoning.chain_composer import ChainComposerLoop
    from app.services.reasoning.heap_layout import HeapLayoutLoop
    from app.services.reasoning.self_correcting import SelfCorrectingExploitLoop

    return {
        # Phase 1+2
        "code_intent":       CodeIntentLoop,
        "invariant_tracker": InvariantTrackerLoop,
        "causal_trace":      CausalTraceLoop,
        "counterfactual":    CounterfactualLoop,
        "hypothesis_decomp": HypothesisDecompLoop,
        "long_context_code": LongContextCodeLoop,
        "cross_file_compare": CrossFileCompareLoop,
        # Phase 3
        "rop_composition":   ROPCompositionLoop,
        "chain_composer":    ChainComposerLoop,
        "heap_layout":       HeapLayoutLoop,
        "self_correcting":   SelfCorrectingExploitLoop,
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

async def dispatch(
    *,
    session_id: str,
    loop_type: str,
    inputs: Dict[str, Any],
    llm_call: Callable[..., Awaitable[Dict[str, Any]]] | None = None,
) -> Dict[str, Any]:
    """Run a reasoning loop and return its structured result.

    The orchestrator calls this when the model emits `tool_use(name=deliberate)`.
    """
    if loop_type not in _BUDGETS:
        return {
            "status": "error",
            "error": f"unknown loop_type '{loop_type}'",
            "supported": list(LOOP_TYPES),
        }

    budget = _BUDGETS[loop_type]
    class_map = _build_class_map()
    loop_cls = class_map.get(loop_type)

    if loop_cls is None:
        # Should be unreachable — _BUDGETS and class_map are kept in sync.
        return {
            "status": "error",
            "error": f"loop_type '{loop_type}' has a budget but no class — registry desync",
            "supported": list(LOOP_TYPES),
        }

    instance = loop_cls(session_id, inputs, llm_call=llm_call, budget=budget)
    return await instance.run()
