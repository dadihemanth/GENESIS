"""T160 — deliberation_framework: meta-architecture every v7 loop composes.

The thesis (manual section v7-tvl): a loop that compresses a 10,000-token
reasoning task into ten 1,000-token turns lets a generic Opus model reach
conclusions a 10x larger monolithic model would otherwise need. The loop is
the search structure; the LLM is the cheap evaluator.

This module provides the shared scaffolding:
  - Working state (persisted per tick to MongoDB `loop_state`)
  - branch() / backtrack() (delegates to T161 tree_of_thought)
  - propagate_constraints()
  - decompose() (delegates to T166 hypothesis_decomp)
  - tick()  — one iteration; subclasses override
  - run()   — drives tick() until done / budget exhausted

Subclasses implement the domain-specific reasoning at each tick. They are
NOT supposed to implement persistence, branching, or budget tracking — that
all comes free from this base.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.services.reasoning import loop_state as _state

logger = logging.getLogger(__name__)


@dataclass
class TickOutcome:
    """What a single tick() call produces.

    `done=True` ends the run. `result` is forwarded to the loop's `result`
    field on completion. `branches` and `chosen` are recorded on the tick
    for replay; they have no behavioural effect on later ticks unless the
    subclass references them via `self.state`.
    """
    done: bool = False
    state_delta: Dict[str, Any] = field(default_factory=dict)
    branches: List[Dict[str, Any]] = field(default_factory=list)
    chosen: Optional[str] = None
    reasoning: str = ""
    tokens: int = 0
    result: Optional[Dict[str, Any]] = None


@dataclass
class LoopBudget:
    max_tokens: int = 10_000
    max_ticks: int = 10


class DeliberationLoop(ABC):
    """Base class for every v7 reasoning loop.

    Subclasses must implement:
        - `loop_type` (class attribute, str)
        - `async def tick(self) -> TickOutcome`

    Subclasses MAY override `setup()` to seed working state from `inputs`.
    """

    loop_type: str = "abstract"

    def __init__(
        self,
        session_id: str,
        inputs: Dict[str, Any],
        *,
        llm_call: Optional[Callable[..., Awaitable[Dict[str, Any]]]] = None,
        budget: Optional[LoopBudget] = None,
    ) -> None:
        self.session_id = session_id
        self.inputs = inputs or {}
        self.budget = budget or LoopBudget()
        self.state: Dict[str, Any] = {}
        self.history: List[TickOutcome] = []
        # `llm_call` is an async callable accepting (system, user, max_tokens)
        # → returning {"text": "...", "tokens": int}. The orchestrator passes
        # one in so loops reuse the session's Anthropic client. Loops that
        # don't need an LLM can ignore it.
        self._llm_call = llm_call
        self.loop_id: Optional[str] = None
        self._tokens_spent = 0

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Seed `self.state` from `self.inputs`. Override as needed."""
        return None

    @abstractmethod
    async def tick(self) -> TickOutcome:
        """Run one iteration. Subclasses must implement."""

    async def teardown(self, result: Optional[Dict[str, Any]]) -> None:
        """Optional cleanup hook (close handles, emit summaries)."""
        return None

    # ------------------------------------------------------------------
    # Driver
    # ------------------------------------------------------------------

    async def run(self) -> Dict[str, Any]:
        """Drive `tick()` until done / budget exhausted. Persists every tick.

        Returns:
            {
              "loop_id": str,
              "loop_type": str,
              "status": "complete" | "aborted",
              "result": {...} | None,
              "ticks": int,
              "tokens_spent": int,
              "abort_reason": str | None,
            }
        """
        self.loop_id = await _state.create_loop(self.session_id, self.loop_type, self.inputs)
        try:
            await self.setup()
        except Exception as exc:
            logger.warning("loop %s setup failed: %s", self.loop_type, exc)
            await _state.finalize_loop(self.session_id, self.loop_id, status="aborted",
                                       result={"abort_reason": f"setup_failed: {exc}"})
            return self._build_return(status="aborted", result=None, abort_reason=f"setup_failed: {exc}")

        status = "complete"
        abort_reason: Optional[str] = None
        result: Optional[Dict[str, Any]] = None

        for i in range(self.budget.max_ticks):
            try:
                outcome = await self.tick()
            except Exception as exc:
                logger.exception("loop %s tick %d crashed: %s", self.loop_type, i + 1, exc)
                status = "aborted"
                abort_reason = f"tick_exception: {exc}"
                break

            # apply state delta and track tokens
            if outcome.state_delta:
                self.state.update(outcome.state_delta)
            self._tokens_spent += int(outcome.tokens or 0)
            self.history.append(outcome)

            await _state.append_tick(
                self.session_id, self.loop_id,
                state_snapshot=_safe_snapshot(self.state),
                branches=outcome.branches,
                chosen=outcome.chosen,
                reasoning=outcome.reasoning,
                tokens=outcome.tokens,
            )

            if outcome.done:
                result = outcome.result
                break

            if self._tokens_spent >= self.budget.max_tokens:
                status = "aborted"
                abort_reason = "token_budget_exceeded"
                # If the subclass had something partial, surface it.
                result = outcome.result
                break
        else:
            # Loop hit max_ticks without setting done.
            status = "aborted"
            abort_reason = "tick_budget_exceeded"
            result = self.history[-1].result if self.history else None

        try:
            await self.teardown(result)
        except Exception as exc:
            logger.debug("loop %s teardown raised (non-fatal): %s", self.loop_type, exc)

        await _state.finalize_loop(
            self.session_id, self.loop_id,
            status=status,
            result={"result": result, "abort_reason": abort_reason} if abort_reason else {"result": result},
        )
        return self._build_return(status=status, result=result, abort_reason=abort_reason)

    # ------------------------------------------------------------------
    # Composition helpers (T161, T166 delegation)
    # ------------------------------------------------------------------

    def branch(self, candidates: List[Dict[str, Any]], score_fn: Optional[Callable[[Dict[str, Any]], float]] = None) -> Dict[str, Any]:
        """Pick the best candidate from a flat list. Cheap default = first.

        Subclasses with a real evaluator should pass a scoring function. The
        T161 tree_of_thought module exposes a richer search; this method is
        the synchronous quick-pick.
        """
        if not candidates:
            return {}
        if score_fn is None:
            return candidates[0]
        return max(candidates, key=score_fn)

    def propagate_constraints(self, constraints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter `self.state.get('candidates', [])` by hard constraints.

        Constraint shape: `{"key": "size_bytes", "op": "<=", "value": 200}`.
        Operators supported: ==, !=, <, <=, >, >=, in, not_in, contains.
        """
        candidates = list(self.state.get("candidates", []))
        for c in constraints:
            key = c.get("key")
            op = c.get("op")
            val = c.get("value")
            candidates = [x for x in candidates if _check_constraint(x.get(key), op, val)]
        return candidates

    async def decompose(self, hypothesis_text: str, parent_id: Optional[str] = None) -> List[str]:
        """Delegate to T166 hypothesis_decomp."""
        # Lazy import to avoid circular references.
        from app.services.reasoning.hypothesis_decomp import decompose_hypothesis
        return await decompose_hypothesis(
            session_id=self.session_id,
            text=hypothesis_text,
            parent_id=parent_id,
            llm_call=self._llm_call,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_return(self, *, status: str, result: Any, abort_reason: Optional[str]) -> Dict[str, Any]:
        return {
            "loop_id": self.loop_id,
            "loop_type": self.loop_type,
            "status": status,
            "result": result,
            "ticks": len(self.history),
            "tokens_spent": self._tokens_spent,
            "abort_reason": abort_reason,
        }


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------

def _check_constraint(actual: Any, op: Optional[str], expected: Any) -> bool:
    if op is None:
        return True
    try:
        if op == "==":
            return actual == expected
        if op == "!=":
            return actual != expected
        if op == "<":
            return actual is not None and actual < expected
        if op == "<=":
            return actual is not None and actual <= expected
        if op == ">":
            return actual is not None and actual > expected
        if op == ">=":
            return actual is not None and actual >= expected
        if op == "in":
            return actual in (expected or [])
        if op == "not_in":
            return actual not in (expected or [])
        if op == "contains":
            return expected in (actual or [])
    except Exception:
        return False
    return False


def _safe_snapshot(state: Dict[str, Any], max_chars: int = 4000) -> Dict[str, Any]:
    """Truncate large fields so MongoDB documents stay reasonable."""
    out: Dict[str, Any] = {}
    for k, v in state.items():
        if isinstance(v, str) and len(v) > max_chars:
            out[k] = v[:max_chars] + f"...[truncated, {len(v)} chars]"
        elif isinstance(v, list) and len(v) > 50:
            out[k] = v[:50] + [f"...[truncated, {len(v)} items]"]
        else:
            out[k] = v
    return out
