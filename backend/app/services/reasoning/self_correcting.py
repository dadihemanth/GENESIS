"""T159 — self_correcting_exploit_loop.

When an exploit attempt fails, classify *why* (wrong offset, wrong primitive,
wrong allocator state, ASLR drift, defensive intervention) and propose a
corrected attempt. Replay in `forge_runner` (sandbox) until success or
budget exhaustion.

Algorithm:
  T1: classify failure via LLM (offset/primitive/allocator/aslr/defence/unknown)
  T2: propose a correction (diff + new payload)
  T3: replay in forge_runner; persist result to `replay_sessions`
  T4: if success → done; else loop to T1 with the new failure mode
  T5: budget exhausted → return last attempt with diagnosis trail

Inputs:
  {
    "exploit_payload":   str,         # current payload (string or hex)
    "execution_lang":    "python|node|bash",   # default "python"
    "execution_code":    str,         # script that delivers + verifies the payload
    "failure_observed":  str,         # what went wrong this run
    "expected_result":   str,         # oracle predicate (what success looks like)
    "target_hint":       str,         # IP/hostname or replica URL
    "cve_id":            str,         # optional, used as replay_sessions key
    "replica_id":        str,         # optional, T122 replica id
    "context":           str,
  }

Result:
  {
    "status":           "success|exhausted|aborted",
    "iterations":       int,
    "final_payload":    str,
    "final_diagnosis":  str,
    "trail":            [{"iteration":..., "failure_mode":..., "diagnosis":..., "action":...}],
    "evidence":         {"oracle_verdict": "...", "stdout_tail": "..."},
  }

Reuse:
  - `forge_runner` MCP tool (sandbox replay).
  - `replay_sessions` MongoDB collection (T131 sameday CVE replay reuses this).
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.mongodb import get_replay_sessions_collection
from app.services.mcp_client import call_mcp_tool
from app.services.reasoning.framework import DeliberationLoop, TickOutcome

logger = logging.getLogger(__name__)


_CLASSIFY_SYSTEM = (
    "You are an EXPLOIT FAILURE CLASSIFIER (GENESIS v7 T159). "
    "Given the original payload, the failure observation, and the target "
    "context, decide which class the failure belongs to. Classes: "
    "'wrong_offset' (off-by-N alignment / pivot), 'wrong_primitive' (the "
    "payload assumes capability the target doesn't have), 'allocator_state' "
    "(heap layout shifted between runs), 'aslr_drift' (an address was "
    "stale), 'defence' (WAF/seccomp/CFI intervened), 'transport' (network "
    "/ encoding bug — not the exploit logic), 'unknown'. "
    "Return STRICT JSON: "
    '{"failure_mode": "...", "confidence": 0.0-1.0, "diagnosis": "...", '
    '"focus_area": "..."}'
)

_PROPOSE_SYSTEM = (
    "You are an EXPLOIT CORRECTION PROPOSER (GENESIS v7 T159). "
    "Given a failure mode and the current execution code, propose a "
    "minimal, focused correction (NOT a rewrite). Keep the verification "
    "oracle intact. Return STRICT JSON: "
    '{"action": "patch_offset|adjust_primitive|reshape_heap|refresh_leak|'
    'evade_defence|swap_transport|abort", '
    '"corrected_code": "...", "corrected_payload": "...", '
    '"rationale": "...", "max_runtime_s": 30}'
)

_VALID_FAILURE_MODES = {
    "wrong_offset", "wrong_primitive", "allocator_state", "aslr_drift",
    "defence", "transport", "unknown",
}


class SelfCorrectingExploitLoop(DeliberationLoop):
    loop_type = "self_correcting"

    async def setup(self) -> None:
        self.state["payload"] = str(self.inputs.get("exploit_payload", "") or "")
        self.state["execution_lang"] = str(self.inputs.get("execution_lang", "python")) or "python"
        self.state["execution_code"] = str(self.inputs.get("execution_code", "") or "")
        self.state["failure_observed"] = str(self.inputs.get("failure_observed", "") or "")[:1500]
        self.state["expected_result"] = str(self.inputs.get("expected_result", "") or "")[:600]
        self.state["target_hint"] = str(self.inputs.get("target_hint", "") or "")
        self.state["cve_id"] = str(self.inputs.get("cve_id", "") or "")
        self.state["replica_id"] = str(self.inputs.get("replica_id", "") or "")
        self.state["context"] = str(self.inputs.get("context", "") or "")[:1500]
        self.state["phase"] = "classify"
        self.state["trail"] = []
        self.state["iteration_count"] = 0
        self.state["last_evidence"] = {}

    async def tick(self) -> TickOutcome:
        if not self.state["execution_code"] and not self.state["payload"]:
            return TickOutcome(
                done=True, reasoning="missing execution_code and exploit_payload",
                result={"status": "aborted", "error": "missing execution_code and exploit_payload"},
            )

        phase = self.state["phase"]
        if phase == "classify":
            return await self._tick_classify()
        if phase == "propose":
            return await self._tick_propose()
        if phase == "replay":
            return await self._tick_replay()
        return TickOutcome(done=True, reasoning=f"unknown phase {phase}",
                           result={"status": "aborted", "error": f"unknown phase {phase}"})

    # ------------------------------------------------------------------

    async def _tick_classify(self) -> TickOutcome:
        if self._llm_call is None:
            # Heuristic classifier on the failure_observed string.
            mode, diag = _heuristic_classify(self.state["failure_observed"])
            self.state["current_failure_mode"] = mode
            self.state["current_diagnosis"] = diag
            self.state["phase"] = "propose"
            return TickOutcome(
                state_delta={"current_failure_mode": mode, "current_diagnosis": diag, "phase": "propose"},
                reasoning=f"heuristic classify → {mode}",
                tokens=0,
            )

        user = (
            f"Original payload (≤500 chars):\n{self.state['payload'][:500]}\n\n"
            f"Failure observed:\n{self.state['failure_observed']}\n\n"
            f"Expected outcome (oracle): {self.state['expected_result']}\n\n"
            f"Target: {self.state['target_hint']}\n"
            f"Context: {self.state['context']}\n\n"
            f"Return JSON only."
        )
        try:
            result = await self._llm_call(system=_CLASSIFY_SYSTEM, user=user, max_tokens=400)
            parsed = _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.warning("self_correcting classify llm failed: %s", exc)
            parsed = {}

        mode = str(parsed.get("failure_mode", "unknown"))
        if mode not in _VALID_FAILURE_MODES:
            mode = "unknown"
        diagnosis = str(parsed.get("diagnosis", ""))[:400]

        self.state["current_failure_mode"] = mode
        self.state["current_diagnosis"] = diagnosis
        self.state["phase"] = "propose"
        return TickOutcome(
            state_delta={"current_failure_mode": mode, "current_diagnosis": diagnosis, "phase": "propose"},
            chosen=mode,
            reasoning=f"classified failure as {mode}: {diagnosis[:120]}",
            tokens=350,
        )

    async def _tick_propose(self) -> TickOutcome:
        if self._llm_call is None:
            return TickOutcome(
                done=True, reasoning="no llm_call → cannot propose correction",
                result=self._build_result("aborted", final_diagnosis="missing llm_call"),
                tokens=0,
            )

        user = (
            f"Failure mode: {self.state['current_failure_mode']}\n"
            f"Diagnosis: {self.state['current_diagnosis']}\n\n"
            f"Original execution code (lang={self.state['execution_lang']}):\n"
            f"{self.state['execution_code'][:2500]}\n\n"
            f"Original payload (≤500 chars):\n{self.state['payload'][:500]}\n\n"
            f"Expected outcome: {self.state['expected_result']}\n"
            f"Target: {self.state['target_hint']}\n\n"
            f"Return JSON only."
        )
        try:
            result = await self._llm_call(system=_PROPOSE_SYSTEM, user=user, max_tokens=900)
            parsed = _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.warning("self_correcting propose llm failed: %s", exc)
            parsed = {}

        action = str(parsed.get("action", "abort"))
        if action == "abort":
            return TickOutcome(
                done=True, reasoning="model recommended abort",
                result=self._build_result(
                    "aborted",
                    final_diagnosis=str(parsed.get("rationale", ""))[:400] or "model abort",
                ),
                tokens=850,
            )

        corrected_code = str(parsed.get("corrected_code", "") or self.state["execution_code"])
        corrected_payload = str(parsed.get("corrected_payload", "") or self.state["payload"])
        max_runtime_s = int(parsed.get("max_runtime_s", 30) or 30)
        max_runtime_s = max(5, min(max_runtime_s, 120))
        rationale = str(parsed.get("rationale", ""))[:400]

        self.state["pending_action"] = action
        self.state["pending_code"] = corrected_code
        self.state["pending_payload"] = corrected_payload
        self.state["pending_runtime_s"] = max_runtime_s
        self.state["pending_rationale"] = rationale
        self.state["phase"] = "replay"
        return TickOutcome(
            state_delta={
                "pending_action": action, "pending_code": corrected_code,
                "pending_payload": corrected_payload,
                "pending_runtime_s": max_runtime_s,
                "pending_rationale": rationale, "phase": "replay",
            },
            chosen=action,
            reasoning=f"correction proposal: {action} ({rationale[:80]})",
            tokens=800,
        )

    async def _tick_replay(self) -> TickOutcome:
        code = self.state.get("pending_code") or self.state["execution_code"]
        payload = self.state.get("pending_payload") or self.state["payload"]
        runtime_s = int(self.state.get("pending_runtime_s", 30))
        action = self.state.get("pending_action", "unknown")

        forge_params: Dict[str, Any] = {
            "lang": self.state["execution_lang"],
            "code": code,
            "wall_time_s": runtime_s,
            "rationale": (
                f"v7 T159 self-correcting replay: action={action}; "
                f"failure_mode={self.state.get('current_failure_mode')}"
            )[:400],
        }
        if self.state["target_hint"]:
            forge_params["target_hint"] = self.state["target_hint"]
        if self.state["expected_result"]:
            forge_params["oracle"] = json.dumps({"body_must_contain": self.state["expected_result"][:200]})

        try:
            result = await call_mcp_tool("forge_runner", forge_params, timeout=runtime_s + 30.0)
        except Exception as exc:
            logger.warning("self_correcting forge_runner failed: %s", exc)
            return TickOutcome(
                done=True, tokens=20,
                reasoning=f"forge_runner raised: {exc}",
                result=self._build_result("aborted", final_diagnosis=f"forge_runner failed: {exc}"),
            )

        parsed = result.get("parsed") or {}
        oracle_verdict = str(parsed.get("oracle_verdict", "no_oracle"))
        stdout_tail = (parsed.get("stdout") or "")[-1500:]
        stderr_tail = (parsed.get("stderr") or "")[-500:]
        timed_out = bool(parsed.get("timed_out", False))
        exit_code = parsed.get("exit_code")

        evidence = {
            "oracle_verdict": oracle_verdict,
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_ms": parsed.get("duration_ms"),
        }
        self.state["last_evidence"] = evidence

        # Persist to replay_sessions for cross-run analysis (T131 reuse).
        await self._record_replay(action=action, evidence=evidence, payload=payload)

        # Append the trail entry.
        self.state["iteration_count"] = self.state.get("iteration_count", 0) + 1
        self.state["trail"].append({
            "iteration": self.state["iteration_count"],
            "failure_mode": self.state.get("current_failure_mode"),
            "diagnosis": self.state.get("current_diagnosis"),
            "action": action,
            "rationale": self.state.get("pending_rationale", ""),
            "oracle_verdict": oracle_verdict,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

        if oracle_verdict == "pass" or (oracle_verdict == "no_oracle" and exit_code == 0 and not timed_out):
            # Promote the corrected code/payload as the canonical state.
            self.state["execution_code"] = code
            self.state["payload"] = payload
            return TickOutcome(
                done=True, tokens=20,
                reasoning=f"replay succeeded after {self.state['iteration_count']} correction(s)",
                result=self._build_result("success", final_diagnosis="oracle satisfied"),
            )

        # Failure → set up the next iteration with fresh failure_observed.
        self.state["execution_code"] = code
        self.state["payload"] = payload
        self.state["failure_observed"] = (
            f"oracle_verdict={oracle_verdict}; exit_code={exit_code}; "
            f"timed_out={timed_out}; stdout_tail={stdout_tail[:300]}; "
            f"stderr_tail={stderr_tail[:200]}"
        )
        self.state["phase"] = "classify"
        return TickOutcome(
            state_delta={
                "execution_code": code, "payload": payload,
                "failure_observed": self.state["failure_observed"],
                "iteration_count": self.state["iteration_count"],
                "trail": self.state["trail"],
                "last_evidence": evidence,
                "phase": "classify",
            },
            chosen=oracle_verdict,
            reasoning=f"replay {self.state['iteration_count']} failed ({oracle_verdict}) → re-classify",
            tokens=20,
        )

    async def _record_replay(self, action: str, evidence: Dict[str, Any], payload: str) -> None:
        try:
            collection = get_replay_sessions_collection()
            await collection.insert_one({
                "session_id": self.session_id,
                "loop_id": self.loop_id,
                "cve_id": self.state.get("cve_id") or "",
                "replica_id": self.state.get("replica_id") or "",
                "iteration": self.state.get("iteration_count", 0) + 1,
                "action": action,
                "failure_mode": self.state.get("current_failure_mode"),
                "diagnosis": self.state.get("current_diagnosis"),
                "payload_head": payload[:500],
                "evidence": evidence,
                "ts": datetime.now(timezone.utc),
                "source": "v7_t159_self_correcting",
            })
        except Exception as exc:
            logger.debug("replay_sessions insert failed (non-fatal): %s", exc)

    def _build_result(self, status: str, *, final_diagnosis: str = "") -> Dict[str, Any]:
        return {
            "status": status,
            "iterations": self.state.get("iteration_count", 0),
            "final_payload": self.state.get("payload", ""),
            "final_diagnosis": final_diagnosis or self.state.get("current_diagnosis", ""),
            "trail": self.state.get("trail", []),
            "evidence": self.state.get("last_evidence", {}),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HEURISTIC_HINTS = (
    (re.compile(r"segfault|sigsegv|access violation", re.I), "wrong_offset"),
    (re.compile(r"connection (?:refused|reset)|timeout|timed out", re.I), "transport"),
    (re.compile(r"forbidden|blocked|waf|csp|seccomp|cfi", re.I), "defence"),
    (re.compile(r"address|0x[0-9a-f]{6,}", re.I), "aslr_drift"),
    (re.compile(r"corrupt|chunk|bin|tcache|allocator|heap", re.I), "allocator_state"),
)


def _heuristic_classify(failure: str) -> tuple[str, str]:
    if not failure:
        return "unknown", "no failure observation provided"
    for pattern, mode in _HEURISTIC_HINTS:
        if pattern.search(failure):
            return mode, f"heuristic: matched /{pattern.pattern}/"
    return "unknown", "no heuristic matched"


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
