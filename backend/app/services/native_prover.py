"""validation milestone 6 — native_prover: ASan/sanitizer-based dynamic prove stage.

For C/C++ (and Rust/Go) memory-safety bugs, the prove stage constructs and
executes triggering inputs against an AddressSanitizer-instrumented binary.
This is what separates "candidate finding" from "confirmed memory-safety bug"
for the reveng and exploitdev agents.

Native sanitizer-based proof is what lets memory-safety candidates become
confirmed findings: the sanitizer report is the proof.

Workflow:
  1. exploitdev/reveng agent emits a NATIVE_PROVE_REQUEST JSON block:
     {"NATIVE_PROVE_REQUEST": {
         "binary_path": "/path/to/target",
         "poc_input": "<hex or base64 or string>",
         "expected_signal": "heap-use-after-free|stack-overflow|double-free|...",
         "candidate_id": "<candidate_id>",
         "compile_flags": ["-fsanitize=address", "-O1"]
     }}
  2. native_prover.prove() spawns an ASan replica, executes the PoC,
     parses the sanitizer report.
  3. If the sanitizer report matches expected_signal → confirmed.
     Calls validated_scanner.record_proof_run(passed=True) with the full
     sanitizer report as verification_output.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.services.replica_manager_client import (
    execute_on_replica,
    spawn_asan_replica,
    teardown_replica,
)

logger = logging.getLogger(__name__)

# Known sanitizer signals and their canonical labels
_ASAN_SIGNALS: List[tuple] = [
    (re.compile(r"heap-use-after-free",       re.I), "heap-use-after-free"),
    (re.compile(r"heap-buffer-overflow",      re.I), "heap-buffer-overflow"),
    (re.compile(r"stack-buffer-overflow",     re.I), "stack-buffer-overflow"),
    (re.compile(r"stack-use-after-return",    re.I), "stack-use-after-return"),
    (re.compile(r"double-free",               re.I), "double-free"),
    (re.compile(r"use-after-poison",          re.I), "use-after-poison"),
    (re.compile(r"attempting double-free",    re.I), "double-free"),
    (re.compile(r"SEGV",                      re.I), "segfault"),
    (re.compile(r"runtime error:.*overflow",  re.I), "integer-overflow"),
    (re.compile(r"AddressSanitizer",          re.I), "asan-generic"),
]

_MSAN_SIGNALS: List[tuple] = [
    (re.compile(r"MemorySanitizer.*use.*uninitialized", re.I), "uninitialized-memory"),
    (re.compile(r"MemorySanitizer",                     re.I), "msan-generic"),
]

_UBSAN_SIGNALS: List[tuple] = [
    (re.compile(r"signed integer overflow", re.I), "signed-integer-overflow"),
    (re.compile(r"null pointer dereference", re.I), "null-deref"),
    (re.compile(r"undefined behavior",       re.I), "ubsan-generic"),
]

_ALL_SIGNALS = _ASAN_SIGNALS + _MSAN_SIGNALS + _UBSAN_SIGNALS


def _detect_sanitizer_signal(stderr: str) -> Optional[str]:
    """Return the first sanitizer signal found in stderr output, or None."""
    for pattern, label in _ALL_SIGNALS:
        if pattern.search(stderr):
            return label
    return None


def _extract_asan_summary(stderr: str, max_chars: int = 3000) -> str:
    """Extract the most relevant ASan report lines."""
    lines = stderr.splitlines()
    summary_lines: List[str] = []
    in_report = False
    for line in lines:
        if "ERROR: AddressSanitizer" in line or "ERROR: MemorySanitizer" in line:
            in_report = True
        if in_report:
            summary_lines.append(line)
            if len("\n".join(summary_lines)) > max_chars:
                break
    return "\n".join(summary_lines) if summary_lines else stderr[:max_chars]


async def prove(
    session_id: str,
    candidate_id: str,
    binary_path: str,
    poc_input: str,
    expected_signal: str = "",
    compile_flags: Optional[List[str]] = None,
    poc_args: Optional[List[str]] = None,
    stdin: bool = True,
) -> Dict[str, Any]:
    """Run the native prove stage for a memory-safety candidate.

    Steps:
      1. Spawn ASan-instrumented replica of binary_path.
      2. Execute poc_input against it.
      3. Parse sanitizer output.
      4. Call record_proof_run() with the result.

    Returns a result dict:
      {
        "passed": bool,
        "signal_detected": str|None,
        "expected_signal": str,
        "signal_matched": bool,
        "asan_summary": str,
        "replica_id": str|None,
        "error": str|None,
      }
    """
    result: Dict[str, Any] = {
        "passed": False,
        "signal_detected": None,
        "expected_signal": expected_signal,
        "signal_matched": False,
        "asan_summary": "",
        "replica_id": None,
        "error": None,
    }

    # Step 1: spawn ASan replica
    replica = await spawn_asan_replica(
        binary_path=binary_path,
        compile_flags=compile_flags,
    )
    if not replica or not replica.get("replica_id"):
        result["error"] = "replica spawn failed"
        logger.warning("native_prover: replica spawn failed for %s", binary_path)
        await _record(session_id, candidate_id, result)
        return result

    replica_id = replica["replica_id"]
    result["replica_id"] = replica_id

    try:
        # Step 2: execute PoC
        exec_result = await execute_on_replica(
            replica_id=replica_id,
            poc_input=poc_input,
            stdin=stdin,
            args=poc_args,
        )
        if exec_result is None:
            result["error"] = "execution failed (replica error)"
            await _record(session_id, candidate_id, result)
            return result

        stderr = exec_result.get("stderr", "") or ""
        crashed = bool(exec_result.get("crashed", False)) or exec_result.get("exit_code", 0) != 0

        # Step 3: parse sanitizer signal
        signal = _detect_sanitizer_signal(stderr)
        result["signal_detected"] = signal
        result["asan_summary"] = _extract_asan_summary(stderr)

        if signal:
            if expected_signal:
                # Check if the detected signal matches or is a subtype
                result["signal_matched"] = (
                    expected_signal.lower() in signal.lower()
                    or signal.lower() in expected_signal.lower()
                    or "asan-generic" in signal  # partial match
                )
                result["passed"] = result["signal_matched"]
            else:
                # No expected signal specified — any sanitizer hit = confirmed
                result["passed"] = True
                result["signal_matched"] = True
        elif crashed:
            # Binary crashed without a sanitizer report — weaker signal
            result["passed"] = False
            result["asan_summary"] = f"Crash detected (exit_code={exec_result.get('exit_code')})"

        logger.info(
            "native_prover: session=%s candidate=%s signal=%s expected=%s passed=%s",
            session_id, candidate_id, signal, expected_signal, result["passed"],
        )
    except Exception as exc:
        result["error"] = str(exc)[:500]
        logger.warning("native_prover: execution error for candidate %s: %s", candidate_id, exc)
    finally:
        await teardown_replica(replica_id)

    await _record(session_id, candidate_id, result)
    return result


async def process_native_prove_requests(
    session_id: str,
    text: str,
) -> int:
    """Extract and process all NATIVE_PROVE_REQUEST blocks from agent output.

    Called from the orchestrator when exploitdev/reveng agents emit their output.
    Returns the number of prove runs dispatched.
    """
    import json as _json
    import re as _re

    pattern = re.compile(r'"NATIVE_PROVE_REQUEST"\s*:', re.I)
    requests_run = 0
    pos = 0
    while True:
        match = pattern.search(text, pos)
        if not match:
            break
        # Find the enclosing JSON object
        start = text.rfind("{", 0, match.start())
        if start == -1:
            pos = match.end()
            continue
        depth = 0
        i = start
        end = -1
        for i, ch in enumerate(text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end == -1:
            pos = match.end()
            continue
        try:
            outer = _json.loads(text[start:end + 1])
            req = outer.get("NATIVE_PROVE_REQUEST") or {}
        except Exception:
            pos = match.end()
            continue
        pos = end + 1

        binary_path = str(req.get("binary_path") or "")
        poc_input = str(req.get("poc_input") or "")
        candidate_id = str(req.get("candidate_id") or "")
        if not binary_path or not poc_input or not candidate_id:
            continue

        await prove(
            session_id=session_id,
            candidate_id=candidate_id,
            binary_path=binary_path,
            poc_input=poc_input,
            expected_signal=str(req.get("expected_signal") or ""),
            compile_flags=req.get("compile_flags"),
            poc_args=req.get("args"),
            stdin=bool(req.get("stdin", True)),
        )
        requests_run += 1

    return requests_run


async def _record(session_id: str, candidate_id: str, result: Dict[str, Any]) -> None:
    """Persist the prove result to validated_scanner."""
    if not candidate_id:
        return
    try:
        from app.services.validated_scanner import record_proof_run
        await record_proof_run(
            session_id=session_id,
            candidate_id=candidate_id,
            proof_tool="native_asan_prover",
            oracle={"expected_signal": result.get("expected_signal", "")},
            inputs={"poc_input_length": len(result.get("asan_summary", ""))},
            result=result,
            artifacts=[],
            passed=result.get("passed", False),
            pass_fail_reason=(
                f"ASan signal: {result.get('signal_detected') or 'none'} "
                f"(expected: {result.get('expected_signal') or 'any'})"
            ),
        )
    except Exception as exc:
        logger.warning("native_prover: record_proof_run failed: %s", exc)
