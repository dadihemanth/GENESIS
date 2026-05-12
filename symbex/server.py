"""
GENESIS symbex · Tier-3 T10 — angr reachability / constraint solver API.

POST /reachability
    {
      "binary_path": "/data/security/artifacts/<session>/<name>",
      "find_addr": "0x401234",         # integer or hex string
      "avoid_addrs": ["0x401100", ...],  # optional
      "start_addr": "0x401000",          # optional; default = entry point
      "stdin_len": 64,                   # symbolic stdin length bound
      "argv_symbolic_lens": [0, 16],     # per-argv symbolic byte bound (0 = concrete "")
      "wall_time_s": 90                  # hard-capped
    }

Returns:
    {
      "ok": true,
      "reached": true|false,
      "stdin_input_b64": "...",          # present if reached and stdin symbolic
      "argv_inputs": [ "...", "..." ],   # present if reached
      "explored_states": 123,
      "duration_seconds": 4.5,
      "note": "free-form status"
    }

Never decompiles, never fuzzes — this is pure constraint solving over a
bounded path space, intended to pair with T4 (decompile) for function-level
questions the AI wants a definite yes/no on.
"""

from __future__ import annotations

import base64
import logging
import os
import signal
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request
from waitress import serve

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("symbex")

ARTIFACT_ROOT = Path(os.environ.get("ARTIFACT_ROOT", "/data/security/artifacts")).resolve()
MAX_WALL_S = 180
DEFAULT_WALL_S = 60

app = Flask(__name__)


def _resolve_binary(p: str) -> Path:
    candidate = Path(p).resolve()
    try:
        candidate.relative_to(ARTIFACT_ROOT)
    except ValueError as exc:
        raise PermissionError(f"binary_path must live under {ARTIFACT_ROOT}") from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"binary not found: {candidate}")
    return candidate


def _parse_addr(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


class _Timeout(Exception):
    pass


@contextmanager
def _wall_clock(seconds: int):
    """SIGALRM-based wall-clock guard. Linux only — fine inside the container."""
    def _handler(_signum, _frame):
        raise _Timeout("symbolic exploration timed out")

    prev = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prev)


def _run_reachability(body: Dict[str, Any]) -> Dict[str, Any]:
    # Heavy imports inside the handler so /health is fast and the container
    # starts even when angr isn't immediately useful.
    import angr  # type: ignore
    import claripy  # type: ignore

    binary = _resolve_binary(str(body.get("binary_path") or ""))
    find_addr = _parse_addr(body.get("find_addr"))
    if find_addr is None:
        raise ValueError("find_addr required (int or '0x...')")

    avoid_raw = body.get("avoid_addrs") or []
    avoid_addrs: List[int] = []
    if isinstance(avoid_raw, list):
        for x in avoid_raw[:32]:
            a = _parse_addr(x)
            if a is not None:
                avoid_addrs.append(a)

    start_addr = _parse_addr(body.get("start_addr"))
    stdin_len = max(0, min(1024, int(body.get("stdin_len") or 0)))
    argv_lens_raw = body.get("argv_symbolic_lens") or []
    argv_lens: List[int] = []
    if isinstance(argv_lens_raw, list):
        for v in argv_lens_raw[:8]:
            try:
                argv_lens.append(max(0, min(256, int(v))))
            except (TypeError, ValueError):
                argv_lens.append(0)

    try:
        wall = int(body.get("wall_time_s") or DEFAULT_WALL_S)
    except (TypeError, ValueError):
        wall = DEFAULT_WALL_S
    wall = max(5, min(MAX_WALL_S, wall))

    proj = angr.Project(binary.as_posix(), auto_load_libs=False)

    # Build argv — symbolic bytes where requested, concrete empty where 0.
    argv: List[Any] = [binary.name.encode()]
    for n in argv_lens:
        if n <= 0:
            continue
        argv.append(claripy.BVS(f"argv{len(argv)}", n * 8))

    # Optional symbolic stdin.
    stdin_sym = None
    if stdin_len > 0:
        stdin_sym = claripy.BVS("stdin_bytes", stdin_len * 8)

    state_kwargs: Dict[str, Any] = {}
    if argv_lens:
        state_kwargs["args"] = argv
    if stdin_sym is not None:
        state_kwargs["stdin"] = stdin_sym

    if start_addr is not None:
        state = proj.factory.blank_state(addr=start_addr, **state_kwargs)
    else:
        state = proj.factory.entry_state(**state_kwargs)

    simgr = proj.factory.simulation_manager(state)
    start = time.monotonic()
    reached = False
    found_state = None
    explored = 0

    try:
        with _wall_clock(wall):
            while True:
                simgr.explore(find=find_addr, avoid=avoid_addrs, num_find=1)
                explored = len(simgr.deadended) + len(simgr.active) + len(simgr.found)
                if simgr.found:
                    reached = True
                    found_state = simgr.found[0]
                    break
                if not simgr.active:
                    break
    except _Timeout:
        log.info("symbex timed out after %ds on %s find=%s", wall, binary, hex(find_addr))
    except Exception as exc:  # noqa: BLE001 — angr raises a wide range
        log.exception("symbex run failed")
        return {
            "ok": False,
            "error": f"symbolic exploration failed: {exc}",
            "binary": str(binary),
        }

    duration = round(time.monotonic() - start, 2)

    out: Dict[str, Any] = {
        "ok": True,
        "reached": reached,
        "explored_states": explored,
        "duration_seconds": duration,
        "binary": str(binary),
        "find_addr": hex(find_addr),
        "avoid_count": len(avoid_addrs),
    }

    if reached and found_state is not None:
        if stdin_sym is not None:
            try:
                concrete_stdin = found_state.solver.eval(stdin_sym, cast_to=bytes)
                out["stdin_input_b64"] = base64.b64encode(concrete_stdin).decode()
                out["stdin_length"] = len(concrete_stdin)
            except Exception as exc:
                out["stdin_solve_error"] = str(exc)
        if argv_lens:
            concrete_argv: List[str] = []
            for a in argv[1:]:
                try:
                    raw = found_state.solver.eval(a, cast_to=bytes)
                    concrete_argv.append(base64.b64encode(raw).decode())
                except Exception as exc:
                    concrete_argv.append(f"solve_error: {exc}")
            out["argv_inputs_b64"] = concrete_argv
        out["note"] = f"target reached after exploring {explored} states in {duration}s"
    elif not reached and explored:
        out["note"] = f"no path found after exploring {explored} states in {duration}s (wall={wall}s)"
    else:
        out["note"] = "symbolic exploration exhausted without reaching target"

    return out


@app.get("/health")
def health() -> Any:
    return jsonify({"ok": True, "service": "symbex", "engine": "angr"})


@app.post("/reachability")
def reachability() -> Any:
    body = request.get_json(force=True, silent=True) or {}
    try:
        result = _run_reachability(body)
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        log.exception("/reachability failed")
        return jsonify({"ok": False, "error": f"internal error: {exc}"}), 500
    status = 200 if result.get("ok") else 500
    return jsonify(result), status


if __name__ == "__main__":
    log.info("symbex listening on 0.0.0.0:3501 · artifact_root=%s", ARTIFACT_ROOT)
    serve(app, host="0.0.0.0", port=3501, threads=1)
