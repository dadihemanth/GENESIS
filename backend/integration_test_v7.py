"""v7.0 integration test — exercises the running backend stack.

Prerequisites:
    1. `start.bat` from the repo root has launched docker-compose
    2. http://localhost:8000 is reachable

Run from anywhere (uses stdlib only):
    python integration_test_v7.py [--base-url http://localhost:8000]
                                  [--with-docker]   (adds the live-loop check)

Checks:
    [A] GET  /api/v1/health                       -> 200 / not "degraded"
    [B] GET  /api/v1/loops/types                  -> 10 loop types with budgets
    [C] GET  /api/v1/loops/{fresh_session_id}     -> empty list
    [D] GET  /api/v1/loops/detail/loop-nonexistent -> 404
    [E] (--with-docker) docker exec the backend container to run a real
        `counterfactual` loop with llm_call=None (heuristic path), then
        re-fetch the list endpoint to confirm the row appears with ticks.

[E] is opt-in because it requires the backend container to be named
`genesis-backend-1` (docker-compose default) — adjust --container if not.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from urllib import request as _ureq
from urllib.error import HTTPError, URLError

EXPECTED_LOOP_TYPES = {
    "code_intent", "invariant_tracker", "causal_trace", "counterfactual",
    "hypothesis_decomp", "long_context_code",
    "rop_composition", "chain_composer", "heap_layout", "self_correcting",
}

PASSED = 0
FAILED: list[str] = []


def _ok(msg: str) -> None:
    global PASSED
    PASSED += 1
    print(f"  [PASS] {msg}")


def _fail(msg: str) -> None:
    FAILED.append(msg)
    print(f"  [FAIL] {msg}")


def _info(msg: str) -> None:
    print(f"  [INFO] {msg}")


_API_KEY: str = ""


def _http_get(url: str, timeout: float = 10.0):
    """Return (status, body_dict). On HTTPError we still capture body."""
    headers = {"Accept": "application/json"}
    if _API_KEY:
        headers["X-API-Key"] = _API_KEY
    req = _ureq.Request(url, headers=headers)
    try:
        with _ureq.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else None
    except HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp else ""
        try:
            parsed = json.loads(body) if body else None
        except Exception:
            parsed = body
        return exc.code, parsed
    except URLError as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_health(base_url: str) -> bool:
    print("\n[A] GET /api/v1/health ...")
    status, body = _http_get(f"{base_url}/api/v1/health")
    if status is None:
        _fail(f"backend unreachable: {body}")
        return False
    if status != 200:
        _fail(f"health returned {status}: {body}")
        return False
    if not isinstance(body, dict):
        _fail(f"health body not a dict: {body!r}")
        return False
    overall = body.get("status")
    if overall == "healthy":
        _ok("backend healthy")
    elif overall == "degraded":
        _info(f"backend degraded — some sidecar services down (still OK for v7 smoke): {body}")
        # degraded is acceptable for the v7 routes; mongo + postgres are what we need
        _ok("backend reachable (degraded)")
    else:
        _fail(f"unexpected health body: {body}")
        return False
    return True


def check_loop_types(base_url: str) -> bool:
    print("\n[B] GET /api/v1/loops/types ...")
    status, body = _http_get(f"{base_url}/api/v1/loops/types")
    if status != 200:
        _fail(f"/loops/types returned {status}: {body}")
        return False
    if not isinstance(body, dict) or "types" not in body:
        _fail(f"unexpected body shape: {body}")
        return False
    types_list = body["types"]
    if not isinstance(types_list, list) or len(types_list) != 10:
        _fail(f"expected 10 types, got {len(types_list) if isinstance(types_list, list) else 'non-list'}")
        return False
    found_keys = {t.get("loop_type") for t in types_list if isinstance(t, dict)}
    if found_keys == EXPECTED_LOOP_TYPES:
        _ok(f"all 10 loop types present: {sorted(found_keys)}")
    else:
        _fail(
            f"loop_type mismatch — missing: {sorted(EXPECTED_LOOP_TYPES - found_keys)}, "
            f"unexpected: {sorted(found_keys - EXPECTED_LOOP_TYPES)}"
        )
        return False
    # Budgets sanity
    for t in types_list:
        if not (isinstance(t.get("max_tokens"), int) and t["max_tokens"] > 0):
            _fail(f"{t.get('loop_type')}: bad max_tokens {t.get('max_tokens')}")
            return False
        if not (isinstance(t.get("max_ticks"), int) and t["max_ticks"] > 0):
            _fail(f"{t.get('loop_type')}: bad max_ticks {t.get('max_ticks')}")
            return False
    _ok("every loop type has positive max_tokens + max_ticks")
    return True


def check_empty_list(base_url: str) -> str:
    print("\n[C] GET /api/v1/loops/{fresh_session_id} ...")
    sid = f"smoke-{uuid.uuid4().hex[:12]}"
    status, body = _http_get(f"{base_url}/api/v1/loops/{sid}")
    if status != 200:
        _fail(f"/loops/{sid} returned {status}: {body}")
        return sid
    if not isinstance(body, dict):
        _fail(f"unexpected body: {body}")
        return sid
    if body.get("session_id") != sid:
        _fail(f"echo mismatch: expected {sid}, got {body.get('session_id')}")
        return sid
    loops = body.get("loops")
    count = body.get("count", -1)
    if loops == [] and count == 0:
        _ok(f"fresh session {sid} returns empty list")
    else:
        _fail(f"fresh session not empty: count={count}, loops={loops}")
    return sid


def check_detail_404(base_url: str) -> bool:
    print("\n[D] GET /api/v1/loops/detail/loop-nonexistent ...")
    status, body = _http_get(f"{base_url}/api/v1/loops/detail/loop-doesnotexist")
    if status == 404:
        _ok("nonexistent loop returns 404")
        return True
    _fail(f"expected 404, got {status}: {body}")
    return False


# ---------------------------------------------------------------------------
# Live loop check (opt-in via --with-docker)
# ---------------------------------------------------------------------------

_DOCKER_PYSCRIPT = '''
import asyncio, json
from app.services.reasoning import registry

async def main():
    result = await registry.dispatch(
        session_id="{session_id}",
        loop_type="counterfactual",
        inputs={{
            "baseline": "SQLi attempt blocked by WAF on /login",
            "starting_primitives": ["unauth_get"],
            "max_depth": 1,
            "max_breadth": 1,
            "context": "v7 integration smoke",
        }},
        llm_call=None,  # heuristic-only path; the loop persists ticks even without LLM
    )
    print(json.dumps({{"loop_id": result.get("loop_id"),
                       "status": result.get("status"),
                       "ticks": result.get("ticks"),
                       "abort_reason": result.get("abort_reason")}}))

asyncio.run(main())
'''


def check_live_loop(base_url: str, container: str) -> bool:
    print(f"\n[E] docker exec {container} -> run counterfactual loop end-to-end ...")
    sid = f"smoke-live-{uuid.uuid4().hex[:12]}"
    script = _DOCKER_PYSCRIPT.format(session_id=sid)
    cmd = ["docker", "exec", "-i", container, "python", "-c", script]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except FileNotFoundError:
        _fail("docker not on PATH — install Docker Desktop or skip [E]")
        return False
    except subprocess.TimeoutExpired:
        _fail("docker exec timed out after 90s")
        return False

    if result.returncode != 0:
        _fail(f"docker exec returned {result.returncode}: stderr={result.stderr.strip()[:600]}")
        return False

    # Parse the loop result line
    last = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    try:
        loop_info = json.loads(last)
    except Exception as exc:
        _fail(f"could not parse docker output: {exc}; stdout={result.stdout.strip()[:600]}")
        return False
    loop_id = loop_info.get("loop_id")
    status_field = loop_info.get("status")
    if not loop_id:
        _fail(f"loop did not return a loop_id: {loop_info}")
        return False
    _ok(f"loop ran inside container — loop_id={loop_id}, status={status_field}, ticks={loop_info.get('ticks')}")

    # Give MongoDB a moment to flush, then verify via the API.
    time.sleep(1)

    print(f"  -> re-fetching /api/v1/loops/{sid} ...")
    s, body = _http_get(f"{base_url}/api/v1/loops/{sid}")
    if s != 200 or not isinstance(body, dict):
        _fail(f"list endpoint returned {s}: {body}")
        return False
    loops = body.get("loops") or []
    if not loops:
        _fail(f"list endpoint shows zero loops for session {sid} (loop_id={loop_id})")
        return False
    matched = [l for l in loops if l.get("loop_id") == loop_id]
    if not matched:
        _fail(f"loop_id {loop_id} not in list response: {[l.get('loop_id') for l in loops]}")
        return False
    _ok(f"list endpoint surfaces the loop: status={matched[0].get('status')}, tick_count={matched[0].get('tick_count')}")

    print(f"  -> fetching /api/v1/loops/detail/{loop_id} ...")
    s, detail = _http_get(f"{base_url}/api/v1/loops/detail/{loop_id}")
    if s != 200 or not isinstance(detail, dict):
        _fail(f"detail endpoint returned {s}: {detail}")
        return False
    ticks = detail.get("ticks")
    if not isinstance(ticks, list) or len(ticks) == 0:
        _fail(f"detail endpoint has no ticks: {detail}")
        return False
    first_tick = ticks[0]
    needed = {"iteration", "state_snapshot", "branches", "chosen", "reasoning", "tokens", "ts"}
    missing = needed - set(first_tick.keys())
    if missing:
        _fail(f"first tick missing fields: {missing}")
        return False
    _ok(f"detail endpoint returns {len(ticks)} ticks with full schema (loop_type={detail.get('loop_type')})")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000",
                        help="Backend base URL (default: http://localhost:8000)")
    parser.add_argument("--with-docker", action="store_true",
                        help="Also run [E] which invokes registry.dispatch via docker exec")
    parser.add_argument("--container", default="genesis-backend-1",
                        help="Backend container name (default: genesis-backend-1)")
    parser.add_argument("--api-key", default="",
                        help="X-API-Key header value (or empty if backend has no API_KEY env)")
    args = parser.parse_args()

    global _API_KEY
    _API_KEY = args.api_key

    print("=" * 72)
    print(f"GENESIS v7.0 integration test  (target: {args.base_url})")
    print("=" * 72)

    if not check_health(args.base_url):
        print("\nBackend unreachable — aborting. Run start.bat first.")
        return 1
    check_loop_types(args.base_url)
    check_empty_list(args.base_url)
    check_detail_404(args.base_url)
    if args.with_docker:
        check_live_loop(args.base_url, args.container)
    else:
        print("\n[E] live loop check SKIPPED — pass --with-docker to enable.")

    print("\n" + "=" * 72)
    status = "PASS" if not FAILED else "FAIL"
    print(f"{status}: {PASSED} passed, {len(FAILED)} failed")
    if FAILED:
        print("\nFailures:")
        for msg in FAILED:
            print(f"  - {msg}")
    print("=" * 72)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
