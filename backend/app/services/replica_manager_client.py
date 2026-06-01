"""Replica manager HTTP client — T122.

Talks to the replica-manager sidecar service (port 3701) to spawn and
manage OSS replicas of the target based on T121 behavioral fingerprints.

The replica gives the orchestrator a safe environment to run destructive
payloads (T94 destructive_test_harness class) without touching production.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

REPLICA_MANAGER_URL = os.getenv("REPLICA_MANAGER_URL", "http://replica_manager:3701")
_TIMEOUT = 60.0  # spawn can take up to 60s pulling images


async def spawn_replica(
    stack_pin: str,
    observed_routes: Optional[list] = None,
    target_ip: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Optional[dict]:
    """Spawn an OSS replica matching stack_pin.

    Returns {"replica_id": str, "base_url": str, "status": "ready"|"building"} or None on failure.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{REPLICA_MANAGER_URL}/spawn",
                json={
                    "stack_pin": stack_pin,
                    "observed_routes": observed_routes or [],
                    "target_ip": target_ip or "",
                    "session_id": session_id or "",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("replica_spawner: spawned %s → %s", data.get("replica_id"), data.get("base_url"))
            return data
    except Exception as exc:
        logger.warning("replica_manager_client.spawn_replica failed: %s", exc)
        return None


async def teardown_replica(replica_id: str) -> bool:
    """Teardown a replica by ID. Returns True on success."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.delete(f"{REPLICA_MANAGER_URL}/replicas/{replica_id}")
            resp.raise_for_status()
            return True
    except Exception as exc:
        logger.warning("replica_manager_client.teardown_replica failed for %s: %s", replica_id, exc)
        return False


async def list_replicas() -> list:
    """List all active replicas."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{REPLICA_MANAGER_URL}/replicas")
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.debug("replica_manager_client.list_replicas failed: %s", exc)
        return []


async def spawn_asan_replica(
    binary_path: str,
    compile_flags: Optional[list] = None,
    env_vars: Optional[dict] = None,
) -> Optional[dict]:
    """validation milestone 6 — spawn a replica instrumented with AddressSanitizer.

    Asks the replica manager to build the target binary with
    -fsanitize=address (ASan) and return a handle for executing PoC inputs.

    Returns:
      {"replica_id": str, "binary_path": str, "status": "ready"|"building",
       "sanitizer": "asan"} or None on failure.
    """
    flags = compile_flags or ["-fsanitize=address", "-g", "-O1"]
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{REPLICA_MANAGER_URL}/spawn_native",
                json={
                    "binary_path": binary_path,
                    "compile_flags": flags,
                    "sanitizer": "asan",
                    "env": env_vars or {"ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1"},
                },
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info(
                "replica_manager: ASan replica spawned for %s → %s",
                binary_path, data.get("replica_id"),
            )
            return data
    except Exception as exc:
        logger.warning("replica_manager_client.spawn_asan_replica failed: %s", exc)
        return None


async def execute_on_replica(
    replica_id: str,
    poc_input: str,
    stdin: bool = True,
    args: Optional[list] = None,
    timeout: float = 30.0,
) -> Optional[dict]:
    """Execute a PoC input on a native replica and return sanitizer output.

    Returns:
      {"exit_code": int, "stdout": str, "stderr": str, "asan_report": str,
       "crashed": bool} or None on failure.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout + 10.0) as client:
            resp = await client.post(
                f"{REPLICA_MANAGER_URL}/replicas/{replica_id}/execute",
                json={
                    "stdin": poc_input if stdin else "",
                    "args": args or [],
                    "timeout": timeout,
                },
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning(
            "replica_manager_client.execute_on_replica %s failed: %s", replica_id, exc,
        )
        return None


async def get_replica_url(session_id: str, stack_pin: str, observed_routes: Optional[list] = None) -> Optional[str]:
    """Convenience: spawn a replica and return its base_url. Returns None if unavailable."""
    result = await spawn_replica(stack_pin, observed_routes, session_id=session_id)
    if result and result.get("base_url"):
        # Store replica_id in session MongoDB doc for later teardown
        try:
            from app.database.mongodb import _get_db
            db = _get_db()
            await db["agent_thoughts"].update_one(
                {"session_id": session_id, "_type": "replica_info"},
                {"$set": {"replica_id": result["replica_id"], "base_url": result["base_url"]}},
                upsert=True,
            )
        except Exception:
            pass
        return result["base_url"]
    return None
