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


async def get_replica_url(session_id: str, stack_pin: str, observed_routes: Optional[list] = None) -> Optional[str]:
    """Convenience: spawn a replica and return its base_url. Returns None if unavailable."""
    result = await spawn_replica(stack_pin, observed_routes)
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
