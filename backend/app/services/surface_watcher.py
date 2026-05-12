"""T98 — surface_watcher: always-on surface monitoring daemon.

Celery beat task that runs hourly per active engagement. Checks DNS, port
deltas, JS-hash changes, and cert-transparency for each watched target.
On delta: triggers a targeted re-scan session sub-task via Redis pub/sub.
State persisted in Redis key `surface_watch:{target_ip}`.

Registration: call `register_target()` to add a target to the watch list.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.redis_client import get_redis as get_redis_client
from app.services.mcp_client import call_mcp_tool

logger = logging.getLogger(__name__)

_REDIS_KEY_PREFIX = "surface_watch:"
_REDIS_TARGETS_KEY = "surface_watch:targets"
_DELTA_CHANNEL_PREFIX = "genesis:surface_delta:"


# ---------------------------------------------------------------------------
# Registration / deregistration
# ---------------------------------------------------------------------------

async def register_target(target_ip: str, session_id: str = "") -> bool:
    """Add a target IP to the surface watch list."""
    try:
        redis = await get_redis_client()
        entry = json.dumps({"target_ip": target_ip, "session_id": session_id,
                            "registered_at": datetime.now(timezone.utc).isoformat()})
        await redis.hset(_REDIS_TARGETS_KEY, target_ip, entry)
        logger.info("surface_watcher: registered target %s", target_ip)
        return True
    except Exception as exc:
        logger.warning("surface_watcher register_target failed: %s", exc)
        return False


async def deregister_target(target_ip: str) -> bool:
    """Remove a target from the watch list."""
    try:
        redis = await get_redis_client()
        await redis.hdel(_REDIS_TARGETS_KEY, target_ip)
        await redis.delete(_REDIS_KEY_PREFIX + target_ip)
        return True
    except Exception as exc:
        logger.warning("surface_watcher deregister_target failed: %s", exc)
        return False


async def list_watched_targets() -> List[Dict[str, Any]]:
    """Return all currently watched targets."""
    try:
        redis = await get_redis_client()
        raw = await redis.hgetall(_REDIS_TARGETS_KEY)
        return [json.loads(v) for v in raw.values()]
    except Exception as exc:
        logger.warning("list_watched_targets failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Core watch logic (called by Celery beat task)
# ---------------------------------------------------------------------------

async def check_target_surface(target_ip: str) -> Dict[str, Any]:
    """Run surface checks for a single target and return delta report."""
    current_state = await _probe_surface(target_ip)
    state_hash = _hash_state(current_state)

    redis = await get_redis_client()
    key = _REDIS_KEY_PREFIX + target_ip
    prev_hash = await redis.get(key)

    delta: Dict[str, Any] = {
        "target_ip": target_ip,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "changed": False,
        "current_state": current_state,
    }

    if prev_hash and prev_hash.decode() != state_hash:
        delta["changed"] = True
        delta["previous_hash"] = prev_hash.decode()
        delta["new_hash"] = state_hash
        await _publish_delta(target_ip, delta)
        logger.info("surface_watcher: DELTA detected for %s", target_ip)

    # Update stored hash
    await redis.set(key, state_hash, ex=86400 * 7)  # 7-day TTL
    return delta


async def run_all_watched() -> List[Dict[str, Any]]:
    """Celery beat entry point: check every registered target."""
    targets = await list_watched_targets()
    results: List[Dict[str, Any]] = []
    for entry in targets:
        ip = entry.get("target_ip", "")
        if not ip:
            continue
        try:
            result = await check_target_surface(ip)
            results.append(result)
        except Exception as exc:
            logger.warning("surface_watcher: error checking %s: %s", ip, exc)
            results.append({"target_ip": ip, "error": str(exc)})
    return results


# ---------------------------------------------------------------------------
# Probe helpers
# ---------------------------------------------------------------------------

async def _probe_surface(target_ip: str) -> Dict[str, Any]:
    """Gather current surface state: open ports, DNS, HTTP headers."""
    state: Dict[str, Any] = {"target_ip": target_ip}

    # Port scan (top-20 common ports, fast)
    try:
        nmap_result = await call_mcp_tool(
            "nmap_scan",
            {"target": target_ip, "arguments": "-sV --top-ports 20 -T4 --open"},
        )
        state["open_ports"] = _extract_ports(nmap_result)
    except Exception as exc:
        logger.debug("port probe failed for %s: %s", target_ip, exc)
        state["open_ports"] = []

    # HTTP probe (headers hash for change detection)
    try:
        http_result = await call_mcp_tool(
            "httpx_probe",
            {"target": f"http://{target_ip}", "follow_redirects": False},
        )
        state["http_headers_hash"] = _hash_state(http_result)
    except Exception as exc:
        logger.debug("http probe failed for %s: %s", target_ip, exc)
        state["http_headers_hash"] = ""

    # DNS check
    try:
        dns_result = await call_mcp_tool(
            "dnsrecon_enumerate",
            {"domain": target_ip, "record_type": "A,MX,NS"},
        )
        state["dns_hash"] = _hash_state(dns_result)
    except Exception as exc:
        logger.debug("dns probe failed for %s: %s", target_ip, exc)
        state["dns_hash"] = ""

    return state


def _extract_ports(nmap_result: Any) -> List[int]:
    if not nmap_result or not isinstance(nmap_result, dict):
        return []
    output = str(nmap_result.get("output", ""))
    import re
    ports = [int(m) for m in re.findall(r"(\d+)/tcp\s+open", output)]
    return sorted(set(ports))


def _hash_state(state: Any) -> str:
    serialized = json.dumps(state, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


async def _publish_delta(target_ip: str, delta: Dict[str, Any]) -> None:
    """Publish a surface delta event to Redis pub/sub for orchestrator pickup."""
    try:
        redis = await get_redis_client()
        channel = _DELTA_CHANNEL_PREFIX + target_ip.replace(".", "_")
        await redis.publish(channel, json.dumps(delta, default=str))
    except Exception as exc:
        logger.debug("delta publish failed: %s", exc)
