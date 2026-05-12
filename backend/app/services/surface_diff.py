"""T104 — surface_diff: delta-aware attack surface view.

Compares the current session's discovered endpoints / services against Neo4j
historical records for the same target.

Returns a structured diff:
  - new_endpoints: appeared since last scan (potential new attack surface)
  - removed_endpoints: disappeared since last scan (bug magnets — old code not
    cleaned up, often contains known-vulnerable versions)
  - new_ports: newly open ports
  - closed_ports: ports that closed

Injected into the session context so the orchestrator knows where to focus.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.database.neo4j_client import get_neo4j_driver

logger = logging.getLogger(__name__)


async def compute_surface_diff(
    session_id: str,
    target_ip: str,
    current_endpoints: List[str],
    current_ports: List[int],
) -> Dict[str, Any]:
    """Diff current session surface against Neo4j historical state for target_ip.

    Args:
        session_id: Current session ID (used to identify prior sessions).
        target_ip: Target being scanned.
        current_endpoints: List of HTTP endpoints discovered in this session.
        current_ports: List of open ports found in this session.

    Returns:
        diff dict with new/removed endpoints and ports.
    """
    historical = await _get_historical_surface(target_ip, exclude_session=session_id)
    if not historical:
        # No prior data — store current state and return empty diff
        await _store_current_surface(session_id, target_ip, current_endpoints, current_ports)
        return {
            "target_ip": target_ip,
            "session_id": session_id,
            "new_endpoints": [],
            "removed_endpoints": [],
            "new_ports": [],
            "closed_ports": [],
            "first_scan": True,
        }

    hist_endpoints = set(historical.get("endpoints", []))
    hist_ports = set(historical.get("ports", []))
    curr_endpoints = set(current_endpoints)
    curr_ports = set(current_ports)

    diff = {
        "target_ip": target_ip,
        "session_id": session_id,
        "new_endpoints": sorted(curr_endpoints - hist_endpoints),
        "removed_endpoints": sorted(hist_endpoints - curr_endpoints),
        "new_ports": sorted(curr_ports - hist_ports),
        "closed_ports": sorted(hist_ports - curr_ports),
        "first_scan": False,
        "previous_session": historical.get("session_id", ""),
    }

    if diff["new_endpoints"] or diff["removed_endpoints"]:
        logger.info(
            "surface_diff: %s new=%d removed=%d",
            target_ip, len(diff["new_endpoints"]), len(diff["removed_endpoints"]),
        )

    # Persist current surface for future diff comparisons
    await _store_current_surface(session_id, target_ip, current_endpoints, current_ports)
    return diff


def format_for_context(diff: Dict[str, Any]) -> str:
    """Format a diff dict as a compact string for LLM context injection."""
    if diff.get("first_scan"):
        return ""
    parts: List[str] = []
    if diff.get("new_endpoints"):
        parts.append("NEW endpoints since last scan (prioritize these):\n" +
                     "\n".join(f"  + {e}" for e in diff["new_endpoints"][:10]))
    if diff.get("removed_endpoints"):
        parts.append("REMOVED endpoints (bug magnets — old code, often vulnerable):\n" +
                     "\n".join(f"  - {e}" for e in diff["removed_endpoints"][:5]))
    if diff.get("new_ports"):
        parts.append("NEW open ports: " + ", ".join(str(p) for p in diff["new_ports"]))
    if not parts:
        return ""
    return "## Surface Delta (T104)\n" + "\n".join(parts)


# ---------------------------------------------------------------------------
# Neo4j helpers
# ---------------------------------------------------------------------------

async def _get_historical_surface(
    target_ip: str,
    exclude_session: str,
) -> Optional[Dict[str, Any]]:
    """Query Neo4j for the most recent surface snapshot of target_ip."""
    driver = await get_neo4j_driver()
    if driver is None:
        return None
    try:
        async with driver.session() as session:
            result = await session.run(
                """
                MATCH (t:Target {ip: $target_ip})-[:ON_TARGET]-(h:Host)
                MATCH (h)-[:LISTENS_ON]->(s:Service)
                OPTIONAL MATCH (s)<-[:AFFECTS]-(f:Finding)
                WHERE f.session_id <> $exclude_session
                RETURN
                  collect(DISTINCT s.port) AS ports,
                  collect(DISTINCT s.endpoint) AS endpoints,
                  t.last_session AS session_id
                LIMIT 1
                """,
                target_ip=target_ip,
                exclude_session=exclude_session,
            )
            record = await result.single()
            if record:
                return {
                    "ports": [p for p in (record.get("ports") or []) if p],
                    "endpoints": [e for e in (record.get("endpoints") or []) if e],
                    "session_id": record.get("session_id", ""),
                }
    except Exception as exc:
        logger.debug("_get_historical_surface failed: %s", exc)
    return None


async def _store_current_surface(
    session_id: str,
    target_ip: str,
    endpoints: List[str],
    ports: List[int],
) -> None:
    """Update Neo4j Target node with current surface state."""
    driver = await get_neo4j_driver()
    if driver is None:
        return
    try:
        async with driver.session() as neo4j_session:
            await neo4j_session.run(
                """
                MERGE (t:Target {ip: $target_ip})
                SET t.last_session = $session_id,
                    t.last_endpoints = $endpoints,
                    t.last_ports = $ports
                """,
                target_ip=target_ip,
                session_id=session_id,
                endpoints=endpoints[:50],
                ports=ports[:50],
            )
    except Exception as exc:
        logger.debug("_store_current_surface failed: %s", exc)
