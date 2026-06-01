"""T130 — CVE Variant Matcher.

Compares active Neo4j service nodes against threat_intel_entries.
Fuzzy-matches service names/versions to CVE affected_components.
Stores matches back into threat_intel_entries.matched_targets.

T131 — Sameday Replay.

When a CVE has a poc_url, spawns a T122 replica at the affected version
and runs the PoC via forge_runner to verify exploitability before probing
the production target.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _normalise(s: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    return re.sub(r"[^a-z0-9./]", " ", s.lower()).strip()


def _component_match(service_name: str, service_version: str, affected_components: List[str]) -> float:
    """Return a confidence score 0–1 for service matching affected_components."""
    sn = _normalise(service_name)
    sv = _normalise(service_version)
    best = 0.0
    for comp in affected_components:
        cn = _normalise(comp)
        parts = cn.split("/", 1)
        cname = parts[0].strip()
        cver = parts[1].strip() if len(parts) > 1 else ""
        name_match = any(token in sn or token in cname for token in sn.split() if len(token) > 2)
        if not name_match and sn not in cname and cname not in sn:
            continue
        if not sv or not cver:
            best = max(best, 0.5)
            continue
        # Version prefix match: "1.18" matches "1.18.0", "1.18.2", etc.
        if sv.startswith(cver) or cver.startswith(sv):
            best = max(best, 0.9)
        elif sv.split(".")[0] == cver.split(".")[0]:
            best = max(best, 0.6)
        else:
            best = max(best, 0.4)
    return best


async def _get_active_services() -> List[Dict[str, Any]]:
    """Query Neo4j for all :Service nodes with version info."""
    from app.database.neo4j_client import get_neo4j_session

    services: List[Dict[str, Any]] = []
    query = "MATCH (s:Service) WHERE s.name IS NOT NULL RETURN s.name AS name, s.version AS version, s.host AS host LIMIT 500"
    try:
        async with get_neo4j_session() as session:
            result = await session.run(query)
            async for record in result:
                services.append({
                    "name": record["name"] or "",
                    "version": record["version"] or "",
                    "host": record["host"] or "",
                })
    except Exception as exc:
        logger.warning("Neo4j service query failed: %s", exc)
    return services


async def run_variant_matcher() -> Dict[str, Any]:
    """Match all unmatched CVEs against active Neo4j service nodes."""
    from app.database.mongodb import get_threat_intel_collection

    services = await _get_active_services()
    if not services:
        return {"matched": 0, "cves_checked": 0, "note": "no active services in graph"}

    collection = await get_threat_intel_collection()
    cves = await collection.find(
        {"matched_targets": {"$exists": True}},
        {"cve_id": 1, "affected_components": 1, "severity": 1, "cvss_score": 1},
    ).to_list(length=500)

    total_matches = 0
    for cve in cves:
        cve_id = cve.get("cve_id", "")
        affected = cve.get("affected_components", [])
        if not affected:
            continue

        new_matches: List[Dict[str, Any]] = []
        for svc in services:
            conf = _component_match(svc["name"], svc["version"], affected)
            if conf >= 0.4:
                new_matches.append({
                    "host": svc["host"],
                    "service": svc["name"],
                    "version": svc["version"],
                    "confidence": conf,
                    "cve_id": cve_id,
                    "severity": cve.get("severity"),
                    "cvss_score": cve.get("cvss_score"),
                })

        if new_matches:
            await collection.update_one(
                {"cve_id": cve_id},
                {"$set": {"matched_targets": new_matches}},
            )
            total_matches += len(new_matches)

    logger.info("CVE variant matcher: %d matches across %d CVEs, %d services", total_matches, len(cves), len(services))
    return {"matched": total_matches, "cves_checked": len(cves), "services_checked": len(services)}


async def run_sameday_replay(cve_id: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    """T131 — Spawn a replica at the affected version and run the CVE PoC."""
    from app.database.mongodb import get_threat_intel_collection, get_replay_sessions_collection
    from app.services.replica_manager_client import spawn_replica

    collection = await get_threat_intel_collection()
    cve = await collection.find_one({"cve_id": cve_id})
    if not cve:
        return {"ok": False, "error": f"CVE {cve_id} not found"}

    poc_url = cve.get("poc_url")
    if not poc_url:
        return {"ok": False, "error": f"No PoC URL for {cve_id}", "skipped": True}

    affected = cve.get("affected_components", [])
    stack_pin = affected[0] if affected else "nginx"

    replica_meta = await spawn_replica(
        stack_pin=stack_pin,
        observed_routes=["/"],
        target_ip=f"replay_{cve_id}",
        session_id=session_id or "",
    )
    if not replica_meta:
        return {"ok": False, "error": "Failed to spawn replica"}

    replica_id = replica_meta.get("replica_id", "")
    base_url = replica_meta.get("base_url", "")

    replay_result: Dict[str, Any] = {
        "cve_id": cve_id,
        "session_id": session_id,
        "replica_id": replica_id,
        "base_url": base_url,
        "poc_url": poc_url,
        "status": "pending",
        "result": None,
    }

    replays = await get_replay_sessions_collection()
    await replays.insert_one(replay_result)

    logger.info("Sameday replay queued for %s on replica %s at %s", cve_id, replica_id, base_url)
    return {
        "ok": True,
        "cve_id": cve_id,
        "replica_id": replica_id,
        "base_url": base_url,
        "poc_url": poc_url,
        "status": "queued",
    }


async def get_threats_for_session(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return CVEs whose matched_targets is non-empty, for the intelligence API."""
    from app.database.mongodb import get_threat_intel_collection

    collection = await get_threat_intel_collection()
    cursor = collection.find(
        {"matched_targets": {"$not": {"$size": 0}}},
        {"_id": 0, "cve_id": 1, "severity": 1, "cvss_score": 1, "description": 1,
         "affected_components": 1, "matched_targets": 1, "poc_url": 1},
    ).sort("cvss_score", -1).limit(100)
    return await cursor.to_list(length=100)
