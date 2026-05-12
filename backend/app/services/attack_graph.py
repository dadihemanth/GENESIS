"""T21 — Attack knowledge graph writer + reader.

Schema (Neo4j 5, cypher):

    (:Target {fingerprint})              — stable per target_ip (cross-session)
    (:Host {id, session_id, ip, hostname, os_guess})
    (:Service {id, session_id, host_id, port, protocol, banner})
    (:Finding {id, session_id, title, severity, cvss, verification_status,
               mitre[], attack_chain_id, chain_position})
    (:Credential {id, session_id, username, realm, source})
    (:Token {id, session_id, kind, scope})
    (:Privilege {id, session_id, name, target_id})

    (h:Host)-[:LISTENS_ON]->(s:Service)
    (h:Host)-[:ON_TARGET]->(t:Target)
    (f:Finding)-[:AFFECTS]->(s:Service)
    (f:Finding)-[:AFFECTS_HOST]->(h:Host)
    (f:Finding)-[:CHAINS_INTO {position}]->(f2:Finding)
    (c:Credential)-[:AUTHENTICATES_TO]->(s:Service)
    (c:Credential)-[:GRANTS]->(p:Privilege)

All writes are idempotent MERGE statements so repeated upserts from the
orchestrator don't duplicate nodes. Each node carries ``session_id`` so
queries can scope per-session or across every session that touched the
same Target fingerprint.
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from app.database.neo4j_client import get_neo4j_driver

logger = logging.getLogger(__name__)


async def _publish_delta(session_id: str, delta: dict[str, Any]) -> None:
    """Emit a ``graph_delta`` WebSocket event for the T27 frontend panel.

    Best-effort — if Redis is unavailable the graph write still succeeds.
    The payload mirrors the shape of /api/v1/graph/session/{id}: lists of
    nodes and edges the frontend appends to its Cytoscape view.
    """
    try:
        from app.database.redis_client import publish_session_message

        await publish_session_message(session_id, {
            "type": "graph_delta",
            "data": delta,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:  # noqa: BLE001
        logger.debug("graph_delta publish failed: %s", exc)


def target_fingerprint(target_ip: str) -> str:
    """Stable per-target identity. Strips scheme/port/path so repeat scans of
    the same host end up on the same Target node even if wording shifted.
    """
    host = (target_ip or "").strip().lower()
    host = re.sub(r"^https?://", "", host)
    host = host.split("/")[0]
    host = host.split(":")[0]
    return hashlib.sha1(host.encode("utf-8")).hexdigest()[:16] if host else "unknown"


def _host_id(session_id: str, ip: str) -> str:
    return f"host:{session_id[:8]}:{ip}"


def _service_id(session_id: str, ip: str, port: int | None, protocol: str | None) -> str:
    return f"svc:{session_id[:8]}:{ip}:{port or 0}:{(protocol or 'tcp').lower()}"


async def upsert_target(fingerprint: str, target_ip: str) -> None:
    try:
        driver = await get_neo4j_driver()
        async with driver.session() as s:
            await s.run(
                "MERGE (t:Target {fingerprint: $fp}) "
                "ON CREATE SET t.first_seen = datetime(), t.ip = $ip "
                "ON MATCH SET t.last_seen = datetime()",
                fp=fingerprint, ip=target_ip,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("upsert_target failed: %s", exc)


async def upsert_host(
    session_id: str,
    ip: str,
    *,
    target_ip: str | None = None,
    hostname: str | None = None,
    os_guess: str | None = None,
    services: list[dict[str, Any]] | None = None,
) -> None:
    """Write a Host + its LISTENS_ON services. Idempotent."""
    if not ip:
        return
    delta_nodes: list[dict[str, Any]] = []
    delta_edges: list[dict[str, Any]] = []
    try:
        driver = await get_neo4j_driver()
        host_id = _host_id(session_id, ip)
        fp = target_fingerprint(target_ip or ip)
        delta_nodes.append({
            "id": host_id, "labels": ["Host"], "session_id": session_id,
            "ip": ip, "hostname": hostname or "", "os_guess": os_guess or "",
        })
        async with driver.session() as s:
            await s.run(
                """
                MERGE (h:Host {id: $host_id})
                ON CREATE SET h.created_at = datetime()
                SET h.session_id = $session_id, h.ip = $ip,
                    h.hostname = coalesce($hostname, h.hostname),
                    h.os_guess = coalesce($os_guess, h.os_guess),
                    h.updated_at = datetime()
                MERGE (t:Target {fingerprint: $fp})
                MERGE (h)-[:ON_TARGET]->(t)
                """,
                host_id=host_id, session_id=session_id, ip=ip,
                hostname=hostname, os_guess=os_guess, fp=fp,
            )
            for svc in services or []:
                port = svc.get("port")
                proto = svc.get("protocol") or "tcp"
                banner = svc.get("banner") or svc.get("label") or ""
                svc_id = _service_id(session_id, ip, port, proto)
                await s.run(
                    """
                    MERGE (sv:Service {id: $svc_id})
                    ON CREATE SET sv.created_at = datetime()
                    SET sv.session_id = $session_id, sv.host_id = $host_id,
                        sv.port = $port, sv.protocol = $proto,
                        sv.banner = coalesce($banner, sv.banner),
                        sv.updated_at = datetime()
                    WITH sv
                    MATCH (h:Host {id: $host_id})
                    MERGE (h)-[:LISTENS_ON]->(sv)
                    """,
                    svc_id=svc_id, session_id=session_id, host_id=host_id,
                    port=port, proto=proto, banner=banner,
                )
                delta_nodes.append({
                    "id": svc_id, "labels": ["Service"], "session_id": session_id,
                    "host_id": host_id, "port": port, "protocol": proto, "banner": banner,
                })
                delta_edges.append({
                    "source": host_id, "target": svc_id, "type": "LISTENS_ON",
                })
    except Exception as exc:  # noqa: BLE001
        logger.warning("upsert_host failed for %s: %s", ip, exc)
        return
    if delta_nodes or delta_edges:
        await _publish_delta(session_id, {"nodes": delta_nodes, "edges": delta_edges})


async def upsert_finding(
    session_id: str,
    vuln_id: str,
    *,
    title: str,
    severity: str,
    cvss: float | None,
    verification_status: str,
    confidence: float,
    mitre: list[str],
    attack_chain_id: str | None,
    chain_position: int | None,
    affected_service: str,
    port: int | None,
    protocol: str | None,
    target_ip: str | None,
) -> None:
    """Write a Finding and its :AFFECTS / :CHAINS_INTO edges."""
    delta_nodes: list[dict[str, Any]] = [{
        "id": vuln_id, "labels": ["Finding"], "session_id": session_id,
        "title": title, "severity": severity.lower(), "cvss": cvss,
        "verification_status": verification_status, "confidence": confidence,
        "mitre": list(mitre or []),
        "attack_chain_id": attack_chain_id, "chain_position": chain_position,
    }]
    delta_edges: list[dict[str, Any]] = []
    try:
        driver = await get_neo4j_driver()
        async with driver.session() as s:
            await s.run(
                """
                MERGE (f:Finding {id: $vuln_id})
                SET f.session_id = $session_id,
                    f.title = $title,
                    f.severity = $severity,
                    f.cvss = $cvss,
                    f.verification_status = $vstatus,
                    f.confidence = $confidence,
                    f.mitre = $mitre,
                    f.attack_chain_id = $acid,
                    f.chain_position = $cpos,
                    f.updated_at = datetime()
                """,
                vuln_id=vuln_id, session_id=session_id, title=title,
                severity=severity.lower(), cvss=cvss, vstatus=verification_status,
                confidence=confidence, mitre=list(mitre or []),
                acid=attack_chain_id, cpos=chain_position,
            )

            # Link finding to host + service when we have enough detail.
            if target_ip:
                host_id = _host_id(session_id, target_ip)
                # Host node may not exist yet if the topology path never ran.
                # Create a bare one so the edge is meaningful.
                await s.run(
                    """
                    MERGE (h:Host {id: $host_id})
                    ON CREATE SET h.created_at = datetime(),
                                  h.session_id = $session_id,
                                  h.ip = $ip
                    WITH h
                    MATCH (f:Finding {id: $vuln_id})
                    MERGE (f)-[:AFFECTS_HOST]->(h)
                    """,
                    host_id=host_id, session_id=session_id, ip=target_ip, vuln_id=vuln_id,
                )
                delta_edges.append({
                    "source": vuln_id, "target": host_id, "type": "AFFECTS_HOST",
                })
                if port:
                    svc_id = _service_id(session_id, target_ip, port, protocol)
                    await s.run(
                        """
                        MERGE (sv:Service {id: $svc_id})
                        ON CREATE SET sv.created_at = datetime(),
                                      sv.session_id = $session_id,
                                      sv.host_id = $host_id,
                                      sv.port = $port,
                                      sv.protocol = $proto,
                                      sv.banner = $banner
                        WITH sv
                        MATCH (f:Finding {id: $vuln_id})
                        MERGE (f)-[:AFFECTS]->(sv)
                        WITH sv
                        MATCH (h:Host {id: $host_id})
                        MERGE (h)-[:LISTENS_ON]->(sv)
                        """,
                        svc_id=svc_id, session_id=session_id, host_id=host_id,
                        port=port, proto=(protocol or "tcp"),
                        banner=affected_service or "", vuln_id=vuln_id,
                    )
                    delta_edges.append({
                        "source": vuln_id, "target": svc_id, "type": "AFFECTS",
                    })

            # CHAINS_INTO — link to the prior finding in the same chain.
            if attack_chain_id and chain_position and chain_position > 1:
                res = await s.run(
                    """
                    MATCH (prev:Finding {session_id: $session_id,
                                         attack_chain_id: $acid,
                                         chain_position: $prev_pos})
                    MATCH (f:Finding {id: $vuln_id})
                    MERGE (prev)-[r:CHAINS_INTO]->(f)
                    SET r.position = $cpos
                    RETURN prev.id AS prev_id
                    """,
                    session_id=session_id, acid=attack_chain_id,
                    prev_pos=chain_position - 1, cpos=chain_position, vuln_id=vuln_id,
                )
                rec = await res.single()
                if rec and rec["prev_id"]:
                    delta_edges.append({
                        "source": rec["prev_id"], "target": vuln_id,
                        "type": "CHAINS_INTO", "position": chain_position,
                    })
    except Exception as exc:  # noqa: BLE001
        logger.warning("upsert_finding failed for %s: %s", vuln_id, exc)
        return
    await _publish_delta(session_id, {"nodes": delta_nodes, "edges": delta_edges})


async def upsert_credential(
    session_id: str,
    *,
    username: str,
    realm: str | None = None,
    source: str | None = None,
    authenticates_to_service_id: str | None = None,
    granted_privilege: str | None = None,
) -> None:
    """Cred discovery — called by future tool integrations (impacket, john, etc.)."""
    if not username:
        return
    try:
        driver = await get_neo4j_driver()
        cred_id = f"cred:{session_id[:8]}:{(realm or '').lower()}:{username.lower()}"
        async with driver.session() as s:
            await s.run(
                """
                MERGE (c:Credential {id: $cred_id})
                SET c.session_id = $session_id,
                    c.username = $username,
                    c.realm = $realm,
                    c.source = coalesce($source, c.source),
                    c.updated_at = datetime()
                """,
                cred_id=cred_id, session_id=session_id, username=username,
                realm=realm, source=source,
            )
            if authenticates_to_service_id:
                await s.run(
                    """
                    MATCH (c:Credential {id: $cred_id})
                    MATCH (sv:Service {id: $svc_id})
                    MERGE (c)-[:AUTHENTICATES_TO]->(sv)
                    """,
                    cred_id=cred_id, svc_id=authenticates_to_service_id,
                )
            if granted_privilege:
                priv_id = f"priv:{session_id[:8]}:{granted_privilege.lower()}"
                await s.run(
                    """
                    MERGE (p:Privilege {id: $priv_id})
                    SET p.session_id = $session_id, p.name = $name
                    WITH p
                    MATCH (c:Credential {id: $cred_id})
                    MERGE (c)-[:GRANTS]->(p)
                    """,
                    priv_id=priv_id, session_id=session_id,
                    name=granted_privilege, cred_id=cred_id,
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("upsert_credential failed: %s", exc)


# ── Read paths ─────────────────────────────────────────────────────────────


def _to_jsonable(v: Any) -> Any:
    # Neo4j time types (DateTime / Date / Time / Duration) aren't JSON-serializable
    # by Pydantic. Convert them to ISO strings; recurse into containers.
    try:
        from neo4j.time import Date, DateTime, Duration, Time  # type: ignore
    except Exception:  # noqa: BLE001
        Date = DateTime = Duration = Time = ()  # type: ignore[assignment]
    if isinstance(v, (DateTime, Date, Time)):  # type: ignore[arg-type]
        return v.iso_format() if hasattr(v, "iso_format") else str(v)
    if isinstance(v, Duration):  # type: ignore[arg-type]
        return str(v)
    if isinstance(v, dict):
        return {k: _to_jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_to_jsonable(x) for x in v]
    return v


async def session_graph(session_id: str) -> dict[str, list[dict[str, Any]]]:
    """Return all nodes + edges for a session. Used by T27 frontend."""
    try:
        driver = await get_neo4j_driver()
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        async with driver.session(default_access_mode="READ") as s:
            res = await s.run(
                """
                MATCH (n)
                WHERE n.session_id = $sid OR (n:Target AND EXISTS {
                    MATCH (h:Host {session_id: $sid})-[:ON_TARGET]->(n)
                })
                RETURN id(n) AS eid, labels(n) AS labels, properties(n) AS props
                """,
                sid=session_id,
            )
            async for rec in res:
                props = _to_jsonable(dict(rec["props"]))
                node = {"eid": rec["eid"], "labels": list(rec["labels"]), **props}
                if "id" not in node:
                    node["id"] = f"eid:{rec['eid']}"
                nodes.append(node)
            res2 = await s.run(
                """
                MATCH (a)-[r]->(b)
                WHERE (a.session_id = $sid OR (a:Target AND EXISTS {
                    MATCH (h:Host {session_id: $sid})-[:ON_TARGET]->(a)
                }))
                  AND (b.session_id = $sid OR (b:Target AND EXISTS {
                    MATCH (h:Host {session_id: $sid})-[:ON_TARGET]->(b)
                }))
                RETURN id(a) AS src, id(b) AS dst,
                       a.id AS src_id, b.id AS dst_id,
                       type(r) AS type, properties(r) AS props
                """,
                sid=session_id,
            )
            async for rec in res2:
                props = _to_jsonable(dict(rec["props"]))
                edges.append({
                    "source": rec["src_id"] if rec["src_id"] is not None else f"eid:{rec['src']}",
                    "target": rec["dst_id"] if rec["dst_id"] is not None else f"eid:{rec['dst']}",
                    "type": rec["type"],
                    **props,
                })
        return {"nodes": nodes, "edges": edges}
    except Exception as exc:  # noqa: BLE001
        logger.warning("session_graph failed: %s", exc)
        return {"nodes": [], "edges": []}


async def shortest_path(
    src_label: str, src_id: str, dst_label: str, dst_id: str, max_hops: int = 8,
) -> list[dict[str, Any]] | None:
    try:
        driver = await get_neo4j_driver()
        async with driver.session(default_access_mode="READ") as s:
            res = await s.run(
                f"""
                MATCH (a:{src_label} {{id: $sid}}), (b:{dst_label} {{id: $did}})
                MATCH p = shortestPath((a)-[*..{int(max_hops)}]-(b))
                RETURN [n IN nodes(p) | {{labels: labels(n), props: properties(n)}}] AS nodes,
                       [r IN relationships(p) | type(r)] AS edges
                LIMIT 1
                """,
                sid=src_id, did=dst_id,
            )
            rec = await res.single()
            if rec is None:
                return None
            return {"nodes": rec["nodes"], "edges": rec["edges"]}
    except Exception as exc:  # noqa: BLE001
        logger.warning("shortest_path failed: %s", exc)
        return None


async def run_read_cypher(
    cypher: str, params: dict[str, Any] | None = None, row_cap: int = 10_000, timeout_s: float = 30.0,
) -> dict[str, Any]:
    """Execute an already-guarded read-only Cypher query. Capped + timed out."""
    from app.database.neo4j_client import is_read_only_cypher

    ok, reason = is_read_only_cypher(cypher)
    if not ok:
        return {"ok": False, "error": f"query rejected: {reason}"}

    try:
        driver = await get_neo4j_driver()
        rows: list[dict[str, Any]] = []
        async with driver.session(default_access_mode="READ") as s:
            res = await s.run(cypher, params or {}, timeout=timeout_s)
            async for rec in res:
                rows.append(dict(rec))
                if len(rows) >= row_cap:
                    break
        return {"ok": True, "rows": rows, "truncated": len(rows) >= row_cap}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
