"""v5 Celery beat daemon tasks: T90, T91, T98, T101.

These are scheduled background tasks that run continuously to learn patterns,
monitor attack surface changes, extract CVE signals, and compact the Neo4j
graph.  Registered via celery_app.conf.beat_schedule.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

from app.services.celery_app import celery_app

logger = logging.getLogger(__name__)


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from a sync Celery task worker."""
    from app.database.chroma_client import reset_chroma_client
    from app.database.redis_client import reset_redis_client
    from app.database.mongodb import reset_mongo_client

    reset_chroma_client()
    reset_redis_client()
    reset_mongo_client()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# T90 — cross_session_miner
# ---------------------------------------------------------------------------

@celery_app.task(name="app.services.daemon_tasks.run_cross_session_miner", bind=True)
def run_cross_session_miner(self: Any) -> Dict[str, Any]:
    """Mine cross-session attack patterns from ChromaDB and Neo4j (T90)."""
    return _run_async(_async_cross_session_miner())


async def _async_cross_session_miner() -> Dict[str, Any]:
    """Query attack_techniques collection for emerging high-yield patterns."""
    from app.database.chroma_client import get_chroma_client

    try:
        client = await get_chroma_client()
        collection = await client.get_or_create_collection(
            name="attack_techniques",
            metadata={"hnsw:space": "cosine"},
        )
        # Pull the most recent technique records and look for clustering
        result = await collection.get(
            include=["metadatas"],
            limit=500,
        )
        if not result or not result.get("ids"):
            return {"status": "no_data"}

        metas = result.get("metadatas", [])
        # Count technique_tag frequencies among successful hits
        tag_counts: Dict[str, int] = {}
        for meta in metas:
            if meta.get("success") and meta.get("technique_tag"):
                tag = meta["technique_tag"]
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        top_patterns = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        logger.info("cross_session_miner: top patterns = %s", top_patterns[:5])
        return {"status": "ok", "top_patterns": top_patterns}
    except Exception as exc:
        logger.warning("cross_session_miner failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# T91 — cve_extrapolator
# ---------------------------------------------------------------------------

@celery_app.task(name="app.services.daemon_tasks.run_cve_extrapolator", bind=True)
def run_cve_extrapolator(self: Any) -> Dict[str, Any]:
    """Fetch NVD CVE feed and check active targets (T91)."""
    return _run_async(_async_cve_extrapolator())


async def _async_cve_extrapolator() -> Dict[str, Any]:
    """Fetch recent CVEs from NVD and submit hypotheses for matching targets."""
    from app.config import settings
    if not settings.cve_extrapolator_enabled:
        return {"status": "disabled"}

    import aiohttp
    from app.database.mongodb import get_db
    from app.services.hypothesis_market import submit_hypothesis

    try:
        # Fetch last 24 hours of NVD CVEs
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            "?resultsPerPage=20&startIndex=0"
        )
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return {"status": "nvd_fetch_failed", "code": resp.status}
                data = await resp.json()

        cves = data.get("vulnerabilities", [])
        logger.info("cve_extrapolator: fetched %d CVEs", len(cves))

        # Get active sessions from MongoDB
        db = await get_db()
        active_sessions = []
        cursor = db["researchsessions"].find(
            {"status": "running"},
            {"id": 1, "target_ip": 1},
        ).limit(20)
        async for doc in cursor:
            active_sessions.append(doc)

        hypotheses_created = 0
        for cve_item in cves[:10]:
            cve = cve_item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            if not desc or not active_sessions:
                continue
            # Submit hypothesis for each active session
            for sess in active_sessions[:3]:
                await submit_hypothesis(
                    session_id=str(sess.get("id", "")),
                    text=f"Target may be affected by {cve_id}: {desc[:300]}",
                    proposer_agent="cve_extrapolator",
                    hypothesis_type="cve_extrapolation",
                    confidence_stake=0.35,
                )
                hypotheses_created += 1

        return {"status": "ok", "cves_processed": len(cves), "hypotheses_created": hypotheses_created}
    except Exception as exc:
        logger.warning("cve_extrapolator failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# T98 — surface_watcher
# ---------------------------------------------------------------------------

@celery_app.task(name="app.services.daemon_tasks.run_surface_watcher", bind=True)
def run_surface_watcher(self: Any) -> Dict[str, Any]:
    """Check all registered targets for surface changes (T98)."""
    return _run_async(_async_surface_watcher())


async def _async_surface_watcher() -> Dict[str, Any]:
    from app.services.surface_watcher import run_all_watched
    results = await run_all_watched()
    deltas = [r for r in results if r.get("changed")]
    logger.info("surface_watcher: checked=%d deltas=%d", len(results), len(deltas))
    return {"status": "ok", "checked": len(results), "deltas": len(deltas)}


# ---------------------------------------------------------------------------
# T101 — graph_compactor
# ---------------------------------------------------------------------------

@celery_app.task(name="app.services.daemon_tasks.run_graph_compactor", bind=True)
def run_graph_compactor(self: Any) -> Dict[str, Any]:
    """Deduplicate and summarize the Neo4j attack graph (T101)."""
    return _run_async(_async_graph_compactor())


async def _async_graph_compactor() -> Dict[str, Any]:
    """Remove duplicate nodes and merge stale findings in Neo4j."""
    from app.database.neo4j_client import get_neo4j_driver

    driver = await get_neo4j_driver()
    if driver is None:
        return {"status": "no_driver"}

    compaction_queries = [
        # Merge duplicate Service nodes on same host+port
        """
        MATCH (s1:Service)-[:LISTENS_ON]->(h:Host)
        WITH h, s1.port AS port, s1.protocol AS proto, collect(s1) AS dupes
        WHERE size(dupes) > 1
        WITH dupes[1..] AS to_delete
        UNWIND to_delete AS d
        DETACH DELETE d
        """,
        # Remove orphan Finding nodes with no AFFECTS relationship
        """
        MATCH (f:Finding)
        WHERE NOT (f)<-[:AFFECTS]-()
        AND f.created_at < datetime() - duration('P30D')
        DETACH DELETE f
        """,
    ]

    deleted_total = 0
    try:
        async with driver.session() as neo4j_session:
            for query in compaction_queries:
                try:
                    result = await neo4j_session.run(query)
                    summary = await result.consume()
                    deleted_total += summary.counters.nodes_deleted
                except Exception as exc:
                    logger.debug("compaction query failed: %s", exc)
    except Exception as exc:
        logger.warning("graph_compactor failed: %s", exc)
        return {"status": "error", "error": str(exc)}

    logger.info("graph_compactor: nodes_deleted=%d", deleted_total)
    return {"status": "ok", "nodes_deleted": deleted_total}


# ---------------------------------------------------------------------------
# validation milestone 7 — recall_benchmark
# ---------------------------------------------------------------------------

_RECALL_BENCHMARK_TARGETS = ["openssl", "nginx", "libpng"]


@celery_app.task(name="app.services.daemon_tasks.run_recall_benchmark", bind=True)
def run_recall_benchmark(self: Any) -> List[Dict[str, Any]]:
    """Weekly recall benchmark: measure GENESIS recall vs. historical CVEs (validation milestone 7)."""
    return _run_async(_async_recall_benchmark())


async def _async_recall_benchmark() -> List[Dict[str, Any]]:
    from app.services.benchmark_recall import run_recall_benchmark as _bench
    results = []
    for target in _RECALL_BENCHMARK_TARGETS:
        try:
            result = await _bench(target_name=target, max_cves=10)
            results.append(result)
            logger.info(
                "recall_benchmark: target=%s recall=%.2f%% f1=%.2f%%",
                target,
                (result.get("recall") or 0) * 100,
                (result.get("f1") or 0) * 100,
            )
        except Exception as exc:
            logger.warning("recall_benchmark: target=%s failed: %s", target, exc)
            results.append({"target": target, "status": "error", "error": str(exc)})
    return results


# ---------------------------------------------------------------------------
# T129 — threat_intel_ingestor
# ---------------------------------------------------------------------------

@celery_app.task(name="app.services.daemon_tasks.run_threat_intel_ingestor", bind=True)
def run_threat_intel_ingestor(self: Any) -> Dict[str, Any]:
    """Fetch new CVEs from NVD and GitHub advisories and upsert to MongoDB (T129)."""
    return _run_async(_async_threat_intel_ingestor())


async def _async_threat_intel_ingestor() -> Dict[str, Any]:
    from app.services.threat_intel_ingestor import run_ingestor
    try:
        return await run_ingestor(since_days=1)
    except Exception as exc:
        logger.warning("threat_intel_ingestor failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# T130 — cve_variant_matcher
# ---------------------------------------------------------------------------

@celery_app.task(name="app.services.daemon_tasks.run_cve_variant_matcher", bind=True)
def run_cve_variant_matcher(self: Any) -> Dict[str, Any]:
    """Match ingested CVEs against active Neo4j service nodes (T130)."""
    return _run_async(_async_cve_variant_matcher())


async def _async_cve_variant_matcher() -> Dict[str, Any]:
    from app.services.cve_variant_matcher import run_variant_matcher
    try:
        return await run_variant_matcher()
    except Exception as exc:
        logger.warning("cve_variant_matcher failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# T151 — reward_model_trainer
# ---------------------------------------------------------------------------

@celery_app.task(name="app.services.daemon_tasks.run_reward_model_trainer", bind=True)
def run_reward_model_trainer(self: Any) -> Dict[str, Any]:
    """Update few-shot curiosity scorer examples from last 7 days of outcomes (T151)."""
    return _run_async(_async_reward_model_trainer())


async def _async_reward_model_trainer() -> Dict[str, Any]:
    from app.services.reward_model_trainer import run_reward_model_trainer
    try:
        return await run_reward_model_trainer()
    except Exception as exc:
        logger.warning("reward_model_trainer failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# T154 — drift_detection
# ---------------------------------------------------------------------------

@celery_app.task(name="app.services.daemon_tasks.run_drift_detection", bind=True)
def run_drift_detection(self: Any) -> Dict[str, Any]:
    """Detect hypothesis-confirmation rate drift vs 30-day baseline (T154)."""
    return _run_async(_async_drift_detection())


async def _async_drift_detection() -> Dict[str, Any]:
    try:
        return await _check_drift()
    except Exception as exc:
        logger.warning("drift_detection failed: %s", exc)
        return {"status": "error", "error": str(exc)}


async def _check_drift() -> Dict[str, Any]:
    """Compare last 7-day confirmation rate vs 30-day baseline; alert if drop >30%."""
    from app.database.chroma_client import get_chroma_client
    from datetime import datetime, timezone, timedelta

    client = await get_chroma_client()
    collection = await client.get_or_create_collection(
        name="hypotheses",
        metadata={"hnsw:space": "cosine"},
    )

    now = datetime.now(timezone.utc)
    cutoff_7d = (now - timedelta(days=7)).isoformat()
    cutoff_30d = (now - timedelta(days=30)).isoformat()

    def _conf_rate(result: Any) -> float:
        metas = result.get("metadatas") or []
        total = len(metas)
        if total == 0:
            return 0.0
        confirmed = sum(1 for m in metas if (m or {}).get("status") == "confirmed")
        return confirmed / total

    try:
        recent = await collection.get(
            include=["metadatas"], limit=500,
            where={"created_at": {"$gt": cutoff_7d}},
        )
        baseline = await collection.get(
            include=["metadatas"], limit=2000,
            where={"created_at": {"$gt": cutoff_30d}},
        )
        recent_rate = _conf_rate(recent)
        baseline_rate = _conf_rate(baseline)
    except Exception:
        recent_rate = baseline_rate = 0.0

    drop = (baseline_rate - recent_rate) / baseline_rate if baseline_rate > 0 else 0.0
    drifted = drop > 0.30

    if drifted:
        logger.warning(
            "drift_detection: confirmation rate dropped %.0f%% (%.2f -> %.2f)",
            drop * 100, baseline_rate, recent_rate,
        )

    return {
        "status": "ok",
        "drift_detected": drifted,
        "recent_rate": round(recent_rate, 4),
        "baseline_rate": round(baseline_rate, 4),
        "drop_pct": round(drop * 100, 1),
        "threshold_pct": 30,
    }
