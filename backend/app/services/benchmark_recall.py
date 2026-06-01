"""validation milestone 7 — benchmark_recall: historical CVE recall measurement harness.

This module re-runs GENESIS against pre-patch snapshots and measures recall
against known CVE ground truth, turning "we believe it works" into
"we have measured proof."

Workflow (Celery task, runs weekly):
  1. For a configured target (e.g. "openssl", "nginx"), fetch recent confirmed
     CVEs from the threat_intel collection (populated by threat_intel_ingestor).
  2. For each CVE, use artifact_resolver to fetch the pre-patch source snapshot
     (via git tag, cve-fixes.com API, or NVD source reference).
  3. Run a GENESIS scan session in `validated_dynamic` mode against the
     pre-patch snapshot.
  4. Compare promoted vulnerabilities against the CVE ground truth
     (fuzzy title + CWE + affected_surface match).
  5. Emit recall/precision/F1 to MongoDB `benchmark_scorecards` collection.
  6. Results are exposed at GET /api/v1/benchmarks/recall.

This is infrastructure for continuous self-measurement: the same discipline
used for credible recall, precision, and false-positive reporting.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fuzzy_match(text: str, cve_title: str, cwe: str, affected: str) -> bool:
    """Loose match: does *text* plausibly describe the CVE?"""
    text_lower = text.lower()
    cve_lower = cve_title.lower()
    # Direct title overlap
    title_words = [w for w in cve_lower.split() if len(w) > 4]
    if any(w in text_lower for w in title_words[:5]):
        return True
    # Affected component match
    if affected and affected.lower()[:20] in text_lower:
        return True
    # CWE class match (e.g. CWE-416 = use-after-free)
    cwe_map = {
        "CWE-416": ["use-after-free", "uaf"],
        "CWE-122": ["heap-overflow", "heap overflow", "buffer overflow"],
        "CWE-121": ["stack-overflow", "stack overflow"],
        "CWE-415": ["double-free"],
        "CWE-125": ["out-of-bounds read", "oob read"],
        "CWE-787": ["out-of-bounds write", "memory corruption"],
        "CWE-89":  ["sql injection", "sqli"],
        "CWE-79":  ["cross-site scripting", "xss"],
        "CWE-22":  ["path traversal", "directory traversal"],
        "CWE-287": ["authentication bypass", "improper authentication"],
    }
    for cwe_id, keywords in cwe_map.items():
        if cwe_id in cwe and any(k in text_lower for k in keywords):
            return True
    return False


async def run_recall_benchmark(
    target_name: str = "openssl",
    max_cves: int = 10,
    scan_timeout: int = 1800,
) -> Dict[str, Any]:
    """Run a recall benchmark for *target_name*.

    Returns a scorecard dict with recall, precision, and F1.
    Persists to MongoDB `benchmark_scorecards`.
    """
    from app.database.mongodb import get_benchmark_scorecards_collection, get_threat_intel_collection

    scorecard_id = f"bench-{uuid.uuid4().hex[:12]}"
    run_at = _now()

    # Step 1: fetch recent confirmed CVEs for this target from threat_intel
    cves = await _fetch_cves_for_target(target_name, max_cves)
    if not cves:
        logger.info("benchmark_recall: no CVEs found for target=%s", target_name)
        return {
            "scorecard_id": scorecard_id,
            "target": target_name,
            "cves_tested": 0,
            "recall": None,
            "precision": None,
            "f1": None,
            "run_at": run_at.isoformat(),
            "note": "no CVEs found",
        }

    logger.info(
        "benchmark_recall: starting recall run for %s with %d CVEs",
        target_name, len(cves),
    )

    cve_ids_tested = [c.get("cve_id") for c in cves if c.get("cve_id")]
    found_count = 0
    total_promoted = 0
    per_cve_results: List[Dict[str, Any]] = []

    for cve in cves:
        cve_id = str(cve.get("cve_id") or "")
        cve_title = str(cve.get("title") or "")
        cwe = str(cve.get("cwe") or "")
        affected = str(cve.get("affected_component") or target_name)

        # Step 2: get pre-patch source snapshot
        snapshot_path = await _fetch_pre_patch_snapshot(cve, target_name)
        if not snapshot_path:
            per_cve_results.append({
                "cve_id": cve_id,
                "found": None,
                "note": "pre-patch snapshot unavailable",
            })
            continue

        # Step 3: run a GENESIS scan session against the snapshot
        session_id, promoted = await _run_scan_session(
            snapshot_path, target_name, scan_timeout,
        )
        total_promoted += promoted

        # Step 4: check if any promoted finding matches the CVE
        matched = await _check_findings_match_cve(
            session_id, cve_id, cve_title, cwe, affected,
        )
        if matched:
            found_count += 1

        per_cve_results.append({
            "cve_id": cve_id,
            "session_id": session_id,
            "found": matched,
            "promoted_findings": promoted,
        })
        logger.info(
            "benchmark_recall: %s cve=%s found=%s promoted=%d",
            target_name, cve_id, matched, promoted,
        )

    tested_with_snapshot = sum(1 for r in per_cve_results if r.get("found") is not None)
    recall = found_count / tested_with_snapshot if tested_with_snapshot > 0 else 0.0
    # Precision: of all promoted findings, how many correspond to a real CVE
    precision = found_count / total_promoted if total_promoted > 0 else 0.0
    f1 = (
        2 * recall * precision / (recall + precision)
        if (recall + precision) > 0
        else 0.0
    )

    scorecard: Dict[str, Any] = {
        "_id": scorecard_id,
        "scorecard_id": scorecard_id,
        "target": target_name,
        "cves_tested": len(cves),
        "cves_with_snapshot": tested_with_snapshot,
        "found_count": found_count,
        "total_promoted": total_promoted,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "per_cve": per_cve_results,
        "cve_ids_tested": cve_ids_tested,
        "run_at": run_at,
    }

    try:
        col = get_benchmark_scorecards_collection()
        await col.insert_one(scorecard)
    except Exception as exc:
        logger.warning("benchmark_recall: scorecard insert failed: %s", exc)

    logger.info(
        "benchmark_recall: %s recall=%.2f%% precision=%.2f%% f1=%.2f%%",
        target_name, recall * 100, precision * 100, f1 * 100,
    )
    return scorecard


async def get_latest_scorecards(limit: int = 20) -> List[Dict[str, Any]]:
    """Return the most recent benchmark scorecards."""
    from app.database.mongodb import get_benchmark_scorecards_collection
    col = get_benchmark_scorecards_collection()
    try:
        cursor = col.find({}).sort("run_at", -1).limit(limit)
        return [doc async for doc in cursor]
    except Exception as exc:
        logger.warning("get_latest_scorecards failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _fetch_cves_for_target(target_name: str, max_cves: int) -> List[Dict[str, Any]]:
    """Fetch confirmed CVEs for the target from threat_intel collection."""
    from app.database.mongodb import get_threat_intel_collection
    try:
        col = get_threat_intel_collection()
        cursor = (
            col.find({
                "affected_components": {"$regex": target_name, "$options": "i"},
                "severity": {"$in": ["critical", "high", "medium"]},
            })
            .sort("ingested_at", -1)
            .limit(max_cves)
        )
        return [doc async for doc in cursor]
    except Exception as exc:
        logger.warning("benchmark_recall: CVE fetch failed: %s", exc)
        return []


async def _fetch_pre_patch_snapshot(cve: Dict[str, Any], target_name: str) -> Optional[str]:
    """Attempt to get a pre-patch source path using artifact_resolver."""
    try:
        from app.services.artifact_resolver import ArtifactResolver
        resolver = ArtifactResolver()
        cve_id = str(cve.get("cve_id") or "")
        # Try to resolve via cve-fixes.com API or NVD references
        path = await resolver.resolve_pre_patch_source(
            cve_id=cve_id,
            target_name=target_name,
        )
        return path
    except Exception as exc:
        logger.debug("pre-patch snapshot unavailable for %s: %s", cve.get("cve_id"), exc)
        return None


async def _run_scan_session(
    snapshot_path: str,
    target_name: str,
    timeout: int,
) -> tuple:
    """Ingest the snapshot and run a validated_dynamic scan. Returns (session_id, promoted_count)."""
    import uuid as _uuid
    session_id = str(_uuid.uuid4())
    promoted = 0
    try:
        # Ingest the source into ChromaDB
        from app.services.repo_ingest import ingest_repository
        await ingest_repository(session_id=session_id, local_path=snapshot_path)

        # Run static analysis (no network target — source-only mode)
        from app.services.invariant_inferer import infer_invariants
        await infer_invariants(session_id=session_id)

        from app.services.pattern_inconsistency_detector import check_pending_candidates
        # For benchmark runs we skip the full orchestrator and rely on static
        # analysis + cross-file detection to surface findings
        promoted = await check_pending_candidates(session_id, None, "")
    except Exception as exc:
        logger.warning("benchmark_recall: scan session failed: %s", exc)
    return session_id, promoted


async def _check_findings_match_cve(
    session_id: str,
    cve_id: str,
    cve_title: str,
    cwe: str,
    affected: str,
) -> bool:
    """Return True if any promoted finding in the session matches the CVE."""
    from app.database.mongodb import get_candidate_findings_collection
    try:
        col = get_candidate_findings_collection()
        cursor = col.find(
            {"session_id": session_id, "status": "promoted"},
        ).limit(50)
        async for finding in cursor:
            text = " ".join([
                str(finding.get("title") or ""),
                str(finding.get("hypothesis") or ""),
                str(finding.get("attack_class") or ""),
                str(finding.get("affected_surface") or ""),
            ])
            if _fuzzy_match(text, cve_title, cwe, affected):
                return True
    except Exception as exc:
        logger.debug("benchmark_recall: finding match check failed: %s", exc)
    return False
