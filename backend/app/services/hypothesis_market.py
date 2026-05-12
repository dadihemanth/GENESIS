"""T89 — hypothesis_market: confidence-staked adversarial hypothesis system.

Every hypothesis has a confidence stake (0–1).  Resource allocation (iteration
budget) is proportional to stake.  Evidence updates stakes retroactively.
Semantically deduplicates against the `hypotheses` ChromaDB collection before
storing a new hypothesis so near-duplicate ideas are merged rather than
re-tried.

MongoDB collection `hypothesis_market`:
  {hypothesis_id, text, confidence_stake, session_id, proposer_agent,
   status, evidence_for: [], evidence_against: [], created_at, updated_at}
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.chroma_client import get_hypotheses_collection
from app.database.mongodb import get_db

logger = logging.getLogger(__name__)

_COLLECTION = "hypothesis_market"
_SIMILARITY_DEDUP_THRESHOLD = 0.85  # cosine similarity above which we treat as duplicate


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------

async def submit_hypothesis(
    session_id: str,
    text: str,
    proposer_agent: str = "orchestrator",
    hypothesis_type: str = "generic",
    confidence_stake: float = 0.5,
) -> Dict[str, Any]:
    """Create a new hypothesis entry, deduplicating against existing ones.

    Returns the created (or existing deduplicated) hypothesis dict.
    """
    confidence_stake = max(0.0, min(1.0, confidence_stake))

    # Semantic dedup check in ChromaDB
    existing = await _find_similar_hypothesis(session_id, text)
    if existing:
        logger.debug(
            "hypothesis_market: dedup — merging into existing %s",
            existing["hypothesis_id"],
        )
        # Boost the existing stake slightly
        new_stake = min(1.0, existing["confidence_stake"] + 0.05)
        await update_stake(existing["hypothesis_id"], new_stake)
        return existing

    hyp_id = f"hyp-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    doc: Dict[str, Any] = {
        "hypothesis_id": hyp_id,
        "session_id": session_id,
        "text": text,
        "proposer_agent": proposer_agent,
        "hypothesis_type": hypothesis_type,
        "confidence_stake": confidence_stake,
        "status": "open",
        "evidence_for": [],
        "evidence_against": [],
        "created_at": now,
        "updated_at": now,
    }

    try:
        db = await get_db()
        await db[_COLLECTION].insert_one(doc)
    except Exception as exc:
        logger.warning("hypothesis_market mongo insert failed: %s", exc)

    # Store in ChromaDB for semantic recall
    await _store_hypothesis_chroma(hyp_id, session_id, text, hypothesis_type, confidence_stake)

    doc["_id"] = None  # drop mongo ObjectId for JSON serialisation
    logger.info(
        "hypothesis_market: new hypothesis %s (stake=%.2f) for session=%s",
        hyp_id, confidence_stake, session_id,
    )
    return doc


# ---------------------------------------------------------------------------
# Stake management
# ---------------------------------------------------------------------------

async def update_stake(
    hypothesis_id: str,
    new_stake: float,
) -> bool:
    """Update the confidence stake for an existing hypothesis."""
    new_stake = max(0.0, min(1.0, new_stake))
    try:
        db = await get_db()
        result = await db[_COLLECTION].update_one(
            {"hypothesis_id": hypothesis_id},
            {"$set": {"confidence_stake": new_stake, "updated_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count > 0
    except Exception as exc:
        logger.warning("update_stake failed: %s", exc)
        return False


async def add_evidence(
    hypothesis_id: str,
    evidence_text: str,
    supports: bool,
) -> bool:
    """Add a piece of evidence for or against a hypothesis, adjusting its stake."""
    try:
        db = await get_db()
        field = "evidence_for" if supports else "evidence_against"
        doc = await db[_COLLECTION].find_one({"hypothesis_id": hypothesis_id})
        if not doc:
            return False

        current_stake = doc.get("confidence_stake", 0.5)
        delta = 0.1 if supports else -0.1
        new_stake = max(0.0, min(1.0, current_stake + delta))

        await db[_COLLECTION].update_one(
            {"hypothesis_id": hypothesis_id},
            {
                "$push": {field: {"text": evidence_text[:500], "added_at": datetime.now(timezone.utc).isoformat()}},
                "$set": {"confidence_stake": new_stake, "updated_at": datetime.now(timezone.utc)},
            },
        )
        return True
    except Exception as exc:
        logger.warning("add_evidence failed: %s", exc)
        return False


async def resolve_hypothesis(
    hypothesis_id: str,
    status: str,  # "confirmed" | "refuted" | "abandoned"
) -> bool:
    """Mark a hypothesis as resolved."""
    valid = {"confirmed", "refuted", "abandoned"}
    if status not in valid:
        return False
    try:
        db = await get_db()
        await db[_COLLECTION].update_one(
            {"hypothesis_id": hypothesis_id},
            {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}},
        )
        return True
    except Exception as exc:
        logger.warning("resolve_hypothesis failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Resource allocation
# ---------------------------------------------------------------------------

async def allocate_resources(
    session_id: str,
    total_budget: int = 20,
    top_n: int = 3,
) -> List[Dict[str, Any]]:
    """Return the top-N hypotheses by stake for iteration-budget allocation.

    Budget is proportional to relative stake among the top-N.
    """
    try:
        db = await get_db()
        cursor = (
            db[_COLLECTION]
            .find({"session_id": session_id, "status": "open"})
            .sort("confidence_stake", -1)
            .limit(top_n)
        )
        top: List[Dict[str, Any]] = []
        async for doc in cursor:
            doc.pop("_id", None)
            top.append(doc)
    except Exception as exc:
        logger.warning("allocate_resources failed: %s", exc)
        return []

    if not top:
        return []

    total_stake = sum(h["confidence_stake"] for h in top) or 1.0
    for h in top:
        h["allocated_iterations"] = max(1, round(total_budget * h["confidence_stake"] / total_stake))
    return top


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

async def get_session_hypotheses(
    session_id: str,
    status: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Retrieve hypotheses for a session, optionally filtered by status."""
    try:
        db = await get_db()
        query: Dict[str, Any] = {"session_id": session_id}
        if status:
            query["status"] = status
        cursor = db[_COLLECTION].find(query).sort("confidence_stake", -1).limit(limit)
        results: List[Dict[str, Any]] = []
        async for doc in cursor:
            doc.pop("_id", None)
            results.append(doc)
        return results
    except Exception as exc:
        logger.warning("get_session_hypotheses failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _find_similar_hypothesis(
    session_id: str,
    text: str,
) -> Optional[Dict[str, Any]]:
    """Return an existing hypothesis if one is semantically similar enough."""
    try:
        collection = await get_hypotheses_collection()
        results = await collection.query(
            query_texts=[text],
            where={"session_id": session_id},
            n_results=1,
            include=["metadatas", "distances"],
        )
        if not (results and results.get("ids") and results["ids"][0]):
            return None
        distance = results["distances"][0][0]
        similarity = 1.0 - distance
        if similarity >= _SIMILARITY_DEDUP_THRESHOLD:
            meta = results["metadatas"][0][0]
            hyp_id = meta.get("hypothesis_id", "")
            if hyp_id:
                db = await get_db()
                doc = await db[_COLLECTION].find_one({"hypothesis_id": hyp_id})
                if doc:
                    doc.pop("_id", None)
                    return doc
    except Exception as exc:
        logger.debug("_find_similar_hypothesis failed: %s", exc)
    return None


async def _store_hypothesis_chroma(
    hyp_id: str,
    session_id: str,
    text: str,
    hypothesis_type: str,
    confidence_stake: float,
) -> None:
    try:
        collection = await get_hypotheses_collection()
        await collection.add(
            ids=[hyp_id],
            documents=[text],
            metadatas=[{
                "hypothesis_id": hyp_id,
                "session_id": session_id,
                "hypothesis_type": hypothesis_type,
                "confidence_stake": confidence_stake,
                "status": "open",
            }],
        )
    except Exception as exc:
        logger.debug("_store_hypothesis_chroma failed: %s", exc)
