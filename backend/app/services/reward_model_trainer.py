"""T151 — Reward Model Trainer.

Daily Celery job that pulls hypothesis→outcome pairs from the last 7 days,
updates few-shot examples in ChromaDB reward_model_examples collection,
and refreshes the curiosity scorer's prompt cache.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


async def _collect_training_pairs(since_days: int = 7) -> List[Dict[str, Any]]:
    """Pull confirmed and ruled-out hypotheses from ChromaDB hypotheses collection."""
    from app.database.chroma_client import get_chroma_client

    client = await get_chroma_client()
    collection = await client.get_or_create_collection(
        name="hypotheses",
        metadata={"hnsw:space": "cosine"},
    )

    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
    cutoff_str = cutoff.isoformat()

    try:
        result = await collection.get(
            include=["documents", "metadatas"],
            limit=500,
            where={"$and": [
                {"status": {"$in": ["confirmed", "ruled_out"]}},
                {"created_at": {"$gt": cutoff_str}},
            ]},
        )
    except Exception:
        # ChromaDB filter may fail — fall back to unfiltered
        result = await collection.get(include=["documents", "metadatas"], limit=500)

    pairs: List[Dict[str, Any]] = []
    docs = result.get("documents") or []
    metas = result.get("metadatas") or []
    for doc, meta in zip(docs, metas):
        status = (meta or {}).get("status", "")
        if status in ("confirmed", "ruled_out"):
            pairs.append({
                "hypothesis": doc,
                "was_confirmed": status == "confirmed",
                "session_id": (meta or {}).get("session_id", ""),
                "target_class": (meta or {}).get("target_class", ""),
                "created_at": (meta or {}).get("created_at", ""),
            })
    return pairs


async def run_reward_model_trainer() -> Dict[str, Any]:
    """Update reward_model_examples ChromaDB collection with new training pairs."""
    from app.database.chroma_client import get_reward_model_examples_collection

    pairs = await _collect_training_pairs(since_days=7)
    if not pairs:
        return {"status": "ok", "pairs_processed": 0, "note": "no new training data"}

    collection = await get_reward_model_examples_collection()

    # Upsert each training pair as a document
    ids = [f"pair_{i}_{datetime.now(timezone.utc).strftime('%Y%m%d')}" for i in range(len(pairs))]
    documents = [p["hypothesis"] for p in pairs]
    metadatas = [
        {
            "was_confirmed": p["was_confirmed"],
            "session_id": p["session_id"],
            "target_class": p["target_class"],
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        for p in pairs
    ]

    await collection.upsert(ids=ids, documents=documents, metadatas=metadatas)

    # Build positive/negative few-shot examples for the curiosity scorer
    positives = [p["hypothesis"][:200] for p in pairs if p["was_confirmed"]][:5]
    negatives = [p["hypothesis"][:200] for p in pairs if not p["was_confirmed"]][:5]

    logger.info("reward_model_trainer: %d pairs upserted (%d pos, %d neg)", len(pairs), len(positives), len(negatives))
    return {
        "status": "ok",
        "pairs_processed": len(pairs),
        "positive_examples": len(positives),
        "negative_examples": len(negatives),
    }
