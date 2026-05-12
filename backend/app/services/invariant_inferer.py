"""T83 — invariant_inferer: infer runtime invariants from static analysis.

Reads the `source_corpus` and `attack_techniques` ChromaDB collections for a
target and infers likely runtime invariants (value ranges, type constraints,
ordering requirements).  Stores results in both:
  - `invariants` ChromaDB collection (for semantic recall by future sessions)
  - MongoDB `invariants` collection (for structured querying by T95/T96)

These invariants feed into T95 (invariant_violator) and T96 (model_checker).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.chroma_client import get_invariants_collection, get_source_corpus_collection
from app.database.mongodb import get_db

logger = logging.getLogger(__name__)

# Patterns that suggest invariants in code comments / variable names
_INVARIANT_HINTS = [
    # Access control
    ("must be authenticated", "auth_required", "high"),
    ("admin only", "privilege_required", "high"),
    ("role check", "rbac_check", "high"),
    # Input validation
    ("must not be null", "non_null", "medium"),
    ("max length", "length_constraint", "medium"),
    ("must be positive", "positive_value", "medium"),
    ("must be integer", "type_constraint", "medium"),
    # Ordering / state
    ("must be called before", "ordering_constraint", "medium"),
    ("must be called after", "ordering_constraint", "medium"),
    ("only once", "singleton_constraint", "medium"),
    # Cryptographic
    ("must be random", "randomness_required", "high"),
    ("constant time", "timing_constraint", "high"),
    # Resource limits
    ("rate limit", "rate_limit", "medium"),
    ("quota", "quota_constraint", "medium"),
]


def _extract_invariants_from_snippet(snippet: str, file_path: str) -> List[Dict[str, Any]]:
    """Heuristically extract invariants from a code snippet."""
    found: List[Dict[str, Any]] = []
    lower = snippet.lower()
    for hint_text, invariant_type, confidence in _INVARIANT_HINTS:
        if hint_text in lower:
            # Find the line containing the hint for context
            lines = snippet.splitlines()
            context_line = next(
                (ln.strip() for ln in lines if hint_text in ln.lower()),
                "",
            )
            found.append({
                "invariant_type": invariant_type,
                "hint": hint_text,
                "context": context_line[:200],
                "file_path": file_path,
                "confidence": confidence,
            })
    return found


async def infer_invariants(
    session_id: str,
    target_ip: str = "",
    target_id: str = "",
) -> List[Dict[str, Any]]:
    """Infer invariants for the given session's ingested source corpus.

    Returns a list of invariant dicts and persists them to ChromaDB + MongoDB.
    """
    try:
        corpus_collection = await get_source_corpus_collection()
        # Pull all source chunks for this session
        corpus_result = await corpus_collection.get(
            where={"session_id": session_id},
            include=["documents", "metadatas"],
            limit=300,
        )
    except Exception as exc:
        logger.warning("invariant_inferer: corpus fetch failed: %s", exc)
        return []

    all_invariants: List[Dict[str, Any]] = []
    if corpus_result and corpus_result.get("ids"):
        for i, chunk_id in enumerate(corpus_result["ids"]):
            doc = corpus_result["documents"][i] if corpus_result.get("documents") else ""
            meta = corpus_result["metadatas"][i] if corpus_result.get("metadatas") else {}
            file_path = meta.get("file_path", "")
            extracted = _extract_invariants_from_snippet(doc, file_path)
            for inv in extracted:
                inv["session_id"] = session_id
                inv["target_ip"] = target_ip
                inv["target_id"] = target_id or session_id
            all_invariants.extend(extracted)

    # Deduplicate by (invariant_type, file_path)
    seen: set = set()
    unique_invariants: List[Dict[str, Any]] = []
    for inv in all_invariants:
        key = (inv["invariant_type"], inv["file_path"])
        if key not in seen:
            seen.add(key)
            unique_invariants.append(inv)

    if not unique_invariants:
        logger.info("invariant_inferer: no invariants found for session=%s", session_id)
        return []

    # Persist to ChromaDB invariants collection
    await _store_invariants_chroma(session_id, target_ip, target_id, unique_invariants)
    # Persist to MongoDB for structured query access
    await _store_invariants_mongo(session_id, target_ip, target_id, unique_invariants)

    logger.info(
        "invariant_inferer: session=%s found=%d invariants",
        session_id, len(unique_invariants),
    )
    return unique_invariants


async def _store_invariants_chroma(
    session_id: str,
    target_ip: str,
    target_id: str,
    invariants: List[Dict[str, Any]],
) -> None:
    try:
        collection = await get_invariants_collection()
        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []

        for inv in invariants:
            inv_id = f"inv-{session_id}-{uuid.uuid4().hex[:8]}"
            doc = (
                f"Invariant: {inv['invariant_type']}\n"
                f"Hint: {inv['hint']}\n"
                f"File: {inv['file_path']}\n"
                f"Context: {inv['context']}"
            )
            ids.append(inv_id)
            docs.append(doc)
            metas.append({
                "session_id": session_id,
                "target_id": target_id or session_id,
                "target_ip": target_ip,
                "invariant_type": inv["invariant_type"],
                "confidence": inv["confidence"],
                "file_path": inv["file_path"],
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

        if ids:
            await collection.add(ids=ids, documents=docs, metadatas=metas)
    except Exception as exc:
        logger.warning("_store_invariants_chroma failed: %s", exc)


async def _store_invariants_mongo(
    session_id: str,
    target_ip: str,
    target_id: str,
    invariants: List[Dict[str, Any]],
) -> None:
    try:
        db = await get_db()
        collection = db["invariants"]
        docs = [
            {
                **inv,
                "session_id": session_id,
                "target_ip": target_ip,
                "target_id": target_id or session_id,
                "created_at": datetime.now(timezone.utc),
            }
            for inv in invariants
        ]
        if docs:
            await collection.insert_many(docs)
    except Exception as exc:
        logger.warning("_store_invariants_mongo failed: %s", exc)


async def recall_invariants(
    target_ip: str,
    n_results: int = 10,
) -> List[Dict[str, Any]]:
    """Recall invariants for a target IP across all past sessions."""
    try:
        collection = await get_invariants_collection()
        results = await collection.query(
            query_texts=[f"runtime invariants for target {target_ip}"],
            where={"target_ip": target_ip},
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )
        items: List[Dict[str, Any]] = []
        if results and results.get("ids"):
            for i, doc_id in enumerate(results["ids"][0]):
                items.append({
                    "id": doc_id,
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "similarity": 1.0 - results["distances"][0][i],
                })
        return items
    except Exception as exc:
        logger.warning("recall_invariants failed: %s", exc)
        return []
