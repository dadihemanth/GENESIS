"""T103 — provenance_recorder: full reasoning trace per confirmed finding.

On vulnerability confirmation, traces back through agent_thoughts and
tool_outputs to reconstruct the chain:
  signals → hypotheses → probes → evidence → confirmed finding

The compressed chain is stored in the `provenance` ChromaDB collection for
semantic recall, enabling future sessions to learn *how* findings were made.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.chroma_client import get_provenance_collection
from app.database.mongodb import (
    get_agent_thoughts_collection,
    get_tool_outputs_collection,
    get_vulnerability_metadata_collection,
)

logger = logging.getLogger(__name__)


async def record_provenance(
    session_id: str,
    finding_id: str,
    finding_title: str = "",
    finding_severity: str = "",
) -> Optional[Dict[str, Any]]:
    """Build and store a provenance chain for a confirmed finding.

    Returns the stored provenance dict, or None on failure.
    """
    try:
        chain = await _build_chain(session_id, finding_id)
        if not chain:
            return None

        compressed = _compress_chain(chain, finding_title, finding_severity)
        await _store_in_chroma(finding_id, session_id, compressed, len(chain))
        await _store_in_mongo(finding_id, session_id, chain, compressed)

        logger.info(
            "provenance_recorder: stored chain for finding=%s (steps=%d)",
            finding_id, len(chain),
        )
        return compressed
    except Exception as exc:
        logger.warning("record_provenance failed: %s", exc)
        return None


async def get_provenance(finding_id: str, session_id: str = "") -> Optional[Dict[str, Any]]:
    """Retrieve the stored provenance chain for a finding."""
    try:
        # Try MongoDB first (full chain)
        meta_coll = get_vulnerability_metadata_collection()
        query: Dict[str, Any] = {"vuln_id": finding_id, "provenance": {"$exists": True}}
        if session_id:
            query["session_id"] = session_id
        doc = await meta_coll.find_one(query)
        if doc:
            return doc.get("provenance")
    except Exception as exc:
        logger.debug("mongo provenance lookup failed: %s", exc)
    return None


async def search_similar_provenances(
    query: str,
    n_results: int = 5,
) -> List[Dict[str, Any]]:
    """Recall provenance chains semantically similar to the query."""
    try:
        collection = await get_provenance_collection()
        results = await collection.query(
            query_texts=[query],
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
        logger.warning("search_similar_provenances failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _build_chain(session_id: str, finding_id: str) -> List[Dict[str, Any]]:
    """Reconstruct the reasoning chain from MongoDB collections."""
    chain: List[Dict[str, Any]] = []

    # 1. Pull tool outputs that mention this finding
    try:
        tool_coll = get_tool_outputs_collection()
        cursor = tool_coll.find(
            {"session_id": session_id},
        ).sort("timestamp", 1).limit(100)
        async for doc in cursor:
            output_str = str(doc.get("output", ""))
            if finding_id in output_str or (len(chain) < 5):
                chain.append({
                    "step_type": "tool_call",
                    "tool": doc.get("tool_name", ""),
                    "timestamp": str(doc.get("timestamp", "")),
                    "output_preview": output_str[:200],
                })
    except Exception as exc:
        logger.debug("tool outputs fetch failed: %s", exc)

    # 2. Pull agent thoughts in temporal order
    try:
        thoughts_coll = get_agent_thoughts_collection()
        cursor = thoughts_coll.find(
            {"session_id": session_id},
        ).sort("timestamp", 1).limit(50)
        async for doc in cursor:
            content = str(doc.get("content", ""))
            # Include thoughts that reference the finding ID or key signals
            if finding_id in content or any(
                kw in content.lower() for kw in ["hypothesis", "evidence", "confirmed", "exploited"]
            ):
                chain.append({
                    "step_type": "agent_thought",
                    "content_preview": content[:300],
                    "timestamp": str(doc.get("timestamp", "")),
                })
    except Exception as exc:
        logger.debug("agent thoughts fetch failed: %s", exc)

    # Sort by timestamp
    chain.sort(key=lambda x: x.get("timestamp", ""))
    return chain[:30]  # cap at 30 steps


def _compress_chain(
    chain: List[Dict[str, Any]],
    finding_title: str,
    finding_severity: str,
) -> Dict[str, Any]:
    """Compress a full chain into a summary for ChromaDB embedding."""
    tool_names = [s["tool"] for s in chain if s.get("step_type") == "tool_call" and s.get("tool")]
    thought_count = sum(1 for s in chain if s.get("step_type") == "agent_thought")
    key_thoughts = [
        s["content_preview"]
        for s in chain
        if s.get("step_type") == "agent_thought"
    ][:3]

    return {
        "finding_title": finding_title,
        "finding_severity": finding_severity,
        "chain_depth": len(chain),
        "tools_used": list(dict.fromkeys(tool_names))[:10],
        "thought_count": thought_count,
        "key_reasoning": key_thoughts,
        "compressed_at": datetime.now(timezone.utc).isoformat(),
    }


async def _store_in_chroma(
    finding_id: str,
    session_id: str,
    compressed: Dict[str, Any],
    chain_depth: int,
) -> None:
    try:
        collection = await get_provenance_collection()
        doc_id = f"prov-{finding_id[:16]}-{uuid.uuid4().hex[:6]}"
        document = (
            f"Finding: {compressed.get('finding_title', '')}\n"
            f"Severity: {compressed.get('finding_severity', '')}\n"
            f"Tools used: {', '.join(compressed.get('tools_used', []))}\n"
            f"Key reasoning: {' | '.join(compressed.get('key_reasoning', []))}"
        )
        await collection.add(
            ids=[doc_id],
            documents=[document],
            metadatas=[{
                "finding_id": finding_id,
                "session_id": session_id,
                "chain_depth": chain_depth,
                "finding_severity": compressed.get("finding_severity", ""),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }],
        )
    except Exception as exc:
        logger.debug("provenance chroma store failed: %s", exc)


async def _store_in_mongo(
    finding_id: str,
    session_id: str,
    chain: List[Dict[str, Any]],
    compressed: Dict[str, Any],
) -> None:
    try:
        meta_coll = get_vulnerability_metadata_collection()
        await meta_coll.update_one(
            {"vuln_id": finding_id, "session_id": session_id},
            {
                "$set": {
                    "provenance": {
                        "compressed": compressed,
                        "chain": chain,
                        "recorded_at": datetime.now(timezone.utc),
                    }
                }
            },
            upsert=True,
        )
    except Exception as exc:
        logger.debug("provenance mongo store failed: %s", exc)
