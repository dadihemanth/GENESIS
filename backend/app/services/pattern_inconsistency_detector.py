"""validation milestone 3 — pattern_inconsistency_detector: cross-file inconsistency analysis.

The validated scanner insight: the IKEv2 double-free (CVE-2026-33824) spanned 6 files and
was only visible by comparing the CORRECT pattern in ike_D.c against the
INCORRECT pattern in ike_A.c/ike_C.c. The correct version performing the same
operation is the strongest evidence that the incorrect site is a bug.

This module implements that capability:
1. When a candidate finding is stored, the source_corpus ChromaDB collection
   is queried for all code chunks performing semantically similar operations
   (same struct type, same operation class: free/alloc/auth-check/lock-acquire).
2. The cluster of similar sites is sent to the LLM: "Compare these N code sites
   performing the same operation. Which site(s) are done differently from the
   majority? Is the deviation a vulnerability?"
3. If a cross-site inconsistency is confirmed, the candidate receives a
   `create_validation_verdict(verdict="support", ...)` with
   `cross_site_confirmed=True`, boosting its chance of promotion.

The detector is a standalone async service. It is called:
  - From multi_agent_orchestrator when code/reveng agents emit CANDIDATE_FINDING
  - From validated_scanner.store_candidate (non-blocking fire-and-forget)
  - Manually via `check_pending_candidates(session_id, client, model)`
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Minimum number of similar code sites needed to run the inconsistency check.
# With fewer than this we can't establish a "majority" pattern.
_MIN_SITES = 3
# Maximum sites to include in one LLM call (cost/context guard)
_MAX_SITES = 12
# ChromaDB query result count
_CHROMA_N_RESULTS = 15

_COMPARE_SYSTEM = (
    "You are a security code auditor specializing in cross-file inconsistency "
    "analysis. You will be given N code snippets from different files that all "
    "perform the same operation (e.g., release a reference, acquire a lock, "
    "validate input). Your task is to:\n"
    "1. Identify the MAJORITY pattern — how most sites perform this operation.\n"
    "2. Find any sites that deviate from the majority.\n"
    "3. Determine whether the deviation is a vulnerability.\n\n"
    "The strongest evidence of a bug is when the correct version exists nearby: "
    "if site A releases the reference before using the pointer AND site B (doing "
    "the same operation) uses the pointer before releasing it, site B is the bug.\n\n"
    "Respond with JSON:\n"
    "{\n"
    "  \"majority_pattern\": \"<description of correct approach>\",\n"
    "  \"deviating_sites\": [\n"
    "    {\"file\": \"<file_path>\", \"deviation\": \"<what is different>\", "
    "\"is_vulnerability\": true|false, \"vulnerability_class\": \"<class>\"}\n"
    "  ],\n"
    "  \"cross_site_confirmed\": true|false,\n"
    "  \"confidence\": 0.0-1.0,\n"
    "  \"explanation\": \"<why this is or is not a bug>\"\n"
    "}"
)


async def check_candidate(
    session_id: str,
    candidate: Dict[str, Any],
    client: Any,
    model: str,
) -> Optional[Dict[str, Any]]:
    """Run cross-file pattern inconsistency check for a single candidate.

    Returns the detector result dict, or None if the check was skipped or
    produced no useful signal. When `cross_site_confirmed` is True in the
    result, a `support` validation verdict is added to the candidate.
    """
    if client is None:
        return None

    hypothesis = str(candidate.get("hypothesis") or candidate.get("title") or "")
    attack_class = str(candidate.get("attack_class") or "")
    candidate_id = str(candidate.get("candidate_id") or candidate.get("_id") or "")
    if not hypothesis or not candidate_id:
        return None

    # Build a semantic query from the candidate's hypothesis + attack class
    query = f"{attack_class} {hypothesis}"[:500]

    # Search source_corpus for semantically similar code patterns
    similar_chunks = await _query_source_corpus(session_id, query)
    if len(similar_chunks) < _MIN_SITES:
        logger.debug(
            "pattern_inconsistency: session=%s candidate=%s — only %d similar sites, skipping",
            session_id, candidate_id, len(similar_chunks),
        )
        return None

    # Build the comparison prompt
    sites_text = _format_sites(similar_chunks[:_MAX_SITES])
    user_msg = (
        f"Session: {session_id}\n"
        f"Candidate finding: {hypothesis[:500]}\n"
        f"Attack class: {attack_class or 'unknown'}\n\n"
        f"The following {len(similar_chunks[:_MAX_SITES])} code sites all perform "
        "a similar operation. Compare them:\n\n"
        f"{sites_text}\n\n"
        "Identify the majority pattern and any deviating sites. "
        "If a deviation is a vulnerability, set cross_site_confirmed=true."
    )

    try:
        resp = await client.messages.create(
            model=model,
            max_tokens=1200,
            timeout=90.0,
            system=_COMPARE_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        )
        text = ""
        for block in (resp.content or []):
            if hasattr(block, "text"):
                text += block.text
        text = text.strip()
    except Exception as exc:
        logger.warning("pattern_inconsistency LLM call failed: %s", exc)
        return None

    import json as _json
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        result = _json.loads(text[start:end + 1])
    except Exception:
        return None

    cross_site_confirmed = bool(result.get("cross_site_confirmed", False))
    confidence = float(result.get("confidence", 0.0))
    explanation = str(result.get("explanation", ""))[:2000]

    if cross_site_confirmed and confidence >= 0.5:
        # Emit a support verdict so the candidate can be promoted
        try:
            from app.services.validated_scanner import create_validation_verdict
            await create_validation_verdict(
                session_id=session_id,
                candidate_id=candidate_id,
                verdict="support",
                validator="pattern_inconsistency_detector",
                reasoning=(
                    f"Cross-file pattern inconsistency confirmed (confidence={confidence:.2f}). "
                    f"Majority pattern: {result.get('majority_pattern', '')[:300]}. "
                    f"{explanation}"
                ),
                missing_evidence=[],
                target_proof_action={
                    "type": "cross_site_confirmed",
                    "deviating_sites": result.get("deviating_sites", []),
                },
            )
        except Exception as exc:
            logger.warning("pattern_inconsistency: verdict insert failed: %s", exc)

        logger.info(
            "pattern_inconsistency: session=%s candidate=%s CONFIRMED cross_site "
            "(confidence=%.2f, sites=%d)",
            session_id, candidate_id, confidence, len(similar_chunks),
        )
    else:
        logger.debug(
            "pattern_inconsistency: session=%s candidate=%s — no inconsistency "
            "(cross_site=%s, conf=%.2f)",
            session_id, candidate_id, cross_site_confirmed, confidence,
        )

    result["session_id"] = session_id
    result["candidate_id"] = candidate_id
    result["sites_compared"] = len(similar_chunks[:_MAX_SITES])
    return result


async def check_pending_candidates(
    session_id: str,
    client: Any,
    model: str,
    limit: int = 20,
) -> int:
    """Run the cross-file inconsistency check on all unvalidated candidates.

    Called by the orchestrator at the start of Phase 2 or on a periodic
    backstop. Returns the number of candidates that received support verdicts.
    """
    from app.database.mongodb import get_candidate_findings_collection

    candidates = await get_candidate_findings_collection().find(
        {"session_id": session_id, "status": {"$nin": ["promoted", "ruled_out"]}},
    ).sort("confidence", -1).limit(limit).to_list(length=limit)

    confirmed = 0
    for cand in candidates:
        result = await check_candidate(session_id, cand, client, model)
        if result and result.get("cross_site_confirmed"):
            confirmed += 1

    logger.info(
        "pattern_inconsistency: check_pending session=%s candidates=%d confirmed=%d",
        session_id, len(candidates), confirmed,
    )
    return confirmed


async def _query_source_corpus(session_id: str, query: str) -> List[Dict[str, Any]]:
    """Query ChromaDB source_corpus for similar code patterns in this session."""
    try:
        from app.database.chroma_client import get_source_corpus_collection
        collection = await get_source_corpus_collection()
        results = await collection.query(
            query_texts=[query],
            n_results=_CHROMA_N_RESULTS,
            where={"session_id": session_id},
        )
        chunks: List[Dict[str, Any]] = []
        docs = (results.get("documents") or [[]])[0]
        metas = (results.get("metadatas") or [[]])[0]
        for doc, meta in zip(docs, metas):
            chunks.append({"code": doc, "file": (meta or {}).get("file_path", "unknown")})
        return chunks
    except Exception as exc:
        logger.debug("source_corpus query failed: %s", exc)
        return []


def _format_sites(chunks: List[Dict[str, Any]]) -> str:
    """Format code chunks into a numbered list for LLM comparison."""
    parts: List[str] = []
    for i, chunk in enumerate(chunks, 1):
        file_path = chunk.get("file", "unknown")
        code = (chunk.get("code") or "")[:600]
        parts.append(f"[Site {i}] File: {file_path}\n```\n{code}\n```")
    return "\n\n".join(parts)
