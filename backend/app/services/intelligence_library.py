from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.chroma_client import get_chroma_client
from app.database.mongodb import (
    get_agent_thoughts_collection,
    get_target_briefs_collection,
    get_tool_outputs_collection,
    get_vulnerability_metadata_collection,
)
from app.models.vulnerability import Vulnerability
from app.models.session import ResearchSession

logger = logging.getLogger(__name__)

_SESSION_COLLECTION = "attack_patterns"
_TECHNIQUE_COLLECTION = "attack_techniques"
_REFLECTION_COLLECTION = "session_reflections"

# When a session stores a technique that was tried but did not yield a confirmed
# finding, we keep it as a negative signal so future runs do not repeat dead ends.
_POSITIVE_STATUSES = {"confirmed", "exploited"}
_NEGATIVE_STATUSES = {"unverified", "disputed"}


async def _get_session_collection() -> Any:
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name=_SESSION_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )


async def _get_technique_collection() -> Any:
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name=_TECHNIQUE_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )


async def _get_reflection_collection() -> Any:
    """ChromaDB collection holding per-session strategic reflections (T8).

    Unlike attack_techniques (which stores *what* worked), this stores the
    *how* — "I wasted 8 iterations before pivoting", "the giveaway was in the
    404 page all along". Recalled alongside techniques on future session starts.
    """
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name=_REFLECTION_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )


def _parse_chroma_results(results: Any, include_success: bool = False) -> List[Dict[str, Any]]:
    """Convert a raw ChromaDB query result dict into a list of item dicts."""
    items: List[Dict[str, Any]] = []
    if not (results and results.get("ids")):
        return items
    ids = results["ids"][0]
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]
    for i, doc_id in enumerate(ids):
        meta = metas[i] if i < len(metas) else {}
        item: Dict[str, Any] = {
            "id": doc_id,
            "document": docs[i] if i < len(docs) else "",
            "metadata": meta,
            "similarity": 1.0 - (distances[i] if i < len(distances) else 1.0),
        }
        if include_success:
            item["success"] = bool(meta.get("success", False))
        items.append(item)
    return items


class IntelligenceLibrary:
    """Cross-session memory for GENESIS.

    Two ChromaDB collections:
      - `attack_patterns`   : one row per completed session (aggregate fingerprint)
      - `attack_techniques` : one row per technique tried, positive or negative
    """

    # ------------------------------------------------------------------
    # Recall (read path)
    # ------------------------------------------------------------------
    async def recall_patterns(
        self, target_fingerprint: str, n: int = 5, target_ip: str = ""
    ) -> List[Dict[str, Any]]:
        try:
            collection = await _get_session_collection()
            # Exact-IP lookup first — works for repeat scans of the same target.
            # ChromaDB still requires query_texts even when using a where filter.
            if target_ip:
                try:
                    ip_results = await collection.query(
                        query_texts=[target_fingerprint],
                        where={"target_ip": target_ip},
                        n_results=n,
                        include=["documents", "metadatas", "distances"],
                    )
                    return _parse_chroma_results(ip_results)
                except Exception as exc:
                    logger.debug("where-filter failed for target_ip=%s: %s — semantic fallback", target_ip, exc)
            # Semantic fallback for brand-new targets similar to past ones.
            results = await collection.query(
                query_texts=[target_fingerprint],
                n_results=n,
                include=["documents", "metadatas", "distances"],
            )
            return _parse_chroma_results(results)
        except Exception as exc:
            logger.warning("IntelligenceLibrary.recall_patterns failed: %s", exc)
            return []

    async def recall_reflections(
        self, target_fingerprint: str, n: int = 3, target_ip: str = ""
    ) -> List[Dict[str, Any]]:
        """Return up to `n` strategic reflections from past sessions on similar targets.

        Complements `recall_techniques` — techniques are *what* to try, reflections
        are lessons about *how to approach* similar targets (sequencing, pitfalls,
        dead-end patterns).
        """
        try:
            collection = await _get_reflection_collection()
            if target_ip:
                try:
                    ip_results = await collection.query(
                        query_texts=[target_fingerprint],
                        where={"target_ip": target_ip},
                        n_results=n,
                        include=["documents", "metadatas", "distances"],
                    )
                    return _parse_chroma_results(ip_results)
                except Exception as exc:
                    logger.debug("where-filter failed for target_ip=%s: %s — semantic fallback", target_ip, exc)
            results = await collection.query(
                query_texts=[target_fingerprint],
                n_results=n,
                include=["documents", "metadatas", "distances"],
            )
            return _parse_chroma_results(results)
        except Exception as exc:
            logger.warning("IntelligenceLibrary.recall_reflections failed: %s", exc)
            return []

    async def recall_techniques(
        self, target_fingerprint: str, n: int = 8, target_ip: str = ""
    ) -> List[Dict[str, Any]]:
        """Return up to `n` per-technique records seen on fingerprint-similar targets.

        Each record carries a `success` flag so callers can distinguish techniques
        that worked from techniques that were tried and fell flat.
        """
        try:
            collection = await _get_technique_collection()
            if target_ip:
                try:
                    ip_results = await collection.query(
                        query_texts=[target_fingerprint],
                        where={"target_ip": target_ip},
                        n_results=n,
                        include=["documents", "metadatas", "distances"],
                    )
                    return _parse_chroma_results(ip_results, include_success=True)
                except Exception as exc:
                    logger.debug("where-filter failed for target_ip=%s: %s — semantic fallback", target_ip, exc)
            results = await collection.query(
                query_texts=[target_fingerprint],
                n_results=n,
                include=["documents", "metadatas", "distances"],
            )
            return _parse_chroma_results(results, include_success=True)
        except Exception as exc:
            logger.warning("IntelligenceLibrary.recall_techniques failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Store (write path)
    # ------------------------------------------------------------------
    async def store_session_patterns(
        self, session_id: str, db: AsyncSession, target_ip: str = ""
    ) -> None:
        try:
            result = await db.execute(
                select(Vulnerability).where(Vulnerability.session_id == uuid.UUID(session_id))
            )
            all_vulns = result.scalars().all()
            if not all_vulns:
                return

            # Resolve target_ip if caller didn't supply it (e.g. direct API calls).
            if not target_ip:
                sess_result = await db.execute(
                    select(ResearchSession).where(ResearchSession.id == uuid.UUID(session_id))
                )
                sess_obj = sess_result.scalar_one_or_none()
                target_ip = (sess_obj.target_ip or "") if sess_obj else ""

            positive_vulns = [
                v for v in all_vulns
                if (v.verification_status or "").lower() in _POSITIVE_STATUSES
            ]
            negative_vulns = [
                v for v in all_vulns
                if (v.verification_status or "").lower() in _NEGATIVE_STATUSES
            ]

            # ---- 1. Session-level pattern (aggregate) ---------------------
            services = list({v.affected_service for v in positive_vulns if v.affected_service})
            techniques = list({t for v in positive_vulns for t in (v.mitre_techniques or [])})
            max_cvss = max((v.cvss_score or 0.0) for v in positive_vulns) if positive_vulns else 0.0
            max_severity = "info"
            if positive_vulns:
                max_severity = max(
                    positive_vulns,
                    key=lambda v: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
                        (v.severity or "").lower(), 0
                    ),
                ).severity.lower()

            document_lines = [
                f"Session: {session_id}",
                f"Confirmed vulnerabilities: {len(positive_vulns)}",
                f"Services: {', '.join(services)}" if services else "Services: (none)",
                f"MITRE techniques: {', '.join(techniques)}" if techniques else "MITRE techniques: (none)",
                f"Max severity: {max_severity}",
                "Top vulnerabilities: " + ", ".join(v.title for v in positive_vulns[:5]),
                f"Dead-end techniques tried: {len(negative_vulns)}",
            ]
            document = "\n".join(document_lines)

            session_collection = await _get_session_collection()
            session_doc_id = f"session-{session_id}"
            try:
                await session_collection.delete(ids=[session_doc_id])
            except Exception:
                pass
            await session_collection.add(
                ids=[session_doc_id],
                documents=[document],
                metadatas=[{
                    "session_id": session_id,
                    "target_ip": target_ip,
                    "vuln_count": len(positive_vulns),
                    "max_severity": max_severity,
                    "max_cvss": max_cvss,
                    "services": ", ".join(services[:10]),
                    "mitre_techniques": ", ".join(techniques[:15]),
                    "negative_count": len(negative_vulns),
                }],
            )

            # ---- 2. Per-technique rows (positive + negative) --------------
            meta_docs: List[Dict[str, Any]] = []
            try:
                cursor = get_vulnerability_metadata_collection().find(
                    {"session_id": session_id}
                )
                async for doc in cursor:
                    meta_docs.append(doc)
            except Exception as exc:
                logger.debug("Vulnerability metadata read failed: %s", exc)

            meta_by_vuln: Dict[str, Dict[str, Any]] = {
                str(m.get("vuln_id", "")): m for m in meta_docs
            }

            technique_collection = await _get_technique_collection()
            add_ids: List[str] = []
            add_docs: List[str] = []
            add_metas: List[Dict[str, Any]] = []

            for v in all_vulns:
                status = (v.verification_status or "").lower()
                if status not in _POSITIVE_STATUSES and status not in _NEGATIVE_STATUSES:
                    continue
                meta = meta_by_vuln.get(str(v.id), {})
                technique_tag = (meta.get("technique_tag") or "").strip()
                endpoint = (meta.get("endpoint") or "").strip()
                tool_used = (meta.get("tool") or "").strip()
                payload = (meta.get("payload") or "").strip()

                success = status in _POSITIVE_STATUSES
                # Build a short document that recall will surface.
                doc_parts = [
                    f"Target services: {v.affected_service or 'unknown'}",
                    f"Title: {v.title}",
                    f"Technique: {technique_tag or '(untagged)'}",
                    f"Endpoint: {endpoint or '(n/a)'}",
                    f"Tool: {tool_used or '(n/a)'}",
                    f"Outcome: {'CONFIRMED' if success else status.upper()}",
                ]
                if payload:
                    doc_parts.append(f"Payload: {payload[:160]}")
                doc_text = "\n".join(doc_parts)

                doc_id = f"technique-{session_id}-{v.id}"
                add_ids.append(doc_id)
                add_docs.append(doc_text)
                add_metas.append({
                    "session_id": session_id,
                    "target_ip": target_ip,
                    "vuln_id": str(v.id),
                    "success": success,
                    "severity": (v.severity or "").lower(),
                    "technique_tag": technique_tag,
                    "endpoint": endpoint,
                    "tool": tool_used,
                    "service": v.affected_service or "",
                    "title": v.title,
                    "status": status,
                })

            if add_ids:
                try:
                    await technique_collection.delete(ids=add_ids)
                except Exception:
                    pass
                await technique_collection.add(
                    ids=add_ids,
                    documents=add_docs,
                    metadatas=add_metas,
                )
            logger.info(
                "Stored intelligence for session %s: %d positive, %d negative techniques",
                session_id, len(positive_vulns), len(negative_vulns),
            )
        except Exception as exc:
            logger.warning("IntelligenceLibrary.store_session_patterns failed: %s", exc)

    # ------------------------------------------------------------------
    # T8 — Post-session strategic reflection
    # ------------------------------------------------------------------
    async def store_session_reflection(
        self,
        session_id: str,
        db: AsyncSession,
        client: Any,
        model: str,
        target_ip: str = "",
    ) -> None:
        """Generate and persist a strategic reflection on a finished session.

        Reads the hypothesis journal, vulnerability outcomes, Target Intent
        Brief (T1), and a sample of tool calls. Asks the critic model to
        produce a compact JSON object describing what worked, what wasted
        time, and what strategic lesson generalises to similar targets.
        Stored in the `session_reflections` ChromaDB collection so future
        sessions can recall it at start.

        All failures are swallowed — reflection is strictly additive.
        """
        if client is None:
            return
        try:
            # ---- Gather transcript inputs ---------------------------------
            vuln_result = await db.execute(
                select(Vulnerability).where(Vulnerability.session_id == uuid.UUID(session_id))
            )
            vulns = vuln_result.scalars().all()

            brief_doc = await get_target_briefs_collection().find_one({"session_id": session_id})
            brief = (brief_doc or {}).get("brief") if brief_doc else None

            # Tool call timeline — first 20 calls, keep it compact
            tool_calls: List[Dict[str, Any]] = []
            tool_cursor = get_tool_outputs_collection().find(
                {"session_id": session_id}
            ).sort("timestamp", 1).limit(40)
            async for t in tool_cursor:
                tool_calls.append({
                    "tool": t.get("tool_name"),
                    "params_keys": list((t.get("params") or {}).keys())[:6],
                    "duration_s": round(t.get("duration_seconds", 0) or 0, 2),
                })

            # Pull the first confirmed/disputed/exploited titles for context
            outcomes = [
                {
                    "title": (v.title or "")[:160],
                    "severity": v.severity or "",
                    "status": v.verification_status or "",
                    "service": v.affected_service or "",
                }
                for v in vulns[:15]
            ]

            # Infer a target fingerprint string for ChromaDB embedding
            services = sorted({v.affected_service for v in vulns if v.affected_service})
            fingerprint_parts = list(services[:6])
            if isinstance(brief, dict):
                stack = brief.get("predicted_stack") or []
                if isinstance(stack, list):
                    fingerprint_parts.extend(str(s) for s in stack[:6])
            if not fingerprint_parts:
                fingerprint_parts = ["unknown-stack"]
            fingerprint = " | ".join(fingerprint_parts)

            # ---- Ask the critic model for a structured reflection ---------
            system = (
                "You are the post-session reflection agent for GENESIS MYTHOS. "
                "Read the inputs and produce a compact JSON object describing "
                "strategic lessons from this session — not technique recall, "
                "but *how to approach* similar targets next time. Keys:\n"
                "  what_worked: array of strings (approaches that yielded results)\n"
                "  wasted_effort: array of strings (approaches / iterations that went nowhere)\n"
                "  should_have_tried_sooner: array of strings\n"
                "  strategic_lesson: one sentence, the meta-lesson\n"
                "  applicable_when: object describing when this lesson applies "
                "(keys like stack, service, port — describe the fingerprint shape).\n"
                "Respond with ONLY the JSON object. No prose, no code fences."
            )
            user_content = json.dumps({
                "brief": brief,
                "outcomes": outcomes,
                "tool_calls_sample": tool_calls[:25],
                "vuln_count": len(vulns),
                "confirmed_count": sum(1 for v in vulns if (v.verification_status or "") in ("confirmed", "exploited")),
            }, default=str)[:12000]

            try:
                resp = await client.messages.create(
                    model=model,
                    max_tokens=800,
                    timeout=120.0,
                    system=system,
                    messages=[{"role": "user", "content": user_content}],
                )
            except Exception as exc:
                logger.debug("Reflection generation call failed: %s", exc)
                return

            text = ""
            for b in (resp.content or []):
                if hasattr(b, "text") and b.text:
                    text += b.text
            text = text.strip()
            if text.startswith("```"):
                text = text.split("```", 2)[1]
                if text.lower().startswith("json"):
                    text = text[4:]
                text = text.strip()
            start_b = text.find("{")
            end_b = text.rfind("}")
            if start_b == -1 or end_b == -1 or end_b <= start_b:
                return
            try:
                reflection = json.loads(text[start_b : end_b + 1])
            except Exception as exc:
                logger.debug("Reflection JSON parse failed: %s", exc)
                return
            if not isinstance(reflection, dict):
                return

            # ---- Persist to ChromaDB -------------------------------------
            doc_parts = [
                f"Target fingerprint: {fingerprint}",
                f"Strategic lesson: {str(reflection.get('strategic_lesson',''))[:400]}",
            ]
            for key in ("what_worked", "wasted_effort", "should_have_tried_sooner"):
                items = reflection.get(key) or []
                if isinstance(items, list) and items:
                    doc_parts.append(f"{key.replace('_',' ').title()}:")
                    for it in items[:5]:
                        doc_parts.append(f"- {str(it)[:200]}")
            document = "\n".join(doc_parts)

            metadata = {
                "session_id": session_id,
                "target_ip": target_ip,
                "fingerprint": fingerprint[:300],
                "strategic_lesson": str(reflection.get("strategic_lesson", ""))[:400],
                "vuln_count": len(vulns),
                "applicable_when": json.dumps(reflection.get("applicable_when", {}))[:600],
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

            collection = await _get_reflection_collection()
            doc_id = f"reflection-{session_id}"
            try:
                await collection.delete(ids=[doc_id])
            except Exception:
                pass
            await collection.add(
                ids=[doc_id],
                documents=[document],
                metadatas=[metadata],
            )
            logger.info("Stored session reflection for %s (%d chars)", session_id, len(document))
        except Exception as exc:
            logger.warning("store_session_reflection failed: %s", exc)

    # ------------------------------------------------------------------
    # Listing (admin UI)
    # ------------------------------------------------------------------
    async def list_patterns(self, page: int = 1, size: int = 20) -> Dict[str, Any]:
        try:
            collection = await _get_session_collection()
            count = await collection.count()

            if count == 0:
                return {"items": [], "total": 0, "page": page, "size": size}

            result = await collection.get(
                include=["documents", "metadatas"],
                limit=min(count, 500),
            )

            all_items = []
            if result and result.get("ids"):
                for i, doc_id in enumerate(result["ids"]):
                    meta = result["metadatas"][i] if result.get("metadatas") else {}
                    all_items.append(
                        {
                            "id": doc_id,
                            "session_id": meta.get("session_id", ""),
                            "vuln_count": meta.get("vuln_count", 0),
                            "max_severity": meta.get("max_severity", ""),
                            "max_cvss": meta.get("max_cvss", 0.0),
                            "services": meta.get("services", ""),
                            "mitre_techniques": meta.get("mitre_techniques", ""),
                            "negative_count": meta.get("negative_count", 0),
                            "document": result["documents"][i] if result.get("documents") else "",
                        }
                    )

            start = (page - 1) * size
            return {
                "items": all_items[start : start + size],
                "total": len(all_items),
                "page": page,
                "size": size,
            }
        except Exception as exc:
            logger.warning("IntelligenceLibrary.list_patterns failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "size": size}
