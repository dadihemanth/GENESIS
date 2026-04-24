from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.chroma_client import get_chroma_client
from app.database.mongodb import get_vulnerability_metadata_collection
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

_SESSION_COLLECTION = "attack_patterns"
_TECHNIQUE_COLLECTION = "attack_techniques"

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
        self, target_fingerprint: str, n: int = 5
    ) -> List[Dict[str, Any]]:
        try:
            collection = await _get_session_collection()
            results = await collection.query(
                query_texts=[target_fingerprint],
                n_results=n,
                include=["documents", "metadatas", "distances"],
            )
            items: List[Dict[str, Any]] = []
            if results and results.get("ids"):
                ids = results["ids"][0]
                docs = results.get("documents", [[]])[0]
                metas = results.get("metadatas", [[]])[0]
                distances = results.get("distances", [[]])[0]
                for i, doc_id in enumerate(ids):
                    items.append(
                        {
                            "id": doc_id,
                            "document": docs[i] if i < len(docs) else "",
                            "metadata": metas[i] if i < len(metas) else {},
                            "similarity": 1.0 - (distances[i] if i < len(distances) else 1.0),
                        }
                    )
            return items
        except Exception as exc:
            logger.warning("IntelligenceLibrary.recall_patterns failed: %s", exc)
            return []

    async def recall_techniques(
        self, target_fingerprint: str, n: int = 8
    ) -> List[Dict[str, Any]]:
        """Return up to `n` per-technique records seen on fingerprint-similar targets.

        Each record carries a `success` flag so callers can distinguish techniques
        that worked from techniques that were tried and fell flat.
        """
        try:
            collection = await _get_technique_collection()
            results = await collection.query(
                query_texts=[target_fingerprint],
                n_results=n,
                include=["documents", "metadatas", "distances"],
            )
            items: List[Dict[str, Any]] = []
            if results and results.get("ids"):
                ids = results["ids"][0]
                docs = results.get("documents", [[]])[0]
                metas = results.get("metadatas", [[]])[0]
                distances = results.get("distances", [[]])[0]
                for i, doc_id in enumerate(ids):
                    meta = metas[i] if i < len(metas) else {}
                    items.append(
                        {
                            "id": doc_id,
                            "document": docs[i] if i < len(docs) else "",
                            "metadata": meta,
                            "similarity": 1.0 - (distances[i] if i < len(distances) else 1.0),
                            "success": bool(meta.get("success", False)),
                        }
                    )
            return items
        except Exception as exc:
            logger.warning("IntelligenceLibrary.recall_techniques failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Store (write path)
    # ------------------------------------------------------------------
    async def store_session_patterns(self, session_id: str, db: AsyncSession) -> None:
        try:
            result = await db.execute(
                select(Vulnerability).where(Vulnerability.session_id == uuid.UUID(session_id))
            )
            all_vulns = result.scalars().all()
            if not all_vulns:
                return

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
