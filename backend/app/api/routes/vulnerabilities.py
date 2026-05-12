from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.chroma_client import search_similar_vulnerabilities
from app.database.postgres import get_db
from app.models.session import ResearchSession
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityList, VulnerabilityRead, VulnerabilitySearchResult

router = APIRouter()


@router.get("", response_model=VulnerabilityList)
async def list_vulnerabilities(
    severity: Optional[str] = Query(default=None),
    session_id: Optional[uuid.UUID] = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    query = select(Vulnerability)
    count_query = select(func.count()).select_from(Vulnerability)

    filters: Dict[str, Any] = {}

    if severity:
        query = query.where(Vulnerability.severity == severity)
        count_query = count_query.where(Vulnerability.severity == severity)
        filters["severity"] = severity

    if session_id:
        query = query.where(Vulnerability.session_id == session_id)
        count_query = count_query.where(Vulnerability.session_id == session_id)
        filters["session_id"] = str(session_id)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    query = query.order_by(Vulnerability.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    vulns = result.scalars().all()

    return {"items": vulns, "total": total, "filters": filters}


@router.get("/search", response_model=VulnerabilitySearchResult)
async def search_vulnerabilities(
    q: str = Query(..., min_length=1),
    n: int = Query(default=10, ge=1, le=50),
) -> Dict[str, Any]:
    try:
        results = await search_similar_vulnerabilities(q, n_results=n)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ChromaDB search failed: {str(exc)}")

    return {"items": results, "query": q}


@router.get("/novel")
async def list_novel_vulnerabilities(
    session_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """v7.x — sandbox-verified PoC findings for the Novel Vulnerabilities tab.

    Definition: verification_status in {confirmed, exploited} AND tool_used
    contains forge_runner / payload_swarm / ai_request_forge — the same
    three-way criterion the CSV `novel` column uses. Plus is_zero_day
    findings get included regardless of verification path.

    NOTE: this route is declared BEFORE ``/{vuln_id}`` on purpose. FastAPI
    matches in declaration order, and the literal ``/novel`` would otherwise
    be parsed as a UUID and 422 out.
    """
    v_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.session_id == session_id)
        .order_by(Vulnerability.created_at.desc())
    )
    vulns = list(v_result.scalars().all())

    metadata_by_vuln: Dict[str, Dict[str, Any]] = {}
    try:
        from app.database.mongodb import get_vulnerability_metadata_collection
        async for doc in get_vulnerability_metadata_collection().find(
            {"session_id": str(session_id)},
        ):
            vid = doc.get("vuln_id")
            if vid:
                metadata_by_vuln[str(vid)] = doc
    except Exception:
        pass

    _SANDBOX_TOOLS = {"forge_runner", "payload_swarm", "ai_request_forge"}

    def _is_novel(v: Vulnerability) -> bool:
        if v.is_zero_day:
            return True
        if v.verification_status not in ("confirmed", "exploited"):
            return False
        meta = metadata_by_vuln.get(str(v.id), {})
        tool_used = str(meta.get("tool_used") or "")
        for t in tool_used.replace(";", ",").split(","):
            if t.strip() in _SANDBOX_TOOLS:
                return True
        return False

    novel_items: List[Dict[str, Any]] = []
    for v in vulns:
        if not _is_novel(v):
            continue
        meta = metadata_by_vuln.get(str(v.id), {})
        novel_items.append({
            "id": str(v.id),
            "title": v.title or "",
            "severity": v.severity or "",
            "cvss_score": v.cvss_score,
            "verification_status": v.verification_status or "",
            "is_zero_day": bool(v.is_zero_day),
            "affected_service": v.affected_service or "",
            "port": v.port,
            "endpoint": str(meta.get("endpoint") or ""),
            "tool_used": str(meta.get("tool_used") or ""),
            "exploit_code": (v.exploit_code or "")[:8000],
            "remediation": v.remediation or "",
            "cve_ids": list(v.cve_ids or []),
            "mitre_techniques": list(v.mitre_techniques or []),
            "created_at": v.created_at.isoformat() if v.created_at else "",
        })

    return {
        "session_id": str(session_id),
        "total_findings": len(vulns),
        "novel_count": len(novel_items),
        "items": novel_items,
    }


@router.get("/{vuln_id}", response_model=VulnerabilityRead)
async def get_vulnerability(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Vulnerability:
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.get("/{vuln_id}/evidence")
async def get_vulnerability_evidence(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """T27 — Evidence-flow view backing data.

    Returns the cited ``evidence_for`` strings + ``verification_output`` audit
    trail from Postgres, plus the candidate tool_outputs from MongoDB that
    were produced by the tool recorded in vulnerability_metadata. Good
    enough for an operator to click through from a confirmed finding to the
    raw tool output that produced it — even though evidence_for is stored as
    free text and there's no hard foreign-key link.
    """
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    from app.database.mongodb import (
        get_tool_outputs_collection,
        get_vulnerability_metadata_collection,
    )

    meta_doc = await get_vulnerability_metadata_collection().find_one(
        {"vuln_id": str(vuln_id)}
    )
    evidence_for = (meta_doc or {}).get("evidence_for", []) or []
    tool_used = (meta_doc or {}).get("tool", "") or ""
    endpoint = (meta_doc or {}).get("endpoint", "") or ""
    technique_tag = (meta_doc or {}).get("technique_tag", "") or ""

    candidate_tool_outputs: List[Dict[str, Any]] = []
    if tool_used:
        # Candidates: same session + same tool, newest 10.
        cursor = (
            get_tool_outputs_collection()
            .find({"session_id": str(vuln.session_id), "tool_name": tool_used})
            .sort("timestamp", -1)
            .limit(10)
        )
        async for doc in cursor:
            doc["_id"] = str(doc.get("_id", ""))
            raw = doc.get("raw_output") or ""
            if isinstance(raw, str) and len(raw) > 4000:
                doc["raw_output"] = raw[:4000] + "\n[...truncated]"
            candidate_tool_outputs.append(doc)

    return {
        "vuln_id": str(vuln_id),
        "title": vuln.title,
        "severity": vuln.severity,
        "verification_status": vuln.verification_status,
        "verification_output": vuln.verification_output,
        "evidence_for": evidence_for,
        "endpoint": endpoint,
        "technique_tag": technique_tag,
        "tool_used": tool_used,
        "candidate_tool_outputs": candidate_tool_outputs,
    }


# Custom-script tools — these are what we surface FIRST when explaining how a
# finding was identified, because they represent agent-authored creative work
# (vs. a stock scanner just reporting a default-rule match).
_CUSTOM_SCRIPT_TOOLS = {
    "forge_runner", "payload_swarm", "ai_request_forge", "instrument_trace",
    "crypto_padding_oracle", "crypto_bleichenbacher", "crypto_ecdsa_nonce_reuse",
    "crypto_length_extension", "crypto_rsa_low_e", "crypto_lattice",
    "crypto_jwt_confusion",
}


def _evidence_overlap_score(evidence_for: List[str], raw_output: str) -> int:
    """How many evidence_for snippets appear (substring) in this tool output.

    Cheap but effective heuristic — the agent's evidence_for entries quote the
    tool result verbatim, so a literal substring match is a strong signal that
    THIS tool call is what produced the cited evidence.
    """
    if not evidence_for or not raw_output:
        return 0
    out = raw_output.lower()
    score = 0
    for snippet in evidence_for:
        if not snippet:
            continue
        # Take a 30-80 char fingerprint from each snippet — long enough to be
        # specific, short enough to survive minor formatting differences.
        s = str(snippet).strip().lower()
        for window in (s[:80], s[:50], s[:30]):
            if window and len(window) >= 12 and window in out:
                score += 1
                break
    return score


@router.get("/{vuln_id}/identification")
async def get_vulnerability_identification(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Explain how this finding was identified.

    Joins the vulnerability with (a) the driving hypothesis, (b) the
    custom-script tool calls whose output produced its evidence, and (c) a
    plain answer to "is this a known vulnerability?". Powers the click-to-
    explain dialog on the Findings tab.
    """
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    from app.database.mongodb import (
        get_hypothesis_journals_collection,
        get_tool_outputs_collection,
        get_vulnerability_metadata_collection,
    )

    meta = await get_vulnerability_metadata_collection().find_one({"vuln_id": str(vuln_id)}) or {}
    evidence_for = meta.get("evidence_for", []) or []
    tool_used = meta.get("tool", "") or ""
    endpoint = meta.get("endpoint", "") or ""
    technique_tag = meta.get("technique_tag", "") or ""

    # 1 ─ Driving hypothesis. Prefer same attack_chain_id + confirmed status.
    # Fall back to the most-recent confirmed hypothesis whose statement
    # overlaps the vuln title or technique tag.
    driving_hypothesis: Optional[Dict[str, Any]] = None
    hyp_coll = get_hypothesis_journals_collection()
    if vuln.attack_chain_id:
        cand = await hyp_coll.find_one(
            {
                "session_id": str(vuln.session_id),
                "attack_chain_id": vuln.attack_chain_id,
                "status": "confirmed",
            },
            sort=[("confidence", -1), ("updated_at", -1)],
        )
        if cand:
            driving_hypothesis = cand
    if driving_hypothesis is None:
        # Title-substring match: pick the hypothesis whose statement shares the
        # most distinctive words with the vuln title or technique tag.
        title_lower = (vuln.title or "").lower()
        tag_lower = (technique_tag or "").lower()
        cursor = hyp_coll.find(
            {"session_id": str(vuln.session_id), "status": "confirmed"}
        ).sort("updated_at", -1).limit(40)
        best = None
        best_score = 0
        async for doc in cursor:
            stmt = (doc.get("statement") or "").lower()
            score = 0
            # Reward overlap of >5-char tokens
            for tok in {*title_lower.split(), *tag_lower.split("-")}:
                tok = tok.strip(".,:;()[]")
                if len(tok) >= 5 and tok in stmt:
                    score += 1
            if score > best_score:
                best_score = score
                best = doc
        if best and best_score >= 1:
            driving_hypothesis = best

    if driving_hypothesis:
        driving_hypothesis = {
            "hyp_id": driving_hypothesis.get("hyp_id"),
            "statement": driving_hypothesis.get("statement"),
            "confidence": driving_hypothesis.get("confidence"),
            "status": driving_hypothesis.get("status"),
            "evidence_for": driving_hypothesis.get("evidence_for", []) or [],
            "evidence_against": driving_hypothesis.get("evidence_against", []) or [],
            "next_test": driving_hypothesis.get("next_test"),
            "falsification_criteria": driving_hypothesis.get("falsification_criteria"),
            "attack_chain_id": driving_hypothesis.get("attack_chain_id"),
            "updated_at": str(driving_hypothesis.get("updated_at", "")),
        }

    # 2 ─ Driving tool calls. Score every same-session tool output by
    # evidence_for substring overlap. Custom-script tools get a +1 base bonus
    # so when overlap ties, the agent-authored payload surfaces first.
    tool_coll = get_tool_outputs_collection()
    cursor = tool_coll.find({"session_id": str(vuln.session_id)}).sort("timestamp", -1).limit(200)
    scored: List[Dict[str, Any]] = []
    async for doc in cursor:
        raw = doc.get("raw_output") or ""
        score = _evidence_overlap_score(evidence_for, raw if isinstance(raw, str) else "")
        if doc.get("tool_name") == tool_used:
            score += 2  # the agent told us THIS tool produced the evidence
        if doc.get("tool_name") in _CUSTOM_SCRIPT_TOOLS:
            score += 1
        if score > 0:
            doc["_score"] = score
            scored.append(doc)
    scored.sort(key=lambda d: (-d.get("_score", 0), d.get("timestamp", "")))
    driving_tool_calls: List[Dict[str, Any]] = []
    for doc in scored[:5]:
        raw = doc.get("raw_output") or ""
        if isinstance(raw, str) and len(raw) > 4000:
            raw = raw[:4000] + "\n[...truncated]"
        params = doc.get("params") or {}
        # Trim payload params to bound response size
        if isinstance(params, dict):
            for k in ("code", "template_code", "body"):
                if k in params and isinstance(params[k], str) and len(params[k]) > 8000:
                    params[k] = params[k][:8000] + "\n[...truncated]"
        parsed = doc.get("parsed_output") or {}
        driving_tool_calls.append({
            "id": str(doc.get("_id", "")),
            "tool_name": doc.get("tool_name"),
            "is_custom_script": doc.get("tool_name") in _CUSTOM_SCRIPT_TOOLS,
            "timestamp": str(doc.get("timestamp", "")),
            "duration_seconds": doc.get("duration_seconds"),
            "params": params,
            "raw_output": raw,
            "oracle_verdict": parsed.get("oracle_verdict") if isinstance(parsed, dict) else None,
            "oracle_reasons": parsed.get("oracle_reasons") if isinstance(parsed, dict) else None,
            "match_score": doc.get("_score", 0),
        })

    # 3 ─ Known-vulnerability classification.
    cve_ids = list(vuln.cve_ids or [])
    if cve_ids:
        is_known = True
        known_explanation = (
            f"Yes — this finding is tied to {len(cve_ids)} published CVE"
            f"{'s' if len(cve_ids) > 1 else ''}: {', '.join(cve_ids)}. "
            "The agent independently confirmed exploitability against this target."
        )
    elif vuln.is_zero_day:
        is_known = False
        known_explanation = (
            "No — the agent flagged this as a novel finding (no matching CVE). "
            "Treat it as a candidate zero-day until cross-referenced."
        )
    else:
        is_known = False
        known_explanation = (
            "No — no CVE was attached. The class is a well-known weakness "
            "category (e.g. SQLi, LFI, command injection) but THIS specific "
            "instance is a misconfiguration / vulnerable application surface, "
            "not a published CVE in a third-party component."
        )

    return {
        "vuln_id": str(vuln_id),
        "title": vuln.title,
        "severity": vuln.severity,
        "verification_status": vuln.verification_status,
        "confidence": vuln.confidence,
        "cve_ids": cve_ids,
        "is_zero_day": vuln.is_zero_day,
        "is_known": is_known,
        "known_explanation": known_explanation,
        "mitre_techniques": list(vuln.mitre_techniques or []),
        "endpoint": endpoint,
        "technique_tag": technique_tag,
        "tool_used": tool_used,
        "evidence_for": evidence_for,
        "driving_hypothesis": driving_hypothesis,
        "driving_tool_calls": driving_tool_calls,
    }


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------


@router.get("/export/csv")
async def export_findings_csv(
    session_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Stream session findings as a structured 8-column CSV.

    Columns (in order):
      finding         — vulnerability title (free-text)
      severity        — critical | high | medium | low | info
      target          — target IP/host (port appended when present)
      remediation     — operator-facing fix instructions
      tools_used      — comma-separated tool names that contributed
                        (drawn from vulnerability_metadata.tool_used and
                        the session's tool_outputs as a fallback)
      cvss            — numeric CVSS score (blank when not assigned)
      signature       — primary CVE id, else MITRE technique tag, else
                        the technique_tag from metadata, else "—"
      novel           — "yes" when sandbox-verified PoC (confirmed/
                        exploited + tool_used in forge_runner /
                        payload_swarm) OR is_zero_day; else "no"
    """
    sess_result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    session = sess_result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    v_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.session_id == session_id)
        .order_by(Vulnerability.created_at.asc())
    )
    vulns = list(v_result.scalars().all())

    # Pull per-vulnerability metadata from Mongo (tool_used, endpoint,
    # technique_tag) — same shape used by the identification endpoint.
    metadata_by_vuln: Dict[str, Dict[str, Any]] = {}
    try:
        from app.database.mongodb import get_vulnerability_metadata_collection
        meta_col = get_vulnerability_metadata_collection()
        async for doc in meta_col.find({"session_id": str(session_id)}):
            vid = doc.get("vuln_id")
            if vid:
                metadata_by_vuln[str(vid)] = doc
    except Exception:
        pass

    _SANDBOX_TOOLS = {"forge_runner", "payload_swarm", "ai_request_forge"}

    def _target_for(v: Vulnerability) -> str:
        """Prefer 'host:port' when both are known; fall back to session target."""
        host = (v.affected_service or session.target_ip or "").strip()
        if host and v.port is not None:
            # affected_service often already contains port (e.g. "nginx 1.2.3");
            # only append when it looks like a bare host or IP.
            if ":" not in host and not any(c.isdigit() for c in host[-5:]):
                return f"{host}:{v.port}"
        return host or (session.target_ip or "")

    def _signature_for(v: Vulnerability, meta: Dict[str, Any]) -> str:
        """Best-effort signature: CVE > MITRE > technique_tag > '—'."""
        cves = [c for c in (v.cve_ids or []) if c]
        if cves:
            return ", ".join(cves[:3])
        mitre = [m for m in (v.mitre_techniques or []) if m]
        if mitre:
            return ", ".join(mitre[:3])
        tag = str(meta.get("technique_tag") or "").strip()
        return tag if tag else "—"

    def _is_novel(v: Vulnerability, meta: Dict[str, Any]) -> bool:
        """Sandbox-verified PoC OR explicitly flagged zero-day."""
        if v.is_zero_day:
            return True
        if v.verification_status not in ("confirmed", "exploited"):
            return False
        tool_used = str(meta.get("tool_used") or "")
        if tool_used in _SANDBOX_TOOLS:
            return True
        # The 'tool_used' field can be a comma-list when multiple tools
        # contributed — accept any one that's a sandbox runner.
        for t in tool_used.split(","):
            if t.strip() in _SANDBOX_TOOLS:
                return True
        return False

    def _tools_used_for(v: Vulnerability, meta: Dict[str, Any]) -> str:
        raw = str(meta.get("tool_used") or "").strip()
        # Normalise comma-or-space-separated lists.
        parts = [t.strip() for t in raw.replace(";", ",").split(",") if t.strip()]
        # Dedup preserving order.
        seen: set = set()
        out: List[str] = []
        for t in parts:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return ", ".join(out)

    def _row_for(v: Vulnerability) -> List[str]:
        meta = metadata_by_vuln.get(str(v.id), {})
        return [
            v.title or "",
            v.severity or "",
            _target_for(v),
            v.remediation or "",
            _tools_used_for(v, meta),
            f"{v.cvss_score:.1f}" if v.cvss_score is not None else "",
            _signature_for(v, meta),
            "yes" if _is_novel(v, meta) else "no",
        ]

    headers = [
        "finding", "severity", "target", "remediation",
        "tools_used", "cvss", "signature", "novel",
    ]

    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(headers)
    for v in vulns:
        writer.writerow(_row_for(v))
    buffer.seek(0)

    filename = f"findings-{session_id}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
