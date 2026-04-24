from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.chroma_client import search_similar_vulnerabilities
from app.database.postgres import get_db
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityList, VulnerabilityRead, VulnerabilitySearchResult

router = APIRouter()


@router.get("", response_model=VulnerabilityList)
async def list_vulnerabilities(
    severity: Optional[str] = Query(default=None),
    session_id: Optional[uuid.UUID] = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
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
