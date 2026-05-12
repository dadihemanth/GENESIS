"""T89 — hypothesis market API routes.

GET  /hypotheses/{session_id}        — list hypotheses for a session
POST /hypotheses/submit              — submit a new hypothesis
PUT  /hypotheses/{id}/evidence       — add evidence for/against a hypothesis
PUT  /hypotheses/{id}/resolve        — mark a hypothesis as confirmed/refuted
GET  /hypotheses/{session_id}/allocate — get resource-allocated top hypotheses
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.hypothesis_market import (
    add_evidence,
    allocate_resources,
    get_session_hypotheses,
    resolve_hypothesis,
    submit_hypothesis,
    update_stake,
)

router = APIRouter()


class SubmitHypothesisRequest(BaseModel):
    session_id: str
    text: str
    proposer_agent: str = "user"
    hypothesis_type: str = "generic"
    confidence_stake: float = Field(default=0.5, ge=0.0, le=1.0)


class EvidenceRequest(BaseModel):
    evidence_text: str
    supports: bool


class ResolveRequest(BaseModel):
    status: str = Field(description="confirmed | refuted | abandoned")


class StakeRequest(BaseModel):
    confidence_stake: float = Field(ge=0.0, le=1.0)


@router.get("/{session_id}")
async def list_hypotheses(
    session_id: str,
    status: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Return all hypotheses for a session, sorted by confidence stake."""
    items = await get_session_hypotheses(session_id, status=status, limit=min(limit, 200))
    return {"session_id": session_id, "hypotheses": items, "count": len(items)}


@router.post("/submit")
async def submit(req: SubmitHypothesisRequest) -> Dict[str, Any]:
    """Submit a new hypothesis to the market (deduplicates semantically)."""
    hyp = await submit_hypothesis(
        session_id=req.session_id,
        text=req.text,
        proposer_agent=req.proposer_agent,
        hypothesis_type=req.hypothesis_type,
        confidence_stake=req.confidence_stake,
    )
    return hyp


@router.put("/{hypothesis_id}/evidence")
async def add_evidence_to_hypothesis(
    hypothesis_id: str,
    req: EvidenceRequest,
) -> Dict[str, Any]:
    """Add a piece of evidence for or against a hypothesis, adjusting its stake."""
    ok = await add_evidence(hypothesis_id, req.evidence_text, req.supports)
    if not ok:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return {"hypothesis_id": hypothesis_id, "updated": True}


@router.put("/{hypothesis_id}/resolve")
async def resolve(hypothesis_id: str, req: ResolveRequest) -> Dict[str, Any]:
    """Mark a hypothesis as confirmed, refuted, or abandoned."""
    ok = await resolve_hypothesis(hypothesis_id, req.status)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Invalid status or hypothesis not found: {req.status}")
    return {"hypothesis_id": hypothesis_id, "status": req.status}


@router.put("/{hypothesis_id}/stake")
async def set_stake(hypothesis_id: str, req: StakeRequest) -> Dict[str, Any]:
    """Directly set the confidence stake for a hypothesis."""
    ok = await update_stake(hypothesis_id, req.confidence_stake)
    if not ok:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return {"hypothesis_id": hypothesis_id, "confidence_stake": req.confidence_stake}


@router.get("/{session_id}/allocate")
async def get_resource_allocation(
    session_id: str,
    total_budget: int = 20,
    top_n: int = 3,
) -> Dict[str, Any]:
    """Return top hypotheses with allocated iteration budgets."""
    allocation = await allocate_resources(
        session_id=session_id,
        total_budget=total_budget,
        top_n=min(top_n, 10),
    )
    return {"session_id": session_id, "allocation": allocation, "total_budget": total_budget}
