from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.validated_scanner import (
    build_benchmark_report,
    create_validation_verdict,
    public_doc,
    record_proof_run,
    promote_ready_candidates,
    rebuild_target_surface_graph,
    rebuild_clusters,
    store_candidate,
)

router = APIRouter()


class CandidateFindingRequest(BaseModel):
    title: str
    attack_class: str = ""
    affected_surface: str = ""
    hypothesis: str = ""
    evidence: List[str] = Field(default_factory=list)
    reachability_claim: str = ""
    proposed_proof: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.5
    severity: str = "info"
    endpoint: str = ""
    affected_service: str = ""
    candidate_kind: str = ""
    source_context: Dict[str, Any] = Field(default_factory=dict)
    reachability_context: Dict[str, Any] = Field(default_factory=dict)
    proof_plan: Dict[str, Any] = Field(default_factory=dict)
    sink: str = ""
    source_input: str = ""
    taint_path: Any = None
    invariant: Any = None
    commit_signal: Any = None


class ValidationVerdictRequest(BaseModel):
    verdict: str = Field(description="support | refute | needs-proof | disputed")
    validator: str = "manual_validator"
    reasoning: str = ""
    missing_evidence: List[str] = Field(default_factory=list)
    target_proof_action: Dict[str, Any] = Field(default_factory=dict)


class ProofRunRequest(BaseModel):
    proof_tool: str
    oracle: Any = None
    inputs: Any = None
    result: Any = None
    artifacts: List[str] = Field(default_factory=list)
    passed: Optional[bool] = None
    pass_fail_reason: str = ""


class ConfirmFindingsRequest(BaseModel):
    candidate_ids: List[str] = Field(default_factory=list)
    operator_validated: bool = False
    reason: str = ""


class BenchmarkRequest(BaseModel):
    label: str = ""
    lane: str = "hybrid"
    ground_truth: List[Any] = Field(default_factory=list)


class CompleteValidationRequest(BaseModel):
    candidate_ids: List[str] = Field(default_factory=list)
    max_candidates: int = Field(default=50, ge=1, le=500)
    force_reproof: bool = False


async def _save_promoted_vulnerability(session_id: str, vuln_data: Dict[str, Any]) -> Optional[str]:
    """Use the canonical vulnerability persistence path for manual promotion."""
    from app.services.ai_orchestrator import AIOrchestrator

    orchestrator = AIOrchestrator()
    try:
        orchestrator._app_settings = await orchestrator.get_settings()  # type: ignore[attr-defined]
    except Exception:
        orchestrator._app_settings = {}  # type: ignore[attr-defined]
    return await orchestrator._save_vulnerability(session_id, vuln_data)  # type: ignore[attr-defined]


async def _promotion_blockers(session_id: str, candidate_ids: List[str]) -> Dict[str, Any]:
    from app.database.mongodb import (
        get_candidate_findings_collection,
        get_proof_runs_collection,
        get_validation_verdicts_collection,
    )

    query: Dict[str, Any] = {"session_id": session_id}
    selected = [str(cid).strip() for cid in candidate_ids if str(cid).strip()]
    if selected:
        query["candidate_id"] = {"$in": selected}

    candidates = await get_candidate_findings_collection().find(query).to_list(length=1000)
    ids = [str(c.get("candidate_id") or "") for c in candidates if c.get("candidate_id")]
    if not ids:
        return {
            "candidate_count": 0,
            "promoted_count": 0,
            "missing_proof_count": 0,
            "missing_support_count": 0,
            "blocked_refute_count": 0,
            "live_replay_needed_count": 0,
            "examples": [],
        }

    verdicts = await get_validation_verdicts_collection().find({
        "session_id": session_id,
        "candidate_id": {"$in": ids},
    }).to_list(length=3000)
    proofs = await get_proof_runs_collection().find({
        "session_id": session_id,
        "candidate_id": {"$in": ids},
    }).to_list(length=3000)

    refuted = {
        str(v.get("candidate_id"))
        for v in verdicts
        if v.get("verdict") in {"refute", "disputed"}
    }
    passed = {str(p.get("candidate_id")) for p in proofs if p.get("passed") is True}
    live_passed = {
        str(p.get("candidate_id"))
        for p in proofs
        if p.get("passed") is True and p.get("proof_class") == "live"
    }

    summary = {
        "candidate_count": len(candidates),
        "promoted_count": sum(1 for c in candidates if c.get("status") == "promoted"),
        "missing_proof_count": 0,
        "missing_support_count": 0,
        "blocked_refute_count": 0,
        "live_replay_needed_count": 0,
        "examples": [],
    }

    for cand in candidates:
        cid = str(cand.get("candidate_id") or "")
        status = str(cand.get("status") or "")
        if status == "promoted":
            continue
        reason = ""
        if cid in refuted:
            summary["blocked_refute_count"] += 1
            reason = "blocking refute/disputed verdict"
        source_context = cand.get("source_context") if isinstance(cand.get("source_context"), dict) else {}
        proof_plan = cand.get("proof_plan") or cand.get("proposed_proof") or {}
        if not isinstance(proof_plan, dict):
            proof_plan = {}
        has_source = bool(source_context and any(source_context.get(k) for k in ("repo", "file_path", "symbol")))
        live_required = has_source and proof_plan.get("live_replay_required", True) is not False
        if live_required and cid not in live_passed:
            summary["live_replay_needed_count"] += 1
            reason = reason or "source-backed candidate still needs a live proof"
        severity = str(cand.get("severity") or "info").lower()
        if cid not in passed:
            summary["missing_proof_count"] += 1
            reason = reason or "candidate has no passing proof run or operator validation"
        if reason and len(summary["examples"]) < 5:
            summary["examples"].append({
                "candidate_id": cid,
                "title": cand.get("title") or "",
                "severity": severity,
                "status": status,
                "reason": reason,
            })
    return summary


@router.get("/sessions/{session_id}/candidates")
async def list_candidates(
    session_id: uuid.UUID,
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> Dict[str, Any]:
    from app.database.mongodb import get_candidate_findings_collection

    query: Dict[str, Any] = {"session_id": str(session_id)}
    if status:
        query["status"] = status
    docs = await (
        get_candidate_findings_collection()
        .find(query)
        .sort("created_at", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return {"session_id": str(session_id), "items": [public_doc(d) for d in docs], "total": len(docs)}


@router.post("/sessions/{session_id}/candidates", status_code=201)
async def create_candidate(
    session_id: uuid.UUID,
    body: CandidateFindingRequest,
) -> Dict[str, Any]:
    doc = await store_candidate(
        session_id=str(session_id),
        data=body.model_dump(),
        source_agent="api",
    )
    return public_doc(doc)


@router.get("/sessions/{session_id}/verdicts")
async def list_validation_verdicts(
    session_id: uuid.UUID,
    candidate_id: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> Dict[str, Any]:
    from app.database.mongodb import get_validation_verdicts_collection

    query: Dict[str, Any] = {"session_id": str(session_id)}
    if candidate_id:
        query["candidate_id"] = candidate_id
    docs = await (
        get_validation_verdicts_collection()
        .find(query)
        .sort("created_at", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return {"session_id": str(session_id), "items": [public_doc(d) for d in docs], "total": len(docs)}


@router.post("/sessions/{session_id}/candidates/{candidate_id}/verdicts", status_code=201)
async def add_validation_verdict(
    session_id: uuid.UUID,
    candidate_id: str,
    body: ValidationVerdictRequest,
) -> Dict[str, Any]:
    doc = await create_validation_verdict(
        session_id=str(session_id),
        candidate_id=candidate_id,
        verdict=body.verdict,
        validator=body.validator,
        reasoning=body.reasoning,
        missing_evidence=body.missing_evidence,
        target_proof_action=body.target_proof_action,
    )
    return public_doc(doc)


@router.get("/sessions/{session_id}/proof-runs")
async def list_proof_runs(
    session_id: uuid.UUID,
    candidate_id: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> Dict[str, Any]:
    from app.database.mongodb import get_proof_runs_collection

    query: Dict[str, Any] = {"session_id": str(session_id)}
    if candidate_id:
        query["candidate_id"] = candidate_id
    docs = await (
        get_proof_runs_collection()
        .find(query)
        .sort("created_at", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return {"session_id": str(session_id), "items": [public_doc(d) for d in docs], "total": len(docs)}


@router.post("/sessions/{session_id}/candidates/{candidate_id}/proof-runs", status_code=201)
async def add_proof_run(
    session_id: uuid.UUID,
    candidate_id: str,
    body: ProofRunRequest,
) -> Dict[str, Any]:
    doc = await record_proof_run(
        session_id=str(session_id),
        candidate_id=candidate_id,
        proof_tool=body.proof_tool,
        oracle=body.oracle,
        inputs=body.inputs,
        result=body.result,
        artifacts=body.artifacts,
        passed=body.passed,
        pass_fail_reason=body.pass_fail_reason,
    )
    return public_doc(doc)


@router.post("/sessions/{session_id}/complete-validation", status_code=202)
async def complete_validation(
    session_id: uuid.UUID,
    body: CompleteValidationRequest,
) -> Dict[str, Any]:
    """Queue proof/promotion work for candidates already present in a session."""
    sid = str(session_id)
    from app.services.tasks import complete_validation_session
    from app.services.validation_completion import create_validation_completion_job

    candidate_ids = [str(cid).strip() for cid in body.candidate_ids if str(cid).strip()]
    job = await create_validation_completion_job(
        session_id=sid,
        candidate_ids=candidate_ids,
        max_candidates=body.max_candidates,
        force_reproof=body.force_reproof,
    )
    if job.get("queued_count", 0) > 0:
        complete_validation_session.apply_async(
            args=[
                job["job_id"],
                sid,
                candidate_ids,
                body.max_candidates,
                body.force_reproof,
            ],
            queue="research",
        )
    else:
        from app.database.mongodb import get_validation_proof_jobs_collection

        await get_validation_proof_jobs_collection().update_one(
            {"session_id": sid, "job_id": job["job_id"]},
            {"$set": {"status": "completed", "completed_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}},
        )
        job["status"] = "completed"
    return {
        "session_id": sid,
        "job_id": job["job_id"],
        "queued_count": job.get("queued_count", 0),
        "status": job.get("status", "queued"),
    }


@router.get("/sessions/{session_id}/proof-jobs/{job_id}")
async def get_proof_job(
    session_id: uuid.UUID,
    job_id: str,
) -> Dict[str, Any]:
    from app.services.validation_completion import get_validation_job

    job = await get_validation_job(str(session_id), job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Proof job not found")
    return job


@router.post("/sessions/{session_id}/confirm")
async def confirm_validated_findings(
    session_id: uuid.UUID,
    body: ConfirmFindingsRequest,
) -> Dict[str, Any]:
    """Promote validated candidates into confirmed findings.

    Default behavior is strict: only candidates that already have support and
    passing proof runs are promoted. When `operator_validated` is true, the
    selected candidates receive an explicit operator support verdict and proof
    record first, so manual confirmation remains auditable.
    """
    sid = str(session_id)
    candidate_ids = [str(cid).strip() for cid in body.candidate_ids if str(cid).strip()]
    operator_validated_count = 0

    if body.operator_validated and not candidate_ids:
        raise HTTPException(
            status_code=400,
            detail="operator_validated requires one or more candidate_ids",
        )

    if body.operator_validated:
        reason = (
            body.reason.strip()
            or "Operator manually validated this candidate from the Validated tab."
        )
        from app.database.mongodb import get_candidate_findings_collection

        existing = await get_candidate_findings_collection().find({
            "session_id": sid,
            "candidate_id": {"$in": candidate_ids},
        }).to_list(length=len(candidate_ids))
        existing_ids = {str(c.get("candidate_id")) for c in existing}
        missing = [cid for cid in candidate_ids if cid not in existing_ids]
        if missing:
            raise HTTPException(
                status_code=404,
                detail=f"Candidate not found: {', '.join(missing[:5])}",
            )

        for cid in candidate_ids:
            await create_validation_verdict(
                session_id=sid,
                candidate_id=cid,
                verdict="support",
                validator="operator_validator",
                reasoning=reason,
                missing_evidence=[],
                target_proof_action={"type": "operator_attestation"},
            )
            await record_proof_run(
                session_id=sid,
                candidate_id=cid,
                proof_tool="operator_validation",
                oracle={"type": "operator_attestation", "operator_validated": True},
                inputs={"candidate_id": cid},
                result={"passed": True, "operator_validated": True, "reason": reason},
                artifacts=[],
                passed=True,
                pass_fail_reason=reason,
            )
            operator_validated_count += 1

    await rebuild_target_surface_graph(sid)
    promoted = await promote_ready_candidates(
        sid,
        _save_promoted_vulnerability,
        candidate_ids=candidate_ids or None,
    )
    await rebuild_clusters(sid)
    blockers = await _promotion_blockers(sid, candidate_ids)
    return {
        "session_id": sid,
        "selected_count": len(candidate_ids),
        "operator_validated_count": operator_validated_count,
        "promoted_count": promoted,
        "remaining": blockers,
    }


@router.get("/sessions/{session_id}/clusters")
async def list_clusters(
    session_id: uuid.UUID,
    rebuild: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1000),
) -> Dict[str, Any]:
    from app.database.mongodb import get_finding_clusters_collection

    if rebuild:
        await rebuild_clusters(str(session_id))
    docs = await (
        get_finding_clusters_collection()
        .find({"session_id": str(session_id)})
        .sort("updated_at", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return {"session_id": str(session_id), "items": [public_doc(d) for d in docs], "total": len(docs)}


@router.get("/sessions/{session_id}/surface-graph")
async def get_surface_graph(
    session_id: uuid.UUID,
    rebuild: bool = Query(default=False),
) -> Dict[str, Any]:
    from app.database.mongodb import get_target_surface_graph_collection

    if rebuild:
        graph = await rebuild_target_surface_graph(str(session_id))
    else:
        graph = await get_target_surface_graph_collection().find_one({"session_id": str(session_id)})
        if not graph:
            graph = await rebuild_target_surface_graph(str(session_id))
    return public_doc(graph)


@router.post("/sessions/{session_id}/benchmark", status_code=201)
async def create_benchmark_report(
    session_id: uuid.UUID,
    body: BenchmarkRequest,
) -> Dict[str, Any]:
    report = await build_benchmark_report(
        str(session_id),
        ground_truth=body.ground_truth,
        label=body.label or body.lane,
        lane=body.lane,
    )
    return public_doc(report)


@router.get("/sessions/{session_id}/benchmark")
async def list_benchmark_reports(
    session_id: uuid.UUID,
    limit: int = Query(default=20, ge=1, le=100),
) -> Dict[str, Any]:
    from app.database.mongodb import get_benchmark_reports_collection

    docs = await (
        get_benchmark_reports_collection()
        .find({"session_id": str(session_id)})
        .sort("created_at", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return {"session_id": str(session_id), "items": [public_doc(d) for d in docs], "total": len(docs)}
