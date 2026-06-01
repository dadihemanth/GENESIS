"""T80–T86 source-analysis API routes.

POST /source/ingest      — clone repo and embed source corpus
POST /source/ast-query   — AST sink/input/dataflow queries
POST /source/taint       — full taint analysis for a session
POST /source/invariants  — infer and store runtime invariants
GET  /source/causal/{session_id} — retrieve causal findings
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.ast_walker import find_sinks, find_user_inputs, trace_dataflow, query_symbol
from app.services.causal_root_cause import build_causal_model, get_causal_findings
from app.services.invariant_inferer import infer_invariants, recall_invariants
from app.services.repo_ingest import ingest_repository, search_source_corpus
from app.services.taint_engine import analyze_taint_paths

router = APIRouter()


class IngestRequest(BaseModel):
    session_id: str
    repo_url: Optional[str] = None
    local_path: Optional[str] = None
    max_files: int = Field(default=500, ge=1, le=2000)


class ASTQueryRequest(BaseModel):
    session_id: str
    query_type: str = Field(description="sinks | inputs | dataflow | symbol")
    language: Optional[str] = None
    source_pattern: Optional[str] = None
    sink_pattern: Optional[str] = None
    symbol: Optional[str] = None
    n_results: int = Field(default=10, ge=1, le=50)


class TaintRequest(BaseModel):
    session_id: str
    language: Optional[str] = None
    n_paths: int = Field(default=20, ge=1, le=50)


class InvariantRequest(BaseModel):
    session_id: str
    target_ip: str = ""
    target_id: str = ""


@router.post("/ingest")
async def ingest_source(req: IngestRequest) -> Dict[str, Any]:
    """T80 — ingest a git repository into the source_corpus ChromaDB collection."""
    result = await ingest_repository(
        session_id=req.session_id,
        repo_url=req.repo_url,
        local_path=req.local_path,
        max_files=req.max_files,
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    try:
        from app.services.validated_scanner import record_source_ingest_summary
        await record_source_ingest_summary(req.session_id, result)
    except Exception:
        pass
    return result


@router.post("/ast-query")
async def ast_query(req: ASTQueryRequest) -> Dict[str, Any]:
    """T81 — query the AST / source corpus for sinks, inputs, or dataflows."""
    qt = req.query_type.lower()
    if qt == "sinks":
        results = await find_sinks(req.session_id, language=req.language, n_results=req.n_results)
    elif qt == "inputs":
        results = await find_user_inputs(req.session_id, language=req.language, n_results=req.n_results)
    elif qt == "dataflow":
        if not req.source_pattern or not req.sink_pattern:
            raise HTTPException(status_code=400, detail="source_pattern and sink_pattern required for dataflow")
        results = await trace_dataflow(
            req.session_id,
            source_pattern=req.source_pattern,
            sink_pattern=req.sink_pattern,
            language=req.language,
            n_results=req.n_results,
        )
    elif qt == "symbol":
        if not req.symbol:
            raise HTTPException(status_code=400, detail="symbol required for symbol query")
        results = await query_symbol(req.session_id, req.symbol, n_results=req.n_results)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown query_type: {req.query_type}")
    return {"query_type": req.query_type, "results": results, "count": len(results)}


@router.post("/taint")
async def taint_analysis(req: TaintRequest) -> Dict[str, Any]:
    """T82 — run full source-to-sink taint analysis for the session."""
    paths = await analyze_taint_paths(
        session_id=req.session_id,
        language=req.language,
        n_paths=req.n_paths,
    )
    return {
        "session_id": req.session_id,
        "taint_paths": paths,
        "count": len(paths),
    }


@router.post("/invariants")
async def infer_target_invariants(req: InvariantRequest) -> Dict[str, Any]:
    """T83 — infer runtime invariants from the session's source corpus."""
    invariants = await infer_invariants(
        session_id=req.session_id,
        target_ip=req.target_ip,
        target_id=req.target_id,
    )
    return {
        "session_id": req.session_id,
        "invariants": invariants,
        "count": len(invariants),
    }


@router.get("/invariants/recall")
async def recall_target_invariants(target_ip: str, n_results: int = 10) -> Dict[str, Any]:
    """Recall invariants for a target IP from across all past sessions."""
    invariants = await recall_invariants(target_ip=target_ip, n_results=n_results)
    return {"target_ip": target_ip, "invariants": invariants, "count": len(invariants)}


@router.get("/causal/{session_id}")
async def get_session_causal_findings(session_id: str) -> Dict[str, Any]:
    """T86 — retrieve causal root-cause findings for a session."""
    findings = await get_causal_findings(session_id)
    return {"session_id": session_id, "causal_findings": findings, "count": len(findings)}


@router.post("/causal/{session_id}/run")
async def run_causal_analysis(
    session_id: str,
    vuln_id: Optional[str] = None,
    max_probes: int = 5,
) -> Dict[str, Any]:
    """T86 — run causal isolation probes for a session."""
    findings = await build_causal_model(
        session_id=session_id,
        vuln_id=vuln_id,
        max_probes=min(max_probes, 10),
    )
    return {"session_id": session_id, "causal_findings": findings, "count": len(findings)}
