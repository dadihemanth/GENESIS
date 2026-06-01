from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import select

from app.database.mongodb import (
    get_candidate_findings_collection,
    get_proof_runs_collection,
    get_validation_proof_jobs_collection,
    get_validation_verdicts_collection,
)
from app.database.postgres import AsyncSessionLocal
from app.models.session import ResearchSession
from app.services.mcp_client import MCPClient
from app.services.validated_scanner import (
    create_validation_verdict,
    public_doc,
    rebuild_clusters,
    rebuild_target_surface_graph,
    record_proof_run,
    promote_ready_candidates,
)

logger = logging.getLogger(__name__)


LIVE_PROOF_TOOLS = {
    "ai_request_forge",
    "forge_runner",
    "browser_session",
    "oob_check",
    "payload_swarm",
    "curl_probe",
}

STATIC_PROOF_TOOLS = {
    "semgrep_scan",
    "semgrep",
    "ast_walker",
    "taint_engine",
    "symbolic_exec",
    "fuzz_binary",
    "instrument_trace",
    "code_read",
    "binary_decompile",
    "bandit_scan",
    "bandit",
}

ALLOWED_PROOF_TOOLS = LIVE_PROOF_TOOLS | STATIC_PROOF_TOOLS


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _json_text(value: Any, limit: int = 5000) -> str:
    try:
        return json.dumps(value, default=str)[:limit]
    except Exception:
        return str(value)[:limit]


def _extract_json_object(text: str) -> Dict[str, Any]:
    if not text:
        return {}
    cleaned = text.strip()
    if "```" in cleaned:
        parts = cleaned.split("```")
        for part in parts:
            candidate = part.strip()
            if candidate.startswith("json"):
                candidate = candidate[4:].strip()
            if candidate.startswith("{") and candidate.endswith("}"):
                cleaned = candidate
                break
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _first_nonempty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _target_base_url(target: str) -> str:
    target = str(target or "").strip()
    if not target:
        return ""
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"http://{target}".rstrip("/")


def _absolute_url(target: str, endpoint: str) -> str:
    endpoint = str(endpoint or "").strip()
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    base = _target_base_url(target)
    if not base or not endpoint:
        return ""
    if not endpoint.startswith("/"):
        endpoint = f"/{endpoint}"
    return f"{base}{endpoint}"


async def get_validation_job(session_id: str, job_id: str) -> Optional[Dict[str, Any]]:
    doc = await get_validation_proof_jobs_collection().find_one({
        "session_id": session_id,
        "job_id": job_id,
    })
    return public_doc(doc) if doc else None


async def _load_session_target(session_id: str) -> str:
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ResearchSession).where(ResearchSession.id == uuid.UUID(session_id))
            )
            session = result.scalar_one_or_none()
            return str(getattr(session, "target_ip", "") or "") if session else ""
    except Exception as exc:  # noqa: BLE001
        logger.debug("validation job could not load session target %s: %s", session_id, exc)
        return ""


async def _candidate_has_passing_proof(session_id: str, candidate_id: str, *, require_live: bool) -> bool:
    query: Dict[str, Any] = {
        "session_id": session_id,
        "candidate_id": candidate_id,
        "passed": True,
    }
    if require_live:
        query["proof_class"] = "live"
    return await get_proof_runs_collection().find_one(query) is not None


def _source_requires_live(candidate: Dict[str, Any]) -> bool:
    source_context = _as_dict(candidate.get("source_context"))
    has_source = any(source_context.get(k) for k in ("repo", "file_path", "symbol"))
    if not has_source:
        return False
    proof_plan = _as_dict(candidate.get("proof_plan") or candidate.get("proposed_proof"))
    return proof_plan.get("live_replay_required", True) is not False


async def _select_candidates(
    session_id: str,
    *,
    candidate_ids: Optional[Iterable[str]] = None,
    max_candidates: int = 50,
    force_reproof: bool = False,
) -> List[Dict[str, Any]]:
    selected = [str(cid).strip() for cid in (candidate_ids or []) if str(cid).strip()]
    query: Dict[str, Any] = {
        "session_id": session_id,
        "status": {"$nin": ["promoted", "ruled_out"]},
    }
    if selected:
        query["candidate_id"] = {"$in": selected}
    candidates = await (
        get_candidate_findings_collection()
        .find(query)
        .sort("created_at", 1)
        .limit(max(max_candidates * 3, max_candidates))
        .to_list(length=max(max_candidates * 3, max_candidates))
    )

    out: List[Dict[str, Any]] = []
    for candidate in candidates:
        cid = str(candidate.get("candidate_id") or "")
        if not cid:
            continue
        if not force_reproof and await _candidate_has_passing_proof(
            session_id,
            cid,
            require_live=_source_requires_live(candidate),
        ):
            continue
        out.append(candidate)
        if len(out) >= max_candidates:
            break
    return out


async def create_validation_completion_job(
    *,
    session_id: str,
    candidate_ids: Optional[List[str]] = None,
    max_candidates: int = 50,
    force_reproof: bool = False,
) -> Dict[str, Any]:
    candidates = await _select_candidates(
        session_id,
        candidate_ids=candidate_ids,
        max_candidates=max_candidates,
        force_reproof=force_reproof,
    )
    job_id = f"vpj-{uuid.uuid4().hex[:12]}"
    now = _now()
    doc = {
        "_id": job_id,
        "job_id": job_id,
        "session_id": session_id,
        "status": "queued",
        "candidate_ids": [str(c.get("candidate_id")) for c in candidates if c.get("candidate_id")],
        "requested_candidate_ids": [str(cid).strip() for cid in (candidate_ids or []) if str(cid).strip()],
        "max_candidates": int(max_candidates),
        "force_reproof": bool(force_reproof),
        "queued_count": len(candidates),
        "processed_count": 0,
        "passed_count": 0,
        "failed_count": 0,
        "promoted_count": 0,
        "remaining_blockers": {},
        "error": "",
        "created_at": now,
        "updated_at": now,
        "started_at": None,
        "completed_at": None,
    }
    await get_validation_proof_jobs_collection().insert_one(doc)
    if candidates:
        await get_candidate_findings_collection().update_many(
            {
                "session_id": session_id,
                "candidate_id": {"$in": doc["candidate_ids"]},
                "status": {"$nin": ["promoted", "ruled_out", "proven"]},
            },
            {"$set": {"status": "proof_queued", "updated_at": now}},
        )
    return public_doc(doc)


def _proof_plan_from_candidate(candidate: Dict[str, Any], target: str) -> Dict[str, Any]:
    proof_plan = _as_dict(candidate.get("proof_plan") or candidate.get("proposed_proof"))
    if not proof_plan:
        return {}
    tool = _first_nonempty(
        proof_plan.get("preferred_tool"),
        proof_plan.get("tool"),
        proof_plan.get("proof_tool"),
    )
    if tool == "proof_planner":
        tool = ""
    params = _as_dict(
        proof_plan.get("params")
        or proof_plan.get("tool_params")
        or proof_plan.get("inputs")
    )
    oracle = proof_plan.get("oracle")

    if not params and tool in {"ai_request_forge", "curl_probe"}:
        endpoint = _first_nonempty(
            candidate.get("endpoint"),
            _as_dict(candidate.get("reachability_context")).get("endpoint"),
            candidate.get("affected_surface"),
        )
        url = _first_nonempty(proof_plan.get("url"), _absolute_url(target, endpoint))
        method = _first_nonempty(
            proof_plan.get("method"),
            _as_dict(candidate.get("reachability_context")).get("method"),
            "GET",
        ).upper()
        if url and oracle:
            params = {
                "method": method,
                "url": url,
                "headers": proof_plan.get("headers") or {},
                "body": proof_plan.get("body") or "",
                "oracle": oracle,
                "rationale": f"Complete validation proof for {candidate.get('title', 'candidate')}",
            }
    if not tool or tool not in ALLOWED_PROOF_TOOLS or not isinstance(params, dict) or not params:
        return {}
    return {
        "proof_tool": tool,
        "params": params,
        "oracle": oracle if oracle is not None else params.get("oracle", {}),
    }


async def _llm_plan_proof(candidate: Dict[str, Any], target: str) -> Dict[str, Any]:
    try:
        from app.services.ai_orchestrator import AIOrchestrator
        from app.services.llm_routing import get_client_and_model_for_role

        orchestrator = AIOrchestrator()
        settings = await orchestrator.get_settings()
        client, model, _profile = await get_client_and_model_for_role("proof_planner", settings)
    except Exception as exc:  # noqa: BLE001
        logger.debug("proof planner route failed: %s", exc)
        return {}

    candidate_summary = {
        "candidate_id": candidate.get("candidate_id"),
        "title": candidate.get("title"),
        "severity": candidate.get("severity"),
        "attack_class": candidate.get("attack_class"),
        "affected_surface": candidate.get("affected_surface"),
        "endpoint": candidate.get("endpoint"),
        "hypothesis": candidate.get("hypothesis"),
        "evidence": _as_list(candidate.get("evidence"))[:8],
        "reachability_claim": candidate.get("reachability_claim"),
        "proof_plan": candidate.get("proof_plan") or candidate.get("proposed_proof"),
        "source_context": candidate.get("source_context"),
        "reachability_context": candidate.get("reachability_context"),
    }
    system = (
        "You are GENESIS proof_planner. Return JSON only. Create one safe, "
        "deterministic proof tool call for an authorized security assessment. "
        "Use only these tools: ai_request_forge, forge_runner, browser_session, "
        "oob_check, payload_swarm, curl_probe, semgrep_scan, ast_walker, "
        "taint_engine, symbolic_exec, fuzz_binary, instrument_trace, code_read, "
        "binary_decompile, bandit_scan. Do not use destructive payloads. "
        "The JSON schema is: {\"proof_tool\":\"...\", \"params\":{...}, "
        "\"oracle\":{...}, \"reason\":\"...\"}. If no safe deterministic proof "
        "is possible, return {\"proof_tool\":\"\", \"params\":{}, \"oracle\":{}, "
        "\"reason\":\"why proof cannot be planned\"}."
    )
    try:
        response = await client.messages.create(
            model=model,
            max_tokens=900,
            timeout=60.0,
            system=system,
            messages=[{
                "role": "user",
                "content": (
                    f"Target base: {_target_base_url(target)}\n"
                    f"Candidate JSON:\n{_json_text(candidate_summary)}"
                ),
            }],
        )
        try:
            from app.services.llm_usage import record_llm_usage
            from app.database.redis_client import publish_session_message

            await record_llm_usage(
                session_id=str(candidate.get("session_id") or ""),
                iteration=0,
                source="proof_planner",
                model=model,
                response=response,
                publish_fn=publish_session_message,
            )
        except Exception:
            pass
        text = response.content[0].text.strip() if getattr(response, "content", None) else ""
        parsed = _extract_json_object(text)
    except Exception as exc:  # noqa: BLE001
        logger.debug("proof planner call failed: %s", exc)
        return {}

    tool = str(parsed.get("proof_tool") or "").strip()
    params = _as_dict(parsed.get("params"))
    oracle = parsed.get("oracle") if parsed.get("oracle") is not None else params.get("oracle", {})
    if tool not in ALLOWED_PROOF_TOOLS or not params:
        return {}
    return {"proof_tool": tool, "params": params, "oracle": oracle, "reason": str(parsed.get("reason") or "")}


async def _record_planning_failure(session_id: str, candidate_id: str, reason: str) -> None:
    await record_proof_run(
        session_id=session_id,
        candidate_id=candidate_id,
        proof_tool="proof_planner",
        oracle={"type": "proof_planning"},
        inputs={},
        result={"passed": False, "success": False, "error": reason},
        artifacts=[],
        passed=False,
        pass_fail_reason=reason,
    )


async def _build_remaining_blockers(session_id: str) -> Dict[str, Any]:
    candidates = await get_candidate_findings_collection().find({"session_id": session_id}).to_list(length=2000)
    ids = [str(c.get("candidate_id") or "") for c in candidates if c.get("candidate_id")]
    proofs = await get_proof_runs_collection().find({
        "session_id": session_id,
        "candidate_id": {"$in": ids},
    }).to_list(length=5000) if ids else []
    verdicts = await get_validation_verdicts_collection().find({
        "session_id": session_id,
        "candidate_id": {"$in": ids},
    }).to_list(length=5000) if ids else []

    passed = {str(p.get("candidate_id")) for p in proofs if p.get("passed") is True}
    live_passed = {
        str(p.get("candidate_id"))
        for p in proofs
        if p.get("passed") is True and p.get("proof_class") == "live"
    }
    refuted = {
        str(v.get("candidate_id"))
        for v in verdicts
        if v.get("verdict") in {"refute", "disputed"}
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
        if _source_requires_live(cand) and cid not in live_passed:
            summary["live_replay_needed_count"] += 1
            reason = reason or "source-backed candidate needs live proof"
        if cid not in passed:
            summary["missing_proof_count"] += 1
            reason = reason or "candidate has no passing proof run or operator validation"
        if reason and len(summary["examples"]) < 5:
            summary["examples"].append({
                "candidate_id": cid,
                "title": cand.get("title") or "",
                "severity": cand.get("severity") or "info",
                "status": status,
                "reason": reason,
            })
    return summary


async def _save_promoted_vulnerability(session_id: str, vuln_data: Dict[str, Any]) -> Optional[str]:
    from app.services.ai_orchestrator import AIOrchestrator

    orchestrator = AIOrchestrator()
    try:
        orchestrator._app_settings = await orchestrator.get_settings()  # type: ignore[attr-defined]
    except Exception:
        orchestrator._app_settings = {}  # type: ignore[attr-defined]
    return await orchestrator._save_vulnerability(session_id, vuln_data)  # type: ignore[attr-defined]


async def run_validation_completion_job(
    *,
    job_id: str,
    session_id: str,
    candidate_ids: Optional[List[str]] = None,
    max_candidates: int = 50,
    force_reproof: bool = False,
) -> Dict[str, Any]:
    jobs = get_validation_proof_jobs_collection()
    now = _now()
    await jobs.update_one(
        {"session_id": session_id, "job_id": job_id},
        {"$set": {"status": "running", "started_at": now, "updated_at": now}},
    )

    processed = 0
    passed = 0
    failed = 0
    try:
        target = await _load_session_target(session_id)
        candidates = await _select_candidates(
            session_id,
            candidate_ids=candidate_ids,
            max_candidates=max_candidates,
            force_reproof=force_reproof,
        )
        await jobs.update_one(
            {"session_id": session_id, "job_id": job_id},
            {"$set": {
                "candidate_ids": [str(c.get("candidate_id")) for c in candidates if c.get("candidate_id")],
                "queued_count": len(candidates),
                "updated_at": _now(),
            }},
        )
        client = MCPClient(timeout=300.0)
        for candidate in candidates:
            cid = str(candidate.get("candidate_id") or "")
            if not cid:
                continue
            processed += 1
            await get_candidate_findings_collection().update_one(
                {"session_id": session_id, "candidate_id": cid},
                {"$set": {"status": "proof_running", "updated_at": _now()}},
            )
            try:
                verdict_exists = await get_validation_verdicts_collection().find_one({
                    "session_id": session_id,
                    "candidate_id": cid,
                })
                if not verdict_exists:
                    await create_validation_verdict(
                        session_id=session_id,
                        candidate_id=cid,
                        verdict="needs-proof",
                        validator="proof_planner",
                        reasoning="Complete Validation queued this candidate for deterministic proof.",
                        missing_evidence=["passing proof run"],
                        target_proof_action=_as_dict(candidate.get("proof_plan") or candidate.get("proposed_proof")),
                    )

                plan = _proof_plan_from_candidate(candidate, target)
                if not plan:
                    plan = await _llm_plan_proof(candidate, target)
                if not plan:
                    failed += 1
                    await _record_planning_failure(
                        session_id,
                        cid,
                        "Proof planner could not create a safe deterministic tool call.",
                    )
                    continue

                if plan["proof_tool"] == "spawn_replica" and isinstance(plan.get("params"), dict):
                    plan["params"].setdefault("session_id", session_id)
                result = await client.execute_tool(plan["proof_tool"], plan["params"])
                reason = _first_nonempty(
                    plan.get("reason"),
                    _as_dict(result.get("parsed")).get("reason"),
                    _as_dict(result.get("parsed")).get("oracle_verdict"),
                    result.get("output"),
                )[:2000]
                proof = await record_proof_run(
                    session_id=session_id,
                    candidate_id=cid,
                    proof_tool=plan["proof_tool"],
                    oracle=plan.get("oracle") or _as_dict(plan.get("params")).get("oracle", {}),
                    inputs=plan.get("params") or {},
                    result=result,
                    artifacts=[],
                    passed=None,
                    pass_fail_reason=reason,
                )
                if proof.get("passed") is True:
                    passed += 1
                else:
                    failed += 1
            finally:
                await jobs.update_one(
                    {"session_id": session_id, "job_id": job_id},
                    {"$set": {
                        "processed_count": processed,
                        "passed_count": passed,
                        "failed_count": failed,
                        "updated_at": _now(),
                    }},
                )

        await rebuild_target_surface_graph(session_id)
        promoted = await promote_ready_candidates(session_id, _save_promoted_vulnerability)
        await rebuild_clusters(session_id)
        blockers = await _build_remaining_blockers(session_id)
        completed = _now()
        await jobs.update_one(
            {"session_id": session_id, "job_id": job_id},
            {"$set": {
                "status": "completed",
                "processed_count": processed,
                "passed_count": passed,
                "failed_count": failed,
                "promoted_count": promoted,
                "remaining_blockers": blockers,
                "completed_at": completed,
                "updated_at": completed,
            }},
        )
        doc = await jobs.find_one({"session_id": session_id, "job_id": job_id}) or {}
        return public_doc(doc)
    except Exception as exc:  # noqa: BLE001
        logger.exception("validation completion job failed: session=%s job=%s", session_id, job_id)
        blockers = await _build_remaining_blockers(session_id)
        await jobs.update_one(
            {"session_id": session_id, "job_id": job_id},
            {"$set": {
                "status": "failed",
                "processed_count": processed,
                "passed_count": passed,
                "failed_count": failed,
                "remaining_blockers": blockers,
                "error": f"{type(exc).__name__}: {str(exc)[:1000]}",
                "completed_at": _now(),
                "updated_at": _now(),
            }},
        )
        doc = await jobs.find_one({"session_id": session_id, "job_id": job_id}) or {}
        return public_doc(doc)
