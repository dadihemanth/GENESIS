"""validated_dynamic pipeline helpers.

This module implements the durable state for the validated scanner mode:
candidate findings, independent validation verdicts, normalized proof runs,
candidate dedup clusters, promotion gates, and benchmark scorecards.

The service is intentionally Mongo-backed so the feature can be introduced
without a relational migration. Final promoted vulnerabilities still flow
through the existing Vulnerability model and AIOrchestrator._save_vulnerability
path so graph mirroring, Chroma embeddings, and WebSocket events stay intact.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional


SaveVulnerabilityFn = Callable[[str, Dict[str, Any]], Awaitable[Optional[str]]]
logger = logging.getLogger(__name__)

LIVE_PROOF_TOOLS = {
    "ai_request_forge",
    "forge_runner",
    "browser_session",
    "oob_check",
    "payload_swarm",
    "curl_probe",
    "operator_validation",
}

STATIC_PROOF_TOOLS = {
    "semgrep_scan",
    "ast_walker",
    "taint_engine",
    "symbolic_exec",
    "fuzz_binary",
    "instrument_trace",
    "code_read",
    "binary_decompile",
    "bandit_scan",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_float(value: Any, default: float = 0.5) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v)[:1000] for v in value if str(v).strip()]
    if isinstance(value, tuple):
        return [str(v)[:1000] for v in value if str(v).strip()]
    text = str(value).strip()
    return [text[:1000]] if text else []


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        return {"description": value.strip()[:2000]}
    return {}


def _clean_dict(value: Any, allowed: Iterable[str], max_string: int = 1000) -> Dict[str, Any]:
    raw = _as_dict(value)
    out: Dict[str, Any] = {}
    for key in allowed:
        val = raw.get(key)
        if val is None:
            continue
        if isinstance(val, str):
            val = val.strip()[:max_string]
            if not val:
                continue
        elif isinstance(val, list):
            val = [str(v)[:max_string] for v in val if str(v).strip()][:20]
        elif isinstance(val, dict):
            val = {str(k)[:120]: str(v)[:max_string] for k, v in val.items()}
        out[key] = val
    return out


def _normalize_source_context(data: Dict[str, Any]) -> Dict[str, Any]:
    ctx = _clean_dict(
        data.get("source_context") or {},
        ("repo", "file_path", "symbol", "language", "line_range", "snippet_id"),
    )
    for src_key, dst_key in (
        ("repo", "repo"),
        ("file_path", "file_path"),
        ("symbol", "symbol"),
        ("language", "language"),
        ("line_range", "line_range"),
        ("snippet_id", "snippet_id"),
    ):
        if src_key in data and dst_key not in ctx:
            ctx[dst_key] = data[src_key]
    return ctx


def _normalize_reachability_context(data: Dict[str, Any]) -> Dict[str, Any]:
    ctx = _clean_dict(
        data.get("reachability_context") or {},
        ("endpoint", "method", "auth_required", "params", "taint_path", "confidence"),
    )
    if data.get("endpoint") and not ctx.get("endpoint"):
        ctx["endpoint"] = str(data.get("endpoint"))[:500]
    if data.get("method") and not ctx.get("method"):
        ctx["method"] = str(data.get("method"))[:20].upper()
    if data.get("taint_path") and not ctx.get("taint_path"):
        ctx["taint_path"] = data.get("taint_path")
    try:
        if "confidence" in ctx:
            ctx["confidence"] = _safe_float(ctx["confidence"])
    except Exception:
        ctx.pop("confidence", None)
    return ctx


def _normalize_proof_plan(data: Dict[str, Any], source_context: Dict[str, Any]) -> Dict[str, Any]:
    plan = _clean_dict(
        data.get("proof_plan") or data.get("proposed_proof") or data.get("proof") or data.get("next_test") or {},
        ("preferred_tool", "tool", "oracle", "live_replay_required", "fallback_tools"),
        max_string=2000,
    )
    if plan.get("tool") and not plan.get("preferred_tool"):
        plan["preferred_tool"] = plan["tool"]
    if "live_replay_required" not in plan and source_context:
        plan["live_replay_required"] = True
    fallback_tools = plan.get("fallback_tools")
    if isinstance(fallback_tools, str):
        plan["fallback_tools"] = [v.strip() for v in fallback_tools.split(",") if v.strip()][:10]
    return plan


def _has_meaningful_source_context(source_context: Dict[str, Any]) -> bool:
    return bool(
        source_context.get("file_path")
        or source_context.get("symbol")
        or source_context.get("snippet_id")
    )


def _candidate_kind(source_context: Dict[str, Any], reachability_context: Dict[str, Any], endpoint: str) -> str:
    has_source = _has_meaningful_source_context(source_context)
    has_endpoint = bool(endpoint or reachability_context.get("endpoint"))
    if has_source and has_endpoint:
        return "hybrid"
    if has_source:
        return "source"
    return "endpoint"


def _norm(value: Any) -> str:
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9/_:.-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _hash_parts(parts: Iterable[Any]) -> str:
    blob = "|".join(_norm(p) for p in parts)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]


def _extract_blocks(text: str, marker_name: str) -> List[Dict[str, Any]]:
    """Extract all JSON blocks containing marker_name from model text."""
    results: List[Dict[str, Any]] = []
    marker = f'"{marker_name}"'
    pos = 0
    while True:
        idx = text.find(marker, pos)
        if idx == -1:
            break
        start = text.rfind("{", 0, idx)
        if start == -1:
            pos = idx + len(marker)
            continue
        depth = 0
        i = start
        in_string = False
        escape_next = False
        while i < len(text):
            ch = text[i]
            if escape_next:
                escape_next = False
            elif ch == "\\" and in_string:
                escape_next = True
            elif ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            outer = json.loads(text[start : i + 1])
                            data = outer.get(marker_name, {})
                            if isinstance(data, dict) and data:
                                results.append(data)
                        except Exception:
                            pass
                        pos = i + 1
                        break
            i += 1
        else:
            pos = idx + len(marker)
    return results


def extract_candidate_blocks(text: str) -> List[Dict[str, Any]]:
    return _extract_blocks(text, "CANDIDATE_FINDING")


def extract_source_candidate_blocks(text: str) -> List[Dict[str, Any]]:
    return _extract_blocks(text, "SOURCE_CANDIDATE_FINDING")


def candidate_from_vulnerability(vuln_data: Dict[str, Any]) -> Dict[str, Any]:
    """Map a legacy VULNERABILITY block into the candidate schema."""
    title = str(vuln_data.get("title") or "Unnamed candidate")
    description = str(vuln_data.get("description") or "")
    endpoint = str(vuln_data.get("endpoint") or "").strip()
    affected_service = str(vuln_data.get("affected_service") or "").strip()
    evidence = _as_list(vuln_data.get("evidence_for"))
    proposed_proof = {
        "tool": str(vuln_data.get("tool") or vuln_data.get("tool_used") or "").strip(),
        "oracle": "legacy VULNERABILITY block claimed verification; rerun deterministic proof before promotion",
    }
    if vuln_data.get("exploit_code"):
        proposed_proof["exploit_code"] = str(vuln_data.get("exploit_code"))[:4000]
    return {
        "title": title,
        "attack_class": str(vuln_data.get("technique_tag") or vuln_data.get("attack_class") or ""),
        "affected_surface": endpoint or affected_service or str(vuln_data.get("port") or ""),
        "hypothesis": description or title,
        "evidence": evidence,
        "reachability_claim": str(vuln_data.get("reachability_claim") or description),
        "proposed_proof": proposed_proof,
        "confidence": vuln_data.get("confidence", 0.5),
        "severity": str(vuln_data.get("severity") or "info").lower(),
        "endpoint": endpoint,
        "affected_service": affected_service,
        "port": vuln_data.get("port"),
        "protocol": vuln_data.get("protocol"),
        "cve_ids": vuln_data.get("cve_ids") or [],
        "cvss_score": vuln_data.get("cvss_score"),
        "remediation": vuln_data.get("remediation") or "",
        "patch_code": vuln_data.get("patch_code"),
        "exploit_code": vuln_data.get("exploit_code"),
        "mitre_techniques": vuln_data.get("mitre_techniques") or [],
        "is_zero_day": bool(vuln_data.get("is_zero_day", False)),
        "legacy_vulnerability": vuln_data,
    }


def candidate_from_source_candidate(data: Dict[str, Any]) -> Dict[str, Any]:
    """Map SOURCE_CANDIDATE_FINDING into the general CandidateFinding schema."""
    source_context = _normalize_source_context(data)
    reachability_context = _normalize_reachability_context(data)
    proof_plan = _normalize_proof_plan(data, source_context)
    endpoint = str(
        data.get("endpoint")
        or reachability_context.get("endpoint")
        or ""
    ).strip()
    sink = str(data.get("sink") or "").strip()
    source_input = str(data.get("source_input") or "").strip()
    taint_path = data.get("taint_path") or reachability_context.get("taint_path")
    evidence = _as_list(data.get("evidence"))
    for key, label in (
        ("sink", sink),
        ("source_input", source_input),
        ("invariant", data.get("invariant")),
        ("commit_signal", data.get("commit_signal")),
    ):
        if label:
            evidence.append(f"{key}: {label}"[:1000])
    return {
        **data,
        "candidate_kind": _candidate_kind(source_context, reachability_context, endpoint),
        "affected_surface": data.get("affected_surface") or endpoint or source_context.get("file_path") or sink,
        "evidence": evidence,
        "endpoint": endpoint,
        "source_context": source_context,
        "reachability_context": reachability_context,
        "proof_plan": proof_plan,
        "proposed_proof": proof_plan or data.get("proposed_proof") or {},
        "sink": sink,
        "source_input": source_input,
        "taint_path": taint_path,
        "invariant": data.get("invariant"),
        "commit_signal": data.get("commit_signal"),
    }


def normalize_candidate(
    *,
    session_id: str,
    data: Dict[str, Any],
    source_agent: str = "",
) -> Dict[str, Any]:
    title = str(data.get("title") or data.get("name") or "Unnamed candidate").strip()
    attack_class = str(data.get("attack_class") or data.get("class") or data.get("technique_tag") or "").strip()
    affected_surface = str(
        data.get("affected_surface")
        or data.get("surface")
        or data.get("endpoint")
        or data.get("affected_service")
        or data.get("port")
        or ""
    ).strip()
    hypothesis = str(data.get("hypothesis") or data.get("description") or title).strip()
    evidence = _as_list(data.get("evidence")) + _as_list(data.get("evidence_for"))
    reachability_claim = str(data.get("reachability_claim") or data.get("reachability") or "").strip()
    source_context = _normalize_source_context(data)
    reachability_context = _normalize_reachability_context(data)
    proof_plan = _normalize_proof_plan(data, source_context)
    proposed_proof = proof_plan or _as_dict(data.get("proposed_proof") or data.get("proof") or data.get("next_test"))
    endpoint = str(data.get("endpoint") or reachability_context.get("endpoint") or "").strip()[:500]
    affected_surface = affected_surface or endpoint or str(source_context.get("file_path") or "")
    sink = str(data.get("sink") or "").strip()[:500]
    source_input = str(data.get("source_input") or "").strip()[:500]
    taint_path = data.get("taint_path") or reachability_context.get("taint_path")
    invariant = data.get("invariant")
    commit_signal = data.get("commit_signal")
    candidate_kind = str(data.get("candidate_kind") or _candidate_kind(source_context, reachability_context, endpoint))
    root_cause_key = _hash_parts([
        attack_class,
        endpoint,
        source_context.get("file_path", ""),
        source_context.get("symbol", ""),
        sink,
        _norm(commit_signal)[:120],
        _norm(data.get("remediation") or hypothesis)[:200],
    ])
    dedup_key = str(data.get("dedup_key") or root_cause_key)
    candidate_id = str(data.get("candidate_id") or data.get("id") or f"cand-{uuid.uuid4().hex[:12]}")
    now = _now()
    priority_score = _safe_float(data.get("priority_score", data.get("confidence", 0.5)))
    if candidate_kind == "hybrid":
        priority_score = min(1.0, priority_score + 0.15)
    if source_context.get("file_path") and evidence:
        priority_score = min(1.0, priority_score + 0.05)
    return {
        "_id": candidate_id,
        "candidate_id": candidate_id,
        "session_id": session_id,
        "candidate_kind": candidate_kind[:40],
        "title": title[:500],
        "attack_class": attack_class[:120],
        "affected_surface": affected_surface[:500],
        "hypothesis": hypothesis[:4000],
        "evidence": evidence[:20],
        "reachability_claim": reachability_claim[:2000],
        "proposed_proof": proposed_proof,
        "proof_plan": proof_plan,
        "source_context": source_context,
        "reachability_context": reachability_context,
        "sink": sink,
        "source_input": source_input,
        "taint_path": taint_path,
        "invariant": invariant,
        "commit_signal": commit_signal,
        "root_cause_key": root_cause_key,
        "patch_dedup_key": _hash_parts([source_context.get("file_path", ""), sink, data.get("remediation") or hypothesis]),
        "priority_score": round(priority_score, 4),
        "confidence": _safe_float(data.get("confidence", 0.5)),
        "severity": str(data.get("severity") or "info").lower()[:50],
        "endpoint": endpoint,
        "affected_service": str(data.get("affected_service") or "")[:255],
        "port": data.get("port"),
        "protocol": data.get("protocol"),
        "cve_ids": data.get("cve_ids") if isinstance(data.get("cve_ids"), list) else [],
        "cvss_score": data.get("cvss_score"),
        "remediation": str(data.get("remediation") or "")[:4000],
        "patch_code": data.get("patch_code"),
        "exploit_code": data.get("exploit_code"),
        "mitre_techniques": data.get("mitre_techniques") if isinstance(data.get("mitre_techniques"), list) else [],
        "is_zero_day": bool(data.get("is_zero_day", False)),
        "source_agent": source_agent[:100],
        "source_agents": [source_agent[:100]] if source_agent else [],
        "dedup_key": dedup_key,
        "status": "candidate",
        "created_at": now,
        "updated_at": now,
        "raw": data,
    }


async def store_candidate(
    *,
    session_id: str,
    data: Dict[str, Any],
    source_agent: str = "",
) -> Dict[str, Any]:
    from app.database.mongodb import get_candidate_findings_collection

    col = get_candidate_findings_collection()
    candidate = normalize_candidate(session_id=session_id, data=data, source_agent=source_agent)
    existing = await col.find_one({"session_id": session_id, "dedup_key": candidate["dedup_key"]})
    if existing:
        kind_set = {str(existing.get("candidate_kind") or ""), str(candidate.get("candidate_kind") or "")}
        if "hybrid" in kind_set or {"source", "endpoint"}.issubset(kind_set):
            merged_kind = "hybrid"
        elif "source" in kind_set:
            merged_kind = "source"
        else:
            merged_kind = "endpoint"
        set_doc: Dict[str, Any] = {
            "updated_at": _now(),
            "confidence": max(float(existing.get("confidence", 0.0)), candidate["confidence"]),
            "priority_score": max(float(existing.get("priority_score", 0.0)), candidate["priority_score"]),
            "status": existing.get("status", "candidate"),
            "candidate_kind": merged_kind,
            "root_cause_key": candidate.get("root_cause_key") or existing.get("root_cause_key"),
            "patch_dedup_key": candidate.get("patch_dedup_key") or existing.get("patch_dedup_key"),
        }
        for key in (
            "source_context",
            "reachability_context",
            "proof_plan",
            "sink",
            "source_input",
            "taint_path",
            "invariant",
            "commit_signal",
            "endpoint",
        ):
            if candidate.get(key):
                set_doc[key] = candidate[key]
        update: Dict[str, Any] = {
            "$set": set_doc,
            "$addToSet": {
                "source_agents": {"$each": candidate["source_agents"]},
                "evidence": {"$each": candidate["evidence"]},
            },
        }
        await col.update_one({"_id": existing["_id"]}, update)
        merged = await col.find_one({"_id": existing["_id"]}) or existing
        await ensure_initial_validation(session_id=session_id, candidate=merged)
        await rebuild_clusters(session_id)
        await rebuild_target_surface_graph(session_id)
        return merged

    await col.insert_one(candidate)
    await ensure_initial_validation(session_id=session_id, candidate=candidate)
    await rebuild_clusters(session_id)
    await rebuild_target_surface_graph(session_id)
    # validation milestone 3 — schedule cross-file inconsistency check as a background task.
    # We pass no client here; the orchestrator calls check_pending_candidates()
    # with a real client after Phase-1 scanning completes. This flag marks the
    # candidate as eligible so the detector can prioritise it.
    try:
        await col.update_one(
            {"_id": candidate["_id"]},
            {"$set": {"cross_file_check_pending": True}},
        )
    except Exception:
        pass
    return candidate


async def store_candidates_from_text(
    session_id: str,
    text: str,
    source_agent: str = "",
) -> int:
    count = 0
    for data in extract_candidate_blocks(text):
        await store_candidate(session_id=session_id, data=data, source_agent=source_agent)
        count += 1
    for data in extract_source_candidate_blocks(text):
        await store_candidate(
            session_id=session_id,
            data=candidate_from_source_candidate(data),
            source_agent=source_agent or "source_candidate",
        )
        count += 1
    return count


async def store_vulnerability_blocks_as_candidates(
    session_id: str,
    vulnerability_blocks: Iterable[Dict[str, Any]],
    source_agent: str = "vulnerability_block",
) -> int:
    count = 0
    for vuln_data in vulnerability_blocks:
        await store_candidate(
            session_id=session_id,
            data=candidate_from_vulnerability(vuln_data),
            source_agent=source_agent,
        )
        count += 1
    return count


async def record_source_ingest_summary(session_id: str, summary: Dict[str, Any]) -> Dict[str, Any]:
    from app.database.mongodb import get_source_ingest_summaries_collection

    doc = {
        "_id": f"sis-{uuid.uuid4().hex[:12]}",
        "session_id": session_id,
        "summary": summary,
        "repos": [str(summary.get("repo") or summary.get("repo_url") or "")],
        "languages": summary.get("languages") or {},
        "entry_points": summary.get("entry_points") or [],
        "file_count": summary.get("file_count", 0),
        "chunks_stored": summary.get("chunks_stored", 0),
        "created_at": _now(),
    }
    await get_source_ingest_summaries_collection().insert_one(doc)
    await rebuild_target_surface_graph(session_id)
    return doc


def _surface_endpoint(candidate: Dict[str, Any]) -> str:
    reachability_context = _as_dict(candidate.get("reachability_context"))
    endpoint = str(candidate.get("endpoint") or reachability_context.get("endpoint") or "").strip()
    if endpoint:
        return endpoint[:500]
    surface = str(candidate.get("affected_surface") or "").strip()
    if surface.startswith("/") or "://" in surface:
        return surface[:500]
    return ""


def _surface_link_from_candidate(candidate: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    source_context = _as_dict(candidate.get("source_context"))
    reachability_context = _as_dict(candidate.get("reachability_context"))
    endpoint = _surface_endpoint(candidate)
    file_path = str(source_context.get("file_path") or "").strip()
    symbol = str(source_context.get("symbol") or "").strip()
    if not endpoint and not file_path and not symbol:
        return None
    confidence = _safe_float(reachability_context.get("confidence", candidate.get("confidence", 0.5)))
    if endpoint and (file_path or symbol):
        confidence = max(confidence, 0.85)
    elif endpoint or file_path or symbol:
        confidence = max(confidence, 0.45)
    link_id = f"tsl-{_hash_parts([endpoint, file_path, symbol, candidate.get('candidate_id')])}"
    return {
        "link_id": link_id,
        "candidate_id": candidate.get("candidate_id"),
        "candidate_title": candidate.get("title", ""),
        "candidate_kind": candidate.get("candidate_kind", "endpoint"),
        "attack_class": candidate.get("attack_class", ""),
        "endpoint": endpoint,
        "method": str(reachability_context.get("method") or "").upper()[:20],
        "auth_required": reachability_context.get("auth_required"),
        "params": reachability_context.get("params") or [],
        "handler_symbol": symbol,
        "file_path": file_path,
        "repo": source_context.get("repo", ""),
        "language": source_context.get("language", ""),
        "snippet_id": source_context.get("snippet_id", ""),
        "taint_path": reachability_context.get("taint_path") or candidate.get("taint_path"),
        "confidence": round(confidence, 4),
        "updated_at": _now(),
    }


async def rebuild_target_surface_graph(session_id: str) -> Dict[str, Any]:
    from app.database.mongodb import (
        get_artifacts_collection,
        get_candidate_findings_collection,
        get_security_commits_collection,
        get_source_ingest_summaries_collection,
        get_target_surface_graph_collection,
        get_vulnerability_metadata_collection,
    )

    candidates = await get_candidate_findings_collection().find({"session_id": session_id}).to_list(length=2000)
    links: Dict[str, Dict[str, Any]] = {}
    endpoints: Dict[str, Dict[str, Any]] = {}
    source_nodes: Dict[str, Dict[str, Any]] = {}

    for cand in candidates:
        link = _surface_link_from_candidate(cand)
        if not link:
            continue
        links[link["link_id"]] = link
        if link.get("endpoint"):
            endpoints[link["endpoint"]] = {
                "endpoint": link["endpoint"],
                "method": link.get("method") or "",
                "auth_required": link.get("auth_required"),
            }
        if link.get("file_path") or link.get("handler_symbol"):
            source_id = f"{link.get('file_path', '')}::{link.get('handler_symbol', '')}"
            source_nodes[source_id] = {
                "source_id": source_id,
                "file_path": link.get("file_path", ""),
                "symbol": link.get("handler_symbol", ""),
                "repo": link.get("repo", ""),
                "language": link.get("language", ""),
            }

    vuln_meta = await get_vulnerability_metadata_collection().find({"session_id": session_id}).to_list(length=1000)
    for meta_doc in vuln_meta:
        endpoint = str(meta_doc.get("endpoint") or "").strip()
        if endpoint:
            endpoints.setdefault(endpoint, {"endpoint": endpoint, "method": "", "auth_required": None})

    source_summaries = await get_source_ingest_summaries_collection().find({"session_id": session_id}).to_list(length=200)
    for summary_doc in source_summaries:
        summary = _as_dict(summary_doc.get("summary"))
        for entry in _as_list(summary.get("entry_points")):
            source_id = f"{entry}::entry"
            source_nodes.setdefault(source_id, {
                "source_id": source_id,
                "file_path": entry,
                "symbol": "",
                "repo": summary.get("repo") or "",
                "language": "",
                "kind": "entry_point",
            })

    artifacts = await get_artifacts_collection().find({"session_id": session_id}).to_list(length=500)
    artifact_nodes = [{
        "artifact_id": str(a.get("_id", "")),
        "kind": a.get("kind") or a.get("mime") or "artifact",
        "source_url": a.get("source_url") or a.get("url") or "",
        "path": a.get("path") or a.get("local_path") or "",
        "sha256": a.get("sha256") or "",
    } for a in artifacts]

    commits = await get_security_commits_collection().find({"session_id": session_id}).sort("risk_score", -1).limit(50).to_list(length=50)
    high_risk_commits = [{
        "commit_hash": c.get("commit_hash", ""),
        "subject": c.get("subject", ""),
        "risk_score": c.get("risk_score", 0),
        "files_changed": c.get("files_changed", [])[:20],
    } for c in commits]

    link_list = sorted(links.values(), key=lambda d: float(d.get("confidence", 0.0)), reverse=True)[:1000]
    hybrid_links = [l for l in link_list if l.get("endpoint") and (l.get("file_path") or l.get("handler_symbol"))]
    doc = {
        "_id": session_id,
        "session_id": session_id,
        "endpoints": list(endpoints.values())[:1000],
        "source_nodes": list(source_nodes.values())[:1000],
        "artifact_nodes": artifact_nodes[:500],
        "links": link_list,
        "high_risk_commits": high_risk_commits,
        "endpoint_count": len(endpoints),
        "source_node_count": len(source_nodes),
        "artifact_count": len(artifact_nodes),
        "link_count": len(link_list),
        "hybrid_link_count": len(hybrid_links),
        "endpoint_source_mapping_rate": round(len(hybrid_links) / max(1, len(endpoints)), 4),
        "updated_at": _now(),
    }
    await get_target_surface_graph_collection().replace_one({"_id": session_id}, doc, upsert=True)
    return doc


def _evidence_has_concrete_signal(evidence: List[str]) -> bool:
    blob = " ".join(evidence).lower()
    markers = (
        "status", "http ", "response", "length", "delta", "oracle",
        "passed", "oob", "callback", "token", "tool output", "line ",
        "forge_runner", "ai_request_forge", "payload_swarm", "curl_probe",
    )
    return any(m in blob for m in markers)


async def ensure_initial_validation(*, session_id: str, candidate: Dict[str, Any]) -> None:
    """Create deterministic baseline verdicts so candidates have validator state."""
    from app.database.mongodb import get_validation_verdicts_collection

    col = get_validation_verdicts_collection()
    candidate_id = str(candidate.get("candidate_id") or candidate.get("_id"))

    evidence = _as_list(candidate.get("evidence"))
    has_proof_plan = bool(candidate.get("proof_plan") or candidate.get("proposed_proof"))
    source_context = _as_dict(candidate.get("source_context"))
    reachability_context = _as_dict(candidate.get("reachability_context"))
    endpoint = str(candidate.get("endpoint") or reachability_context.get("endpoint") or "")
    source_present = _has_meaningful_source_context(source_context)
    endpoint_present = bool(endpoint)
    concrete_evidence = bool(evidence and _evidence_has_concrete_signal(evidence))
    endpoint_signal = bool(
        endpoint_present
        and (
            concrete_evidence
            or bool(candidate.get("reachability_claim"))
            or any(k in reachability_context for k in ("params", "taint_path", "confidence", "auth_required"))
        )
    )
    source_signal = bool(
        source_present
        and (
            concrete_evidence
            or candidate.get("sink")
            or candidate.get("taint_path")
            or candidate.get("invariant")
            or candidate.get("commit_signal")
        )
    )

    verdicts: List[Dict[str, Any]] = []
    general_missing: List[str] = []
    if not evidence:
        general_missing.append("concrete evidence")
    if not has_proof_plan:
        general_missing.append("target proof action")
    verdicts.append({
        "validator": "heuristic_policy",
        "verdict": "support" if concrete_evidence and has_proof_plan else "needs-proof",
        "reasoning": (
            "Candidate has concrete evidence and a proof plan."
            if concrete_evidence and has_proof_plan
            else "Candidate preserved, but proof/evidence is not sufficient for promotion."
        ),
        "missing_evidence": general_missing,
    })

    verdicts.append({
        "validator": "endpoint_validator",
        "verdict": "support" if endpoint_signal else "needs-proof",
        "reasoning": (
            "Candidate has mapped endpoint reachability plus concrete evidence or explicit reachability context."
            if endpoint_present else "No live endpoint mapping is present yet."
        ),
        "missing_evidence": [] if endpoint_signal else (
            ["concrete endpoint evidence or reachability context beyond path/method"]
            if endpoint_present else ["mapped endpoint or live replay"]
        ),
    })

    verdicts.append({
        "validator": "source_validator",
        "verdict": "support" if source_signal else "needs-proof",
        "reasoning": (
            "Candidate has source context plus a sink, taint, invariant, commit, or concrete evidence signal."
            if source_present else "No source context is attached to this candidate."
        ),
        "missing_evidence": [] if source_signal else (
            ["source sink, taint path, invariant, commit signal, or concrete source evidence"]
            if source_present else ["source_context.file_path, source_context.symbol, or source_context.snippet_id"]
        ),
    })

    counter_missing: List[str] = []
    proof_plan = _as_dict(candidate.get("proof_plan") or candidate.get("proposed_proof"))
    if not proof_plan:
        counter_missing.append("proof_plan for candidate")
    if source_present and not endpoint_present and proof_plan.get("live_replay_required", True):
        counter_missing.append("live endpoint replay for source-backed candidate")
    verdicts.append({
        "validator": "counter_validator",
        "verdict": "needs-proof" if counter_missing else "support",
        "reasoning": (
            "No blocking contradiction found by deterministic counter-policy."
            if not counter_missing else "Candidate needs more evidence before promotion."
        ),
        "missing_evidence": counter_missing,
    })

    for verdict_doc in verdicts:
        existing = await col.find_one({
            "session_id": session_id,
            "candidate_id": candidate_id,
            "validator": verdict_doc["validator"],
        })
        if existing:
            continue
        await col.insert_one({
            "_id": f"vv-{uuid.uuid4().hex[:12]}",
            "session_id": session_id,
            "candidate_id": candidate_id,
            "validator": verdict_doc["validator"],
            "verdict": verdict_doc["verdict"],
            "reasoning": verdict_doc["reasoning"],
            "missing_evidence": verdict_doc["missing_evidence"],
            "target_proof_action": candidate.get("proof_plan") or candidate.get("proposed_proof") or {},
            "created_at": _now(),
        })


async def create_validation_verdict(
    *,
    session_id: str,
    candidate_id: str,
    verdict: str,
    validator: str = "validator",
    reasoning: str = "",
    missing_evidence: Optional[List[str]] = None,
    target_proof_action: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from app.database.mongodb import get_validation_verdicts_collection

    verdict = verdict if verdict in {"support", "refute", "needs-proof", "disputed"} else "needs-proof"
    doc = {
        "_id": f"vv-{uuid.uuid4().hex[:12]}",
        "session_id": session_id,
        "candidate_id": candidate_id,
        "validator": validator[:100],
        "verdict": verdict,
        "reasoning": reasoning[:4000],
        "missing_evidence": missing_evidence or [],
        "target_proof_action": target_proof_action or {},
        "created_at": _now(),
    }
    await get_validation_verdicts_collection().insert_one(doc)
    return doc


def proof_passed_from_result(result: Any) -> bool:
    if isinstance(result, dict):
        if result.get("passed") is True or result.get("ok") is True and result.get("oracle_passed") is True:
            return True
        parsed = result.get("parsed")
        if isinstance(parsed, dict) and (parsed.get("passed") is True or parsed.get("oracle_passed") is True):
            return True
    text = json.dumps(result, default=str).lower() if not isinstance(result, str) else result.lower()
    pass_markers = ("oracle_passed", "oracle passed", '"passed": true', "'passed': true", "proof passed")
    fail_markers = ("oracle_failed", "oracle failed", '"passed": false', "'passed': false", "proof failed")
    return any(m in text for m in pass_markers) and not any(m in text for m in fail_markers)


async def record_proof_run(
    *,
    session_id: str,
    candidate_id: str,
    proof_tool: str,
    oracle: Any = None,
    inputs: Any = None,
    result: Any = None,
    artifacts: Optional[List[str]] = None,
    passed: Optional[bool] = None,
    pass_fail_reason: str = "",
) -> Dict[str, Any]:
    from app.database.mongodb import get_candidate_findings_collection, get_proof_runs_collection

    passed_value = proof_passed_from_result(result) if passed is None else bool(passed)
    candidate = await get_candidate_findings_collection().find_one({
        "session_id": session_id,
        "candidate_id": candidate_id,
    }) or {}
    proof_tool_name = str(proof_tool or "").strip()
    tool_name = proof_tool_name.lower()
    source_context = _as_dict(candidate.get("source_context"))
    reachability_context = _as_dict(candidate.get("reachability_context"))
    endpoint = str(candidate.get("endpoint") or reachability_context.get("endpoint") or "")
    proof_plan = _as_dict(candidate.get("proof_plan") or candidate.get("proposed_proof"))
    needs_live_replay = _has_meaningful_source_context(source_context) and proof_plan.get("live_replay_required", True) is not False
    is_live_proof = tool_name in LIVE_PROOF_TOOLS
    is_static_proof = tool_name in STATIC_PROOF_TOOLS
    doc = {
        "_id": f"pr-{uuid.uuid4().hex[:12]}",
        "session_id": session_id,
        "candidate_id": candidate_id,
        "proof_tool": proof_tool_name[:100],
        "oracle": oracle if oracle is not None else {},
        "inputs": inputs if inputs is not None else {},
        "result": result if result is not None else {},
        "artifacts": artifacts or [],
        "passed": passed_value,
        "proof_class": "live" if is_live_proof else "static" if is_static_proof else "other",
        "live_replay_required": needs_live_replay,
        "pass_fail_reason": pass_fail_reason[:2000],
        "created_at": _now(),
    }
    await get_proof_runs_collection().insert_one(doc)
    if passed_value and needs_live_replay and not is_live_proof:
        status = "source_verified_needs_replay" if endpoint else "source_verified_unreachable"
    else:
        status = "proven" if passed_value else "proof_failed"
    candidate_filter: Dict[str, Any] = {"session_id": session_id, "candidate_id": candidate_id}
    if not passed_value:
        protected_statuses = ["proven", "promoted"]
        if needs_live_replay and not is_live_proof:
            protected_statuses.extend(["source_verified_needs_replay", "source_verified_unreachable"])
        candidate_filter["status"] = {"$nin": protected_statuses}
    elif needs_live_replay and not is_live_proof:
        candidate_filter["status"] = {"$nin": ["proven", "promoted"]}
    await get_candidate_findings_collection().update_one(
        candidate_filter,
        {"$set": {"status": status, "updated_at": _now()}},
    )
    return doc


async def rebuild_clusters(session_id: str) -> List[Dict[str, Any]]:
    from app.database.mongodb import get_candidate_findings_collection, get_finding_clusters_collection

    candidates = await get_candidate_findings_collection().find({"session_id": session_id}).to_list(length=1000)
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for cand in candidates:
        grouped.setdefault(str(cand.get("dedup_key") or cand.get("candidate_id")), []).append(cand)

    clusters: List[Dict[str, Any]] = []
    col = get_finding_clusters_collection()
    for dedup_key, items in grouped.items():
        items.sort(key=lambda d: float(d.get("confidence", 0.0)), reverse=True)
        canonical = items[0]
        cluster_id = f"fc-{dedup_key}"
        evidence: List[str] = []
        for item in items:
            for e in _as_list(item.get("evidence")):
                if e not in evidence:
                    evidence.append(e)
        doc = {
            "cluster_id": cluster_id,
            "session_id": session_id,
            "dedup_key": dedup_key,
            "canonical_candidate_id": canonical.get("candidate_id"),
            "title": canonical.get("title", ""),
            "attack_class": canonical.get("attack_class", ""),
            "affected_surface": canonical.get("affected_surface", ""),
            "duplicates": [i.get("candidate_id") for i in items[1:]],
            "candidate_count": len(items),
            "merged_evidence": evidence[:25],
            "root_cause_summary": canonical.get("hypothesis", "")[:1200],
            "updated_at": _now(),
        }
        await col.update_one(
            {"_id": cluster_id},
            {"$set": doc, "$setOnInsert": {"_id": cluster_id}},
            upsert=True,
        )
        clusters.append({"_id": cluster_id, **doc})
    return clusters


async def _candidate_has_blocking_refute(session_id: str, candidate_id: str) -> bool:
    from app.database.mongodb import get_validation_verdicts_collection

    verdict = await get_validation_verdicts_collection().find_one({
        "session_id": session_id,
        "candidate_id": candidate_id,
        "verdict": {"$in": ["refute", "disputed"]},
    })
    return verdict is not None


async def _candidate_has_support(session_id: str, candidate_id: str) -> bool:
    from app.database.mongodb import get_validation_verdicts_collection

    verdict = await get_validation_verdicts_collection().find_one({
        "session_id": session_id,
        "candidate_id": candidate_id,
        "verdict": "support",
        "validator": {"$ne": "counter_validator"},
    })
    return verdict is not None


async def _passing_proof(session_id: str, candidate_id: str) -> Optional[Dict[str, Any]]:
    from app.database.mongodb import get_proof_runs_collection

    return await get_proof_runs_collection().find_one({
        "session_id": session_id,
        "candidate_id": candidate_id,
        "passed": True,
    })


async def _passing_live_proof(session_id: str, candidate_id: str) -> Optional[Dict[str, Any]]:
    from app.database.mongodb import get_proof_runs_collection

    return await get_proof_runs_collection().find_one({
        "session_id": session_id,
        "candidate_id": candidate_id,
        "passed": True,
        "proof_class": "live",
    })


def _source_candidate_requires_live_replay(candidate: Dict[str, Any]) -> bool:
    source_context = _as_dict(candidate.get("source_context"))
    if not _has_meaningful_source_context(source_context):
        return False
    proof_plan = _as_dict(candidate.get("proof_plan") or candidate.get("proposed_proof"))
    return proof_plan.get("live_replay_required", True) is not False


async def promote_ready_candidates(
    session_id: str,
    save_vulnerability: SaveVulnerabilityFn,
    candidate_ids: Optional[Iterable[str]] = None,
) -> int:
    """Promote candidates that passed validation/proof into Vulnerability rows."""
    from app.database.mongodb import get_candidate_findings_collection

    selected_ids = {str(cid).strip() for cid in (candidate_ids or []) if str(cid).strip()}
    col = get_candidate_findings_collection()
    query: Dict[str, Any] = {
        "session_id": session_id,
        "status": {"$nin": ["promoted", "ruled_out"]},
    }
    if selected_ids:
        query["candidate_id"] = {"$in": sorted(selected_ids)}
    candidates = await col.find(query).to_list(length=1000)

    promoted = 0
    for cand in candidates:
        candidate_id = str(cand.get("candidate_id") or cand.get("_id"))
        if await _candidate_has_blocking_refute(session_id, candidate_id):
            await col.update_one(
                {"_id": cand["_id"]},
                {"$set": {"status": "ruled_out", "updated_at": _now()}},
            )
            continue

        proof = await _passing_proof(session_id, candidate_id)
        severity = str(cand.get("severity") or "info").lower()
        live_replay_required = _source_candidate_requires_live_replay(cand)
        if live_replay_required:
            live_proof = await _passing_live_proof(session_id, candidate_id)
            if live_proof:
                proof = live_proof
            else:
                await col.update_one(
                    {"_id": cand["_id"]},
                    {"$set": {
                        "status": (
                            "source_verified_needs_replay"
                            if (cand.get("endpoint") or _as_dict(cand.get("reachability_context")).get("endpoint"))
                            else "source_verified_unreachable"
                        ),
                        "updated_at": _now(),
                    }},
                )
                continue
        if not proof:
            continue

        evidence = _as_list(cand.get("evidence"))
        evidence.append(
            "validated_dynamic proof_run_passed: "
            f"{proof.get('proof_tool', 'proof')} {proof.get('pass_fail_reason', '')}".strip()
        )

        vuln_data = {
            "title": cand.get("title") or "Validated candidate",
            "severity": severity,
            "cvss_score": cand.get("cvss_score"),
            "cve_ids": cand.get("cve_ids") or [],
            "affected_service": cand.get("affected_service") or cand.get("affected_surface") or "",
            "port": cand.get("port"),
            "protocol": cand.get("protocol"),
            "description": cand.get("hypothesis") or cand.get("reachability_claim") or "",
            "exploit_code": cand.get("exploit_code"),
            "patch_code": cand.get("patch_code"),
            "remediation": cand.get("remediation") or "Validate the affected code/configuration and remove the vulnerable behavior.",
            "confidence": cand.get("confidence", 0.5),
            "verification_status": "confirmed",
            "mitre_techniques": cand.get("mitre_techniques") or [],
            "is_zero_day": bool(cand.get("is_zero_day", False)),
            "evidence_for": evidence,
            "endpoint": cand.get("endpoint") or cand.get("affected_surface") or "",
            "technique_tag": cand.get("attack_class") or "",
            "tool_used": proof.get("proof_tool"),
        }
        await save_vulnerability(session_id, vuln_data)
        await col.update_one(
            {"_id": cand["_id"]},
            {"$set": {"status": "promoted", "promoted_at": _now(), "updated_at": _now()}},
        )
        promoted += 1
    return promoted


async def patch_semantic_dedup(
    session_id: str,
    client: Any,
    model: str,
    similarity_lo: float = 0.60,
    similarity_hi: float = 0.85,
) -> int:
    """validation milestone 5 — patch-based semantic deduplication.

    validated scanner deduplicates findings by "patch-based grouping" — semantically
    equivalent fixes are the same bug regardless of how the two instances were
    described. This catches cases the existing cosine-similarity dedup misses:
      (a) Same bug described differently by two agents.
      (b) Same root-cause fix needed at multiple call sites.

    Algorithm:
      1. Fetch all promoted candidates for the session (status=promoted).
      2. For pairs with cosine similarity between similarity_lo and similarity_hi
         (below the existing auto-merge threshold), call the LLM:
         "Would the patch for finding A also fix finding B?"
      3. When yes — create a dedup_cluster in MongoDB and tag both findings
         with patch_equivalent=True.

    Returns the number of new patch-equivalent clusters created.
    """
    if client is None:
        return 0

    from app.database.mongodb import get_candidate_findings_collection, get_dedup_clusters_collection
    from app.database.chroma_client import get_source_corpus_collection
    import itertools as _itertools

    col = get_candidate_findings_collection()
    candidates = await col.find(
        {"session_id": session_id, "status": "promoted"},
    ).to_list(length=200)

    if len(candidates) < 2:
        return 0

    # Try to get embeddings-based similarity pairs via ChromaDB hypothesis collection
    try:
        from app.database.chroma_client import get_hypotheses_collection
        hyp_col = await get_hypotheses_collection()
    except Exception:
        hyp_col = None

    clusters_created = 0
    dedup_col = get_dedup_clusters_collection()
    checked_pairs: set = set()

    for cand_a, cand_b in _itertools.combinations(candidates, 2):
        id_a = str(cand_a.get("candidate_id") or cand_a.get("_id"))
        id_b = str(cand_b.get("candidate_id") or cand_b.get("_id"))
        pair_key = tuple(sorted([id_a, id_b]))
        if pair_key in checked_pairs:
            continue
        checked_pairs.add(pair_key)

        # Skip pairs from the same dedup_key (already merged by structural dedup)
        if cand_a.get("dedup_key") == cand_b.get("dedup_key"):
            continue

        # Quick pre-filter: attack_class must overlap or both be empty
        cls_a = str(cand_a.get("attack_class") or "").lower()
        cls_b = str(cand_b.get("attack_class") or "").lower()
        if cls_a and cls_b and cls_a.split("_")[0] != cls_b.split("_")[0]:
            # Different top-level attack families — almost certainly different bugs
            continue

        rem_a = str(cand_a.get("remediation") or cand_a.get("hypothesis") or "")[:400]
        rem_b = str(cand_b.get("remediation") or cand_b.get("hypothesis") or "")[:400]
        if not rem_a or not rem_b:
            continue

        # Ask the LLM: same patch?
        user_msg = (
            "You are a security engineer reviewing two vulnerability findings.\n\n"
            f"Finding A:\n  Title: {cand_a.get('title', '')[:200]}\n"
            f"  Remediation: {rem_a}\n\n"
            f"Finding B:\n  Title: {cand_b.get('title', '')[:200]}\n"
            f"  Remediation: {rem_b}\n\n"
            "Would the same code fix (patch) resolve both findings? "
            "Answer with JSON: {\"patch_equivalent\": true|false, \"reason\": \"...\", "
            "\"patch_summary\": \"one-line description of the shared fix\"}"
        )
        try:
            resp = await client.messages.create(
                model=model,
                max_tokens=256,
                timeout=30.0,
                system="You are a precise security triage assistant. Answer only with the JSON asked.",
                messages=[{"role": "user", "content": user_msg}],
            )
            text = "".join(
                getattr(b, "text", "") for b in (resp.content or [])
            ).strip()
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1:
                continue
            import json as _json
            parsed = _json.loads(text[start:end + 1])
        except Exception as exc:
            logger.debug("patch_semantic_dedup LLM call failed: %s", exc)
            continue

        if not parsed.get("patch_equivalent", False):
            continue

        patch_summary = str(parsed.get("patch_summary", ""))[:300]
        cluster_id = f"pdc-{_hash_parts([id_a, id_b])}"
        cluster_doc = {
            "_id": cluster_id,
            "session_id": session_id,
            "finding_ids": [id_a, id_b],
            "patch_summary": patch_summary,
            "reason": str(parsed.get("reason", ""))[:500],
            "created_at": _now(),
        }
        try:
            await dedup_col.replace_one({"_id": cluster_id}, cluster_doc, upsert=True)
            # Tag both candidates
            await col.update_many(
                {"session_id": session_id, "candidate_id": {"$in": [id_a, id_b]}},
                {"$set": {"patch_equivalent": True, "patch_cluster_id": cluster_id}},
            )
            clusters_created += 1
            logger.info(
                "patch_semantic_dedup: session=%s new cluster %s — %s / %s",
                session_id, cluster_id,
                cand_a.get("title", "")[:60], cand_b.get("title", "")[:60],
            )
        except Exception as exc:
            logger.debug("patch_semantic_dedup cluster insert failed: %s", exc)

    logger.info(
        "patch_semantic_dedup: session=%s pairs_checked=%d clusters_created=%d",
        session_id, len(checked_pairs), clusters_created,
    )
    return clusters_created


def _matches_truth(text: str, truth: Any) -> bool:
    hay = _norm(text)
    if isinstance(truth, dict):
        fields = [truth.get(k, "") for k in ("id", "title", "attack_class", "endpoint", "description")]
        needles = [_norm(f) for f in fields if str(f).strip()]
    else:
        needles = [_norm(truth)]
    return any(n and (n in hay or hay in n) for n in needles)


async def build_benchmark_report(
    session_id: str,
    *,
    ground_truth: Optional[List[Any]] = None,
    label: str = "",
    lane: str = "hybrid",
) -> Dict[str, Any]:
    from sqlalchemy import func, select

    from app.database.mongodb import (
        get_benchmark_reports_collection,
        get_candidate_findings_collection,
        get_finding_clusters_collection,
        get_proof_runs_collection,
        get_target_surface_graph_collection,
    )
    from app.database.postgres import AsyncSessionLocal
    from app.models.vulnerability import Vulnerability

    candidates = await get_candidate_findings_collection().find({"session_id": session_id}).to_list(length=2000)
    clusters = await get_finding_clusters_collection().find({"session_id": session_id}).to_list(length=2000)
    proof_runs = await get_proof_runs_collection().find({"session_id": session_id}).to_list(length=2000)
    passed_proofs = [p for p in proof_runs if p.get("passed")]
    live_proofs = [p for p in passed_proofs if p.get("proof_class") == "live"]
    static_proofs = [p for p in passed_proofs if p.get("proof_class") == "static"]
    surface_graph = await get_target_surface_graph_collection().find_one({"session_id": session_id}) or {}
    endpoint_candidates = [c for c in candidates if c.get("candidate_kind") == "endpoint"]
    source_candidates = [c for c in candidates if c.get("candidate_kind") == "source"]
    hybrid_candidates = [c for c in candidates if c.get("candidate_kind") == "hybrid"]

    total_vulns = 0
    confirmed_vulns = 0
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(
                func.count(Vulnerability.id).label("total"),
                func.count(Vulnerability.id)
                .filter(Vulnerability.verification_status.in_(["confirmed", "exploited"]))
                .label("confirmed"),
            ).where(Vulnerability.session_id == uuid.UUID(session_id))
        )
        row = result.one()
        total_vulns = int(row.total or 0)
        confirmed_vulns = int(row.confirmed or 0)

    duplicate_rate = 0.0
    if candidates:
        duplicate_rate = max(0.0, 1.0 - (len(clusters) / len(candidates)))
    proof_coverage = (len(passed_proofs) / max(1, len(candidates))) if candidates else 0.0
    precision = (confirmed_vulns / total_vulns) if total_vulns else 0.0

    recall = None
    matched_truth: List[Any] = []
    if ground_truth:
        candidate_texts = [
            " ".join(
                str(c.get(k, ""))
                for k in (
                    "title", "attack_class", "affected_surface", "hypothesis",
                    "endpoint", "sink", "source_input", "commit_signal",
                )
            )
            for c in candidates
        ]
        for truth in ground_truth:
            if any(_matches_truth(text, truth) for text in candidate_texts):
                matched_truth.append(truth)
        recall = len(matched_truth) / max(1, len(ground_truth))

    report = {
        "_id": f"bench-{uuid.uuid4().hex[:12]}",
        "session_id": session_id,
        "label": label,
        "lane": lane,
        "candidate_count": len(candidates),
        "cluster_count": len(clusters),
        "duplicate_rate": round(duplicate_rate, 4),
        "proof_run_count": len(proof_runs),
        "passed_proof_count": len(passed_proofs),
        "live_proof_count": len(live_proofs),
        "static_proof_count": len(static_proofs),
        "proof_coverage": round(proof_coverage, 4),
        "vulnerability_count": total_vulns,
        "confirmed_vulnerability_count": confirmed_vulns,
        "precision_proxy": round(precision, 4),
        "endpoint_candidate_count": len(endpoint_candidates),
        "source_candidate_count": len(source_candidates),
        "hybrid_candidate_count": len(hybrid_candidates),
        "surface_link_count": int(surface_graph.get("link_count", 0) or 0),
        "hybrid_surface_link_count": int(surface_graph.get("hybrid_link_count", 0) or 0),
        "endpoint_source_mapping_rate": float(surface_graph.get("endpoint_source_mapping_rate", 0.0) or 0.0),
        "ground_truth_count": len(ground_truth or []),
        "matched_ground_truth_count": len(matched_truth),
        "recall": round(recall, 4) if recall is not None else None,
        "created_at": _now(),
    }
    await get_benchmark_reports_collection().insert_one(report)
    return report


def public_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    def convert(value: Any) -> Any:
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {str(k): convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [convert(v) for v in value]
        return value

    out = convert(dict(doc))
    if "_id" in out:
        out["_id"] = str(out["_id"])
    return out
