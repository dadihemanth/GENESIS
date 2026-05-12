"""T92 — architectural_reasoner: trust boundary and data-flow analysis.

Reads OpenAPI specs, Docker Compose files, and architecture notes attached to
a session (stored in MongoDB target_briefs).  Extracts trust boundaries, data
flows, and authentication seams, then emits a structured threat model that
extends the T1 target brief and generates hypotheses via hypothesis_market.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.database.mongodb import get_target_briefs_collection
from app.services.hypothesis_market import submit_hypothesis

logger = logging.getLogger(__name__)

_ARCH_SYSTEM = (
    "You are the ARCHITECTURAL REASONER in GENESIS v5. "
    "Given architecture artifacts (OpenAPI spec, Docker Compose, or architecture notes), "
    "identify: trust boundaries, unauthenticated endpoints, privilege escalation seams, "
    "internal services exposed to external callers, and data flows carrying sensitive data. "
    "Respond with JSON: {"
    "  \"trust_boundaries\": [{\"name\": \"...\", \"description\": \"...\"}], "
    "  \"unauthenticated_endpoints\": [{\"path\": \"...\", \"method\": \"...\", \"risk\": \"...\"}], "
    "  \"privilege_seams\": [{\"from\": \"...\", \"to\": \"...\", \"mechanism\": \"...\"}], "
    "  \"sensitive_flows\": [{\"source\": \"...\", \"sink\": \"...\", \"data\": \"...\"}], "
    "  \"attack_hypotheses\": [{\"text\": \"...\", \"confidence\": 0.0–1.0}]"
    "}"
)


def _extract_openapi_summary(spec: Dict[str, Any]) -> str:
    """Pull a compact summary of an OpenAPI spec for the LLM prompt."""
    paths = spec.get("paths", {})
    lines = [f"Title: {spec.get('info', {}).get('title', 'unknown')}"]
    for path, methods in list(paths.items())[:30]:
        for method, detail in methods.items():
            if not isinstance(detail, dict):
                continue
            security = detail.get("security", [])
            auth = "authenticated" if security else "UNAUTHENTICATED"
            summary = detail.get("summary", "")[:60]
            lines.append(f"  {method.upper()} {path} — {auth} — {summary}")
    return "\n".join(lines)


def _extract_compose_summary(compose: Dict[str, Any]) -> str:
    """Pull a compact summary of a docker-compose config."""
    services = compose.get("services", {})
    lines = []
    for name, svc in list(services.items())[:20]:
        ports = svc.get("ports", [])
        networks = list((svc.get("networks") or {}).keys())
        env_keys = list((svc.get("environment") or {}).keys())[:5]
        lines.append(
            f"  {name}: ports={ports} networks={networks} env_keys={env_keys}"
        )
    return "\n".join(lines)


async def analyze_architecture(
    session_id: str,
    client: Any,
    model: str,
    openapi_spec: Optional[Dict[str, Any]] = None,
    compose_config: Optional[Dict[str, Any]] = None,
    architecture_notes: str = "",
) -> Dict[str, Any]:
    """Produce a structured threat model from available architecture artifacts.

    Extends the MongoDB target_brief for this session and submits
    attack hypotheses to the hypothesis market.
    """
    if client is None:
        return {}

    # Build the context string
    sections: List[str] = []
    if openapi_spec:
        sections.append("## OpenAPI Spec\n" + _extract_openapi_summary(openapi_spec))
    if compose_config:
        sections.append("## Docker Compose Services\n" + _extract_compose_summary(compose_config))
    if architecture_notes:
        sections.append("## Architecture Notes\n" + architecture_notes[:2000])

    if not sections:
        logger.info("architectural_reasoner: no artifacts for session=%s", session_id)
        return {}

    context = "\n\n".join(sections)

    try:
        resp = await client.messages.create(
            model=model,
            max_tokens=1200,
            timeout=120.0,
            system=_ARCH_SYSTEM,
            messages=[{"role": "user", "content": context}],
        )
        text = ""
        for block in (resp.content or []):
            if hasattr(block, "text"):
                text += block.text
        text = text.strip()

        # Parse JSON from response
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            return {}
        threat_model = json.loads(text[start:end + 1])

    except Exception as exc:
        logger.warning("architectural_reasoner LLM call failed: %s", exc)
        return {}

    # Persist threat model into target_brief (extend T1 brief)
    try:
        briefs = get_target_briefs_collection()
        await briefs.update_one(
            {"session_id": session_id},
            {"$set": {"threat_model": threat_model, "arch_analyzed": True}},
            upsert=True,
        )
    except Exception as exc:
        logger.debug("architectural_reasoner brief update failed: %s", exc)

    # Submit attack hypotheses to the market
    for hyp in threat_model.get("attack_hypotheses", [])[:5]:
        if isinstance(hyp, dict) and "text" in hyp:
            await submit_hypothesis(
                session_id=session_id,
                text=hyp["text"],
                proposer_agent="architectural_reasoner",
                hypothesis_type="architectural",
                confidence_stake=float(hyp.get("confidence", 0.5)),
            )

    logger.info(
        "architectural_reasoner: session=%s boundaries=%d endpoints=%d hypotheses=%d",
        session_id,
        len(threat_model.get("trust_boundaries", [])),
        len(threat_model.get("unauthenticated_endpoints", [])),
        len(threat_model.get("attack_hypotheses", [])),
    )
    return threat_model


async def get_threat_model(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve the stored threat model for a session."""
    try:
        briefs = get_target_briefs_collection()
        doc = await briefs.find_one({"session_id": session_id})
        if doc:
            return doc.get("threat_model")
    except Exception as exc:
        logger.debug("get_threat_model failed: %s", exc)
    return None
