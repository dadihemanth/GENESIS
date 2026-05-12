"""PagerDuty event notifier for critical GENESIS findings (T143)."""
from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


async def send_pagerduty(finding: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    routing_key = config.get("routing_key", "")
    if not routing_key:
        return {"ok": False, "error": "no routing_key configured"}

    severity = (finding.get("severity") or "info").lower()
    # Only page on critical/high
    if severity not in ("critical", "high"):
        return {"ok": True, "skipped": True, "reason": f"severity {severity} below paging threshold"}

    title = finding.get("title") or finding.get("type") or "Security Finding"
    target = finding.get("target_url") or finding.get("target") or "unknown"

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": f"[GENESIS] {severity.upper()}: {title} on {target}",
            "severity": "critical" if severity == "critical" else "error",
            "source": "GENESIS v6.0",
            "custom_details": {
                "session_id": finding.get("session_id", ""),
                "description": (finding.get("description") or "")[:500],
                "evidence": str(finding.get("evidence", ""))[:300],
            },
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(PD_EVENTS_URL, json=payload)
            resp.raise_for_status()
        return {"ok": True, "dedup_key": resp.json().get("dedup_key", "")}
    except Exception as exc:
        logger.warning("PagerDuty notification failed: %s", exc)
        return {"ok": False, "error": str(exc)}
