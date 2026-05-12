"""Slack webhook notifier for GENESIS findings (T143)."""
from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":orange_circle:",
    "medium": ":yellow_circle:",
    "low": ":white_circle:",
    "info": ":blue_circle:",
}


async def send_slack(finding: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return {"ok": False, "error": "no webhook_url configured"}

    severity = (finding.get("severity") or "info").lower()
    emoji = SEVERITY_EMOJI.get(severity, ":white_circle:")
    title = finding.get("title") or finding.get("type") or "Security Finding"
    target = finding.get("target_url") or finding.get("target") or "unknown"
    session_id = finding.get("session_id", "")

    payload = {
        "text": f"{emoji} *GENESIS Finding: {title}*",
        "attachments": [{
            "color": {"critical": "danger", "high": "danger", "medium": "warning"}.get(severity, "good"),
            "fields": [
                {"title": "Severity", "value": severity.upper(), "short": True},
                {"title": "Target", "value": target, "short": True},
                {"title": "Session", "value": session_id[:8] if session_id else "N/A", "short": True},
                {"title": "Description", "value": (finding.get("description") or "")[:300], "short": False},
            ],
            "footer": "GENESIS v6.0 Tier-8",
        }],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
        return {"ok": True, "status_code": resp.status_code}
    except Exception as exc:
        logger.warning("Slack notification failed: %s", exc)
        return {"ok": False, "error": str(exc)}
