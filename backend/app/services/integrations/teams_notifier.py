"""Microsoft Teams webhook notifier for GENESIS findings (T143)."""
from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

SEVERITY_COLOR = {
    "critical": "FF0000",
    "high": "FF6600",
    "medium": "FFCC00",
    "low": "99CC00",
    "info": "0099FF",
}


async def send_teams(finding: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return {"ok": False, "error": "no webhook_url configured"}

    severity = (finding.get("severity") or "info").lower()
    title = finding.get("title") or finding.get("type") or "Security Finding"
    target = finding.get("target_url") or finding.get("target") or "unknown"
    description = (finding.get("description") or "")[:300]
    color = SEVERITY_COLOR.get(severity, "0099FF")

    # Adaptive Card payload for Teams
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"GENESIS Finding: {title}",
        "sections": [{
            "activityTitle": f"**GENESIS {severity.upper()}: {title}**",
            "activitySubtitle": f"Target: {target}",
            "activityText": description,
            "facts": [
                {"name": "Severity", "value": severity.upper()},
                {"name": "Session", "value": (finding.get("session_id") or "N/A")[:8]},
                {"name": "Attack Class", "value": finding.get("attack_class") or "N/A"},
            ],
        }],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
        return {"ok": True}
    except Exception as exc:
        logger.warning("Teams notification failed: %s", exc)
        return {"ok": False, "error": str(exc)}
