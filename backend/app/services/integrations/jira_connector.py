"""Jira issue creator for GENESIS findings (T143)."""
from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

SEVERITY_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


async def create_jira_issue(finding: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    base_url = config.get("base_url", "").rstrip("/")
    project_key = config.get("project_key", "")
    email = config.get("email", "")
    api_token = config.get("api_token", "")

    if not all([base_url, project_key, email, api_token]):
        return {"ok": False, "error": "missing jira config (base_url, project_key, email, api_token)"}

    severity = (finding.get("severity") or "info").lower()
    title = finding.get("title") or finding.get("type") or "Security Finding"
    target = finding.get("target_url") or finding.get("target") or "unknown"
    description = finding.get("description") or ""
    evidence = str(finding.get("evidence") or "")[:1000]

    issue_body = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[GENESIS] {severity.upper()}: {title} — {target}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": f"{description}\n\nEvidence:\n{evidence}"}],
                }],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": SEVERITY_PRIORITY.get(severity, "Medium")},
        }
    }

    try:
        async with httpx.AsyncClient(timeout=15, auth=(email, api_token)) as client:
            resp = await client.post(
                f"{base_url}/rest/api/3/issue",
                json=issue_body,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
        return {"ok": True, "issue_key": data.get("key", ""), "issue_url": f"{base_url}/browse/{data.get('key', '')}"}
    except Exception as exc:
        logger.warning("Jira issue creation failed: %s", exc)
        return {"ok": False, "error": str(exc)}
