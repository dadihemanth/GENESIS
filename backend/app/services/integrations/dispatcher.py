"""T143 — SOC Integration Dispatcher.

Fan-out notification to all enabled integrations when a finding occurs.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


async def notify_finding(finding: Dict[str, Any], integrations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fan out a finding notification to all enabled integrations."""
    from app.services.integrations.slack_notifier import send_slack
    from app.services.integrations.pagerduty_notifier import send_pagerduty
    from app.services.integrations.jira_connector import create_jira_issue
    from app.services.integrations.splunk_forwarder import forward_to_splunk
    from app.services.integrations.teams_notifier import send_teams

    dispatch_map = {
        "slack": send_slack,
        "pagerduty": send_pagerduty,
        "jira": create_jira_issue,
        "splunk": forward_to_splunk,
        "teams": send_teams,
    }

    tasks = []
    for integration in integrations:
        if not integration.get("enabled", True):
            continue
        itype = integration.get("type", "")
        fn = dispatch_map.get(itype)
        if fn:
            tasks.append(fn(finding, integration))

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)
    outcomes = []
    for integration, result in zip(integrations, results):
        if isinstance(result, Exception):
            outcomes.append({"type": integration.get("type"), "ok": False, "error": str(result)})
        else:
            outcomes.append({"type": integration.get("type"), "ok": True, **result})
    return outcomes
